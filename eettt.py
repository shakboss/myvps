import socket
import struct
import threading
import argparse
import logging
import time
import select
from queue import Queue, Empty, Full # Added Full for explicit catch

# --- Configuration ---
SOCKS_VERSION = 5
BUFFER_SIZE = 65535
CLIENT_CONNECTION_TIMEOUT = 20
RELAY_TIMEOUT_SELECT = 0.1 # Timeout for select in C2T loop
RELAY_TIMEOUT_QUEUE_GET = 0.2 # Timeout for queue.get in T2C loop
UDP_RECEIVER_SELECT_TIMEOUT = 0.2

# --- Logging Setup ---
# Clear any existing handlers to avoid duplicate logs if script is re-run in same session
# This should be done once at the very start if __main__
if __name__ == "__main__":
    logging.getLogger().handlers = []
    log_level = logging.DEBUG # Default to DEBUG for this version
    # The arg parser below will potentially override this based on --debug flag
    logging.basicConfig(level=log_level,
                        format='%(asctime)s - %(levelname)s - %(threadName)s - [%(funcName)s] - %(message)s')

# --- Global state ---
udp_tunnel_socket = None
tunnel_server_address_global = None
tunnel_auth_details_global = {}

active_socks_sessions = {}
session_lock = threading.Lock()
next_session_id_counter = 1

def get_next_session_id():
    global next_session_id_counter
    with session_lock:
        session_id = next_session_id_counter
        next_session_id_counter = (next_session_id_counter % 254) + 1
        if next_session_id_counter == 0:
            next_session_id_counter = 1
        return session_id

def pack_tunnel_request_data(username, password, sender_counter, receiver_counter, dest_ip_str, dest_port, payload):
    try:
        username_bytes = username.encode('utf-8')
        password_bytes = password.encode('utf-8')
        sc = max(1, min(255, int(sender_counter)))
        rc = max(0, min(255, int(receiver_counter)))
        dest_ip_bytes = socket.inet_aton(dest_ip_str)

        packet = struct.pack('!B', len(username_bytes)) + \
                 username_bytes + \
                 struct.pack('!B', len(password_bytes)) + \
                 password_bytes + \
                 struct.pack('!BB', sc, rc) + \
                 dest_ip_bytes + \
                 struct.pack('!H', dest_port) + \
                 payload
        # This log is very verbose, enable only if absolutely needed for packet structure debugging
        # logging.debug(f"Packed: ULen:{len(username_bytes)}, PLen:{len(password_bytes)}, SC:{sc}, RC:{rc}, IP:{dest_ip_str}, Port:{dest_port}, PayloadLen:{len(payload)}")
        return packet
    except struct.error as e:
        logging.error(f"Struct packing error: {e}. SC:{sender_counter}, RC:{receiver_counter}, IP:{dest_ip_str}, Port:{dest_port}")
        return None
    except socket.error as e:
        logging.error(f"Socket error during packing (invalid IP '{dest_ip_str}'?): {e}")
        return None
    except Exception as e:
        logging.error(f"Error packing tunnel request: {e}")
        return None

def unpack_tunnel_response_data(data):
    if len(data) < 2:
        logging.warning(f"Tunnel response too short ({len(data)} bytes).")
        return None, None, None
    try:
        sender_counter_echoed = data[0]
        receiver_counter_echoed = data[1]
        payload = data[2:]
        return sender_counter_echoed, receiver_counter_echoed, payload
    except Exception as e:
        logging.error(f"Error unpacking tunnel response: {e}")
        return None, None, None

def udp_receiver_thread_func():
    global udp_tunnel_socket
    logging.info("UDP Receiver thread started.")
    while True:
        if udp_tunnel_socket is None:
            logging.warning("UDP Receiver: Socket not initialized. Retrying...")
            time.sleep(1)
            continue
        try:
            ready_to_read, _, _ = select.select([udp_tunnel_socket], [], [], UDP_RECEIVER_SELECT_TIMEOUT)
            if ready_to_read:
                data, server_addr = udp_tunnel_socket.recvfrom(BUFFER_SIZE)
                if not data:
                    logging.warning(f"UDP Receiver: Empty packet from {server_addr}.")
                    continue

                logging.debug(f"UDP Receiver: Raw data received from {server_addr}, len={len(data)}")
                sc_echo, rc_echo, payload = unpack_tunnel_response_data(data)

                if payload is None:
                    continue

                session_key = (sc_echo, rc_echo)
                with session_lock:
                    session_queue = active_socks_sessions.get(session_key)

                if session_queue:
                    try:
                        session_queue.put(payload, timeout=0.1)
                        logging.debug(f"UDP Receiver: Queued {len(payload)} bytes for session {session_key}")
                    except Full:
                        logging.warning(f"UDP Receiver: Queue full for session {session_key}. Packet dropped.")
                else:
                    logging.warning(f"UDP Receiver: No SOCKS session for SC_echo={sc_echo}, RC_echo={rc_echo} (key: {session_key}). Packet dropped. Active: {list(active_socks_sessions.keys())}")
        except socket.timeout:
            continue
        except ConnectionResetError:
            logging.warning("UDP Receiver: ConnectionResetError.")
            time.sleep(1)
        except Exception as e:
            logging.error(f"UDP Receiver critical error: {e}", exc_info=True)
            time.sleep(1)

class SocksProxySessionHandler(threading.Thread):
    def __init__(self, client_socket, client_address, tunnel_server_addr, tunnel_auth):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address
        self.daemon = True # Threads exit when main exits
        self.session_id = get_next_session_id()
        self.client_chosen_receiver_counter = 0 # Fixed RC for this session's outgoing packets
        self.data_queue_from_tunnel = Queue(maxsize=100)
        self.target_host_str = None
        self.target_port_int = None
        self.target_ip_resolved = None
        self.tunnel_server_addr_param = tunnel_server_addr
        self.tunnel_auth_param = tunnel_auth
        self.session_demux_key = (self.session_id, self.client_chosen_receiver_counter)
        self.stop_event = threading.Event() # For signaling threads to stop

    def _register_session_for_tunnel_responses(self):
        with session_lock:
            if self.session_demux_key in active_socks_sessions:
                logging.warning(f"SOCKS {self.session_id}: Demux key {self.session_demux_key} collision! This is bad.")
            active_socks_sessions[self.session_demux_key] = self.data_queue_from_tunnel
        logging.info(f"SOCKS {self.session_id}: Registered session for demux key {self.session_demux_key} ({self.client_address})")

    def _unregister_session(self):
        with session_lock:
            if self.session_demux_key in active_socks_sessions:
                del active_socks_sessions[self.session_demux_key]
                logging.info(f"SOCKS {self.session_id}: Unregistered session for demux key {self.session_demux_key}")
            # else:
                # logging.debug(f"SOCKS {self.session_id}: Session demux key {self.session_demux_key} already unregistered or never registered.")

    def _handle_socks_negotiation(self):
        # (Identical to previous version - seems okay)
        try:
            self.client_socket.settimeout(CLIENT_CONNECTION_TIMEOUT)
            header = self.client_socket.recv(2)
            if not header or header[0] != SOCKS_VERSION:
                logging.warning(f"SOCKS {self.session_id}: Invalid SOCKS version {header[0] if header else 'None'} from {self.client_address}")
                return False
            nmethods = header[1]
            methods = self.client_socket.recv(nmethods)
            if 0 not in methods:
                logging.warning(f"SOCKS {self.session_id}: No acceptable auth method (0x00) from {self.client_address}. Methods: {list(methods)}")
                self.client_socket.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
                return False
            self.client_socket.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))
            return True
        except socket.timeout:
            logging.warning(f"SOCKS {self.session_id}: Timeout during negotiation with {self.client_address}")
            return False
        except Exception as e:
            logging.error(f"SOCKS {self.session_id}: Negotiation error with {self.client_address}: {e}", exc_info=True)
            return False


    def _handle_socks_request(self):
        # (Identical to previous version - seems okay)
        try:
            self.client_socket.settimeout(CLIENT_CONNECTION_TIMEOUT)
            request_header = self.client_socket.recv(4)
            if not request_header or len(request_header) < 4:
                logging.warning(f"SOCKS {self.session_id}: Truncated request from {self.client_address}")
                return False

            ver, cmd, rsv, atyp = request_header
            if ver != SOCKS_VERSION:
                logging.warning(f"SOCKS {self.session_id}: Invalid SOCKS version in request: {ver}")
                return False

            if cmd == 1: pass # CONNECT
            elif cmd == 3: # UDP ASSOCIATE
                logging.warning(f"SOCKS {self.session_id}: UDP ASSOCIATE command (3) not supported from {self.client_address}")
                self._send_socks_reply(0x07) # Command not supported
                return False
            else: # Other commands like BIND
                logging.warning(f"SOCKS {self.session_id}: Unsupported command {cmd} from {self.client_address}")
                self._send_socks_reply(0x07)
                return False

            if atyp == 1: # IPv4
                addr_bytes = self.client_socket.recv(4)
                if len(addr_bytes) < 4: return False
                self.target_host_str = socket.inet_ntoa(addr_bytes)
                self.target_ip_resolved = self.target_host_str
            elif atyp == 3: # Domain name
                domain_len_byte = self.client_socket.recv(1)
                if not domain_len_byte: return False
                domain_len = domain_len_byte[0]
                domain_bytes = self.client_socket.recv(domain_len)
                if len(domain_bytes) < domain_len: return False
                self.target_host_str = domain_bytes.decode('utf-8', errors='ignore')
            elif atyp == 4: # IPv6
                logging.warning(f"SOCKS {self.session_id}: IPv6 ATYP (4) received but tunnel uses IPv4.")
                self._send_socks_reply(0x08); return False # Address type not supported
            else:
                logging.warning(f"SOCKS {self.session_id}: Unknown ATYP {atyp} from {self.client_address}")
                self._send_socks_reply(0x08); return False

            port_bytes = self.client_socket.recv(2)
            if len(port_bytes) < 2: return False
            self.target_port_int = struct.unpack('!H', port_bytes)[0]

            if atyp == 3: # Resolve domain if it was a domain name
                try:
                    self.target_ip_resolved = socket.gethostbyname(self.target_host_str)
                    logging.info(f"SOCKS {self.session_id}: Resolved {self.target_host_str} to {self.target_ip_resolved}")
                except socket.gaierror:
                    logging.warning(f"SOCKS {self.session_id}: Failed to resolve hostname {self.target_host_str}")
                    self._send_socks_reply(0x04); return False # Host unreachable

            self._send_socks_reply(0x00) # Succeeded
            logging.info(f"SOCKS {self.session_id}: CONNECT from {self.client_address} to {self.target_host_str}:{self.target_port_int} (IP: {self.target_ip_resolved})")
            return True
        except socket.timeout:
            logging.warning(f"SOCKS {self.session_id}: Timeout during request phase with {self.client_address}")
            self._send_socks_reply(0x01); return False
        except Exception as e:
            logging.error(f"SOCKS {self.session_id}: Request error with {self.client_address} for {self.target_host_str}:{self.target_port_int}: {e}", exc_info=True)
            self._send_socks_reply(0x01); return False

    def _send_socks_reply(self, rep_code, bind_addr_str="0.0.0.0", bind_port_int=0):
        # (Identical to previous version)
        try:
            atyp = 1 # IPv4
            bnd_addr_bytes = socket.inet_aton(bind_addr_str)
            reply = struct.pack("!BBBB", SOCKS_VERSION, rep_code, 0x00, atyp) + \
                    bnd_addr_bytes + \
                    struct.pack("!H", bind_port_int)
            self.client_socket.sendall(reply)
        except Exception as e:
            logging.error(f"SOCKS {self.session_id}: Failed to send SOCKS reply (code {rep_code}): {e}")

    def _relay_data_streams(self):
        self._register_session_for_tunnel_responses()
        # No explicit timeout on client_socket here; select will handle it in C2T loop

        c2t_thread = threading.Thread(target=self._client_to_tunnel_loop, name=f"C2T-{self.session_id}", daemon=True)
        t2c_thread = threading.Thread(target=self._tunnel_to_client_loop, name=f"T2C-{self.session_id}", daemon=True)

        c2t_thread.start()
        t2c_thread.start()

        # Wait for either thread to signal completion or an error
        while not self.stop_event.is_set():
            if not c2t_thread.is_alive() or not t2c_thread.is_alive():
                logging.debug(f"SOCKS {self.session_id}: A relay thread exited. C2T alive: {c2t_thread.is_alive()}, T2C alive: {t2c_thread.is_alive()}.")
                self.stop_event.set() # Signal the other thread to stop
            time.sleep(0.1) # Check periodically

        logging.debug(f"SOCKS {self.session_id}: Main relay loop detected stop_event. Joining C2T and T2C threads.")
        c2t_thread.join(timeout=1.5) # Give threads a moment to exit from stop_event
        t2c_thread.join(timeout=1.5)

        if c2t_thread.is_alive():
            logging.warning(f"SOCKS {self.session_id}: C2T thread {c2t_thread.name} did not terminate gracefully.")
        if t2c_thread.is_alive():
            logging.warning(f"SOCKS {self.session_id}: T2C thread {t2c_thread.name} did not terminate gracefully (possibly stuck on queue).")

    def _client_to_tunnel_loop(self):
        username = self.tunnel_auth_param['username']
        password = self.tunnel_auth_param['password']
        logging.debug(f"SOCKS C->T {self.session_id}: Started.")
        try:
            while not self.stop_event.is_set():
                readable, _, _ = select.select([self.client_socket], [], [], RELAY_TIMEOUT_SELECT)
                if self.stop_event.is_set(): break # Check immediately after select

                if readable:
                    data_from_client = self.client_socket.recv(BUFFER_SIZE - 200) # Space for header
                    if not data_from_client:
                        logging.info(f"SOCKS C->T {self.session_id}: Client {self.client_address} closed connection (recv: 0 bytes).")
                        self.stop_event.set(); break

                    logging.debug(f"SOCKS C->T {self.session_id}: Recv {len(data_from_client)} bytes from SOCKS client for {self.target_ip_resolved}:{self.target_port_int}")
                    tunnel_packet = pack_tunnel_request_data(
                        username, password, self.session_id, self.client_chosen_receiver_counter,
                        self.target_ip_resolved, self.target_port_int, data_from_client
                    )
                    if tunnel_packet and udp_tunnel_socket:
                        udp_tunnel_socket.sendto(tunnel_packet, self.tunnel_server_addr_param)
                        logging.debug(f"SOCKS C->T {self.session_id}: Sent {len(tunnel_packet)} bytes to tunnel {self.tunnel_server_addr_param}")
                    elif not udp_tunnel_socket:
                        logging.error(f"SOCKS C->T {self.session_id}: udp_tunnel_socket is None!"); self.stop_event.set(); break
                    elif not tunnel_packet:
                        logging.error(f"SOCKS C->T {self.session_id}: Failed to pack tunnel data!"); self.stop_event.set(); break
                # If not readable, select timed out, loop and check stop_event
        except socket.error as e: # Includes timeout if not handled by select, and other socket errors
            if not self.stop_event.is_set(): # Only log if not already stopping
                 logging.info(f"SOCKS C->T {self.session_id}: Socket error {e}. Client {self.client_address} likely disconnected.")
            self.stop_event.set()
        except Exception as e:
            if not self.stop_event.is_set():
                logging.error(f"SOCKS C->T {self.session_id}: Unexpected error: {e}", exc_info=True)
            self.stop_event.set()
        finally:
            logging.debug(f"SOCKS C->T {self.session_id}: Exiting loop. stop_event: {self.stop_event.is_set()}")
            self.stop_event.set() # Ensure it's set

    def _tunnel_to_client_loop(self):
        logging.debug(f"SOCKS T->C {self.session_id}: Started.")
        try:
            while not self.stop_event.is_set():
                try:
                    payload_from_tunnel = self.data_queue_from_tunnel.get(timeout=RELAY_TIMEOUT_QUEUE_GET)
                    # Check stop_event immediately after get, in case it was set while waiting
                    if self.stop_event.is_set() and not payload_from_tunnel: # if stopping and no packet, break
                         self.data_queue_from_tunnel.task_done() # must call if get succeeded even if no payload
                         break

                    if payload_from_tunnel:
                        logging.debug(f"SOCKS T->C {self.session_id}: Recv {len(payload_from_tunnel)} bytes from tunnel queue.")
                        self.client_socket.sendall(payload_from_tunnel)
                        logging.debug(f"SOCKS T->C {self.session_id}: Sent {len(payload_from_tunnel)} bytes to SOCKS client {self.client_address}.")
                    self.data_queue_from_tunnel.task_done()

                except Empty: # Queue.get timed out
                    if self.stop_event.is_set(): break # If signaled to stop, exit
                    continue # Otherwise, just a timeout, try again
                except socket.error as e: # e.g. SOCKS client disconnected while sending
                    if not self.stop_event.is_set():
                        logging.info(f"SOCKS T->C {self.session_id}: Socket error {e} sending to SOCKS client. Client likely disconnected.")
                    self.stop_event.set(); break
        except Exception as e:
            if not self.stop_event.is_set():
                logging.error(f"SOCKS T->C {self.session_id}: Unexpected error: {e}", exc_info=True)
            self.stop_event.set()
        finally:
            # Attempt to drain queue if stopping to prevent task_done errors on exit
            if self.stop_event.is_set():
                while not self.data_queue_from_tunnel.empty():
                    try:
                        self.data_queue_from_tunnel.get_nowait()
                        self.data_queue_from_tunnel.task_done()
                    except Empty:
                        break
            logging.debug(f"SOCKS T->C {self.session_id}: Exiting loop. stop_event: {self.stop_event.is_set()}")
            self.stop_event.set()

    def run(self):
        logging.info(f"SOCKS {self.session_id}: New SOCKS client from {self.client_address}")
        try:
            if not self._handle_socks_negotiation(): return
            if not self._handle_socks_request(): return
            if not self.target_ip_resolved:
                logging.error(f"SOCKS {self.session_id}: Target IP not resolved. Aborting.")
                return
            self._relay_data_streams()
        except Exception as e:
            logging.error(f"SOCKS {self.session_id}: Unhandled exception in run(): {e}", exc_info=True)
            self.stop_event.set() # Ensure cleanup if error occurs here
        finally:
            self.stop_event.set() # Make sure it's set for cleanup
            self._unregister_session()
            logging.info(f"SOCKS {self.session_id}: Session for {self.client_address} to {self.target_host_str}:{self.target_port_int} ended.")
            try:
                self.client_socket.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.client_socket.close()

def start_socks5_proxy_server(local_listen_host, local_listen_port, tunnel_srv_addr, tunnel_auth):
    global udp_tunnel_socket, tunnel_server_address_global, tunnel_auth_details_global

    tunnel_server_address_global = tunnel_srv_addr
    tunnel_auth_details_global = tunnel_auth

    try:
        udp_tunnel_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logging.info(f"UDP Tunnel Client component initialized for server {tunnel_srv_addr}")
    except Exception as e:
        logging.critical(f"Failed to create UDP socket: {e}"); return

    receiver_main_thread = threading.Thread(target=udp_receiver_thread_func, name="UDP-Receiver", daemon=True)
    receiver_main_thread.start()

    socks_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        socks_server_socket.bind((local_listen_host, local_listen_port))
        socks_server_socket.listen(20)
        logging.info(f"SOCKS5 proxy listening on {local_listen_host}:{local_listen_port}")

        active_session_threads = []
        while True:
            try:
                client_conn, client_addr = socks_server_socket.accept()
                session = SocksProxySessionHandler(client_conn, client_addr, tunnel_srv_addr, tunnel_auth)
                active_session_threads.append(session)
                session.start()
                # Prune dead threads (optional, as they are daemons)
                active_session_threads = [t for t in active_session_threads if t.is_alive()]
            except KeyboardInterrupt:
                logging.info("SOCKS5 server shutting down by user (Ctrl+C).")
                break
            except Exception as e:
                logging.error(f"SOCKS5 main accept loop error: {e}", exc_info=True)
                time.sleep(0.1)
    except OSError as e:
        logging.critical(f"SOCKS5: Could not bind to {local_listen_host}:{local_listen_port}. Error: {e}")
    finally:
        logging.info("SOCKS5 server closing main socket...")
        socks_server_socket.close()

        logging.info("Signaling all active SOCKS sessions to stop...")
        for session_thread in active_session_threads:
            if session_thread.is_alive():
                session_thread.stop_event.set()
        for session_thread in active_session_threads: # Second pass for join
             if session_thread.is_alive():
                session_thread.join(timeout=1.0)


        if udp_tunnel_socket:
            logging.info("Closing UDP tunnel socket.")
            udp_tunnel_socket.close() # Close after signaling sessions, as they might use it last minute

        if receiver_main_thread.is_alive():
            logging.info("Waiting for UDP receiver thread to exit (it's daemon, should exit with main).")
            # Daemon threads exit automatically, explicit join not strictly needed for them here
            # but udp_tunnel_socket closure might cause it to error out and stop.
        logging.info("SOCKS5 server shutdown complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Termux UDP Tunnel Client with SOCKS5 Proxy (Corrected)")
    parser.add_argument('--tunnel-host', required=True, help="IP of UDP tunnel server")
    parser.add_argument('--tunnel-port', required=True, type=int, help="Port of UDP tunnel server")
    parser.add_argument('--username', required=True, help="Username for tunnel auth")
    parser.add_argument('--password', required=True, help="Password for tunnel auth")
    parser.add_argument('--socks-host', default='127.0.0.1', help="Local host for SOCKS5 proxy (0.0.0.0 for LAN access)")
    parser.add_argument('--socks-port', default=1080, type=int, help="Local port for SOCKS5 proxy")
    parser.add_argument('--log-level', default='DEBUG', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="Logging level (default: DEBUG)")

    args = parser.parse_args()

    # Re-configure logging based on command-line arg
    logging.getLogger().handlers = [] # Clear previous basicConfig
    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format='%(asctime)s - %(levelname)s - %(threadName)s - [%(funcName)s] - %(message)s')


    current_tunnel_server_address = (args.tunnel_host, args.tunnel_port)
    current_tunnel_auth_details = {
        'username': args.username,
        'password': args.password
    }

    start_socks5_proxy_server(args.socks_host, args.socks_port, current_tunnel_server_address, current_tunnel_auth_details)