import socket
import struct
import threading
import logging
import argparse

# --- Configuration ---
# Server will listen on this host and port
SERVER_HOST = '0.0.0.0' # Listen on all available interfaces
# SERVER_PORT = 5000 # Choose a port for your tunnel server

# Allowed users (username: password)
# In a real application, use hashed passwords and a more secure storage
ALLOWED_USERS = {
    "user1": "pass1",
    "testuser": "testpass"
}

BUFFER_SIZE = 4096  # Max UDP packet size to handle
FORWARD_TIMEOUT = 5.0 # Seconds to wait for a response from the destination

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')

def parse_client_packet(data):
    """
    Parses the incoming packet from the client.
    Format:
    1. Username Length (1 byte)
    2. Username (variable)
    3. Password Length (1 byte)
    4. Password (variable)
    5. Sender Counter (1 byte)
    6. Receiver Counter (1 byte)
    7. Destination IP (4 bytes)
    8. Destination Port (2 bytes, network order)
    9. Payload (rest of the data)
    """
    try:
        offset = 0

        # Username
        username_len = data[offset]
        offset += 1
        username = data[offset:offset+username_len].decode('utf-8')
        offset += username_len

        # Password
        password_len = data[offset]
        offset += 1
        password = data[offset:offset+password_len].decode('utf-8')
        offset += password_len

        # Counters
        sender_counter = data[offset]
        offset += 1
        receiver_counter = data[offset]
        offset += 1

        # Destination IP and Port
        dest_ip_bytes = data[offset:offset+4]
        dest_ip_str = socket.inet_ntoa(dest_ip_bytes)
        offset += 4
        dest_port = struct.unpack('!H', data[offset:offset+2])[0] # !H for network order (big-endian) unsigned short
        offset += 2

        # Payload
        payload = data[offset:]

        # Validate counter ranges (1-255)
        if not (1 <= sender_counter <= 255 and 1 <= receiver_counter <= 255):
            logging.warning("Invalid counter range.")
            return None

        # Validate port range (1-65535)
        if not (1 <= dest_port <= 65535):
            logging.warning(f"Invalid destination port: {dest_port}")
            return None

        return {
            "username": username,
            "password": password,
            "sender_counter": sender_counter,
            "receiver_counter": receiver_counter,
            "dest_ip": dest_ip_str,
            "dest_port": dest_port,
            "payload": payload
        }

    except IndexError:
        logging.error("Malformed packet: Not enough data for header.")
        return None
    except struct.error:
        logging.error("Malformed packet: Struct unpack error (likely dest_port).")
        return None
    except UnicodeDecodeError:
        logging.error("Malformed packet: Username/password UTF-8 decode error.")
        return None
    except Exception as e:
        logging.error(f"Error parsing client packet: {e}")
        return None

def handle_client_request(data, client_addr, server_socket):
    """
    Handles a single client request:
    1. Parses the packet.
    2. Authenticates the user.
    3. Forwards the payload to the destination.
    4. Waits for a response from the destination.
    5. Sends the response (with counters) back to the client.
    """
    logging.debug(f"Received {len(data)} bytes from {client_addr}")

    parsed_info = parse_client_packet(data)
    if not parsed_info:
        logging.warning(f"Dropping malformed packet from {client_addr}")
        return

    username = parsed_info["username"]
    password = parsed_info["password"]
    sender_counter = parsed_info["sender_counter"]
    receiver_counter = parsed_info["receiver_counter"]
    dest_ip = parsed_info["dest_ip"]
    dest_port = parsed_info["dest_port"]
    payload_to_forward = parsed_info["payload"]

    # 1. Authentication
    if username not in ALLOWED_USERS or ALLOWED_USERS[username] != password:
        logging.warning(f"Authentication failed for user '{username}' from {client_addr}. Dropping.")
        return
    logging.info(f"Authenticated user '{username}' from {client_addr}")

    # 2. Forwarding
    forward_socket = None
    try:
        forward_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forward_socket.settimeout(FORWARD_TIMEOUT)

        logging.info(f"Forwarding {len(payload_to_forward)} bytes from {client_addr} (user: {username}, SC:{sender_counter}, RC:{receiver_counter}) to {dest_ip}:{dest_port}")
        forward_socket.sendto(payload_to_forward, (dest_ip, dest_port))

        # 3. Wait for response from destination
        try:
            response_data, response_server_addr = forward_socket.recvfrom(BUFFER_SIZE)
            logging.info(f"Received {len(response_data)} bytes from {response_server_addr} (dest for {client_addr})")

            # 4. Prepare response packet for original client
            #    Prepend original sender_counter, receiver_counter bytes
            response_to_client = bytes([sender_counter, receiver_counter]) + response_data

            # 5. Send response back to original client using the main server_socket
            server_socket.sendto(response_to_client, client_addr)
            logging.info(f"Sent {len(response_to_client)} bytes (response for {dest_ip}:{dest_port}) back to {client_addr}")

        except socket.timeout:
            logging.warning(f"Timeout waiting for response from {dest_ip}:{dest_port} for client {client_addr}")
        except Exception as e:
            logging.error(f"Error receiving/sending response for {client_addr} from {dest_ip}:{dest_port}: {e}")

    except socket.gaierror: # getaddrinfo error
        logging.error(f"DNS resolution failed for destination {dest_ip}. Cannot forward.")
    except Exception as e:
        logging.error(f"Error in forwarding logic for {client_addr} to {dest_ip}:{dest_port}: {e}")
    finally:
        if forward_socket:
            forward_socket.close()

def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((host, port))
        logging.info(f"UDP Tunnel Server listening on {host}:{port}")

        while True:
            try:
                data, client_addr = server_socket.recvfrom(BUFFER_SIZE)
                # Handle each client in a new thread to allow concurrent forwarding
                # For very high loads, a thread pool or asyncio might be more efficient
                client_handler_thread = threading.Thread(
                    target=handle_client_request,
                    args=(data, client_addr, server_socket),
                    daemon=True # So threads exit when main program exits
                )
                client_handler_thread.start()
            except ConnectionResetError:
                # This can happen on Windows if a previous sendto failed (e.g., ICMP port unreachable)
                logging.warning(f"ConnectionResetError from {client_addr}. Client might have closed connection.")
            except Exception as e:
                logging.error(f"Error in main server loop: {e}")

    except OSError as e:
        logging.critical(f"Could not bind to {host}:{port}. Error: {e}")
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        logging.info("Closing server socket.")
        server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Tunnel Server")
    parser.add_argument('--host', type=str, default=SERVER_HOST, help=f"Host to listen on (default: {SERVER_HOST})")
    parser.add_argument('--port', type=int, required=True, help="Port to listen on (e.g., 5000)")
    args = parser.parse_args()

    start_server(args.host, args.port)