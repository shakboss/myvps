import socket
import struct
import hashlib
import time
import threading

# --- Configuration ---
SERVER_HOST = '0.0.0.0'  # Listen on all available interfaces
SERVER_PORT = 9999       # The port your server will listen on
BUFFER_SIZE = 4096       # Max UDP packet size (payload part can be smaller)

# --- User Credentials (Store pre-hashed passwords in a real production system) ---
# Passwords here are hashed for comparison. Clients would send plain passwords
# which this server then hashes to compare with these stored hashes.
USERS = {
    "user1": hashlib.sha256("pass1".encode()).hexdigest(),
    "user2": hashlib.sha256("pass2".encode()).hexdigest()
}

# --- Request/Response Types ---
REQ_AUTH = 0x01
REQ_DATA = 0x02

RESP_AUTH_OK = 0x81
RESP_AUTH_FAIL = 0x82
RESP_DATA_ACK_ECHO = 0x83
RESP_ERROR = 0xEE
RESP_STALE_PACKET = 0xEF # For counter issues

# --- Server State ---
# (client_addr) -> {
#     "username": str,
#     "last_seen": float,
#     "client_counter": int, # Last successfully validated client sender_counter
#     "server_counter": int  # Server's next response counter for this session
# }
authenticated_sessions = {}
session_lock = threading.Lock()
SESSION_TIMEOUT = 300 # 5 minutes for inactive sessions

# --- Helper Functions ---
def hash_password(password):
    """Hashes a password string for comparison."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_next_counter_val(current_val):
    """Calculates the next counter value, wrapping from 255 back to 1."""
    return (current_val % 255) + 1

# --- Packet Handling ---
# Client -> Server Packet Structure:
# REQUEST_TYPE (1 byte), SENDER_COUNTER (1 byte),
# USERNAME_LEN (1 byte), PASSWORD_LEN (1 byte),
# CLIENT_SRC_PORT_METADATA (2 bytes, H), CLIENT_DST_PORT_METADATA (2 bytes, H),
# PAYLOAD_LEN (2 bytes, H)
# USERNAME (variable), PASSWORD (variable), PAYLOAD (variable)
HEADER_FORMAT_CLIENT_PREFIX = "!BBBBHHH" # Network byte order
HEADER_CLIENT_PREFIX_LEN = struct.calcsize(HEADER_FORMAT_CLIENT_PREFIX)

# Server -> Client Packet Structure:
# RESPONSE_TYPE (1 byte), SERVER_COUNTER (1 byte),
# ECHOED_SENDER_COUNTER (1 byte), PAYLOAD_LEN (2 bytes, H)
# PAYLOAD (variable)
HEADER_FORMAT_SERVER_PREFIX = "!BBBH" # Network byte order
HEADER_SERVER_PREFIX_LEN = struct.calcsize(HEADER_FORMAT_SERVER_PREFIX)


def parse_client_packet(data):
    """Parses the incoming client packet."""
    if len(data) < HEADER_CLIENT_PREFIX_LEN:
        print(f"Malformed Packet: Too short for header prefix ({len(data)} < {HEADER_CLIENT_PREFIX_LEN})")
        return None

    req_type, sender_counter, user_len, pass_len, client_src_port, client_dst_port, payload_len = \
        struct.unpack(HEADER_FORMAT_CLIENT_PREFIX, data[:HEADER_CLIENT_PREFIX_LEN])

    current_offset = HEADER_CLIENT_PREFIX_LEN
    expected_total_len = current_offset + user_len + pass_len + payload_len
    if len(data) < expected_total_len:
        print(f"Malformed Packet: Too short for declared lengths (Got {len(data)}, Expected {expected_total_len})")
        return None

    try:
        username = data[current_offset : current_offset + user_len].decode('utf-8')
        current_offset += user_len

        password = data[current_offset : current_offset + pass_len].decode('utf-8')
        current_offset += pass_len

        payload = data[current_offset : current_offset + payload_len]
    except UnicodeDecodeError:
        print("Malformed Packet: Username or Password UTF-8 decode error.")
        return None

    return {
        "type": req_type,
        "sender_counter": sender_counter,
        "username": username,
        "password": password, # Client sends plain, server will hash for comparison
        "client_src_port_meta": client_src_port,
        "client_dst_port_meta": client_dst_port,
        "payload_len": payload_len,
        "payload": payload
    }

def create_server_response(resp_type, server_counter, echoed_sender_counter, payload=b""):
    """Creates a response packet to send to the client."""
    payload_len = len(payload)
    header = struct.pack(HEADER_FORMAT_SERVER_PREFIX,
                         resp_type,
                         server_counter,
                         echoed_sender_counter,
                         payload_len)
    return header + payload

def handle_auth_request(packet_data, client_addr, server_socket):
    """Handles an authentication request."""
    username = packet_data["username"]
    password_client_sent = packet_data["password"]
    sender_counter = packet_data["sender_counter"] # Client's current counter

    hashed_client_pass = hash_password(password_client_sent)

    response_payload = b""
    response_type = RESP_AUTH_FAIL
    server_resp_counter = 0 # Will be set if auth ok

    if username in USERS and USERS[username] == hashed_client_pass:
        with session_lock:
            # Initialize or update session
            server_resp_counter = get_next_counter_val(0) # Start server counter for this session at 1
            authenticated_sessions[client_addr] = {
                "username": username,
                "last_seen": time.time(),
                "client_counter": sender_counter, # Store client's counter from this AUTH packet as baseline
                "server_counter": server_resp_counter
            }
        response_type = RESP_AUTH_OK
        response_payload = b"Authentication successful"
        print(f"AUTH_OK: User '{username}' from {client_addr} (counter: {sender_counter}) authenticated.")
    else:
        response_payload = b"Authentication failed"
        print(f"AUTH_FAIL: User '{username}' from {client_addr} failed authentication.")
        # No session created or updated if auth fails

    response = create_server_response(response_type, server_resp_counter, sender_counter, response_payload)
    server_socket.sendto(response, client_addr)

def handle_data_request(packet_data, client_addr, server_socket):
    """Handles a data request from an authenticated client."""
    req_username = packet_data["username"]
    req_password_client_sent = packet_data["password"]
    req_sender_counter = packet_data["sender_counter"]
    payload = packet_data["payload"]
    client_src_port_meta = packet_data["client_src_port_meta"]
    client_dst_port_meta = packet_data["client_dst_port_meta"]

    session = None
    with session_lock:
        if client_addr in authenticated_sessions:
            session = authenticated_sessions[client_addr]

    if not session:
        print(f"DATA_REJECT (NO_SESSION): No active session for {client_addr}. Sending AUTH_FAIL.")
        response = create_server_response(RESP_AUTH_FAIL, 0, req_sender_counter, b"Not authenticated. Please authenticate first.")
        server_socket.sendto(response, client_addr)
        return

    # --- CRITICAL: Re-validate credentials from the data packet against the session user ---
    hashed_req_password = hash_password(req_password_client_sent)
    if req_username != session["username"] or USERS.get(session["username"]) != hashed_req_password:
        print(f"DATA_REJECT (CRED_MISMATCH): Credential mismatch for data packet from {client_addr}. Expected user '{session['username']}'.")
        # Consider invalidating session here or rate limiting, as this is suspicious.
        # For now, just send auth fail.
        response = create_server_response(RESP_AUTH_FAIL, 0, req_sender_counter, b"Data packet credential mismatch.")
        server_socket.sendto(response, client_addr)
        return

    # --- Counter Validation ---
    # session["client_counter"] stores the last successfully processed counter from this client.
    session_last_client_counter = session["client_counter"]
    valid_counter = False

    if req_sender_counter == 1 and session_last_client_counter > 1:
        # Client explicitly reset its counter to 1. Accept this.
        # Ideally, a counter reset implies re-authentication for stronger security.
        valid_counter = True
        print(f"INFO: Client {client_addr} counter reset to 1 (was {session_last_client_counter}).")
    elif req_sender_counter > session_last_client_counter:
        # Standard increment.
        valid_counter = True
    # Case: req_sender_counter == session_last_client_counter
    # This could happen if the client re-sent an AUTH packet and then immediately a DATA packet with the same counter.
    # If the AUTH packet updated session["client_counter"], then this DATA packet might be "stale" if not handled.
    # The current logic: AUTH sets the baseline. DATA must be > or a reset to 1.
    # So, if client sends AUTH (counter N), session["client_counter"] becomes N.
    # If client then sends DATA (counter N), `N > N` is false. `N==1 and N>1` is false. This would be rejected.
    # Client MUST increment counter for DATA packets after an AUTH.

    if not valid_counter:
        print(f"DATA_REJECT (STALE_COUNTER): Stale/replayed counter from {client_addr}. SessCounter: {session_last_client_counter}, PktCounter: {req_sender_counter}.")
        # Server counter for error response: use current session's server_counter or 0 if it's problematic
        error_server_counter = session.get("server_counter", 0) # Use existing or 0
        response = create_server_response(RESP_STALE_PACKET, error_server_counter, req_sender_counter, b"Stale or replayed packet counter.")
        server_socket.sendto(response, client_addr)
        return

    # If counter is valid, update session state
    with session_lock: # Re-acquire lock for update
        session["last_seen"] = time.time()
        session["client_counter"] = req_sender_counter # Update to this packet's counter
        session["server_counter"] = get_next_counter_val(session["server_counter"])
        # Ensure session object in authenticated_sessions is updated if it was copied
        authenticated_sessions[client_addr] = session


    print(f"DATA_RECV: User '{session['username']}' from {client_addr} sent {len(payload)} bytes.")
    print(f"  Client Meta: SrcP={client_src_port_meta}, DstP={client_dst_port_meta}. ClientCtr={req_sender_counter}, ServRespCtr={session['server_counter']}")

    # --- Tunneling Logic (Echo for this example) ---
    # WARNING: PAYLOAD IS NOT ENCRYPTED. THIS IS NOT A SECURE VPN.
    # In a real VPN, you would:
    # 1. DECRYPT payload here.
    # 2. Forward the inner (decrypted) packet to its actual destination (e.g., internet, another VPN client).
    # 3. Receive a response from the destination.
    # 4. ENCRYPT that response.
    # 5. Send the encrypted response back in the tunnel.
    response_payload = payload # Echoing the received payload

    response = create_server_response(RESP_DATA_ACK_ECHO,
                                      session["server_counter"],
                                      req_sender_counter, # Echo back the client's sender counter
                                      response_payload)
    server_socket.sendto(response, client_addr)
    print(f"DATA_ECHO: Sent {len(response_payload)} bytes back to {client_addr}")


def cleanup_inactive_sessions():
    """Periodically removes inactive sessions."""
    while True:
        time.sleep(60) # Check every minute
        now = time.time()
        with session_lock:
            inactive_addrs = [
                addr for addr, session_data in authenticated_sessions.items()
                if now - session_data["last_seen"] > SESSION_TIMEOUT
            ]
            for addr in inactive_addrs:
                print(f"SESSION_TIMEOUT: Removing inactive session for {authenticated_sessions[addr]['username']}@{addr}")
                del authenticated_sessions[addr]

# --- Main Server Loop ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        print(f"UDP Tunnel Server (Corrected) listening on {SERVER_HOST}:{SERVER_PORT}")
        print("WARNING: THIS SERVER DOES NOT ENCRYPT TUNNELED DATA. NOT FOR PRODUCTION VPN USE.")
        print("         IT IS FOR EDUCATIONAL PURPOSES TO DEMONSTRATE PROTOCOL LAYERING.")

        cleanup_thread = threading.Thread(target=cleanup_inactive_sessions, daemon=True)
        cleanup_thread.start()

        while True:
            try:
                data, client_addr = server_socket.recvfrom(BUFFER_SIZE)
                # print(f"\nReceived {len(data)} bytes from {client_addr}") # Verbose

                packet_data = parse_client_packet(data)
                if not packet_data:
                    # parse_client_packet already prints error, no need to send response for fully malformed packets
                    print(f"Discarding malformed packet from {client_addr}.")
                    continue

                if packet_data["type"] == REQ_AUTH:
                    handle_auth_request(packet_data, client_addr, server_socket)
                elif packet_data["type"] == REQ_DATA:
                    handle_data_request(packet_data, client_addr, server_socket)
                else:
                    print(f"Unknown request type {packet_data['type']} from {client_addr}")
                    # Create a generic error response
                    # We don't have a session server_counter, use 0. Echo client's sender_counter if available.
                    error_resp = create_server_response(RESP_ERROR, 0, packet_data.get("sender_counter",0), b"Unknown request type")
                    server_socket.sendto(error_resp, client_addr)

            except ConnectionResetError: # Mainlys on Windows
                print(f"ConnectionResetError from {client_addr}. Client might have closed abruptly or port unreachable.")
            except struct.error as e: # Should be caught by parse_client_packet, but as a fallback
                print(f"Packet Struct Unpacking Error: {e} from {client_addr}. Malformed packet.")
            except Exception as e:
                print(f"General Error processing packet from {client_addr}: {e}")
                # Avoid sending response if client_addr might be spoofed or error is severe

    except OSError as e:
        print(f"Server socket OS error: {e}")
    except KeyboardInterrupt:
        print("\nServer shutting down due to KeyboardInterrupt.")
    finally:
        print("Closing server socket.")
        server_socket.close()

if __name__ == "__main__":
    start_server()