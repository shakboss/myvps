import socket
import struct
import hashlib
import time
import random

# --- Server/Client Shared Constants (should match server's) ---
REQ_AUTH = 0x01
REQ_DATA = 0x02

RESP_AUTH_OK = 0x81
RESP_AUTH_FAIL = 0x82
RESP_DATA_ACK_ECHO = 0x83
RESP_ERROR = 0xEE
RESP_STALE_PACKET = 0xEF

# Packet Structure (Client -> Server)
HEADER_FORMAT_CLIENT_PREFIX = "!BBBBHHH"
HEADER_CLIENT_PREFIX_LEN = struct.calcsize(HEADER_FORMAT_CLIENT_PREFIX)

# Packet Structure (Server -> Client)
HEADER_FORMAT_SERVER_PREFIX = "!BBBH"
HEADER_SERVER_PREFIX_LEN = struct.calcsize(HEADER_FORMAT_SERVER_PREFIX)

BUFFER_SIZE = 4096
SOCKET_TIMEOUT = 5.0 # seconds

# --- Helper Functions ---
def get_next_counter_val(current_val):
    """Calculates the next counter value, wrapping from 255 back to 1."""
    return (current_val % 255) + 1

# --- Client Class ---
class TunnelClient:
    def __init__(self, server_host, server_port, username, password):
        self.server_address = (server_host, server_port)
        self.username = username
        self.password = password # Sent plain, server hashes for comparison
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_socket.settimeout(SOCKET_TIMEOUT)

        self.authenticated = False
        self.sender_counter = random.randint(1, 255) # Start with a random counter
        self.last_server_counter = 0 # Track server's counter

        # Dummy port metadata for this client
        self.client_src_port_meta = 10000
        self.client_dst_port_meta = 20000

    def _create_packet(self, req_type, payload=b""):
        username_bytes = self.username.encode('utf-8')
        password_bytes = self.password.encode('utf-8')
        user_len = len(username_bytes)
        pass_len = len(password_bytes)
        payload_len = len(payload)

        if user_len > 255 or pass_len > 255:
            raise ValueError("Username or password too long (max 255 bytes)")

        header = struct.pack(HEADER_FORMAT_CLIENT_PREFIX,
                             req_type,
                             self.sender_counter,
                             user_len,
                             pass_len,
                             self.client_src_port_meta,
                             self.client_dst_port_meta,
                             payload_len)
        return header + username_bytes + password_bytes + payload

    def _parse_server_response(self, data):
        if len(data) < HEADER_SERVER_PREFIX_LEN:
            print("Malformed Server Response: Too short for header.")
            return None

        resp_type, server_counter, echoed_sender_counter, payload_len = \
            struct.unpack(HEADER_FORMAT_SERVER_PREFIX, data[:HEADER_SERVER_PREFIX_LEN])

        current_offset = HEADER_SERVER_PREFIX_LEN
        expected_total_len = current_offset + payload_len
        if len(data) < expected_total_len:
            print(f"Malformed Server Response: Too short for declared payload (Got {len(data)}, Expected {expected_total_len})")
            return None

        payload = data[current_offset : current_offset + payload_len]

        return {
            "type": resp_type,
            "server_counter": server_counter,
            "echoed_sender_counter": echoed_sender_counter,
            "payload_len": payload_len,
            "payload": payload
        }

    def authenticate(self):
        print(f"Attempting authentication as '{self.username}' with initial counter {self.sender_counter}...")
        # For AUTH, payload is typically empty or a specific challenge request
        auth_packet = self._create_packet(REQ_AUTH)

        try:
            self.client_socket.sendto(auth_packet, self.server_address)
            response_data, _ = self.client_socket.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            print("Authentication timed out. No response from server.")
            return False
        except Exception as e:
            print(f"Error during authentication send/recv: {e}")
            return False

        parsed_response = self._parse_server_response(response_data)
        if not parsed_response:
            return False

        print(f"Server AUTH response: Type={hex(parsed_response['type'])}, ServerCounter={parsed_response['server_counter']}, EchoedClientCounter={parsed_response['echoed_sender_counter']}")
        print(f"  Payload: {parsed_response['payload'].decode('utf-8', errors='ignore')}")


        if parsed_response["type"] == RESP_AUTH_OK:
            if parsed_response["echoed_sender_counter"] != self.sender_counter:
                print("Authentication Error: Server echoed wrong sender counter!")
                return False

            self.authenticated = True
            self.last_server_counter = parsed_response["server_counter"]
            # The sender_counter used for AUTH is now the "last used" one.
            # Next data packet should use an incremented counter.
            print(f"Authentication successful. Server counter is {self.last_server_counter}.")
            return True
        else:
            print("Authentication failed.")
            self.authenticated = False
            return False

    def send_data(self, message_str):
        if not self.authenticated:
            print("Not authenticated. Cannot send data.")
            return False

        self.sender_counter = get_next_counter_val(self.sender_counter)
        print(f"Sending DATA with client counter: {self.sender_counter}")
        payload_bytes = message_str.encode('utf-8')
        data_packet = self._create_packet(REQ_DATA, payload_bytes)

        try:
            self.client_socket.sendto(data_packet, self.server_address)
            response_data, _ = self.client_socket.recvfrom(BUFFER_SIZE)
        except socket.timeout:
            print("Data send/receive timed out.")
            return False
        except Exception as e:
            print(f"Error during data send/recv: {e}")
            return False

        parsed_response = self._parse_server_response(response_data)
        if not parsed_response:
            return False # Error already printed by parser

        print(f"Server DATA response: Type={hex(parsed_response['type'])}, ServerCounter={parsed_response['server_counter']}, EchoedClientCounter={parsed_response['echoed_sender_counter']}")

        if parsed_response["type"] == RESP_DATA_ACK_ECHO:
            if parsed_response["echoed_sender_counter"] != self.sender_counter:
                print("Data Error: Server echoed wrong sender counter!")
                # Potentially desynced, might need re-auth
                self.authenticated = False # A simple strategy
                return False

            # Validate server counter
            is_valid_server_counter = False
            if parsed_response["server_counter"] == 1 and self.last_server_counter > 1 : # Server counter wrapped
                is_valid_server_counter = True
            elif parsed_response["server_counter"] > self.last_server_counter:
                is_valid_server_counter = True
            # Handle case where server might have restarted and its counter is now 1
            # Or our last_server_counter was 0 (initial state after auth failure perhaps)
            elif self.last_server_counter == 0 and parsed_response["server_counter"] >= 1:
                 is_valid_server_counter = True


            if not is_valid_server_counter:
                print(f"Data Error: Invalid server counter. Expected >{self.last_server_counter} or 1 (if wrap), got {parsed_response['server_counter']}.")
                # self.authenticated = False # Consider how to handle this
                return False

            self.last_server_counter = parsed_response["server_counter"]
            echoed_payload = parsed_response['payload'].decode('utf-8', errors='ignore')
            print(f"  Server Echoed (SrvCtr: {self.last_server_counter}): {echoed_payload}")
            return True

        elif parsed_response["type"] == RESP_AUTH_FAIL:
            print("  Server Response: Authentication required or failed for data packet.")
            self.authenticated = False # Force re-auth
            return False
        elif parsed_response["type"] == RESP_STALE_PACKET:
            print("  Server Response: Stale or replayed packet (counter issue). Try again or re-authenticate.")
            # Client might need to re-sync its counter or re-authenticate
            return False
        else:
            print(f"  Server Response: Unknown or error response type {hex(parsed_response['type'])}")
            print(f"  Payload: {parsed_response['payload'].decode('utf-8', errors='ignore')}")
            return False

    def close(self):
        print("Closing client socket.")
        self.client_socket.close()

# --- Main Execution ---
if __name__ == "__main__":
    server_ip = input("Enter server IP address: ")
    server_port_str = input("Enter server port: ")
    username = input("Enter username: ")
    password = input("Enter password: ")

    try:
        server_port = int(server_port_str)
        if not (1 <= server_port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        print(f"Invalid port: {e}")
        exit(1)

    client = TunnelClient(server_ip, server_port, username, password)

    if client.authenticate():
        print("\n--- Authenticated. Type 'exit' to quit. ---")
        try:
            while True:
                message = input("Enter message to send: ")
                if message.lower() == 'exit':
                    break
                if not message:
                    continue

                if not client.send_data(message):
                    if not client.authenticated:
                        print("Session lost. Please restart client to re-authenticate.")
                        break
                    # Else, it was a transient error like timeout or stale packet, try again
        except KeyboardInterrupt:
            print("\nExiting due to user interrupt.")
        finally:
            client.close()
    else:
        print("Could not authenticate with the server.")
        client.close()

    print("Client finished.")