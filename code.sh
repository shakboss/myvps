#!/bin/bash

# --- CONFIGURATION ---
# !!! REVIEW AND SET THESE VARIABLES !!!
YOUR_DOMAIN="ser.shaktt.site" # Optional: Your domain (e.g., yourserver.example.com). If set, Nginx will be configured for it.
EMAIL_FOR_LETSENCRYPT="khaliyqabdullah23@gmail.com" # Optional: Your email for Let's Encrypt (if YOUR_DOMAIN is set).
SSH_PORT="22" # Your current SSH port.

XRAY_SOCKS_PORT="1080" # Port for Xray SOCKS5 proxy
XRAY_SOCKS_USER="your_socks_user" # Username for SOCKS5 proxy
XRAY_SOCKS_PASS="YourStrongS0cksP@sswOrd" # Password for SOCKS5 proxy - CHANGE THIS!

UDP_ECHO_SERVER_PORT="1024" # Port for the Python UDP Echo Server
# --- END CONFIGURATION ---

# --- SCRIPT START ---
set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Print commands and their arguments as they are executed (for debugging).

echo "=== Starting Xray SOCKS5 & UDP Echo Server Setup ==="

# --- 0. PREREQUISITES & SYSTEM UPDATE ---
echo "[INFO] Updating system and installing basic packages..."
apt update
apt upgrade -y
apt install -y curl wget socat software-properties-common gnupg2 lsb-release ca-certificates apt-transport-https git unzip python3 python3-pip ufw

# --- 1. SET UP FIREWALL (UFW) ---
echo "[INFO] Configuring Firewall (UFW)..."
ufw allow $SSH_PORT/tcp                               # Your SSH Port
ufw allow 80/tcp                                  # For Let's Encrypt HTTP-01 & HTTP->HTTPS redirect
ufw allow 443/tcp                                 # For Nginx (HTTPS)
ufw allow $XRAY_SOCKS_PORT/tcp                    # For Xray SOCKS5 TCP
ufw allow $XRAY_SOCKS_PORT/udp                    # For Xray SOCKS5 UDP
ufw allow $UDP_ECHO_SERVER_PORT/udp               # For Python UDP Echo Server

ufw default deny incoming
ufw default allow outgoing
ufw --force enable
echo "[INFO] UFW status:"
ufw status verbose

# --- 2. INSTALL NGINX & CERTBOT (for general web serving & future TLS) ---
echo "[INFO] Installing Nginx and Certbot..."
apt install -y nginx certbot python3-certbot-nginx

# Basic Nginx config
NGINX_CONF_MESSAGE="Nginx is configured with a default page."
if [ -n "$YOUR_DOMAIN" ] && [ -n "$EMAIL_FOR_LETSENCRYPT" ]; then
    echo "[INFO] Configuring Nginx for domain: $YOUR_DOMAIN"
    cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $YOUR_DOMAIN www.$YOUR_DOMAIN _; # Catch-all for initial cert

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    systemctl restart nginx
    echo "[INFO] Attempting to obtain SSL certificate for $YOUR_DOMAIN..."
    # Ensure DNS A record for YOUR_DOMAIN points to this server's IP before running this
    # Adding a small delay for DNS propagation, although this is not foolproof
    echo "[INFO] Pausing for 15 seconds for potential DNS propagation..."
    sleep 15
    certbot --nginx -d "$YOUR_DOMAIN" --non-interactive --agree-tos -m "$EMAIL_FOR_LETSENCRYPT" --redirect || echo "[WARNING] Certbot failed. Check DNS and Nginx config. Manual run: certbot --nginx -d $YOUR_DOMAIN -m $EMAIL_FOR_LETSENCRYPT --redirect"
    NGINX_CONF_MESSAGE="Nginx is configured for $YOUR_DOMAIN with HTTPS (if certbot succeeded)."
else
    echo "[INFO] YOUR_DOMAIN or EMAIL_FOR_LETSENCRYPT not set. Configuring Nginx with default HTTP page."
    cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
fi

mkdir -p /var/www/html
echo "<html><body><h1>Server Setup In Progress</h1><p>$NGINX_CONF_MESSAGE</p><p>Xray SOCKS5 and UDP Echo server are being set up.</p></body></html>" > /var/www/html/index.html
chown -R www-data:www-data /var/www/html

systemctl enable nginx
systemctl restart nginx


# --- 3. INSTALL XRAY-CORE ---
echo "[INFO] Installing Xray-core..."
bash <(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)

# Configure Xray for SOCKS5 with UDP enabled
echo "[INFO] Configuring Xray for SOCKS5 (TCP/UDP)..."
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "0.0.0.0", // Listen on all interfaces. Change to "127.0.0.1" to only allow local access (e.g., via SSH tunnel)
      "port": $XRAY_SOCKS_PORT,
      "protocol": "socks",
      "settings": {
        "auth": "password",
        "accounts": [
          {"user": "$XRAY_SOCKS_USER", "pass": "$XRAY_SOCKS_PASS"}
        ],
        "udp": true, // Enable UDP relay for SOCKS5
        "ip": "0.0.0.0" // IP address Xray uses for outgoing UDP packets from SOCKS. 0.0.0.0 lets OS choose.
                        // Could be set to server's public IP if known and static.
      },
      "tag": "socks_in"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

systemctl enable xray
systemctl restart xray
echo "[INFO] Xray service configured and started."

# --- 4. CREATE PYTHON UDP ECHO SERVER ---
echo "[INFO] Setting up Python UDP Echo Server..."
mkdir -p /opt/udp_echo_server
cat > /opt/udp_echo_server/udp_echo_server.py <<EOF
import socket
import sys

# Configuration
HOST = '0.0.0.0'  # Listen on all available interfaces
PORT = $UDP_ECHO_SERVER_PORT
BUFFER_SIZE = 1024

def run_udp_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        server_socket.bind((HOST, PORT))
        print(f"[*] UDP Echo Server listening on {HOST}:{PORT}", flush=True)
    except socket.error as e:
        print(f"[!] Bind failed. Error: {e}", flush=True)
        sys.exit(1)

    try:
        while True:
            print(f"[*] Waiting to receive message on port {PORT}...", flush=True)
            data, addr = server_socket.recvfrom(BUFFER_SIZE)
            print(f"[*] Received {len(data)} bytes from {addr}", flush=True)
            print(f"[*] Data: {data.decode(errors='ignore')}", flush=True)

            if data:
                print(f"[*] Sending {len(data)} bytes of data back to {addr}", flush=True)
                server_socket.sendto(data, addr)
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.", flush=True)
    finally:
        server_socket.close()
        print("[*] Socket closed.", flush=True)

if __name__ == "__main__":
    run_udp_server()
EOF

chmod +x /opt/udp_echo_server/udp_echo_server.py

# --- 5. CREATE SYSTEMD SERVICE FOR UDP ECHO SERVER ---
echo "[INFO] Creating systemd service for UDP Echo Server..."
cat > /etc/systemd/system/udp-echo-server.service <<EOF
[Unit]
Description=Python UDP Echo Server
After=network.target xray.service

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/bin/python3 /opt/udp_echo_server/udp_echo_server.py
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udp-echo-server.service
systemctl start udp-echo-server.service
echo "[INFO] UDP Echo Server service created and started."

# --- 6. ENABLE IP FORWARDING (OPTIONAL BUT GOOD PRACTICE) ---
# For SOCKS proxy, Xray handles forwarding. This is more for VPN-like setups.
# However, it doesn't hurt to have it enabled.
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "[INFO] Enabling IP forwarding..."
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
fi

# --- 7. FINAL OUTPUT ---
SERVER_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="<your_server_ip>"
fi

DOMAIN_TO_USE="$SERVER_IP"
if [ -n "$YOUR_DOMAIN" ]; then
    DOMAIN_TO_USE="$YOUR_DOMAIN"
fi


echo ""
echo "============================================================"
echo "                    SETUP COMPLETE"
echo "============================================================"
echo ""
echo "SERVER IP: $SERVER_IP"
if [ -n "$YOUR_DOMAIN" ]; then
    echo "CONFIGURED DOMAIN: $YOUR_DOMAIN"
fi
echo ""
echo "--- Xray SOCKS5 Proxy Details ---"
echo "  Address:          $DOMAIN_TO_USE"
echo "  Port:             $XRAY_SOCKS_PORT"
echo "  Username:         $XRAY_SOCKS_USER"
echo "  Password:         $XRAY_SOCKS_PASS"
echo "  UDP Forwarding:   Enabled"
echo ""
echo "--- Python UDP Echo Server Details ---"
echo "  (This server listens for UDP packets directly on the VPS)"
echo "  Address:          $DOMAIN_TO_USE (or $SERVER_IP)"
echo "  Port:             $UDP_ECHO_SERVER_PORT (UDP)"
echo ""
echo "--- How to Test UDP Echo Server through Xray SOCKS5 ---"
echo "1. Configure your 'SocksIP app' or any SOCKS5 client (e.g., 'ncat'/'netcat' with proxy support, or a browser extension like FoxyProxy/SwitchyOmega for TCP part) to use the Xray SOCKS5 proxy above."
echo "2. In your application, attempt to send a UDP packet to:"
echo "   Target Host: $DOMAIN_TO_USE (or $SERVER_IP, where the UDP echo server is running)"
echo "   Target Port: $UDP_ECHO_SERVER_PORT"
echo "3. The UDP echo server should receive the packet (forwarded by Xray) and send it back."
echo "   Check server logs: journalctl -u udp-echo-server -f"
echo "   Check Xray logs: journalctl -u xray -f"
echo ""
echo "If you set Xray SOCKS5 'listen' to '127.0.0.1', you'll need to use SSH port forwarding to access it:"
echo "  ssh -L $XRAY_SOCKS_PORT:127.0.0.1:$XRAY_SOCKS_PORT user@$DOMAIN_TO_USE -p $SSH_PORT"
echo "  Then configure your client to use 127.0.0.1:$XRAY_SOCKS_PORT as the SOCKS proxy."
echo ""
echo "NGINX Web Server:"
if [ -n "$YOUR_DOMAIN" ] && [ -n "$EMAIL_FOR_LETSENCRYPT" ]; then
    echo "  Accessible at: http://$YOUR_DOMAIN and https://$YOUR_DOMAIN (if SSL cert succeeded)"
else
    echo "  Accessible at: http://$SERVER_IP"
fi
echo "  A test page is at the root."
echo ""
echo "RECOMMENDATION: Reboot the server to ensure all services start correctly in their final environment."
echo "  sudo reboot"
echo "============================================================"
