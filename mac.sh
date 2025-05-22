#!/bin/bash

# --- Configuration ---
PUBLIC_IP="190.83.222.248"
NGINX_UDP_PORTS=("8888" "8880" "443" "8989" "8443")
BADVPN_INTERNAL_PORT="7300"
SSH_PORT="22"
SOCKS_SERVER_PORT="1080" # Port Dante will listen on (on 127.0.0.1)

VPN_USER="vpnuser"
VPN_PASSWORD="YourStrongSocksPasswordHere" # CHANGE THIS!

# --- Script Start ---
echo "VPN Server with SOCKS5 & UDP Forwarding Setup"
echo "---------------------------------------------"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Use sudo." >&2
  exit 1
fi

# Update and install necessary packages
echo "[*] Updating system and installing dependencies..."
apt update
apt install -y nginx git cmake build-essential screen ufw cron dante-server

# --- Setup Firewall (UFW) ---
echo "[*] Configuring Firewall (UFW)..."
ufw allow $SSH_PORT/tcp        # SSH access
for port in "${NGINX_UDP_PORTS[@]}"; do
  ufw allow $port/udp        # Nginx public UDP ports
  echo "    Allowed UDP port $port"
done
# ufw allow $SOCKS_SERVER_PORT/tcp # Not needed publicly, Dante listens on 127.0.0.1
# ufw allow $BADVPN_INTERNAL_PORT/udp # Not strictly needed if Nginx is the only entry
ufw --force enable
ufw reload
echo "[*] UFW configured and reloaded."

# --- Create VPN User ---
echo "[*] Setting up VPN user '$VPN_USER'..."
if id "$VPN_USER" &>/dev/null; then
    echo "    User '$VPN_USER' already exists. Setting password."
else
    useradd -m -s /bin/false "$VPN_USER"
    echo "    User '$VPN_USER' created."
fi
echo "$VPN_USER:$VPN_PASSWORD" | chpasswd
echo "    Password for '$VPN_USER' set."

# --- Configure SSHD ---
echo "[*] Configuring SSHD..."
sed -i 's/#PermitTunnel no/PermitTunnel yes/' /etc/ssh/sshd_config
sed -i 's/PermitTunnel no/PermitTunnel yes/' /etc/ssh/sshd_config
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sed -i 's/AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config
if grep -q "^PasswordAuthentication" /etc/ssh/sshd_config; then
    sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
else
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
fi
systemctl restart sshd
echo "    SSHD reconfigured and restarted."

# --- Install badvpn-udpgw ---
echo "[*] Installing badvpn-udpgw..."
if [ -f /usr/local/bin/badvpn-udpgw ]; then
  echo "    badvpn-udpgw already seems to be installed. Skipping compilation."
else
  cd /tmp
  git clone https://github.com/ambrop72/badvpn.git
  cd badvpn
  mkdir build && cd build
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
  make install
  cd / && rm -rf /tmp/badvpn
  echo "    badvpn-udpgw installed to /usr/local/bin/badvpn-udpgw."
fi

# --- Create systemd service for badvpn-udpgw ---
echo "[*] Creating systemd service for badvpn-udpgw..."
cat <<EOF > /etc/systemd/system/badvpn-udpgw.service
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${BADVPN_INTERNAL_PORT} --max-clients 1024 --max-processes 4 --client-socket-sndbuf 0
User=nobody
Group=nogroup
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable badvpn-udpgw
systemctl start badvpn-udpgw
echo "    badvpn-udpgw service created, enabled, and started."

# --- Configure Dante SOCKS5 Server ---
echo "[*] Configuring Dante SOCKS5 server..."
# Detect primary network interface for 'external' line in danted.conf
EXTERNAL_INTERFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -z "$EXTERNAL_INTERFACE" ]; then
    echo "    WARNING: Could not automatically determine external network interface. Using 'eth0'."
    EXTERNAL_INTERFACE="eth0" # Fallback
fi
echo "    Using '$EXTERNAL_INTERFACE' as external interface for Dante."

cat <<EOF > /etc/danted.conf
logoutput: syslog /var/log/danted.log
internal: 127.0.0.1 port = ${SOCKS_SERVER_PORT}
# If your server has multiple IPs and you want Dante to use the public one for outgoing:
# internal: ${PUBLIC_IP} port = ${SOCKS_SERVER_PORT} # Less common for this SSH setup
external: ${EXTERNAL_INTERFACE}

# Method for client authentication (none, as SSH handles auth)
clientmethod: none
socksmethod: none
# If you wanted SOCKS-level auth (user must provide SOCKS user/pass additionally):
# socksmethod: username

user.privileged: root
user.notprivileged: nobody
user.unprivileged: nobody # For dante versions < 1.4.3

client pass {
    from: 127.0.0.1/32 to: 0.0.0.0/0
    log: error connect disconnect
}

# Allow SOCKS commands
socks pass {
    from: 127.0.0.1/32 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: error connect disconnect
}
# For return traffic from bind etc.
socks pass {
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bindreply udpreply
    log: error connect disconnect
}
EOF

systemctl enable danted
systemctl restart danted
echo "    Dante SOCKS5 server configured and restarted (listening on 127.0.0.1:${SOCKS_SERVER_PORT})."

# --- Configure Nginx for UDP Proxying ---
echo "[*] Configuring Nginx for UDP proxying..."
NGINX_CONF_STREAM="/etc/nginx/nginx-stream.conf"
STREAM_CONFIG="stream {\n"
STREAM_CONFIG+="    upstream udpgw_backend {\n"
STREAM_CONFIG+="        server 127.0.0.1:${BADVPN_INTERNAL_PORT};\n"
STREAM_CONFIG+="    }\n\n"

for port in "${NGINX_UDP_PORTS[@]}"; do
  STREAM_CONFIG+="    server {\n"
  STREAM_CONFIG+="        listen ${port} udp;       # Listen on 0.0.0.0 (all IPv4) for this port\n"
  STREAM_CONFIG+="        listen [::]:${port} udp;  # Listen on all IPv6 for this port (optional)\n"
  STREAM_CONFIG+="        proxy_pass udpgw_backend;\n"
  STREAM_CONFIG+="        proxy_timeout 3s;\n"
  STREAM_CONFIG+="        proxy_responses 0;\n"
  STREAM_CONFIG+="    }\n\n"
done
STREAM_CONFIG+="}\n"
echo -e "$STREAM_CONFIG" > "$NGINX_CONF_STREAM"

if ! grep -q "include /etc/nginx/nginx-stream.conf;" /etc/nginx/nginx.conf; then
  echo "include /etc/nginx/nginx-stream.conf;" >> /etc/nginx/nginx.conf
fi

nginx -t
if [ $? -eq 0 ]; then
  systemctl restart nginx
  echo "    Nginx configured and restarted."
else
  echo "    Nginx configuration test failed. Please check $NGINX_CONF_STREAM and /etc/nginx/nginx.conf" >&2
  exit 1
fi

# --- Final Instructions ---
echo ""
echo "-------------------------------------------------"
echo "VPN Server with SOCKS5 & UDP Setup Complete!"
echo "-------------------------------------------------"
echo ""
echo "Server Public IP: $PUBLIC_IP"
echo "SSH Port: $SSH_PORT"
echo "VPN/SSH Username: $VPN_USER"
echo "VPN/SSH Password: $VPN_PASSWORD (CHANGE THIS IF YOU HAVEN'T!)"
echo ""
echo "Server-Side SOCKS5 Proxy: 127.0.0.1:$SOCKS_SERVER_PORT (Access via SSH local port forwarding)"
echo ""
echo "Nginx is listening on UDP ports (forwarding to badvpn-udpgw):"
for port in "${NGINX_UDP_PORTS[@]}"; do
  echo "  - $PUBLIC_IP:$port (UDP)"
done
echo ""
echo "Client App Configuration (e.g., SocksIP, HTTP Injector/Custom):"
echo "  1. SSH Connection:"
echo "     SSH Host: $PUBLIC_IP"
echo "     SSH Port: $SSH_PORT"
echo "     Username: $VPN_USER"
echo "     Password: $VPN_PASSWORD"
echo ""
echo "  2. SSH Local Port Forwarding (for SOCKS5):"
echo "     Source Port (Local on your device): e.g., 1080 or 10800"
echo "     Destination Host (on Server): 127.0.0.1"
echo "     Destination Port (on Server): $SOCKS_SERVER_PORT"
echo ""
echo "  3. App's SOCKS5 Proxy Settings:"
echo "     Proxy Host: 127.0.0.1"
echo "     Proxy Port: The 'Source Port' you chose in step 2 (e.g., 1080 or 10800)"
echo "     Proxy Type: SOCKS5"
echo "     (No SOCKS username/password needed as SSH handles authentication)"
echo ""
echo "  4. UDP Forwarding (e.g., UDPCustom feature in the app):"
echo "     Remote UDP Port (on Server): Choose ONE of ${NGINX_UDP_PORTS[*]}"
echo "     Local UDP Port (Client-side, app's internal listener): Usually 7300, 7200, or configurable."
echo ""
echo "Make sure your client app supports SSH local port forwarding AND a separate UDP forwarding mechanism (like badvpn integration)."
echo "Check service status with:"
echo "  systemctl status sshd"
echo "  systemctl status badvpn-udpgw"
echo "  systemctl status danted"
echo "  systemctl status nginx"
echo "  sudo netstat -tulnp | grep -E '$SSH_PORT|${BADVPN_INTERNAL_PORT}|${SOCKS_SERVER_PORT}|$(IFS=\|; echo "${NGINX_UDP_PORTS[*]}")'"
echo "Dante logs: /var/log/danted.log or journalctl -u danted -f"
echo "-------------------------------------------------"

exit 0
