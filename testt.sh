#!/bin/bash

# --- Configuration ---
PUBLIC_IP="190.83.222.248"
NGINX_UDP_PORTS=("8888" "8880" "443" "8989" "8443") # Public UDP ports Nginx will listen on
BADVPN_INTERNAL_PORT="7300" # Internal port for badvpn-udpgw
SSH_PORT="22" # Your server's SSH port

# New SSH user for VPN (will be created if it doesn't exist)
VPN_USER="one"
VPN_PASSWORD="one" # CHANGE THIS!

# --- Script Start ---
echo "VPN Server Setup Script"
echo "-----------------------"

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root. Use sudo." >&2
  exit 1
fi

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Update and install necessary packages
echo "[*] Updating system and installing dependencies..."
apt update
apt install -y nginx git cmake build-essential screen ufw cron

# --- Setup Firewall (UFW) ---
echo "[*] Configuring Firewall (UFW)..."
ufw allow $SSH_PORT/tcp        # SSH access
for port in "${NGINX_UDP_PORTS[@]}"; do
  ufw allow $port/udp        # Nginx public UDP ports
  echo "    Allowed UDP port $port"
done
ufw allow $BADVPN_INTERNAL_PORT/udp # Allow direct access for testing if needed, usually not required if Nginx is proxying
ufw --force enable # Enable UFW if not already (use with caution if you have other rules)
ufw reload
echo "[*] UFW configured and reloaded."

# --- Create VPN User ---
echo "[*] Setting up VPN user '$VPN_USER'..."
if id "$VPN_USER" &>/dev/null; then
    echo "    User '$VPN_USER' already exists. Setting password."
else
    useradd -m -s /bin/false "$VPN_USER" # /bin/false shell for SSH tunneling only
    echo "    User '$VPN_USER' created."
fi
echo "$VPN_USER:$VPN_PASSWORD" | chpasswd
echo "    Password for '$VPN_USER' set."

# --- Configure SSHD ---
echo "[*] Configuring SSHD..."
# Ensure PasswordAuthentication is yes if you want to use password (less secure than keys)
# Ensure AllowTcpForwarding is yes (default usually)
sed -i 's/#PermitTunnel no/PermitTunnel yes/' /etc/ssh/sshd_config
sed -i 's/PermitTunnel no/PermitTunnel yes/' /etc/ssh/sshd_config # If already uncommented
sed -i 's/#AllowTcpForwarding yes/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sed -i 's/AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config # If already uncommented
# Add or modify PasswordAuthentication
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
  mkdir build
  cd build
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
  make install
  # Cleanup
  cd /
  rm -rf /tmp/badvpn
  echo "    badvpn-udpgw installed to /usr/local/bin/badvpn-udpgw."
fi

# --- Create systemd service for badvpn-udpgw ---
echo "[*] Creating systemd service for badvpn-udpgw..."
cat <<EOF > /etc/systemd/system/badvpn-udpgw.service
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:${BADVPN_INTERNAL_PORT} --max-clients 512 --max-processes 4 --client-socket-sndbuf 0
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

# --- Configure Nginx for UDP Load Balancing/Proxying ---
echo "[*] Configuring Nginx for UDP proxying..."

NGINX_CONF_STREAM="/etc/nginx/nginx-stream.conf" # Separate file for stream config

# Create the upstream block for badvpn-udpgw
STREAM_CONFIG="stream {\n"
STREAM_CONFIG+="    upstream udpgw_backend {\n"
STREAM_CONFIG+="        server 127.0.0.1:${BADVPN_INTERNAL_PORT};\n"
STREAM_CONFIG+="    }\n\n"

# Create server blocks for each public UDP port
for port in "${NGINX_UDP_PORTS[@]}"; do
  STREAM_CONFIG+="    server {\n"
  STREAM_CONFIG+="        listen ${PUBLIC_IP}:${port} udp;\n"
  STREAM_CONFIG+="        listen [::]:${port} udp; # For IPv6 if needed, remove if not\n"
  STREAM_CONFIG+="        proxy_pass udpgw_backend;\n"
  STREAM_CONFIG+="        proxy_timeout 3s;\n" # Optional: Adjust timeout
  STREAM_CONFIG+="        proxy_responses 0;\n" # Important for UDP to not expect responses
  STREAM_CONFIG+="        # error_log /var/log/nginx/udp_${port}_error.log debug; # Uncomment for debugging specific port\n"
  STREAM_CONFIG+="    }\n\n"
done
STREAM_CONFIG+="}\n"

echo -e "$STREAM_CONFIG" > "$NGINX_CONF_STREAM"

# Include the stream configuration in the main nginx.conf
if ! grep -q "include /etc/nginx/nginx-stream.conf;" /etc/nginx/nginx.conf; then
  # Add include directive at the end of nginx.conf, but outside http {} block
  # This is a bit simplistic; ideally, it should be placed at the top level
  echo "include /etc/nginx/nginx-stream.conf;" >> /etc/nginx/nginx.conf
fi

# Test Nginx configuration and restart
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
echo "VPN Server Setup Complete!"
echo "-------------------------------------------------"
echo ""
echo "Your Public IP: $PUBLIC_IP"
echo "SSH Port: $SSH_PORT"
echo "VPN Username: $VPN_USER"
echo "VPN Password: $VPN_PASSWORD"
echo ""
echo "Nginx is listening on UDP ports:"
for port in "${NGINX_UDP_PORTS[@]}"; do
  echo "  - $PUBLIC_IP:$port (UDP)"
done
echo "These ports forward to badvpn-udpgw on 127.0.0.1:$BADVPN_INTERNAL_PORT"
echo ""
echo "Client Configuration (HTTP Injector/Custom):"
echo "  Connection Type: SSH"
echo "  SSH Host: $PUBLIC_IP"
echo "  SSH Port: $SSH_PORT"
echo "  Username: $VPN_USER"
echo "  Password: $VPN_PASSWORD"
echo ""
echo "  Enable UDP Forwarding (sometimes called UDPCustom or similar):"
echo "    Remote UDP Port: Choose one of ${NGINX_UDP_PORTS[*]}"
echo "    Local UDP Port: Usually 7300 or 7200 (client-side setting)"
echo ""
echo "Make sure to change the default VPN_PASSWORD!"
echo "You can check service status with:"
echo "  systemctl status sshd"
echo "  systemctl status badvpn-udpgw"
echo "  systemctl status nginx"
echo "  netstat -tulnp | grep -E '$SSH_PORT|${BADVPN_INTERNAL_PORT}|$(IFS=\|; echo "${NGINX_UDP_PORTS[*]}")'"
echo "-------------------------------------------------"

# Add cron job to keep badvpn-udpgw running if it crashes and systemd doesn't catch it (belt and suspenders)
# (crontab -l 2>/dev/null; echo "*/5 * * * * if ! pgrep -x badvpn-udpgw > /dev/null; then systemctl restart badvpn-udpgw; fi") | crontab -

exit 0
