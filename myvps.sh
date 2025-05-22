#!/bin/bash

# --- CONFIGURATION ---
# !!! SET THESE VARIABLES !!!
YOUR_DOMAIN="yourdomain.com" # Your main domain
EMAIL_FOR_LETSENCRYPT="your_email@example.com" # For Let's Encrypt SSL
SSH_PORT="22" # Or your custom SSH port

# Generate a strong password for services or use UUIDs where appropriate
# Example: VLESS_UUID=$(cat /proc/sys/kernel/random/uuid)
# Example: TROJAN_PASSWORD=$(openssl rand -base64 16)

# --- SCRIPT START ---
set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Print commands and their arguments as they are executed (for debugging).

echo "=== Starting VPN & Proxy Server Setup ==="

# --- 0. PREREQUISITES & SYSTEM UPDATE ---
echo "Updating system and installing basic packages..."
apt update
apt upgrade -y
apt install -y curl wget socat software-properties-common gnupg2 lsb-release ca-certificates apt-transport-https git unzip

# --- 1. SET UP FIREWALL (UFW) ---
echo "Configuring Firewall (UFW)..."
ufw allow $SSH_PORT/tcp # Your SSH Port
ufw allow 80/tcp      # For Let's Encrypt HTTP-01 challenge & HTTP to HTTPS redirect
ufw allow 443/tcp     # For Nginx (HTTPS)
ufw allow 443/udp     # For Hysteria (QUIC) / OpenVPN UDP (if using 443)
# Add other ports if OpenVPN/Hysteria uses them explicitly
# ufw allow 1194/udp # Example for OpenVPN
# ufw allow 3478/udp # Example for Hysteria port hopping
# ufw allow 5000:8000/udp # Example range for Hysteria port hopping

ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose

# --- 2. INSTALL NGINX & CERTBOT (for SSL) ---
echo "Installing Nginx and Certbot..."
apt install -y nginx certbot python3-certbot-nginx

# Stop Nginx temporarily for Certbot standalone if needed, or use webroot
# systemctl stop nginx

# Obtain SSL Certificate
# Ensure your domain's A record is pointing to this server's IP
echo "Obtaining SSL certificate for $YOUR_DOMAIN..."
certbot certonly --nginx -d "$YOUR_DOMAIN" --non-interactive --agree-tos -m "$EMAIL_FOR_LETSENCRYPT"
# For wildcard, you might need DNS challenge:
# certbot certonly --dns-cloudflare --dns-cloudflare-credentials ~/.secrets/certbot/cloudflare.ini -d "$YOUR_DOMAIN" -d "*.$YOUR_DOMAIN" ...

# Create a basic Nginx config (we'll modify it later for proxies)
cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $YOUR_DOMAIN www.$YOUR_DOMAIN; # Add any other subdomains you want to redirect

    # Redirect all HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name $YOUR_DOMAIN; # Your main domain

    ssl_certificate /etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # Generate if not exists: openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048

    # Default root or a placeholder page
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # We will add proxy_pass locations for V2Ray, Trojan etc. here later
    # Example placeholder for V2Ray WebSocket:
    # location /v2rayws { # Replace with your chosen path
    #     proxy_redirect off;
    #     proxy_pass http://127.0.0.1:10001; # Xray listening port for this service
    #     proxy_http_version 1.1;
    #     proxy_set_header Upgrade \$http_upgrade;
    #     proxy_set_header Connection "upgrade";
    #     proxy_set_header Host \$host;
    #     proxy_set_header X-Real-IP \$remote_addr;
    #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    # }
}
EOF

# Create a dummy index.html for the root
mkdir -p /var/www/html
echo "<html><body><h1>Server Works!</h1><p>This is a placeholder page.</p></body></html>" > /var/www/html/index.html

systemctl restart nginx
systemctl enable nginx

# --- 3. INSTALL XRAY-CORE (for VMess, VLESS, Trojan, SOCKS5) ---
echo "Installing Xray-core..."
bash <(curl -L https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)

# Configure Xray - THIS IS THE MOST COMPLEX PART
# Generate UUIDs
VLESS_WS_UUID=$(xray uuid)
VMESS_WS_UUID=$(xray uuid)
TROJAN_PASSWORD=$(openssl rand -base64 16) # Or use a UUID if your client supports it for Trojan

# Paths for WebSocket (must match Nginx locations)
VLESS_WS_PATH="/your-vless-ws-path" # e.g., /vlws
VMESS_WS_PATH="/your-vmess-ws-path" # e.g., /vmws
TROJAN_WS_PATH="/your-trojan-ws-path" # e.g., /trws (optional, Trojan usually uses direct TCP)
TROJAN_GRPC_SERVICE_NAME="yourtrojangrpc"

# Ports Xray will listen on (localhost)
XRAY_VLESS_WS_PORT="10001"
XRAY_VMESS_WS_PORT="10002"
XRAY_TROJAN_PORT="10003" # For Trojan over TCP (direct, not proxied by Nginx for TLS)
XRAY_TROJAN_WS_PORT="10004" # For Trojan over WebSocket (proxied by Nginx for TLS)
XRAY_SOCKS5_PORT="10808" # SOCKS5, typically localhost only unless you secure it

# Create Xray config /usr/local/etc/xray/config.json
# This is a comprehensive example. Adjust to your needs.
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
    { // VLESS over WebSocket (Nginx handles TLS)
      "listen": "127.0.0.1",
      "port": $XRAY_VLESS_WS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$VLESS_WS_UUID",
            "level": 0,
            "email": "user1@$YOUR_DOMAIN"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$VLESS_WS_PATH"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    { // VMess over WebSocket (Nginx handles TLS)
      "listen": "127.0.0.1",
      "port": $XRAY_VMESS_WS_PORT,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$VMESS_WS_UUID",
            "alterId": 0, // Keep it simple, 0 for auto
            "level": 0,
            "email": "user2@$YOUR_DOMAIN"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$VMESS_WS_PATH"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    { // Trojan over TCP (Direct, Xray handles TLS if not behind Nginx for this)
      // If you want Nginx to handle TLS, use another inbound with network: "ws" like above
      // This example is for direct Trojan connection, so Xray needs certs
      "listen": "0.0.0.0", // Listen on all interfaces for direct Trojan
      "port": $XRAY_TROJAN_PORT, // Use a distinct port, or 443 if Nginx isn't using it
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASSWORD",
            "level": 0,
            "email": "user3@$YOUR_DOMAIN"
          }
        ],
        "fallbacks": [ // Optional: fallback to a webserver if Trojan handshake fails
           {
             "dest": "80" // Forwards to local port 80 (e.g., Nginx default page)
           }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls", // Xray handles TLS here
        "tlsSettings": {
          "serverName": "$YOUR_DOMAIN",
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem"
            }
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    // Add Trojan over WebSocket (Nginx handles TLS) - Similar to VLESS/VMess WS
    // {
    //   "listen": "127.0.0.1",
    //   "port": $XRAY_TROJAN_WS_PORT,
    //   "protocol": "trojan",
    //   "settings": {
    //     "clients": [ { "password": "$TROJAN_PASSWORD" } ]
    //   },
    //   "streamSettings": {
    //     "network": "ws",
    //     "wsSettings": { "path": "$TROJAN_WS_PATH" }
    //   }
    // },
    { // SOCKS5 Proxy (typically for local use or SSH tunnel)
      "listen": "127.0.0.1", // Or 0.0.0.0 if you want to expose it (NOT RECOMMENDED without auth)
      "port": $XRAY_SOCKS5_PORT,
      "protocol": "socks",
      "settings": {
        "auth": "password", // Change to "noauth" if not needed, or use "ip" for IP whitelist
        "accounts": [
          {"user": "socksuser", "pass": "sockspassword"} // Change these
        ],
        "udp": true // Enable UDP relay for SOCKS5
      },
      "tag": "socks_in"
    }
    // You can also add VLESS/VMess over gRPC if desired.
    // {
    //   "listen": "127.0.0.1",
    //   "port": 10005, // Another internal port
    //   "protocol": "vless",
    //   "settings": { /* ... VLESS clients ... */ },
    //   "streamSettings": {
    //     "network": "grpc",
    //     "grpcSettings": { "serviceName": "$TROJAN_GRPC_SERVICE_NAME" }
    //   }
    // }
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

# Now, update Nginx config to proxy to Xray WebSocket services
# Add these location blocks inside the `server { listen 443 ssl ... }` block in /etc/nginx/sites-available/default
# Make sure the paths and ports match your Xray config
# Example for VLESS WS:
# location /your-vless-ws-path { # Must match Xray wsSettings.path
#     if (\$request_method != 'GET') { return 403; } # Optional: only allow GET for WS upgrade
#     proxy_redirect off;
#     proxy_pass http://127.0.0.1:10001; # Xray VLESS WS listening port
#     proxy_http_version 1.1;
#     proxy_set_header Upgrade \$http_upgrade;
#     proxy_set_header Connection "upgrade";
#     proxy_set_header Host \$host;
#     proxy_set_header X-Real-IP \$remote_addr;
#     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
# }
# Do similarly for VMess WS, Trojan WS, and gRPC if you use them.
# For gRPC:
# location /yourtrojangrpc { # Must match Xray grpcSettings.serviceName
#     if (\$request_method != 'POST') { return 404; } # gRPC uses POST
#     client_max_body_size 0;
#     grpc_pass grpc://127.0.0.1:10005; # Xray gRPC listening port
# }

echo "Manually edit /etc/nginx/sites-available/default to add proxy_pass location blocks for Xray services."
echo "Add blocks like these INSIDE the 'server { listen 443 ssl ... }' block:"
echo "
    location $VLESS_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$XRAY_VLESS_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location $VMESS_WS_PATH {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$XRAY_VMESS_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    # Add more for Trojan WS, gRPC if configured
"
echo "After editing, run: nginx -t && systemctl reload nginx"
read -p "Press [Enter] to continue after editing Nginx config..."

nginx -t && systemctl reload nginx

# --- 4. INSTALL OPENVPN ---
echo "Installing OpenVPN..."
wget https://git.io/vpn -O openvpn-install.sh
chmod +x openvpn-install.sh
# Run openvpn-install.sh. It will ask questions.
# For protocol, you can choose UDP (faster) or TCP (more reliable over bad networks, easier to disguise on port 443 if Nginx isn't using it)
# If you want to run OpenVPN TCP on 443 and Nginx is also on 443, you'll need `sslh` or use a different port for OpenVPN.
# Easiest is to use a standard OpenVPN port like 1194 UDP.
AUTO_INSTALL_OPENVPN=y ./openvpn-install.sh # Review script options for non-interactive
# Or run interactively: ./openvpn-install.sh

# --- 5. INSTALL HYSTERIA ---
echo "Installing Hysteria..."
# Check Hysteria GitHub releases for the latest version and architecture
# https://github.com/apernet/hysteria/releases
HYSTERIA_VERSION="2.0.3" # Example, check latest
ARCH=$(uname -m)
[[ "$ARCH" == "x86_64" ]] && HYSTERIA_ARCH="amd64" || HYSTERIA_ARCH="arm64" # Basic check

wget "https://github.com/apernet/hysteria/releases/download/v${HYSTERIA_VERSION}/hysteria-linux-${HYSTERIA_ARCH}" -O /usr/local/bin/hysteria
chmod +x /usr/local/bin/hysteria

# Create Hysteria server config
mkdir -p /etc/hysteria
HYSTERIA_PORT="3478" # Example UDP port, make sure it's open in UFW
HYSTERIA_OBFS_PASSWORD=$(openssl rand -hex 16)

cat > /etc/hysteria/server.json <<EOF
{
  "listen": ":$HYSTERIA_PORT",
  "protocol": "udp", // "udp" is common, "wechat-video", "faketcp" are options
  "acme": { // If Hysteria handles its own TLS. If behind Nginx (not typical for Hysteria), this is different
    "domains": ["$YOUR_DOMAIN"], // Or a specific subdomain for Hysteria
    "email": "$EMAIL_FOR_LETSENCRYPT"
  },
  // OR if using self-signed or pre-existing certs (e.g., from Let's Encrypt via Nginx)
  // "cert": "/etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem",
  // "key": "/etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem",
  "obfs": "$HYSTERIA_OBFS_PASSWORD", // Obfuscation password
  "up_mbps": 100,
  "down_mbps": 500
  // "auth": { // Optional: user authentication
  //   "type": "password",
  //   "password": "your_hysteria_user_password"
  // },
  // "masquerade": "https://your.legitimate.site.com" // Optional: makes probing traffic look like it's going elsewhere
}
EOF

# Create systemd service for Hysteria
cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria Server Service (UDP Proxy)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/server.json
WorkingDirectory=/etc/hysteria
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hysteria-server
systemctl start hysteria-server
# Remember to open HYSTERIA_PORT in UFW: ufw allow $HYSTERIA_PORT/udp

# --- 6. IPTABLES FOR INTERNET ACCESS (NAT) ---
echo "Configuring iptables for NAT..."
# Enable IP forwarding
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
# For IPv6 if needed (Xray/OpenVPN might handle this)
# echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Get the main network interface (e.g., eth0, ens3)
# THIS IS A GUESS. VERIFY IT.
MAIN_INTERFACE=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
if [ -z "$MAIN_INTERFACE" ]; then
    echo "Could not auto-detect main network interface. Please set it manually in the script."
    # read -p "Enter main network interface (e.g., eth0): " MAIN_INTERFACE
    exit 1
fi
echo "Detected main interface: $MAIN_INTERFACE"

# Add NAT rule for IPv4
iptables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE
# If OpenVPN creates a tun0 interface and its subnet is 10.8.0.0/24
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $MAIN_INTERFACE -j MASQUERADE
# Xray often uses internal routing, but if it acts as a full VPN giving IPs, add its subnet too
# e.g., if Xray uses 10.1.0.0/24: iptables -t nat -A POSTROUTING -s 10.1.0.0/24 -o $MAIN_INTERFACE -j MASQUERADE

# For IPv6 (if your VPS has IPv6 and you want to route it)
# This is more complex and depends on your IPv6 prefix.
# ip6tables -t nat -A POSTROUTING -o $MAIN_INTERFACE -j MASQUERADE (generally not for IPv6, use direct routing)

# Persist iptables rules (install iptables-persistent)
apt install -y iptables-persistent
# It will ask to save current IPv4 and IPv6 rules. Say Yes.
# Or manually:
# iptables-save > /etc/iptables/rules.v4
# ip6tables-save > /etc/iptables/rules.v6

echo "=== Basic Server Setup Complete ==="
echo ""
echo "--- Client Configuration Info ---"
echo "DOMAIN: $YOUR_DOMAIN"
echo ""
echo "XRAY (VMess/VLESS/Trojan over WebSocket with Nginx TLS):"
echo "  VLESS + WebSocket:"
echo "    Address: $YOUR_DOMAIN"
echo "    Port: 443"
echo "    UUID: $VLESS_WS_UUID"
echo "    Encryption: none (TLS is by Nginx)"
echo "    Transport: ws"
echo "    Path: $VLESS_WS_PATH"
echo "    Host: $YOUR_DOMAIN"
echo "    TLS: enabled, serverName: $YOUR_DOMAIN (or SNI)"
echo ""
echo "  VMess + WebSocket:"
echo "    Address: $YOUR_DOMAIN"
echo "    Port: 443"
echo "    UUID: $VMESS_WS_UUID"
echo "    AlterId: 0"
echo "    Security: auto (or aes-128-gcm)"
echo "    Transport: ws"
echo "    Path: $VMESS_WS_PATH"
echo "    Host: $YOUR_DOMAIN"
echo "    TLS: enabled, serverName: $YOUR_DOMAIN (or SNI)"
echo ""
echo "  Trojan (Direct TCP, Xray handles TLS):"
echo "    Address: $YOUR_DOMAIN"
echo "    Port: $XRAY_TROJAN_PORT"
echo "    Password: $TROJAN_PASSWORD"
echo "    SNI/Peer: $YOUR_DOMAIN"
echo ""
# If you configured Trojan over WS via Nginx:
# echo "  Trojan + WebSocket:"
# echo "    Address: $YOUR_DOMAIN"
# echo "    Port: 443"
# echo "    Password: $TROJAN_PASSWORD"
# echo "    Transport: ws"
# echo "    Path: $TROJAN_WS_PATH"
# echo "    Host: $YOUR_DOMAIN"
# echo "    TLS: enabled, serverName: $YOUR_DOMAIN (or SNI)"
echo ""
echo "SOCKS5 Proxy (via Xray, typically for local SSH tunnel):"
echo "  Listen Address (on server): 127.0.0.1"
echo "  Listen Port (on server): $XRAY_SOCKS5_PORT"
echo "  Username: socksuser"
echo "  Password: sockspassword"
echo "  To use remotely: ssh -L 1080:$127.0.0.1:$XRAY_SOCKS5_PORT user@$YOUR_DOMAIN"
echo ""
echo "OpenVPN:"
echo "  Client config file usually in /root/clientname.ovpn. Download it securely."
echo "  Protocol and port depend on your choices during openvpn-install.sh."
echo ""
echo "Hysteria:"
echo "  Address: $YOUR_DOMAIN:$HYSTERIA_PORT"
echo "  Protocol: udp (or what you set)"
echo "  Auth (if set in Hysteria config): your_hysteria_user_password"
echo "  OBFS: $HYSTERIA_OBFS_PASSWORD"
echo "  Server Name (SNI): $YOUR_DOMAIN (or specific subdomain for Hysteria)"
echo "  ALPN: h3 (usually default for QUIC)"
echo "  Download Hysteria client for your OS."
echo ""
echo "SSH Tunnel (SOCKS5 proxy):"
echo "  Command on client: ssh -D 1080 -N -C user@$YOUR_DOMAIN -p $SSH_PORT"
echo "  Then configure browser/system to use SOCKS5 proxy 127.0.0.1:1080"
echo ""
echo "UDP Request / UDPmod: "
echo "  This is not a specific protocol. Hysteria is UDP-based. OpenVPN can be UDP."
echo "  SOCKS5 with Xray has UDP enabled ('udp': true)."
echo "  For general UDP forwarding, you might need specific iptables DNAT rules if not handled by the proxy/VPN protocol itself."
echo ""
echo "Clash Configuration:"
echo "  You'll need to manually create a Clash config (config.yaml) using the parameters above."
echo "  Example proxy entry for Clash (VMess WS):"
echo "  - name: \"MyVMessWS\""
echo "    type: vmess"
echo "    server: $YOUR_DOMAIN"
echo "    port: 443"
echo "    uuid: $VMESS_WS_UUID"
echo "    alterId: 0"
echo "    cipher: auto"
echo "    tls: true"
echo "    skip-cert-verify: false # Assuming valid Let's Encrypt cert"
echo "    servername: $YOUR_DOMAIN # SNI"
echo "    network: ws"
echo "    ws-opts:"
echo "      path: \"$VMESS_WS_PATH\""
echo "      headers:"
echo "        Host: $YOUR_DOMAIN"
echo ""
echo "Remember to secure your server, keep it updated, and monitor logs."
echo "Rebooting might be a good idea to ensure all services start correctly: sudo reboot"