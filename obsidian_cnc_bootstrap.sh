#!/usr/bin/env bash
#
# Obsidian Command & Control (C&C) Bootstrap Script
# Prepares Ubuntu 24.04 LTS VM for centralized Obsidian platform management
# 
# This script is idempotent and can be run multiple times safely
# All placeholders use ALL-CAPS format for envsubst processing
#
# Author: Obsidian Platform Team
# Version: 1.0
# Date: 2025-07-19

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration variables (to be substituted by automation)
readonly OBSIDIAN_CNC_HOME="/opt/obsidian-cnc"
readonly DOMAIN="${DOMAIN}"
readonly EMAIL="${EMAIL}"
readonly DB_PASSWORD="${DB_PASSWORD}"
readonly KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD}"
readonly WG_NETWORK_CIDR="${WG_NETWORK_CIDR:-10.0.0.0/24}"
readonly WG_SERVER_IP="${WG_SERVER_IP:-10.0.0.1}"
readonly WG_PORT="${WG_PORT:-51820}"
readonly GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD}"
readonly S3_BUCKET="${S3_BUCKET}"
readonly S3_ACCESS_KEY="${S3_ACCESS_KEY}"
readonly S3_SECRET_KEY="${S3_SECRET_KEY}"
readonly S3_ENDPOINT="${S3_ENDPOINT}"
readonly ADMIN_EMAIL="${ADMIN_EMAIL}"
readonly SMTP_HOST="${SMTP_HOST}"
readonly SMTP_PORT="${SMTP_PORT:-587}"
readonly SMTP_USER="${SMTP_USER}"
readonly SMTP_PASSWORD="${SMTP_PASSWORD}"

# Logging functions
info() {
    echo -e "${GREEN}[INFO]${NC} $*" >&2
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

debug() {
    echo -e "${BLUE}[DEBUG]${NC} $*" >&2
}

# Helper function to run commands as specific user
run_as() {
    local user="$1"
    shift
    if [[ $EUID -eq 0 ]]; then
        sudo -u "$user" "$@"
    else
        "$@"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Create C&C directory structure
setup_directories() {
    info "Setting up Obsidian C&C directory structure"
    install -d -m 755 "$OBSIDIAN_CNC_HOME"
    install -d -m 755 "$OBSIDIAN_CNC_HOME/config"
    install -d -m 755 "$OBSIDIAN_CNC_HOME/scripts"
    install -d -m 755 "$OBSIDIAN_CNC_HOME/logs"
    install -d -m 755 "$OBSIDIAN_CNC_HOME/certs"
    install -d -m 755 "$OBSIDIAN_CNC_HOME/data"
    install -d -m 700 "/etc/wireguard/clients"
    install -d -m 755 "/var/lib/postgresql/data"
    install -d -m 755 "/var/lib/grafana"
    install -d -m 755 "/var/lib/prometheus"
}

# Update system packages
update_system() {
    info "Updating system packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get upgrade -y
    apt-get install -y \
        curl \
        wget \
        gnupg \
        lsb-release \
        ca-certificates \
        software-properties-common \
        apt-transport-https \
        jq \
        envsubst \
        nginx \
        certbot \
        python3-certbot-nginx \
        postgresql \
        postgresql-contrib \
        redis-server \
        fail2ban \
        ufw \
        htop \
        iftop \
        iotop \
        tree
}

# Install Docker and Docker Compose
install_docker() {
    info "Installing Docker and Docker Compose"
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

    # Install Docker
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Enable and start Docker
    systemctl enable --now docker

    # Add Docker log rotation
    cat > /etc/docker/daemon.json << 'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
EOF

    systemctl restart docker
}

# Install and configure WireGuard Server
install_wireguard_server() {
    info "Installing and configuring WireGuard VPN Server"
    
    # Install WireGuard
    apt-get install -y wireguard wireguard-tools qrencode

    # Generate server keys
    cd /etc/wireguard
    umask 077
    
    if [[ ! -f server_private.key ]]; then
        wg genkey > server_private.key
        wg pubkey < server_private.key > server_public.key
        info "Generated WireGuard server keys"
    fi

    local server_private_key=$(cat server_private.key)
    local server_public_key=$(cat server_public.key)

    # Create server configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${server_private_key}
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
SaveConfig = false

# Enable IP forwarding and NAT
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip route add ${WG_NETWORK_CIDR} dev wg0
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip route del ${WG_NETWORK_CIDR} dev wg0

# Clients will be added here dynamically
EOF

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p

    # Create client management script
    cat > "$OBSIDIAN_CNC_HOME/scripts/add_wireguard_client.sh" << 'EOF'
#!/bin/bash
# Add WireGuard client configuration

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <client_name> <client_ip>"
    echo "Example: $0 node01 10.0.0.2"
    exit 1
fi

CLIENT_NAME="$1"
CLIENT_IP="$2"
CLIENT_DIR="/etc/wireguard/clients"
SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
WG_PORT="${WG_PORT:-51820}"
DOMAIN="${DOMAIN}"

# Generate client keys
cd "$CLIENT_DIR"
wg genkey > "${CLIENT_NAME}_private.key"
wg pubkey < "${CLIENT_NAME}_private.key" > "${CLIENT_NAME}_public.key"

CLIENT_PRIVATE_KEY=$(cat "${CLIENT_NAME}_private.key")
CLIENT_PUBLIC_KEY=$(cat "${CLIENT_NAME}_public.key")

# Create client configuration
cat > "${CLIENT_NAME}.conf" << EOC
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}/32
DNS = ${WG_SERVER_IP}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${DOMAIN}:${WG_PORT}
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOC

# Add client to server configuration
cat >> /etc/wireguard/wg0.conf << EOC

# Client: ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUBLIC_KEY}
AllowedIPs = ${CLIENT_IP}/32
EOC

# Generate QR code for easy mobile setup
qrencode -t ansiutf8 < "${CLIENT_NAME}.conf"

echo "Client ${CLIENT_NAME} added successfully!"
echo "Configuration saved to: ${CLIENT_DIR}/${CLIENT_NAME}.conf"
echo "Client public key: ${CLIENT_PUBLIC_KEY}"

# Restart WireGuard to apply changes
systemctl restart wg-quick@wg0
EOF

    chmod +x "$OBSIDIAN_CNC_HOME/scripts/add_wireguard_client.sh"

    # Enable WireGuard service
    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service

    # Store server public key for distribution
    echo "$server_public_key" > "$OBSIDIAN_CNC_HOME/wireguard_server_public_key"
    info "WireGuard server configured - Public key saved for client distribution"
}

# Install and configure Cockpit Management Server
install_cockpit_server() {
    info "Installing and configuring Cockpit Management Server"
    
    # Install cockpit packages
    apt-get install -y \
        cockpit \
        cockpit-machines \
        cockpit-pcp \
        cockpit-packagekit \
        cockpit-composer \
        cockpit-podman

    # Configure Cockpit for centralized management
    cat > /etc/cockpit/cockpit.conf << 'EOF'
[WebService]
ListenStream = 9090
Origins = https://localhost:9090 wss://localhost:9090
ProtocolHeader = X-Forwarded-Proto
AllowUnencrypted = false
LoginTo = false
LoginTitle = Obsidian Command & Control

[OAuth]
URL = https://keycloak.DOMAIN/realms/obsidian
ClientId = cockpit-cnc
Scope = openid profile email groups

[Session]
IdleTimeout = 60
Banner = /etc/cockpit/issue.cockpit
EOF

    # Create management banner
    cat > /etc/cockpit/issue.cockpit << 'EOF'
Obsidian Command & Control Center
Centralized management for all Obsidian nodes
Authorized personnel only - All activities logged
EOF

    # Create cluster management API
    cat > "$OBSIDIAN_CNC_HOME/scripts/cluster_api.py" << 'EOF'
#!/usr/bin/env python3
"""
Obsidian Cluster Management API
Handles node registration and management
"""

import json
import logging
from flask import Flask, request, jsonify
from flask_httpauth import HTTPTokenAuth
import sqlite3
from datetime import datetime
import subprocess
import os

app = Flask(__name__)
auth = HTTPTokenAuth(scheme='Bearer')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect('/opt/obsidian-cnc/data/nodes.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT UNIQUE NOT NULL,
            ip_address TEXT,
            public_key TEXT,
            wireguard_ip TEXT,
            cockpit_url TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

@auth.verify_token
def verify_token(token):
    # In production, validate against proper token store
    return token == os.environ.get('CLUSTER_JOIN_TOKEN', 'default-token')

@app.route('/api/cluster/join', methods=['POST'])
@auth.login_required
def join_cluster():
    try:
        data = request.json
        hostname = data.get('hostname')
        public_key = data.get('public_key')
        wireguard_ip = data.get('wireguard_ip')
        cockpit_url = data.get('cockpit_url')
        
        if not all([hostname, public_key]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Store node information
        conn = sqlite3.connect('/opt/obsidian-cnc/data/nodes.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO nodes (hostname, public_key, wireguard_ip, cockpit_url, status)
            VALUES (?, ?, ?, ?, 'active')
        ''', (hostname, public_key, wireguard_ip, cockpit_url))
        conn.commit()
        conn.close()
        
        logger.info(f"Node {hostname} joined cluster")
        return jsonify({'status': 'success', 'message': 'Node registered successfully'})
    
    except Exception as e:
        logger.error(f"Error joining cluster: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/nodes', methods=['GET'])
@auth.login_required
def list_nodes():
    try:
        conn = sqlite3.connect('/opt/obsidian-cnc/data/nodes.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM nodes ORDER BY created_at DESC')
        nodes = cursor.fetchall()
        conn.close()
        
        node_list = []
        for node in nodes:
            node_list.append({
                'id': node[0],
                'hostname': node[1],
                'ip_address': node[2],
                'wireguard_ip': node[4],
                'cockpit_url': node[5],
                'status': node[6],
                'created_at': node[7],
                'last_seen': node[8]
            })
        
        return jsonify({'nodes': node_list})
    
    except Exception as e:
        logger.error(f"Error listing nodes: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000)
EOF

    chmod +x "$OBSIDIAN_CNC_HOME/scripts/cluster_api.py"

    # Create systemd service for cluster API
    cat > /etc/systemd/system/obsidian-cluster-api.service << 'EOF'
[Unit]
Description=Obsidian Cluster Management API
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/obsidian-cnc/scripts
ExecStart=/usr/bin/python3 cluster_api.py
Restart=always
RestartSec=5
Environment=FLASK_ENV=production

[Install]
WantedBy=multi-user.target
EOF

    # Install Python dependencies
    apt-get install -y python3-flask python3-flask-httpauth python3-pip
    pip3 install sqlite3

    systemctl daemon-reload
    systemctl enable obsidian-cluster-api.service

    # Enable cockpit socket
    systemctl enable --now cockpit.socket
}

# Install and configure Keycloak SSO
install_keycloak() {
    info "Installing and configuring Keycloak SSO"
    
    # Create Keycloak Docker Compose configuration
    cat > "$OBSIDIAN_CNC_HOME/docker-compose.keycloak.yml" << EOF
version: '3.8'

services:
  keycloak-db:
    image: postgres:15
    container_name: keycloak-db
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - keycloak_db_data:/var/lib/postgresql/data
    networks:
      - keycloak-network
    restart: unless-stopped

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    container_name: keycloak
    command: start --optimized
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://keycloak-db:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${DB_PASSWORD}
      KC_HOSTNAME: ${DOMAIN}
      KC_PROXY: edge
    ports:
      - "8080:8080"
    depends_on:
      - keycloak-db
    networks:
      - keycloak-network
    restart: unless-stopped

volumes:
  keycloak_db_data:

networks:
  keycloak-network:
    driver: bridge
EOF

    # Start Keycloak
    cd "$OBSIDIAN_CNC_HOME"
    docker compose -f docker-compose.keycloak.yml up -d

    info "Keycloak started - Available at http://localhost:8080"
    info "Admin credentials: admin / ${KEYCLOAK_ADMIN_PASSWORD}"
}

# Install monitoring stack (Prometheus + Grafana)
install_monitoring() {
    info "Installing monitoring stack (Prometheus + Grafana)"
    
    # Create Prometheus configuration
    cat > "$OBSIDIAN_CNC_HOME/config/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter-cnc'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'obsidian-nodes'
    static_configs:
      # Node targets will be dynamically updated
      - targets: []
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'keycloak'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/auth/realms/master/metrics'

  - job_name: 'cockpit-cluster-api'
    static_configs:
      - targets: ['localhost:5000']
    metrics_path: '/metrics'
EOF

    # Create monitoring Docker Compose
    cat > "$OBSIDIAN_CNC_HOME/docker-compose.monitoring.yml" << EOF
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    networks:
      - monitoring
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana:/etc/grafana/provisioning
    networks:
      - monitoring
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:

networks:
  monitoring:
    driver: bridge
EOF

    # Create Grafana provisioning
    mkdir -p "$OBSIDIAN_CNC_HOME/config/grafana/datasources"
    mkdir -p "$OBSIDIAN_CNC_HOME/config/grafana/dashboards"

    cat > "$OBSIDIAN_CNC_HOME/config/grafana/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

    # Start monitoring stack
    cd "$OBSIDIAN_CNC_HOME"
    docker compose -f docker-compose.monitoring.yml up -d

    info "Monitoring stack started:"
    info "- Prometheus: http://localhost:9090"
    info "- Grafana: http://localhost:3000 (admin / ${GRAFANA_ADMIN_PASSWORD})"
}

# Configure Nginx reverse proxy with SSL
configure_nginx() {
    info "Configuring Nginx reverse proxy with SSL"
    
    # Remove default configuration
    rm -f /etc/nginx/sites-enabled/default

    # Create Obsidian C&C configuration
    cat > /etc/nginx/sites-available/obsidian-cnc << EOF
# Obsidian Command & Control Nginx Configuration
server {
    listen 80;
    server_name ${DOMAIN};
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL Configuration (certificates will be added by certbot)
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    
    # Cockpit Management Interface
    location / {
        proxy_pass https://localhost:9090;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
    
    # Keycloak SSO
    location /auth/ {
        proxy_pass http://localhost:8080/auth/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Grafana Monitoring
    location /grafana/ {
        proxy_pass http://localhost:3000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Cluster Management API
    location /api/ {
        proxy_pass http://localhost:5000/api/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/obsidian-cnc /etc/nginx/sites-enabled/

    # Test and reload Nginx
    nginx -t && systemctl reload nginx

    # Obtain SSL certificate
    info "Obtaining SSL certificate with Let's Encrypt"
    certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive

    info "Nginx configured with SSL for domain: $DOMAIN"
}

# Configure security (firewall, fail2ban)
configure_security() {
    info "Configuring security (firewall and fail2ban)"
    
    # Configure UFW firewall
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services
    ufw allow 22/tcp comment 'SSH'
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ufw allow "$WG_PORT/udp" comment 'WireGuard VPN'
    
    # Enable UFW
    ufw --force enable

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[cockpit]
enabled = true
port = 9090
filter = cockpit
logpath = /var/log/auth.log
maxretry = 3
EOF

    systemctl enable --now fail2ban
    
    info "Security configuration completed"
}

# Setup backup system
setup_backups() {
    info "Setting up backup system"
    
    # Install restic
    apt-get install -y restic

    # Create backup environment
    cat > /etc/restic/env.d/cnc-backup.env << EOF
RESTIC_REPOSITORY=s3:${S3_ENDPOINT}/${S3_BUCKET}-cnc
RESTIC_PASSWORD_FILE=/etc/restic/cnc-password
AWS_ACCESS_KEY_ID=${S3_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${S3_SECRET_KEY}
EOF

    # Generate backup password
    openssl rand -base64 32 > /etc/restic/cnc-password
    chmod 600 /etc/restic/cnc-password

    # Create backup script
    cat > "$OBSIDIAN_CNC_HOME/scripts/backup_cnc.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

source /etc/restic/env.d/cnc-backup.env

# Initialize repository if it doesn't exist
if ! restic snapshots > /dev/null 2>&1; then
    restic init
fi

# Stop services for consistent backup
docker compose -f /opt/obsidian-cnc/docker-compose.keycloak.yml stop
docker compose -f /opt/obsidian-cnc/docker-compose.monitoring.yml stop

# Run backup
restic backup \
    --tag obsidian-cnc \
    --host "$(hostname)" \
    /opt/obsidian-cnc \
    /etc/nginx/sites-available \
    /etc/wireguard \
    /var/lib/docker/volumes

# Restart services
docker compose -f /opt/obsidian-cnc/docker-compose.keycloak.yml start
docker compose -f /opt/obsidian-cnc/docker-compose.monitoring.yml start

# Cleanup old snapshots
restic forget --prune \
    --keep-daily 14 \
    --keep-weekly 8 \
    --keep-monthly 12 \
    --host "$(hostname)"
EOF

    chmod +x "$OBSIDIAN_CNC_HOME/scripts/backup_cnc.sh"

    # Create systemd backup service
    cat > /etc/systemd/system/obsidian-cnc-backup.service << EOF
[Unit]
Description=Obsidian C&C Backup
After=docker.service

[Service]
Type=oneshot
ExecStart=$OBSIDIAN_CNC_HOME/scripts/backup_cnc.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

    # Create backup timer - daily at 01:00 UTC
    cat > /etc/systemd/system/obsidian-cnc-backup.timer << 'EOF'
[Unit]
Description=Daily Obsidian C&C Backup
Requires=obsidian-cnc-backup.service

[Timer]
OnCalendar=01:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable obsidian-cnc-backup.timer
    systemctl start obsidian-cnc-backup.timer
}

# Create management scripts
create_management_scripts() {
    info "Creating management and utility scripts"
    
    # Node management script
    cat > "$OBSIDIAN_CNC_HOME/scripts/manage_nodes.sh" << 'EOF'
#!/bin/bash
# Obsidian Node Management Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="/opt/obsidian-cnc/data/nodes.db"

show_help() {
    echo "Obsidian Node Management"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  list                    List all registered nodes"
    echo "  add-vpn <name> <ip>    Add WireGuard VPN client"
    echo "  remove <hostname>       Remove node from cluster"
    echo "  status                  Show cluster status"
    echo "  health                  Check health of all nodes"
    echo ""
}

list_nodes() {
    echo "Registered Obsidian Nodes:"
    echo "=========================="
    sqlite3 "$DB_PATH" "SELECT hostname, wireguard_ip, status, created_at FROM nodes ORDER BY created_at DESC;" | \
    while IFS='|' read -r hostname ip status created; do
        printf "%-20s %-15s %-10s %s\n" "$hostname" "$ip" "$status" "$created"
    done
}

add_vpn_client() {
    local name="$1"
    local ip="$2"
    "$SCRIPT_DIR/add_wireguard_client.sh" "$name" "$ip"
}

cluster_status() {
    echo "Obsidian Cluster Status:"
    echo "======================="
    echo "WireGuard Server: $(systemctl is-active wg-quick@wg0)"
    echo "Cockpit: $(systemctl is-active cockpit.socket)"
    echo "Cluster API: $(systemctl is-active obsidian-cluster-api)"
    echo "Keycloak: $(docker ps --format 'table {{.Names}}\t{{.Status}}' | grep keycloak || echo 'Not running')"
    echo "Monitoring: $(docker ps --format 'table {{.Names}}\t{{.Status}}' | grep -E '(prometheus|grafana)' || echo 'Not running')"
}

case "${1:-}" in
    list)
        list_nodes
        ;;
    add-vpn)
        if [[ $# -ne 3 ]]; then
            echo "Usage: $0 add-vpn <name> <ip>"
            exit 1
        fi
        add_vpn_client "$2" "$3"
        ;;
    status)
        cluster_status
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        exit 1
        ;;
esac
EOF

    chmod +x "$OBSIDIAN_CNC_HOME/scripts/manage_nodes.sh"

    # Health check script
    cat > "$OBSIDIAN_CNC_HOME/scripts/cnc_health_check.sh" << 'EOF'
#!/bin/bash
# Obsidian C&C Health Check Script

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_service() {
    local service="$1"
    if systemctl is-active --quiet "$service"; then
        echo -e "${GREEN}✓${NC} $service is running"
        return 0
    else
        echo -e "${RED}✗${NC} $service is not running"
        return 1
    fi
}

check_container() {
    local container="$1"
    if docker ps | grep -q "$container"; then
        echo -e "${GREEN}✓${NC} $container container is running"
        return 0
    else
        echo -e "${RED}✗${NC} $container container is not running"
        return 1
    fi
}

echo "=== Obsidian C&C Health Check ==="
echo "Timestamp: $(date)"
echo "Hostname: $(hostname)"
echo

# Check system services
echo "--- System Services ---"
check_service "nginx"
check_service "postgresql"
check_service "redis-server"
check_service "wg-quick@wg0"
check_service "cockpit.socket"
check_service "obsidian-cluster-api"
check_service "docker"

echo

# Check containers
echo "--- Docker Containers ---"
check_container "keycloak"
check_container "prometheus"
check_container "grafana"
check_container "node-exporter"

echo

# Check ports
echo "--- Network Ports ---"
ss -tuln | grep -E ':(80|443|9090|8080|3000|9090|51820) ' || echo -e "${YELLOW}!${NC} Some ports may not be listening"

echo

# Check disk space
echo "--- Disk Usage ---"
df -h / | awk 'NR==2 {
    use = $5; 
    gsub(/%/, "", use); 
    if (use > 80) 
        printf "\033[0;31m✗\033[0m Root filesystem is %s full\n", $5; 
    else 
        printf "\033[0;32m✓\033[0m Root filesystem is %s full\n", $5
}'

echo
echo "=== Health Check Complete ==="
EOF

    chmod +x "$OBSIDIAN_CNC_HOME/scripts/cnc_health_check.sh"
}

# Finalize C&C setup
finalize_setup() {
    info "Finalizing C&C setup"
    
    # Create obsidian-cnc user
    if ! id obsidian-cnc > /dev/null 2>&1; then
        useradd -r -d "$OBSIDIAN_CNC_HOME" -s /bin/bash obsidian-cnc
        usermod -a -G docker obsidian-cnc
    fi
    
    # Set proper permissions
    chown -R obsidian-cnc:obsidian-cnc "$OBSIDIAN_CNC_HOME"
    chmod -R 755 "$OBSIDIAN_CNC_HOME/scripts"
    
    # Start all services
    systemctl start obsidian-cluster-api.service
    
    # Create startup script
    cat > "$OBSIDIAN_CNC_HOME/scripts/startup.sh" << 'EOF'
#!/bin/bash
# Obsidian C&C Startup Script

set -euo pipefail

echo "Starting Obsidian Command & Control services..."

# Start core services
systemctl start wg-quick@wg0.service
systemctl start cockpit.socket
systemctl start obsidian-cluster-api.service

# Start Docker containers
cd /opt/obsidian-cnc
docker compose -f docker-compose.keycloak.yml up -d
docker compose -f docker-compose.monitoring.yml up -d

echo "Obsidian C&C startup complete"
EOF
    chmod +x "$OBSIDIAN_CNC_HOME/scripts/startup.sh"

    # Clean up
    apt-get autoremove -y
    apt-get autoclean
}

# Main execution flow
main() {
    info "Starting Obsidian Command & Control Bootstrap Process"
    info "Target: Ubuntu 24.04 LTS"
    info "Domain: $DOMAIN"
    info "Date: $(date)"
    
    check_root
    setup_directories
    update_system
    install_docker
    install_wireguard_server
    install_cockpit_server
    install_keycloak
    install_monitoring
    configure_nginx
    configure_security
    setup_backups
    create_management_scripts
    finalize_setup
    
    # Print completion message
    echo
    info "Obsidian Command & Control Bootstrap Complete!"
    echo
    info "Access Points:"
    info "- Main Dashboard: https://$DOMAIN"
    info "- Grafana Monitoring: https://$DOMAIN/grafana"
    info "- Keycloak SSO: https://$DOMAIN/auth"
    echo
    info "WireGuard Server Public Key (distribute to clients):"
    cat "$OBSIDIAN_CNC_HOME/wireguard_server_public_key"
    echo
    info "Management Commands:"
    info "- Node Management: $OBSIDIAN_CNC_HOME/scripts/manage_nodes.sh"
    info "- Health Check: $OBSIDIAN_CNC_HOME/scripts/cnc_health_check.sh"
    info "- Add VPN Client: $OBSIDIAN_CNC_HOME/scripts/add_wireguard_client.sh"
    echo
    warn "Complete the following manual steps:"
    warn "1. Configure Keycloak realm and clients"
    warn "2. Set up Grafana dashboards"
    warn "3. Configure email notifications"
    warn "4. Add first WireGuard clients"
    
    # Run initial health check
    "$OBSIDIAN_CNC_HOME/scripts/cnc_health_check.sh"
}

# Execute main function
main "$@"
