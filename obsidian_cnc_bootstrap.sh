#!/usr/bin/env bash
#
# Obsidian Command & Control (C&C) Bootstrap Script
# Optimized for headless deployment on Hetzner Cloud
# 
# This script is fully autonomous with self-error correction
# All operations are logged to /var/log/obsidian-cnc-bootstrap.log
#
# Author: Obsidian Platform Team
# Version: 2.1
# Date: 2025-01-19

set -euo pipefail

# Detect execution environment
readonly IS_HEADLESS="${HEADLESS:-true}"
readonly IS_INTERACTIVE=$([ -t 1 ] && [ -t 2 ] && echo "true" || echo "false")

# Logging setup - handle headless vs interactive differently
readonly LOG_FILE="/var/log/obsidian-cnc-bootstrap.log"
readonly ERROR_LOG_FILE="/var/log/obsidian-cnc-bootstrap-errors.log"
readonly HEADLESS_LOG_FILE="/root/obsidian-cnc-bootstrap.log"
readonly HEADLESS_ERROR_LOG_FILE="/root/obsidian-cnc-bootstrap-errors.log"

# Ensure log files exist and are writable
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "/root"
touch "$LOG_FILE" "$ERROR_LOG_FILE" "$HEADLESS_LOG_FILE" "$HEADLESS_ERROR_LOG_FILE"
chmod 644 "$LOG_FILE" "$ERROR_LOG_FILE"
chmod 600 "$HEADLESS_LOG_FILE" "$HEADLESS_ERROR_LOG_FILE"

# Smart output redirection based on environment
if [[ "$IS_HEADLESS" == "true" || "$IS_INTERACTIVE" == "false" ]]; then
    # Headless mode - direct to files only (both system and root locations)
    exec 1> >(tee -a "$LOG_FILE" >> "$HEADLESS_LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG_FILE" >> "$HEADLESS_ERROR_LOG_FILE")
else
    # Interactive mode - use tee for dual output
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG_FILE" >&2)
fi

# Configuration variables (to be substituted by automation)
readonly OBSIDIAN_CNC_HOME="/opt/obsidian-cnc"
readonly DOMAIN="${DOMAIN:-localhost}"
readonly EMAIL="${EMAIL:-admin@localhost}"
readonly DB_PASSWORD="${DB_PASSWORD:-$(openssl rand -base64 32)}"
readonly KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-$(openssl rand -base64 32)}"
readonly WG_NETWORK_CIDR="${WG_NETWORK_CIDR:-10.0.0.0/24}"
readonly WG_SERVER_IP="${WG_SERVER_IP:-10.0.0.1}"
readonly WG_PORT="${WG_PORT:-51820}"
readonly GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-$(openssl rand -base64 32)}"

# Enhanced self-correction parameters
readonly MAX_RETRIES=5
readonly INITIAL_RETRY_DELAY=10
readonly HEALTH_CHECK_TIMEOUT=120
readonly SERVICE_START_TIMEOUT=180

# Auto-detect network interface with better fallbacks
detect_network_interface() {
    local interface
    
    # Try multiple methods to detect primary interface
    interface=$(ip route | grep '^default' | head -n1 | awk '{print $5}' 2>/dev/null || echo "")
    
    if [[ -z "$interface" ]]; then
        # Fallback: find first active interface (excluding loopback)
        interface=$(ip link show | grep -E '^[0-9]+: (eth|ens|enp)' | head -n1 | cut -d: -f2 | tr -d ' ' || echo "")
    fi
    
    if [[ -z "$interface" ]]; then
        # Final fallback for cloud providers
        interface="eth0"
    fi
    
    echo "$interface"
}

readonly NETWORK_INTERFACE=$(detect_network_interface)

# Enhanced logging functions without colors in headless mode
log_with_timestamp() {
    local level="$1"
    shift
    local timestamp="[$(date '+%Y-%m-%d %H:%M:%S UTC')]"
    
    if [[ "$IS_INTERACTIVE" == "true" && "$IS_HEADLESS" != "true" ]]; then
        # Interactive mode with colors
        case "$level" in
            "INFO") echo -e "\033[0;32m${timestamp} [INFO]\033[0m $*" ;;
            "WARN") echo -e "\033[1;33m${timestamp} [WARN]\033[0m $*" ;;
            "ERROR") echo -e "\033[0;31m${timestamp} [ERROR]\033[0m $*" ;;
            "DEBUG") echo -e "\033[0;34m${timestamp} [DEBUG]\033[0m $*" ;;
            *) echo "${timestamp} [$level] $*" ;;
        esac
    else
        # Headless mode without colors
        echo "${timestamp} [$level] $*"
    fi
}

info() {
    log_with_timestamp "INFO" "$*"
}

warn() {
    log_with_timestamp "WARN" "$*"
}

error() {
    log_with_timestamp "ERROR" "$*"
}

debug() {
    log_with_timestamp "DEBUG" "$*"
}

# Enhanced self-error correction with exponential backoff
retry_with_backoff() {
    local max_attempts="$1"
    local initial_delay="$2"
    local description="$3"
    shift 3
    local attempt=1
    local delay="$initial_delay"
    
    while [[ $attempt -le $max_attempts ]]; do
        info "Attempting $description (attempt $attempt/$max_attempts)"
        
        # Create a subshell to contain any errors
        if (set -e; "$@"); then
            info "$description completed successfully"
            return 0
        fi
        
        local exit_code=$?
        
        if [[ $attempt -eq $max_attempts ]]; then
            error "$description failed after $max_attempts attempts (exit code: $exit_code)"
            return 1
        fi
        
        warn "$description failed (exit code: $exit_code), retrying in ${delay}s..."
        sleep "$delay"
        ((attempt++))
        
        # Exponential backoff with jitter
        delay=$((delay * 2 + RANDOM % 10))
    done
}

# Robust service waiting with better error handling
wait_for_service() {
    local service="$1"
    local timeout="${2:-$HEALTH_CHECK_TIMEOUT}"
    local elapsed=0
    local check_interval=5
    
    info "Waiting for $service to become ready (timeout: ${timeout}s)"
    
    while [[ $elapsed -lt $timeout ]]; do
        # Check if service exists first
        if ! systemctl list-unit-files --type=service | grep -q "^${service}\.service"; then
            error "Service $service does not exist"
            return 1
        fi
        
        # Check if service is active
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            info "$service is ready (took ${elapsed}s)"
            return 0
        fi
        
        # Check if service failed
        if systemctl is-failed --quiet "$service" 2>/dev/null; then
            error "$service has failed. Status:"
            systemctl status "$service" --no-pager -l || true
            return 1
        fi
        
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
        
        # Progress indicator for long waits
        if [[ $((elapsed % 30)) -eq 0 ]]; then
            info "Still waiting for $service... (${elapsed}/${timeout}s)"
        fi
    done
    
    error "$service failed to start within ${timeout}s"
    systemctl status "$service" --no-pager -l || true
    return 1
}

# Enhanced container waiting with health checks
wait_for_container() {
    local container="$1"
    local timeout="${2:-$HEALTH_CHECK_TIMEOUT}"
    local elapsed=0
    local check_interval=5
    
    info "Waiting for container $container to be ready (timeout: ${timeout}s)"
    
    while [[ $elapsed -lt $timeout ]]; do
        # Check if container is running
        if docker ps --filter "name=$container" --filter "status=running" --format "{{.Names}}" | grep -q "^${container}$"; then
            # If container has healthcheck, wait for it to be healthy
            local health_status
            health_status=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
            
            if [[ "$health_status" == "healthy" ]] || [[ "$health_status" == "none" ]]; then
                info "Container $container is ready (took ${elapsed}s)"
                return 0
            elif [[ "$health_status" == "unhealthy" ]]; then
                error "Container $container is unhealthy"
                docker logs --tail=20 "$container" || true
                return 1
            else
                debug "Container $container health status: $health_status"
            fi
        else
            # Check if container exists but is stopped/failed
            if docker ps -a --filter "name=$container" --format "{{.Names}}" | grep -q "^${container}$"; then
                local container_status
                container_status=$(docker ps -a --filter "name=$container" --format "{{.Status}}")
                debug "Container $container status: $container_status"
                
                # If container exited, it's failed
                if [[ "$container_status" == *"Exited"* ]]; then
                    error "Container $container has exited. Logs:"
                    docker logs --tail=50 "$container" || true
                    return 1
                fi
            fi
        fi
        
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
        
        # Progress indicator
        if [[ $((elapsed % 30)) -eq 0 ]]; then
            info "Still waiting for container $container... (${elapsed}/${timeout}s)"
        fi
    done
    
    error "Container $container failed to start within ${timeout}s"
    docker logs --tail=50 "$container" || true
    return 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Enhanced directory setup with proper error handling
setup_directories() {
    info "Setting up Obsidian C&C directory structure with comprehensive pre-setup"
    
    local directories=(
        "$OBSIDIAN_CNC_HOME:755"
        "$OBSIDIAN_CNC_HOME/config:755"
        "$OBSIDIAN_CNC_HOME/scripts:755"
        "$OBSIDIAN_CNC_HOME/logs:755"
        "$OBSIDIAN_CNC_HOME/certs:755"
        "$OBSIDIAN_CNC_HOME/data:755"
        "/etc/wireguard:700"
        "/etc/wireguard/clients:700"
        "/root/wireguard-credentials:700"
        "/var/lib/postgresql/data:755"
        "/var/lib/grafana:755"
        "/var/lib/prometheus:755"
        "$OBSIDIAN_CNC_HOME/config/grafana:755"
        "$OBSIDIAN_CNC_HOME/config/grafana/datasources:755"
        "$OBSIDIAN_CNC_HOME/config/grafana/dashboards:755"
        "/var/www/html:755"
        "/var/log/nginx:755"
        "/var/log/postgresql:755"
        "/etc/docker:755"
        "/etc/cockpit:755"
        "/etc/fail2ban:755"
        "/etc/letsencrypt:755"
    )
    
    for dir_spec in "${directories[@]}"; do
        local dir_path="${dir_spec%:*}"
        local dir_mode="${dir_spec#*:}"
        
        if ! install -d -m "$dir_mode" "$dir_path"; then
            error "Failed to create directory: $dir_path"
            return 1
        fi
        debug "Created directory: $dir_path (mode: $dir_mode)"
    done
    
    info "All required directories created successfully"
}

# Enhanced system update with better package management
update_system_impl() {
    info "Updating system packages"
    export DEBIAN_FRONTEND=noninteractive
    
    # Configure dpkg to handle conflicts automatically
    local dpkg_options=(
        "--force-confdef"
        "--force-confold"
    )
    
    # Set dpkg options
    for option in "${dpkg_options[@]}"; do
        echo "DPkg::Options \"$option\";" >> /etc/apt/apt.conf.d/90-obsidian-noninteractive
    done
    
    # Additional APT configuration for headless operation
    cat > /etc/apt/apt.conf.d/90-obsidian-noninteractive << 'EOF'
APT::Get::Assume-Yes "true";
APT::Get::force-yes "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
DPkg::Options "--force-confdef";
DPkg::Options "--force-confold";
DPkg::Post-Invoke-Success { "rm -f /var/cache/apt/archives/*.deb"; };
EOF
    
    # Fix any broken packages first
    dpkg --configure -a || true
    apt-get --fix-broken install -y || true
    
    # Update package lists with retry
    local update_attempts=0
    while [[ $update_attempts -lt 3 ]]; do
        if apt-get update; then
            break
        fi
        ((update_attempts++))
        warn "Package list update failed, attempt $update_attempts/3"
        sleep 10
    done
    
    # Upgrade system
    apt-get upgrade -y
    
    # Install packages with error handling
    local packages=(
        curl wget gnupg lsb-release ca-certificates software-properties-common
        apt-transport-https jq envsubst nginx certbot python3-certbot-nginx
        postgresql postgresql-contrib redis-server fail2ban ufw
        htop iftop iotop tree sqlite3 python3-flask python3-flask-httpauth
        python3-pip flock
    )
    
    apt-get install -y "${packages[@]}"
}

# Enhanced Docker installation with self-correction
install_docker() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "Docker installation" install_docker_impl
}

install_docker_impl() {
    info "Installing Docker and Docker Compose"
    
    # Remove any existing Docker installations
    apt-get remove -y docker docker-engine docker.io containerd runc || true
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

    # Install Docker
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Configure Docker daemon
    cat > /etc/docker/daemon.json << 'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "live-restore": true
}
EOF

    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    wait_for_service "docker" $HEALTH_CHECK_TIMEOUT
}

# Enhanced WireGuard installation with network interface detection
install_wireguard_server() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "WireGuard server installation" install_wireguard_server_impl
}

install_wireguard_server_impl() {
    info "Installing WireGuard VPN Server (interface: $NETWORK_INTERFACE)"
    
    apt-get install -y wireguard wireguard-tools qrencode

    cd /etc/wireguard
    umask 077
    
    if [[ ! -f server_private.key ]]; then
        wg genkey > server_private.key
        wg pubkey < server_private.key > server_public.key
        info "Generated WireGuard server keys"
    fi

    local server_private_key=$(cat server_private.key)

    # Create server configuration with detected interface
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${server_private_key}
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
SaveConfig = false

# Enable IP forwarding and NAT for detected interface
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${NETWORK_INTERFACE} -j MASQUERADE; ip route add ${WG_NETWORK_CIDR} dev wg0
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${NETWORK_INTERFACE} -j MASQUERADE; ip route del ${WG_NETWORK_CIDR} dev wg0

# Clients will be added here dynamically
EOF

    # Enable IP forwarding permanently
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

    systemctl enable wg-quick@wg0.service
    systemctl start wg-quick@wg0.service
    
    wait_for_service "wg-quick@wg0" $HEALTH_CHECK_TIMEOUT

    echo "$(cat server_public.key)" > "$OBSIDIAN_CNC_HOME/wireguard_server_public_key"
}

# Create default WireGuard client configurations
create_default_wireguard_clients() {
    info "Creating default WireGuard client credentials in /root/wireguard-credentials/"
    
    local server_public_key=$(cat /etc/wireguard/server_public.key)
    local credentials_dir="/root/wireguard-credentials"
    
    # Default clients to create
    local default_clients=(
        "admin:10.0.0.10"
        "laptop:10.0.0.11"
        "mobile:10.0.0.12"
        "backup:10.0.0.13"
    )
    
    # Create README file
    cat > "$credentials_dir/README.md" << EOF
# Default WireGuard Client Credentials

This directory contains pre-generated WireGuard client configurations for immediate use.

## Available Clients:
- **admin** (10.0.0.10) - Primary administration access
- **laptop** (10.0.0.11) - Laptop/workstation access  
- **mobile** (10.0.0.12) - Mobile device access
- **backup** (10.0.0.13) - Backup/emergency access

## Usage:
1. Copy the .conf file to your WireGuard client
2. Import the configuration
3. Connect to the VPN

## QR Codes:
Use the .png files to scan QR codes with mobile devices.

## Security Notes:
- These are default credentials for initial setup
- Change or regenerate these credentials in production
- Monitor access logs regularly

Generated on: $(date)
Server: ${DOMAIN}
Server Public Key: ${server_public_key}
EOF
    
    for client_info in "${default_clients[@]}"; do
        local client_name="${client_info%%:*}"
        local client_ip="${client_info##*:}"
        
        info "Creating default client: $client_name ($client_ip)"
        
        # Generate client keys
        cd "$credentials_dir"
        wg genkey > "${client_name}_private.key"
        wg pubkey < "${client_name}_private.key" > "${client_name}_public.key"
        
        local client_private_key=$(cat "${client_name}_private.key")
        local client_public_key=$(cat "${client_name}_public.key")
        
        # Create client configuration
        cat > "${client_name}.conf" << EOC
[Interface]
PrivateKey = ${client_private_key}
Address = ${client_ip}/32
DNS = ${WG_SERVER_IP}

[Peer]
PublicKey = ${server_public_key}
Endpoint = ${DOMAIN}:${WG_PORT}
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOC
        
        # Generate QR code for mobile setup
        qrencode -t PNG -o "${client_name}_qr.png" < "${client_name}.conf"
        
        # Add client to server configuration
        cat >> /etc/wireguard/wg0.conf << EOC

# Default Client: ${client_name}
[Peer]
PublicKey = ${client_public_key}
AllowedIPs = ${client_ip}/32
EOC
        
        # Create individual client info file
        cat > "${client_name}_info.txt" << EOC
Client Name: ${client_name}
IP Address: ${client_ip}
Private Key: ${client_private_key}
Public Key: ${client_public_key}
Server Endpoint: ${DOMAIN}:${WG_PORT}
Server Public Key: ${server_public_key}
Created: $(date)

Configuration File: ${client_name}.conf
QR Code: ${client_name}_qr.png
EOC
        
        info "Created default client $client_name with IP $client_ip"
    done
    
    # Set proper permissions
    chmod -R 600 "$credentials_dir"/*
    chmod 700 "$credentials_dir"
    
    # Create summary file for automated provisioning
    cat > "$credentials_dir/server_info.txt" << EOF
WireGuard Server Information
============================
Generated: $(date)
Server Domain: ${DOMAIN}
Server Port: ${WG_PORT}
Server Public Key: ${server_public_key}
Network CIDR: ${WG_NETWORK_CIDR}
Server VPN IP: ${WG_SERVER_IP}

Client IP Range: 10.0.0.10-13 (default clients)
Next Available IP: 10.0.0.14

For automated client provisioning, use:
- Server Public Key: ${server_public_key}
- Server Endpoint: ${DOMAIN}:${WG_PORT}
- DNS Server: ${WG_SERVER_IP}
EOF
    
    info "Default WireGuard credentials created in $credentials_dir"
    info "Server public key for client provisioning: ${server_public_key}"
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

# Enhanced Keycloak installation
install_keycloak() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "Keycloak installation" install_keycloak_impl
}

install_keycloak_impl() {
    info "Installing and configuring Keycloak SSO"
    
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
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 30s
      timeout: 10s
      retries: 3

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
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/auth/realms/master || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  keycloak_db_data:

networks:
  keycloak-network:
    driver: bridge
EOF

    cd "$OBSIDIAN_CNC_HOME"
    docker compose -f docker-compose.keycloak.yml up -d
    
    wait_for_container "keycloak" $HEALTH_CHECK_TIMEOUT
}

# Install and configure monitoring stack (Prometheus + Grafana)
install_monitoring() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "monitoring stack installation" install_monitoring_impl
}

install_monitoring_impl() {
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
    healthcheck:
      test: ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:9090/ || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - grafana_data:/var/lib/grafana
      - ./config/grafana:/etc/grafana/provisioning
    networks:
      - monitoring
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:3000/api/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

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

    cd "$OBSIDIAN_CNC_HOME"
    docker compose -f docker-compose.monitoring.yml up -d
    
    wait_for_container "prometheus" $HEALTH_CHECK_TIMEOUT
    wait_for_container "grafana" $HEALTH_CHECK_TIMEOUT
}

# Enhanced nginx configuration with self-correction
configure_nginx() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "Nginx configuration" configure_nginx_impl
}

configure_nginx_impl() {
    info "Configuring Nginx reverse proxy with SSL"
    
    # Stop nginx if running to avoid conflicts
    systemctl stop nginx || true
    
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

    # Test configuration before starting
    nginx -t
    systemctl start nginx
    wait_for_service "nginx" $HEALTH_CHECK_TIMEOUT

    # Obtain SSL certificate with retry logic
    info "Obtaining SSL certificate with Let's Encrypt"
    local cert_attempts=0
    while [[ $cert_attempts -lt 3 ]]; do
        if certbot --nginx -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive; then
            info "SSL certificate obtained successfully"
            break
        fi
        ((cert_attempts++))
        if [[ $cert_attempts -eq 3 ]]; then
            warn "Failed to obtain SSL certificate after 3 attempts, continuing without SSL"
        else
            warn "SSL certificate attempt $cert_attempts failed, retrying in 30s..."
            sleep 30
        fi
    done
}

# Simplified security configuration
configure_security() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "security configuration" configure_security_impl
}

configure_security_impl() {
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

    systemctl enable fail2ban
    systemctl start fail2ban
    wait_for_service "fail2ban" $HEALTH_CHECK_TIMEOUT
}

# Remove backup-related functions (S3 dependencies removed)

# Enhanced finalization with comprehensive health check
finalize_setup() {
    retry_with_backoff $MAX_RETRIES $INITIAL_RETRY_DELAY "finalization" finalize_setup_impl
}

finalize_setup_impl() {
    info "Finalizing C&C setup"
    
    # Create obsidian-cnc user
    if ! id obsidian-cnc > /dev/null 2>&1; then
        useradd -r -d "$OBSIDIAN_CNC_HOME" -s /bin/bash obsidian-cnc
        usermod -a -G docker obsidian-cnc
    fi
    
    chown -R obsidian-cnc:obsidian-cnc "$OBSIDIAN_CNC_HOME"
    chmod -R 755 "$OBSIDIAN_CNC_HOME/scripts"
    
    systemctl start obsidian-cluster-api.service
    wait_for_service "obsidian-cluster-api" $HEALTH_CHECK_TIMEOUT
    
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

    apt-get autoremove -y
    apt-get autoclean
    
    # Final comprehensive health check
    run_final_health_check
}

# Comprehensive final health check
run_final_health_check() {
    info "Running final comprehensive health check"
    
    local failed_services=()
    
    # Check system services
    for service in nginx postgresql redis-server wg-quick@wg0 cockpit.socket obsidian-cluster-api docker; do
        if ! systemctl is-active --quiet "$service"; then
            failed_services+=("$service")
            error "Service $service is not running"
        else
            info "Service $service is healthy"
        fi
    done
    
    # Check containers
    for container in keycloak prometheus grafana node-exporter; do
        if ! docker ps --filter "name=$container" --filter "status=running" | grep -q "$container"; then
            failed_services+=("container:$container")
            error "Container $container is not running"
        else
            info "Container $container is healthy"
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        error "Final health check failed. Failed components: ${failed_services[*]}"
        return 1
    else
        info "All services passed final health check"
        return 0
    fi
}

# Enhanced main execution with better error handling and environment detection
main() {
    info "Starting Obsidian Command & Control Bootstrap Process"
    info "Environment: $([ "$IS_HEADLESS" == "true" ] && echo "Headless" || echo "Interactive")"
    info "Target: Ubuntu 24.04 LTS (Hetzner Cloud Optimized)"
    info "Domain: $DOMAIN"
    info "Network Interface: $NETWORK_INTERFACE"
    info "Date: $(date)"
    
    # Log file locations for headless mode
    if [[ "$IS_HEADLESS" == "true" ]]; then
        info "Headless mode detected - logs are being written to:"
        info "  - System logs: $LOG_FILE"
        info "  - Root logs: $HEADLESS_LOG_FILE"
        info "  - Error logs: $ERROR_LOG_FILE and $HEADLESS_ERROR_LOG_FILE"
    fi
    
    # Environment validation
    if [[ -z "${DOMAIN// }" ]] || [[ "$DOMAIN" == "localhost" ]]; then
        warn "No domain configured, using localhost (not suitable for production)"
    fi
    
    # Pre-flight checks
    check_root
    
    # Create lock file to prevent concurrent executions
    local lock_file="/var/lock/obsidian-cnc-bootstrap.lock"
    if ! (
        flock -n 200 || {
            error "Another instance of this script is already running"
            exit 1
        }
        
        # Main installation sequence with enhanced error handling
        local installation_steps=(
            "setup_directories"
            "update_system"
            "install_docker"
            "install_wireguard_server"
            "install_cockpit_server"
            "install_keycloak"
            "install_monitoring"
            "configure_nginx"
            "configure_security"
            "create_management_scripts"
            "finalize_setup"
        )
        
        local failed_steps=()
        
        for step in "${installation_steps[@]}"; do
            info "Executing step: $step"
            if ! $step; then
                error "Step $step failed"
                failed_steps+=("$step")
                
                # Try recovery for some steps
                case "$step" in
                    "install_docker"|"install_keycloak"|"install_monitoring")
                        warn "Attempting recovery for $step..."
                        systemctl daemon-reload || true
                        sleep 30
                        if ! $step; then
                            error "Step $step failed on recovery"
                        else
                            info "Step $step recovered successfully"
                            # Remove from failed steps if recovery succeeded
                            unset 'failed_steps[-1]'
                        fi
                        ;;
                esac
            else
                info "Step $step completed successfully"
            fi
        done
        
        # Report results
        if [[ ${#failed_steps[@]} -gt 0 ]]; then
            error "Bootstrap completed with ${#failed_steps[@]} failed steps: ${failed_steps[*]}"
            exit 1
        else
            info "All installation steps completed successfully"
        fi
        
    ) 200>"$lock_file"; then
        exit 1
    fi
    
    # Final success message
    info "Obsidian Command & Control Bootstrap Complete!"
    info "All services are running and healthy"
    info "Access Point: https://$DOMAIN"
    info "WireGuard Server Public Key available at: $OBSIDIAN_CNC_HOME/wireguard_server_public_key"
    info "Default client credentials available in: /root/wireguard-credentials/"
    
    # Headless mode summary
    if [[ "$IS_HEADLESS" == "true" ]]; then
        info "Headless deployment summary written to: $HEADLESS_LOG_FILE"
        
        # Create deployment summary in /root
        cat > "/root/obsidian-cnc-deployment-summary.txt" << EOF
Obsidian Command & Control - Deployment Summary
===============================================
Deployment Date: $(date)
Domain: $DOMAIN
Network Interface: $NETWORK_INTERFACE

Services Status:
$(systemctl is-active docker nginx postgresql wg-quick@wg0 cockpit.socket obsidian-cluster-api 2>/dev/null | sed 's/^/  - /')

Access Points:
  - Main Dashboard: https://$DOMAIN
  - Grafana Monitoring: https://$DOMAIN/grafana
  - Keycloak SSO: https://$DOMAIN/auth

Credentials:
  - Database Password: $DB_PASSWORD
  - Keycloak Admin Password: $KEYCLOAK_ADMIN_PASSWORD
  - Grafana Admin Password: $GRAFANA_ADMIN_PASSWORD

Files Created:
  - WireGuard Server Key: $OBSIDIAN_CNC_HOME/wireguard_server_public_key
  - Default Client Configs: /root/wireguard-credentials/
  - Full Logs: $HEADLESS_LOG_FILE
  - Error Logs: $HEADLESS_ERROR_LOG_FILE

Next Steps:
  1. Configure DNS to point $DOMAIN to this server
  2. Review default WireGuard client configurations in /root/wireguard-credentials/
  3. Access Cockpit management interface at https://$DOMAIN
  4. Configure Keycloak SSO realms and clients
EOF
        
        info "Deployment summary saved to: /root/obsidian-cnc-deployment-summary.txt"
    fi
    
    # Log final system state
    info "Final system state:"
    {
        echo "=== Services Status ==="
        systemctl status docker nginx postgresql wg-quick@wg0 cockpit.socket obsidian-cluster-api --no-pager -l 2>/dev/null || true
        echo "=== Container Status ==="
        docker ps 2>/dev/null || true
        echo "=== Network Status ==="
        ss -tuln | head -20 2>/dev/null || true
    } >> "$LOG_FILE" 2>&1
}

# Execute main function with all arguments
main "$@"
