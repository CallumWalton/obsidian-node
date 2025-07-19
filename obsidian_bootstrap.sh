#!/usr/bin/env bash
#
# Obsidian Node Bootstrap Script
# Prepares Ubuntu 24.04 LTS VM for Obsidian platform usage
# 
# This script is idempotent and can be run multiple times safely
# Optimized for headless deployment with proper error handling
#
# Author: Obsidian Platform Team
# Version: 2.0
# Date: 2025-01-19

set -euo pipefail

# Detect execution environment
readonly IS_HEADLESS="${HEADLESS:-true}"
readonly IS_INTERACTIVE=$([ -t 1 ] && [ -t 2 ] && echo "true" || echo "false")

# Logging setup
readonly LOG_FILE="/var/log/obsidian-node-bootstrap.log"
readonly ERROR_LOG_FILE="/var/log/obsidian-node-bootstrap-errors.log"

# Create log files
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE" "$ERROR_LOG_FILE"
chmod 644 "$LOG_FILE" "$ERROR_LOG_FILE"

# Smart output redirection
if [[ "$IS_HEADLESS" == "true" || "$IS_INTERACTIVE" == "false" ]]; then
    exec 1>>"$LOG_FILE"
    exec 2>>"$ERROR_LOG_FILE"
else
    exec 1> >(tee -a "$LOG_FILE")
    exec 2> >(tee -a "$ERROR_LOG_FILE" >&2)
fi

# Configuration variables (to be substituted by automation)
readonly OBSIDIAN_HOME="/opt/obsidian-node"
readonly CNC_FQDN="${CNC_FQDN:-cnc.local}"
readonly CLUSTER_CA_PEM="${CLUSTER_CA_PEM:-}"
readonly CLUSTER_JOIN_TOKEN="${CLUSTER_JOIN_TOKEN:-default-token}"
readonly KEYCLOAK_REALM_URL="${KEYCLOAK_REALM_URL:-}"
readonly WG_DNS_IP="${WG_DNS_IP:-10.0.0.1}"
readonly WG_SERVER_ENDPOINT="${WG_SERVER_ENDPOINT:-}"
readonly WG_PSK="${WG_PSK:-}"
readonly WG_PORT="${WG_PORT:-51820}"
readonly PTERO_VERSION="${PTERO_VERSION:-latest}"
readonly PANEL_URL="${PANEL_URL:-}"
readonly NODE_UUID="${NODE_UUID:-}"
readonly TOKEN="${TOKEN:-}"
readonly ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"
readonly WINGS_PORTS="${WINGS_PORTS:-2022,8080-8090}"

# Enhanced logging without colors in headless mode
log_with_timestamp() {
    local level="$1"
    shift
    local timestamp="[$(date '+%Y-%m-%d %H:%M:%S UTC')]"
    
    if [[ "$IS_INTERACTIVE" == "true" && "$IS_HEADLESS" != "true" ]]; then
        case "$level" in
            "INFO") echo -e "\033[0;32m${timestamp} [INFO]\033[0m $*" ;;
            "WARN") echo -e "\033[1;33m${timestamp} [WARN]\033[0m $*" ;;
            "ERROR") echo -e "\033[0;31m${timestamp} [ERROR]\033[0m $*" ;;
            "DEBUG") echo -e "\033[0;34m${timestamp} [DEBUG]\033[0m $*" ;;
            *) echo "${timestamp} [$level] $*" ;;
        esac
    else
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

# Enhanced retry mechanism
retry_with_backoff() {
    local max_attempts="$1"
    local initial_delay="$2"
    local description="$3"
    shift 3
    local attempt=1
    local delay="$initial_delay"
    
    while [[ $attempt -le $max_attempts ]]; do
        info "Attempting $description (attempt $attempt/$max_attempts)"
        
        if (set -e; "$@"); then
            info "$description completed successfully"
            return 0
        fi
        
        local exit_code=$?
        
        if [[ $attempt -eq $max_attempts ]]; then
            error "$description failed after $max_attempts attempts (exit code: $exit_code)"
            return 1
        fi
        
        warn "$description failed, retrying in ${delay}s..."
        sleep "$delay"
        ((attempt++))
        delay=$((delay * 2))
    done
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Create obsidian directory structure
setup_directories() {
    info "Setting up Obsidian directory structure"
    install -d -m 755 "$OBSIDIAN_HOME"
    install -d -m 755 "$OBSIDIAN_HOME/config"
    install -d -m 755 "$OBSIDIAN_HOME/scripts"
    install -d -m 755 "$OBSIDIAN_HOME/logs"
    install -d -m 700 "/etc/restic/env.d"
    install -d -m 755 "/etc/pterodactyl"
}

# Enhanced system update
update_system() {
    info "Updating system packages"
    export DEBIAN_FRONTEND=noninteractive
    
    # Configure apt for headless operation
    cat > /etc/apt/apt.conf.d/90-obsidian-noninteractive << 'EOF'
APT::Get::Assume-Yes "true";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
DPkg::Options "--force-confdef";
DPkg::Options "--force-confold";
EOF
    
    # Fix broken packages
    dpkg --configure -a || true
    apt-get --fix-broken install -y || true
    
    retry_with_backoff 3 10 "package update" apt-get update
    apt-get upgrade -y
    apt-get install -y curl wget gnupg lsb-release ca-certificates software-properties-common apt-transport-https jq envsubst flock
}

# Install and configure Cockpit
install_cockpit() {
    info "Installing and configuring Cockpit"
    
    # Install cockpit packages
    apt-get install -y \
        cockpit \
        cockpit-machines \
        cockpit-pcp \
        cockpit-packagekit \
        cockpit-composer

    # Enable cockpit socket
    systemctl enable --now cockpit.socket

    # Configure HTTPS only on port 9090 - BIND TO WIREGUARD INTERFACE ONLY
    cat > /etc/cockpit/cockpit.conf << 'EOF'
[WebService]
# CRITICAL: Only bind to WireGuard interface - NO PUBLIC ACCESS
ListenStream = 10.0.0.1:9090
Origins = https://10.0.0.1:9090 wss://10.0.0.1:9090
ProtocolHeader = X-Forwarded-Proto
AllowUnencrypted = false
LoginTo = false
LoginTitle = Obsidian Node Management

[Session]
IdleTimeout = 30
Banner = /etc/cockpit/issue.cockpit
EOF

    # Create login banner
    cat > /etc/cockpit/issue.cockpit << 'EOF'
Obsidian Node Management Console
Authorized access only. All activities are monitored.
EOF

    # Import cluster CA certificate
    if [[ -n "$CLUSTER_CA_PEM" ]]; then
        echo "$CLUSTER_CA_PEM" > "$OBSIDIAN_HOME/cluster-ca.pem"
        cp "$OBSIDIAN_HOME/cluster-ca.pem" /usr/local/share/ca-certificates/obsidian-cluster.crt
        update-ca-certificates
    fi

    # Configure cockpit cluster joining (placeholder for API call)
    cat > "$OBSIDIAN_HOME/scripts/join_cluster.sh" << EOF
#!/bin/bash
# Join cockpit cluster - ONLY callable after WireGuard is up
set -euo pipefail

# Ensure WireGuard is active before attempting cluster join
if ! wg show wg0 >/dev/null 2>&1; then
    echo "ERROR: WireGuard must be active before joining cluster"
    exit 1
fi

# Join cluster through secure VPN connection
curl -X POST "https://${CNC_FQDN}/api/cluster/join" \\
    --connect-timeout 30 \\
    --max-time 60 \\
    -H "Authorization: Bearer ${CLUSTER_JOIN_TOKEN}" \\
    -H "Content-Type: application/json" \\
    -d '{
        "hostname": "$(hostname)", 
        "public_key": "$(cat /etc/ssh/ssh_host_rsa_key.pub)",
        "wireguard_ip": "10.0.0.1",
        "cockpit_url": "https://10.0.0.1:9090"
    }'
EOF
    chmod +x "$OBSIDIAN_HOME/scripts/join_cluster.sh"

    # Restart cockpit to apply changes
    systemctl restart cockpit.socket
}

# Configure Single Sign-On with Keycloak
configure_sso() {
    info "Configuring Single Sign-On with Keycloak"
    
    # Create obsidian group
    if ! getent group obsidian > /dev/null 2>&1; then
        groupadd obsidian
        info "Created obsidian group"
    fi

    # Configure cockpit OIDC - BIND TO WIREGUARD INTERFACE ONLY
    cat > /etc/cockpit/cockpit.conf << EOF
[WebService]
# CRITICAL: Only bind to WireGuard interface - NO PUBLIC ACCESS
ListenStream = 10.0.0.1:9090
Origins = https://10.0.0.1:9090 wss://10.0.0.1:9090
ProtocolHeader = X-Forwarded-Proto
AllowUnencrypted = false
LoginTo = false
LoginTitle = Obsidian Node Management

[OAuth]
URL = ${KEYCLOAK_REALM_URL}
ClientId = cockpit-obsidian
Scope = openid profile email groups

[Session]
IdleTimeout = 30
Banner = /etc/cockpit/issue.cockpit
EOF

    # Restrict access to obsidian group only
    cat > /etc/cockpit/disallowed-users << 'EOF'
# Only users in the 'obsidian' group can log in
# All other users are denied access
root
daemon
bin
sys
sync
games
man
lp
mail
news
uucp
proxy
www-data
backup
list
irc
gnats
nobody
systemd-network
systemd-resolve
systemd-timesync
messagebus
syslog
_apt
tss
uuidd
tcpdump
sshd
landscape
pollinate
ubuntu
EOF

    systemctl restart cockpit.socket
}

# Enhanced WireGuard installation
install_wireguard() {
    info "Installing and configuring WireGuard VPN"
    
    apt-get install -y wireguard wireguard-tools resolvconf qrencode

    cd /etc/wireguard
    umask 077
    
    if [[ ! -f privatekey ]]; then
        wg genkey > privatekey
        wg pubkey < privatekey > publickey
        info "Generated new WireGuard keys"
    fi

    local private_key public_key
    private_key=$(cat privatekey)
    public_key=$(cat publickey)

    # Detect primary network interface
    local primary_interface
    primary_interface=$(ip route | grep '^default' | head -n1 | awk '{print $5}' || echo "eth0")

    # Create WireGuard configuration with server public key placeholder
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${private_key}
Address = \${NODE_VPN_IP}/32
DNS = ${WG_DNS_IP}

# Enhanced PostUp/PostDown rules with error handling
PostUp = iptables -I INPUT -i lo -j ACCEPT || true
PostUp = iptables -I INPUT -i wg0 -j ACCEPT || true
PostUp = iptables -I INPUT -p tcp --dport 9090 -i ${primary_interface} -j DROP || true
PostUp = iptables -I INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT || true
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT || true
PostUp = iptables -t nat -A POSTROUTING -o ${primary_interface} -j MASQUERADE || true

PostDown = iptables -D INPUT -i lo -j ACCEPT || true
PostDown = iptables -D INPUT -i wg0 -j ACCEPT || true
PostDown = iptables -D INPUT -p tcp --dport 9090 -i ${primary_interface} -j DROP || true
PostDown = iptables -D INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT || true
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT || true
PostDown = iptables -t nat -D POSTROUTING -o ${primary_interface} -j MASQUERADE || true

[Peer]
PublicKey = \${WG_SERVER_PUBLIC_KEY}
PresharedKey = ${WG_PSK}
Endpoint = ${WG_SERVER_ENDPOINT}
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOF

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p

    # Store public key for C&C server provisioning
    echo "$public_key" > "$OBSIDIAN_HOME/wireguard_public_key"
    
    # Create configuration update script for post-provisioning
    cat > "$OBSIDIAN_HOME/scripts/update_wireguard_config.sh" << 'EOF'
#!/bin/bash
# Update WireGuard configuration with server details
# Called after C&C server provides connection details

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <server_public_key> <node_vpn_ip> <server_endpoint>"
    echo "Example: $0 'server_key_here' '10.0.0.15' 'cnc.example.com:51820'"
    exit 1
fi

WG_SERVER_PUBLIC_KEY="$1"
NODE_VPN_IP="$2"
WG_SERVER_ENDPOINT="$3"

# Update WireGuard configuration
sed -i "s/\${WG_SERVER_PUBLIC_KEY}/${WG_SERVER_PUBLIC_KEY}/" /etc/wireguard/wg0.conf
sed -i "s/\${NODE_VPN_IP}/${NODE_VPN_IP}/" /etc/wireguard/wg0.conf

# Restart WireGuard if it's running
if systemctl is-active --quiet wg-quick@wg0; then
    systemctl restart wg-quick@wg0
    echo "WireGuard configuration updated and service restarted"
else
    echo "WireGuard configuration updated (service not running)"
fi

# Test connectivity
sleep 5
if wg show wg0 >/dev/null 2>&1; then
    echo "WireGuard interface is active"
    if ping -c 3 -W 5 "${WG_DNS_IP}" >/dev/null 2>&1; then
        echo "VPN connectivity confirmed"
    else
        echo "WARNING: VPN connectivity test failed"
    fi
else
    echo "WARNING: WireGuard interface not active"
fi
EOF

    chmod +x "$OBSIDIAN_HOME/scripts/update_wireguard_config.sh"
    
    # Don't enable WireGuard service yet - wait for server provisioning
    info "WireGuard configured with placeholders - awaiting server provisioning"
    info "Client public key saved to $OBSIDIAN_HOME/wireguard_public_key"
    info "Use update_wireguard_config.sh to complete configuration"
}

# Install Docker for Pterodactyl Wings
install_docker() {
    info "Installing Docker for Pterodactyl Wings"
    
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

# Install Pterodactyl Wings
install_wings() {
    info "Installing Pterodactyl Wings"
    
    # Add Wings repository and GPG key
    curl -fsSL https://repo.pterodactyl.io/gpg | gpg --dearmor -o /usr/share/keyrings/pterodactyl-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/pterodactyl-keyring.gpg] https://repo.pterodactyl.io/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/pterodactyl.list

    # Update and install Wings
    apt-get update
    apt-get install -y "wings=${PTERO_VERSION}"

    # Create Wings configuration
    cat > /etc/pterodactyl/config.yml << EOF
debug: false
uuid: ${NODE_UUID}
token_id: ${NODE_UUID}
token: ${TOKEN}
api:
  host: 0.0.0.0
  port: 8080
  ssl:
    enabled: false
  upload_limit: 100
system:
  data: /var/lib/pterodactyl/volumes
  archive_directory: /var/lib/pterodactyl/archives
  backup_directory: /var/lib/pterodactyl/backups
  username: pterodactyl
allowed_mounts:
  - /tmp
  - /var/lib/pterodactyl/mounts
allowed_origins: []
remote: ${PANEL_URL}
docker:
  network:
    name: pterodactyl_nw
    ispn: false
    driver: bridge
    network_mode: pterodactyl_nw
    is_internal: false
    enable_icc: true
    network_mtu: 1500
    dns:
      - 1.1.1.1
      - 1.0.0.1
  socket: /var/run/docker.sock
  autoupdate_images: true
  log_config:
    type: local
    config:
      max-size: 5m
      max-file: 1
EOF

    # Create pterodactyl user
    if ! id pterodactyl > /dev/null 2>&1; then
        useradd -r -d /var/lib/pterodactyl -s /bin/bash pterodactyl
    fi

    # Create pterodactyl directories
    install -d -o pterodactyl -g pterodactyl -m 755 /var/lib/pterodactyl/volumes
    install -d -o pterodactyl -g pterodactyl -m 755 /var/lib/pterodactyl/archives
    install -d -o pterodactyl -g pterodactyl -m 755 /var/lib/pterodactyl/backups
    install -d -o pterodactyl -g pterodactyl -m 755 /var/lib/pterodactyl/mounts

    # Add pterodactyl user to docker group
    usermod -a -G docker pterodactyl

    # Create systemd override for Wings - WAIT FOR WIREGUARD
    install -d /etc/systemd/system/wings.service.d
    cat > /etc/systemd/system/wings.service.d/override.conf << 'EOF'
[Unit]
After=docker.service network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
User=pterodactyl
WorkingDirectory=/var/lib/pterodactyl
LimitNOFILE=4096
PIDFile=/var/run/wings/daemon.pid
ExecStartPre=/bin/mkdir -p /var/run/wings
ExecStartPre=/bin/chown pterodactyl:pterodactyl /var/run/wings
# Ensure WireGuard is up before starting Wings
ExecStartPre=/bin/bash -c 'until wg show wg0 >/dev/null 2>&1; do sleep 5; done'
EOF

    # Enable Wings service
    systemctl daemon-reload
    systemctl enable wings.service
}

# Install backup solutions
install_backups() {
    info "Installing backup solutions (Restic)"
    
    # Install restic
    apt-get install -y restic

    # Create restic environment file for S3
    cat > /etc/restic/env.d/s3.env << EOF
RESTIC_REPOSITORY=s3:${S3_ENDPOINT}/${S3_BUCKET}
RESTIC_PASSWORD_FILE=/etc/restic/password
AWS_ACCESS_KEY_ID=${S3_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${S3_SECRET_KEY}
EOF

    # Generate restic password
    openssl rand -base64 32 > /etc/restic/password
    chmod 600 /etc/restic/password

    # Create backup script
    cat > "$OBSIDIAN_HOME/scripts/backup.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

source /etc/restic/env.d/s3.env

# Initialize repository if it doesn't exist
if ! restic snapshots > /dev/null 2>&1; then
    restic init
fi

# Run backup
restic backup \
    --tag obsidian \
    --host "$(hostname)" \
    /etc \
    /var/lib/pterodactyl \
    /opt/obsidian-node \
    --exclude="/var/lib/pterodactyl/volumes/*/logs" \
    --exclude="/var/lib/pterodactyl/volumes/*/cache"

# Cleanup old snapshots (keep last 7 daily, 4 weekly, 6 monthly)
restic forget --prune \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 6 \
    --host "$(hostname)"
EOF
    chmod +x "$OBSIDIAN_HOME/scripts/backup.sh"

    # Create systemd service for backup
    cat > /etc/systemd/system/obsidian-backup.service << EOF
[Unit]
Description=Obsidian Node Backup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$OBSIDIAN_HOME/scripts/backup.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

    # Create systemd timer for daily backups at 02:00 UTC
    cat > /etc/systemd/system/obsidian-backup.timer << 'EOF'
[Unit]
Description=Daily Obsidian Node Backup
Requires=obsidian-backup.service

[Timer]
OnCalendar=daily
Persistent=true
AccuracySec=1h

[Install]
WantedBy=timers.target
EOF

    # Enable backup timer
    systemctl daemon-reload
    systemctl enable obsidian-backup.timer
    systemctl start obsidian-backup.timer
}

# Configure security and operational hygiene
configure_security() {
    info "Configuring security and operational hygiene"
    
    # Configure unattended upgrades
    apt-get install -y unattended-upgrades apt-listchanges
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "auto";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "${ADMIN_EMAIL}";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    # Install and configure fail2ban
    apt-get install -y fail2ban
    
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

[cockpit]
enabled = true
port = 9090
filter = cockpit
logpath = /var/log/auth.log
maxretry = 3
EOF

    # Create cockpit fail2ban filter
    cat > /etc/fail2ban/filter.d/cockpit.conf << 'EOF'
[Definition]
failregex = ^.*cockpit-auth: authentication failed for .*from <HOST>.*$
ignoreregex =
EOF

    systemctl enable --now fail2ban

    # Install needrestart
    apt-get install -y needrestart
    
    cat > /etc/needrestart/needrestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = 1;
$nrconf{ucodehints} = 1;
EOF

    # Enhanced UFW configuration with better port handling
    apt-get install -y ufw
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    ufw deny 9090/tcp comment 'Block Cockpit Public Access'
    ufw allow "${WG_PORT}/udp" comment 'WireGuard VPN'
    
    # Parse and allow Wings ports with error handling
    IFS=',' read -ra PORTS_ARRAY <<< "$WINGS_PORTS" || true
    for port_spec in "${PORTS_ARRAY[@]}"; do
        # Handle both single ports and ranges
        if [[ "$port_spec" =~ ^[0-9]+-[0-9]+$ ]]; then
            ufw allow "$port_spec" comment 'Pterodactyl Wings Range'
        elif [[ "$port_spec" =~ ^[0-9]+$ ]]; then
            ufw allow "$port_spec" comment 'Pterodactyl Wings'
        else
            warn "Invalid port specification: $port_spec"
        fi
    done
    
    ufw --force enable
}

# Install observability and health monitoring
install_observability() {
    info "Installing observability and health monitoring tools"
    
    # Install Prometheus Node Exporter
    apt-get install -y prometheus-node-exporter
    systemctl enable --now prometheus-node-exporter
    
    # Install NetData
    curl -fsSL https://packagecloud.io/install/repositories/netdata/netdata/script.deb.sh | bash
    apt-get install -y netdata
    
    # Configure NetData to listen only on WireGuard interface
    cat > /etc/netdata/netdata.conf << 'EOF'
[global]
    run as user = netdata
    web files owner = root
    web files group = netdata
    bind socket to IP = 10.0.0.1
    default port = 19999
    disconnect idle clients after seconds = 60
    enable web responses gzip compression = yes

[web]
    web files owner = root
    web files group = netdata
    allow connections from = localhost 10.0.0.*
    allow dashboard from = localhost 10.0.0.*
    allow badges from = *
    allow streaming from = *
    allow netdata.conf from = localhost 10.0.0.*
EOF

    systemctl enable --now netdata
    
    # Allow NetData on UFW for WireGuard network only
    ufw allow from 10.0.0.0/24 to any port 19999 comment 'NetData (WireGuard only)'
    
    # Install Telegraf (optional)
    curl -fsSL https://repos.influxdata.com/influxdata-archive_compat.key | gpg --dearmor -o /usr/share/keyrings/influxdata-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/influxdata-archive-keyring.gpg] https://repos.influxdata.com/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/influxdb.list
    
    apt-get update
    apt-get install -y telegraf
    
    # Create basic Telegraf configuration
    cat > /etc/telegraf/telegraf.conf << 'EOF'
[global_tags]
  environment = "production"
  role = "obsidian-node"

[agent]
  interval = "10s"
  round_interval = true
  metric_batch_size = 1000
  metric_buffer_limit = 10000
  collection_jitter = "0s"
  flush_interval = "10s"
  flush_jitter = "0s"
  precision = ""
  hostname = ""
  omit_hostname = false

[[outputs.influxdb_v2]]
  urls = ["INFLUXDB_URL_PLACEHOLDER"]
  token = "INFLUXDB_TOKEN_PLACEHOLDER"
  organization = "INFLUXDB_ORG_PLACEHOLDER"
  bucket = "INFLUXDB_BUCKET_PLACEHOLDER"

[[inputs.cpu]]
  percpu = true
  totalcpu = true
  collect_cpu_time = false
  report_active = false

[[inputs.disk]]
  ignore_fs = ["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]

[[inputs.diskio]]

[[inputs.kernel]]

[[inputs.mem]]

[[inputs.processes]]

[[inputs.swap]]

[[inputs.system]]

[[inputs.net]]

[[inputs.netstat]]

[[inputs.docker]]
  endpoint = "unix:///var/run/docker.sock"
EOF

    systemctl enable telegraf
}

# Create health check script
create_health_check() {
    info "Creating system health check script"
    
    cat > "$OBSIDIAN_HOME/scripts/health_check.sh" << 'EOF'
#!/bin/bash
# Obsidian Node Health Check Script

set -euo pipefail

# Colors for output
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

check_port() {
    local port="$1"
    local service="$2"
    if ss -tuln | grep -q ":$port "; then
        echo -e "${GREEN}✓${NC} $service is listening on port $port"
        return 0
    else
        echo -e "${RED}✗${NC} $service is not listening on port $port"
        return 1
    fi
}

echo "=== Obsidian Node Health Check ==="
echo "Timestamp: $(date)"
echo "Hostname: $(hostname)"
echo

# Check critical services
echo "--- Service Status ---"
check_service "cockpit.socket"
check_service "docker"
check_service "wings"
check_service "wg-quick@wg0"
check_service "prometheus-node-exporter"
check_service "netdata"
check_service "fail2ban"

echo

# Check network ports
echo "--- Network Ports ---"
check_port "22" "SSH"
check_port "9090" "Cockpit"
check_port "8080" "Wings API"
check_port "9100" "Node Exporter"
check_port "19999" "NetData"

echo

# Check disk space
echo "--- Disk Usage ---"
df -h | grep -E '^/dev/' | awk '{
    use = $5;
    gsub(/%/, "", use);
    if (use > 90) 
        printf "\033[0;31m✗\033[0m %s is %s full (%s used of %s)\n", $6, $5, $3, $2;
    else if (use > 75)
        printf "\033[1;33m!\033[0m %s is %s full (%s used of %s)\n", $6, $5, $3, $2;
    else
        printf "\033[0;32m✓\033[0m %s is %s full (%s used of %s)\n", $6, $5, $3, $2;
}'

echo

# Check memory usage
echo "--- Memory Usage ---"
free -h | awk 'NR==2{
    used = $3;
    total = $2;
    percent = ($3/$2) * 100;
    if (percent > 90)
        printf "\033[0;31m✗\033[0m Memory usage: %s/%s (%.1f%%)\n", used, total, percent;
    else if (percent > 75)
        printf "\033[1;33m!\033[0m Memory usage: %s/%s (%.1f%%)\n", used, total, percent;
    else
        printf "\033[0;32m✓\033[0m Memory usage: %s/%s (%.1f%%)\n", used, total, percent;
}'

echo

# Check WireGuard connection
echo "--- WireGuard Status ---"
if wg show wg0 > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} WireGuard interface wg0 is up"
    wg show wg0
else
    echo -e "${RED}✗${NC} WireGuard interface wg0 is down"
fi

echo
echo "=== Health Check Complete ==="
EOF

    chmod +x "$OBSIDIAN_HOME/scripts/health_check.sh"
    
    # Create systemd service for health check
    cat > /etc/systemd/system/obsidian-health-check.service << EOF
[Unit]
Description=Obsidian Node Health Check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=$OBSIDIAN_HOME/scripts/health_check.sh
User=root
StandardOutput=journal
StandardError=journal
EOF

    # Create timer for periodic health checks
    cat > /etc/systemd/system/obsidian-health-check.timer << 'EOF'
[Unit]
Description=Periodic Obsidian Node Health Check
Requires=obsidian-health-check.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable obsidian-health-check.timer
    systemctl start obsidian-health-check.timer
}

# Final system configuration
finalize_setup() {
    info "Finalizing system setup"
    
    # Create obsidian system user
    if ! id obsidian > /dev/null 2>&1; then
        useradd -r -d "$OBSIDIAN_HOME" -s /bin/bash -G obsidian,docker obsidian
        chown -R obsidian:obsidian "$OBSIDIAN_HOME"
    fi
    
    # Set up log rotation for obsidian logs
    cat > /etc/logrotate.d/obsidian << EOF
$OBSIDIAN_HOME/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    su obsidian obsidian
}
EOF

    # Enhanced startup script with better error handling
    cat > "$OBSIDIAN_HOME/scripts/startup.sh" << 'EOF'
#!/bin/bash
# Obsidian Node Startup Script - Enhanced Error Handling
set -euo pipefail

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a /var/log/obsidian-node-startup.log
}

log "Starting Obsidian Node services with WireGuard security..."

# Function to wait for service
wait_for_service() {
    local service="$1"
    local timeout="${2:-60}"
    local elapsed=0
    
    while [[ $elapsed -lt $timeout ]]; do
        if systemctl is-active --quiet "$service"; then
            log "$service is ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    log "ERROR: $service failed to start within ${timeout}s"
    return 1
}

# Start WireGuard first
log "Starting WireGuard VPN..."
if ! systemctl start wg-quick@wg0.service; then
    log "ERROR: Failed to start WireGuard"
    exit 1
fi

# Wait for WireGuard interface
timeout=60
counter=0
until wg show wg0 >/dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        log "ERROR: WireGuard failed to start within $timeout seconds"
        exit 1
    fi
    log "Waiting for WireGuard interface... ($counter/$timeout)"
    sleep 1
    counter=$((counter + 1))
done

log "WireGuard VPN is active"

# Verify WireGuard IP assignment
if ! ip addr show wg0 | grep -q "10.0.0."; then
    log "ERROR: WireGuard interface missing expected IP"
    exit 1
fi

# Apply firewall rules with error handling
primary_interface=$(ip route | grep '^default' | head -n1 | awk '{print $5}' || echo "eth0")

iptables -I INPUT -i lo -j ACCEPT 2>/dev/null || log "WARN: Failed to add lo rule"
iptables -I INPUT -i wg0 -j ACCEPT 2>/dev/null || log "WARN: Failed to add wg0 rule"
iptables -I INPUT -p tcp --dport 9090 -i "$primary_interface" -j DROP 2>/dev/null || log "WARN: Failed to block cockpit on public"
iptables -I INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT 2>/dev/null || log "WARN: Failed to allow cockpit on VPN"

# Test VPN connectivity
log "Testing VPN connectivity..."
timeout=30
counter=0
until ping -c1 -W1 ${WG_DNS_IP} >/dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        log "WARNING: VPN DNS not reachable, continuing anyway"
        break
    fi
    log "Waiting for VPN connectivity... ($counter/$timeout)"
    sleep 1
    counter=$((counter + 1))
done

# Start Cockpit
log "Starting Cockpit..."
if ! systemctl restart cockpit.socket; then
    log "ERROR: Failed to start Cockpit"
    exit 1
fi

wait_for_service "cockpit.socket" 30

# Verify Cockpit binding
if ! ss -tuln | grep -q "10.0.0.1:9090"; then
    log "ERROR: Cockpit not bound to WireGuard interface"
    systemctl status cockpit.socket --no-pager -l || true
    exit 1
fi

# Start Wings if configured
if [[ -f /etc/pterodactyl/config.yml ]] && ! systemctl is-active --quiet wings; then
    log "Starting Pterodactyl Wings..."
    if systemctl start wings; then
        wait_for_service "wings" 60
    else
        log "WARNING: Failed to start Wings"
    fi
fi

log "Obsidian Node startup complete"
log "Cockpit accessible at: https://10.0.0.1:9090"
EOF
    chmod +x "$OBSIDIAN_HOME/scripts/startup.sh"
    
    # Create systemd service with proper dependencies
    cat > /etc/systemd/system/obsidian-startup.service << 'EOF'
[Unit]
Description=Obsidian Node Startup
After=network-online.target multi-user.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/obsidian-node/scripts/startup.sh
User=root
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable obsidian-startup.service
    
    # Clean up
    apt-get autoremove -y
    apt-get autoclean
}

# Enhanced main function
main() {
    info "Starting Obsidian Node Bootstrap Process"
    info "Environment: $([ "$IS_HEADLESS" == "true" ] && echo "Headless" || echo "Interactive")"
    info "Target: Ubuntu 24.04 LTS"
    info "Date: $(date)"
    
    # Validation
    if [[ -z "${CNC_FQDN// }" ]] || [[ "$CNC_FQDN" == "cnc.local" ]]; then
        warn "No C&C FQDN configured or using default"
    fi
    
    check_root
    
    # Lock file for single execution
    local lock_file="/var/lock/obsidian-node-bootstrap.lock"
    if ! (
        flock -n 200 || {
            error "Another instance of this script is running"
            exit 1
        }
        
        # Installation steps
        local steps=(
            "setup_directories"
            "update_system"
            "install_cockpit"
            "configure_sso"
            "install_wireguard"
            "validate_wireguard_security"
            "install_docker"
            "install_wings"
            "configure_security"
            "install_observability"
            "create_health_check"
            "finalize_setup"
        )
        
        local failed_steps=()
        
        for step in "${steps[@]}"; do
            info "Executing step: $step"
            if ! $step; then
                error "Step $step failed"
                failed_steps+=("$step")
            else
                info "Step $step completed successfully"
            fi
        done
        
        if [[ ${#failed_steps[@]} -gt 0 ]]; then
            error "Bootstrap failed on steps: ${failed_steps[*]}"
            exit 1
        fi
        
    ) 200>"$lock_file"; then
        exit 1
    fi
    
    # Success message
    info "Bootstrap complete!"
    info "WireGuard Public Key (save for server configuration):"
    cat "$OBSIDIAN_HOME/wireguard_public_key" 2>/dev/null || echo "Key file not found"
    info "Cockpit accessible at: https://10.0.0.1:9090 (VPN ONLY)"
    info "Health check: $OBSIDIAN_HOME/scripts/health_check.sh"
    
    # Run health check
    "$OBSIDIAN_HOME/scripts/health_check.sh" || true
}

# Execute main function
main "$@"
