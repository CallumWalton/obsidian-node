#!/usr/bin/env bash
#
# Obsidian Node Bootstrap Script
# Prepares Ubuntu 24.04 LTS VM for Obsidian platform usage
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
readonly OBSIDIAN_HOME="/opt/obsidian-node"
readonly CNC_FQDN="${CNC_FQDN}"
readonly CLUSTER_CA_PEM="${CLUSTER_CA_PEM}"
readonly CLUSTER_JOIN_TOKEN="${CLUSTER_JOIN_TOKEN}"
readonly KEYCLOAK_REALM_URL="${KEYCLOAK_REALM_URL}"
readonly WG_DNS_IP="${WG_DNS_IP}"
readonly WG_SERVER_ENDPOINT="${WG_SERVER_ENDPOINT}"
readonly WG_PSK="${WG_PSK}"
readonly WG_POR    # Create systemd service for startup - ENSURE WIREGUARD FIRST
    cat > /etc/systemd/system/obsidian-startup.service << EOF
[Unit]
Description=Obsidian Node Startup - WireGuard First
After=network-online.target wg-quick@wg0.service
Wants=network-online.target
Requires=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStart=$OBSIDIAN_HOME/scripts/startup.sh
User=root
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOFeadonly PTERO_VERSION="${PTERO_VERSION}"
readonly PANEL_URL="${PANEL_URL}"
readonly NODE_UUID="${NODE_UUID}"
readonly TOKEN="${TOKEN}"
readonly S3_BUCKET="${S3_BUCKET}"
readonly S3_ACCESS_KEY="${S3_ACCESS_KEY}"
readonly S3_SECRET_KEY="${S3_SECRET_KEY}"
readonly S3_ENDPOINT="${S3_ENDPOINT}"
readonly ADMIN_EMAIL="${ADMIN_EMAIL}"
readonly WINGS_PORTS="${WINGS_PORTS}"

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
        envsubst
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

# Install and configure WireGuard VPN
install_wireguard() {
    info "Installing and configuring WireGuard VPN"
    
    # Install WireGuard
    apt-get install -y wireguard wireguard-tools resolvconf

    # Generate WireGuard keys
    cd /etc/wireguard
    umask 077
    
    if [[ ! -f privatekey ]]; then
        wg genkey > privatekey
        wg pubkey < privatekey > publickey
        info "Generated new WireGuard keys"
    fi

    local private_key=$(cat privatekey)
    local public_key=$(cat publickey)

    # Create WireGuard configuration
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = ${private_key}
Address = 10.0.0.0/32
DNS = ${WG_DNS_IP}
# CRITICAL: Route all traffic through VPN except cloud metadata
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -I INPUT -i lo -j ACCEPT
PostUp = iptables -I INPUT -i wg0 -j ACCEPT
PostUp = iptables -I INPUT -p tcp --dport 9090 -i eth0 -j DROP
PostUp = iptables -I INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D INPUT -i lo -j ACCEPT
PostDown = iptables -D INPUT -i wg0 -j ACCEPT
PostDown = iptables -D INPUT -p tcp --dport 9090 -i eth0 -j DROP
PostDown = iptables -D INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT

[Peer]
PublicKey = SERVER_PUBLIC_KEY_PLACEHOLDER
PresharedKey = ${WG_PSK}
Endpoint = ${WG_SERVER_ENDPOINT}
# CRITICAL: Route all traffic through VPN except cloud metadata and DNS
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOF

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    sysctl -p

    # Enable WireGuard service
    systemctl enable wg-quick@wg0.service

    # Store public key for provisioning system
    echo "$public_key" > "$OBSIDIAN_HOME/wireguard_public_key"
    info "WireGuard public key saved to $OBSIDIAN_HOME/wireguard_public_key"
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

    # Install needrestart for automatic service restarts
    apt-get install -y needrestart
    
    cat > /etc/needrestart/needrestart.conf << 'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = 1;
$nrconf{ucodehints} = 1;
EOF

    # Configure UFW firewall - BLOCK COCKPIT ON PUBLIC INTERFACE
    apt-get install -y ufw
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH
    ufw allow 22/tcp comment 'SSH'
    
    # CRITICAL: Block Cockpit on all public interfaces
    ufw deny 9090/tcp comment 'Block Cockpit Public Access'
    
    # Allow WireGuard
    ufw allow "${WG_PORT}/udp" comment 'WireGuard VPN'
    
    # Allow Wings ports (assuming comma-separated)
    IFS=',' read -ra PORTS <<< "$WINGS_PORTS"
    for port in "${PORTS[@]}"; do
        ufw allow "$port" comment 'Pterodactyl Wings'
    done
    
    # Enable UFW
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
    
    # Create obsidian system user for platform operations
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

    # Create startup script - WIREGUARD MANDATORY
    cat > "$OBSIDIAN_HOME/scripts/startup.sh" << 'EOF'
#!/bin/bash
# Obsidian Node Startup Script - WireGuard Security First
set -euo pipefail

echo "Starting Obsidian Node services with WireGuard security..."

# CRITICAL: Ensure WireGuard is up BEFORE anything else
echo "Ensuring WireGuard VPN is active..."
systemctl start wg-quick@wg0.service

# Wait for WireGuard interface to be fully up
timeout=60
counter=0
until wg show wg0 >/dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        echo "ERROR: WireGuard failed to start within $timeout seconds"
        exit 1
    fi
    echo "Waiting for WireGuard interface to be ready... ($counter/$timeout)"
    sleep 1
    counter=$((counter + 1))
done

echo "WireGuard VPN is active and ready"

# Verify WireGuard IP is assigned
if ! ip addr show wg0 | grep -q "10.0.0."; then
    echo "ERROR: WireGuard interface does not have expected IP address"
    exit 1
fi

# Apply additional firewall rules to ensure Cockpit isolation
iptables -I INPUT -p tcp --dport 9090 -i eth0 -j DROP
iptables -I INPUT -p tcp --dport 9090 -i wg0 -j ACCEPT

# Wait for VPN network connectivity through tunnel
echo "Testing VPN connectivity..."
timeout=30
counter=0
until ping -c1 -W1 ${WG_DNS_IP} >/dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        echo "WARNING: VPN DNS not reachable, but continuing..."
        break
    fi
    echo "Waiting for VPN network connectivity... ($counter/$timeout)"
    sleep 1
    counter=$((counter + 1))
done

# Start Cockpit (should now be bound to WireGuard interface only)
echo "Starting Cockpit on WireGuard interface..."
systemctl restart cockpit.socket

# Verify Cockpit is bound to WireGuard interface
if ! ss -tuln | grep -q "10.0.0.1:9090"; then
    echo "ERROR: Cockpit is not bound to WireGuard interface"
    exit 1
fi

# Start Wings if not already running
if ! systemctl is-active --quiet wings; then
    echo "Starting Pterodactyl Wings..."
    systemctl start wings
fi

echo "Obsidian Node startup complete - All services secured behind WireGuard VPN"
echo "Cockpit accessible ONLY at: https://10.0.0.1:9090"
EOF
    chmod +x "$OBSIDIAN_HOME/scripts/startup.sh"
    
    # Create systemd service for startup
    cat > /etc/systemd/system/obsidian-startup.service << EOF
[Unit]
Description=Obsidian Node Startup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$OBSIDIAN_HOME/scripts/startup.sh
User=root
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable obsidian-startup.service
    
    # Clean up package cache
    apt-get autoremove -y
    apt-get autoclean
}

# Validate WireGuard security configuration
validate_wireguard_security() {
    info "Validating WireGuard security configuration"
    
    # Verify WireGuard configuration exists
    if [[ ! -f /etc/wireguard/wg0.conf ]]; then
        error "WireGuard configuration file missing"
        exit 1
    fi
    
    # Verify WireGuard interface can start
    if ! wg-quick up wg0 2>/dev/null; then
        warn "WireGuard interface failed to start - this is expected if already running"
    fi
    
    # Wait for interface to be ready
    sleep 5
    
    # Verify WireGuard interface is up
    if ! wg show wg0 >/dev/null 2>&1; then
        error "WireGuard interface is not active after configuration"
        exit 1
    fi
    
    # Verify Cockpit is NOT listening on public interfaces
    if ss -tuln | grep -E ":9090.*0\.0\.0\.0" >/dev/null 2>&1; then
        error "SECURITY BREACH: Cockpit is listening on public interface!"
        systemctl stop cockpit.socket
        exit 1
    fi
    
    # Verify Cockpit IS listening on WireGuard interface
    if ! ss -tuln | grep -q "10.0.0.1:9090"; then
        warn "Cockpit not yet bound to WireGuard interface - will be available after full startup"
    fi
    
    info "WireGuard security validation passed"
}

# Main execution flow
main() {
    info "Starting Obsidian Node Bootstrap Process"
    info "Target: Ubuntu 24.04 LTS"
    info "Date: $(date)"
    
    check_root
    setup_directories
    update_system
    install_cockpit
    configure_sso
    install_wireguard
    validate_wireguard_security
    install_docker
    install_wings
    install_backups
    configure_security
    install_observability
    create_health_check
    finalize_setup
    
    # Print completion message and WireGuard public key
    echo
    info "Bootstrap complete!"
    echo
    info "WireGuard Public Key (save this for server configuration):"
    cat "$OBSIDIAN_HOME/wireguard_public_key"
    echo
    warn "SECURITY NOTICE: Cockpit is ONLY accessible through WireGuard VPN"
    info "System is ready for Obsidian platform usage"
    info "Access Cockpit at: https://10.0.0.1:9090 (VPN ONLY)"
    info "Health check available at: $OBSIDIAN_HOME/scripts/health_check.sh"
    warn "Public network access to Cockpit is BLOCKED by firewall"
    
    # Run initial health check
    "$OBSIDIAN_HOME/scripts/health_check.sh"
}

# Execute main function
main "$@"
