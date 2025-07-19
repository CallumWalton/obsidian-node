# Hetzner Cloud Deployment Guide
## Obsidian Command & Control + Client Node

**Version:** 1.0  
**Date:** July 19, 2025  
**Provider:** Hetzner Cloud  
**Target:** Ubuntu 24.04 LTS

This guide walks you through deploying the complete Obsidian infrastructure on Hetzner Cloud, including the Command & Control server and one managed client node.

---

## 🎯 Prerequisites

### Required Tools
- [ ] **Hetzner Cloud Account** with API access
- [ ] **Domain Name** pointing to Hetzner (DNS configured)
- [ ] **Local Terminal** with SSH client
- [ ] **Email Account** for SSL certificates and notifications

### Required Information
- [ ] Domain name (e.g., `control.obsidian.example.com`)
- [ ] Email address for SSL certificates
- [ ] SSH public key for server access
- [ ] **GitHub Personal Access Token (PAT)** with repository access
- [ ] SMTP server details for notifications (optional)

---

## 📋 Phase 1: Initial Setup

### Step 1.1: Create Hetzner Cloud Project
1. **Login to Hetzner Cloud Console**
   - Visit: https://console.hetzner.cloud/
   - Login with your Hetzner account

2. **Create New Project**
   ```
   Project Name: obsidian-infrastructure
   Location: Choose closest to your users (e.g., Nuremberg, Finland, Virginia)
   ```

3. **Generate API Token**
   - Go to **Security** → **API Tokens**
   - Click **Generate API Token**
   - Name: `obsidian-deployment`
   - Permissions: **Read & Write**
   - **Save the token securely** - you'll need it later

### Step 1.2: Configure DNS
1. **Point Domain to Hetzner**
   - Login to your domain registrar
   - Update nameservers to Hetzner DNS (if using Hetzner DNS):
     ```
     helga.ns.hetzner.de
     walt.ns.hetzner.com
     zeus.ns.hetzner.com
     ```

2. **Create DNS Zone** (if using Hetzner DNS)
   - Go to **DNS** in Hetzner Console
   - Add zone for your domain
   - We'll add the A record after server creation

### Step 1.3: Prepare SSH Access
1. **Generate SSH Key** (if you don't have one)
   ```bash
   ssh-keygen -t ed25519 -C "obsidian-admin@yourdomain.com"
   # Save as: ~/.ssh/obsidian_hetzner
   ```

2. **Add SSH Key to Hetzner**
   - Go to **Security** → **SSH Keys**
   - Click **Add SSH Key**
   - Name: `obsidian-admin`
   - Paste your public key content

---

## 🏗️ Phase 2: Deploy Command & Control Server

### Step 2.1: Create C&C Server Instance
1. **Create New Server**
   - Go to **Servers** → **Add Server**
   - **Location**: Same as project location
   - **Image**: Ubuntu 24.04
   - **Type**: **CX31** (2 vCPU, 8GB RAM, 80GB SSD) - Minimum recommended
   - **Networking**: 
     - ✅ Public IPv4
     - ✅ Public IPv6 (optional)
   - **SSH Keys**: Select your `obsidian-admin` key
   - **Name**: `obsidian-cnc-server`
   - **Labels**: 
     ```
     environment: production
     role: command-control
     project: obsidian
     ```

2. **Note Server Details**
   ```bash
   # Save these details for later use
   SERVER_NAME=obsidian-cnc-server
   SERVER_IP=<your-server-ip>
   DOMAIN=control.obsidian.example.com
   ```

### Step 2.2: Configure DNS Record
1. **Add A Record**
   - Go to **DNS** → Your domain zone
   - Add Record:
     ```
     Type: A
     Name: control (or @ for root domain)
     Value: <your-server-ip>
     TTL: 300
     ```

2. **Verify DNS Resolution**
   ```bash
   # Wait 2-5 minutes, then test
   nslookup control.obsidian.example.com
   # Should return your server IP
   ```

### Step 2.3: Connect to Server
```bash
# Connect via SSH
ssh -i ~/.ssh/obsidian_hetzner root@<your-server-ip>

# Update system first
apt update && apt upgrade -y
```

### Step 2.4: Prepare Environment Configuration
```bash
# Create configuration directory
mkdir -p /root/obsidian-config

# Set GitHub PAT Token for repository access
export GITHUB_PAT_TOKEN="ghp_your_personal_access_token_here"

# Generate secure passwords
export DB_PASSWORD="$(openssl rand -base64 32)"
export KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -base64 16)"
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 16)"
export CLUSTER_JOIN_TOKEN="$(openssl rand -base64 32)"

# Create environment file
cat > /root/obsidian-config/cnc.env << EOF
# GitHub Configuration
export GITHUB_PAT_TOKEN="$GITHUB_PAT_TOKEN"

# Obsidian C&C Configuration
export DOMAIN="control.obsidian.example.com"
export EMAIL="admin@obsidian.example.com"
export ADMIN_EMAIL="admin@obsidian.example.com"

# Generated Passwords (SAVE THESE SECURELY)
export DB_PASSWORD="$DB_PASSWORD"
export KEYCLOAK_ADMIN_PASSWORD="$KEYCLOAK_ADMIN_PASSWORD"
export GRAFANA_ADMIN_PASSWORD="$GRAFANA_ADMIN_PASSWORD"
export CLUSTER_JOIN_TOKEN="$CLUSTER_JOIN_TOKEN"

# VPN Configuration
export WG_NETWORK_CIDR="10.0.0.0/24"
export WG_SERVER_IP="10.0.0.1"
export WG_PORT="51820"

# Backup Configuration - DISABLED FOR NOW
# export S3_BUCKET="obsidian-backups"
# export S3_ACCESS_KEY="your-s3-access-key"
# export S3_SECRET_KEY="your-s3-secret-key"
# export S3_ENDPOINT="https://s3.amazonaws.com"

# Email Configuration (Optional - for notifications)
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="noreply@obsidian.example.com"
export SMTP_PASSWORD="your-smtp-password"
EOF

# Display passwords for secure storage
echo "=== SAVE THESE PASSWORDS SECURELY ==="
echo "GitHub PAT Token: $GITHUB_PAT_TOKEN"
echo "Database Password: $DB_PASSWORD"
echo "Keycloak Admin Password: $KEYCLOAK_ADMIN_PASSWORD"
echo "Grafana Admin Password: $GRAFANA_ADMIN_PASSWORD"
echo "Cluster Join Token: $CLUSTER_JOIN_TOKEN"
echo "========================================"
```

### Step 2.5: Authenticate with GitHub and Download Bootstrap Script
```bash
# Configure Git with authentication
git config --global user.name "Obsidian Deployer"
git config --global user.email "admin@obsidian.example.com"

# Load configuration first
source /root/obsidian-config/cnc.env

# Authenticate with GitHub using PAT token
echo "https://$GITHUB_PAT_TOKEN@github.com" > /root/.git-credentials
git config --global credential.helper store

# Clone the repository to get latest scripts
cd /tmp
git clone https://github.com/CallumWalton/obsidian-node.git
cd obsidian-node

# Copy the bootstrap script
cp obsidian_cnc_bootstrap.py /root/
chmod +x /root/obsidian_cnc_bootstrap.py
```

### Step 2.6: Execute Bootstrap Script
```bash
# Run the Python bootstrap script (this will take 10-15 minutes)
python3 /root/obsidian_cnc_bootstrap.py 2>&1 | tee /var/log/obsidian-cnc-bootstrap.log

# Monitor progress
tail -f /var/log/obsidian-cnc-bootstrap.log
```

### Step 2.7: Verify C&C Server Installation
```bash
# Run health check
/opt/obsidian-cnc/scripts/cnc_health_check.sh

# Check services status
systemctl status nginx wg-quick@wg0 cockpit.socket obsidian-cluster-api

# Verify SSL certificate
curl -I https://control.obsidian.example.com
```

---

## 🔧 Phase 3: Configure C&C Server

### Step 3.1: Access Web Interfaces
1. **Main Dashboard (Cockpit)**
   - URL: `https://control.obsidian.example.com`
   - Login with system user credentials (create first)

2. **Keycloak Admin Console**
   - URL: `https://control.obsidian.example.com/auth/admin`
   - Username: `admin`
   - Password: `$KEYCLOAK_ADMIN_PASSWORD` (from step 2.4)

3. **Grafana Dashboard**
   - URL: `https://control.obsidian.example.com/grafana`
   - Username: `admin`
   - Password: `$GRAFANA_ADMIN_PASSWORD` (from step 2.4)

### Step 3.2: Create System Admin User
```bash
# Create admin user for Cockpit access
useradd -m -G sudo obsidian-admin
passwd obsidian-admin
# Enter a secure password when prompted

# Add to obsidian group
usermod -a -G obsidian obsidian-admin
```

### Step 3.3: Configure Keycloak Realm
1. **Create Obsidian Realm**
   - Login to Keycloak Admin Console
   - **Master** dropdown → **Add Realm**
   - **Name**: `obsidian`
   - **Display Name**: `Obsidian Platform`
   - Click **Create**

2. **Create Admin User**
   - Go to **Users** → **Add User**
   - **Username**: `obsidian-admin`
   - **Email**: `admin@obsidian.example.com`
   - **First Name**: `Obsidian`
   - **Last Name**: `Administrator`
   - **User Enabled**: ON
   - Click **Save**

3. **Set User Password**
   - Go to **Credentials** tab
   - **Password**: Create secure password
   - **Temporary**: OFF
   - Click **Set Password**

4. **Create Obsidian Group**
   - Go to **Groups** → **New**
   - **Name**: `obsidian`
   - Click **Save**
   - Add `obsidian-admin` user to group

### Step 3.4: Configure OIDC Clients
1. **Create Cockpit Client**
   - Go to **Clients** → **Create**
   - **Client ID**: `cockpit-cnc`
   - **Client Protocol**: `openid-connect`
   - Click **Save**
   
2. **Configure Client Settings**
   - **Access Type**: `confidential`
   - **Valid Redirect URIs**: `https://control.obsidian.example.com/*`
   - **Web Origins**: `https://control.obsidian.example.com`
   - Click **Save**

3. **Get Client Secret**
   - Go to **Credentials** tab
   - Note the **Secret** (you'll need this for Cockpit configuration)

### Step 3.5: Create First VPN Client
```bash
# Create VPN client for admin access
/opt/obsidian-cnc/scripts/add_wireguard_client.sh admin-laptop 10.0.0.2

# Display client configuration (save this securely)
cat /etc/wireguard/clients/admin-laptop.conf

# Generate QR code for mobile devices
qrencode -t ansiutf8 < /etc/wireguard/clients/admin-laptop.conf
```

---

## 🖥️ Phase 4: Deploy Client Node

### Step 4.1: Create Client Server Instance
1. **Create New Server**
   - Go to **Servers** → **Add Server**
   - **Location**: Same as C&C server
   - **Image**: Ubuntu 24.04
   - **Type**: **CX21** (2 vCPU, 4GB RAM, 40GB SSD) - Minimum for client
   - **Networking**: 
     - ✅ Public IPv4
     - ❌ Public IPv6 (not needed for client)
   - **SSH Keys**: Select your `obsidian-admin` key
   - **Name**: `obsidian-node-01`
   - **Labels**: 
     ```
     environment: production
     role: client-node
     project: obsidian
     node-id: 01
     ```

2. **Note Client Server Details**
   ```bash
   CLIENT_IP=<client-server-ip>
   CLIENT_NAME=obsidian-node-01
   ```

### Step 4.2: Prepare Client Configuration
1. **Connect to C&C Server**
   ```bash
   ssh -i ~/.ssh/obsidian_hetzner root@<cnc-server-ip>
   ```

2. **Create VPN Client for Node**
   ```bash
   # Create VPN configuration for the client node
   /opt/obsidian-cnc/scripts/add_wireguard_client.sh node01 10.0.0.10
   
   # Get WireGuard server public key
   WG_SERVER_PUBLIC_KEY=$(cat /opt/obsidian-cnc/wireguard_server_public_key)
   echo "Server Public Key: $WG_SERVER_PUBLIC_KEY"
   
   # Get client configuration
   cat /etc/wireguard/clients/node01.conf
   ```

3. **Prepare Client Environment File**
   ```bash
   # Create client configuration (update with actual values)
   cat > /root/obsidian-config/client.env << EOF
   # Obsidian Client Node Configuration
   export CNC_FQDN="control.obsidian.example.com"
   export CLUSTER_CA_PEM=""
   export CLUSTER_JOIN_TOKEN="$CLUSTER_JOIN_TOKEN"
   export KEYCLOAK_REALM_URL="https://control.obsidian.example.com/auth/realms/obsidian"
   
   # VPN Configuration  
   export WG_DNS_IP="10.0.0.1"
   export WG_SERVER_ENDPOINT="control.obsidian.example.com:51820"
   export WG_PSK=""
   export WG_PORT="51820"
   export WG_SERVER_PUBLIC_KEY="$WG_SERVER_PUBLIC_KEY"
   
   # Pterodactyl Configuration (generate UUID)
   export PTERO_VERSION="1.11.0"
   export PANEL_URL="https://control.obsidian.example.com"
   export NODE_UUID="$(uuidgen)"
   export TOKEN="ptlc_example_token_replace_with_real"
   
   # Backup Configuration - DISABLED FOR NOW
   export S3_BUCKET="obsidian-node-backups"
   export S3_ACCESS_KEY="your-s3-access-key"
   export S3_SECRET_KEY="your-s3-secret-key"
   export S3_ENDPOINT="https://s3.amazonaws.com"
   
   # Operations
   export ADMIN_EMAIL="admin@obsidian.example.com"
   export WINGS_PORTS="8080,2022"
   EOF
   ```

### Step 4.3: Connect to Client Node and Deploy
1. **Connect to Client Node**
   ```bash
   ssh -i ~/.ssh/obsidian_hetzner root@<client-server-ip>
   
   # Update system
   apt update && apt upgrade -y
   ```

2. **Transfer Configuration and Scripts**
   ```bash
   # On C&C server, prepare transfer
   scp -i ~/.ssh/obsidian_hetzner /root/obsidian-config/client.env root@<client-server-ip>:/root/
   scp -i ~/.ssh/obsidian_hetzner /etc/wireguard/clients/node01.conf root@<client-server-ip>:/root/
   ```

3. **Download Client Bootstrap Script**
   ```bash
   # On client node - authenticate with GitHub using the same PAT token
   export GITHUB_PAT_TOKEN="ghp_your_personal_access_token_here"  # Same as C&C server
   
   # Configure Git with authentication
   git config --global user.name "Obsidian Deployer"
   git config --global user.email "admin@obsidian.example.com"
   echo "https://$GITHUB_PAT_TOKEN@github.com" > /root/.git-credentials
   git config --global credential.helper store
   
   # Clone repository and get bootstrap script
   cd /tmp
   git clone https://github.com/CallumWalton/obsidian-node.git
   cd obsidian-node
   cp obsidian_bootstrap.py /root/
   chmod +x /root/obsidian_bootstrap.py
   ```

4. **Prepare Client WireGuard Configuration**
   ```bash
   # Install WireGuard first
   apt install -y wireguard
   
   # Copy client configuration
   install -d -m 700 /etc/wireguard
   cp /root/node01.conf /etc/wireguard/wg0.conf
   chmod 600 /etc/wireguard/wg0.conf
   
   # Update configuration to use server public key
   source /root/client.env
   sed -i "s/SERVER_PUBLIC_KEY_PLACEHOLDER/$WG_SERVER_PUBLIC_KEY/" /etc/wireguard/wg0.conf
   ```

5. **Execute Client Bootstrap**
   ```bash
   # Load configuration
   source /root/client.env
   
   # Run Python bootstrap script
   python3 /root/obsidian_bootstrap.py 2>&1 | tee /var/log/obsidian-bootstrap.log
   ```

---

## ✅ Phase 5: Verification and Testing

### Step 5.1: Verify VPN Connectivity
1. **On C&C Server**
   ```bash
   # Check WireGuard status
   wg show wg0
   
   # Should show connected clients
   # Test ping to client
   ping -c 3 10.0.0.10
   ```

2. **On Client Node**
   ```bash
   # Check WireGuard status
   wg show wg0
   
   # Test ping to C&C server
   ping -c 3 10.0.0.1
   
   # Test DNS resolution through VPN
   nslookup control.obsidian.example.com 10.0.0.1
   ```

### Step 5.2: Verify Node Registration
1. **Check C&C Server**
   ```bash
   # List registered nodes
   /opt/obsidian-cnc/scripts/manage_nodes.sh list
   
   # Check cluster status
   /opt/obsidian-cnc/scripts/manage_nodes.sh status
   ```

2. **Access Cockpit Dashboard**
   - URL: `https://control.obsidian.example.com`
   - Should show client node in connected systems

### Step 5.3: Test Client Node Access
1. **Access Client Cockpit via VPN**
   ```bash
   # Connect to client Cockpit (VPN required)
   # First install VPN client on your local machine using the admin-laptop.conf
   
   # Then access client at:
   # https://10.0.0.10:9090
   ```

### Step 5.4: Run Health Checks
```bash
# On C&C Server
/opt/obsidian-cnc/scripts/cnc_health_check.sh

# On Client Node  
/opt/obsidian-node/scripts/health_check.sh
```

---

## 🔐 Phase 6: Security Hardening

### Step 6.1: Update Firewall Rules on Hetzner
1. **Create Firewall for C&C Server**
   - Go to **Firewalls** → **Add Firewall**
   - **Name**: `obsidian-cnc-firewall`
   - **Rules**:
     ```
     Inbound:
     - SSH (22/tcp) from 0.0.0.0/0
     - HTTP (80/tcp) from 0.0.0.0/0  
     - HTTPS (443/tcp) from 0.0.0.0/0
     - WireGuard (51820/udp) from 0.0.0.0/0
     
     Outbound:
     - All traffic allowed
     ```
   - **Apply to**: `obsidian-cnc-server`

2. **Create Firewall for Client Node**
   - **Name**: `obsidian-client-firewall`
   - **Rules**:
     ```
     Inbound:
     - SSH (22/tcp) from <your-admin-ip>/32
     - WireGuard (51820/udp) from <cnc-server-ip>/32
     - Wings ports (8080,2022/tcp) from <cnc-server-ip>/32
     
     Outbound:
     - All traffic allowed
     ```
   - **Apply to**: `obsidian-node-01`

### Step 6.2: Configure SSH Security
```bash
# On both servers
cat >> /etc/ssh/sshd_config << EOF

# Obsidian Security Hardening
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
X11Forwarding no
AllowUsers obsidian-admin root
EOF

systemctl restart sshd
```

### Step 6.3: Set Up Monitoring Alerts
1. **Configure Grafana Alerts**
   - Access Grafana: `https://control.obsidian.example.com/grafana`
   - Import Node Exporter dashboard (ID: 1860)
   - Set up alerts for high CPU, memory, and disk usage

2. **Configure Email Notifications**
   - Set up SMTP configuration in Grafana
   - Test notification channels

---

## 📊 Phase 7: Operational Procedures

### Step 7.1: Daily Operations Checklist
```bash
# Run on C&C server daily
/opt/obsidian-cnc/scripts/cnc_health_check.sh
/opt/obsidian-cnc/scripts/manage_nodes.sh status

# Check backup status - S3 BACKUPS CURRENTLY DISABLED
# systemctl status obsidian-cnc-backup.timer
# restic snapshots --repo s3:$S3_ENDPOINT/$S3_BUCKET-cnc

# Check for updates in the repository
cd /tmp/obsidian-node && git pull origin main
```

### Step 7.2: Access Patterns
- **Admin VPN Access**: Use `admin-laptop.conf` for secure access
- **C&C Dashboard**: `https://control.obsidian.example.com`
- **Client Management**: Access via VPN at `https://10.0.0.10:9090`
- **Monitoring**: `https://control.obsidian.example.com/grafana`

### Step 7.3: Adding More Nodes
```bash
# For each additional node:
# 1. Create new Hetzner server
# 2. Generate new VPN client configuration
/opt/obsidian-cnc/scripts/add_wireguard_client.sh node02 10.0.0.11

# 3. Deploy using same client bootstrap process
# 4. Update IP address in client configuration
```

---

## 💰 Cost Estimation (Hetzner Cloud)

### Monthly Costs (EUR)
- **CX31 (C&C Server)**: ~€8.50/month
- **CX21 (Client Node)**: ~€5.90/month
- **Backup Storage**: Not configured (S3 backups disabled)
- **Bandwidth**: Usually included (20TB/month)

**Total Monthly Cost**: ~€14.40/month for basic setup

### Cost Optimization Tips
- Use **CX11** (€3.29) for development/testing client nodes
- Enable **backups** through Hetzner for additional safety (20% of server cost)
- Consider **load balancers** for high availability (€5.39/month)

---

## 🚨 Troubleshooting Common Issues

### Issue 1: SSL Certificate Failed
```bash
# Check DNS resolution
nslookup control.obsidian.example.com

# Manual certificate request
certbot certonly --nginx -d control.obsidian.example.com

# Check nginx configuration
nginx -t
```

### Issue 2: VPN Connection Issues
```bash
# On C&C server - check WireGuard
wg show wg0
systemctl status wg-quick@wg0

# Check firewall
ufw status verbose
```

### Issue 3: Client Node Not Connecting
```bash
# Check client VPN configuration
wg show wg0

# Test connectivity
ping 10.0.0.1

# Check services
systemctl status wg-quick@wg0 cockpit.socket
```

### Issue 4: Performance Issues
```bash
# Check system resources
htop
iotop
df -h

# Consider upgrading server types in Hetzner Console
```

---

## 🎉 Deployment Complete!

**Congratulations!** You now have a fully functional Obsidian infrastructure running on Hetzner Cloud:

✅ **Command & Control Server** - Centralized management at `https://control.obsidian.example.com`  
✅ **Secure VPN Network** - Private network for all management traffic  
✅ **Client Node** - Managed server connected via VPN  
✅ **Monitoring Stack** - Prometheus + Grafana for observability  
✅ **Identity Management** - Keycloak SSO for secure access  
✅ **Git Integration** - Automated deployment from GitHub repository  
✅ **Automated Updates** - Pull latest configurations from Git repository  

### Next Steps
1. **Add more client nodes** using the same process
2. **Configure monitoring dashboards** in Grafana  
3. **Set up alerting rules** for proactive monitoring
4. **Configure S3 backup system** when ready (currently disabled)
5. **Implement automated deployment pipelines** using Git webhooks
6. **Document access procedures** for your team

### Support Resources
- **Health Checks**: Run daily on both servers
- **Log Locations**: `/var/log/obsidian-*bootstrap.log`
- **Configuration**: All configs in `/opt/obsidian-*/`
- **Management Scripts**: Located in respective `scripts/` directories

**Your Obsidian platform is now ready for production use!** 🚀
