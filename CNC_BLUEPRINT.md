# Obsidian Command & Control (C&C) Server Blueprint

**Version:** 1.0  
**Date:** July 19, 2025  
**Target:** Ubuntu 24.04 LTS  
**Purpose:** Centralized management infrastructure for Obsidian node ecosystem

## 🎯 Executive Summary

The Obsidian Command & Control (C&C) Bootstrap Script provisions Ubuntu 24.04 LTS virtual machines as the central management hub for the entire Obsidian platform ecosystem. This server provides secure VPN infrastructure, identity management, monitoring, and centralized administration for all connected Obsidian nodes.

### Key Infrastructure Components
- ✅ **WireGuard VPN Server** - Secure private network for all management traffic
- ✅ **Centralized Cockpit** - Web-based management console for entire fleet
- ✅ **Keycloak SSO** - Single sign-on and identity management
- ✅ **Prometheus + Grafana** - Comprehensive monitoring and alerting
- ✅ **Cluster Management API** - Automated node registration and management
- ✅ **SSL/TLS Termination** - Secure external access via Nginx reverse proxy

---

## 📋 Pre-Deployment Requirements

### Infrastructure Prerequisites
- [ ] Ubuntu 24.04 LTS VM with root access
- [ ] Minimum 4 CPU cores, 8GB RAM, 100GB storage
- [ ] Public IP address and domain name configured
- [ ] Internet connectivity for package installation
- [ ] SMTP server access for notifications

### Network Requirements
- [ ] Domain name pointing to server IP (A record)
- [ ] Ports 80, 443, and WireGuard port accessible from internet
- [ ] Firewall rules allowing inbound traffic on required ports
- [ ] S3-compatible storage for backups

### Required Configuration Variables
All variables must be provided via environment substitution:

```bash
# Core Infrastructure
export DOMAIN="control.obsidian.example.com"
export EMAIL="admin@obsidian.example.com"
export ADMIN_EMAIL="admin@obsidian.example.com"

# Database & Authentication
export DB_PASSWORD="$(openssl rand -base64 32)"
export KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -base64 16)"
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 16)"

# VPN Configuration
export WG_NETWORK_CIDR="10.0.0.0/24"
export WG_SERVER_IP="10.0.0.1"
export WG_PORT="51820"

# Backup Configuration
export S3_BUCKET="obsidian-backups"
export S3_ACCESS_KEY="AKIA..."
export S3_SECRET_KEY="..."
export S3_ENDPOINT="https://s3.us-east-1.amazonaws.com"

# Email Configuration
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="noreply@obsidian.example.com"
export SMTP_PASSWORD="smtp-password"
```

---

## 🏗️ Architecture Overview

### Service Architecture
```
Internet -> [Nginx SSL Proxy] -> [Service Router]
                                        ├─ Cockpit Management (/)
                                        ├─ Keycloak SSO (/auth/)
                                        ├─ Grafana Monitoring (/grafana/)
                                        └─ Cluster API (/api/)

WireGuard VPN Server -> Private Network (10.0.0.0/24)
                               ├─ C&C Server (10.0.0.1)
                               └─ Node Clients (10.0.0.2+)
```

### Component Stack
| Layer | Component | Purpose |
|-------|-----------|---------|
| **Proxy** | Nginx | SSL termination, reverse proxy, security headers |
| **Management** | Cockpit | Web-based system administration interface |
| **Identity** | Keycloak | SSO, OIDC provider, user management |
| **Monitoring** | Prometheus + Grafana | Metrics collection, visualization, alerting |
| **VPN** | WireGuard | Secure private network for node communication |
| **API** | Flask API | Node registration, cluster management |
| **Database** | PostgreSQL | Keycloak data, node registry |
| **Cache** | Redis | Session storage, caching |

---

## 🚀 Deployment Guide

### Pre-Deployment Checklist
1. **DNS Configuration**
   ```bash
   # Verify DNS resolution
   nslookup control.obsidian.example.com
   ```

2. **Generate Secure Passwords**
   ```bash
   export DB_PASSWORD="$(openssl rand -base64 32)"
   export KEYCLOAK_ADMIN_PASSWORD="$(openssl rand -base64 16)"
   export GRAFANA_ADMIN_PASSWORD="$(openssl rand -base64 16)"
   
   # Save passwords securely
   echo "DB_PASSWORD=$DB_PASSWORD" >> /root/obsidian-secrets.env
   echo "KEYCLOAK_ADMIN_PASSWORD=$KEYCLOAK_ADMIN_PASSWORD" >> /root/obsidian-secrets.env
   echo "GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD" >> /root/obsidian-secrets.env
   ```

3. **Configure Environment**
   ```bash
   # Create configuration file
   cat > /root/obsidian-cnc.env << EOF
   export DOMAIN="control.obsidian.example.com"
   export EMAIL="admin@obsidian.example.com"
   export ADMIN_EMAIL="admin@obsidian.example.com"
   export DB_PASSWORD="your-generated-password"
   export KEYCLOAK_ADMIN_PASSWORD="your-keycloak-password"
   export GRAFANA_ADMIN_PASSWORD="your-grafana-password"
   export WG_NETWORK_CIDR="10.0.0.0/24"
   export WG_SERVER_IP="10.0.0.1"
   export WG_PORT="51820"
   export S3_BUCKET="obsidian-backups"
   export S3_ACCESS_KEY="your-s3-access-key"
   export S3_SECRET_KEY="your-s3-secret-key"
   export S3_ENDPOINT="https://s3.us-east-1.amazonaws.com"
   export SMTP_HOST="smtp.example.com"
   export SMTP_PORT="587"
   export SMTP_USER="noreply@obsidian.example.com"
   export SMTP_PASSWORD="your-smtp-password"
   EOF
   ```

### Deployment Methods

#### Method 1: Direct Execution (Recommended)
```bash
# Download and prepare script
curl -o obsidian_cnc_bootstrap.sh https://your-repo.com/obsidian_cnc_bootstrap.sh
chmod +x obsidian_cnc_bootstrap.sh

# Load configuration
source /root/obsidian-cnc.env

# Substitute variables and execute
envsubst < obsidian_cnc_bootstrap.sh > cnc_bootstrap_configured.sh
chmod +x cnc_bootstrap_configured.sh
./cnc_bootstrap_configured.sh 2>&1 | tee /var/log/obsidian-cnc-bootstrap.log
```

#### Method 2: Terraform Deployment
```hcl
resource "aws_instance" "obsidian_cnc" {
  ami                    = "ami-ubuntu-24.04"
  instance_type          = "t3.large"
  key_name              = var.key_name
  vpc_security_group_ids = [aws_security_group.obsidian_cnc.id]
  
  user_data = templatefile("obsidian_cnc_bootstrap.sh", {
    DOMAIN = var.domain
    EMAIL = var.email
    # ... all variables
  })
  
  tags = {
    Name = "Obsidian-CnC-Server"
  }
}

resource "aws_security_group" "obsidian_cnc" {
  name_prefix = "obsidian-cnc-"
  
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

#### Method 3: Cloud-Init
```yaml
#cloud-config
packages:
  - curl
  - wget
  - envsubst

write_files:
  - path: /root/obsidian-cnc.env
    permissions: '0600'
    content: |
      export DOMAIN="${DOMAIN}"
      export EMAIL="${EMAIL}"
      # ... all environment variables

  - path: /tmp/obsidian_cnc_bootstrap.sh
    permissions: '0755'
    encoding: b64
    content: |
      [BASE64_ENCODED_SCRIPT_CONTENT]

runcmd:
  - source /root/obsidian-cnc.env
  - envsubst < /tmp/obsidian_cnc_bootstrap.sh > /tmp/cnc_configured.sh
  - chmod +x /tmp/cnc_configured.sh
  - /tmp/cnc_configured.sh 2>&1 | tee /var/log/obsidian-cnc-bootstrap.log
```

---

## 🔧 Post-Deployment Configuration

### 1. SSL Certificate Verification
```bash
# Verify SSL certificate installation
curl -I https://control.obsidian.example.com

# Check certificate details
openssl s_client -connect control.obsidian.example.com:443 -servername control.obsidian.example.com < /dev/null
```

### 2. Keycloak Realm Setup
1. **Access Keycloak Admin Console**
   - URL: `https://control.obsidian.example.com/auth/admin`
   - Username: `admin`
   - Password: `${KEYCLOAK_ADMIN_PASSWORD}`

2. **Create Obsidian Realm**
   ```json
   {
     "realm": "obsidian",
     "enabled": true,
     "displayName": "Obsidian Platform",
     "loginTheme": "obsidian"
   }
   ```

3. **Configure OIDC Clients**
   - **cockpit-cnc**: Main Cockpit interface
   - **cockpit-obsidian**: Node Cockpit instances
   - **grafana**: Monitoring dashboard

### 3. Grafana Dashboard Import
```bash
# Access Grafana
# URL: https://control.obsidian.example.com/grafana
# Username: admin
# Password: ${GRAFANA_ADMIN_PASSWORD}

# Import recommended dashboards:
# - Node Exporter Full (ID: 1860)
# - Docker Monitoring (ID: 893)
# - WireGuard Dashboard (ID: 13501)
```

### 4. First VPN Client Setup
```bash
# Add first management client
/opt/obsidian-cnc/scripts/add_wireguard_client.sh admin-laptop 10.0.0.2

# View QR code for mobile setup
qrencode -t ansiutf8 < /etc/wireguard/clients/admin-laptop.conf
```

---

## 📊 Operations Manual

### Daily Operations

#### Node Management
```bash
# List all registered nodes
/opt/obsidian-cnc/scripts/manage_nodes.sh list

# Check cluster status
/opt/obsidian-cnc/scripts/manage_nodes.sh status

# Add new VPN client for node
/opt/obsidian-cnc/scripts/add_wireguard_client.sh node01 10.0.0.10
```

#### Health Monitoring
```bash
# Run comprehensive health check
/opt/obsidian-cnc/scripts/cnc_health_check.sh

# Monitor service logs
journalctl -f -u obsidian-cluster-api
docker compose -f /opt/obsidian-cnc/docker-compose.keycloak.yml logs -f
docker compose -f /opt/obsidian-cnc/docker-compose.monitoring.yml logs -f
```

#### Backup Verification
```bash
# Check backup status
systemctl status obsidian-cnc-backup.timer

# Manual backup execution
/opt/obsidian-cnc/scripts/backup_cnc.sh

# List backup snapshots
source /etc/restic/env.d/cnc-backup.env && restic snapshots
```

### Maintenance Procedures

#### Certificate Renewal
```bash
# Certificates auto-renew via certbot
# Check renewal status
certbot certificates

# Manual renewal if needed
certbot renew --nginx
```

#### Service Updates
```bash
# Update Docker containers
cd /opt/obsidian-cnc
docker compose -f docker-compose.keycloak.yml pull
docker compose -f docker-compose.monitoring.yml pull
docker compose -f docker-compose.keycloak.yml up -d
docker compose -f docker-compose.monitoring.yml up -d
```

#### Database Maintenance
```bash
# PostgreSQL maintenance
sudo -u postgres psql -c "VACUUM ANALYZE;"

# View database size
sudo -u postgres psql -c "SELECT pg_size_pretty(pg_database_size('keycloak'));"
```

### Monitoring & Alerting

#### Key Metrics to Monitor
- **WireGuard VPN**: Connection count, bandwidth usage
- **Cockpit**: Active sessions, authentication failures  
- **Keycloak**: Login success/failure rates, token issuance
- **System Resources**: CPU, memory, disk usage
- **Docker Containers**: Container health, resource usage
- **Network**: Bandwidth utilization, connection counts

#### Alert Configurations
```yaml
# Prometheus Alert Rules Example
groups:
  - name: obsidian-cnc
    rules:
      - alert: HighCPUUsage
        expr: cpu_usage > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on C&C server"

      - alert: KeycloakDown
        expr: up{job="keycloak"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Keycloak service is down"
```

---

## 🚨 Troubleshooting Guide

### Common Issues

#### SSL Certificate Issues
```bash
# Check certificate status
certbot certificates

# Renewal issues
tail -f /var/log/letsencrypt/letsencrypt.log

# Manual certificate test
certbot --nginx --dry-run -d control.obsidian.example.com
```

#### WireGuard Connectivity Problems
```bash
# Check WireGuard status
wg show wg0

# View WireGuard logs
journalctl -u wg-quick@wg0 -f

# Test client connectivity
ping 10.0.0.2  # Test specific client IP
```

#### Docker Container Issues
```bash
# Check container status
docker ps -a

# View container logs
docker logs keycloak
docker logs prometheus
docker logs grafana

# Restart containers
cd /opt/obsidian-cnc
docker compose -f docker-compose.keycloak.yml restart
docker compose -f docker-compose.monitoring.yml restart
```

#### Database Connection Issues
```bash
# Check PostgreSQL status
systemctl status postgresql

# Test database connectivity
sudo -u postgres psql -l

# Check Keycloak database
sudo -u postgres psql keycloak -c "SELECT COUNT(*) FROM user_entity;"
```

### Recovery Procedures

#### Complete Service Recovery
```bash
# Stop all services
systemctl stop nginx cockpit.socket obsidian-cluster-api
cd /opt/obsidian-cnc
docker compose -f docker-compose.keycloak.yml down
docker compose -f docker-compose.monitoring.yml down

# Restart in order
systemctl start postgresql redis-server
docker compose -f docker-compose.keycloak.yml up -d
docker compose -f docker-compose.monitoring.yml up -d
systemctl start obsidian-cluster-api cockpit.socket nginx

# Run health check
/opt/obsidian-cnc/scripts/cnc_health_check.sh
```

#### Backup Restoration
```bash
# List available backups
source /etc/restic/env.d/cnc-backup.env
restic snapshots

# Restore specific snapshot
restic restore <snapshot-id> --target /tmp/restore
```

---

## 🔐 Security Considerations

### Access Control
- **Multi-Factor Authentication**: Configure MFA in Keycloak for all admin accounts
- **Role-Based Access**: Implement granular permissions for different user roles
- **Session Management**: Configure appropriate session timeouts
- **Audit Logging**: Enable comprehensive audit logs for all administrative actions

### Network Security
- **VPN-Only Management**: Critical management interfaces only accessible via VPN
- **SSL/TLS**: All external communication encrypted with strong ciphers
- **Firewall Rules**: Minimal exposed services with strict rules
- **DDoS Protection**: Consider implementing rate limiting and DDoS protection

### Data Protection
- **Database Encryption**: Enable encryption at rest for PostgreSQL
- **Backup Encryption**: All backups encrypted using Restic
- **Secret Management**: Rotate passwords and keys regularly
- **Container Security**: Regular security updates for all container images

---

## 📈 Scaling Considerations

### Horizontal Scaling
- **Load Balancer**: Add load balancer for high availability
- **Database Cluster**: Scale PostgreSQL with read replicas
- **Container Orchestration**: Consider Kubernetes for larger deployments

### Performance Optimization
- **Database Tuning**: Optimize PostgreSQL for workload
- **Caching**: Implement Redis caching for frequently accessed data
- **CDN**: Use CDN for static assets and improved global performance

### Monitoring Scaling
- **Metrics Retention**: Adjust Prometheus retention based on requirements
- **Log Aggregation**: Implement centralized logging solution
- **Alerting Channels**: Configure multiple notification channels

---

## 📞 Support Information

### Log Locations
- **Bootstrap Logs**: `/var/log/obsidian-cnc-bootstrap.log`
- **Application Logs**: `/opt/obsidian-cnc/logs/`
- **Nginx Logs**: `/var/log/nginx/`
- **System Logs**: `/var/log/syslog`, `/var/log/auth.log`
- **Docker Logs**: `docker logs [container-name]`

### Configuration Files
- **Main Config**: `/opt/obsidian-cnc/config/`
- **Nginx Config**: `/etc/nginx/sites-available/obsidian-cnc`
- **WireGuard Config**: `/etc/wireguard/wg0.conf`
- **SSL Certificates**: `/etc/letsencrypt/live/DOMAIN/`

### Quick Commands Reference
```bash
# Service status overview
/opt/obsidian-cnc/scripts/cnc_health_check.sh

# Add VPN client
/opt/obsidian-cnc/scripts/add_wireguard_client.sh <name> <ip>

# Node management
/opt/obsidian-cnc/scripts/manage_nodes.sh list

# View logs
tail -f /var/log/obsidian-cnc-bootstrap.log
journalctl -f -u obsidian-cluster-api

# Restart services
systemctl restart obsidian-cluster-api nginx cockpit.socket
cd /opt/obsidian-cnc && docker compose -f docker-compose.keycloak.yml restart
```

---

## 📄 Integration with Node Bootstrap

### Node Configuration Updates
When deploying nodes using the `obsidian_bootstrap.sh` script, use these C&C server values:

```bash
# Update node bootstrap variables to point to this C&C server
export CNC_FQDN="control.obsidian.example.com"
export KEYCLOAK_REALM_URL="https://control.obsidian.example.com/auth/realms/obsidian"
export WG_SERVER_ENDPOINT="control.obsidian.example.com:51820"
export WG_DNS_IP="10.0.0.1"

# Obtain from C&C server after bootstrap
export CLUSTER_CA_PEM="$(curl -s https://control.obsidian.example.com/ca.crt)"
export CLUSTER_JOIN_TOKEN="bearer-token-from-keycloak"
```

### Automated Node Provisioning
1. **Generate VPN Client Config**: Use C&C server to create VPN client configuration
2. **Distribute Server Public Key**: Include WireGuard server public key in node config
3. **Node Registration**: Nodes automatically register via cluster API on first boot
4. **Monitoring Integration**: Nodes appear in Grafana dashboard automatically

---

**⚠️ IMPORTANT SECURITY NOTICE**

This Command & Control server is the central hub for your entire Obsidian platform. Ensure:
- Strong passwords for all administrative accounts
- Regular security updates and patches
- Backup and disaster recovery procedures tested
- Network access restricted to authorized personnel only
- Multi-factor authentication enabled for all admin access

**For emergency recovery, maintain offline backups of critical configuration files and access credentials.**
