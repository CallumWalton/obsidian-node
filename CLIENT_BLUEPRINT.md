# Obsidian Node Client Blueprint

**Version:** 1.0  
**Date:** July 19, 2025  
**Target:** Ubuntu 24.04 LTS  
**Security Level:** Zero-Trust VPN-Only Access

## 🎯 Executive Summary

The Obsidian Node Bootstrap Script provisions Ubuntu 24.04 LTS virtual machines for secure integration into the Obsidian platform ecosystem. This blueprint ensures **zero public network exposure** for management interfaces while providing comprehensive monitoring, backup, and container orchestration capabilities.

### Key Security Features
- ✅ **WireGuard VPN-Only Access** - All management traffic isolated to private network
- ✅ **Zero Public Exposure** - Cockpit management interface completely blocked from internet
- ✅ **Multi-Layer Security** - Firewall, interface binding, and service dependencies
- ✅ **Automated Security Validation** - Continuous monitoring of security posture

---

## 📋 Pre-Deployment Requirements

### Infrastructure Prerequisites
- [ ] Ubuntu 24.04 LTS VM with root access
- [ ] Minimum 2 CPU cores, 4GB RAM, 20GB storage
- [ ] Internet connectivity for package installation
- [ ] Cloud metadata service accessible (for initial provisioning only)

### Network Requirements
- [ ] WireGuard server infrastructure operational
- [ ] Command & Control Cockpit server accessible via VPN
- [ ] Keycloak SSO realm configured and accessible
- [ ] S3-compatible backup storage configured

### Required Configuration Variables
All variables must be provided via environment substitution:

```bash
# Core Infrastructure
export CNC_FQDN="control.obsidian.internal"
export CLUSTER_CA_PEM="-----BEGIN CERTIFICATE-----..."
export CLUSTER_JOIN_TOKEN="eyJhbGciOiJSUzI1NiIs..."

# Identity & Access
export KEYCLOAK_REALM_URL="https://sso.obsidian.internal/realms/obsidian"

# VPN Configuration
export WG_DNS_IP="10.0.0.1"
export WG_SERVER_ENDPOINT="vpn.obsidian.internal:51820"
export WG_PSK="optional-preshared-key"
export WG_PORT="51820"

# Pterodactyl Integration
export PTERO_VERSION="1.11.0"
export PANEL_URL="https://panel.obsidian.internal"
export NODE_UUID="550e8400-e29b-41d4-a716-446655440000"
export TOKEN="ptlc_..."

# Backup Configuration
export S3_BUCKET="obsidian-node-backups"
export S3_ACCESS_KEY="AKIA..."
export S3_SECRET_KEY="..."
export S3_ENDPOINT="https://s3.us-east-1.amazonaws.com"

# Operations
export ADMIN_EMAIL="admin@obsidian.internal"
export WINGS_PORTS="8080,2022"
```

---

## 🚀 Deployment Methods

### Method 1: Cloud-Init (Recommended)
```yaml
#cloud-config
package_update: true
package_upgrade: true

write_files:
  - path: /tmp/obsidian_bootstrap.sh
    permissions: '0755'
    encoding: b64
    content: |
      [BASE64_ENCODED_SCRIPT_CONTENT]
  
  - path: /tmp/env_config.sh
    permissions: '0644'
    content: |
      export CNC_FQDN="${CNC_FQDN}"
      export CLUSTER_CA_PEM="${CLUSTER_CA_PEM}"
      export CLUSTER_JOIN_TOKEN="${CLUSTER_JOIN_TOKEN}"
      # ... all other variables

runcmd:
  - source /tmp/env_config.sh
  - envsubst < /tmp/obsidian_bootstrap.sh > /tmp/bootstrap_final.sh
  - chmod +x /tmp/bootstrap_final.sh
  - /tmp/bootstrap_final.sh 2>&1 | tee /var/log/obsidian-bootstrap.log
```

### Method 2: Terraform Provisioner
```hcl
resource "aws_instance" "obsidian_node" {
  # ... instance configuration

  provisioner "file" {
    content = templatefile("obsidian_bootstrap.sh", {
      CNC_FQDN = var.cnc_fqdn
      CLUSTER_CA_PEM = var.cluster_ca_pem
      # ... all variables
    })
    destination = "/tmp/obsidian_bootstrap.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/obsidian_bootstrap.sh",
      "sudo /tmp/obsidian_bootstrap.sh"
    ]
  }
}
```

### Method 3: Ansible Playbook
```yaml
---
- name: Deploy Obsidian Node
  hosts: obsidian_nodes
  become: yes
  vars:
    obsidian_config:
      cnc_fqdn: "{{ cnc_fqdn }}"
      cluster_ca_pem: "{{ cluster_ca_pem }}"
      # ... all variables

  tasks:
    - name: Template bootstrap script
      template:
        src: obsidian_bootstrap.sh.j2
        dest: /tmp/obsidian_bootstrap.sh
        mode: '0755'

    - name: Execute bootstrap script
      shell: /tmp/obsidian_bootstrap.sh
      register: bootstrap_result

    - name: Display bootstrap output
      debug:
        var: bootstrap_result.stdout_lines
```

### Method 4: Direct Execution
```bash
# Download and prepare script
curl -o obsidian_bootstrap.sh https://your-repo.com/obsidian_bootstrap.sh
chmod +x obsidian_bootstrap.sh

# Set environment variables
source your_config.env

# Substitute variables and execute
envsubst < obsidian_bootstrap.sh > bootstrap_configured.sh
chmod +x bootstrap_configured.sh
sudo ./bootstrap_configured.sh
```

---

## 🔧 Installation Components

### A. Management Layer
**Cockpit Web Console**
- **Purpose:** Centralized system management and monitoring
- **Access:** VPN-only at `https://10.0.0.1:9090`
- **Features:** System metrics, service management, container oversight
- **Security:** OIDC integration with Keycloak, group-based access control

**Single Sign-On Integration**
- **Provider:** Keycloak OIDC
- **Access Control:** `obsidian` group membership required
- **Session Management:** 30-minute idle timeout, secure token handling

### B. Network Security
**WireGuard VPN Client**
- **Interface:** `wg0` with automatic startup
- **Traffic Routing:** All management traffic through VPN tunnel
- **DNS:** Private DNS resolution via VPN
- **Security:** Pre-shared key authentication, persistent keepalive

**Firewall Configuration**
- **Engine:** UFW with custom iptables rules
- **Policy:** Default deny incoming, allow outgoing
- **Exceptions:** SSH (22), WireGuard (port specified), Wings ports
- **Protection:** Cockpit access blocked on public interfaces

### C. Container Orchestration
**Docker Engine**
- **Version:** Latest stable from official repository
- **Configuration:** Log rotation, resource limits
- **Security:** Daemon socket protection, user namespace isolation

**Pterodactyl Wings**
- **Purpose:** Game server container management
- **Configuration:** Automated deployment from official repository
- **Integration:** Panel API connection, Docker network isolation
- **Security:** Dedicated user account, file system restrictions

### D. Data Protection
**Restic Backup System**
- **Schedule:** Daily backups at 02:00 UTC
- **Retention:** 7 daily, 4 weekly, 6 monthly snapshots
- **Storage:** S3-compatible backend with encryption
- **Coverage:** System configuration, application data, logs

**Automated Maintenance**
- **Updates:** Unattended security updates with email notifications
- **Restarts:** Automatic service restarts for security patches
- **Cleanup:** Package cache management, log rotation

### E. Observability Stack
**Monitoring Agents**
- **Prometheus Node Exporter:** System metrics collection
- **NetData:** Real-time performance monitoring (VPN-only access)
- **Telegraf:** Optional metrics forwarding to InfluxDB

**Health Monitoring**
- **System Checks:** Automated hourly health assessments
- **Service Monitoring:** Critical service status validation
- **Alert Integration:** Ready for external monitoring systems

---

## 🛡️ Security Architecture

### Zero-Trust Network Model
```
Internet -> [Firewall] -> Ubuntu VM
                 ↓
          [WireGuard VPN] -> Private Network
                 ↓
          [Cockpit Management] -> Obsidian C&C
```

### Access Control Matrix
| Service | Public Network | WireGuard VPN | Local Only |
|---------|----------------|---------------|------------|
| SSH | ✅ | ✅ | ✅ |
| Cockpit | ❌ | ✅ | ✅ |
| Wings API | ✅* | ✅ | ✅ |
| NetData | ❌ | ✅ | ✅ |
| Node Exporter | ❌ | ✅ | ✅ |

*Wings API exposure limited to configured panel communication

### Security Validation Points
1. **Pre-Service Startup:** WireGuard connectivity verification
2. **Interface Binding:** Cockpit restricted to VPN interface only  
3. **Firewall Rules:** Multiple layers blocking public management access
4. **Service Dependencies:** Management services require VPN operational
5. **Runtime Monitoring:** Continuous security posture assessment

---

## 📊 Operational Procedures

### Post-Deployment Verification
```bash
# Execute health check
sudo /opt/obsidian-node/scripts/health_check.sh

# Verify VPN connectivity
sudo wg show wg0

# Check service status
sudo systemctl status cockpit.socket wings docker

# Validate firewall rules
sudo ufw status verbose

# Test backup configuration
sudo /opt/obsidian-node/scripts/backup.sh --dry-run
```

### Cluster Integration
```bash
# Join Cockpit cluster (after VPN is operational)
sudo /opt/obsidian-node/scripts/join_cluster.sh

# Verify cluster membership
curl -k https://10.0.0.1:9090/cockpit/ws
```

### Monitoring Access Points
- **Cockpit Dashboard:** `https://10.0.0.1:9090` (VPN required)
- **NetData Metrics:** `http://10.0.0.1:19999` (VPN required)
- **Prometheus Metrics:** `http://10.0.0.1:9100/metrics` (VPN required)

### Log Locations
- **Bootstrap Logs:** `/var/log/obsidian-bootstrap.log`
- **Application Logs:** `/opt/obsidian-node/logs/`
- **System Logs:** `/var/log/syslog`, `/var/log/auth.log`
- **Docker Logs:** `docker logs [container]`

---

## 🔄 Maintenance Procedures

### Regular Maintenance Tasks
- **Daily:** Automated backups, security updates
- **Weekly:** Health check review, log rotation
- **Monthly:** Certificate renewal, dependency updates
- **Quarterly:** Security audit, configuration review

### Emergency Procedures
```bash
# Emergency VPN reconnection
sudo systemctl restart wg-quick@wg0.service
sudo systemctl restart cockpit.socket

# Service recovery
sudo systemctl restart wings.service
sudo systemctl restart docker.service

# Security incident response
sudo ufw reset
sudo /opt/obsidian-node/scripts/health_check.sh
```

### Update Procedures
The bootstrap script is idempotent and can be safely re-run for updates:
```bash
# Re-run bootstrap with updated configuration
sudo ./obsidian_bootstrap.sh
```

---

## 🚨 Troubleshooting Guide

### Common Issues

**WireGuard Connection Failures**
```bash
# Check WireGuard status
sudo wg show
sudo systemctl status wg-quick@wg0.service

# Verify configuration
sudo wg-quick down wg0
sudo wg-quick up wg0
```

**Cockpit Access Issues**
```bash
# Verify binding to VPN interface
sudo ss -tuln | grep 10.0.0.1:9090

# Check firewall rules
sudo iptables -L INPUT -n | grep 9090
```

**Wings Connection Problems**
```bash
# Check Wings logs
sudo journalctl -u wings.service -f

# Verify Docker connectivity
sudo docker ps
sudo systemctl status docker
```

### Diagnostic Commands
```bash
# Network connectivity test
ping -c 3 ${WG_DNS_IP}
curl -k https://${CNC_FQDN}/health

# Service status overview
sudo systemctl list-units --failed
sudo systemctl status obsidian-*

# Security posture check
sudo /opt/obsidian-node/scripts/health_check.sh
```

---

## 📈 Performance Specifications

### Resource Requirements
| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| Base System | 0.5 cores | 1GB | 5GB | 100Mbps |
| Cockpit | 0.1 cores | 256MB | 1GB | 10Mbps |
| Wings | 0.5 cores | 1GB | 5GB | 1Gbps |
| Docker | 0.2 cores | 512MB | 10GB | 500Mbps |
| Monitoring | 0.2 cores | 512MB | 2GB | 50Mbps |
| **Total Minimum** | **2 cores** | **4GB** | **25GB** | **100Mbps** |

### Scaling Considerations
- **Horizontal:** Multiple nodes behind load balancer
- **Vertical:** Increase resources based on container workload
- **Network:** WireGuard bandwidth scales with server capacity

---

## 🔐 Security Compliance

### Standards Alignment
- **Zero Trust Architecture:** All management access through VPN
- **Principle of Least Privilege:** Service-specific user accounts
- **Defense in Depth:** Multiple security layers and validation points
- **Audit Trail:** Comprehensive logging and monitoring

### Compliance Features
- **Data Encryption:** All backup data encrypted at rest and in transit
- **Access Logging:** Complete audit trail of management access
- **Automated Updates:** Security patches applied automatically
- **Network Segmentation:** Management traffic isolated from application traffic

---

## 📞 Support & Documentation

### Quick Reference Commands
```bash
# View system status
sudo /opt/obsidian-node/scripts/health_check.sh

# Access logs
sudo tail -f /var/log/obsidian-bootstrap.log

# Restart all services
sudo systemctl restart obsidian-startup.service

# Emergency security lockdown
sudo ufw deny 9090/tcp
sudo systemctl stop cockpit.socket
```

### Documentation Links
- [WireGuard Configuration Guide](https://www.wireguard.com/quickstart/)
- [Cockpit Administration](https://cockpit-project.org/guide/latest/)
- [Pterodactyl Wings Setup](https://pterodactyl.io/wings/1.0/installing.html)
- [Ubuntu 24.04 Security Guide](https://ubuntu.com/security)

### Support Contacts
- **Infrastructure Team:** infrastructure@obsidian.internal
- **Security Team:** security@obsidian.internal  
- **Emergency Hotline:** +1-XXX-XXX-XXXX

---

## 📄 Change Log

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-07-19 | Initial release with zero-trust VPN architecture |

---

**⚠️ CRITICAL SECURITY NOTICE**

This blueprint implements a zero-trust security model where **ALL management access requires VPN connectivity**. Public network access to management interfaces is completely blocked. Ensure your WireGuard infrastructure is operational before deployment.

**For emergency access, use the VM console through your cloud provider's management interface.**
