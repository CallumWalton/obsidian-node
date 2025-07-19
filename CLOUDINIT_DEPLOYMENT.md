# Obsidian CloudInit Deployment Guide

This directory contains CloudInit configurations for automated deployment of the Obsidian platform infrastructure.

## Files

- `server-cloudinit.yml` - CloudInit configuration for the C&C server
- `client-cloudinit.yml` - CloudInit configuration for client nodes
- `CLOUDINIT_DEPLOYMENT.md` - This guide

## Quick Start

### 1. C&C Server Deployment

1. **Set environment variables** (via cloud provider metadata or user data):
```bash
GITHUB_PAT_TOKEN=ghp_your_personal_access_token_here
DOMAIN=cnc.obsidian.example.com
EMAIL=admin@example.com
DB_PASSWORD=$(openssl rand -base64 32)
KEYCLOAK_ADMIN_PASSWORD=$(openssl rand -base64 32)
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 32)
ADMIN_EMAIL=admin@example.com
SMTP_HOST=smtp.example.com
SMTP_USER=noreply@example.com
SMTP_PASSWORD=your-smtp-password
# Note: S3 backups are currently disabled
```

2. **Deploy server** using `server-cloudinit.yml`:
```bash
# Hetzner Cloud CLI example
hcloud server create \
  --type cx31 \
  --image ubuntu-24.04 \
  --name obsidian-cnc \
  --ssh-key your-key \
  --user-data-from-file server-cloudinit.yml \
  --label environment=production \
  --label role=cnc-server
```

3. **Monitor deployment**:
```bash
# SSH to server after ~5 minutes
ssh obsidian@<server-ip>

# Check deployment progress
tail -f /var/log/obsidian-bootstrap.log
tail -f /var/log/cloud-init-output.log
```

### 2. Client Node Deployment

1. **Wait for C&C server deployment completion** (~15-20 minutes)

2. **Verify C&C server is accessible**:
```bash
# Test C&C server accessibility
curl -I https://cnc.obsidian.example.com
```

3. **Set client environment variables** (server public key will be auto-retrieved):
```bash
GITHUB_PAT_TOKEN=ghp_your_personal_access_token_here
CNC_DOMAIN=cnc.obsidian.example.com
NODE_VPN_IP=10.0.0.2
CLUSTER_JOIN_TOKEN=<cluster-join-token>
NODE_NAME=game-node-01
# Note: CNC_PUBLIC_KEY is no longer needed - auto-retrieved from server
```

4. **Deploy client** using `client-cloudinit.yml`:
```bash
# Hetzner Cloud CLI example
hcloud server create \
  --type cx21 \
  --image ubuntu-24.04 \
  --name obsidian-node-01 \
  --ssh-key your-key \
  --user-data-from-file client-cloudinit.yml \
  --label environment=production \
  --label role=game-node
```

The client will automatically:
- Retrieve the WireGuard server public key from the C&C server
- Configure and establish VPN connection
- Register with the cluster management system

## Hetzner Cloud Deployment Examples

### Using Hetzner Cloud Console

1. **Create C&C Server**:
   - Go to Hetzner Cloud Console
   - Click "Add Server"
   - Choose Ubuntu 24.04 LTS
   - Select CX31 (4 vCPU, 8GB RAM)
   - Add your SSH key
   - In "Cloud config" tab, paste `server-cloudinit.yml`
   - Modify environment variables section with your values
   - Create server

2. **Create Client Node**:
   - Follow same process with CX21 (2 vCPU, 4GB RAM)
   - Use `client-cloudinit.yml`
   - Set appropriate environment variables

### Using Terraform

```hcl
# variables.tf
variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
}

variable "domain" {
  description = "Domain for C&C server"
  type        = string
}

variable "admin_email" {
  description = "Administrator email"
  type        = string
}

# main.tf
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

# SSH Key
resource "hcloud_ssh_key" "obsidian" {
  name       = "obsidian-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# C&C Server
resource "hcloud_server" "cnc" {
  name        = "obsidian-cnc"
  image       = "ubuntu-24.04"
  server_type = "cx31"
  ssh_keys    = [hcloud_ssh_key.obsidian.id]
  
  user_data = templatefile("server-cloudinit.yml", {
    GITHUB_PAT_TOKEN         = var.github_pat_token
    DOMAIN                   = var.domain
    EMAIL                    = var.admin_email
    DB_PASSWORD              = random_password.db.result
    KEYCLOAK_ADMIN_PASSWORD  = random_password.keycloak.result
    GRAFANA_ADMIN_PASSWORD   = random_password.grafana.result
    ADMIN_EMAIL              = var.admin_email
    SMTP_HOST                = var.smtp_host
    SMTP_USER                = var.smtp_user
    SMTP_PASSWORD            = var.smtp_password
    # S3 variables commented out since backups are disabled
    # S3_BUCKET               = "obsidian-${random_id.bucket.hex}"
    # S3_ACCESS_KEY           = var.s3_access_key
    # S3_SECRET_KEY           = var.s3_secret_key
    # S3_ENDPOINT             = "https://s3.eu-central-1.hetzner-cloud.com"
  })

  labels = {
    environment = "production"
    role        = "cnc-server"
  }
}

# Client Node
resource "hcloud_server" "client" {
  count       = 1
  name        = "obsidian-node-${count.index + 1}"
  image       = "ubuntu-24.04"
  server_type = "cx21"
  ssh_keys    = [hcloud_ssh_key.obsidian.id]
  
  user_data = templatefile("client-cloudinit.yml", {
    GITHUB_PAT_TOKEN   = var.github_pat_token
    CNC_DOMAIN         = var.domain
    CNC_PUBLIC_KEY     = "PLACEHOLDER" # Will be updated post-deployment
    NODE_VPN_IP        = "10.0.0.${count.index + 2}"
    CLUSTER_JOIN_TOKEN = random_uuid.cluster_token.result
    NODE_NAME          = "game-node-${format("%02d", count.index + 1)}"
  })

  labels = {
    environment = "production"
    role        = "game-node"
  }

  depends_on = [hcloud_server.cnc]
}

# Random passwords
resource "random_password" "db" {
  length = 32
}

resource "random_password" "keycloak" {
  length = 32
}

resource "random_password" "grafana" {
  length = 32
}

resource "random_id" "bucket" {
  byte_length = 8
}

resource "random_uuid" "cluster_token" {}

# Outputs
output "cnc_server_ip" {
  value = hcloud_server.cnc.ipv4_address
}

output "client_ips" {
  value = hcloud_server.client[*].ipv4_address
}

output "passwords" {
  value = {
    database = random_password.db.result
    keycloak = random_password.keycloak.result
    grafana  = random_password.grafana.result
  }
  sensitive = true
}
```

## Environment Variable Reference

### Server CloudInit Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `GITHUB_PAT_TOKEN` | GitHub Personal Access Token | `ghp_xxxxxxxxxxxx` | Yes |
| `DOMAIN` | C&C server domain | `cnc.obsidian.example.com` | Yes |
| `EMAIL` | Let's Encrypt email | `admin@example.com` | Yes |
| `DB_PASSWORD` | Database password | `$(openssl rand -base64 32)` | Yes |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak admin password | `$(openssl rand -base64 32)` | Yes |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password | `$(openssl rand -base64 32)` | Yes |
| `ADMIN_EMAIL` | Administrator email | `admin@example.com` | Yes |
| `SMTP_HOST` | SMTP server | `smtp.example.com` | Yes |
| `SMTP_USER` | SMTP username | `noreply@example.com` | Yes |
| `SMTP_PASSWORD` | SMTP password | `smtp-password` | Yes |
| `WG_NETWORK_CIDR` | VPN network CIDR | `10.0.0.0/24` | No |
| `WG_SERVER_IP` | VPN server IP | `10.0.0.1` | No |
| `WG_PORT` | WireGuard port | `51820` | No |
| ~~`S3_BUCKET`~~ | ~~S3 bucket for backups~~ | ~~Disabled~~ | No |
| ~~`S3_ACCESS_KEY`~~ | ~~S3 access key~~ | ~~Disabled~~ | No |
| ~~`S3_SECRET_KEY`~~ | ~~S3 secret key~~ | ~~Disabled~~ | No |
| ~~`S3_ENDPOINT`~~ | ~~S3 endpoint URL~~ | ~~Disabled~~ | No |

### Client CloudInit Variables

| Variable | Description | Example | Required |
|----------|-------------|---------|----------|
| `GITHUB_PAT_TOKEN` | GitHub Personal Access Token | `ghp_xxxxxxxxxxxx` | Yes |
| `CNC_DOMAIN` | C&C server domain | `cnc.obsidian.example.com` | Yes |
| `CNC_PUBLIC_KEY` | C&C WireGuard public key | `base64-encoded-key` | Yes |
| `NODE_VPN_IP` | This node's VPN IP | `10.0.0.2` | Yes |
| `CLUSTER_JOIN_TOKEN` | Cluster join token | `uuid-token` | Yes |
| `NODE_NAME` | Unique node name | `game-node-01` | Yes |
| `WG_PORT` | WireGuard port | `51820` | No |
| `COCKPIT_PORT` | Cockpit port | `9090` | No |

## Deployment Validation

### Server Health Check
```bash
# SSH to C&C server
ssh obsidian@<cnc-server-ip>

# Run health check
sudo /opt/obsidian-cnc/scripts/cnc_health_check.sh

# Check logs
sudo tail -f /var/log/obsidian-bootstrap.log
```

### Client Health Check
```bash
# SSH to client node
ssh obsidian@<client-ip>

# Check services
sudo systemctl status wg-quick@wg0
sudo systemctl status cockpit.socket
sudo systemctl status docker

# Check VPN connectivity
ping 10.0.0.1  # Should ping C&C server

# Check logs
sudo tail -f /var/log/obsidian-bootstrap.log
```

## Troubleshooting

### Common Issues

1. **CloudInit fails**: Check `/var/log/cloud-init-output.log`
2. **Bootstrap fails**: Check `/var/log/obsidian-bootstrap.log`
3. **VPN connection fails**: Verify C&C public key and network settings
4. **SSL certificate fails**: Ensure DNS is pointing to server IP

### Log Files

- `/var/log/cloud-init-output.log` - CloudInit execution log
- `/var/log/obsidian-bootstrap.log` - Bootstrap script log
- `/var/log/obsidian-validation.log` - Pre-deployment validation (clients)
- `/var/log/obsidian-registration.log` - C&C registration log (clients)
- `/var/log/obsidian-status.log` - System status monitoring

### Manual Recovery

If automated deployment fails, you can run the bootstrap scripts manually:

```bash
# For C&C server
curl -fsSL https://raw.githubusercontent.com/CallumWalton/obsidian-node/main/obsidian_cnc_bootstrap.py | python3

# For client nodes  
curl -fsSL https://raw.githubusercontent.com/CallumWalton/obsidian-node/main/obsidian_bootstrap.py | python3
```

## Cost Estimation (Hetzner Cloud)

| Resource | Type | Monthly Cost (EUR) |
|----------|------|-------------------|
| C&C Server | CX31 (4 vCPU, 8GB) | ~€9.60 |
| Client Node | CX21 (2 vCPU, 4GB) | ~€5.80 |
| Load Balancer | LB11 (basic) | ~€5.39 |
| Floating IP | Per IP | ~€1.19 |

**Total for 1 C&C + 1 Client**: ~€15.40/month

## Security Considerations

- SSH keys are required - password authentication is disabled
- All services run behind WireGuard VPN
- Automatic security updates enabled
- Fail2ban configured for intrusion prevention
- UFW firewall with minimal required ports
- SSL/TLS encryption for all web services

## Next Steps

After successful deployment:

1. Configure DNS to point your domain to the C&C server
2. Complete Keycloak realm configuration
3. Set up Grafana dashboards
4. Configure SMTP for notifications
5. Add additional client nodes as needed
6. Set up monitoring alerts
7. Configure backup schedules

For detailed post-deployment configuration, see the main deployment guides in this repository.
