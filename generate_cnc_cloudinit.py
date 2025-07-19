#!/usr/bin/env python3
"""
Obsidian Command and Control Cloud-Init Generator

Interactive Python script to generate cloud-init configuration for Obsidian C&C Bootstrap.
This script prompts the user for all required configuration parameters and generates
a complete cloud-init YAML file for deploying the Obsidian Command & Control server
on Hetzner Cloud or other cloud providers.

Author: Obsidian Platform Team
Version: 1.0
Date: 2025-01-19
"""

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Callable


class Colors:
    """Color constants for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'


def write_colored_output(message: str, color: str = Colors.WHITE) -> None:
    """Write colored output to console"""
    print(f"{color}{message}{Colors.RESET}")


def write_info(message: str) -> None:
    """Write info message with cyan color"""
    write_colored_output(f"ℹ️  {message}", Colors.CYAN)


def write_success(message: str) -> None:
    """Write success message with green color"""
    write_colored_output(f"✅ {message}", Colors.GREEN)


def write_warning(message: str) -> None:
    """Write warning message with yellow color"""
    write_colored_output(f"⚠️  {message}", Colors.YELLOW)


def write_error(message: str) -> None:
    """Write error message with red color"""
    write_colored_output(f"❌ {message}", Colors.RED)


def test_domain_name(domain: str) -> bool:
    """Validate domain name format"""
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def test_email_address(email: str) -> bool:
    """Validate email address format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def test_cidr_notation(cidr: str) -> bool:
    """Validate CIDR notation format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$'
    return bool(re.match(pattern, cidr))


def test_port(port: str) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False


def new_secure_password(length: int = 32) -> str:
    """Generate a secure random password"""
    return base64.b64encode(secrets.token_bytes(length)).decode('utf-8')


def read_validated_input(
    prompt: str,
    default_value: Optional[str] = None,
    validator: Optional[Callable[[str], bool]] = None,
    validation_message: str = "Invalid input. Please try again.",
    is_password: bool = False,
    allow_empty: bool = False
) -> str:
    """Read and validate user input"""
    while True:
        display_prompt = f"{prompt} [{default_value}]" if default_value else prompt
        
        if is_password:
            user_input = getpass.getpass(f"{display_prompt}: ")
        else:
            user_input = input(f"{display_prompt}: ").strip()
        
        if not user_input and default_value:
            user_input = default_value
        
        if not user_input and allow_empty:
            return user_input
        
        if not user_input:
            write_warning("Input cannot be empty.")
            continue
        
        if validator and not validator(user_input):
            write_warning(validation_message)
            continue
        
        return user_input


def get_cnc_configuration(pre_config: Dict = None) -> Dict[str, str]:
    """Collect configuration from user input"""
    if pre_config is None:
        pre_config = {}
    
    write_colored_output("\n🚀 Obsidian Command and Control Cloud-Init Generator", Colors.MAGENTA)
    write_colored_output("=" * 60, Colors.GRAY)
    
    config = {}
    
    # Core Infrastructure
    write_info("Core Infrastructure Configuration")
    write_colored_output("-" * 40, Colors.GRAY)
    
    config['DOMAIN'] = read_validated_input(
        "Enter your CNC server domain (e.g. cnc.obsidian.example.com)",
        pre_config.get('DOMAIN'),
        test_domain_name,
        "Please enter a valid domain name (e.g. cnc.example.com)"
    )
    
    config['EMAIL'] = read_validated_input(
        "Enter administrator email for Let's Encrypt certificates",
        pre_config.get('EMAIL'),
        test_email_address,
        "Please enter a valid email address"
    )
    
    config['ADMIN_EMAIL'] = read_validated_input(
        "Enter administrator email for notifications",
        pre_config.get('ADMIN_EMAIL', config['EMAIL']),
        test_email_address,
        "Please enter a valid email address"
    )
    
    # GitHub Configuration
    write_info("\nGitHub Repository Configuration")
    write_colored_output("-" * 40, Colors.GRAY)
    
    config['GITHUB_PAT_TOKEN'] = read_validated_input(
        "Enter GitHub Personal Access Token (ghp_...)",
        pre_config.get('GITHUB_PAT_TOKEN'),
        lambda x: re.match(r'^ghp_[a-zA-Z0-9]{36}$', x),
        "Please enter a valid GitHub PAT token starting with 'ghp_'",
        is_password=True
    )
    
    # Security Passwords
    write_info("\nSecurity Configuration (leave blank to auto-generate)")
    write_colored_output("-" * 40, Colors.GRAY)
    
    auto_generate = not pre_config.get('DB_PASSWORD')
    if auto_generate:
        write_info("Auto-generating secure passwords...")
    
    config['DB_PASSWORD'] = pre_config.get('DB_PASSWORD') or new_secure_password(32)
    write_success(f"Database password: {'Generated' if auto_generate else 'Using provided'}")
    
    config['KEYCLOAK_ADMIN_PASSWORD'] = pre_config.get('KEYCLOAK_ADMIN_PASSWORD') or new_secure_password(24)
    write_success(f"Keycloak admin password: {'Generated' if auto_generate else 'Using provided'}")
    
    config['GRAFANA_ADMIN_PASSWORD'] = pre_config.get('GRAFANA_ADMIN_PASSWORD') or new_secure_password(24)
    write_success(f"Grafana admin password: {'Generated' if auto_generate else 'Using provided'}")
    
    # VPN Configuration
    write_info("\nWireGuard VPN Configuration")
    write_colored_output("-" * 40, Colors.GRAY)
    
    config['WG_NETWORK_CIDR'] = read_validated_input(
        "Enter VPN network CIDR",
        pre_config.get('WG_NETWORK_CIDR', '10.0.0.0/24'),
        test_cidr_notation,
        "Please enter a valid CIDR notation (e.g., 10.0.0.0/24)"
    )
    
    # Auto-determine WG_SERVER_IP from CIDR (first usable IP)
    network_base = config['WG_NETWORK_CIDR'].split('/')[0]
    config['WG_SERVER_IP'] = '.'.join(network_base.split('.')[:-1] + ['1'])
    write_info(f"VPN server IP auto-determined: {config['WG_SERVER_IP']}")
    
    config['WG_PORT'] = read_validated_input(
        "Enter WireGuard port",
        pre_config.get('WG_PORT', '51820'),
        test_port,
        "Please enter a valid port number (1-65535)"
    )
    
    # SSH Configuration
    write_info("\nSSH Configuration")
    write_colored_output("-" * 40, Colors.GRAY)
    
    default_key_path = Path.home() / '.ssh' / 'id_rsa.pub'
    ssh_key_exists = default_key_path.exists()
    
    if ssh_key_exists:
        write_success(f"Found SSH public key at: {default_key_path}")
        use_default = input("Use this SSH key? (Y/n): ").strip()
        if use_default.lower() in ['', 'y', 'yes']:
            config['SSH_PUBLIC_KEY'] = default_key_path.read_text().strip()
    
    if 'SSH_PUBLIC_KEY' not in config:
        write_warning("Please provide your SSH public key content:")
        config['SSH_PUBLIC_KEY'] = read_validated_input(
            "SSH Public Key (ssh-rsa AAAA...)",
            None,
            lambda x: re.match(r'^ssh-(rsa|ed25519|ecdsa)', x),
            "Please enter a valid SSH public key"
        )
    
    # Optional SMTP Configuration
    write_info("\nSMTP Configuration (Optional - leave blank to skip email notifications)")
    write_colored_output("-" * 40, Colors.GRAY)
    
    config['SMTP_HOST'] = read_validated_input(
        "SMTP server hostname",
        pre_config.get('SMTP_HOST'),
        allow_empty=True
    )
    
    if config['SMTP_HOST']:
        config['SMTP_PORT'] = read_validated_input(
            "SMTP port",
            pre_config.get('SMTP_PORT', '587'),
            test_port,
            "Please enter a valid port number"
        )
        
        config['SMTP_USER'] = read_validated_input(
            "SMTP username",
            pre_config.get('SMTP_USER'),
            test_email_address,
            "Please enter a valid email address"
        )
        
        config['SMTP_PASSWORD'] = read_validated_input(
            "SMTP password",
            pre_config.get('SMTP_PASSWORD'),
            is_password=True
        )
    
    return config


def new_cloud_init_yaml(config: Dict[str, str]) -> str:
    """Generate cloud-init YAML configuration"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    smtp_env_vars = ""
    if config.get('SMTP_HOST'):
        smtp_env_vars = f'''      export SMTP_HOST="{config['SMTP_HOST']}"
      export SMTP_PORT="{config['SMTP_PORT']}"
      export SMTP_USER="{config['SMTP_USER']}"
      export SMTP_PASSWORD="{config['SMTP_PASSWORD']}"'''
    else:
        smtp_env_vars = '''      # SMTP configuration disabled
      # export SMTP_HOST="smtp.example.com"
      # export SMTP_PORT="587"
      # export SMTP_USER="noreply@example.com"
      # export SMTP_PASSWORD="smtp-password"'''
    
    smtp_notification = ""
    if config.get('SMTP_HOST'):
        smtp_notification = f'''  # Send deployment notification
  - |
    if command -v mail >/dev/null 2>&1; then
      echo "Obsidian C&C Server deployment initiated on $(hostname) - $(date)" | \\
      mail -s "Obsidian C&C Deployment Started" "{config['ADMIN_EMAIL']}" || true
    fi'''
    else:
        smtp_notification = "  # SMTP notifications disabled"
    
    final_message_smtp = f'  - SMTP Host: {config["SMTP_HOST"]}' if config.get('SMTP_HOST') else ""
    
    yaml = f'''#cloud-config
# Obsidian Command and Control Server CloudInit Configuration
# Generated by generate_cnc_cloudinit.py on {timestamp}
# For Ubuntu 24.04 LTS on Hetzner Cloud CX31 or equivalent
# 
# This cloud-init configuration will:
# 1. Set up the server with proper security
# 2. Download and execute the CNC bootstrap script
# 3. Configure all required services automatically

# Package management
package_update: true
package_upgrade: true
packages:
  - curl
  - wget
  - git
  - htop
  - vim
  - unattended-upgrades
  - netcat-openbsd

# Users
users:
  - name: obsidian
    groups: [adm, docker, sudo]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    ssh_authorized_keys:
      - {config['SSH_PUBLIC_KEY'].strip()}

# Hostname and timezone
hostname: obsidian-cnc
timezone: UTC

# Automatic security updates
write_files:
  # Unattended upgrades configuration
  - path: /etc/apt/apt.conf.d/50unattended-upgrades
    content: |
      Unattended-Upgrade::Allowed-Origins {{
          "${{distro_id}}:${{distro_codename}}";
          "${{distro_id}}:${{distro_codename}}-security";
          "${{distro_id}}ESMApps:${{distro_codename}}-apps-security";
          "${{distro_id}}ESM:${{distro_codename}}-infra-security";
      }};
      Unattended-Upgrade::DevRelease "auto";
      Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
      Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
      Unattended-Upgrade::Remove-Unused-Dependencies "true";
      Unattended-Upgrade::Automatic-Reboot "true";
      Unattended-Upgrade::Automatic-Reboot-Time "02:00";
    permissions: '0644'

  # Environment variables for the bootstrap script
  - path: /opt/obsidian-env
    content: |
      export HEADLESS="true"
      export GITHUB_PAT_TOKEN="{config['GITHUB_PAT_TOKEN']}"
      export DOMAIN="{config['DOMAIN']}"
      export EMAIL="{config['EMAIL']}"
      export DB_PASSWORD="{config['DB_PASSWORD']}"
      export KEYCLOAK_ADMIN_PASSWORD="{config['KEYCLOAK_ADMIN_PASSWORD']}"
      export WG_NETWORK_CIDR="{config['WG_NETWORK_CIDR']}"
      export WG_SERVER_IP="{config['WG_SERVER_IP']}"
      export WG_PORT="{config['WG_PORT']}"
      export GRAFANA_ADMIN_PASSWORD="{config['GRAFANA_ADMIN_PASSWORD']}"
      export ADMIN_EMAIL="{config['ADMIN_EMAIL']}"
{smtp_env_vars}
    permissions: '0600'
    owner: root:root

  # SSH configuration hardening
  - path: /etc/ssh/sshd_config.d/obsidian-hardening.conf
    content: |
      # Obsidian SSH Security Configuration
      Protocol 2
      PermitRootLogin no
      PasswordAuthentication no
      PubkeyAuthentication yes
      AuthorizedKeysFile .ssh/authorized_keys
      PermitEmptyPasswords no
      ChallengeResponseAuthentication no
      UsePAM yes
      X11Forwarding no
      PrintMotd no
      ClientAliveInterval 300
      ClientAliveCountMax 2
      AllowUsers obsidian
      MaxAuthTries 3
      MaxSessions 2
    permissions: '0644'

  # System monitoring script
  - path: /opt/system-monitor.sh
    content: |
      #!/bin/bash
      # Basic system monitoring for cloud-init deployment
      
      echo "=== Obsidian C&C Server Status ===" > /var/log/obsidian-status.log
      echo "Deployment time: $(date)" >> /var/log/obsidian-status.log
      echo "Hostname: $(hostname)" >> /var/log/obsidian-status.log
      echo "Public IP: $(curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo 'Unknown')" >> /var/log/obsidian-status.log
      echo "Memory usage: $(free -h)" >> /var/log/obsidian-status.log
      echo "Disk usage: $(df -h /)" >> /var/log/obsidian-status.log
      echo "Active services: $(systemctl list-units --state=active --no-pager | wc -l)" >> /var/log/obsidian-status.log
      echo "Docker status: $(systemctl is-active docker 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
      echo "WireGuard status: $(systemctl is-active wg-quick@wg0 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
      echo "Nginx status: $(systemctl is-active nginx 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
    permissions: '0755'
    owner: root:root

  # Deployment validation script
  - path: /opt/validate-deployment.sh
    content: |
      #!/bin/bash
      # Pre-deployment validation for Obsidian C&C
      
      set -euo pipefail
      
      source /opt/obsidian-env
      
      echo "=== Obsidian C&C Pre-Deployment Validation ===" | tee /var/log/obsidian-validation.log
      echo "Timestamp: $(date)" | tee -a /var/log/obsidian-validation.log
      
      # Check required environment variables
      REQUIRED_VARS=("DOMAIN" "EMAIL" "DB_PASSWORD" "KEYCLOAK_ADMIN_PASSWORD" "GRAFANA_ADMIN_PASSWORD")
      
      for var in "${{REQUIRED_VARS[@]}}"; do
          if [[ -z "${{!var:-}}" ]]; then
              echo "ERROR: Required variable $var is not set" | tee -a /var/log/obsidian-validation.log
              exit 1
          else
              echo "✓ $var is set" | tee -a /var/log/obsidian-validation.log
          fi
      done
      
      # Test internet connectivity
      if ping -c 3 8.8.8.8 > /dev/null 2>&1; then
          echo "✓ Internet connectivity confirmed" | tee -a /var/log/obsidian-validation.log
      else
          echo "WARNING: Internet connectivity issues detected" | tee -a /var/log/obsidian-validation.log
      fi
      
      # Check disk space
      DISK_USAGE=$(df / | awk 'NR==2 {{print $5}}' | sed 's/%//')
      if [[ $DISK_USAGE -lt 80 ]]; then
          echo "✓ Sufficient disk space available (${{DISK_USAGE}}% used)" | tee -a /var/log/obsidian-validation.log
      else
          echo "WARNING: Low disk space (${{DISK_USAGE}}% used)" | tee -a /var/log/obsidian-validation.log
      fi
      
      echo "Pre-deployment validation complete" | tee -a /var/log/obsidian-validation.log
    permissions: '0755'
    owner: root:root

# System configuration
bootcmd:
  # Ensure proper time sync
  - timedatectl set-ntp true
  - systemctl enable systemd-timesyncd

runcmd:
  # Update system packages
  - apt-get update
  - apt-get upgrade -y
  
  # Set proper hostname
  - hostnamectl set-hostname obsidian-cnc
  - echo "127.0.0.1 obsidian-cnc" >> /etc/hosts
  
  # Configure automatic security updates
  - echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  - systemctl enable unattended-upgrades
  - systemctl start unattended-upgrades
  
  # Run pre-deployment validation
  - /opt/validate-deployment.sh
  
  # Configure Git authentication
  - source /opt/obsidian-env
  - git config --global user.name "Obsidian CloudInit"
  - git config --global user.email "${{ADMIN_EMAIL}}"
  - echo "https://${{GITHUB_PAT_TOKEN}}@github.com" > /root/.git-credentials
  - git config --global credential.helper store
  
  # Clone repository and get bootstrap script
  - cd /tmp
  - git clone https://github.com/CallumWalton/obsidian-node.git
  - cd obsidian-node
  - cp obsidian_cnc_bootstrap.sh /root/
  - chmod +x /root/obsidian_cnc_bootstrap.sh
  
  # Substitute variables and run bootstrap
  - source /opt/obsidian-env
  - envsubst < /root/obsidian_cnc_bootstrap.sh > /root/cnc_bootstrap_final.sh
  - chmod +x /root/cnc_bootstrap_final.sh
  - nohup /root/cnc_bootstrap_final.sh > /var/log/obsidian-bootstrap.log 2>&1 &
  
  # Set up log rotation for bootstrap log
  - |
    cat > /etc/logrotate.d/obsidian << EOF
    /var/log/obsidian-*.log {{
        daily
        rotate 30
        compress
        delaycompress
        missingok
        notifempty
        create 0644 root root
    }}
    EOF
  
  # Create monitoring cron job
  - /opt/system-monitor.sh
  - echo "*/5 * * * * /opt/system-monitor.sh" | crontab -
  
  # Restart SSH with new configuration
  - systemctl restart ssh
  
{smtp_notification}

  # Wait for bootstrap to complete and run final status
  - sleep 30
  - /opt/system-monitor.sh

# Final message
final_message: |
  Obsidian Command & Control Server deployment initiated via cloud-init.
  
  Configuration Summary:
  - Domain: {config['DOMAIN']}
  - Admin Email: {config['ADMIN_EMAIL']}
  - VPN Network: {config['WG_NETWORK_CIDR']}
  - VPN Server IP: {config['WG_SERVER_IP']}
  - WireGuard Port: {config['WG_PORT']}
{final_message_smtp}
  
  Monitor deployment progress:
  - Validation log: /var/log/obsidian-validation.log
  - Bootstrap log: /var/log/obsidian-bootstrap.log
  - System status: /var/log/obsidian-status.log
  - Cloud-init log: /var/log/cloud-init-output.log
  
  Once deployment completes (15-25 minutes), access your C&C server at:
  https://{config['DOMAIN']}
  
  SSH access: ssh obsidian@<server-ip>
  
  Important: Configure DNS to point {config['DOMAIN']} to this server IP!

# Power state management
power_state:
  delay: "+1"
  mode: reboot
  message: "Rebooting after Obsidian CNC installation"
  condition: true
'''

    return yaml


def new_credentials_summary(config: Dict[str, str]) -> str:
    """Generate credentials summary"""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    smtp_config = ""
    if config.get('SMTP_HOST'):
        smtp_config = f'''SMTP Configuration:
  Host: {config['SMTP_HOST']}
  Port: {config['SMTP_PORT']}
  Username: {config['SMTP_USER']}
  Password: {config['SMTP_PASSWORD']}'''
    else:
        smtp_config = "SMTP Configuration: Disabled"
    
    summary = f'''Obsidian Command and Control - Generated Credentials
=================================================
Generated: {timestamp}
Domain: {config['DOMAIN']}
Admin Email: {config['ADMIN_EMAIL']}

IMPORTANT: Save these credentials securely!

Database Configuration:
  Database Password: {config['DB_PASSWORD']}

Keycloak SSO:
  Admin Username: admin
  Admin Password: {config['KEYCLOAK_ADMIN_PASSWORD']}
  Access URL: https://{config['DOMAIN']}/auth/admin

Grafana Monitoring:
  Admin Username: admin
  Admin Password: {config['GRAFANA_ADMIN_PASSWORD']}
  Access URL: https://{config['DOMAIN']}/grafana

WireGuard VPN:
  Network: {config['WG_NETWORK_CIDR']}
  Server IP: {config['WG_SERVER_IP']}
  Port: {config['WG_PORT']}

{smtp_config}

Access Information:
  Main Dashboard: https://{config['DOMAIN']}
  SSH: ssh obsidian@<server-ip>
  Default WireGuard clients will be available in: /root/wireguard-credentials/

Post-Deployment Steps:
  1. Configure DNS A record: {config['DOMAIN']} -> <server-ip>
  2. Wait for bootstrap completion (~15-25 minutes)
  3. Access Cockpit dashboard at https://{config['DOMAIN']}
  4. Configure Keycloak realm and clients
  5. Set up Grafana dashboards
  6. Add WireGuard VPN clients as needed

Security Notes:
  All management interfaces are secured with SSL/TLS
  WireGuard VPN provides secure access to management functions
  Automatic security updates are enabled
  Fail2ban is configured for intrusion prevention

For support and documentation, see:
https://github.com/CallumWalton/obsidian-node
'''

    return summary


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Generate cloud-init configuration for Obsidian C&C Bootstrap"
    )
    parser.add_argument(
        '--output-path',
        default=os.getcwd(),
        help="Path where the generated cloud-init file will be saved (default: current directory)"
    )
    parser.add_argument(
        '--config-file',
        help="Optional JSON file with pre-configured values to skip interactive prompts"
    )
    
    args = parser.parse_args()
    
    try:
        write_colored_output("\n🔧 Obsidian CNC Cloud-Init Generator", Colors.MAGENTA)
        write_colored_output("=" * 60, Colors.GRAY)
        write_info("This script will generate a complete cloud-init configuration for deploying")
        write_info("the Obsidian Command and Control server on Hetzner Cloud or other providers.")
        print()
        
        # Load pre-configuration if provided
        pre_config = {}
        if args.config_file and os.path.exists(args.config_file):
            write_info(f"Loading configuration from: {args.config_file}")
            with open(args.config_file, 'r') as f:
                pre_config = json.load(f)
            write_success("Configuration loaded successfully")
        
        # Collect configuration
        config = get_cnc_configuration(pre_config)
        
        # Generate files
        write_info("\nGenerating cloud-init configuration...")
        cloud_init_yaml = new_cloud_init_yaml(config)
        credentials_summary = new_credentials_summary(config)
        
        # Ensure output directory exists
        output_path = Path(args.output_path)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate file names with timestamp
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        cloud_init_file = output_path / f"obsidian-cnc-cloudinit-{timestamp}.yml"
        credentials_file = output_path / f"obsidian-cnc-credentials-{timestamp}.txt"
        config_json_file = output_path / f"obsidian-cnc-config-{timestamp}.json"
        
        # Write files
        cloud_init_file.write_text(cloud_init_yaml, encoding='utf-8')
        credentials_file.write_text(credentials_summary, encoding='utf-8')
        config_json_file.write_text(json.dumps(config, indent=2), encoding='utf-8')
        
        # Success message
        write_success("\nFiles generated successfully!")
        print()
        write_info("Generated Files:")
        write_colored_output(f"  Cloud-Init: {cloud_init_file}", Colors.WHITE)
        write_colored_output(f"  Credentials: {credentials_file}", Colors.WHITE)
        write_colored_output(f"  Config JSON: {config_json_file}", Colors.WHITE)
        
        print()
        write_info("Next Steps:")
        write_colored_output(f"  1. Configure DNS: {config['DOMAIN']} -> server-ip", Colors.YELLOW)
        write_colored_output("  2. Deploy to Hetzner Cloud using the generated cloud-init file", Colors.YELLOW)
        write_colored_output("  3. Monitor deployment logs: /var/log/obsidian-bootstrap.log", Colors.YELLOW)
        write_colored_output(f"  4. Access dashboard: https://{config['DOMAIN']}", Colors.YELLOW)
        
        write_warning("\nIMPORTANT: Keep the credentials file secure!")
        write_warning("The generated passwords are required for initial system access.")
        
        # Hetzner Cloud deployment hint
        print()
        write_info("Hetzner Cloud Deployment Example:")
        deployment_example = f'''hcloud server create \\
  --type cx31 \\
  --image ubuntu-24.04 \\
  --name obsidian-cnc \\
  --ssh-key your-key-name \\
  --user-data-from-file "{cloud_init_file}" \\
  --label environment=production \\
  --label role=cnc-server'''
        write_colored_output(deployment_example, Colors.GRAY)
        
    except Exception as e:
        write_error(f"Error generating cloud-init configuration: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
