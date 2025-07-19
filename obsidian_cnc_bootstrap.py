#!/usr/bin/env python3
"""
Obsidian Command & Control (C&C) Bootstrap Script
Optimized for headless deployment on Hetzner Cloud

This script is fully autonomous with self-error correction
All operations are logged to /var/log/obsidian-cnc-bootstrap.log

Author: Obsidian Platform Team
Version: 2.1
Date: 2025-01-19
"""

import os
import sys
import subprocess
import time
import logging
import shutil
import socket
import json
import secrets
import base64
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import fcntl


class Colors:
    """Color constants for terminal output"""
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    RESET = '\033[0m'


class ObsidianBootstrap:
    """Main bootstrap class for Obsidian C&C setup"""
    
    def __init__(self):
        # Detect execution environment
        self.is_headless = os.environ.get('HEADLESS', 'true').lower() == 'true'
        self.is_interactive = sys.stdout.isatty() and sys.stderr.isatty()
        
        # Logging setup
        self.log_file = Path("/var/log/obsidian-cnc-bootstrap.log")
        self.error_log_file = Path("/var/log/obsidian-cnc-bootstrap-errors.log")
        self.headless_log_file = Path("/root/obsidian-cnc-bootstrap.log")
        self.headless_error_log_file = Path("/root/obsidian-cnc-bootstrap-errors.log")
        
        # Configuration variables
        self.obsidian_cnc_home = Path("/opt/obsidian-cnc")
        self.domain = os.environ.get('DOMAIN', 'localhost')
        self.email = os.environ.get('EMAIL', 'admin@localhost')
        self.db_password = os.environ.get('DB_PASSWORD') or self._generate_password(32)
        self.keycloak_admin_password = os.environ.get('KEYCLOAK_ADMIN_PASSWORD') or self._generate_password(32)
        self.wg_network_cidr = os.environ.get('WG_NETWORK_CIDR', '10.0.0.0/24')
        self.wg_server_ip = os.environ.get('WG_SERVER_IP', '10.0.0.1')
        self.wg_port = os.environ.get('WG_PORT', '51820')
        self.grafana_admin_password = os.environ.get('GRAFANA_ADMIN_PASSWORD') or self._generate_password(32)
        
        # Enhanced self-correction parameters
        self.max_retries = 5
        self.initial_retry_delay = 10
        self.health_check_timeout = 120
        
        # Auto-detect network interface
        self.network_interface = self._detect_network_interface()
        
        # Setup logging
        self._setup_logging()
    
    def _generate_password(self, length: int = 32) -> str:
        """Generate a secure random password"""
        return base64.b64encode(secrets.token_bytes(length)).decode('utf-8')
    
    def _detect_network_interface(self) -> str:
        """Detect primary network interface"""
        try:
            # Try to get default route interface
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if line.startswith('default'):
                    parts = line.split()
                    if len(parts) >= 5:
                        return parts[4]
        except subprocess.CalledProcessError:
            pass
        
        try:
            # Fallback: find first active interface (excluding loopback)
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                match = re.match(r'^\d+: (eth\d+|ens\d+|enp\d+s\d+):', line)
                if match:
                    return match.group(1)
        except subprocess.CalledProcessError:
            pass
        
        # Final fallback for cloud providers
        return 'eth0'
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Ensure log directories exist
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.headless_log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create log files
        for log_file in [self.log_file, self.error_log_file, self.headless_log_file, self.headless_error_log_file]:
            log_file.touch()
            if 'root' in str(log_file):
                log_file.chmod(0o600)
            else:
                log_file.chmod(0o644)
        
        # Setup logging
        log_format = '[%(asctime)s] [%(levelname)s] %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S UTC'
        
        # Configure root logger
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            datefmt=date_format,
            handlers=[
                logging.FileHandler(self.log_file),
                logging.FileHandler(self.headless_log_file),
            ]
        )
        
        # Add console handler if interactive
        if self.is_interactive and not self.is_headless:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format, date_format))
            logging.getLogger().addHandler(console_handler)
        
        self.logger = logging.getLogger(__name__)
    
    def _log_with_color(self, level: str, message: str):
        """Log message with color if interactive"""
        timestamp = datetime.utcnow().strftime('[%Y-%m-%d %H:%M:%S UTC]')
        
        if self.is_interactive and not self.is_headless:
            color_map = {
                'INFO': Colors.GREEN,
                'WARN': Colors.YELLOW,
                'ERROR': Colors.RED,
                'DEBUG': Colors.BLUE
            }
            color = color_map.get(level, '')
            formatted_message = f"{color}{timestamp} [{level}]{Colors.RESET} {message}"
            print(formatted_message)
        
        # Always log to files
        log_message = f"{timestamp} [{level}] {message}"
        with open(self.log_file, 'a') as f:
            f.write(log_message + '\n')
        with open(self.headless_log_file, 'a') as f:
            f.write(log_message + '\n')
    
    def info(self, message: str):
        """Log info message"""
        self._log_with_color('INFO', message)
        self.logger.info(message)
    
    def warn(self, message: str):
        """Log warning message"""
        self._log_with_color('WARN', message)
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self._log_with_color('ERROR', message)
        self.logger.error(message)
    
    def debug(self, message: str):
        """Log debug message"""
        self._log_with_color('DEBUG', message)
        self.logger.debug(message)
    
    def retry_with_backoff(self, max_attempts: int, initial_delay: int, description: str, func, *args, **kwargs):
        """Retry function with exponential backoff"""
        attempt = 1
        delay = initial_delay
        
        while attempt <= max_attempts:
            self.info(f"Attempting {description} (attempt {attempt}/{max_attempts})")
            
            try:
                func(*args, **kwargs)
                self.info(f"{description} completed successfully")
                return True
            except Exception as e:
                if attempt == max_attempts:
                    self.error(f"{description} failed after {max_attempts} attempts: {e}")
                    return False
                
                self.warn(f"{description} failed: {e}, retrying in {delay}s...")
                time.sleep(delay)
                attempt += 1
                delay = delay * 2 + (secrets.randbelow(10))
        
        return False
    
    def wait_for_service(self, service: str, timeout: int = None) -> bool:
        """Wait for systemd service to become ready"""
        if timeout is None:
            timeout = self.health_check_timeout
        
        self.info(f"Waiting for {service} to become ready (timeout: {timeout}s)")
        elapsed = 0
        check_interval = 5
        
        while elapsed < timeout:
            try:
                # Check if service is active
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    self.info(f"{service} is ready (took {elapsed}s)")
                    return True
                
                # Check if service failed
                result = subprocess.run(['systemctl', 'is-failed', service], 
                                      capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    self.error(f"{service} has failed")
                    subprocess.run(['systemctl', 'status', service, '--no-pager', '-l'], check=False)
                    return False
                
            except subprocess.CalledProcessError:
                pass
            
            time.sleep(check_interval)
            elapsed += check_interval
            
            if elapsed % 30 == 0:
                self.info(f"Still waiting for {service}... ({elapsed}/{timeout}s)")
        
        self.error(f"{service} failed to start within {timeout}s")
        return False
    
    def wait_for_container(self, container: str, timeout: int = None) -> bool:
        """Wait for Docker container to be ready"""
        if timeout is None:
            timeout = self.health_check_timeout
        
        self.info(f"Waiting for container {container} to be ready (timeout: {timeout}s)")
        elapsed = 0
        check_interval = 5
        
        while elapsed < timeout:
            try:
                # Check if container is running
                result = subprocess.run(['docker', 'ps', '--filter', f'name={container}', 
                                       '--filter', 'status=running', '--format', '{{.Names}}'],
                                      capture_output=True, text=True, check=True)
                
                if container in result.stdout:
                    # Check health status if available
                    health_result = subprocess.run(['docker', 'inspect', '--format', 
                                                  '{{.State.Health.Status}}', container],
                                                 capture_output=True, text=True, check=False)
                    
                    health_status = health_result.stdout.strip() if health_result.returncode == 0 else 'none'
                    
                    if health_status in ['healthy', 'none']:
                        self.info(f"Container {container} is ready (took {elapsed}s)")
                        return True
                    elif health_status == 'unhealthy':
                        self.error(f"Container {container} is unhealthy")
                        subprocess.run(['docker', 'logs', '--tail=20', container], check=False)
                        return False
                    else:
                        self.debug(f"Container {container} health status: {health_status}")
                else:
                    # Check if container exists but stopped
                    result = subprocess.run(['docker', 'ps', '-a', '--filter', f'name={container}',
                                           '--format', '{{.Status}}'],
                                          capture_output=True, text=True, check=False)
                    if result.stdout and 'Exited' in result.stdout:
                        self.error(f"Container {container} has exited")
                        subprocess.run(['docker', 'logs', '--tail=50', container], check=False)
                        return False
            
            except subprocess.CalledProcessError:
                pass
            
            time.sleep(check_interval)
            elapsed += check_interval
            
            if elapsed % 30 == 0:
                self.info(f"Still waiting for container {container}... ({elapsed}/{timeout}s)")
        
        self.error(f"Container {container} failed to start within {timeout}s")
        return False
    
    def check_root(self):
        """Check if running as root"""
        if os.geteuid() != 0:
            self.error("This script must be run as root")
            sys.exit(1)
    
    def run_command(self, command: List[str], check: bool = True, env: Dict[str, str] = None) -> subprocess.CompletedProcess:
        """Run shell command with logging"""
        cmd_str = ' '.join(command)
        self.debug(f"Running command: {cmd_str}")
        
        if env is None:
            env = os.environ.copy()
        
        result = subprocess.run(command, capture_output=True, text=True, check=check, env=env)
        
        if result.stdout:
            self.debug(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            self.debug(f"Command error: {result.stderr.strip()}")
        
        return result
    
    def setup_directories(self):
        """Setup directory structure"""
        self.info("Setting up Obsidian C&C directory structure")
        
        directories = [
            (self.obsidian_cnc_home, 0o755),
            (self.obsidian_cnc_home / 'config', 0o755),
            (self.obsidian_cnc_home / 'scripts', 0o755),
            (self.obsidian_cnc_home / 'logs', 0o755),
            (self.obsidian_cnc_home / 'certs', 0o755),
            (self.obsidian_cnc_home / 'data', 0o755),
            (Path('/etc/wireguard'), 0o700),
            (Path('/etc/wireguard/clients'), 0o700),
            (Path('/root/wireguard-credentials'), 0o700),
            (self.obsidian_cnc_home / 'config/grafana', 0o755),
            (self.obsidian_cnc_home / 'config/grafana/datasources', 0o755),
            (self.obsidian_cnc_home / 'config/grafana/dashboards', 0o755),
        ]
        
        for dir_path, mode in directories:
            dir_path.mkdir(parents=True, exist_ok=True)
            dir_path.chmod(mode)
            self.debug(f"Created directory: {dir_path} (mode: {oct(mode)})")
        
        self.info("All required directories created successfully")
    
    def update_system(self):
        """Update system packages"""
        def update_impl():
            self.info("Updating system packages")
            
            # Set environment for non-interactive installation
            env = os.environ.copy()
            env['DEBIAN_FRONTEND'] = 'noninteractive'
            
            # Configure APT for non-interactive mode
            apt_conf_dir = Path('/etc/apt/apt.conf.d')
            apt_conf_dir.mkdir(exist_ok=True)
            
            apt_conf = apt_conf_dir / '90-obsidian-noninteractive'
            apt_conf.write_text('''APT::Get::Assume-Yes "true";
APT::Get::force-yes "false";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
DPkg::Options "--force-confdef";
DPkg::Options "--force-confold";
DPkg::Post-Invoke-Success { "rm -f /var/cache/apt/archives/*.deb"; };
''')
            
            # Fix any broken packages
            self.run_command(['dpkg', '--configure', '-a'], check=False)
            self.run_command(['apt-get', '--fix-broken', 'install', '-y'], check=False)
            
            # Update package lists
            for attempt in range(3):
                try:
                    self.run_command(['apt-get', 'update'], env=env)
                    break
                except subprocess.CalledProcessError:
                    if attempt == 2:
                        raise
                    self.warn(f"Package list update failed, attempt {attempt + 1}/3")
                    time.sleep(10)
            
            # Upgrade system
            self.run_command(['apt-get', 'upgrade', '-y'], env=env)
            
            # Install essential packages
            packages = [
                'curl', 'wget', 'gnupg', 'lsb-release', 'ca-certificates',
                'software-properties-common', 'apt-transport-https', 'jq',
                'gettext-base', 'nginx', 'certbot', 'python3-certbot-nginx',
                'postgresql', 'postgresql-contrib', 'redis-server', 'fail2ban',
                'ufw', 'htop', 'iftop', 'iotop', 'tree', 'sqlite3',
                'python3-flask', 'python3-flask-httpauth', 'python3-pip', 'flock'
            ]
            
            self.run_command(['apt-get', 'install', '-y'] + packages, env=env)
        
        self.retry_with_backoff(self.max_retries, self.initial_retry_delay, 
                               "system update", update_impl)
    
    def install_docker(self):
        """Install Docker and Docker Compose"""
        def install_impl():
            self.info("Installing Docker and Docker Compose")
            
            # Remove existing Docker installations
            self.run_command(['apt-get', 'remove', '-y', 'docker', 'docker-engine', 
                            'docker.io', 'containerd', 'runc'], check=False)
            
            # Add Docker's GPG key
            self.run_command(['curl', '-fsSL', 'https://download.docker.com/linux/ubuntu/gpg', 
                            '-o', '/tmp/docker.gpg'])
            self.run_command(['gpg', '--dearmor', '-o', '/usr/share/keyrings/docker-archive-keyring.gpg',
                            '/tmp/docker.gpg'])
            
            # Add Docker repository
            lsb_release = self.run_command(['lsb_release', '-cs']).stdout.strip()
            arch = self.run_command(['dpkg', '--print-architecture']).stdout.strip()
            
            repo_line = f"deb [arch={arch} signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu {lsb_release} stable"
            Path('/etc/apt/sources.list.d/docker.list').write_text(repo_line)
            
            # Install Docker
            self.run_command(['apt-get', 'update'])
            self.run_command(['apt-get', 'install', '-y', 'docker-ce', 'docker-ce-cli',
                            'containerd.io', 'docker-compose-plugin'])
            
            # Configure Docker daemon
            docker_config = {
                "log-driver": "json-file",
                "log-opts": {
                    "max-size": "10m",
                    "max-file": "3"
                },
                "storage-driver": "overlay2",
                "live-restore": True
            }
            
            Path('/etc/docker').mkdir(exist_ok=True)
            Path('/etc/docker/daemon.json').write_text(json.dumps(docker_config, indent=2))
            
            # Enable and start Docker
            self.run_command(['systemctl', 'enable', 'docker'])
            self.run_command(['systemctl', 'start', 'docker'])
            
            if not self.wait_for_service('docker'):
                raise RuntimeError("Docker failed to start")
        
        self.retry_with_backoff(self.max_retries, self.initial_retry_delay,
                               "Docker installation", install_impl)
    
    def install_wireguard_server(self):
        """Install WireGuard VPN Server"""
        def install_impl():
            self.info(f"Installing WireGuard VPN Server (interface: {self.network_interface})")
            
            self.run_command(['apt-get', 'install', '-y', 'wireguard', 'wireguard-tools', 'qrencode'])
            
            wg_dir = Path('/etc/wireguard')
            os.chdir(wg_dir)
            os.umask(0o077)
            
            # Generate server keys if they don't exist
            if not (wg_dir / 'server_private.key').exists():
                result = self.run_command(['wg', 'genkey'])
                (wg_dir / 'server_private.key').write_text(result.stdout.strip())
                
                result = self.run_command(['wg', 'pubkey'], 
                                        input=(wg_dir / 'server_private.key').read_text())
                (wg_dir / 'server_public.key').write_text(result.stdout.strip())
                self.info("Generated WireGuard server keys")
            
            server_private_key = (wg_dir / 'server_private.key').read_text().strip()
            
            # Create server configuration
            wg_config = f"""[Interface]
PrivateKey = {server_private_key}
Address = {self.wg_server_ip}/24
ListenPort = {self.wg_port}
SaveConfig = false

# Enable IP forwarding and NAT for detected interface
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o {self.network_interface} -j MASQUERADE; ip route add {self.wg_network_cidr} dev wg0
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o {self.network_interface} -j MASQUERADE; ip route del {self.wg_network_cidr} dev wg0

# Clients will be added here dynamically
"""
            (wg_dir / 'wg0.conf').write_text(wg_config)
            
            # Enable IP forwarding
            sysctl_conf = Path('/etc/sysctl.conf')
            sysctl_content = sysctl_conf.read_text()
            if 'net.ipv4.ip_forward = 1' not in sysctl_content:
                sysctl_conf.write_text(sysctl_content + '\nnet.ipv4.ip_forward = 1\n')
            if 'net.ipv6.conf.all.forwarding = 1' not in sysctl_content:
                sysctl_conf.write_text(sysctl_conf.read_text() + 'net.ipv6.conf.all.forwarding = 1\n')
            
            self.run_command(['sysctl', '-p'])
            
            # Create client management script
            self._create_wireguard_client_script()
            self._create_default_wireguard_clients()
            
            self.run_command(['systemctl', 'enable', 'wg-quick@wg0.service'])
            self.run_command(['systemctl', 'start', 'wg-quick@wg0.service'])
            
            if not self.wait_for_service('wg-quick@wg0'):
                raise RuntimeError("WireGuard failed to start")
            
            # Copy server public key for reference
            server_public_key = (wg_dir / 'server_public.key').read_text().strip()
            (self.obsidian_cnc_home / 'wireguard_server_public_key').write_text(server_public_key)
        
        self.retry_with_backoff(self.max_retries, self.initial_retry_delay,
                               "WireGuard server installation", install_impl)
    
    def _create_wireguard_client_script(self):
        """Create WireGuard client management script"""
        script_content = f'''#!/bin/bash
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
WG_PORT="{self.wg_port}"
DOMAIN="{self.domain}"

# Generate client keys
cd "$CLIENT_DIR"
wg genkey > "${{CLIENT_NAME}}_private.key"
wg pubkey < "${{CLIENT_NAME}}_private.key" > "${{CLIENT_NAME}}_public.key"

CLIENT_PRIVATE_KEY=$(cat "${{CLIENT_NAME}}_private.key")
CLIENT_PUBLIC_KEY=$(cat "${{CLIENT_NAME}}_public.key")

# Create client configuration
cat > "${{CLIENT_NAME}}.conf" << EOC
[Interface]
PrivateKey = ${{CLIENT_PRIVATE_KEY}}
Address = ${{CLIENT_IP}}/32
DNS = {self.wg_server_ip}

[Peer]
PublicKey = ${{SERVER_PUBLIC_KEY}}
Endpoint = ${{DOMAIN}}:${{WG_PORT}}
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
EOC

# Add client to server configuration
cat >> /etc/wireguard/wg0.conf << EOC

# Client: ${{CLIENT_NAME}}
[Peer]
PublicKey = ${{CLIENT_PUBLIC_KEY}}
AllowedIPs = ${{CLIENT_IP}}/32
EOC

# Generate QR code
qrencode -t ansiutf8 < "${{CLIENT_NAME}}.conf"

echo "Client ${{CLIENT_NAME}} added successfully!"
echo "Configuration saved to: ${{CLIENT_DIR}}/${{CLIENT_NAME}}.conf"

# Restart WireGuard
systemctl restart wg-quick@wg0
'''
        
        script_path = self.obsidian_cnc_home / 'scripts/add_wireguard_client.sh'
        script_path.write_text(script_content)
        script_path.chmod(0o755)
    
    def _create_default_wireguard_clients(self):
        """Create default WireGuard client configurations"""
        self.info("Creating default WireGuard client credentials in /root/wireguard-credentials/")
        
        server_public_key = Path('/etc/wireguard/server_public.key').read_text().strip()
        credentials_dir = Path('/root/wireguard-credentials')
        
        default_clients = [
            ('admin', '10.0.0.10'),
            ('laptop', '10.0.0.11'),
            ('mobile', '10.0.0.12'),
            ('backup', '10.0.0.13'),
        ]
        
        # Create README
        readme_content = f"""# Default WireGuard Client Credentials

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Server: {self.domain}
Server Public Key: {server_public_key}

## Available Clients:
- **admin** (10.0.0.10) - Primary administration access
- **laptop** (10.0.0.11) - Laptop/workstation access  
- **mobile** (10.0.0.12) - Mobile device access
- **backup** (10.0.0.13) - Backup/emergency access
"""
        (credentials_dir / 'README.md').write_text(readme_content)
        
        wg_config_template = """[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = {server_ip}

[Peer]
PublicKey = {server_public_key}
Endpoint = {domain}:{port}
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
PersistentKeepalive = 25
"""
        
        wg_server_config = Path('/etc/wireguard/wg0.conf')
        
        for client_name, client_ip in default_clients:
            self.info(f"Creating default client: {client_name} ({client_ip})")
            
            # Generate client keys
            private_key_result = self.run_command(['wg', 'genkey'])
            private_key = private_key_result.stdout.strip()
            
            public_key_result = self.run_command(['wg', 'pubkey'], input=private_key)
            public_key = public_key_result.stdout.strip()
            
            # Create client configuration
            client_config = wg_config_template.format(
                private_key=private_key,
                client_ip=client_ip,
                server_ip=self.wg_server_ip,
                server_public_key=server_public_key,
                domain=self.domain,
                port=self.wg_port
            )
            
            client_conf_path = credentials_dir / f"{client_name}.conf"
            client_conf_path.write_text(client_config)
            
            # Generate QR code
            self.run_command(['qrencode', '-t', 'PNG', '-o', 
                            str(credentials_dir / f"{client_name}_qr.png")],
                           input=client_config)
            
            # Add client to server configuration
            server_peer_config = f"""
# Default Client: {client_name}
[Peer]
PublicKey = {public_key}
AllowedIPs = {client_ip}/32
"""
            
            with wg_server_config.open('a') as f:
                f.write(server_peer_config)
        
        # Set proper permissions
        for item in credentials_dir.glob('*'):
            item.chmod(0o600)
        credentials_dir.chmod(0o700)
        
        self.info(f"Default WireGuard credentials created in {credentials_dir}")
    
    def create_management_scripts(self):
        """Create management and monitoring scripts"""
        # This method can be added to create additional management utilities
        pass
    
    def finalize_setup(self):
        """Finalize C&C setup"""
        def finalize_impl():
            self.info("Finalizing C&C setup")
            
            # Create obsidian-cnc user
            try:
                self.run_command(['id', 'obsidian-cnc'], check=False)
            except subprocess.CalledProcessError:
                self.run_command(['useradd', '-r', '-d', str(self.obsidian_cnc_home), 
                                '-s', '/bin/bash', 'obsidian-cnc'])
                self.run_command(['usermod', '-a', '-G', 'docker', 'obsidian-cnc'])
            
            # Set permissions
            shutil.chown(self.obsidian_cnc_home, user='obsidian-cnc', group='obsidian-cnc')
            for item in self.obsidian_cnc_home.rglob('*'):
                shutil.chown(item, user='obsidian-cnc', group='obsidian-cnc')
            
            # Make scripts executable
            scripts_dir = self.obsidian_cnc_home / 'scripts'
            for script in scripts_dir.glob('*.sh'):
                script.chmod(0o755)
            
            self.run_command(['apt-get', 'autoremove', '-y'])
            self.run_command(['apt-get', 'autoclean'])
        
        self.retry_with_backoff(self.max_retries, self.initial_retry_delay,
                               "finalization", finalize_impl)
    
    def run_final_health_check(self) -> bool:
        """Run comprehensive final health check"""
        self.info("Running final comprehensive health check")
        
        failed_services = []
        
        # Check system services
        services = ['nginx', 'postgresql', 'redis-server', 'wg-quick@wg0', 'docker']
        for service in services:
            if not self.wait_for_service(service, timeout=30):
                failed_services.append(service)
                self.error(f"Service {service} is not running")
            else:
                self.info(f"Service {service} is healthy")
        
        if failed_services:
            self.error(f"Final health check failed. Failed services: {failed_services}")
            return False
        else:
            self.info("All services passed final health check")
            return True
    
    def main(self):
        """Main execution function"""
        self.info("Starting Obsidian Command & Control Bootstrap Process")
        self.info(f"Environment: {'Headless' if self.is_headless else 'Interactive'}")
        self.info(f"Target: Ubuntu 24.04 LTS (Hetzner Cloud Optimized)")
        self.info(f"Domain: {self.domain}")
        self.info(f"Network Interface: {self.network_interface}")
        self.info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.is_headless:
            self.info("Headless mode detected - logs are being written to:")
            self.info(f"  - System logs: {self.log_file}")
            self.info(f"  - Root logs: {self.headless_log_file}")
        
        # Check if running as root
        self.check_root()
        
        # Create lock file to prevent concurrent executions
        lock_file = Path('/var/lock/obsidian-cnc-bootstrap.lock')
        
        try:
            with open(lock_file, 'w') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                
                # Main installation sequence
                installation_steps = [
                    ('setup_directories', self.setup_directories),
                    ('update_system', self.update_system),
                    ('install_docker', self.install_docker),
                    ('install_wireguard_server', self.install_wireguard_server),
                    ('create_management_scripts', self.create_management_scripts),
                    ('finalize_setup', self.finalize_setup),
                ]
                
                failed_steps = []
                
                for step_name, step_func in installation_steps:
                    self.info(f"Executing step: {step_name}")
                    try:
                        step_func()
                        self.info(f"Step {step_name} completed successfully")
                    except Exception as e:
                        self.error(f"Step {step_name} failed: {e}")
                        failed_steps.append(step_name)
                
                # Final health check
                if not failed_steps:
                    self.run_final_health_check()
                
                if failed_steps:
                    self.error(f"Bootstrap completed with {len(failed_steps)} failed steps: {failed_steps}")
                    return False
                else:
                    self.info("All installation steps completed successfully")
        
        except BlockingIOError:
            self.error("Another instance of this script is already running")
            return False
        
        # Success message
        self.info("Obsidian Command & Control Bootstrap Complete!")
        self.info("All services are running and healthy")
        self.info(f"Access Point: https://{self.domain}")
        self.info(f"WireGuard Server Public Key available at: {self.obsidian_cnc_home}/wireguard_server_public_key")
        self.info("Default client credentials available in: /root/wireguard-credentials/")
        
        # Create deployment summary
        if self.is_headless:
            summary_content = f"""Obsidian Command & Control - Deployment Summary
===============================================
Deployment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Domain: {self.domain}
Network Interface: {self.network_interface}

Access Points:
  - Main Dashboard: https://{self.domain}

Credentials:
  - Database Password: {self.db_password}
  - Keycloak Admin Password: {self.keycloak_admin_password}
  - Grafana Admin Password: {self.grafana_admin_password}

Files Created:
  - WireGuard Server Key: {self.obsidian_cnc_home}/wireguard_server_public_key
  - Default Client Configs: /root/wireguard-credentials/
  - Full Logs: {self.headless_log_file}

Next Steps:
  1. Configure DNS to point {self.domain} to this server
  2. Review default WireGuard client configurations
  3. Access management interface at https://{self.domain}
"""
            
            Path('/root/obsidian-cnc-deployment-summary.txt').write_text(summary_content)
            self.info("Deployment summary saved to: /root/obsidian-cnc-deployment-summary.txt")
        
        return True


def main():
    """Main entry point"""
    bootstrap = ObsidianBootstrap()
    success = bootstrap.main()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()