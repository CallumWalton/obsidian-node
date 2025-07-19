#Requires -Version 5.1
<#
.SYNOPSIS
    Interactive PowerShell script to generate cloud-init configuration for Obsidian C&C Bootstrap

.DESCRIPTION
    This script prompts the user for all required configuration parameters and generates
    a complete cloud-init YAML file for deploying the Obsidian Command & Control server
    on Hetzner Cloud or other cloud providers.

.PARAMETER OutputPath
    Path where the generated cloud-init file will be saved (default: current directory)

.PARAMETER ConfigFile
    Optional JSON file with pre-configured values to skip interactive prompts

.EXAMPLE
    .\Generate-CncCloudInit.ps1
    
.EXAMPLE
    .\Generate-CncCloudInit.ps1 -OutputPath "C:\Deploy\" -ConfigFile "my-config.json"

.NOTES
    Author: Obsidian Platform Team
    Version: 1.0
    Date: 2025-01-19
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = $null,
    
    [Parameter(Mandatory = $false)]
    [switch]$Interactive = $true
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "Continue"

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput "ℹ️  $Message" -ForegroundColor "Cyan"
}

function Write-Success {
    param([string]$Message)
    Write-ColorOutput "✅ $Message" -ForegroundColor "Green"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "⚠️  $Message" -ForegroundColor "Yellow"
}

function Write-Error {
    param([string]$Message)
    Write-ColorOutput "❌ $Message" -ForegroundColor "Red"
}

# Configuration validation functions
function Test-DomainName {
    param([string]$Domain)
    return $Domain -match '^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.[a-zA-Z]{2,}$'
}

function Test-EmailAddress {
    param([string]$Email)
    return $Email -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
}

function Test-IPAddress {
    param([string]$IP)
    try {
        [System.Net.IPAddress]::Parse($IP) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-CIDRNotation {
    param([string]$CIDR)
    return $CIDR -match '^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$'
}

function Test-Port {
    param([string]$Port)
    try {
        $portNum = [int]$Port
        return ($portNum -ge 1 -and $portNum -le 65535)
    }
    catch {
        return $false
    }
}

# Generate secure password
function New-SecurePassword {
    param([int]$Length = 32)
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

# Prompt with validation
function Read-ValidatedInput {
    param(
        [string]$Prompt,
        [string]$DefaultValue = $null,
        [scriptblock]$Validator = $null,
        [string]$ValidationMessage = "Invalid input. Please try again.",
        [switch]$IsPassword,
        [switch]$AllowEmpty
    )
    
    do {
        if ($DefaultValue) {
            $displayPrompt = "$Prompt [$DefaultValue]"
        } else {
            $displayPrompt = $Prompt
        }
        
        if ($IsPassword) {
            $input = Read-Host -Prompt $displayPrompt -AsSecureString
            $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input))
        } else {
            $input = Read-Host -Prompt $displayPrompt
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $DefaultValue) {
            $input = $DefaultValue
        }
        
        if ([string]::IsNullOrWhiteSpace($input) -and $AllowEmpty) {
            return $input
        }
        
        if ([string]::IsNullOrWhiteSpace($input)) {
            Write-Warning "Input cannot be empty."
            continue
        }
        
        if ($Validator -and -not (& $Validator $input)) {
            Write-Warning $ValidationMessage
            continue
        }
        
        return $input
        
    } while ($true)
}

# Main configuration collection
function Get-CncConfiguration {
    param([hashtable]$PreConfig = @{})
    
    Write-ColorOutput "`n🚀 Obsidian Command & Control Cloud-Init Generator" -ForegroundColor "Magenta"
    Write-ColorOutput "=" * 60 -ForegroundColor "Gray"
    
    $config = @{}
    
    # Core Infrastructure
    Write-Info "Core Infrastructure Configuration"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $config.DOMAIN = Read-ValidatedInput `
        -Prompt "Enter your C&C server domain (e.g., cnc.obsidian.example.com)" `
        -DefaultValue $PreConfig.DOMAIN `
        -Validator { Test-DomainName $args[0] } `
        -ValidationMessage "Please enter a valid domain name (e.g., cnc.example.com)"
    
    $config.EMAIL = Read-ValidatedInput `
        -Prompt "Enter administrator email for Let's Encrypt certificates" `
        -DefaultValue $PreConfig.EMAIL `
        -Validator { Test-EmailAddress $args[0] } `
        -ValidationMessage "Please enter a valid email address"
    
    $config.ADMIN_EMAIL = Read-ValidatedInput `
        -Prompt "Enter administrator email for notifications" `
        -DefaultValue $config.EMAIL `
        -Validator { Test-EmailAddress $args[0] } `
        -ValidationMessage "Please enter a valid email address"
    
    # GitHub Configuration
    Write-Info "`nGitHub Repository Configuration"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $config.GITHUB_PAT_TOKEN = Read-ValidatedInput `
        -Prompt "Enter GitHub Personal Access Token (ghp_...)" `
        -DefaultValue $PreConfig.GITHUB_PAT_TOKEN `
        -IsPassword `
        -Validator { $args[0] -match '^ghp_[a-zA-Z0-9]{36}$' } `
        -ValidationMessage "Please enter a valid GitHub PAT token starting with 'ghp_'"
    
    # Security Passwords
    Write-Info "`nSecurity Configuration (leave blank to auto-generate)"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $autoGenerate = $null -eq $PreConfig.DB_PASSWORD
    if ($autoGenerate) {
        Write-Info "Auto-generating secure passwords..."
    }
    
    $config.DB_PASSWORD = if ($PreConfig.DB_PASSWORD) { 
        $PreConfig.DB_PASSWORD 
    } else { 
        New-SecurePassword -Length 32
    }
    Write-Success "Database password: $(if ($autoGenerate) { 'Generated' } else { 'Using provided' })"
    
    $config.KEYCLOAK_ADMIN_PASSWORD = if ($PreConfig.KEYCLOAK_ADMIN_PASSWORD) { 
        $PreConfig.KEYCLOAK_ADMIN_PASSWORD 
    } else { 
        New-SecurePassword -Length 24
    }
    Write-Success "Keycloak admin password: $(if ($autoGenerate) { 'Generated' } else { 'Using provided' })"
    
    $config.GRAFANA_ADMIN_PASSWORD = if ($PreConfig.GRAFANA_ADMIN_PASSWORD) { 
        $PreConfig.GRAFANA_ADMIN_PASSWORD 
    } else { 
        New-SecurePassword -Length 24
    }
    Write-Success "Grafana admin password: $(if ($autoGenerate) { 'Generated' } else { 'Using provided' })"
    
    # VPN Configuration
    Write-Info "`nWireGuard VPN Configuration"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $config.WG_NETWORK_CIDR = Read-ValidatedInput `
        -Prompt "Enter VPN network CIDR" `
        -DefaultValue ($PreConfig.WG_NETWORK_CIDR -or "10.0.0.0/24") `
        -Validator { Test-CIDRNotation $args[0] } `
        -ValidationMessage "Please enter a valid CIDR notation (e.g., 10.0.0.0/24)"
    
    # WG_SERVER_IP is auto-determined from CIDR (first usable IP)
    $config.WG_SERVER_IP = ($config.WG_NETWORK_CIDR -replace '/.*', '') -replace '\d+$', '1'
    Write-Info "VPN server IP auto-determined: $($config.WG_SERVER_IP)"
    
    $config.WG_PORT = Read-ValidatedInput `
        -Prompt "Enter WireGuard port" `
        -DefaultValue ($PreConfig.WG_PORT -or "51820") `
        -Validator { Test-Port $args[0] } `
        -ValidationMessage "Please enter a valid port number (1-65535)"
    
    # SSH Configuration
    Write-Info "`nSSH Configuration"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $defaultKeyPath = "$env:USERPROFILE\.ssh\id_rsa.pub"
    $sshKeyExists = Test-Path $defaultKeyPath
    
    if ($sshKeyExists) {
        Write-Success "Found SSH public key at: $defaultKeyPath"
        $useDefault = Read-Host "Use this SSH key? (Y/n)"
        if ($useDefault -eq "" -or $useDefault -eq "Y" -or $useDefault -eq "y") {
            $config.SSH_PUBLIC_KEY = Get-Content $defaultKeyPath -Raw
        }
    }
    
    if (-not $config.SSH_PUBLIC_KEY) {
        Write-Warning "Please provide your SSH public key content:"
        $config.SSH_PUBLIC_KEY = Read-ValidatedInput `
            -Prompt "SSH Public Key (ssh-rsa AAAA...)" `
            -Validator { $args[0] -match '^ssh-(rsa|ed25519|ecdsa)' } `
            -ValidationMessage "Please enter a valid SSH public key"
    }
    
    # Optional SMTP Configuration
    Write-Info "`nSMTP Configuration (Optional - leave blank to skip email notifications)"
    Write-ColorOutput "-" * 40 -ForegroundColor "Gray"
    
    $config.SMTP_HOST = Read-ValidatedInput `
        -Prompt "SMTP server hostname" `
        -DefaultValue $PreConfig.SMTP_HOST `
        -AllowEmpty
    
    if ($config.SMTP_HOST) {
        $config.SMTP_PORT = Read-ValidatedInput `
            -Prompt "SMTP port" `
            -DefaultValue ($PreConfig.SMTP_PORT -or "587") `
            -Validator { Test-Port $args[0] } `
            -ValidationMessage "Please enter a valid port number"
        
        $config.SMTP_USER = Read-ValidatedInput `
            -Prompt "SMTP username" `
            -DefaultValue $PreConfig.SMTP_USER `
            -Validator { Test-EmailAddress $args[0] } `
            -ValidationMessage "Please enter a valid email address"
        
        $config.SMTP_PASSWORD = Read-ValidatedInput `
            -Prompt "SMTP password" `
            -DefaultValue $PreConfig.SMTP_PASSWORD `
            -IsPassword
    }
    
    return $config
}

# Generate cloud-init YAML
function New-CloudInitYaml {
    param([hashtable]$Config)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    
    $yaml = @"
#cloud-config
# Obsidian Command & Control Server CloudInit Configuration
# Generated by Generate-CncCloudInit.ps1 on $timestamp
# For Ubuntu 24.04 LTS on Hetzner Cloud CX31 or equivalent
# 
# This cloud-init configuration will:
# 1. Set up the server with proper security
# 2. Download and execute the C&C bootstrap script
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
      - $($Config.SSH_PUBLIC_KEY.Trim())

# Hostname and timezone
hostname: obsidian-cnc
timezone: UTC

# Automatic security updates
write_files:
  # Unattended upgrades configuration
  - path: /etc/apt/apt.conf.d/50unattended-upgrades
    content: |
      Unattended-Upgrade::Allowed-Origins {
          "`${distro_id}:`${distro_codename}";
          "`${distro_id}:`${distro_codename}-security";
          "`${distro_id}ESMApps:`${distro_codename}-apps-security";
          "`${distro_id}ESM:`${distro_codename}-infra-security";
      };
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
      export GITHUB_PAT_TOKEN="$($Config.GITHUB_PAT_TOKEN)"
      export DOMAIN="$($Config.DOMAIN)"
      export EMAIL="$($Config.EMAIL)"
      export DB_PASSWORD="$($Config.DB_PASSWORD)"
      export KEYCLOAK_ADMIN_PASSWORD="$($Config.KEYCLOAK_ADMIN_PASSWORD)"
      export WG_NETWORK_CIDR="$($Config.WG_NETWORK_CIDR)"
      export WG_SERVER_IP="$($Config.WG_SERVER_IP)"
      export WG_PORT="$($Config.WG_PORT)"
      export GRAFANA_ADMIN_PASSWORD="$($Config.GRAFANA_ADMIN_PASSWORD)"
      export ADMIN_EMAIL="$($Config.ADMIN_EMAIL)"
$(if ($Config.SMTP_HOST) {
@"
      export SMTP_HOST="$($Config.SMTP_HOST)"
      export SMTP_PORT="$($Config.SMTP_PORT)"
      export SMTP_USER="$($Config.SMTP_USER)"
      export SMTP_PASSWORD="$($Config.SMTP_PASSWORD)"
"@
} else {
@"
      # SMTP configuration disabled
      # export SMTP_HOST="smtp.example.com"
      # export SMTP_PORT="587"
      # export SMTP_USER="noreply@example.com"
      # export SMTP_PASSWORD="smtp-password"
"@
})
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
      echo "Deployment time: `$(date)" >> /var/log/obsidian-status.log
      echo "Hostname: `$(hostname)" >> /var/log/obsidian-status.log
      echo "Public IP: `$(curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo 'Unknown')" >> /var/log/obsidian-status.log
      echo "Memory usage: `$(free -h)" >> /var/log/obsidian-status.log
      echo "Disk usage: `$(df -h /)" >> /var/log/obsidian-status.log
      echo "Active services: `$(systemctl list-units --state=active --no-pager | wc -l)" >> /var/log/obsidian-status.log
      echo "Docker status: `$(systemctl is-active docker 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
      echo "WireGuard status: `$(systemctl is-active wg-quick@wg0 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
      echo "Nginx status: `$(systemctl is-active nginx 2>/dev/null || echo 'Not active')" >> /var/log/obsidian-status.log
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
      echo "Timestamp: `$(date)" | tee -a /var/log/obsidian-validation.log
      
      # Check required environment variables
      REQUIRED_VARS=("DOMAIN" "EMAIL" "DB_PASSWORD" "KEYCLOAK_ADMIN_PASSWORD" "GRAFANA_ADMIN_PASSWORD")
      
      for var in "`${REQUIRED_VARS[@]}"; do
          if [[ -z "`${!var:-}" ]]; then
              echo "ERROR: Required variable `$var is not set" | tee -a /var/log/obsidian-validation.log
              exit 1
          else
              echo "✓ `$var is set" | tee -a /var/log/obsidian-validation.log
          fi
      done
      
      # Test internet connectivity
      if ping -c 3 8.8.8.8 > /dev/null 2>&1; then
          echo "✓ Internet connectivity confirmed" | tee -a /var/log/obsidian-validation.log
      else
          echo "WARNING: Internet connectivity issues detected" | tee -a /var/log/obsidian-validation.log
      fi
      
      # Check disk space
      DISK_USAGE=`$(df / | awk 'NR==2 {print `$5}' | sed 's/%//')
      if [[ `$DISK_USAGE -lt 80 ]]; then
          echo "✓ Sufficient disk space available (`${DISK_USAGE}% used)" | tee -a /var/log/obsidian-validation.log
      else
          echo "WARNING: Low disk space (`${DISK_USAGE}% used)" | tee -a /var/log/obsidian-validation.log
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
  - git config --global user.email "`${ADMIN_EMAIL}"
  - echo "https://`${GITHUB_PAT_TOKEN}@github.com" > /root/.git-credentials
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
    /var/log/obsidian-*.log {
        daily
        rotate 30
        compress
        delaycompress
        missingok
        notifempty
        create 0644 root root
    }
    EOF
  
  # Create monitoring cron job
  - /opt/system-monitor.sh
  - echo "*/5 * * * * /opt/system-monitor.sh" | crontab -
  
  # Restart SSH with new configuration
  - systemctl restart ssh
  
$(if ($Config.SMTP_HOST) {
@"
  # Send deployment notification
  - |
    if command -v mail >/dev/null 2>&1; then
      echo "Obsidian C&C Server deployment initiated on `$(hostname) - `$(date)" | \
      mail -s "Obsidian C&C Deployment Started" "$($Config.ADMIN_EMAIL)" || true
    fi
"@
} else {
@"
  # SMTP notifications disabled
"@
})

  # Wait for bootstrap to complete and run final status
  - sleep 30
  - /opt/system-monitor.sh

# Final message
final_message: |
  Obsidian Command & Control Server deployment initiated via cloud-init.
  
  Configuration Summary:
  - Domain: $($Config.DOMAIN)
  - Admin Email: $($Config.ADMIN_EMAIL)
  - VPN Network: $($Config.WG_NETWORK_CIDR)
  - VPN Server IP: $($Config.WG_SERVER_IP)
  - WireGuard Port: $($Config.WG_PORT)
$(if ($Config.SMTP_HOST) {
@"
  - SMTP Host: $($Config.SMTP_HOST)
"@
})
  
  Monitor deployment progress:
  - Validation log: /var/log/obsidian-validation.log
  - Bootstrap log: /var/log/obsidian-bootstrap.log
  - System status: /var/log/obsidian-status.log
  - Cloud-init log: /var/log/cloud-init-output.log
  
  Once deployment completes (15-25 minutes), access your C&C server at:
  https://$($Config.DOMAIN)
  
  SSH access: ssh obsidian@<server-ip>
  
  Important: Configure DNS to point $($Config.DOMAIN) to this server's IP!

# Power state management
power_state:
  delay: "+1"
  mode: reboot
  message: "Rebooting after Obsidian C&C installation"
  condition: true
"@

    return $yaml
}

# Generate credentials summary
function New-CredentialsSummary {
    param([hashtable]$Config)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
    
    $summary = @"
Obsidian Command & Control - Generated Credentials
================================================
Generated: $timestamp
Domain: $($Config.DOMAIN)
Admin Email: $($Config.ADMIN_EMAIL)

IMPORTANT: Save these credentials securely!

Database Configuration:
- Database Password: $($Config.DB_PASSWORD)

Keycloak SSO:
- Admin Username: admin
- Admin Password: $($Config.KEYCLOAK_ADMIN_PASSWORD)
- Access URL: https://$($Config.DOMAIN)/auth/admin

Grafana Monitoring:
- Admin Username: admin
- Admin Password: $($Config.GRAFANA_ADMIN_PASSWORD)  
- Access URL: https://$($Config.DOMAIN)/grafana

WireGuard VPN:
- Network: $($Config.WG_NETWORK_CIDR)
- Server IP: $($Config.WG_SERVER_IP)
- Port: $($Config.WG_PORT)

$(if ($Config.SMTP_HOST) {
@"
SMTP Configuration:
- Host: $($Config.SMTP_HOST)
- Port: $($Config.SMTP_PORT)
- Username: $($Config.SMTP_USER)
- Password: $($Config.SMTP_PASSWORD)
"@
} else {
@"
SMTP Configuration: Disabled
"@
})

Access Information:
- Main Dashboard: https://$($Config.DOMAIN)
- SSH: ssh obsidian@<server-ip>
- Default WireGuard clients will be available in: /root/wireguard-credentials/

Post-Deployment Steps:
1. Configure DNS A record: $($Config.DOMAIN) -> <server-ip>
2. Wait for bootstrap completion (~15-25 minutes)
3. Access Cockpit dashboard at https://$($Config.DOMAIN)
4. Configure Keycloak realm and clients
5. Set up Grafana dashboards
6. Add WireGuard VPN clients as needed

Security Notes:
- All management interfaces are secured with SSL/TLS
- WireGuard VPN provides secure access to management functions
- Automatic security updates are enabled
- Fail2ban is configured for intrusion prevention

For support and documentation, see:
https://github.com/CallumWalton/obsidian-node
"@

    return $summary
}

# Main execution
function Main {
    try {
        Write-ColorOutput "`n🔧 Obsidian C&C Cloud-Init Generator" -ForegroundColor "Magenta"
        Write-ColorOutput "=" * 60 -ForegroundColor "Gray"
        Write-Info "This script will generate a complete cloud-init configuration for deploying"
        Write-Info "the Obsidian Command & Control server on Hetzner Cloud or other providers."
        Write-ColorOutput ""
        
        # Load pre-configuration if provided
        $preConfig = @{}
        if ($ConfigFile -and (Test-Path $ConfigFile)) {
            Write-Info "Loading configuration from: $ConfigFile"
            $preConfig = Get-Content $ConfigFile | ConvertFrom-Json -AsHashtable
            Write-Success "Configuration loaded successfully"
        }
        
        # Collect configuration
        $config = Get-CncConfiguration -PreConfig $preConfig
        
        # Generate files
        Write-Info "`nGenerating cloud-init configuration..."
        $cloudInitYaml = New-CloudInitYaml -Config $config
        $credentialsSummary = New-CredentialsSummary -Config $config
        
        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Generate file names with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $cloudInitFile = Join-Path $OutputPath "obsidian-cnc-cloudinit-$timestamp.yml"
        $credentialsFile = Join-Path $OutputPath "obsidian-cnc-credentials-$timestamp.txt"
        $configJsonFile = Join-Path $OutputPath "obsidian-cnc-config-$timestamp.json"
        
        # Write files
        $cloudInitYaml | Out-File -FilePath $cloudInitFile -Encoding UTF8
        $credentialsSummary | Out-File -FilePath $credentialsFile -Encoding UTF8
        $config | ConvertTo-Json -Depth 10 | Out-File -FilePath $configJsonFile -Encoding UTF8
        
        # Success message
        Write-Success "`nFiles generated successfully!"
        Write-ColorOutput ""
        Write-Info "Generated Files:"
        Write-ColorOutput "  📋 Cloud-Init: $cloudInitFile" -ForegroundColor "White"
        Write-ColorOutput "  🔑 Credentials: $credentialsFile" -ForegroundColor "White"
        Write-ColorOutput "  ⚙️  Config JSON: $configJsonFile" -ForegroundColor "White"
        
        Write-ColorOutput ""
        Write-Info "Next Steps:"
        Write-ColorOutput "  1. Configure DNS: $($config.DOMAIN) -> <server-ip>" -ForegroundColor "Yellow"
        Write-ColorOutput "  2. Deploy to Hetzner Cloud using the generated cloud-init file" -ForegroundColor "Yellow"
        Write-ColorOutput "  3. Monitor deployment logs: /var/log/obsidian-bootstrap.log" -ForegroundColor "Yellow"
        Write-ColorOutput "  4. Access dashboard: https://$($config.DOMAIN)" -ForegroundColor "Yellow"
        
        Write-Warning "`n⚠️  IMPORTANT: Keep the credentials file secure!"
        Write-Warning "⚠️  The generated passwords are required for initial system access."
        
        # Hetzner Cloud deployment hint
        Write-ColorOutput ""
        Write-Info "Hetzner Cloud Deployment Example:"
        Write-ColorOutput @"
hcloud server create \
  --type cx31 \
  --image ubuntu-24.04 \
  --name obsidian-cnc \
  --ssh-key your-key-name \
  --user-data-from-file "$cloudInitFile" \
  --label environment=production \
  --label role=cnc-server
"@ -ForegroundColor "Gray"
        
    }
    catch {
        Write-Error "Error generating cloud-init configuration: $($_.Exception.Message)"
        Write-Error "Stack trace: $($_.ScriptStackTrace)"
        exit 1
    }
}

# Execute main function
Main
# Execute main function
Main
"@

    return $yaml
}

# Run the main function
Main
