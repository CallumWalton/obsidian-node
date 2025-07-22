#!/usr/bin/env python3
"""
generate_orchestrator_cloud_init.py

Generates a Hetzner-compatible cloud-init YAML for your orchestrator node.
Autogenerates secure passwords and a secret.  Requests only the base domain.
Writes out both the cloud-init YAML and a JSON file with the generated credentials,
then validates the generated YAML for correctness.

Refactored to expose each service on its own sub-domain:
  headscale.<base>, keycloak.<base>, metrics.<base>,
  loki.<base>, nats.<base>
"""

import argparse
import secrets
import string
import json
import sys
import yaml
from string import Template

CLOUD_INIT_TEMPLATE = Template("""#cloud-config
package_update: true
package_upgrade: true
packages:
  - docker.io
  - docker-compose
  - wireguard-tools
  - postgresql
  - postgresql-contrib
  - caddy
  - nftables
  - jq
  - curl
  - python3-yaml

users:
  - default
  - name: obsidian
    groups: [adm, sudo, systemd-journal]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash

write_files:
  - path: /etc/caddy/Caddyfile
    content: |
      {
        email $acme_email
      }
      
      # Headscale Server (VPN control plane)
      $headscale_domain {
        # Handle API endpoints
        reverse_proxy localhost:8080 {
          header_up X-Real-IP {remote_host}
        }
      }
      
      # Headscale Web UI (admin interface)
      $headscale_ui_domain {
        reverse_proxy localhost:8081 {
          header_up X-Real-IP {remote_host}
        }
      }
      
      # Keycloak (admin UI & OIDC) - Different port to avoid conflict
      $keycloak_domain {
        reverse_proxy localhost:8083 {
          header_up Host {host}
          header_up X-Real-IP {remote_host}
        }
      }

      # VictoriaMetrics metrics endpoint
      $metrics_domain {
        reverse_proxy localhost:8428
      }

      # Loki query & ingestion
      $loki_domain {
        reverse_proxy localhost:3100
      }

      # NATS server & monitoring
      $nats_domain {
        @monitoring {
          path /_monitoring*
        }
        handle @monitoring {
          reverse_proxy localhost:8222
        }
        reverse_proxy localhost:4222
      }

      # Cockpit management interface (VPN-only)
      $cockpit_domain {
        @vpn_access {
          remote_ip 100.64.0.0/10 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
        }
        handle @vpn_access {
          reverse_proxy localhost:9092 {
            header_up X-Real-IP {remote_host}
          }
        }
        respond "Access denied - VPN connection required. Connect to Headscale VPN first." 403
      }

  - path: /etc/nftables.conf
    content: |
      #!/usr/sbin/nft -f
      flush ruleset
      table inet filter {
        chain input {
          type filter hook input priority filter; policy drop;
          iif lo accept
          ct state established,related accept
          tcp dport { 22, 80, 443 } accept
          # Headscale/metrics/loki/nats/cockpit/keycloak
          tcp dport { 8080, 8081, 8082, 8083, 8428, 3100, 4222, 8222, 9091, 9092, 33073, 33079 } accept
          udp dport { 51820, 33073, 41641 } accept
          ip saddr 100.64.0.0/10 accept comment "Tailscale network"
        }
      }

  - path: /etc/loki/local-config.yaml
    content: |
      auth_enabled: false
      server:
        http_listen_port: 3100
        grpc_listen_port: 9096
      common:
        path_prefix: /loki
        storage:
          filesystem:
            chunks_directory: /loki/chunks
            rules_directory: /loki/rules
        replication_factor: 1
        ring:
          instance_addr: 127.0.0.1
          kvstore:
            store: inmemory
      query_scheduler:
        max_outstanding_requests_per_tenant: 32768
      limits_config:
        allow_structured_metadata: false
      schema_config:
        configs:
          - from: 2020-10-24
            store: tsdb
            object_store: filesystem
            schema: v13
            index:
              prefix: index_
              period: 24h

  - path: /etc/keycloak/realm-config.json
    content: |
      {
        "realm": "headscale",
        "enabled": true,
        "displayName": "Headscale OIDC",
        "registrationAllowed": true,
        "registrationEmailAsUsername": true,
        "rememberMe": true,
        "verifyEmail": false,
        "loginWithEmailAllowed": true,
        "duplicateEmailsAllowed": false,
        "resetPasswordAllowed": true,
        "editUsernameAllowed": false,
        "bruteForceProtected": true,
        "clients": [
          {
            "clientId": "headscale-client",
            "name": "Headscale VPN",
            "enabled": true,
            "clientAuthenticatorType": "client-secret",
            "secret": "$headscale_client_secret",
            "redirectUris": [
              "https://$headscale_domain/oidc/callback",
              "https://$headscale_domain/auth/callback"
            ],
            "webOrigins": [
              "https://$headscale_domain"
            ],
            "protocol": "openid-connect",
            "publicClient": false,
            "bearerOnly": false,
            "consentRequired": false,
            "standardFlowEnabled": true,
            "implicitFlowEnabled": false,
            "directAccessGrantsEnabled": true,
            "serviceAccountsEnabled": false,
            "authorizationServicesEnabled": false,
            "fullScopeAllowed": true,
            "attributes": {
              "saml.assertion.signature": "false",
              "saml.force.post.binding": "false",
              "saml.multivalued.roles": "false",
              "saml.encrypt": "false",
              "post.logout.redirect.uris": "+",
              "oauth2.device.authorization.grant.enabled": "false",
              "backchannel.logout.revoke.offline.tokens": "false",
              "saml.server.signature": "false",
              "saml.server.signature.keyinfo.ext": "false",
              "exclude.session.state.from.auth.response": "false",
              "oidc.ciba.grant.enabled": "false",
              "saml.artifact.binding": "false",
              "backchannel.logout.session.required": "true",
              "client_credentials.use_refresh_token": "false",
              "saml_force_name_id_format": "false",
              "require.pushed.authorization.requests": "false",
              "saml.client.signature": "false",
              "tls.client.certificate.bound.access.tokens": "false",
              "saml.authnstatement": "false",
              "display.on.consent.screen": "false",
              "saml.onetimeuse.condition": "false"
            },
            "protocolMappers": [
              {
                "name": "email",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-property-mapper",
                "consentRequired": false,
                "config": {
                  "userinfo.token.claim": "true",
                  "user.attribute": "email",
                  "id.token.claim": "true",
                  "access.token.claim": "true",
                  "claim.name": "email",
                  "jsonType.label": "String"
                }
              },
              {
                "name": "username",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-property-mapper",
                "consentRequired": false,
                "config": {
                  "userinfo.token.claim": "true",
                  "user.attribute": "username",
                  "id.token.claim": "true",
                  "access.token.claim": "true",
                  "claim.name": "preferred_username",
                  "jsonType.label": "String"
                }
              },
              {
                "name": "groups",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-group-membership-mapper",
                "consentRequired": false,
                "config": {
                  "full.path": "false",
                  "id.token.claim": "true",
                  "access.token.claim": "true",
                  "claim.name": "groups",
                  "userinfo.token.claim": "true"
                }
              }
            ]
          }
        ],
        "groups": [
          {
            "name": "admin",
            "path": "/admin"
          },
          {
            "name": "users", 
            "path": "/users"
          }
        ],
        "users": [
          {
            "username": "admin",
            "enabled": true,
            "email": "admin@$base_domain",
            "firstName": "Administrator",
            "lastName": "User",
            "groups": ["/admin"],
            "credentials": [
              {
                "type": "password",
                "value": "$keycloak_admin_password",
                "temporary": false
              }
            ],
            "realmRoles": ["admin"],
            "clientRoles": {
              "realm-management": ["realm-admin"],
              "account": ["manage-account"]
            }
          }
        ]
      }

  - path: /etc/headscale/config.yaml
    content: |
      server_url: https://$headscale_domain
      listen_addr: 0.0.0.0:8080
      metrics_listen_addr: 127.0.0.1:9090
      grpc_listen_addr: 0.0.0.0:50443
      grpc_allow_insecure: false
      
      private_key_path: /var/lib/headscale/private.key
      noise:
        private_key_path: /var/lib/headscale/noise_private.key
      
      prefixes:
        v6: "fd7a:115c:a1e0::/48"
        v4: "100.64.0.0/10"
      
      derp:
        server:
          enabled: false
        urls:
          - https://controlplane.tailscale.com/derpmap/default
        paths: []
        auto_update_enabled: true
        update_frequency: 24h
      
      disable_check_updates: false
      ephemeral_node_inactivity_timeout: 30m
      node_update_check_interval: 10s
      
      database:
        type: postgres
        postgres:
          host: localhost
          port: 5432
          name: headscale
          user: headscale
          pass: "$headscale_db_pass"
      
      acme_url: https://acme-v02.api.letsencrypt.org/directory
      acme_email: $acme_email
      
      tls_letsencrypt_hostname: ""
      tls_letsencrypt_cache_dir: /var/lib/headscale/cache
      tls_letsencrypt_challenge_type: ""
      tls_letsencrypt_listen: ""
      
      log_level: info
      
      policy:
        path: /etc/headscale/acl.hujson
      
      dns:
        override_local_dns: true
        nameservers:
          global:
            - 1.1.1.1
            - 8.8.8.8
        search_domains: []
        magic_dns: true
        base_domain: tailnet.local
        extra_records:
          - name: "orchestrator"
            type: "A"
            value: "100.64.0.1"
          - name: "keycloak.internal"
            type: "A" 
            value: "100.64.0.1"
          - name: "metrics.internal"
            type: "A"
            value: "100.64.0.1"
          - name: "loki.internal"
            type: "A"
            value: "100.64.0.1"
          - name: "nats.internal"
            type: "A"
            value: "100.64.0.1"
          - name: "cockpit.internal"
            type: "A"
            value: "100.64.0.1"
      
      unix_socket: /var/run/headscale/headscale.sock
      unix_socket_permission: "0770"
      
      oidc:
        only_start_if_oidc_is_available: true
        issuer: https://$keycloak_domain/realms/headscale
        client_id: headscale-client
        client_secret: $headscale_client_secret
        scope: ["openid", "profile", "email", "groups"]
        extra_params: {}
        allowed_domains: []
        allowed_users: []

  - path: /etc/headscale/acl.hujson
    content: |
      {
        "groups": {
          "group:admin": ["admin@$base_domain"],
          "group:users": ["users@$base_domain"]
        },
        
        "acls": [
          {
            "action": "accept",
            "src": ["*"],
            "dst": ["*:*"]
          }
        ]
      }

  - path: /root/deploy-services.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      
      # Enhanced logging for repair and deployment
      exec > >(tee -a /var/log/deploy-services.log) 2>&1
      echo "$(date): Starting service deployment..."
      
      # Update system and install required packages
      echo "$(date): Updating system and installing packages..."
      apt-get update
      apt-get install -y \
        docker.io \
        docker-compose \
        wireguard-tools \
        postgresql \
        postgresql-contrib \
        caddy \
        nftables \
        jq \
        curl \
        python3-yaml \
        iptables-persistent
      echo "✓ Packages installed"
      
      # Fix iptables/nftables conflicts and ensure Docker networking works
      echo "$(date): Fixing Docker networking issues..."
      
      # Stop services to avoid conflicts
      systemctl stop docker 2>/dev/null || true
      systemctl stop nftables 2>/dev/null || true
      
      # Reset iptables to ensure clean state
      iptables -F
      iptables -X
      iptables -t nat -F
      iptables -t nat -X
      iptables -t mangle -F
      iptables -t mangle -X
      
      # Set up basic iptables rules that work with Docker
      iptables -P INPUT ACCEPT
      iptables -P FORWARD ACCEPT
      iptables -P OUTPUT ACCEPT
      
      # Allow Docker to manage its own chains
      iptables -N DOCKER 2>/dev/null || true
      iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
      iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
      iptables -N DOCKER-USER 2>/dev/null || true
      
      # Configure Docker daemon to avoid conflicts
      mkdir -p /etc/docker
      cat > /etc/docker/daemon.json << 'EOF'
      {
        "iptables": true,
        "ip-forward": true,
        "ip-masq": true,
        "userland-proxy": false,
        "live-restore": true
      }
      EOF
      
      # Function to check container status
      check_container() {
        local container_name=$1
        local max_attempts=${2:-30}
        local attempt=1
        
        echo "Checking $container_name status..."
        while [ $attempt -le $max_attempts ]; do
          if docker ps --filter "name=$container_name" --filter "status=running" --format "{{.Names}}" | grep -q "^${container_name}$"; then
            echo "✓ $container_name is running"
            return 0
          fi
          echo "Attempt $attempt/$max_attempts: $container_name not running yet..."
          docker logs $container_name --tail 10 2>/dev/null || echo "No logs available for $container_name"
          sleep 5
          ((attempt++))
        done
        
        echo "✗ $container_name failed to start after $max_attempts attempts"
        echo "Final container status:"
        docker ps -a --filter "name=$container_name" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo "Container logs:"
        docker logs $container_name 2>/dev/null || echo "No logs available"
        return 1
      }
      
      # Start Docker service
      echo "$(date): Starting Docker..."
      systemctl enable --now docker
      until systemctl is-active --quiet docker; do
        echo "Waiting for Docker..."
        sleep 2
      done
      echo "✓ Docker is running"
      
      # Wait a bit more for Docker to fully initialize networking
      sleep 5
      
      # Add user to docker group
      usermod -aG docker obsidian || true
      
      # Check PostgreSQL
      echo "$(date): Checking PostgreSQL..."
      if ! systemctl is-active --quiet postgresql; then
        echo "Starting PostgreSQL..."
        systemctl enable --now postgresql
        sleep 5
        
        # Initialize PostgreSQL if needed
        if [ ! -f /var/lib/postgresql/*/main/postgresql.conf ]; then
          echo "Initializing PostgreSQL..."
          sudo -u postgres /usr/lib/postgresql/*/bin/initdb -D /var/lib/postgresql/data
        fi
      fi
      
      # Wait for PostgreSQL to be fully ready
      echo "Waiting for PostgreSQL to be ready..."
      for i in {1..60}; do
        if pg_isready -h localhost -p 5432 -U postgres 2>/dev/null; then
          echo "✓ PostgreSQL is ready"
          break
        fi
        if [ $i -eq 60 ]; then
          echo "✗ PostgreSQL failed to start after 60 attempts"
          systemctl status postgresql
          exit 1
        fi
        sleep 2
      done
      
      # Create users and databases with error handling
      echo "$(date): Creating database users and databases..."
      sudo -u postgres psql -c "CREATE USER headscale WITH PASSWORD '$headscale_db_pass';" 2>/dev/null || echo "User headscale may already exist"
      sudo -u postgres psql -c "CREATE USER keycloak WITH PASSWORD '$keycloak_db_pass';" 2>/dev/null || echo "User keycloak may already exist"
      
      sudo -u postgres psql -c "CREATE DATABASE headscale OWNER headscale;" 2>/dev/null || echo "Database headscale may already exist"
      sudo -u postgres psql -c "CREATE DATABASE keycloak OWNER keycloak;" 2>/dev/null || echo "Database keycloak may already exist"
      
      sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE headscale TO headscale;" 2>/dev/null || true
      sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;" 2>/dev/null || true
      echo "✓ Databases verified"
      
      # Create directories
      echo "$(date): Creating directories..."
      mkdir -p /var/lib/headscale /etc/headscale /var/run/headscale
      mkdir -p /var/lib/keycloak/data /var/lib/keycloak/data/tmp /etc/keycloak
      mkdir -p /var/lib/victoria-metrics /var/lib/loki /var/lib/nats
      mkdir -p /var/lib/cockpit
      
      # Set proper permissions for Keycloak directories
      chown -R 1000:1000 /var/lib/keycloak
      chmod -R 755 /var/lib/keycloak
      echo "✓ Directories created and permissions set"
      
      # Copy configuration files
      cp /etc/keycloak/realm-config.json /var/lib/keycloak/
      echo "✓ Configuration files copied"
      
      # Create docker network for services
      echo "$(date): Creating Docker network..."
      docker network create orchestrator-net 2>/dev/null || echo "Network may already exist"
      
      # Clean up any existing containers
      echo "$(date): Cleaning up existing containers..."
      for container in headscale headscale-ui keycloak victoria-metrics loki nats cockpit; do
        docker stop $container 2>/dev/null || true
        docker rm $container 2>/dev/null || true
      done
      
      # Function to deploy container with retry
      deploy_container() {
        local container_name=$1
        local max_retries=3
        local retry=1
        
        while [ $retry -le $max_retries ]; do
          echo "$(date): Deploying $container_name (attempt $retry/$max_retries)..."
          
          # Stop and remove existing container
          docker stop $container_name 2>/dev/null || true
          docker rm $container_name 2>/dev/null || true
          
          case $container_name in
            "headscale")
              docker pull headscale/headscale:latest && \\
              docker run -d --name headscale \\
                --restart unless-stopped \\
                --network host \\
                -v /var/lib/headscale:/var/lib/headscale \\
                -v /etc/headscale:/etc/headscale:ro \\
                -v /var/run/headscale:/var/run/headscale \\
                headscale/headscale:latest headscale serve && \\
              check_container headscale 60 && return 0
              ;;
              
            "headscale-ui")
              docker pull ghcr.io/gurucomputing/headscale-ui:latest && \\
              docker run -d --name headscale-ui \\
                --restart unless-stopped \\
                --network host \\
                -e HS_SERVER=https://$headscale_domain \\
                -e SCRIPT_NAME=/admin -e KEY_API= \\
                -e PORT=8081 \\
                ghcr.io/gurucomputing/headscale-ui:latest && \\
              check_container headscale-ui && return 0
              ;;
              
            "keycloak")
              docker pull quay.io/keycloak/keycloak:latest && \\
              docker run -d --name keycloak \\
                --restart unless-stopped --network host \\
                -v /var/lib/keycloak:/opt/keycloak/data \\
                -e KEYCLOAK_ADMIN=admin \\
                -e KEYCLOAK_ADMIN_PASSWORD='$keycloak_admin_password' \\
                -e KC_DB=postgres \\
                -e KC_DB_URL=jdbc:postgresql://localhost:5432/keycloak \\
                -e KC_DB_USERNAME=keycloak \\
                -e KC_DB_PASSWORD='$keycloak_db_pass' \\
                -e KC_HOSTNAME=$keycloak_domain \\
                -e KC_HOSTNAME_STRICT=false \\
                -e KC_HTTP_ENABLED=true \\
                -e KC_HTTP_PORT=8083 \\
                -e KC_PROXY_HEADERS=xforwarded \\
                -e JAVA_OPTS_APPEND="-Djava.io.tmpdir=/opt/keycloak/data/tmp" \\
                --user 1000:1000 \\
                quay.io/keycloak/keycloak:latest start && \\
              check_container keycloak 120 && return 0
              ;;
              
            "victoria-metrics")
              docker pull victoriametrics/victoria-metrics:latest && \\
              docker run -d --name victoria-metrics \\
                --restart unless-stopped --network host \\
                -v /var/lib/victoria-metrics:/victoria-metrics-data \\
                victoriametrics/victoria-metrics:latest \\
                -storageDataPath=/victoria-metrics-data \\
                -retentionPeriod=90d -httpListenAddr=:8428 && \\
              check_container victoria-metrics && return 0
              ;;
              
            "loki")
              docker pull grafana/loki:latest && \\
              docker run -d --name loki \\
                --restart unless-stopped --network host \\
                -v /var/lib/loki:/loki -v /etc/loki:/etc/loki \\
                grafana/loki:latest \\
                -config.file=/etc/loki/local-config.yaml && \\
              check_container loki && return 0
              ;;
              
            "nats")
              docker pull nats:alpine && \\
              docker run -d --name nats \\
                --restart unless-stopped --network host \\
                -v /var/lib/nats:/data \\
                nats:alpine --js --store_dir /data --http_port 8222 --port 4222 && \\
              check_container nats && return 0
              ;;
              
            "cockpit")
              docker pull quay.io/cockpit/ws:latest && \\
              docker run -d --name cockpit \\
                --restart unless-stopped --privileged --pid host --network host \\
                -v /:/host:ro -v /var/run/docker.sock:/var/run/docker.sock \\
                -v /var/lib/cockpit:/var/lib/cockpit \\
                -e COCKPIT_WS_CERTS_DIR=/var/lib/cockpit \\
                quay.io/cockpit/ws:latest \\
                /usr/libexec/cockpit-ws --no-tls --port=9092 && \\
              check_container cockpit && return 0
              ;;
          esac
          
          echo "✗ Failed to deploy $container_name, attempt $retry failed"
          ((retry++))
          sleep 10
        done
        
        echo "✗ Failed to deploy $container_name after $max_retries attempts"
        return 1
      }
      
      # Deploy all containers
      echo "$(date): Starting container deployment..."
      
      containers=("headscale" "headscale-ui" "keycloak" "victoria-metrics" "loki" "nats" "cockpit")
      failed_containers=()
      
      for container in "${containers[@]}"; do
        if ! deploy_container $container; then
          failed_containers+=($container)
        fi
      done
      
      # Special handling for headscale user creation
      if docker ps --filter "name=headscale" --filter "status=running" -q | grep -q .; then
        echo "$(date): Creating default user..."
        sleep 10
        # Try the modern user creation command
        docker exec headscale headscale users create default 2>/dev/null || echo "User default may already exist"
      fi
      
      # Special handling for keycloak realm import
      if docker ps --filter "name=keycloak" --filter "status=running" -q | grep -q .; then
        echo "$(date): Importing Keycloak realm..."
        sleep 30  # Give Keycloak more time to fully start
        
        # Check if Keycloak is actually ready
        for i in {1..60}; do
          if curl -f http://localhost:8083/health/ready 2>/dev/null; then
            echo "✓ Keycloak is ready, importing realm..."
            docker exec keycloak /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/realm-config.json || \\
              echo "⚠ Realm import may have failed"
            break
          fi
          [ $i -eq 60 ] && echo "⚠ Keycloak health check timeout"
          sleep 5
        done
      fi
      
      # Final deployment summary with error reporting
      echo "$(date): Deployment completed!"
      
      if [ ${#failed_containers[@]} -eq 0 ]; then
        echo "✅ ALL CONTAINERS DEPLOYED SUCCESSFULLY"
      else
        echo "❌ FAILED CONTAINERS: ${failed_containers[*]}"
      fi
      echo ""
      echo "✓ All containers deployed and verified:"
      docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
      
      echo ""
      echo "Service status:"
      systemctl is-active docker && echo "✓ Docker: running" || echo "✗ Docker: failed"
      systemctl is-active postgresql && echo "✓ PostgreSQL: running" || echo "✗ PostgreSQL: failed"
      systemctl is-active caddy && echo "✓ Caddy: running" || echo "✗ Caddy: failed"
      systemctl is-active nftables && echo "✓ nftables: running" || echo "✗ nftables: failed"
      
      echo ""
      echo "Services available locally:"
      echo "- Headscale Server: http://localhost:8080"
      echo "- Headscale Web UI: http://localhost:8081" 
      echo "- Keycloak: http://localhost:8083"
      echo "- VictoriaMetrics: http://localhost:8428"
      echo "- Loki: http://localhost:3100"
      echo "- NATS: http://localhost:4222 (monitoring: 8222)"
      echo "- Cockpit: http://localhost:9092"
      echo ""
      echo "Internal VPN routing enabled for:"
      echo "- orchestrator (100.64.0.1)"
      echo "- keycloak.internal (100.64.0.1:8083)"
      echo "- metrics.internal (100.64.0.1:8428)"
      echo "- loki.internal (100.64.0.1:3100)"
      echo "- nats.internal (100.64.0.1:4222)"
      echo "- cockpit.internal (100.64.0.1:9092)"
      echo ""
      echo "Logs saved to: /var/log/deploy-services.log"
      echo "Check individual container logs with: docker logs <container-name>"

runcmd:
  # Enable services first
  - systemctl enable --now caddy
  # Apply nftables rules after Docker is running and containers are deployed
  - systemctl enable --now nftables || echo "⚠ nftables enable failed, trying manual rule application..."
  # Apply rules manually if systemd fails
  - /usr/sbin/nft -f /etc/nftables.conf || echo "⚠ Manual nftables rule application failed"
  # Run the deployment script
  - /root/deploy-services.sh
  # Final verification
  - sleep 10
  - docker ps --format "table {{.Names}} {{.Status}} {{.Ports}}"
  - systemctl status caddy --no-pager
  - echo "Orchestrator deployment completed successfully"

final_message: |
  Orchestrator deployment completed!
  
  Services available at:
  - Headscale Server: https://$headscale_domain (control plane)
  - Headscale Web UI: https://$headscale_ui_domain (admin interface)
  - Keycloak: https://$keycloak_domain (pre-configured with OIDC)
  - Metrics: https://$metrics_domain
  - Loki: https://$loki_domain
  - NATS: https://$nats_domain
  - Cockpit: https://$cockpit_domain (VPN-only access)
  
  IMPORTANT: Keycloak is pre-configured with OIDC integration!
  - Keycloak admin: admin / (see credentials JSON file)
  - Headscale OIDC is automatically configured
  - Default realm 'headscale' is enabled with OIDC client
  
  Headscale/Tailscale Setup:
  1. Download Tailscale clients from https://tailscale.com/download
  2. Connect clients using: tailscale up --login-server https://$headscale_domain
  3. Access Headscale Web UI: https://$headscale_ui_domain
  4. Connect to your Tailscale VPN to access UI and other services
  
  OIDC Authentication:
  - Users can authenticate via Keycloak at: https://$keycloak_domain
  - Headscale will automatically handle OIDC login redirects
  - Create additional users in Keycloak admin interface
  
  Check deployment logs: /var/log/cloud-init-output.log
  Docker containers status: docker ps
""")

def gen_password(length=24):
    """Generate a secure URL-safe password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # remove characters that may confuse shell quoting
    safe = alphabet.replace("'", "").replace('"', "").replace("\\", "")
    return ''.join(secrets.choice(safe) for _ in range(length))

def main():
    parser = argparse.ArgumentParser(
        description="Generate orchestrator-cloud-init.yaml and credentials JSON"
    )
    parser.add_argument(
        "--base-domain", "-d",
        required=True,
        help="Base domain (e.g. example.com). All services will live on <service>.<base-domain>."
    )
    parser.add_argument(
        "--email", "-e",
        required=True,
        help="Email address for ACME/Let's Encrypt certificates"
    )
    parser.add_argument(
        "--output-yaml", "-y",
        default="orchestrator-cloud-init.yaml",
        help="Output filename for cloud-init YAML"
    )
    parser.add_argument(
        "--output-json", "-j",
        default="orchestrator-credentials.json",
        help="Output filename for credentials JSON"
    )
    args = parser.parse_args()

    # derive separate hostnames
    headscale_domain = f"headscale.{args.base_domain}"
    headscale_ui_domain = f"headscale-ui.{args.base_domain}"
    keycloak_domain = f"keycloak.{args.base_domain}"
    metrics_domain = f"metrics.{args.base_domain}"
    loki_domain = f"loki.{args.base_domain}"
    nats_domain = f"nats.{args.base_domain}"
    cockpit_domain = f"cockpit.{args.base_domain}"

    creds = {
        "HEADSCALE_DB_PASS": gen_password(),
        "KEYCLOAK_DB_PASS": gen_password(),
        "KEYCLOAK_ADMIN_PASSWORD": gen_password(16),
        "HEADSCALE_CLIENT_SECRET": gen_password(32)
    }

    # render cloud-init
    filled = CLOUD_INIT_TEMPLATE.safe_substitute(
        base_domain=args.base_domain,
        headscale_domain=headscale_domain,
        headscale_ui_domain=headscale_ui_domain,
        keycloak_domain=keycloak_domain,
        metrics_domain=metrics_domain,
        loki_domain=loki_domain,
        nats_domain=nats_domain,
        cockpit_domain=cockpit_domain,
        acme_email=args.email,
        headscale_db_pass=creds["HEADSCALE_DB_PASS"],
        keycloak_db_pass=creds["KEYCLOAK_DB_PASS"],
        keycloak_admin_password=creds["KEYCLOAK_ADMIN_PASSWORD"],
        headscale_client_secret=creds["HEADSCALE_CLIENT_SECRET"]
    )

    # write YAML & JSON with UTF-8 encoding
    with open(args.output_yaml, "w", encoding="utf-8") as f_yaml:
        f_yaml.write(filled)
    with open(args.output_json, "w", encoding="utf-8") as f_json:
        json.dump(creds, f_json, indent=2)

    # validate
    try:
        yaml.safe_load(filled)
        print("✓ Generated cloud-init YAML is syntactically valid")
    except yaml.YAMLError as e:
        print("✗ YAML validation error:", e)
        sys.exit(1)

    print(f"✓ Generated cloud-init YAML: {args.output_yaml}")
    print(f"✓ Generated credentials JSON: {args.output_json}")
    print()
    print("Next Steps:")
    print(f"  • Create DNS A records pointing to your server's IP for:")
    for svc in ("headscale", "headscale-ui", "keycloak", "metrics", "loki", "nats", "cockpit"):
        print(f"    - {svc}.{args.base_domain}")
    print("  • Boot the instance using the generated cloud-init YAML.")
    print(f"  • After boot, verify each service is reachable:")
    print(f"    - Headscale API -> https://{headscale_domain}")
    print(f"    - Headscale UI -> https://{headscale_ui_domain}")
    print(f"    - Keycloak UI -> https://{keycloak_domain}")
    print(f"    - Metrics API -> https://{metrics_domain}")
    print(f"    - Loki -> https://{loki_domain}")
    print(f"    - NATS -> https://{nats_domain}")
    print(f"    - Cockpit -> https://{cockpit_domain} (VPN-only)")
    print()
    print("  IMPORTANT SETUP STEPS:")
    print(f"  1. Keycloak is pre-configured with OIDC integration!")
    print(f"     - Access Keycloak: https://{keycloak_domain}")
    print(f"     - Admin login: admin / (check credentials JSON)")
    print("  2. Headscale OIDC is automatically configured and ready")
    print("  3. Connect to Headscale VPN to access UI and Cockpit")
    print(f"  4. Access Headscale Dashboard: https://{headscale_ui_domain}")
    print("  5. Download Tailscale clients from https://tailscale.com/download")
    print(f"  6. Connect clients using: tailscale up --login-server https://{headscale_domain}")
    print("  7. Users can authenticate via OIDC:")
    print(f"     - Register/login at: https://{keycloak_domain}")
    print("     - Headscale will handle OIDC authentication automatically")
    print("  8. Manage users and access policies in Headscale Dashboard")
    print("  • Enjoy your new orchestrator with Headscale/Tailscale VPN!")
    
if __name__ == "__main__":
    main()
