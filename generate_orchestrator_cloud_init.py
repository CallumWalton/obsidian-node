#!/usr/bin/env python3
"""
generate_orchestrator_cloud_init.py

Generates a Hetzner-compatible cloud-init YAML for your orchestrator node.
Autogenerates secure passwords and a secret. Requests only the base domain.
Writes out both the cloud-init YAML and a JSON file with the generated credentials.
"""

import argparse
import secrets
import string
import json
from string import Template

CLOUD_INIT_TEMPLATE = Template("""#cloud-config
package_update: true
package_upgrade: true
packages:
  - podman
  - cockpit
  - cockpit-podman
  - wireguard-tools
  - postgresql-14
  - caddy
  - nftables
  - jq
  - curl

write_files:
  - path: /etc/containers/systemd/headscale.container
    content: |
      [Container]
      Image=docker.io/headscale/headscale:latest
      Volume=/var/lib/headscale:/var/lib/headscale:Z
      Volume=/etc/headscale:/etc/headscale:ro,Z
      PublishPort=8080:8080
      Environment=HEADSCALE_LOG_LEVEL=info
      
      [Service]
      Restart=always
      
      [Install]
      WantedBy=multi-user.target

  - path: /etc/headscale/config.yaml
    content: |
      server_url: https://$control_domain:8080
      listen_addr: 0.0.0.0:8080
      metrics_listen_addr: 127.0.0.1:9090
      private_key_path: /var/lib/headscale/private.key
      ip_prefixes:
        - 100.64.0.0/10
      db_type: postgres
      db_host: localhost
      db_port: 5432
      db_name: headscale
      db_user: headscale
      db_pass: $headscale_db_pass

  - path: /etc/containers/systemd/authentik.container
    content: |
      [Container]
      Image=docker.io/goauthentik/server:latest
      Volume=/var/lib/authentik:/media:Z
      PublishPort=9000:9000
      Environment=AUTHENTIK_POSTGRESQL__HOST=localhost
      Environment=AUTHENTIK_POSTGRESQL__NAME=authentik
      Environment=AUTHENTIK_POSTGRESQL__USER=authentik
      Environment=AUTHENTIK_POSTGRESQL__PASSWORD=$authentik_db_pass
      Environment=AUTHENTIK_SECRET_KEY=$authentik_secret
      
      [Service]
      Restart=always
      
      [Install]
      WantedBy=multi-user.target

  - path: /etc/containers/systemd/victoria-metrics.container
    content: |
      [Container]
      Image=docker.io/victoriametrics/victoria-metrics:stable
      Volume=/var/lib/victoria-metrics:/victoria-metrics-data:Z
      PublishPort=8428:8428
      
      [Service]
      Restart=always
      ExecStart=/victoria-metrics \\
        -storageDataPath=/victoria-metrics-data \\
        -retentionPeriod=90d \\
        -httpListenAddr=:8428
      
      [Install]
      WantedBy=multi-user.target

  - path: /etc/containers/systemd/loki.container
    content: |
      [Container]
      Image=docker.io/grafana/loki:latest
      Volume=/var/lib/loki:/loki:Z
      Volume=/etc/loki:/etc/loki:ro,Z
      PublishPort=3100:3100
      
      [Service]
      Restart=always
      
      [Install]
      WantedBy=multi-user.target

  - path: /etc/loki/loki-config.yaml
    content: |
      auth_enabled: false
      server:
        http_listen_port: 3100
      ingester:
        lifecycler:
          address: 127.0.0.1
          ring:
            kvstore:
              store: inmemory
            replication_factor: 1
      schema_config:
        configs:
          - from: 2020-10-24
            store: boltdb-shipper
            object_store: filesystem
            schema: v11
            index:
              prefix: index_
              period: 24h
      storage_config:
        boltdb_shipper:
          active_index_directory: /loki/boltdb-shipper-active
          cache_location: /loki/boltdb-shipper-cache
          shared_store: filesystem
        filesystem:
          directory: /loki/chunks

  - path: /etc/containers/systemd/nats.container
    content: |
      [Container]
      Image=docker.io/nats:alpine
      Volume=/var/lib/nats:/data:Z
      PublishPort=4222:4222
      PublishPort=8222:8222
      
      [Service]
      Restart=always
      ExecStart=/nats-server \\
        --js \\
        --sd /data \\
        --http_port 8222
      
      [Install]
      WantedBy=multi-user.target

  - path: /etc/caddy/Caddyfile
    content: |
      $control_domain {
        reverse_proxy /auth/* localhost:9000
        reverse_proxy /metrics/* localhost:8428
        reverse_proxy /headscale/* localhost:8080
        reverse_proxy /* localhost:9090
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
          tcp dport { 22, 80, 443, 9090 } accept
          udp dport { 51820 } accept
          ip saddr 100.64.0.0/10 accept comment "Headscale network"
        }
      }

runcmd:
  - systemctl enable --now postgresql
  - sudo -u postgres createuser headscale
  - sudo -u postgres createdb -O headscale headscale
  - sudo -u postgres psql -c "ALTER USER headscale PASSWORD '$headscale_db_pass';"
  - sudo -u postgres createuser authentik
  - sudo -u postgres createdb -O authentik authentik
  - sudo -u postgres psql -c "ALTER USER authentik PASSWORD '$authentik_db_pass';"
  - mkdir -p /var/lib/{headscale,authentik,victoria-metrics,loki,nats}
  - mkdir -p /etc/{headscale,loki}
  - systemctl daemon-reload
  - systemctl enable --now podman.socket
  - systemctl enable --now headscale.container
  - systemctl enable --now authentik.container
  - systemctl enable --now victoria-metrics.container
  - systemctl enable --now loki.container
  - systemctl enable --now nats.container
  - systemctl enable --now caddy
  - systemctl enable --now cockpit.socket
  - systemctl enable --now nftables
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
        help="Base domain (e.g. example.com). Will create control.<base-domain>."
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

    control_domain = f"control.{args.base_domain}"
    creds = {
        "HEADSCALE_DB_PASS": gen_password(),
        "AUTHENTIK_DB_PASS": gen_password(),
        "AUTHENTIK_SECRET": gen_password(32)
    }

    # Write cloud-init YAML
    filled = CLOUD_INIT_TEMPLATE.substitute(
        control_domain=control_domain,
        headscale_db_pass=creds["HEADSCALE_DB_PASS"],
        authentik_db_pass=creds["AUTHENTIK_DB_PASS"],
        authentik_secret=creds["AUTHENTIK_SECRET"]
    )
    with open(args.output_yaml, "w") as f_yaml:
        f_yaml.write(filled)

    # Write credentials JSON
    with open(args.output_json, "w") as f_json:
        json.dump(creds, f_json, indent=2)

    print(f"✓ Generated cloud-init YAML: {args.output_yaml}")
    print(f"✓ Generated credentials JSON: {args.output_json}")

if __name__ == "__main__":
    main()