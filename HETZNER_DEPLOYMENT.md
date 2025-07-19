# Hetzner Deployment Guide for Orchestrator

This guide walks you through the steps to stand up your control-plane “orchestrator” node on the Hetzner Cloud using the provided `orchestrator-cloud-init.yaml`. All tooling is zero-touch once the server is created.

## Prerequisites

- A [Hetzner Cloud](https://console.hetzner.cloud) account with:
  - At least one project created
  - An API token with **read/write** scope
- `hcloud` CLI installed and authenticated  
  ```bash
  curl -O https://github.com/hetznercloud/cli/releases/latest/download/hcloud-linux-amd64.tar.gz
  tar -xzf hcloud-linux-amd64.tar.gz
  sudo mv hcloud /usr/local/bin/
  hcloud context create my-project --token YOUR_HCLOUD_TOKEN
  ```
- Your public SSH key already imported into Hetzner (via the UI or `hcloud ssh-key add`)

## 1. Configure Firewall

We recommend locking down everything except:
- TCP 22 (SSH) – optional, for break-glass
- TCP 80/443 (Caddy reverse proxy + Cockpit)
- UDP 51820 (WireGuard head-end)

```bash
hcloud firewall create \
  --name orchestrator-fw \
  --rule 'in:tcp:22:0.0.0.0/0' \
  --rule 'in:tcp:80,443:0.0.0.0/0' \
  --rule 'in:udp:51820:0.0.0.0/0'
```

> Note: You can tighten SSH to your office IP, or disable it completely once VPN is in place.

## 2. (Optional) Create a Private Network

If you plan multiple control-plane replicas or want an L2 segment for containers:

```bash
hcloud network create \
  --name orchestrator-net \
  --ip-range 10.99.0.0/16 \
  --subnet 10.99.0.0/16 \
  --network-zone eu-central
```

## 3. Prepare Your Cloud-Init File

Save the orchestrator user-data snippet you have as `orchestrator-cloud-init.yaml` alongside any credential placeholders:

```bash
cat > orchestrator-cloud-init.yaml <<EOF
#cloud-config
...  # (copy in your full YAML from previous steps)
EOF
```

Ensure you’ve replaced `${DOMAIN}`, `${HEADSCALE_DB_PASS}`, `${AUTHENTIK_DB_PASS}`, and `${AUTHENTIK_SECRET}` with real values (or supply them via a secure template tool).

## 4. Create the Orchestrator Server

Use `hcloud server create` to provision:

```bash
hcloud server create \
  --name orchestrator-1 \
  --type cx41 \
  --image ubuntu-24.04 \
  --ssh-key MyPublicKey \
  --user-data-from-file=orchestrator-cloud-init.yaml \
  --firewall orchestrator-fw \
  --network orchestrator-net \
  --datacenter nbg1
```

Adjust:
- `--type` to the flavor you need (CPU/RAM)
- `--datacenter` to your preferred region (e.g. `fsn1`, `nbg1`, `ash`)
- `--network` omitting if you’re not using a private network

## 5. (Optional) Attach Persistent Volumes

If you need extra storage for PostgreSQL, Loki, VictoriaMetrics, etc.:

```bash
hcloud volume create \
  --name orchestrator-data \
  --size 200GB \
  --format ext4 \
  --server orchestrator-1 \
  --automount yes
```

Volumes will appear under `/mnt/volume_...` – adjust your `/etc/containers/systemd/*.container` volume mappings as needed.

## 6. Verify Deployment

1. Watch the server’s console via the Hetzner UI until cloud-init finishes.
2. From your local shell, confirm the orchestrator is reachable:
   ```bash
   curl -k https://orchestrator.your.domain/healthz
   ```
3. Log in to Cockpit (over HTTPS + OIDC) at:
   ```
   https://orchestrator.your.domain/
   ```
4. Validate that:
   - Headscale UI is up (`https://orchestrator.your.domain:8080`)
   - Authentik is reachable (`https://orchestrator.your.domain/auth/`)
   - Metrics endpoints respond:
     ```bash
     curl http://orchestrator.your.domain:8428/metrics
     curl http://orchestrator.your.domain:3100/ready
     ```
5. Check WireGuard listening:
   ```bash
   sudo wg show
   ```

## 7. Next Steps

- Use Headscale to register and tag your game nodes.
- Spin up your client nodes with the matching `client-cloud-init.yaml`.
- Confirm mesh connectivity: `ping 100.64.x.x` between orchestrator and clients.
- Begin provisioning Wings containers and managing them via Cockpit.

---

You now have a fully-automated, FOSS-only control plane running on Hetzner Cloud with zero manual post-provisioning.