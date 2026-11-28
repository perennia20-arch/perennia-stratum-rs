#!/usr/bin/env bash
set -euo pipefail

# Perennia v1.0 Core Hub Provisioner (Ubuntu 24.04 LTS Bare Metal)
# Usage: sudo DOMAIN=perennia.io ./provision-core-hub.sh

DOMAIN="${DOMAIN:-perennia.io}"
PERENNIA_USER="${PERENNIA_USER:-perennia}"
APP_ROOT="${APP_ROOT:-/home/${PERENNIA_USER}}"
ENV_FILE="${ENV_FILE:-/etc/perennia/.env}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  curl ca-certificates gnupg lsb-release ufw fail2ban wireguard \
  postgresql-16 redis-server jq build-essential pkg-config libssl-dev

# 1. Kernel TCP BBR + High-Concurrency Descriptor Tuning
cat >/etc/sysctl.d/99-perennia-core.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 2097152
vm.overcommit_memory = 1
EOF
sysctl --system >/dev/null

# 2. UFW Firewall & Fail2ban Hardening
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP Acme'
ufw allow 443/tcp comment 'HTTPS TLS 1.3'
ufw allow 443/udp comment 'HTTP/3 QUIC'
ufw allow 6551/tcp comment 'Stratum GPU'
ufw allow 6552/tcp comment 'Stratum Home ASIC'
ufw allow 6553/tcp comment 'Stratum Whale ASIC'
ufw allow 51820/udp comment 'WireGuard Mesh'
ufw --force enable

cat >/etc/fail2ban/jail.d/perennia.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 3600
EOF
systemctl enable --now fail2ban

# 3. Caddy TLS 1.3 + HTTP/3 Reverse Proxy
if ! command -v caddy >/dev/null 2>&1; then
  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi

cat >/etc/caddy/Caddyfile <<EOF
${DOMAIN}, www.${DOMAIN} {
    encode zstd gzip
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }
    handle /api/v1/agent* {
        reverse_proxy 127.0.0.1:8003
    }
    reverse_proxy 127.0.0.1:3000
}
EOF
systemctl enable --now caddy

# 4. PostgreSQL 16 + Redis 7 Service Enablement
systemctl enable --now postgresql redis-server

# 5. Hardened Systemd Units
mkdir -p /etc/perennia
chmod 750 /etc/perennia

cat >/etc/systemd/system/kaspad.service <<EOF
[Unit]
Description=Rusty-Kaspa Full Node (--utxoindex)
After=network-online.target
Wants=network-online.target

[Service]
User=${PERENNIA_USER}
Group=${PERENNIA_USER}
ExecStart=/usr/local/bin/kaspad --utxoindex --rpclisten=127.0.0.1:16110
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${APP_ROOT}/.rusty-kaspa
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/perennia-stratum.service <<EOF
[Unit]
Description=Perennia Sovereign Stratum & L1 Settlement Engine
After=network-online.target postgresql.service redis-server.service kaspad.service
Requires=postgresql.service redis-server.service

[Service]
User=${PERENNIA_USER}
Group=${PERENNIA_USER}
WorkingDirectory=${APP_ROOT}/perennia-v5-backend
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_ROOT}/perennia-v5-backend/target/release/perennia-stratum-rs
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${APP_ROOT}/perennia-v5-backend
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/perennia-solver.service <<EOF
[Unit]
Description=Perennia Non-Custodial Dark Pool & Arbitrage Solver
After=network-online.target perennia-stratum.service
Requires=postgresql.service redis-server.service

[Service]
User=${PERENNIA_USER}
Group=${PERENNIA_USER}
WorkingDirectory=${APP_ROOT}/perennia-solver-rs
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_ROOT}/perennia-solver-rs/target/release/perennia-solver-rs
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/perennia-web.service <<EOF
[Unit]
Description=Perennia Sovereign SvelteKit Web Server
After=network-online.target perennia-stratum.service

[Service]
User=${PERENNIA_USER}
Group=${PERENNIA_USER}
WorkingDirectory=${APP_ROOT}/perennia-frontend
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/node ${APP_ROOT}/perennia-frontend/build/index.js
Restart=always
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ Perennia Core Hub provisioned (domain=${DOMAIN}). Review ${ENV_FILE} and start services."
