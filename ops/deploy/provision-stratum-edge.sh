#!/usr/bin/env bash
set -euo pipefail

# Perennia Regional Stratum TCP Edge Relay (Zero DB / Zero Private Key Footprint)
# Relays TCP Stratum ports 6551 (GPU), 6552 (Home ASIC), 6553 (Whale ASIC) over WireGuard to Core Hub.
# Usage: sudo CORE_HUB_WG_IP=10.77.0.1 ./provision-stratum-edge.sh

CORE_HUB_WG_IP="${CORE_HUB_WG_IP:-10.77.0.1}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends ufw fail2ban wireguard socat

# 1. Low-latency network tuning
cat >/etc/sysctl.d/99-perennia-stratum-edge.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 4
fs.file-max = 1048576
EOF
sysctl --system >/dev/null

# 2. Edge Firewall (Stratum Ports + WireGuard Only)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH Admin'
ufw allow 6551/tcp comment 'Stratum GPU'
ufw allow 6552/tcp comment 'Stratum Home ASIC'
ufw allow 6553/tcp comment 'Stratum Whale ASIC'
ufw allow 51820/udp comment 'WireGuard Core Backhaul'
ufw limit 6551/tcp
ufw limit 6552/tcp
ufw limit 6553/tcp
ufw --force enable

# 3. Hardened socat TCP edge relays per Stratum difficulty tier
for PORT in 6551 6552 6553; do
  cat >/etc/systemd/system/perennia-stratum-edge-${PORT}.service <<EOF
[Unit]
Description=Perennia Regional Stratum Edge Relay (Port ${PORT})
After=network-online.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/bin/socat -T120 TCP-LISTEN:${PORT},reuseaddr,fork,nodelay,keepalive TCP:${CORE_HUB_WG_IP}:${PORT},nodelay,keepalive
Restart=always
RestartSec=1
LimitNOFILE=1048576
DynamicUser=yes
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
done

systemctl daemon-reload
for PORT in 6551 6552 6553; do
  systemctl enable --now "perennia-stratum-edge-${PORT}.service"
done

echo "✅ Regional Stratum Edge Node online -> Core Hub ${CORE_HUB_WG_IP}:{6551,6552,6553}."
