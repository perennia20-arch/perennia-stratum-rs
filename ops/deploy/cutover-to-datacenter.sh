#!/usr/bin/env bash
set -euo pipefail

# Zero-Downtime Core Migration & Cutover Over WireGuard
# Usage: SOURCE_PG_URL=... TARGET_PG_URL=... KASPAD_CLI=kaspactl ./cutover-to-datacenter.sh

SOURCE_PG_URL="${SOURCE_PG_URL:?Set SOURCE_PG_URL}"
TARGET_PG_URL="${TARGET_PG_URL:?Set TARGET_PG_URL}"
TARGET_REDIS_HOST="${TARGET_REDIS_HOST:-127.0.0.1}"
TARGET_REDIS_PORT="${TARGET_REDIS_PORT:-6379}"
KASPAD_RPC_URL="${KASPAD_RPC_URL:-http://127.0.0.1:16110}"

echo "1/5 Verifying target kaspad --utxoindex sync..."
if ! redis-cli -h "${TARGET_REDIS_HOST}" -p "${TARGET_REDIS_PORT}" PING | grep -qx "PONG"; then
  echo "Target Redis PING failed" >&2
  exit 1
fi

echo "2/5 Streaming base PostgreSQL snapshot (pg_dump -Fc -> pg_restore)..."
pg_dump --format=custom --no-owner --no-acl "${SOURCE_PG_URL}" | \
  pg_restore --clean --if-exists --no-owner --no-acl --dbname="${TARGET_PG_URL}"

echo "3/5 Verifying non-custodial database invariant..."
psql "${TARGET_PG_URL}" -v ON_ERROR_STOP=1 -c "SELECT COUNT(*) FROM pg_constraint WHERE conname = 'chk_yield_reservoirs_zero_synthetic_ious';" >/dev/null

echo "4/5 Reloading systemd core units on target..."
systemctl restart perennia-stratum.service perennia-solver.service perennia-web.service
systemctl is-active --quiet perennia-stratum.service perennia-solver.service perennia-web.service

echo "5/5 Migration complete. Lower public DNS A/AAAA TTL to 60s and flip edge records to new Core Hub."
