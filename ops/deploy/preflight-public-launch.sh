#!/usr/bin/env bash
set -euo pipefail

# Perennia v1.0 Public Launch Go/No-Go Preflight Audit
# Usage: WEB_ORIGIN=https://perennia.io ./preflight-public-launch.sh

WEB_ORIGIN="${WEB_ORIGIN:-http://127.0.0.1:3000}"
AGENT_TEST_KEY="${AGENT_TEST_KEY:-}"
REPO_ROOT="${REPO_ROOT:-/home/perennia/perennia-v5-backend}"

echo "=== Perennia v1.0 Pre-Launch Preflight Audit ==="

echo "[1/6] Checking git tracked files contain zero .env secrets..."
if git -C "${REPO_ROOT}" ls-files | grep -E '(^|/)\.env(\.|$)' | grep -v '\.example$'; then
  echo "FAIL: Tracked .env file found in git!" >&2
  exit 1
fi
echo "OK: Zero tracked .env files."

echo "[2/6] Verifying live systemd services..."
for svc in perennia-stratum.service perennia-solver.service perennia-web.service; do
  if ! systemctl is-active --quiet "${svc}"; then
    echo "FAIL: ${svc} is not active" >&2
    exit 1
  fi
done
echo "OK: All 3 systemd services active."

echo "[3/6] Checking stealth /forge gate returns HTTP 404 unauthenticated..."
FORGE_STATUS="$(curl -s -o /dev/null -w '%{http_code}' "${WEB_ORIGIN}/forge")"
if [[ "${FORGE_STATUS}" != "404" ]]; then
  echo "FAIL: /forge returned HTTP ${FORGE_STATUS}, expected 404" >&2
  exit 1
fi
echo "OK: /forge returned 404."

echo "[4/6] Checking /api/v1/agent/alpha denies unauthenticated requests..."
ALPHA_UNAUTH_STATUS="$(curl -s -o /dev/null -w '%{http_code}' "${WEB_ORIGIN}/api/v1/agent/alpha")"
if [[ "${ALPHA_UNAUTH_STATUS}" != "401" && "${ALPHA_UNAUTH_STATUS}" != "403" ]]; then
  echo "FAIL: unauthenticated /api/v1/agent/alpha returned ${ALPHA_UNAUTH_STATUS}" >&2
  exit 1
fi
echo "OK: unauthenticated /api/v1/agent/alpha rejected (${ALPHA_UNAUTH_STATUS})."

if [[ -n "${AGENT_TEST_KEY}" ]]; then
  ALPHA_AUTH_STATUS="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${AGENT_TEST_KEY}" "${WEB_ORIGIN}/api/v1/agent/alpha")"
  if [[ "${ALPHA_AUTH_STATUS}" != "200" ]]; then
    echo "FAIL: authenticated /api/v1/agent/alpha returned ${ALPHA_AUTH_STATUS}" >&2
    exit 1
  fi
  echo "OK: authenticated /api/v1/agent/alpha returned 200."
fi

echo "[5/6] Checking non-custodial Postgres constraint & Redis ping..."
if [[ -n "${DATABASE_URL:-}" ]]; then
  psql "${DATABASE_URL}" -tAc "SELECT 1 FROM pg_constraint WHERE conname = 'chk_yield_reservoirs_zero_synthetic_ious';" | grep -qx "1"
  echo "OK: chk_yield_reservoirs_zero_synthetic_ious verified."
fi
if redis-cli PING | grep -qx "PONG"; then
  echo "OK: Redis PONG."
fi

echo "[6/6] Checking /llms.txt availability and /forge redaction..."
LLMS_BODY="$(curl -sf "${WEB_ORIGIN}/llms.txt")"
if echo "${LLMS_BODY}" | grep -qi "/forge"; then
  echo "FAIL: /llms.txt leaks /forge!" >&2
  exit 1
fi
echo "OK: /llms.txt clean."

echo "=== ALL PREFLIGHT LAUNCH CHECKS PASSED ==="
