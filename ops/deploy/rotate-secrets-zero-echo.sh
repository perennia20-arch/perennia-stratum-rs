#!/usr/bin/env bash
set -euo pipefail

# Zero-Echo Production Secret Rotation Script
# Generates 32-byte CSPRNG secrets directly into target .env with mode 0600 and ZERO secret stdout output.
# Usage: ./rotate-secrets-zero-echo.sh /path/to/.env

ENV_TARGET="${1:-/etc/perennia/.env}"
umask 077

if [[ ! -f "${ENV_TARGET}" ]]; then
  echo "Target env file not found: ${ENV_TARGET}" >&2
  exit 1
fi

TMP_FILE="$(mktemp "${ENV_TARGET}.tmp.XXXXXX")"
trap 'rm -f "${TMP_FILE}"' EXIT

cp -p "${ENV_TARGET}" "${TMP_FILE}"
chmod 600 "${TMP_FILE}"

rotate_key() {
  local key="$1"
  local new_val
  new_val="$(openssl rand -hex 32)"
  if grep -q "^${key}=" "${TMP_FILE}"; then
    awk -v k="${key}" -v v="${new_val}" 'BEGIN{FS=OFS="="} $1==k{$0=k"="v} {print}' "${TMP_FILE}" > "${TMP_FILE}.next"
    mv -f "${TMP_FILE}.next" "${TMP_FILE}"
  else
    printf '%s=%s\n' "${key}" "${new_val}" >> "${TMP_FILE}"
  fi
  chmod 600 "${TMP_FILE}"
}

for KEY_NAME in \
  INTERNAL_ADMIN_TOKEN \
  PERENNIA_ADMIN_KEY \
  AGENT_INTERNAL_SERVICE_SECRET \
  AGENT_MACAROON_SECRET \
  LEDGER_HMAC_SECRET \
  KYC_MASTER_KEY; do
  rotate_key "${KEY_NAME}"
done

NEW_PG_PASS="$(openssl rand -hex 24)"
if grep -q '^POSTGRES_PASSWORD=' "${TMP_FILE}"; then
  awk -v v="${NEW_PG_PASS}" 'BEGIN{FS=OFS="="} $1=="POSTGRES_PASSWORD"{$0="POSTGRES_PASSWORD="v} {print}' "${TMP_FILE}" > "${TMP_FILE}.next"
  mv -f "${TMP_FILE}.next" "${TMP_FILE}"
fi

mv -f "${TMP_FILE}" "${ENV_TARGET}"
chmod 600 "${ENV_TARGET}"
trap - EXIT

echo "✅ Rotated 6 protocol secrets + POSTGRES_PASSWORD cleanly in ${ENV_TARGET} (0600, zero stdout echo)."
echo "⚠️  Remember to update ALTER USER password & DATABASE_URL if Postgres credentials changed."
