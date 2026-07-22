#!/bin/sh
set -eu

if [ "${POO_QPROXY_ENABLED:-0}" = "1" ] || [ "${POO_QPROXY_ENABLED:-}" = "true" ]; then
  mkdir -p /tmp/qproxy
  ip link set lo up 2>/dev/null || true
  echo "[qproxy] starting supervisor: parent-cid=${POO_QPROXY_PARENT_CID:-3}, config=${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}"
  if [ "${POO_QPROXY_PRINT_CONFIG:-1}" = "1" ] && [ -r "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}" ]; then
    sed 's/^/[qproxy-config] /' "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}" || true
  fi
  (
    while true; do
      RUST_LOG="${QPROXY_LOG:-info}" qproxy enclave \
        --parent-cid "${POO_QPROXY_PARENT_CID:-3}" \
        --config "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}"
      status=$?
      echo "[qproxy] enclave exited with status ${status}; retrying in ${POO_QPROXY_RETRY_DELAY_SECONDS:-2}s"
      sleep "${POO_QPROXY_RETRY_DELAY_SECONDS:-2}"
    done
  ) &
fi

exec /attest
