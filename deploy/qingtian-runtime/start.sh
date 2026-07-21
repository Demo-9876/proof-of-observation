#!/bin/sh
set -eu

if [ "${POO_QPROXY_ENABLED:-0}" = "1" ] || [ "${POO_QPROXY_ENABLED:-}" = "true" ]; then
  mkdir -p /tmp/qproxy
  ip link set lo up 2>/dev/null || true
  RUST_LOG="${QPROXY_LOG:-warn}" qproxy enclave \
    --parent-cid "${POO_QPROXY_PARENT_CID:-3}" \
    --config "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}" &
  qproxy_pid=$!
  sleep "${POO_QPROXY_STARTUP_DELAY_SECONDS:-1}"
  if ! kill -0 "$qproxy_pid" 2>/dev/null; then
    wait "$qproxy_pid"
    exit 1
  fi
fi

exec /attest
