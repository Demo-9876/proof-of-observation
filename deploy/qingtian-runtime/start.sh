#!/bin/sh
set -eu

LOG_DIR=/tmp/qproxy
START_LOG="$LOG_DIR/startup.log"

log() {
  printf '%s\n' "$*" >> "$START_LOG" 2>/dev/null || true
  if [ -w /dev/console ]; then
    printf '%s\n' "$*" > /dev/console 2>/dev/null || true
  fi
}

if [ "${POO_QPROXY_ENABLED:-0}" = "1" ] || [ "${POO_QPROXY_ENABLED:-}" = "true" ]; then
  mkdir -p "$LOG_DIR"
  ip link set lo up 2>/dev/null || true
  log "[qproxy] starting supervisor: parent-cid=${POO_QPROXY_PARENT_CID:-3}, config=${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}"
  if [ "${POO_QPROXY_PRINT_CONFIG:-1}" = "1" ] && [ -r "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}" ]; then
    while IFS= read -r line; do
      log "[qproxy-config] $line"
    done < "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}"
  fi
  (
    while true; do
      RUST_LOG="${QPROXY_LOG:-info}" qproxy enclave \
        --parent-cid "${POO_QPROXY_PARENT_CID:-3}" \
        --config "${POO_QPROXY_CONFIG:-/etc/qproxy/config.toml}" \
        >> "$LOG_DIR/qproxy-enclave.log" 2>&1
      status=$?
      log "[qproxy] enclave exited with status ${status}; retrying in ${POO_QPROXY_RETRY_DELAY_SECONDS:-2}s"
      sleep "${POO_QPROXY_RETRY_DELAY_SECONDS:-2}"
    done
  ) &
else
  mkdir -p "$LOG_DIR"
fi

exec /attest >> "$LOG_DIR/attest.log" 2>&1
