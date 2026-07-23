#!/bin/sh
set -eu

umask 077

: "${TEE_PROFILE:=aliyun-vtpm}"
: "${ALIYUN_PROOF_HELPER_SOCKET:=/run/aliyun-proof-helper.sock}"
export TEE_PROFILE
export ALIYUN_PROOF_HELPER_SOCKET

echo "[info] TEE_PROFILE=$TEE_PROFILE"
echo "[info] helper socket=$ALIYUN_PROOF_HELPER_SOCKET"

mkdir -p /run
rm -f "$ALIYUN_PROOF_HELPER_SOCKET"

/usr/bin/aliyun-proof-helper --socket "$ALIYUN_PROOF_HELPER_SOCKET" &
HELPER_PID=$!

ready=0
for i in $(seq 1 100); do
  if /usr/bin/aliyun-proof-helper --socket "$ALIYUN_PROOF_HELPER_SOCKET" --health-check; then
    ready=1
    break
  fi

  if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    wait "$HELPER_PID" || true
    echo "[error] aliyun-proof-helper exited during startup" >&2
    exit 1
  fi

  sleep 0.1
done

if [ "$ready" != "1" ]; then
  echo "[error] aliyun-proof-helper not ready" >&2
  kill "$HELPER_PID" 2>/dev/null || true
  wait "$HELPER_PID" 2>/dev/null || true
  exit 1
fi

echo "[info] aliyun-proof-helper is ready"
exec /attest
