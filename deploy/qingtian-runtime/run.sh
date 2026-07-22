#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ENV_FILE="${1:-$SCRIPT_DIR/qingtian.env}"
if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a
  source "$ENV_FILE"
  set +a
fi

: "${QINGTIAN_IMAGE:=proof-observation-qingtian:dev}"
: "${QINGTIAN_EIF:=proof-observation-qingtian.signed.eif}"
: "${QINGTIAN_CID:=4}"
: "${QINGTIAN_CPUS:=2}"
: "${QINGTIAN_MEM:=1024}"
: "${QINGTIAN_PARENT_CIDS:=3}"
: "${QINGTIAN_EGRESS_MODE:=qproxy}"
: "${QINGTIAN_QPROXY_ENABLED:=1}"
: "${QINGTIAN_QPROXY_PARENT_CID:=${QINGTIAN_PARENT_CIDS%%,*}}"
: "${QINGTIAN_QPROXY_EGRESS_PORTS:=8444,8445}"
: "${QINGTIAN_UPSTREAM_PROXY_URL:=}"
: "${QINGTIAN_FORWARD_PROXY_PROTOCOL:=}"
: "${QTSM_SDK_DIR:=third_party/qingtian-sdk}"
: "${APT_MIRROR:=}"
: "${CARGO_REGISTRY_MIRROR:=}"
: "${QINGTIAN_PRIVATE_KEY:=private-key.pem}"
: "${QINGTIAN_SIGNING_CERTIFICATE:=server.pem}"
: "${QINGTIAN_START_EXTRA_ARGS:=}"

cd "$REPO_ROOT"

: "${QINGTIAN_QT_DOCKER_CONFIG:=$REPO_ROOT/.tmp/qingtian-qt-docker-config}"
mkdir -p "$QINGTIAN_QT_DOCKER_CONFIG"
if [ ! -f "$QINGTIAN_QT_DOCKER_CONFIG/config.json" ]; then
  printf '{"auths":{}}\n' > "$QINGTIAN_QT_DOCKER_CONFIG/config.json"
fi

qt_cmd() {
  DOCKER_CONFIG="$QINGTIAN_QT_DOCKER_CONFIG" qt "$@"
}

if [ ! -f "$QTSM_SDK_DIR/enclave/qtsm/lib/Makefile" ]; then
  echo "missing QTSM SDK at $QTSM_SDK_DIR/enclave/qtsm/lib/Makefile" >&2
  echo "clone or copy Huawei QingTian SDK, then set QTSM_SDK_DIR in $ENV_FILE" >&2
  exit 2
fi
if [ ! -d "$QTSM_SDK_DIR/qingtian-tools/qproxy" ] || [ ! -d "$QTSM_SDK_DIR/enclave/qtsm-sdk-rs" ] || [ ! -d "$QTSM_SDK_DIR/enclave/qtsm-sdk-sys" ]; then
  echo "missing qproxy or Rust QTSM SDK crates under $QTSM_SDK_DIR" >&2
  echo "required: qingtian-tools/qproxy, enclave/qtsm-sdk-rs, enclave/qtsm-sdk-sys" >&2
  exit 2
fi

docker build --no-cache \
  --build-arg "QTSM_SDK_DIR=$QTSM_SDK_DIR" \
  --build-arg "APT_MIRROR=$APT_MIRROR" \
  --build-arg "CARGO_REGISTRY_MIRROR=$CARGO_REGISTRY_MIRROR" \
  --build-arg "POO_PARENT_CIDS=$QINGTIAN_PARENT_CIDS" \
  --build-arg "POO_EGRESS_MODE=$QINGTIAN_EGRESS_MODE" \
  --build-arg "POO_QPROXY_ENABLED=$QINGTIAN_QPROXY_ENABLED" \
  --build-arg "POO_QPROXY_PARENT_CID=$QINGTIAN_QPROXY_PARENT_CID" \
  --build-arg "POO_QPROXY_EGRESS_PORTS=$QINGTIAN_QPROXY_EGRESS_PORTS" \
  --build-arg "POO_UPSTREAM_PROXY_URL=$QINGTIAN_UPSTREAM_PROXY_URL" \
  --build-arg "POO_FORWARD_PROXY_PROTOCOL=$QINGTIAN_FORWARD_PROXY_PROTOCOL" \
  -f deploy/qingtian-runtime/Dockerfile \
  -t "$QINGTIAN_IMAGE" .

make_img_args=(
  enclave make-img
  --docker-uri "$QINGTIAN_IMAGE"
  --eif "$QINGTIAN_EIF"
)

if [ -n "${QINGTIAN_PRIVATE_KEY:-}" ] || [ -n "${QINGTIAN_SIGNING_CERTIFICATE:-}" ]; then
  if [ ! -f "$QINGTIAN_PRIVATE_KEY" ] || [ ! -f "$QINGTIAN_SIGNING_CERTIFICATE" ]; then
    echo "signing material not found: $QINGTIAN_PRIVATE_KEY / $QINGTIAN_SIGNING_CERTIFICATE" >&2
    echo "set both paths, or set both variables to empty for an unsigned smoke EIF" >&2
    exit 2
  fi
  make_img_args+=(--private-key "$QINGTIAN_PRIVATE_KEY" --signing-certificate "$QINGTIAN_SIGNING_CERTIFICATE")
fi

qt_cmd "${make_img_args[@]}"
qt_cmd enclave query-eif --eif "$QINGTIAN_EIF"

start_args=(
  enclave start
  --mem "$QINGTIAN_MEM"
  --cpus "$QINGTIAN_CPUS"
  --eif "$QINGTIAN_EIF"
  --cid "$QINGTIAN_CID"
)

if [ -n "$QINGTIAN_START_EXTRA_ARGS" ]; then
  # Intentionally split operator-provided CLI flags from qingtian.env.
  # shellcheck disable=SC2206
  extra_args=($QINGTIAN_START_EXTRA_ARGS)
  start_args+=("${extra_args[@]}")
fi

qt_cmd "${start_args[@]}"
qt_cmd enclave query
