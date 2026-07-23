# QingTian 代理版 Enclave E2E Runbook

本文档专门用于在真实 Huawei QingTian Enclave 父 VM 上验证：

```text
new-api
  -> QingTian Enclave /attest
  -> qproxy enclave
  -> qproxy host
  -> 父 VM 正向代理（HTTP CONNECT 或 SOCKS5）
  -> 模型 HTTPS 上游
```

验证目标：

- Enclave 通过正向代理访问模型上游。
- Enclave 内仍然自己对真实模型域名建立 TLS 并校验证书。
- 返回响应包含 `profile=qingtian` proof。
- Node verifier 的 response-only 和 full bundle 验证都通过。

本文以百炼 `dashscope.aliyuncs.com` 为主，OpenAI `api.openai.com` 可用同样方式追加。

## 0. 约定

```bash
export PROOF_REPO="$HOME/proof-of-observation"
export DEPLOY_DIR="$HOME/new-api-qingtian-proof"

export ENCLAVE_CID=4
export ENCLAVE_PORT=5005

export UPSTREAM_HOST=dashscope.aliyuncs.com
export UPSTREAM_TLS_PORT=443

# 代理版 Enclave 只需要一个 egress port。该端口同时用于：
# 1. Enclave 内 /attest 连接 qproxy enclave
# 2. qproxy host 连接父 VM 本地正向代理
export PROXY_PORT=18080

export NEW_API_CONTAINER=new-api-proof
export NEW_API_PORT=7070
```

## 1. 拉取代理分支

```bash
cd ~

if [ ! -d proof-of-observation/.git ]; then
  git clone https://github.com/Demo-9876/proof-of-observation.git
fi

cd "$PROOF_REPO"
git fetch origin
git checkout feature/qingtian-enclave-proxy-egress
git pull --ff-only origin feature/qingtian-enclave-proxy-egress
git rev-parse HEAD
```

确认当前分支：

```bash
git branch --show-current
```

期望：

```text
feature/qingtian-enclave-proxy-egress
```

## 2. 准备 QingTian SDK 和签名材料

```bash
cd "$PROOF_REPO"

test -d third_party/qingtian-sdk || mkdir -p third_party

if [ ! -d third_party/qingtian-sdk/.git ]; then
  git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git third_party/qingtian-sdk
fi

test -f third_party/qingtian-sdk/enclave/qtsm/lib/Makefile
test -d third_party/qingtian-sdk/qingtian-tools/qproxy
test -d third_party/qingtian-sdk/enclave/qtsm-sdk-rs
test -d third_party/qingtian-sdk/enclave/qtsm-sdk-sys

test -f private-key.pem
test -f server.pem

openssl x509 -in server.pem -pubkey -noout > /tmp/qingtian-cert.pub
openssl pkey -in private-key.pem -pubout > /tmp/qingtian-key.pub
diff /tmp/qingtian-cert.pub /tmp/qingtian-key.pub
```

`diff` 没有输出才继续。

## 3. 清理旧 Enclave 和旧转发进程

```bash
qt enclave query || true
qt enclave stop --enclave-id 0 2>/dev/null || true

pgrep -af 'qingtian-forward-proxy|qproxy hos[t]|qingtian-proof-egres[s]|socat|18080|8444|8445' || true

pgrep -f 'qingtian-forward-prox[y]' | xargs -r kill 2>/dev/null || true
pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
pgrep -f 'qingtian-proof-egres[s]' | xargs -r kill 2>/dev/null || true
```

## 4. 启动父 VM 正向代理

先写一个只用于验证的轻量代理脚本。它会打印每次 CONNECT 目标，便于确认确实走了代理。

```bash
cat > /tmp/qingtian-forward-proxy.py <<'PY'
#!/usr/bin/env python3
import argparse
import socket
import struct
import threading


def relay(a, b):
    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def handle_http(conn):
    with conn:
        f = conn.makefile("rb")
        line = f.readline(65536).rstrip(b"\r\n").decode("ascii", "replace")
        parts = line.split()
        if len(parts) < 3 or parts[0].upper() != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        target = parts[1]
        host, port = target.rsplit(":", 1)
        port = int(port)
        while True:
            hdr = f.readline(65536)
            if hdr in (b"\r\n", b"\n", b""):
                break
        print(f"HTTP CONNECT {host}:{port}", flush=True)
        upstream = socket.create_connection((host, port), timeout=30)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: qingtian-test\r\n\r\n")
        relay(conn, upstream)


def handle_socks5(conn):
    with conn:
        head = conn.recv(2)
        if len(head) != 2 or head[0] != 5:
            raise ConnectionError("bad socks5 greeting")
        methods = conn.recv(head[1])
        if 0 not in methods:
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x00")

        req = conn.recv(4)
        if len(req) != 4 or req[0] != 5 or req[1] != 1:
            raise ConnectionError("bad socks5 request")
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            host = conn.recv(ln).decode("utf-8")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            raise ConnectionError(f"unsupported atyp {atyp}")
        port = struct.unpack("!H", conn.recv(2))[0]
        print(f"SOCKS5 CONNECT {host}:{port}", flush=True)
        upstream = socket.create_connection((host, port), timeout=30)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        relay(conn, upstream)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["http-connect", "socks5"], required=True)
    ap.add_argument("--listen", default="127.0.0.1:18080")
    args = ap.parse_args()

    host, port = args.listen.rsplit(":", 1)
    port = int(port)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(128)
    print(f"listening {args.mode} on {host}:{port}", flush=True)
    while True:
        conn, _ = s.accept()
        handler = handle_http if args.mode == "http-connect" else handle_socks5
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
PY
chmod +x /tmp/qingtian-forward-proxy.py
```

### 4.1 HTTP CONNECT 模式

先跑 HTTP CONNECT。后面如果要换 SOCKS5，再执行 4.2。

```bash
export PROXY_SCHEME=http
export PROXY_MODE=http-connect
export PROXY_LOG=/tmp/qingtian-forward-proxy-http.log

nohup /tmp/qingtian-forward-proxy.py \
  --mode "$PROXY_MODE" \
  --listen "127.0.0.1:${PROXY_PORT}" \
  > "$PROXY_LOG" 2>&1 &
echo $! > /tmp/qingtian-forward-proxy.pid

sleep 1
ss -ltnp | grep "127.0.0.1:${PROXY_PORT}"
tail -n 20 "$PROXY_LOG"
```

### 4.2 SOCKS5 模式

如果要测 SOCKS5，先停 HTTP CONNECT 代理，再启动 SOCKS5：

```bash
kill "$(cat /tmp/qingtian-forward-proxy.pid)" 2>/dev/null || true

export PROXY_SCHEME=socks5
export PROXY_MODE=socks5
export PROXY_LOG=/tmp/qingtian-forward-proxy-socks5.log

nohup /tmp/qingtian-forward-proxy.py \
  --mode "$PROXY_MODE" \
  --listen "127.0.0.1:${PROXY_PORT}" \
  > "$PROXY_LOG" 2>&1 &
echo $! > /tmp/qingtian-forward-proxy.pid

sleep 1
ss -ltnp | grep "127.0.0.1:${PROXY_PORT}"
tail -n 20 "$PROXY_LOG"
```

## 5. 构建并启动代理版 signed EIF

```bash
cd "$PROOF_REPO"

cat > deploy/qingtian-runtime/qingtian-proxy.env <<EOF
QINGTIAN_IMAGE=proof-observation-qingtian:proxy-${PROXY_MODE}
QINGTIAN_EIF=proof-observation-qingtian.proxy-${PROXY_MODE}.signed.eif
QINGTIAN_CID=${ENCLAVE_CID}
QINGTIAN_CPUS=2
QINGTIAN_MEM=4096
QINGTIAN_PARENT_CIDS=3
QINGTIAN_EGRESS_MODE=qproxy
QINGTIAN_QPROXY_ENABLED=1
QINGTIAN_QPROXY_PARENT_CID=3
QINGTIAN_QPROXY_EGRESS_PORTS=${PROXY_PORT}
QINGTIAN_UPSTREAM_PROXY_URL=${PROXY_SCHEME}://127.0.0.1:${PROXY_PORT}
QTSM_SDK_DIR=third_party/qingtian-sdk
APT_MIRROR=http://repo.huaweicloud.com/debian
CARGO_REGISTRY_MIRROR=sparse+https://rsproxy.cn/index/
QINGTIAN_PRIVATE_KEY=private-key.pem
QINGTIAN_SIGNING_CERTIFICATE=server.pem
QINGTIAN_QT_DOCKER_CONFIG=
QINGTIAN_START_EXTRA_ARGS=
EOF

qt enclave stop --enclave-id 0 2>/dev/null || true

bash deploy/qingtian-runtime/run.sh deploy/qingtian-runtime/qingtian-proxy.env \
  | tee qingtian-proxy-build-start.log

qt enclave query | tee qingtian-proxy-query.log
qt enclave query-eif --eif "proof-observation-qingtian.proxy-${PROXY_MODE}.signed.eif" \
  | tee qingtian-proxy-query-eif.log
```

确认：

```bash
grep -E '"Status":.*"Running"' qingtian-proxy-query.log
grep -E '"PCR0"|"PCR8"' qingtian-proxy-query-eif.log
```

记录 PCR：

```bash
export QINGTIAN_PCR0="$(python3 -c 'import json; print(json.load(open("qingtian-proxy-query-eif.log"))["PCR0"])')"
export QINGTIAN_PCR8="$(python3 -c 'import json; print(json.load(open("qingtian-proxy-query-eif.log"))["PCR8"])')"
echo "$QINGTIAN_PCR0"
echo "$QINGTIAN_PCR8"
```

## 6. 启动 qproxy host

代理版链路不需要原来的 `8444 -> dashscope.aliyuncs.com:443` parent-local mapper。qproxy host 只需要把 enclave 的 `vsock_port=${PROXY_PORT}` 转到父 VM 本地代理 `127.0.0.1:${PROXY_PORT}`。

如果父 VM 上还没有 `qproxy` 命令，直接从上一步构建好的 QingTian runtime 镜像里提取：

```bash
mkdir -p "$HOME/.local/bin"
export PATH="$HOME/.local/bin:$PATH"

if ! command -v qproxy >/dev/null 2>&1; then
  docker rm -f qproxy-extract 2>/dev/null || true
  docker create --name qproxy-extract "proof-observation-qingtian:proxy-${PROXY_MODE}"
  docker cp qproxy-extract:/usr/local/bin/qproxy "$HOME/.local/bin/qproxy"
  docker rm -f qproxy-extract
  chmod +x "$HOME/.local/bin/qproxy"
fi

qproxy --help | head
```

```bash
mkdir -p "$DEPLOY_DIR/qproxy"
cd "$DEPLOY_DIR/qproxy"

cat > config_qproxy_proxy.toml <<EOF
[[outbound_connections]]
hostname = "127.0.0.1"
vsock_port = ${PROXY_PORT}
tcp_port = ${PROXY_PORT}

[log_location]
host_log = "host.log"
enclave_log = "enclave.log"
log_level = "info"
host_log_dir = "/var/log/qproxy"
enclave_log_dir = "/var/log/qproxy"
EOF

sudo mkdir -p /var/log/qproxy
sudo chown -R "$USER:$USER" /var/log/qproxy

qproxy check-config ./config_qproxy_proxy.toml

pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
nohup qproxy host --config=./config_qproxy_proxy.toml "$ENCLAVE_CID" \
  > "$DEPLOY_DIR/qproxy/qproxy-host-proxy.out" 2>&1 &

sleep 2
pgrep -af 'qproxy hos[t]'
tail -n 80 "$DEPLOY_DIR/qproxy/qproxy-host-proxy.out"
tail -n 80 /var/log/qproxy/host.log 2>/dev/null || true
```

## 7. 配置 new-api 指向代理版 Enclave

new-api 仍然只需要配置真实上游 host 到 egress port 的映射。这里把百炼和 OpenAI 都映射到同一个代理端口：

```text
dashscope.aliyuncs.com:18080
api.openai.com:18080
```

### 7.1 确认 new-api 镜像

如果已经有 `new-api-proof` 容器，优先复用它当前使用的镜像：

```bash
export NEW_API_IMAGE="$(docker inspect "$NEW_API_CONTAINER" --format '{{.Config.Image}}' 2>/dev/null || true)"
```

如果上面没有输出，手动指定你已经拉取或构建好的 new-api 镜像：

```bash
export NEW_API_IMAGE="shihuo-acr-registry.cn-hangzhou.cr.aliyuncs.com/shihuo-base/ai-platform-newapi:aliyun-enclave-20260717"
```

确认镜像存在：

```bash
docker image inspect "$NEW_API_IMAGE" --format '{{.Id}} {{.RepoTags}}'
```

### 7.2 准备 new-api 基础配置

如果你前面已经按普通 QingTian qproxy 流程生成过 `$DEPLOY_DIR/qingtian-proof.env`，可以复用其中的数据库、Redis、Session 配置：

```bash
test -f "$DEPLOY_DIR/qingtian-proof.env"
```

如果没有这个文件，先交互式写入最小必需配置：

```bash
mkdir -p "$DEPLOY_DIR/data" "$DEPLOY_DIR/logs"
cd "$DEPLOY_DIR"

read -r -p "SQL_DSN: " SQL_DSN
read -r -s -p "REDIS_CONN_STRING: " REDIS_CONN_STRING
printf '\n'
SESSION_SECRET="$(openssl rand -base64 48)"
```

### 7.3 生成代理版 new-api env 文件

优先从已有 `qingtian-proof.env` 复制一份，然后覆盖 `TEE_PROOF_*`；如果没有旧 env，则生成完整 env：

```bash
mkdir -p "$DEPLOY_DIR/data" "$DEPLOY_DIR/logs"
cd "$DEPLOY_DIR"

if [ -f "$DEPLOY_DIR/qingtian-proof.env" ]; then
  cp "$DEPLOY_DIR/qingtian-proof.env" "$DEPLOY_DIR/qingtian-proxy-newapi.env"
else
  cat > "$DEPLOY_DIR/qingtian-proxy-newapi.env" <<EOF
READ_CONFIG=false
TZ=Asia/Shanghai
NODE_NAME=new-api-qingtian-proxy-01
PORT=${NEW_API_PORT}
SESSION_SECRET=${SESSION_SECRET}
SQL_DSN=${SQL_DSN}
REDIS_CONN_STRING=${REDIS_CONN_STRING}
TEE_PROOF_STORE=memory
TEE_PROOF_STORE_TTL_SECONDS=600
TEE_PROOF_STORE_MAX_ITEMS=10000
EOF
fi

python3 - "$DEPLOY_DIR/qingtian-proxy-newapi.env" <<PY
from pathlib import Path
import sys

path = Path(sys.argv[1])
updates = {
    "PORT": "${NEW_API_PORT}",
    "TEE_PROOF_ENABLED": "true",
    "TEE_PROOF_REQUIRE": "false",
    "TEE_PROOF_ENCLAVE_CID": "${ENCLAVE_CID}",
    "TEE_PROOF_ENCLAVE_PORT": "${ENCLAVE_PORT}",
    "TEE_PROOF_EXPECTED_PCR0": "${QINGTIAN_PCR0}",
    "TEE_PROOF_ALLOWED_HOSTS": "${UPSTREAM_HOST},api.openai.com",
    "TEE_PROOF_EGRESS_PORTS": "${UPSTREAM_HOST}:${PROXY_PORT},api.openai.com:${PROXY_PORT}",
    "TEE_PROOF_TIMEOUT_SECONDS": "300",
    "TEE_PROOF_MAX_BODY_BYTES": "67108864",
}
lines = path.read_text().splitlines()
seen = set()
out = []
for line in lines:
    if "=" not in line or line.startswith("#"):
        out.append(line)
        continue
    key = line.split("=", 1)[0]
    if key in updates:
        out.append(f"{key}={updates[key]}")
        seen.add(key)
    else:
        out.append(line)
for key, value in updates.items():
    if key not in seen:
        out.append(f"{key}={value}")
path.write_text("\\n".join(out) + "\\n")
PY

chmod 600 "$DEPLOY_DIR/qingtian-proxy-newapi.env"

sed -E \
  -e 's/^(SESSION_SECRET=).*/\1***masked***/' \
  -e 's/^(SQL_DSN=).*/\1***masked***/' \
  -e 's/^(REDIS_CONN_STRING=).*/\1***masked***/' \
  "$DEPLOY_DIR/qingtian-proxy-newapi.env"
```

最终必须包含：

```bash
grep '^TEE_PROOF_' "$DEPLOY_DIR/qingtian-proxy-newapi.env"
```

期望关键值：

```text
TEE_PROOF_ENABLED=true
TEE_PROOF_REQUIRE=false
TEE_PROOF_ENCLAVE_CID=4
TEE_PROOF_ENCLAVE_PORT=5005
TEE_PROOF_ALLOWED_HOSTS=dashscope.aliyuncs.com,api.openai.com
TEE_PROOF_EGRESS_PORTS=dashscope.aliyuncs.com:18080,api.openai.com:18080
```

### 7.4 重启 new-api Docker 容器

new-api 需要创建 `AF_VSOCK` socket 连接 Enclave。验证阶段建议使用 `--network host --privileged`：

```bash
docker rm -f "$NEW_API_CONTAINER" 2>/dev/null || true

docker run -d \
  --name "$NEW_API_CONTAINER" \
  --restart always \
  --network host \
  --privileged \
  --env-file "$DEPLOY_DIR/qingtian-proxy-newapi.env" \
  -v "$DEPLOY_DIR/data:/data" \
  -v "$DEPLOY_DIR/logs:/app/logs" \
  "$NEW_API_IMAGE" \
  --log-dir /app/logs

sleep 3
docker ps --filter "name=$NEW_API_CONTAINER"
docker logs --tail 120 "$NEW_API_CONTAINER"
curl -sS "http://127.0.0.1:${NEW_API_PORT}/health" || true
```

检查容器内实际生效值：

```bash
docker exec "$NEW_API_CONTAINER" env | grep '^TEE_PROOF_'
docker exec "$NEW_API_CONTAINER" env | grep '^PORT='
```

如果容器里不是上述值，说明容器没有使用 `qingtian-proxy-newapi.env` 启动，需要重新执行本节 `docker rm -f` 和 `docker run`。

### 7.5 可选：使用 docker compose 启动

如果你更习惯 Compose，可以生成单独部署文件，不修改 new-api 仓库：

```bash
cat > "$DEPLOY_DIR/docker-compose.qingtian-proxy.yml" <<EOF
version: "3.4"

services:
  new-api-proof:
    image: ${NEW_API_IMAGE}
    container_name: ${NEW_API_CONTAINER}
    restart: always
    network_mode: host
    privileged: true
    command: --log-dir /app/logs
    env_file:
      - ./qingtian-proxy-newapi.env
    volumes:
      - ./data:/data
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O - http://localhost:${NEW_API_PORT}/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

cd "$DEPLOY_DIR"
docker compose -f docker-compose.qingtian-proxy.yml up -d
```

## 8. 发起非流式请求

```bash
cd "$DEPLOY_DIR"

read -r -s -p "NEW_API_TOKEN: " NEW_API_TOKEN
printf '\n'
read -r -p "MODEL: " MODEL

cat > request.proxy.nonstream.json <<EOF
{
  "model": "$MODEL",
  "messages": [{"role": "user", "content": "你好，请用一句话介绍一下你自己。"}],
  "stream": false
}
EOF

curl -sS -D headers.proxy.nonstream.txt \
  "http://127.0.0.1:${NEW_API_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${NEW_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @request.proxy.nonstream.json \
  -o response.proxy.nonstream.multipart

cat headers.proxy.nonstream.txt
grep -a '"profile":"qingtian"' response.proxy.nonstream.multipart
```

确认代理确实收到 CONNECT：

```bash
tail -n 200 "$PROXY_LOG"
grep -a "${UPSTREAM_HOST}:${UPSTREAM_TLS_PORT}" "$PROXY_LOG"
```

## 9. 发起流式请求

```bash
cd "$DEPLOY_DIR"

cat > request.proxy.stream.json <<EOF
{
  "model": "$MODEL",
  "messages": [{"role": "user", "content": "你好，请用一句话介绍一下你自己。"}],
  "stream": true,
  "stream_options": {"include_usage": true}
}
EOF

curl -N -sS -D headers.proxy.stream.txt \
  "http://127.0.0.1:${NEW_API_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${NEW_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @request.proxy.stream.json \
  -o response.proxy.stream.sse

cat headers.proxy.stream.txt
grep -a 'event: tee.proof' response.proxy.stream.sse | tail -n 2
grep -a '"profile":"qingtian"' response.proxy.stream.sse
tail -n 200 "$PROXY_LOG"
```

## 10. 生成 trust config

```bash
cd "$DEPLOY_DIR"

cat > qingtian-proxy-trust.e2e.json <<EOF
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "$QINGTIAN_PCR0",
    "sha384:8": "$QINGTIAN_PCR8"
  },
  "platformTrust": {
    "mode": "cert-chain",
    "trustAnchorId": "huawei-qingtian-prod",
    "rootFingerprintsSha256": [
      "F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581"
    ],
    "revocation": {
      "required": false,
      "method": "crl-or-ocsp",
      "checkedExternally": false
    }
  }
}
EOF
```

## 11. verifier 验证

```bash
cd "$PROOF_REPO/verifier"
npm ci

npx tsx tee-verify-stream.ts \
  "$DEPLOY_DIR/response.proxy.nonstream.multipart" \
  --trust "$DEPLOY_DIR/qingtian-proxy-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify.proxy.nonstream.response-only.log"

npx tsx tee-verify-stream.ts \
  "$DEPLOY_DIR/response.proxy.stream.sse" \
  --trust "$DEPLOY_DIR/qingtian-proxy-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify.proxy.stream.response-only.log"

npx tsx make-real-bundle.ts \
  "$DEPLOY_DIR/request.proxy.nonstream.json" \
  "$DEPLOY_DIR/response.proxy.nonstream.multipart" \
  "$DEPLOY_DIR/bundle.proxy.nonstream.full.json"

npx tsx verify-real-bundle.ts \
  "$DEPLOY_DIR/bundle.proxy.nonstream.full.json" \
  --trust "$DEPLOY_DIR/qingtian-proxy-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify.proxy.nonstream.full.log"

npx tsx make-real-bundle.ts \
  "$DEPLOY_DIR/request.proxy.stream.json" \
  "$DEPLOY_DIR/response.proxy.stream.sse" \
  "$DEPLOY_DIR/bundle.proxy.stream.full.json"

npx tsx verify-real-bundle.ts \
  "$DEPLOY_DIR/bundle.proxy.stream.full.json" \
  --trust "$DEPLOY_DIR/qingtian-proxy-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify.proxy.stream.full.log"
```

## 12. 确认真的走了代理

至少同时满足这三项：

```bash
# 1. 代理日志里有 CONNECT 目标
grep -a "${UPSTREAM_HOST}:${UPSTREAM_TLS_PORT}" "$PROXY_LOG"

# 2. 停掉代理后同样请求失败
kill "$(cat /tmp/qingtian-forward-proxy.pid)" 2>/dev/null || true
curl -sS -D headers.proxy.expect-fail.txt \
  "http://127.0.0.1:${NEW_API_PORT}/v1/chat/completions" \
  -H "Authorization: Bearer ${NEW_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @request.proxy.nonstream.json \
  -o response.proxy.expect-fail.txt || true
cat response.proxy.expect-fail.txt

# 3. 重新启动代理后请求和 verifier 又通过
nohup /tmp/qingtian-forward-proxy.py \
  --mode "$PROXY_MODE" \
  --listen "127.0.0.1:${PROXY_PORT}" \
  > "$PROXY_LOG" 2>&1 &
echo $! > /tmp/qingtian-forward-proxy.pid
```

如果停掉代理后请求仍然成功，说明当前请求没有走代理版 EIF，优先检查：

```bash
qt enclave query
qt enclave query-eif --eif "$PROOF_REPO/proof-observation-qingtian.proxy-${PROXY_MODE}.signed.eif"
docker exec "$NEW_API_CONTAINER" env | grep '^TEE_PROOF_'
pgrep -af 'qproxy|qingtian-forward-proxy|socat|18080|8444|8445'
```

## 13. 成功判定

全部满足才认为代理版 Enclave E2E 跑通：

- `qt enclave query` 显示 `Status=Running`。
- `query-eif` 输出非 0 `PCR8`。
- `qproxy host` 正在运行。
- 父 VM 代理监听 `127.0.0.1:18080`。
- 代理日志出现 `HTTP CONNECT dashscope.aliyuncs.com:443` 或 `SOCKS5 CONNECT dashscope.aliyuncs.com:443`。
- 停掉代理后请求失败。
- 恢复代理后非流式和流式请求都返回 `profile=qingtian` proof。
- `tee-verify-stream.ts` 验证通过。
- `verify-real-bundle.ts` full 验证通过。

当前 proof 证明真实上游 host、响应签名和请求绑定；它不把代理路径写入 signed statement。因此第三方 verifier 目前不能仅凭 proof 判断“必须经过某个代理”。如果需要第三方也验证代理路径，需要把 proxy scheme/host/port 纳入 proof 的签名字段。
