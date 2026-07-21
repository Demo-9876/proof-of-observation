# QingTian qproxy E2E Runbook

本文档是在真实 Huawei QingTian Enclave 父 VM 上，用 Huawei 官方 qproxy 跑通 `proof-of-observation` 端到端验证的可复现流程。即使上下文丢失，也应能按本文从代码拉取、QingTian 业务镜像构建、signed EIF 启动、qproxy 出网、new-api 接入，到非流式/流式 proof 请求完整复现。

已验证结论：

- QingTian runtime image 可构建成功。
- `qt enclave make-img --private-key --signing-certificate` 可生成 signed EIF。
- `PCR8` 非 0，来自 signing certificate。
- Enclave normal mode 可启动并保持 Running。
- Huawei qproxy 双端链路可用。
- DashScope 上游通过 `8444` 出网可返回模型响应和 `profile=qingtian` proof。
- OpenAI 上游预留 `8445`，生产可同时配置多个上游。

约定：

- 父 VM 用户：`ansible`
- `proof-of-observation` 仓库：`~/proof-of-observation`
- 分支：`feature/qingtian-enclave-technical-plan`
- QingTian enclave CID：`4`
- Enclave control port：`5005`
- DashScope 走 egress port `8444`
- OpenAI 走 egress port `8445`

最终链路：

```text
client
  -> new-api on QingTian parent VM
  -> AF_VSOCK cid=4 port=5005
  -> /attest inside QingTian enclave
  -> TCP 127.0.0.1:<egress_port> inside enclave
  -> qproxy enclave
  -> AF_VSOCK parent cid=3 vsock_port=<egress_port>
  -> qproxy host on parent VM
  -> TCP 127.0.0.1:<egress_port> on parent VM
  -> parent-local TCP mapper
  -> real upstream host:443
```

关键约束：

- 接入方协议不变：new-api 仍然只把 `egress_port` 放进 request head，proof wire protocol 保持和 Nitro 版兼容。
- qproxy 必须双端运行：enclave 内 `qproxy enclave` 由业务镜像启动；父 VM 上必须启动 `qproxy host`。
- 多个 HTTPS 上游都是真实 `:443` 时，qproxy 配置不能直接写多个 `tcp_port = 443`。本文使用 parent-local TCP mapper，把 qproxy 的 `127.0.0.1:8444/8445` 再转到真实上游 `:443`。
- 旧的裸 `vsock -> TCP` 转发器必须停止，否则会造成端口冲突或误走旧路径。

## 1. 拉取 qproxy 版本代码

```bash
cd ~

if [ ! -d proof-of-observation/.git ]; then
  git clone https://github.com/Demo-9876/proof-of-observation.git
fi

cd ~/proof-of-observation
git fetch origin
git checkout feature/qingtian-enclave-technical-plan
git pull --ff-only origin feature/qingtian-enclave-technical-plan
git rev-parse HEAD
```

推荐至少拉到以下 commit 或更高版本：

```text
3e4ecc6 Isolate qt Docker config for QingTian image creation
31a93a7 Fix qproxy Docker SDK crate copy
768b49b Add QingTian qproxy runtime support
```

## 2. 准备 QingTian SDK

```bash
cd ~/proof-of-observation
mkdir -p third_party

if [ ! -d third_party/qingtian-sdk/.git ]; then
  git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git third_party/qingtian-sdk
fi

test -f third_party/qingtian-sdk/enclave/qtsm/lib/Makefile
test -d third_party/qingtian-sdk/qingtian-tools/qproxy
test -d third_party/qingtian-sdk/enclave/qtsm-sdk-rs
test -d third_party/qingtian-sdk/enclave/qtsm-sdk-sys
git -C third_party/qingtian-sdk rev-parse HEAD
```

这些目录缺一不可：

- `enclave/qtsm`：构建 `libqtsm.so`
- `qingtian-tools/qproxy`：构建 Huawei qproxy
- `enclave/qtsm-sdk-rs`：qproxy attestation 依赖
- `enclave/qtsm-sdk-sys`：`qtsm-sdk-rs` 的 path dependency

## 3. 准备 EIF 签名材料

生产环境应使用固定 release signing key/cert。先确认当前目录存在并匹配：

```bash
cd ~/proof-of-observation

test -f private-key.pem
test -f server.pem

openssl x509 -in server.pem -pubkey -noout > /tmp/qingtian-cert.pub
openssl pkey -in private-key.pem -pubout > /tmp/qingtian-key.pub
diff /tmp/qingtian-cert.pub /tmp/qingtian-key.pub
```

`diff` 无输出才继续。

## 4. 配置并启动 QingTian Enclave

```bash
cd ~/proof-of-observation

cat > deploy/qingtian-runtime/qingtian.env <<'EOF'
QINGTIAN_IMAGE=proof-observation-qingtian:qproxy-e2e
QINGTIAN_EIF=proof-observation-qingtian.qproxy-e2e.signed.eif
QINGTIAN_CID=4
QINGTIAN_CPUS=2
QINGTIAN_MEM=4096
QINGTIAN_PARENT_CIDS=3
QINGTIAN_EGRESS_MODE=qproxy
QINGTIAN_QPROXY_ENABLED=1
QINGTIAN_QPROXY_PARENT_CID=3
QINGTIAN_QPROXY_EGRESS_PORTS=8444,8445
QTSM_SDK_DIR=third_party/qingtian-sdk
APT_MIRROR=http://repo.huaweicloud.com/debian
CARGO_REGISTRY_MIRROR=sparse+https://rsproxy.cn/index/
QINGTIAN_PRIVATE_KEY=private-key.pem
QINGTIAN_SIGNING_CERTIFICATE=server.pem
QINGTIAN_QT_DOCKER_CONFIG=
QINGTIAN_START_EXTRA_ARGS=
EOF

qt enclave stop --enclave-id 0 2>/dev/null || true
bash deploy/qingtian-runtime/run.sh deploy/qingtian-runtime/qingtian.env \
  | tee qingtian-qproxy-e2e-build-start.log

qt enclave query | tee qingtian-qproxy-e2e-query.log
qt enclave query-eif --eif proof-observation-qingtian.qproxy-e2e.signed.eif \
  | tee qingtian-qproxy-e2e-query-eif.log
```

确认：

- `qt enclave query` 显示 `Status: Running`
- `query-eif` 输出 `PCR0` 和非 0 `PCR8`

如果上一次 Docker build 已经成功，但 `qt enclave make-img` 因 Docker auth config 失败，拉取最新代码后直接重跑本节命令即可。`run.sh` 会让 `qt` 使用干净的 `.tmp/qingtian-qt-docker-config/config.json`，不会再读取可能损坏的 `~/.docker/config.json`。

## 5. 写入父 VM 部署变量

把 `QINGTIAN_PCR0` / `QINGTIAN_PCR8` 替换为上一步 `query-eif` 的输出。

```bash
cat > ~/qingtian-proof-vars.sh <<'EOF'
export PROOF_REPO="$HOME/proof-of-observation"
export DEPLOY_DIR="$HOME/new-api-qingtian-proof"

export ENCLAVE_CID=4
export ENCLAVE_PORT=5005
export QINGTIAN_PCR0=<PCR0_FROM_QUERY_EIF>
export QINGTIAN_PCR8=<PCR8_FROM_QUERY_EIF>

export UPSTREAM_HOST=dashscope.aliyuncs.com
export UPSTREAM_TLS_PORT=443
export EGRESS_VSOCK_PORT=8444
export EXTRA_UPSTREAMS=api.openai.com:8445

export NEW_API_IMAGE=shihuo-acr-registry.cn-hangzhou.cr.aliyuncs.com/shihuo-base/ai-platform-newapi:aliyun-enclave-20260717
export NEW_API_CONTAINER=new-api-proof
export NEW_API_PORT=7070
EOF

source ~/qingtian-proof-vars.sh
```

## 6. 启动 qproxy host 和 parent-local TCP mapper

先停掉旧的裸 `vsock -> TCP` 转发器。以前用临时 Python / `nc-vsock` / 其它 vsock proxy 跑通时，可能会残留旧进程：

```bash
pgrep -af 'vsock|nc-vsock|python|8444|8445|5005' || true

# 按实际进程选择停止；下面命令只作为常见模式清理。
pgrep -f 'nc-vsock' | xargs -r kill 2>/dev/null || true
pgrep -f 'vsock.*8444|vsock.*8445' | xargs -r kill 2>/dev/null || true
```

启动新的 qproxy host 和 parent-local TCP mapper：

```bash
source ~/qingtian-proof-vars.sh

sudo yum install -y socat || sudo dnf install -y socat || sudo apt-get install -y socat

mkdir -p "$DEPLOY_DIR/qproxy"
cd "$DEPLOY_DIR/qproxy"

UPSTREAM_MAPPINGS="$UPSTREAM_HOST:$EGRESS_VSOCK_PORT ${EXTRA_UPSTREAMS:-}"

{
  for item in $UPSTREAM_MAPPINGS; do
    port="${item##*:}"
    printf '[[outbound_connections]]\n'
    printf 'hostname = "127.0.0.1"\n'
    printf 'vsock_port = %s\n' "$port"
    printf 'tcp_port = %s\n\n' "$port"
  done
  printf '[log_location]\n'
  printf 'host_log = "host.log"\n'
  printf 'enclave_log = "enclave.log"\n'
  printf 'log_level = "info"\n'
  printf 'host_log_dir = "/var/log/qproxy"\n'
  printf 'enclave_log_dir = "/var/log/qproxy"\n'
} > config_qproxy_egress.toml

cat > upstream-mappings.env <<EOF
UPSTREAM_MAPPINGS="$UPSTREAM_MAPPINGS"
UPSTREAM_TLS_PORT="$UPSTREAM_TLS_PORT"
EOF

sudo mkdir -p /var/log/qproxy
sudo chown -R "$USER:$USER" /var/log/qproxy
qproxy check-config ./config_qproxy_egress.toml

pgrep -f 'qingtian-proof-egres[s]' | xargs -r kill 2>/dev/null || true
for item in $UPSTREAM_MAPPINGS; do
  host="${item%:*}"
  port="${item##*:}"
  nohup socat -ly -lp "qingtian-proof-egress-$port" \
    TCP-LISTEN:"$port",bind=127.0.0.1,reuseaddr,fork \
    TCP:"$host":"$UPSTREAM_TLS_PORT" \
    > "$DEPLOY_DIR/qproxy/tcp-mapper-$port.out" 2>&1 &
done

pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
nohup qproxy host --config=./config_qproxy_egress.toml "$ENCLAVE_CID" \
  > "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>&1 &

sleep 2
pgrep -af 'qingtian-proof-egres[s]'
pgrep -af 'qproxy hos[t]'
for item in $UPSTREAM_MAPPINGS; do
  port="${item##*:}"
  ss -ltnp | grep "127.0.0.1:$port" || true
done
tail -n 80 "$DEPLOY_DIR/qproxy/qproxy-host.out"
```

检查点：

```bash
pgrep -af 'qingtian-proof-egres[s]'
pgrep -af 'qproxy hos[t]'
ss -ltnp | grep -E '127\.0\.0\.1:(8444|8445)'
tail -n 200 /var/log/qproxy/host.log 2>/dev/null || true
```

`qproxy-host.out` 只有下面内容不代表失败：

```text
nohup: ignoring input
```

实际是否运行以 `pgrep -af 'qproxy hos[t]'` 和 `/var/log/qproxy/host.log` 为准。

## 7. 启动 new-api 容器

下面假设你已经有可用的 `SQL_DSN`、`REDIS_CONN_STRING`、`SESSION_SECRET`。如果只是临时验证，也可以沿用现有 new-api 部署中的值。

```bash
source ~/qingtian-proof-vars.sh

mkdir -p "$DEPLOY_DIR/data" "$DEPLOY_DIR/logs"
cd "$DEPLOY_DIR"

read -r -p "SQL_DSN: " SQL_DSN
read -r -s -p "REDIS_CONN_STRING: " REDIS_CONN_STRING
printf '\n'
SESSION_SECRET="$(openssl rand -base64 48)"

UPSTREAM_MAPPINGS="$UPSTREAM_HOST:$EGRESS_VSOCK_PORT ${EXTRA_UPSTREAMS:-}"
TEE_ALLOWED_HOSTS=""
TEE_EGRESS_PORTS=""
for item in $UPSTREAM_MAPPINGS; do
  host="${item%:*}"
  port="${item##*:}"
  TEE_ALLOWED_HOSTS="${TEE_ALLOWED_HOSTS:+$TEE_ALLOWED_HOSTS,}$host"
  TEE_EGRESS_PORTS="${TEE_EGRESS_PORTS:+$TEE_EGRESS_PORTS,}$host:$port"
done

cat > qingtian-proof.env <<EOF
READ_CONFIG=false
TZ=Asia/Shanghai
NODE_NAME=new-api-qingtian-proof-01
PORT=$NEW_API_PORT
SESSION_SECRET=$SESSION_SECRET
SQL_DSN=$SQL_DSN
REDIS_CONN_STRING=$REDIS_CONN_STRING

TEE_PROOF_ENABLED=true
TEE_PROOF_REQUIRE=true
TEE_PROOF_ENCLAVE_CID=$ENCLAVE_CID
TEE_PROOF_ENCLAVE_PORT=$ENCLAVE_PORT
TEE_PROOF_EXPECTED_PCR0=$QINGTIAN_PCR0
TEE_PROOF_ALLOWED_HOSTS=$TEE_ALLOWED_HOSTS
TEE_PROOF_EGRESS_PORTS=$TEE_EGRESS_PORTS
TEE_PROOF_TIMEOUT_SECONDS=300
TEE_PROOF_MAX_BODY_BYTES=67108864
TEE_PROOF_STORE=memory
TEE_PROOF_STORE_TTL_SECONDS=600
TEE_PROOF_STORE_MAX_ITEMS=10000
EOF

chmod 600 qingtian-proof.env

docker rm -f "$NEW_API_CONTAINER" 2>/dev/null || true
docker run -d \
  --name "$NEW_API_CONTAINER" \
  --restart always \
  --network host \
  --privileged \
  --env-file "$DEPLOY_DIR/qingtian-proof.env" \
  -v "$DEPLOY_DIR/data:/data" \
  -v "$DEPLOY_DIR/logs:/app/logs" \
  "$NEW_API_IMAGE" \
  --log-dir /app/logs

sleep 3
docker ps --filter "name=$NEW_API_CONTAINER"
docker logs --tail 120 "$NEW_API_CONTAINER"
```

## 8. 发起 DashScope 非流式验证请求

把 `sk-xxxxx` 和模型名替换为现场可用值。

```bash
cat > /tmp/qingtian-chat.json <<'EOF'
{
  "model": "qwen3.7-plus",
  "messages": [
    {
      "role": "user",
      "content": "你好，请用一句话介绍一下你自己。"
    }
  ],
  "temperature": 0.7,
  "stream": false
}
EOF

curl -sS -i -X POST "http://127.0.0.1:7070/v1/chat/completions" \
  -H "Authorization: Bearer sk-xxxxx" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @/tmp/qingtian-chat.json \
  | tee /tmp/qingtian-nonstream.multipart

grep -a '"profile":"qingtian"' /tmp/qingtian-nonstream.multipart
```

## 9. 发起 DashScope 流式验证请求

```bash
cat > /tmp/qingtian-chat-stream.json <<'EOF'
{
  "model": "qwen3.7-plus",
  "messages": [
    {
      "role": "user",
      "content": "你好，请用一句话介绍一下你自己。"
    }
  ],
  "temperature": 0.7,
  "stream": true,
  "stream_options": {
    "include_usage": true
  }
}
EOF

curl -sS -N -X POST "http://127.0.0.1:7070/v1/chat/completions" \
  -H "Authorization: Bearer sk-xxxxx" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @/tmp/qingtian-chat-stream.json \
  | tee /tmp/qingtian-stream.sse

grep -a 'tee.proof' /tmp/qingtian-stream.sse | tail -n 2
```

## 10. 验证 proof

本地 verifier 的完整用法见 `docs/qingtian-new-api-parent-relay-deployment.md` 第 13 节。最小检查是：

```bash
cd ~/proof-of-observation/verifier
npm install

node --version
npm test
```

如果只需要先确认响应里带 QingTian proof：

```bash
grep -a '"profile":"qingtian"' /tmp/qingtian-nonstream.multipart /tmp/qingtian-stream.sse
```

response-only 验证会确认响应 proof、QingTian evidence、PCR、公钥绑定和响应签名；full 验证还会额外确认请求绑定。因为第 9 节已经用 `--data-binary @/tmp/qingtian-chat*.json` 保存了实际请求体,可以直接生成 full bundle：

```bash
source ~/qingtian-proof-vars.sh
cd ~/proof-of-observation/verifier

cat > /tmp/qingtian-trust.e2e.json <<EOF
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

npx tsx make-real-bundle.ts \
  /tmp/qingtian-chat.json \
  /tmp/qingtian-nonstream.multipart \
  /tmp/qingtian-nonstream.full-bundle.json

npx tsx verify-real-bundle.ts \
  /tmp/qingtian-nonstream.full-bundle.json \
  --trust /tmp/qingtian-trust.e2e.json \
  --host dashscope.aliyuncs.com

npx tsx make-real-bundle.ts \
  /tmp/qingtian-chat-stream.json \
  /tmp/qingtian-stream.sse \
  /tmp/qingtian-stream.full-bundle.json

npx tsx verify-real-bundle.ts \
  /tmp/qingtian-stream.full-bundle.json \
  --trust /tmp/qingtian-trust.e2e.json \
  --host dashscope.aliyuncs.com
```

## 11. 停止和重启

停止顺序：

```bash
source ~/qingtian-proof-vars.sh

docker rm -f "$NEW_API_CONTAINER" 2>/dev/null || true
pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
pgrep -f 'qingtian-proof-egres[s]' | xargs -r kill 2>/dev/null || true
qt enclave stop --enclave-id 0 2>/dev/null || true
qt enclave query
```

重启顺序：

```bash
source ~/qingtian-proof-vars.sh

qt enclave start \
  --mem 4096 \
  --cpus 2 \
  --eif "$PROOF_REPO/proof-observation-qingtian.qproxy-e2e.signed.eif" \
  --cid "$ENCLAVE_CID"

cd "$DEPLOY_DIR/qproxy"
source ./upstream-mappings.env

pgrep -f 'qingtian-proof-egres[s]' | xargs -r kill 2>/dev/null || true
for item in $UPSTREAM_MAPPINGS; do
  host="${item%:*}"
  port="${item##*:}"
  nohup socat -ly -lp "qingtian-proof-egress-$port" \
    TCP-LISTEN:"$port",bind=127.0.0.1,reuseaddr,fork \
    TCP:"$host":"$UPSTREAM_TLS_PORT" \
    > "$DEPLOY_DIR/qproxy/tcp-mapper-$port.out" 2>&1 &
done

pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
nohup qproxy host --config=./config_qproxy_egress.toml "$ENCLAVE_CID" \
  > "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>&1 &

docker start "$NEW_API_CONTAINER"

sleep 2
qt enclave query
pgrep -af 'qingtian-proof-egres[s]'
pgrep -af 'qproxy hos[t]'
docker ps --filter "name=$NEW_API_CONTAINER"
```

## 12. 已遇到问题和处理方式

| 阶段 | 现象 | 原因 | 处理 |
|---|---|---|---|
| Docker build 拉基础镜像 | `registry-1.docker.io` timeout | 父 VM 到 Docker Hub 不稳定 | 配置 Docker registry mirror，或先 `docker pull` 所需基础镜像 |
| Docker build apt | HTTPS Debian mirror 报 `No system certificates available` / `Certificate verification failed` | `debian:bookworm-slim` 首次 `apt-get update` 前没有 CA | `APT_MIRROR=http://repo.huaweicloud.com/debian`，首次 apt 用 HTTP |
| Cargo build | 无法访问 `index.crates.io` | 父 VM 网络/DNS 对 crates.io 不稳定 | `CARGO_REGISTRY_MIRROR=sparse+https://rsproxy.cn/index/` |
| qproxy build | `failed to read /src/enclave/qtsm-sdk-sys/Cargo.toml` | Dockerfile 只复制了 `qtsm-sdk-rs`，漏了 path dependency `qtsm-sdk-sys` | 已在 `31a93a7` 修复；拉最新代码 |
| `qt enclave make-img` | `not enough values to unpack (expected 2, got 1)` | Python Docker SDK 解析 `~/.docker/config.json` 中坏掉的 `auth` 字段失败 | 已在 `3e4ecc6` 修复；`run.sh` 给 `qt` 使用干净 Docker config |
| `qt enclave query` | `[]` 或 enclave 短暂 Running 后退出 | enclave 主进程退出、qproxy 启动失败或运行参数不匹配 | 看 `/var/log/qingtian_enclaves/qingtian-tool.log`，确认 `start-qingtian-attest`、`qproxy enclave` 和 `/attest` |
| qproxy host 输出 | `qproxy-host.out` 只有 `nohup: ignoring input` | 这是 nohup 常规输出，不代表失败 | 用 `pgrep -af 'qproxy hos[t]'` 和 `/var/log/qproxy/host.log` 判断 |
| 请求失败 | `Connection reset/refused` | qproxy host、enclave 内 qproxy、parent-local mapper 或旧 vsock 转发器冲突 | 停旧转发器，检查 `pgrep` 和 `ss -ltnp` |
| 多上游配置 | 直接配置多个 `tcp_port = 443` 不可用 | qproxy `tcp_port` 同时作为 enclave-local listener 和 host-side target port | 使用本文 `127.0.0.1:8444/8445 -> real host:443` mapper 模式 |

## 13. 常用排障命令

```bash
qt enclave query
tail -n 200 /var/log/qingtian_enclaves/qingtian-tool.log

source ~/qingtian-proof-vars.sh
pgrep -af 'qingtian-proof-egres[s]'
pgrep -af 'qproxy hos[t]'
for port in 8444 8445; do
  ss -ltnp | grep "127.0.0.1:$port" || true
done
tail -n 200 "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>/dev/null || true
tail -n 200 /var/log/qproxy/host.log 2>/dev/null || true

docker logs --tail 200 "$NEW_API_CONTAINER"
docker exec "$NEW_API_CONTAINER" env | grep '^TEE_PROOF_'
```

## 14. 最终成功判定

全部满足才认为 qproxy E2E 跑通：

- `git rev-parse HEAD` 不低于 `3e4ecc6`。
- `qt enclave query` 显示 enclave `Status=Running`，`LaunchMode=normal`。
- `qt enclave query-eif` 输出 `PCR8` 非 0。
- `pgrep -af 'qproxy hos[t]'` 有 qproxy host 进程。
- `pgrep -af 'qingtian-proof-egres[s]'` 有 `8444` / `8445` 的 `socat` 进程。
- `ss -ltnp` 显示 `127.0.0.1:8444` 和 `127.0.0.1:8445` 正在监听。
- new-api 容器启动，环境变量包含 `TEE_PROOF_ENABLED=true`、`TEE_PROOF_ENCLAVE_CID=4`、`TEE_PROOF_ENCLAVE_PORT=5005`。
- 非流式请求响应中包含 `"profile":"qingtian"`。
- 流式请求 SSE 末尾包含 `tee.proof` 事件。
- Node verifier 对保存的 response/proof 校验通过。
