# QingTian qproxy E2E Quickstart

本文档是在真实 Huawei QingTian Enclave 父 VM 上，用 Huawei 官方 qproxy 重新跑 `proof-of-observation` 端到端验证的最短命令流。

约定：

- 父 VM 用户：`ansible`
- `proof-of-observation` 仓库：`~/proof-of-observation`
- 分支：`feature/qingtian-enclave-technical-plan`
- QingTian enclave CID：`4`
- Enclave control port：`5005`
- DashScope 走 egress port `8444`
- OpenAI 走 egress port `8445`

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

## 2. 准备 QingTian SDK

```bash
cd ~/proof-of-observation
mkdir -p third_party

if [ ! -d third_party/qingtian-sdk/.git ]; then
  git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git third_party/qingtian-sdk
fi

test -f third_party/qingtian-sdk/enclave/qtsm/lib/Makefile
test -d third_party/qingtian-sdk/qingtian-tools/qproxy
git -C third_party/qingtian-sdk rev-parse HEAD
```

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

本地 verifier 的完整用法见 `docs/qingtian-new-api-parent-relay-deployment.md` 第 12 节。最小检查是：

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

## 11. 常用排障命令

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
