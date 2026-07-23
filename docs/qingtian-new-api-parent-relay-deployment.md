# QingTian 父 VM new-api Relay Docker 部署 Runbook

本文档给出在 Huawei Cloud QingTian Enclave 父 VM 上，从 `ai-platform-newapi` 源码构建 Docker 镜像并部署为 `proof-of-observation` relay 的完整操作流程。

约定：

- `proof-of-observation` 仓库在父 VM：`~/proof-of-observation`
- `ai-platform-newapi` 仓库在父 VM：`~/ai-platform-newapi`
- QingTian enclave 已用 `proof-of-observation` signed EIF 启动。
- 当前已验证的 enclave：`CID=4`，control port：`5005`
- 当前 signed EIF PCR：
  - `PCR0=ce20e9feca6b19c7367460b996f7aaa336cfef9026b0765550b19bd786547465d5ea54f51d8a4d786d608c9de142677a`
  - `PCR8=9e45f72e25849c5cfb6b91b2160fdde7666413ef451b54f2f0a61d06492fb72ed7b277541a8cd0e03757e44fc2f05949`

阅读方式：

- `bash` 代码块表示需要复制到 QingTian 父 VM 执行的命令。
- `text` / `toml` / `env` 代码块只表示链路、配置内容或期望输出，不要当成 shell 命令执行。
- 需要人工填写的敏感值会通过 `read` 命令写入本机变量文件，后续命令直接引用变量文件。

完整执行顺序：

```text
1. 写入部署变量
2. 检查/启动 QingTian enclave
3. 安装或构建 qproxy
4. 启动 qproxy host
5. 准备 ai-platform-newapi 源码
6. 从源码构建 new-api Docker 镜像
7. 创建 new-api env 文件
8. Docker 启动 new-api
9. 在 new-api 控制台配置渠道和 token
10. curl 验证非流式和流式 proof
11. 用 proof-of-observation verifier 验证响应
```

## 0. 部署链路说明

实际链路：

```text
client
  -> new-api Docker container on parent VM
  -> AF_VSOCK cid=4 port=5005
  -> proof-of-observation enclave /attest
  -> TCP 127.0.0.1:<egress_port> inside enclave
  -> qproxy enclave
  -> AF_VSOCK parent cid=3 vsock_port=<egress_port>
  -> qproxy host on parent VM
  -> TCP 127.0.0.1:<egress_port> on parent VM
  -> parent-local TCP mapper
  -> TCP <actual-upstream-host>:443
```

new-api 负责接入客户端请求并把符合条件的 `/v1/chat/completions` 请求送进 enclave。enclave 内部建立 TLS，并通过 Huawei 官方 qproxy 出网。父 VM 的 qproxy 只做 vsock/TCP 字节转发；TLS SNI、`Host` 头和证书校验仍由 enclave 内 `/attest` 对真实上游完成。

重要限制：

- qproxy `outbound_connections.tcp_port` 同时是 enclave 内本地 TCP listener 端口，也是 parent 侧要连接的目标 TCP 端口。
- 因此多个 HTTPS 上游都需要连真实 `:443` 时，不能在 qproxy 中直接写多个 `tcp_port = 443`。
- 本文采用固定映射：qproxy 只连接 parent VM 的 `127.0.0.1:8444/8445/...`，再由 parent-local TCP mapper 转到真实上游 `dashscope.aliyuncs.com:443`、`api.openai.com:443`。这样 new-api 仍然只需要配置 `TEE_PROOF_EGRESS_PORTS=host:egress_port`，接入方协议不变。

当前 `ai-platform-newapi` 代码里的 proof 接入点：

- `relay/channel/api_request.go` 调用 `proof.TryDoRequest()`
- `relay/proof/config.go` 读取 `TEE_PROOF_*`
- `relay/proof/dialer_linux.go` 创建 `AF_VSOCK`
- `relay/proof/passthrough.go` 输出 SSE tail `event: tee.proof` 或非流式 `multipart/mixed`
- `controller/tee_proof.go` 提供 `GET /api/tee/proofs/:proof_id`

## 1. 设置本次部署变量

先写入固定部署变量：

```bash
cat > ~/qingtian-proof-vars.sh <<'EOF'
export PROOF_REPO="$HOME/proof-of-observation"
export NEWAPI_REPO="$HOME/ai-platform-newapi"
export DEPLOY_DIR="$HOME/new-api-qingtian-proof"

export ENCLAVE_CID=4
export ENCLAVE_PORT=5005
export QINGTIAN_PCR0=ce20e9feca6b19c7367460b996f7aaa336cfef9026b0765550b19bd786547465d5ea54f51d8a4d786d608c9de142677a
export QINGTIAN_PCR8=9e45f72e25849c5cfb6b91b2160fdde7666413ef451b54f2f0a61d06492fb72ed7b277541a8cd0e03757e44fc2f05949

export UPSTREAM_HOST=dashscope.aliyuncs.com
export UPSTREAM_TLS_PORT=443
export EGRESS_VSOCK_PORT=8444
export EXTRA_UPSTREAMS=api.openai.com:8445

export NEW_API_IMAGE=new-api-proof:qingtian
export NEW_API_CONTAINER=new-api-proof
export NEW_API_PORT=7070
EOF

source ~/qingtian-proof-vars.sh
```

再写入需要按现场填写的变量。下面命令会交互式提示输入，不会把敏感值回显到终端：

```bash
source ~/qingtian-proof-vars.sh

read -r -p "ai-platform-newapi Git URL: " AI_PLATFORM_NEWAPI_GIT_URL
read -r -p "SQL_DSN: " SQL_DSN
read -r -s -p "REDIS_CONN_STRING: " REDIS_CONN_STRING
printf '\n'
SESSION_SECRET="$(openssl rand -base64 48)"

{
  printf 'export AI_PLATFORM_NEWAPI_GIT_URL=%q\n' "$AI_PLATFORM_NEWAPI_GIT_URL"
  printf 'export SQL_DSN=%q\n' "$SQL_DSN"
  printf 'export REDIS_CONN_STRING=%q\n' "$REDIS_CONN_STRING"
  printf 'export SESSION_SECRET=%q\n' "$SESSION_SECRET"
} > ~/qingtian-proof-secrets.sh

chmod 600 ~/qingtian-proof-secrets.sh
source ~/qingtian-proof-secrets.sh
```

成功判断：

```bash
source ~/qingtian-proof-vars.sh
source ~/qingtian-proof-secrets.sh

test -n "$AI_PLATFORM_NEWAPI_GIT_URL"
test -n "$SQL_DSN"
test -n "$REDIS_CONN_STRING"
test -n "$SESSION_SECRET"
printf 'deploy vars ok\n'
```

## 2. 检查 QingTian Enclave 已运行

执行：

```bash
source ~/qingtian-proof-vars.sh

qt enclave query
qt enclave query-eif --eif "$PROOF_REPO/proof-observation-qingtian.e2e.signed.eif"
```

期望：

```text
Status: Running
EnclaveCID: 4
PCR0: ce20e9...
PCR8: 9e45f7...
```

如果 `qt enclave query` 返回 `[]`，先重新启动 enclave：

```bash
source ~/qingtian-proof-vars.sh

qt enclave start \
  --mem 4096 \
  --cpus 2 \
  --eif "$PROOF_REPO/proof-observation-qingtian.e2e.signed.eif" \
  --cid "$ENCLAVE_CID"

for i in $(seq 1 12); do
  date
  qt enclave query
  sleep 5
done
```

## 3. 安装/构建 qproxy

说明：下面是真正需要执行的代理命令，不是 `vsock listen ...` 这种示意文本。

qproxy 来自 Huawei QingTian SDK，官方父 VM 启动形式是：

```text
qproxy host --config=/path/to/config_qproxy.toml <enclave-cid>
```

先安装 Rust 工具链和依赖。如果机器上已有 `cargo`，这一段可以跳过：

```bash
rustc -V || true
cargo -V || true

sudo yum install -y gcc make openssl-devel libcurl-devel libcbor-devel pkgconfig rust cargo || true
```

构建 qproxy：

```bash
source ~/qingtian-proof-vars.sh

if [ ! -d "$PROOF_REPO/third_party/qingtian-sdk" ]; then
  git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git \
    "$PROOF_REPO/third_party/qingtian-sdk"
fi

cd "$PROOF_REPO/third_party/qingtian-sdk/qingtian-tools/qproxy"
cargo build --release

sudo install -m 0755 target/release/qproxy /usr/local/bin/qproxy
qproxy --help
```

如果 `qingtian-tools/qproxy` 目录不存在，先定位当前 SDK checkout 的 qproxy 目录：

```bash
source ~/qingtian-proof-vars.sh
find "$PROOF_REPO/third_party/qingtian-sdk" -maxdepth 5 \
  \( -iname 'qproxy' -o -iname 'Cargo.toml' \) \
  -print | head -n 80
```

## 4. 配置并启动 qproxy host

安装 parent-local TCP mapper 依赖。本文用 `socat`，生产也可以换成 systemd 管理的等价 TCP forwarder：

```bash
sudo yum install -y socat || sudo dnf install -y socat || sudo apt-get install -y socat
```

创建 qproxy host 配置。注意这里的 `hostname` 固定写 `127.0.0.1`，`tcp_port` 和 `vsock_port` 都使用分配给该上游的 egress port；真实上游域名由下一步 parent-local TCP mapper 处理：

```bash
source ~/qingtian-proof-vars.sh

mkdir -p "$DEPLOY_DIR/qproxy"
cd "$DEPLOY_DIR/qproxy"

UPSTREAM_MAPPINGS="$UPSTREAM_HOST:$EGRESS_VSOCK_PORT ${EXTRA_UPSTREAMS:-}"

{
  for item in $UPSTREAM_MAPPINGS; do
    host="${item%:*}"
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
```

启动 parent-local TCP mapper。它监听父 VM 的 `127.0.0.1:<egress_port>`，转发到真实上游 `<host>:443`：

```bash
source ~/qingtian-proof-vars.sh
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

sleep 2
pgrep -af 'qingtian-proof-egres[s]'
for item in $UPSTREAM_MAPPINGS; do
  port="${item##*:}"
  ss -ltnp | grep "127.0.0.1:$port" || true
done
```

先前台启动 qproxy host，便于观察错误：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR/qproxy"

qproxy host --config=./config_qproxy_egress.toml "$ENCLAVE_CID"
```

保持这个窗口不关。另开一个 SSH 窗口继续后续步骤。确认链路可用后，可以改成后台运行：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR/qproxy"

pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true

nohup qproxy host --config=./config_qproxy_egress.toml "$ENCLAVE_CID" \
  > "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>&1 &

sleep 2
pgrep -af 'qproxy hos[t]'
tail -n 100 "$DEPLOY_DIR/qproxy/qproxy-host.out"
tail -n 100 /var/log/qproxy/host.log 2>/dev/null || true
```

检查配置和 EIF 内置端口是否一致。`deploy/qingtian-runtime/qingtian.env` 中的 `QINGTIAN_QPROXY_EGRESS_PORTS` 必须包含这里所有 egress port，例如：

```bash
source ~/qingtian-proof-vars.sh
grep '^QINGTIAN_QPROXY_EGRESS_PORTS=' "$PROOF_REPO/deploy/qingtian-runtime/qingtian.env"
cat "$DEPLOY_DIR/qproxy/upstream-mappings.env"
```

示例对应关系：

```text
DashScope: qproxy tcp/vsock 8444 -> parent mapper 127.0.0.1:8444 -> dashscope.aliyuncs.com:443
OpenAI:    qproxy tcp/vsock 8445 -> parent mapper 127.0.0.1:8445 -> api.openai.com:443
```

## 5. 准备 ai-platform-newapi 源码

如果父 VM 上还没有源码，先克隆：

```bash
source ~/qingtian-proof-vars.sh
source ~/qingtian-proof-secrets.sh

if [ ! -d "$NEWAPI_REPO/.git" ]; then
  git clone "$AI_PLATFORM_NEWAPI_GIT_URL" "$NEWAPI_REPO"
fi

cd "$NEWAPI_REPO"
git status --short
git rev-parse --abbrev-ref HEAD
git rev-parse HEAD
```

确认源码包含 proof relay 代码：

```bash
cd "$NEWAPI_REPO"

grep -R "TEE_PROOF_ENABLED" -n relay/proof | head
grep -R "TryDoRequest" -n relay/channel relay/proof | head
grep -R "/api/tee/proofs" -n router controller | head
```

期望能看到：

```text
relay/proof/config.go
relay/channel/api_request.go
router/api-router.go
controller/tee_proof.go
```

## 6. 从源码构建 new-api Docker 镜像

`ai-platform-newapi/Dockerfile` 使用了 BuildKit secret：

```text
RUN --mount=type=secret,id=gitkey,target=/root/.ssh/id_rsa go mod download
```

因此构建时必须开启 BuildKit，并提供能访问私有依赖的 SSH key。

确认 SSH key：

```bash
test -f "$HOME/.ssh/id_rsa"
ssh -T git@code.shihuo.cn || true
```

如果你的私有 Git 使用的不是 `~/.ssh/id_rsa`，先把本次构建使用的 key 写入变量：

```bash
read -r -p "Docker build SSH key path [$HOME/.ssh/id_rsa]: " DOCKER_BUILD_SSH_KEY
DOCKER_BUILD_SSH_KEY="${DOCKER_BUILD_SSH_KEY:-$HOME/.ssh/id_rsa}"
test -f "$DOCKER_BUILD_SSH_KEY"
printf 'export DOCKER_BUILD_SSH_KEY=%q\n' "$DOCKER_BUILD_SSH_KEY" >> ~/qingtian-proof-secrets.sh
source ~/qingtian-proof-secrets.sh
```

构建镜像：

```bash
source ~/qingtian-proof-vars.sh
source ~/qingtian-proof-secrets.sh
cd "$NEWAPI_REPO"

export DOCKER_BUILDKIT=1

docker build \
  --secret id=gitkey,src="${DOCKER_BUILD_SSH_KEY:-$HOME/.ssh/id_rsa}" \
  -f Dockerfile \
  -t "$NEW_API_IMAGE" \
  .
```

如果当前用户没有 Docker 权限，用 `sudo -E docker build ...` 重试。构建成功后检查：

```bash
docker image inspect "$NEW_API_IMAGE" --format '{{.Id}} {{.RepoTags}}'
```

## 7. 创建 new-api proof 环境文件

创建部署目录：

```bash
source ~/qingtian-proof-vars.sh

mkdir -p "$DEPLOY_DIR/data" "$DEPLOY_DIR/logs"
cd "$DEPLOY_DIR"
```

配置说明：

| 配置项 | 来源 | 说明 |
|---|---|---|
| `SESSION_SECRET` | `~/qingtian-proof-secrets.sh` | 多节点必须一致；本文自动随机生成。 |
| `SQL_DSN` | `~/qingtian-proof-secrets.sh` | 生产库连接串；如果接入已有 new-api，必须使用同一个库。 |
| `REDIS_CONN_STRING` | `~/qingtian-proof-secrets.sh` | 生产 Redis；多实例建议必填。 |
| `TEE_PROOF_ENCLAVE_CID` | `~/qingtian-proof-vars.sh` | 必须等于 `qt enclave query` 的 `EnclaveCID`。 |
| `TEE_PROOF_EGRESS_PORTS` | `~/qingtian-proof-vars.sh` | 必须和 qproxy `outbound_connections` 一一对应。 |

执行下面命令生成 Docker `--env-file`：

```bash
source ~/qingtian-proof-vars.sh
source ~/qingtian-proof-secrets.sh
cd "$DEPLOY_DIR"

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
sed -E \
  -e 's/^(SESSION_SECRET=).*/\1***masked***/' \
  -e 's/^(SQL_DSN=).*/\1***masked***/' \
  -e 's/^(REDIS_CONN_STRING=).*/\1***masked***/' \
  qingtian-proof.env
```

注意：如果 `SQL_DSN` / `REDIS_CONN_STRING` 里包含 `#`、空格或特殊字符，Docker `--env-file` 可能解析异常，建议改用 `docker compose` 的 `env_file` 或在 systemd 中引用环境文件。

## 8. Docker 运行 new-api proof relay

new-api 容器需要创建 Linux `AF_VSOCK` socket 连接 enclave。最稳的验证方式是先用 `--network host --privileged` 启动。

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

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
curl -sS "http://127.0.0.1:$NEW_API_PORT/health" || true
```

如果你必须使用 Compose，生成一个单独的部署文件，不修改 `ai-platform-newapi` 仓库：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

cat > docker-compose.qingtian-proof.yml <<EOF
version: "3.4"

services:
  new-api-proof:
    image: $NEW_API_IMAGE
    container_name: $NEW_API_CONTAINER
    restart: always
    network_mode: host
    privileged: true
    command: --log-dir /app/logs
    env_file:
      - ./qingtian-proof.env
    volumes:
      - ./data:/data
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O - http://localhost:$NEW_API_PORT/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

docker compose -f docker-compose.qingtian-proof.yml up -d
```

如果系统只有旧版 `docker-compose`：

```bash
docker-compose -f docker-compose.qingtian-proof.yml up -d
```

## 9. 配置 new-api 渠道和 Token

这一节是控制台配置说明，不是 shell 命令。

用于 proof 的渠道需要满足：

- relay format 为 OpenAI。
- 客户端请求 endpoint 为 `/v1/chat/completions`。
- 上游 URL 的 hostname 必须等于 `TEE_PROOF_ALLOWED_HOSTS` 中的值，例如 `api.openai.com`。
- 渠道不要开启会改写响应字节的设置：
  - `ForceFormat=false`
  - `ThinkingToContent=false`
- 请求 `Content-Type` 必须是 JSON。
- 请求体必须有明确 `Content-Length`。

如果是新数据库，需要在 new-api 管理后台创建：

- 可用用户或测试 token。
- 指向 `$UPSTREAM_HOST` 的 OpenAI-format 渠道。
- 可路由到该渠道的模型名，例如 `<MODEL>`。

后续命令用：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

read -r -s -p "NEW_API_TOKEN: " NEW_API_TOKEN
printf '\n'
read -r -p "MODEL: " MODEL

{
  printf 'export NEW_API_TOKEN=%q\n' "$NEW_API_TOKEN"
  printf 'export MODEL=%q\n' "$MODEL"
} > "$DEPLOY_DIR/qingtian-proof-test-vars.sh"

chmod 600 "$DEPLOY_DIR/qingtian-proof-test-vars.sh"
source "$DEPLOY_DIR/qingtian-proof-test-vars.sh"
```

## 10. 发起非流式 proof 请求

执行：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

source "$DEPLOY_DIR/qingtian-proof-test-vars.sh"

cat > request.qingtian.nonstream.json <<EOF
{
  "model": "$MODEL",
  "messages": [{"role": "user", "content": "Say hello from QingTian proof non-stream"}],
  "stream": false
}
EOF

curl -sS -D headers.qingtian.nonstream.txt \
  "http://127.0.0.1:$NEW_API_PORT/v1/chat/completions" \
  -H "Authorization: Bearer $NEW_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @request.qingtian.nonstream.json \
  -o response.qingtian.nonstream.multipart
```

检查响应：

```bash
cd "$DEPLOY_DIR"

cat headers.qingtian.nonstream.txt
grep -i '^content-type:' headers.qingtian.nonstream.txt
grep -i '^x-tee-proof-' headers.qingtian.nonstream.txt
grep -a '"profile":"qingtian"' response.qingtian.nonstream.multipart
```

期望：

```text
Content-Type: multipart/mixed; boundary=...
X-TEE-Proof-Id: ...
X-TEE-Proof-Version: 2
X-TEE-Proof-PCR0: ce20e9...
X-TEE-Proof-Upstream-Host: api.openai.com
```

验证 proof sidecar 查询接口：

```bash
cd "$DEPLOY_DIR"

PROOF_ID="$(awk 'BEGIN{IGNORECASE=1} /^X-TEE-Proof-Id:/ {gsub("\r","",$2); print $2}' headers.qingtian.nonstream.txt)"

curl -sS \
  "http://127.0.0.1:$NEW_API_PORT/api/tee/proofs/${PROOF_ID}" \
  -H "Authorization: Bearer $NEW_API_TOKEN" \
  | tee proof-sidecar.qingtian.json
```

## 11. 发起流式 SSE proof 请求

执行：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

source "$DEPLOY_DIR/qingtian-proof-test-vars.sh"

cat > request.qingtian.stream.json <<EOF
{
  "model": "$MODEL",
  "messages": [{"role": "user", "content": "Say hello from QingTian proof stream"}],
  "stream": true,
  "stream_options": {"include_usage": true}
}
EOF

curl -N -sS -D headers.qingtian.stream.txt \
  "http://127.0.0.1:$NEW_API_PORT/v1/chat/completions" \
  -H "Authorization: Bearer $NEW_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  --data-binary @request.qingtian.stream.json \
  -o response.qingtian.stream.sse
```

检查响应：

```bash
cd "$DEPLOY_DIR"

cat headers.qingtian.stream.txt
grep -i '^x-tee-proof-' headers.qingtian.stream.txt
grep -a 'event: tee.proof' response.qingtian.stream.sse | tail -n 2
grep -a '"profile":"qingtian"' response.qingtian.stream.sse
```

期望：

- 流式响应 header 不包含 `X-TEE-Proof-Id`。
- SSE body 末尾包含 `event: tee.proof`。
- proof JSON 包含 `"profile":"qingtian"`。

## 12. 生成 QingTian trust config

执行：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

cat > qingtian-trust.e2e.json <<EOF
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

cat qingtian-trust.e2e.json
```

## 13. 使用 Node CLI verifier 验证响应

安装 verifier 依赖：

```bash
source ~/qingtian-proof-vars.sh
cd "$PROOF_REPO/verifier"
npm ci
```

验证非流式 multipart：

```bash
source ~/qingtian-proof-vars.sh
cd "$PROOF_REPO/verifier"

npx tsx tee-verify-stream.ts \
  "$DEPLOY_DIR/response.qingtian.nonstream.multipart" \
  --trust "$DEPLOY_DIR/qingtian-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify-qingtian-new-api-nonstream.log"
```

验证流式 SSE：

```bash
source ~/qingtian-proof-vars.sh
cd "$PROOF_REPO/verifier"

npx tsx tee-verify-stream.ts \
  "$DEPLOY_DIR/response.qingtian.stream.sse" \
  --trust "$DEPLOY_DIR/qingtian-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify-qingtian-new-api-stream.log"
```

完整请求绑定验证。该档会把实际请求体、剥离 proof 后的响应体、proof 放进同一个 bundle,再验证“答的就是这条请求”：

```bash
source ~/qingtian-proof-vars.sh
cd "$PROOF_REPO/verifier"

npx tsx make-real-bundle.ts \
  "$DEPLOY_DIR/request.qingtian.nonstream.json" \
  "$DEPLOY_DIR/response.qingtian.nonstream.multipart" \
  "$DEPLOY_DIR/bundle.qingtian.nonstream.full.json"

npx tsx verify-real-bundle.ts \
  "$DEPLOY_DIR/bundle.qingtian.nonstream.full.json" \
  --trust "$DEPLOY_DIR/qingtian-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify-qingtian-new-api-nonstream-full.log"

npx tsx make-real-bundle.ts \
  "$DEPLOY_DIR/request.qingtian.stream.json" \
  "$DEPLOY_DIR/response.qingtian.stream.sse" \
  "$DEPLOY_DIR/bundle.qingtian.stream.full.json"

npx tsx verify-real-bundle.ts \
  "$DEPLOY_DIR/bundle.qingtian.stream.full.json" \
  --trust "$DEPLOY_DIR/qingtian-trust.e2e.json" \
  --host "$UPSTREAM_HOST" \
  | tee "$DEPLOY_DIR/verify-qingtian-new-api-stream-full.log"
```

通过标准：

- QingTian evidence 格式通过。
- QingTian COSE 签名通过。
- QingTian 证书链链到 Huawei QingTian root。
- PCR0/PCR8 与 trust config 匹配。
- attestation public key 与 proof public key 绑定。
- nonce 绑定通过。
- response body hash 与客户端实际收到的 body 匹配。
- v2 statement Ed25519 签名通过。
- `--host` 指定的上游 host 与 proof 中签名覆盖的 host 一致。

## 14. 停止和重启

停止 new-api Docker：

```bash
source ~/qingtian-proof-vars.sh
docker rm -f "$NEW_API_CONTAINER"
```

停止 qproxy host：

```bash
pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
```

停止 parent-local TCP mapper：

```bash
pgrep -f 'qingtian-proof-egres[s]' | xargs -r kill 2>/dev/null || true
```

停止 enclave：

```bash
qt enclave stop --enclave-id 0
qt enclave query
```

重启顺序：

```bash
source ~/qingtian-proof-vars.sh

qt enclave start \
  --mem 4096 \
  --cpus 2 \
  --eif "$PROOF_REPO/proof-observation-qingtian.e2e.signed.eif" \
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

sleep 2
for item in $UPSTREAM_MAPPINGS; do
  port="${item##*:}"
  ss -ltnp | grep "127.0.0.1:$port" || true
done
pgrep -af 'qproxy hos[t]'

docker start "$NEW_API_CONTAINER"
```

## 15. 常见错误排查

### 15.1 `vsock: command not found`

`vsock listen :8445 -> tcp api.openai.com:443` 是映射说明，不是命令。实际命令是：

```bash
qproxy host --config=./config_qproxy_egress.toml 4
```

### 15.2 `TEE proof required but request is not eligible: upstream host not allowed`

new-api 实际上游 URL 的 hostname 不在 `TEE_PROOF_ALLOWED_HOSTS`。检查 new-api 日志中的 `fullRequestURL`：

```bash
source ~/qingtian-proof-vars.sh
docker logs "$NEW_API_CONTAINER" 2>&1 | grep 'fullRequestURL' | tail -n 20
grep -R "fullRequestURL" -n "$DEPLOY_DIR/logs" | tail -n 20 || true
```

把真实 hostname 写入变量文件。下面命令会追加一个新上游，并同步更新 new-api env 文件；端口需要是一个尚未使用的 egress port，并且必须已经包含在 EIF 构建时的 `QINGTIAN_QPROXY_EGRESS_PORTS` 中。若没有包含，需要先更新 `deploy/qingtian-runtime/qingtian.env`、重建 signed EIF 并重启 enclave。

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR"

read -r -p "Actual upstream host: " ACTUAL_UPSTREAM_HOST
read -r -p "Actual upstream egress port, e.g. 8446: " ACTUAL_EGRESS_PORT

{
  printf 'export ACTUAL_UPSTREAM_HOST=%q\n' "$ACTUAL_UPSTREAM_HOST"
  printf 'export ACTUAL_EGRESS_PORT=%q\n' "$ACTUAL_EGRESS_PORT"
} >> "$DEPLOY_DIR/qingtian-proof-test-vars.sh"

cp qingtian-proof.env "qingtian-proof.env.$(date +%Y%m%d%H%M%S).bak"

python3 - "$ACTUAL_UPSTREAM_HOST" "$ACTUAL_EGRESS_PORT" <<'PY'
import pathlib
import sys

host = sys.argv[1].strip()
port = sys.argv[2].strip()
path = pathlib.Path("qingtian-proof.env")
lines = path.read_text().splitlines()

def append_csv(current: str, item: str) -> str:
    values = [v.strip() for v in current.split(",") if v.strip()]
    if item not in values:
        values.append(item)
    return ",".join(values)

out = []
for line in lines:
    if line.startswith("TEE_PROOF_ALLOWED_HOSTS="):
        out.append("TEE_PROOF_ALLOWED_HOSTS=" + append_csv(line.split("=", 1)[1], host))
    elif line.startswith("TEE_PROOF_EGRESS_PORTS="):
        out.append("TEE_PROOF_EGRESS_PORTS=" + append_csv(line.split("=", 1)[1], f"{host}:{port}"))
    else:
        out.append(line)
path.write_text("\n".join(out) + "\n")
PY

grep '^TEE_PROOF_ALLOWED_HOSTS=\|^TEE_PROOF_EGRESS_PORTS=' qingtian-proof.env
```

同时在 `config_qproxy_egress.toml` 增加对应 `[[outbound_connections]]`，并启动 parent-local TCP mapper：

```bash
source ~/qingtian-proof-vars.sh
source "$DEPLOY_DIR/qingtian-proof-test-vars.sh"
cd "$DEPLOY_DIR/qproxy"

cat >> config_qproxy_egress.toml <<EOF

[[outbound_connections]]
hostname = "127.0.0.1"
vsock_port = $ACTUAL_EGRESS_PORT
tcp_port = $ACTUAL_EGRESS_PORT
EOF

tail -n 20 config_qproxy_egress.toml
qproxy check-config ./config_qproxy_egress.toml

nohup socat -ly -lp "qingtian-proof-egress-$ACTUAL_EGRESS_PORT" \
  TCP-LISTEN:"$ACTUAL_EGRESS_PORT",bind=127.0.0.1,reuseaddr,fork \
  TCP:"$ACTUAL_UPSTREAM_HOST":"$UPSTREAM_TLS_PORT" \
  > "$DEPLOY_DIR/qproxy/tcp-mapper-$ACTUAL_EGRESS_PORT.out" 2>&1 &
```

修改后重启 qproxy 和 new-api 容器：

```bash
source ~/qingtian-proof-vars.sh
cd "$DEPLOY_DIR/qproxy"

pgrep -f 'qproxy hos[t]' | xargs -r kill 2>/dev/null || true
nohup qproxy host --config=./config_qproxy_egress.toml "$ENCLAVE_CID" \
  > "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>&1 &

docker rm -f "$NEW_API_CONTAINER"
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
```

### 15.3 `TEE proof required but request is not eligible: egress port missing`

host 在白名单，但 `TEE_PROOF_EGRESS_PORTS` 没有对应映射。补齐 `host:vsock_port`，并重启 new-api 容器。

### 15.4 `force format may rewrite response` / `thinking_to_content may rewrite response`

该渠道开启了会改写响应的设置。proof 要证明客户端收到的 body 与 enclave 观察到的 body 字节一致，父 VM 不能二次改写。关闭相关渠道设置，或新建专用 proof 渠道。

### 15.5 new-api Docker 连接 enclave 失败

检查 enclave：

```bash
qt enclave query
```

检查容器权限和环境变量：

```bash
source ~/qingtian-proof-vars.sh
docker inspect "$NEW_API_CONTAINER" --format '{{json .HostConfig.NetworkMode}} {{json .HostConfig.Privileged}}'
docker exec "$NEW_API_CONTAINER" env | grep '^TEE_PROOF_'
docker logs --tail 200 "$NEW_API_CONTAINER"
```

如果裸进程可用但 Docker 不可用，通常是容器 seccomp/capability 阻止了 `AF_VSOCK`。先使用本文的 `--network host --privileged` 配置验证。

### 15.6 qproxy 没有转发成功

检查 qproxy 进程和日志：

```bash
source ~/qingtian-proof-vars.sh
pgrep -af 'qproxy hos[t]'
tail -n 200 "$DEPLOY_DIR/qproxy/qproxy-host.out" 2>/dev/null || true
tail -n 200 /var/log/qproxy/host.log 2>/dev/null || true
```

检查父 VM 能访问上游：

```bash
source ~/qingtian-proof-vars.sh
curl -Iv "https://$UPSTREAM_HOST" --connect-timeout 10
```

### 15.7 verifier 报 PCR 不匹配

重新获取当前 EIF PCR：

```bash
source ~/qingtian-proof-vars.sh
qt enclave query-eif --eif "$PROOF_REPO/proof-observation-qingtian.e2e.signed.eif"
```

如果 PCR0 改了，说明 enclave 镜像内容变了，必须更新发布 manifest 和 trust config。生产环境只允许信任正式发布 manifest 中的 PCR。

## 16. 发布前检查清单

执行检查：

```bash
source ~/qingtian-proof-vars.sh

qt enclave query
qt enclave query-eif --eif "$PROOF_REPO/proof-observation-qingtian.e2e.signed.eif"
pgrep -af 'qproxy hos[t]'
docker ps --filter "name=$NEW_API_CONTAINER"
docker logs --tail 80 "$NEW_API_CONTAINER"
```

人工确认：

- `qt enclave query` 显示 `Status=Running`、`LaunchMode=normal`。
- Signed EIF 的 `PCR8` 非 0。
- `TEE_PROOF_ENCLAVE_CID` 等于 `qt enclave query` 的 `EnclaveCID`。
- `TEE_PROOF_ENCLAVE_PORT=5005`。
- `TEE_PROOF_ALLOWED_HOSTS` 覆盖所有 proof 业务上游 host。
- `TEE_PROOF_EGRESS_PORTS` 对每个 allowed host 都有映射。
- qproxy `outbound_connections` 对每个 allowed host 都有映射。
- proof 渠道关闭会改写响应字节的 channel setting。
- 非流式和流式各保存一份完整响应并通过 Node CLI verifier。
- 发布材料记录 `ai-platform-newapi` revision、`proof-of-observation` revision、QingTian SDK revision、EIF sha256、PCR0、PCR8、签名证书指纹和 trust config。
