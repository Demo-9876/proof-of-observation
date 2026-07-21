# QingTian 父 VM new-api Relay 部署文档

本文档梳理在 Huawei Cloud QingTian Enclave 父 VM 上部署 `ai-platform-newapi` 作为 `proof-of-observation` relay 的完整步骤。

`ai-platform-newapi` 仓库路径：

```text
/Users/admin/Documents/code/go/code.shihuo.cn/aibrain/ai-platform-newapi
```

本文只描述部署和验证步骤，不要求修改 `ai-platform-newapi` 代码。

## 1. 当前实现边界

父 VM 上的 new-api 不是单独的 sidecar，而是在现有 OpenAI relay 请求链路中启用 `relay/proof`：

- 上游请求创建后，`relay/channel/api_request.go` 调用 `proof.TryDoRequest()`。
- new-api 通过 Linux `AF_VSOCK` 连接 enclave：`TEE_PROOF_ENCLAVE_CID:TEE_PROOF_ENCLAVE_PORT`。
- enclave 默认监听 control port `5005`，当前 QingTian 启动参数中 `EnclaveCID=4`。
- enclave 收到父 VM 请求后，再通过父 VM egress vsock proxy 连接真实上游。
- 流式响应在 SSE 尾部追加 `event: tee.proof`。
- 非流式响应改为 `multipart/mixed`，第一段是原始上游响应 body，第二段是 `tee.proof` JSON。
- 非流式响应会返回 `X-TEE-Proof-Id`，可通过 `GET /api/tee/proofs/:proof_id` 查询 proof；该接口使用 `TokenAuthReadOnly()`，只能由同 token 读取。

当前 new-api proof 仅注册了 OpenAI relay format 的 `/v1/chat/completions`：

- `chat.completions.non_stream`
- `chat.completions.stream`

不覆盖 Responses API、Claude Messages API、图片、音频、rerank 等其它 relay mode。

## 2. 推荐部署拓扑

推荐先使用专用 proof relay 实例灰度，不要直接在承载混合业务的主 new-api 实例上全量启用。

```text
client
  |
  | HTTPS /v1/chat/completions
  v
new-api on parent VM
  |
  | vsock cid=4 port=5005
  v
proof-of-observation enclave
  |
  | vsock parent cid=3 egress_port=<host-mapped-port>
  v
parent egress proxy
  |
  | TCP/TLS passthrough
  v
official upstream host:443
```

原因：当前代码中 `TEE_PROOF_ENABLED=true` 后，OpenAI-format chat completions JSON endpoint 会默认进入 proof-required 判断。如果同一实例还承载不在 `TEE_PROOF_ALLOWED_HOSTS` / `TEE_PROOF_EGRESS_PORTS` 内的 OpenAI chat 流量，请求可能因 eligibility 不满足而返回错误。生产灰度建议使用专用域名、专用实例或专用渠道。

## 3. 前置条件

在 QingTian 父 VM 上确认 enclave 已经正常运行：

```bash
qt enclave query
qt enclave query-eif --eif ~/proof-of-observation/proof-observation-qingtian.e2e.signed.eif
```

期望：

- `Status` 为 `Running`。
- `LaunchMode` 为 `normal`。
- `EnclaveCID` 为后续配置的 `TEE_PROOF_ENCLAVE_CID`，当前验证为 `4`。
- `PCR8` 非 0，说明 signed EIF 生效。

当前已验证的一组 E2E PCR：

```text
PCR0=f2646224f07a0e6eb98c172ed41c820e90b2e4686728027e854fc6935488e1c7e490fc100ac5e6f3f8cc7cff3c5566c1
PCR8=9e45f72e25849c5cfb6b91b2160fdde7666413ef451b54f2f0a61d06492fb72ed7b277541a8cd0e03757e44fc2f05949
```

生产环境应替换为正式发布 manifest 中的 PCR0/PCR8。

确认父 VM 支持 vsock：

```bash
uname -m
lsmod | grep -E 'vsock|virtio_vsock|vhost_vsock' || true
test -e /proc/net/vsock && cat /proc/net/vsock || true
```

如果 new-api 运行在 Docker 容器内，建议优先改为父 VM 裸进程/systemd 运行。若必须容器化，容器需要允许创建 `AF_VSOCK` socket，通常需要 `--privileged` 或至少放开 seccomp；上线前必须用真实 proof 请求验证。

## 4. Egress vsock proxy

new-api 配置的是 host 到 egress port 的映射：

```text
TEE_PROOF_EGRESS_PORTS=api.openai.com:8445,dashscope.aliyuncs.com:8444
```

含义不是 TCP 端口监听给客户端访问，而是：

- new-api 把 `egress_port` 写入发给 enclave 的 request head。
- enclave 通过 parent CID `3` 连接父 VM 上该 vsock port。
- 父 VM egress proxy 将这个 vsock 连接透明转发到对应上游 host 的 `443`。
- TLS 在 enclave 内建立，父 VM egress proxy 只做字节转发。

如果已有 Nitro 版 egress-vsock proxy，QingTian 版保持同一组 egress port 即可，只需确认 parent CID 为 `3`，enclave 能连回父 VM。

部署时为每个允许的上游 host 启动一个 proxy 映射，例如：

```text
vsock listen :8445 -> tcp api.openai.com:443
vsock listen :8444 -> tcp dashscope.aliyuncs.com:443
```

由于不同环境使用的 proxy 工具不同，实际命令以现有 Nitro 部署中的 egress proxy 为准。建议统一纳入 systemd，例如：

```ini
# /etc/systemd/system/poo-egress-api-openai.service
[Unit]
Description=Proof of Observation egress proxy for api.openai.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=2
User=root
ExecStart=/usr/local/bin/<your-vsock-egress-proxy> \
  --listen-vsock-port 8445 \
  --target-host api.openai.com \
  --target-port 443

[Install]
WantedBy=multi-user.target
```

启动和检查：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now poo-egress-api-openai.service
sudo systemctl status poo-egress-api-openai.service --no-pager -l
sudo journalctl -u poo-egress-api-openai.service -n 100 --no-pager
```

## 5. new-api 环境变量

在父 VM 上为 new-api 增加以下环境变量：

```bash
export TEE_PROOF_ENABLED=true
export TEE_PROOF_REQUIRE=true
export TEE_PROOF_ENCLAVE_CID=4
export TEE_PROOF_ENCLAVE_PORT=5005
export TEE_PROOF_EXPECTED_PCR0=f2646224f07a0e6eb98c172ed41c820e90b2e4686728027e854fc6935488e1c7e490fc100ac5e6f3f8cc7cff3c5566c1
export TEE_PROOF_ALLOWED_HOSTS=api.openai.com
export TEE_PROOF_EGRESS_PORTS=api.openai.com:8445
export TEE_PROOF_TIMEOUT_SECONDS=300
export TEE_PROOF_MAX_BODY_BYTES=67108864
export TEE_PROOF_STORE=memory
export TEE_PROOF_STORE_TTL_SECONDS=600
export TEE_PROOF_STORE_MAX_ITEMS=10000
```

变量说明：

| 变量 | 说明 |
|---|---|
| `TEE_PROOF_ENABLED` | 总开关。`true` 后 OpenAI chat completions JSON endpoint 会进入 proof eligibility。 |
| `TEE_PROOF_REQUIRE` | 建议生产 `true`。proof 不可用时 fail closed，而不是降级到普通上游请求。 |
| `TEE_PROOF_ENCLAVE_CID` | `qt enclave query` 中的 `EnclaveCID`，当前 E2E 为 `4`。 |
| `TEE_PROOF_ENCLAVE_PORT` | enclave control port，当前实现固定为 `5005`。 |
| `TEE_PROOF_EXPECTED_PCR0` | 当前部署对外透出的 PCR0，用于 header/审计展示；真正 verifier 还要使用 trust config 校验 PCR0/PCR8。 |
| `TEE_PROOF_ALLOWED_HOSTS` | 允许走 proof 的上游 host 白名单，必须和 new-api 实际上游 URL 的 hostname 完全一致。 |
| `TEE_PROOF_EGRESS_PORTS` | host 到父 VM egress vsock port 的映射，必须覆盖所有 `TEE_PROOF_ALLOWED_HOSTS`。 |
| `TEE_PROOF_TIMEOUT_SECONDS` | new-api 等待 enclave 完成 upstream 请求和 proof 的超时时间。 |
| `TEE_PROOF_MAX_BODY_BYTES` | 允许送入 enclave 的最大请求体大小。 |
| `TEE_PROOF_STORE` | 当前代码只支持 `memory`。 |
| `TEE_PROOF_STORE_TTL_SECONDS` | 非流式 proof id 查询的内存保留时间。 |
| `TEE_PROOF_STORE_MAX_ITEMS` | 非流式 proof 内存 store 最大条数。 |

多上游示例：

```bash
export TEE_PROOF_ALLOWED_HOSTS=api.openai.com,dashscope.aliyuncs.com
export TEE_PROOF_EGRESS_PORTS=api.openai.com:8445,dashscope.aliyuncs.com:8444
```

## 6. new-api 渠道配置要求

用于 proof 的渠道需要满足：

- relay format 为 OpenAI。
- endpoint 为 `/v1/chat/completions`。
- 请求方法为 `POST`。
- 请求 `Content-Type` 包含 `application/json`。
- 请求体有明确 `Content-Length`，且大小不超过 `TEE_PROOF_MAX_BODY_BYTES`。
- 上游 hostname 在 `TEE_PROOF_ALLOWED_HOSTS` 中。
- 该 hostname 在 `TEE_PROOF_EGRESS_PORTS` 有映射。
- 渠道不要开启会改写响应字节的设置：
  - `ForceFormat=false`
  - `ThinkingToContent=false`

如果这些条件不满足：

- `TEE_PROOF_REQUIRE=true` 或默认 proof-required 场景下会返回错误。
- 非 required 场景下可能降级普通请求，但生产不建议依赖降级。

## 7. systemd 方式部署 new-api

推荐在 QingTian 父 VM 上用 systemd 直接运行 new-api，避免 Docker seccomp 对 `AF_VSOCK` 的影响。

示例环境文件：

```bash
sudo tee /etc/new-api-proof.env >/dev/null <<'EOF'
TZ=Asia/Shanghai
SESSION_SECRET=<replace-with-production-secret>
SQL_DSN=<replace-with-production-sql-dsn>
REDIS_CONN_STRING=<replace-with-production-redis>
NODE_NAME=new-api-qingtian-proof-01

TEE_PROOF_ENABLED=true
TEE_PROOF_REQUIRE=true
TEE_PROOF_ENCLAVE_CID=4
TEE_PROOF_ENCLAVE_PORT=5005
TEE_PROOF_EXPECTED_PCR0=f2646224f07a0e6eb98c172ed41c820e90b2e4686728027e854fc6935488e1c7e490fc100ac5e6f3f8cc7cff3c5566c1
TEE_PROOF_ALLOWED_HOSTS=api.openai.com
TEE_PROOF_EGRESS_PORTS=api.openai.com:8445
TEE_PROOF_TIMEOUT_SECONDS=300
TEE_PROOF_MAX_BODY_BYTES=67108864
TEE_PROOF_STORE=memory
TEE_PROOF_STORE_TTL_SECONDS=600
TEE_PROOF_STORE_MAX_ITEMS=10000
EOF

sudo chmod 600 /etc/new-api-proof.env
```

示例 service：

```bash
sudo tee /etc/systemd/system/new-api-proof.service >/dev/null <<'EOF'
[Unit]
Description=new-api proof relay for QingTian Enclave
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ansible
WorkingDirectory=/home/ansible/ai-platform-newapi
EnvironmentFile=/etc/new-api-proof.env
ExecStart=/home/ansible/ai-platform-newapi/new-api --log-dir /home/ansible/ai-platform-newapi/logs
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now new-api-proof.service
sudo systemctl status new-api-proof.service --no-pager -l
sudo journalctl -u new-api-proof.service -n 100 --no-pager
```

如使用仓库内已有 `new-api.service`，只需要把 `EnvironmentFile=/etc/new-api-proof.env` 和实际 `ExecStart` 路径合并进去。

## 8. Docker 方式部署 new-api

如果必须用 Docker，推荐使用 host 网络并放开 seccomp/权限后再验证 vsock：

```bash
docker run -d --name new-api-proof \
  --restart always \
  --network host \
  --privileged \
  -v "$PWD/data:/data" \
  -v "$PWD/logs:/app/logs" \
  --env-file /etc/new-api-proof.env \
  <your-new-api-image> \
  --log-dir /app/logs
```

更收敛的容器权限可以在真实机器上逐步验证，但最小验收标准是 proof 请求能通过 enclave，不能只看 HTTP 普通请求成功。

如果使用 `docker-compose.yml`，核心配置是：

```yaml
services:
  new-api:
    network_mode: host
    privileged: true
    env_file:
      - /etc/new-api-proof.env
```

注意：`network_mode: host` 与 compose 中的 `ports`、自定义 bridge network 通常不能同时使用，需要按实际部署文件调整。

## 9. 启动顺序

建议顺序：

1. 启动父 VM egress proxy。
2. 启动 QingTian enclave。
3. 确认 `qt enclave query` 为 `Running`。
4. 启动 new-api proof relay。
5. 发起 `X-TEE-Proof: required` 测试请求。
6. 保存完整 SSE / multipart 响应并用 verifier 验证。

检查命令：

```bash
qt enclave query
sudo systemctl status poo-egress-api-openai.service --no-pager -l
sudo systemctl status new-api-proof.service --no-pager -l
sudo journalctl -u new-api-proof.service -n 100 --no-pager
```

## 10. 业务请求验证

以下示例假设 new-api 监听 `http://127.0.0.1:7070`，token 为 `<NEW_API_TOKEN>`，模型为 `<MODEL>`。

### 10.1 非流式 multipart

```bash
curl -sS -D headers.qingtian.nonstream.txt \
  http://127.0.0.1:7070/v1/chat/completions \
  -H "Authorization: Bearer <NEW_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  -d '{
    "model": "<MODEL>",
    "messages": [{"role": "user", "content": "Say hello from QingTian proof non-stream"}],
    "stream": false
  }' \
  -o response.qingtian.nonstream.multipart
```

检查：

```bash
cat headers.qingtian.nonstream.txt
grep -i '^content-type:' headers.qingtian.nonstream.txt
grep -i '^x-tee-proof-' headers.qingtian.nonstream.txt
grep -a '"profile":"qingtian"' response.qingtian.nonstream.multipart
```

期望：

- `Content-Type` 为 `multipart/mixed; boundary=...`。
- header 包含 `X-TEE-Proof-Id`、`X-TEE-Proof-Version: 2`、`X-TEE-Proof-PCR0`、`X-TEE-Proof-Upstream-Host`。
- body 中第二段包含 `"profile":"qingtian"`。

如需验证 proof 查询接口：

```bash
PROOF_ID="$(awk 'BEGIN{IGNORECASE=1} /^X-TEE-Proof-Id:/ {gsub("\r","",$2); print $2}' headers.qingtian.nonstream.txt)"
curl -sS \
  "http://127.0.0.1:7070/api/tee/proofs/${PROOF_ID}" \
  -H "Authorization: Bearer <NEW_API_TOKEN>" \
  | tee proof-sidecar.qingtian.json
```

### 10.2 流式 SSE

```bash
curl -N -sS -D headers.qingtian.stream.txt \
  http://127.0.0.1:7070/v1/chat/completions \
  -H "Authorization: Bearer <NEW_API_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "X-TEE-Proof: required" \
  -d '{
    "model": "<MODEL>",
    "messages": [{"role": "user", "content": "Say hello from QingTian proof stream"}],
    "stream": true,
    "stream_options": {"include_usage": true}
  }' \
  -o response.qingtian.stream.sse
```

检查：

```bash
cat headers.qingtian.stream.txt
grep -i '^x-tee-proof-' headers.qingtian.stream.txt
grep -a 'event: tee.proof' response.qingtian.stream.sse | tail -n 2
grep -a '"profile":"qingtian"' response.qingtian.stream.sse
```

期望：

- 流式响应 header 不暴露 `X-TEE-Proof-Id`。
- SSE body 末尾包含 `event: tee.proof`。
- proof JSON 包含 `"profile":"qingtian"`。

## 11. verifier 验证

在 `proof-of-observation` 仓库中生成 trust config：

```bash
cd ~/proof-of-observation

cat > qingtian-trust.e2e.json <<'EOF'
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "f2646224f07a0e6eb98c172ed41c820e90b2e4686728027e854fc6935488e1c7e490fc100ac5e6f3f8cc7cff3c5566c1",
    "sha384:8": "9e45f72e25849c5cfb6b91b2160fdde7666413ef451b54f2f0a61d06492fb72ed7b277541a8cd0e03757e44fc2f05949"
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

验证非流式 multipart：

```bash
cd ~/proof-of-observation/verifier
npm ci
npx tsx tee-verify-stream.ts ../response.qingtian.nonstream.multipart \
  --trust ../qingtian-trust.e2e.json \
  --host api.openai.com \
  | tee ../verify-qingtian-new-api-nonstream.log
```

验证流式 SSE：

```bash
npx tsx tee-verify-stream.ts ../response.qingtian.stream.sse \
  --trust ../qingtian-trust.e2e.json \
  --host api.openai.com \
  | tee ../verify-qingtian-new-api-stream.log
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

## 12. 发布前检查清单

发布前逐项确认：

- `qt enclave query` 显示 `Status: Running`、`LaunchMode: normal`。
- Signed EIF 的 `PCR8` 非 0。
- `TEE_PROOF_ENCLAVE_CID` 等于 `qt enclave query` 的 `EnclaveCID`。
- `TEE_PROOF_ENCLAVE_PORT=5005`。
- `TEE_PROOF_ALLOWED_HOSTS` 覆盖所有 proof 业务上游 host。
- `TEE_PROOF_EGRESS_PORTS` 对每个 allowed host 都有映射。
- 父 VM egress proxy 已启动，且端口映射到正确上游 `host:443`。
- proof 渠道关闭会改写响应字节的 channel setting。
- new-api 和 egress proxy 都纳入 systemd/容器重启策略。
- 非流式和流式各保存一份完整响应并通过 Node CLI verifier。
- 发布材料记录 source revision、QingTian SDK revision、EIF sha256、PCR0、PCR8、签名证书指纹和 trust config。

## 13. 常见问题

### 13.1 `TEE proof required but request is not eligible: upstream host not allowed`

说明 new-api 实际上游 URL 的 hostname 不在 `TEE_PROOF_ALLOWED_HOSTS`。检查渠道上游地址：

```bash
grep -n "fullRequestURL" logs/*.log | tail -n 20
```

将真实 hostname 加入：

```bash
export TEE_PROOF_ALLOWED_HOSTS=api.openai.com,<actual-host>
export TEE_PROOF_EGRESS_PORTS=api.openai.com:8445,<actual-host>:<egress-port>
```

同时启动对应 egress proxy。

### 13.2 `TEE proof required but request is not eligible: egress port missing`

说明 host 在白名单，但 `TEE_PROOF_EGRESS_PORTS` 没有对应映射。补齐 `host:port`。

### 13.3 `TEE proof required but request is not eligible: force format may rewrite response`

该渠道开启了会改写响应的 `ForceFormat`。proof 要证明客户端收到的 body 与 enclave 观察到的 body 字节一致，不能在父 VM 上二次改写。关闭该渠道设置或使用专用 proof 渠道。

### 13.4 `TEE proof required but request is not eligible: thinking_to_content may rewrite response`

同上，`ThinkingToContent` 会改写响应结构，关闭该设置。

### 13.5 vsock 连接 enclave 失败

检查：

```bash
qt enclave query
grep -E '^TEE_PROOF_ENCLAVE_' /etc/new-api-proof.env
sudo journalctl -u new-api-proof.service -n 100 --no-pager
```

如果 new-api 在 Docker 中运行，优先用 systemd 裸进程复测；若裸进程可用、容器不可用，说明容器权限/seccomp 阻止了 `AF_VSOCK`。

### 13.6 响应里没有 `tee.proof`

检查：

- 请求是否命中 `/v1/chat/completions`。
- 请求是否是 `Content-Type: application/json`。
- 是否设置 `X-TEE-Proof: required`。
- new-api 日志里是否有 `TEE proof` 错误。
- enclave 是否仍在运行。
- egress proxy 是否能连接上游。

### 13.7 verifier 报 PCR 不匹配

说明 trust config 中 PCR0/PCR8 与当前 signed EIF 不一致。重新获取：

```bash
qt enclave query-eif --eif ~/proof-of-observation/proof-observation-qingtian.e2e.signed.eif
```

生产环境只允许使用发布 manifest 中的 PCR，不要临时信任现场未知 PCR。

