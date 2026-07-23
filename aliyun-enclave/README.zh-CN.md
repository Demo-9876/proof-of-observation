# 阿里云 Enclave proof 生成器

本模块是 `aliyun-vtpm` evidence profile 的阿里云 Enclave 内 proof 生成实现。

它保留现有的 `tee-exchange-v2` statement 格式，并将 Nitro NSM attestation document 替换为阿里云 Enclave vTPM `QuoteReport` envelope。

## 信任链路

预期生产信任链路如下：

```text
QuoteReport.Cert -> 阿里云 root/intermediate 证书链
QuoteReport.Cert public key -> TPM quote signature
TPM quote QualifyingData -> sha256(challenge_payload)
challenge_payload -> tee-exchange-v2 statement facts
PCR values -> verifier allowlist
Ed25519 statement signature -> request/response bytes
```

该生成器不会调用阿里云远程证明服务来换取 OIDC/JWT token。verifier 会在本地根据阿里云 TPM EK root/intermediate 链和 Enclave EK 证书 CN 规则，对 `QuoteReport.Cert` 做 appraisal。

阿里云技术人员确认的官方 CA 材料：

- EK intermediate CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt`
- EK root CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt`

从上述官方 CA 文件观察并 pin 的 SHA-256 指纹：

- Root CA:
  `870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f`
- EKMF intermediate CA:
  `141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0`

## 构建

本地测试不需要阿里云硬件或 SDK 访问：

```bash
cd aliyun-enclave
go test ./...
```

真实 vTPM adapter 位于 `aliyun_enclave` build tag 后面。在阿里云 Enclave 构建环境中，需要加入官方 SDK module 后再构建：

```bash
cd aliyun-enclave
go get github.com/aliyun/acs-apsara-enclave/sdk/attest@f81674a6b341e7b835d33ee5da9cb2add6a24379
go build -tags aliyun_enclave ./cmd/aliyun-proof
go build -tags aliyun_enclave ./cmd/aliyun-proof-helper
```

## 生成 proof

`aliyun-proof` 会对已有 request/response bytes 签名，并请求 vTPM 基于 canonical challenge payload 生成 `QuoteReport`。

```bash
./aliyun-proof \
  --nonce-b64 "$NONCE_B64" \
  --upstream-host api.example.com \
  --upstream-path /v1/messages \
  --http-method POST \
  --http-status 200 \
  --resp-content-type text/event-stream \
  --request-body-file request.bin \
  --response-body-file response.bin \
  --out tee.proof.json
```

流式调用方可以直接传入已计算好的 digest，避免缓冲或落盘完整响应体：

```bash
./aliyun-proof \
  --nonce-b64 "$NONCE_B64" \
  --upstream-host api.example.com \
  --upstream-path /v1/messages \
  --http-method POST \
  --http-status 200 \
  --resp-content-type text/event-stream \
  --request-sha256 "$REQUEST_BODY_SHA256" \
  --response-sha256 "$RESPONSE_BODY_SHA256" \
  --out tee.proof.json
```

`--generate-nonce` 仅用于本地实验。生产调用方应传入 verifier/requester nonce，并验证返回 proof 中包含同一个 nonce。

该命令会写出 `verifier/tee-verify-core.ts` 消费的同一套顶层 proof 结构，包括：

- `evidence`：结构化的 `aliyun-vtpm` evidence envelope；
- `attestation`：同一 envelope 的 base64 JSON 编码，用于传输兼容。

可复用库同时暴露 `proof.GenerateFromHashes`。生产 streaming proxy 应在增量计算 request 和 response bytes hash 后调用这个 API，因此无需在创建 proof 前缓冲完整上游响应。

## Helper daemon

`aliyun-proof-helper` 是 Rust streaming relay 使用的 Enclave 本地 daemon。它监听 Unix domain socket，持有进程内 Ed25519 signing key，复用阿里云 vTPM attester，并基于 relay 提供的 request/response hashes 返回完整的 `aliyun-vtpm` `tee.proof`。

```bash
aliyun-proof-helper --socket /run/aliyun-proof-helper.sock
```

relay 应设置：

```bash
export TEE_PROFILE=aliyun-vtpm
export ALIYUN_PROOF_HELPER_SOCKET=/run/aliyun-proof-helper.sock
```

启动脚本可以通过下面的命令等待 helper 就绪：

```bash
aliyun-proof-helper --socket /run/aliyun-proof-helper.sock --health-check
```

helper protocol 使用 4 字节 big-endian length prefix，后面跟 JSON。请求 payload 上限为 64 KiB，响应 payload 上限为 4 MiB。

## Runtime 镜像

合并后的阿里云 Enclave runtime 位于 `deploy/aliyun-vtpm-runtime/`：

- `deploy/aliyun-vtpm-runtime/Dockerfile`
- `deploy/aliyun-vtpm-runtime/run.sh`

在仓库根目录执行下面命令构建：

```bash
sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

## 当前限制

- 当前实现包含 Enclave 侧 proof 生成核心，以及 Rust streaming relay 使用的 helper daemon。完整生产发布仍需要在阿里云 Enclave 上构建并验证合并后的 Rust relay + helper EIF。
- 生产 verifier 发布前仍需要 CRL 检查，或接入外部 CRL appraisal 步骤。
- 第一阶段有意不支持浏览器 verifier 的 `aliyun-vtpm` profile。
