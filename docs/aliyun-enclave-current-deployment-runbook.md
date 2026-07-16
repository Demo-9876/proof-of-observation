# 当前版本部署到阿里云 Enclave 的验证 Runbook

本文记录当前分支将 `aliyun-vtpm` proof 生成端部署到阿里云 Enclave，并拿到真实 `QuoteReport.Cert` / TPM quote fixture 的最小可执行步骤。

当前版本的定位：

- 已实现：Enclave 内 `aliyun-proof` CLI / Go library，调用阿里云 vTPM 生成 `QuoteReport`，输出 `tee-exchange-v2` proof。
- 已实现：Node verifier 的 `aliyun-vtpm` profile，可验证 quote 签名、challenge、PCR digest、PCR allowlist、`QuoteReport.Cert` root/intermediate 链和 Enclave EK CN。
- 未实现：完整 streaming relay。当前 runbook 先跑最小 fixture 链路；完整用户请求流式转发仍需后续把 `proof.GenerateFromHashes` 接入 Enclave 内 relay。
- 未实现：TypeScript 内置 CRL 解析。当前 verifier 可配置 `revocation.required=false` 先完成链路校准；生产前需要外部 CRL appraiser 或内置 CRL 检查。

## 1. 前提

父 VM 需要满足：

- 已购买支持 Enclave 的阿里云 ECS 实例。
- 已安装并可运行 `enclave-cli`。
- 已安装 Docker。
- 当前仓库代码已同步到父 VM。
- 父 VM 上有一个可用的 `socat-vsock` 可执行文件，用于 Enclave 将 fixture tar 包发回父 VM。
- 父 VM 上有 `jq`、`openssl`、`tar`、`base64`。
- verifier 机器上有 Node.js，并可安装/运行 `verifier` 目录依赖。

检查：

```bash
sudo enclave-cli describe-enclaves
docker version
jq --version
openssl version
```

如果 `describe-enclaves` 返回 `[]`，说明当前没有运行中的 Enclave，这是正常的。

## 2. 准备变量

在父 VM 的仓库根目录执行：

```bash
cd ~/proof-of-observation

export IMAGE_NAME=proof-observation-aliyun-vtpm-fixture:latest
export EIF_FILE=aliyun-vtpm-fixture.eif
export OUT_TGZ=aliyun-vtpm-fixture.tgz
```

如果仓库路径不同，后续命令中的 `~/proof-of-observation` 替换为实际路径。
后续每打开一个新的父 VM 终端，都需要重新执行这些 `export`，或直接把命令中的变量替换为实际文件名。
本文档中的 vsock 接收端口固定为 `5005`；如果要改端口，必须同时修改父 VM listener 和 Enclave 内 `run.sh` 的 `vsock-connect:3:5005`。

## 3. 构建 `aliyun-proof`

真实 vTPM adapter 需要 `aliyun_enclave` build tag。

如果父 VM 已安装 Go：

```bash
cd ~/proof-of-observation/aliyun-enclave
go test ./...
go test -tags aliyun_enclave ./...

mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -tags aliyun_enclave -o bin/aliyun-proof ./cmd/aliyun-proof

ls -lh bin/aliyun-proof
file bin/aliyun-proof
```

如果父 VM 没有 Go，可以用能访问的 Go builder 镜像构建。注意不同环境的 Docker registry 可能不同，按实际网络改 `FROM` 镜像：

```bash
cd ~/proof-of-observation/aliyun-enclave

cat > Dockerfile.build <<'EOF'
FROM golang:1.24-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -tags aliyun_enclave -o /out/aliyun-proof ./cmd/aliyun-proof
EOF

sudo docker build --network host -f Dockerfile.build -t aliyun-proof-builder .
cid=$(sudo docker create aliyun-proof-builder)
mkdir -p bin
sudo docker cp "$cid:/out/aliyun-proof" bin/aliyun-proof
sudo docker rm "$cid"
sudo chown "$(id -u):$(id -g)" bin/aliyun-proof

ls -lh bin/aliyun-proof
```

## 4. 准备最小 fixture Enclave 镜像上下文

这个 fixture 镜像只做一件事：在 Enclave 内调用 vTPM 生成 proof，并把 proof、request/response 样本、metadata 打包后通过 vsock 发回父 VM。

准备目录：

```bash
cd ~/proof-of-observation
mkdir -p deploy/aliyun-vtpm-fixture

cp aliyun-enclave/bin/aliyun-proof deploy/aliyun-vtpm-fixture/aliyun-proof

SOCAT_VSOCK=/path/to/socat-vsock
file "$SOCAT_VSOCK"
ldd "$SOCAT_VSOCK" || true
cp "$SOCAT_VSOCK" deploy/aliyun-vtpm-fixture/socat-vsock

chmod +x deploy/aliyun-vtpm-fixture/aliyun-proof deploy/aliyun-vtpm-fixture/socat-vsock
```

如果 `socat-vsock` 已在当前目录或历史测试目录中，替换 `/path/to/socat-vsock` 为实际路径。
建议使用静态链接或已在 Alibaba Cloud Linux 2 环境验证过的 `socat-vsock`，避免 EIF 启动后因动态库不兼容导致无法把 fixture 发回父 VM。

创建 `run.sh`：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture

cat > run.sh <<'EOF'
#!/bin/sh
set -eux

mkdir -p /out

echo '[info] devices'
ls -l /dev/tpm* /dev/tpmrm* || true

echo '[info] prepare sample request/response bytes'
printf '{"model":"fixture","messages":[{"role":"user","content":"hello aliyun enclave"}]}' > /out/request.bin
printf 'event: message_stop\ndata: {"fixture":true}\n\n' > /out/response.bin

REQ_SHA256=$(sha256sum /out/request.bin | awk '{print $1}')
RESP_SHA256=$(sha256sum /out/response.bin | awk '{print $1}')
NONCE_B64=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n')

echo '[info] generate aliyun-vtpm proof'
/usr/bin/aliyun-proof \
  --nonce-b64 "$NONCE_B64" \
  --upstream-host api.example.com \
  --upstream-path /v1/messages \
  --http-method POST \
  --http-status 200 \
  --resp-content-type text/event-stream \
  --request-sha256 "$REQ_SHA256" \
  --response-sha256 "$RESP_SHA256" \
  --out /out/tee.proof.json

cat > /out/metadata.txt <<METAEOF
nonce_b64=$NONCE_B64
request_sha256=$REQ_SHA256
response_sha256=$RESP_SHA256
upstream_host=api.example.com
upstream_path=/v1/messages
profile=aliyun-vtpm
METAEOF

tar czf /out/aliyun-vtpm-fixture.tgz -C /out \
  tee.proof.json \
  request.bin \
  response.bin \
  metadata.txt

echo '[info] send fixture to parent cid=3 port=5005'
sent=0
for i in $(seq 1 60); do
  if /usr/bin/socat-vsock -u \
    OPEN:/out/aliyun-vtpm-fixture.tgz \
    vsock-connect:3:5005; then
    echo '[info] sent fixture'
    sent=1
    break
  fi
  echo "[warn] send failed, retry=$i"
  sleep 1
done

if [ "$sent" != "1" ]; then
  echo '[error] failed to send fixture to parent after retries' >&2
  exit 1
fi

echo '[info] done'
sleep 3600
EOF

chmod +x run.sh
```

创建 Dockerfile：

```bash
cat > Dockerfile <<'EOF'
FROM alibaba-cloud-linux-2-registry.cn-hangzhou.cr.aliyuncs.com/alinux2/alinux2

RUN yum install -y \
    coreutils \
    findutils \
    tar \
    gzip \
  && yum clean all

COPY aliyun-proof /usr/bin/aliyun-proof
COPY socat-vsock /usr/bin/socat-vsock
COPY run.sh /run.sh

RUN chmod +x /usr/bin/aliyun-proof /usr/bin/socat-vsock /run.sh

CMD ["/run.sh"]
EOF
```

构建 Docker 镜像：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture
sudo docker build --network host -t "$IMAGE_NAME" .
sudo docker tag "$IMAGE_NAME" docker.io/library/"$IMAGE_NAME"
```

## 5. 构建 EIF 并记录 PCR

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture

sudo enclave-cli build-enclave \
  --docker-dir . \
  --docker-uri "$IMAGE_NAME" \
  --output-file "$EIF_FILE" \
  | tee build-measurements.log
```

从输出中记录：

- `PCR8`
- `PCR9`
- `PCR11`

示例输出形态：

```json
{
  "Measurements": {
    "HashAlgorithm": "Sha256 { ... }",
    "PCR11": "<PCR11>",
    "PCR8": "<PCR8>",
    "PCR9": "<PCR9>"
  }
}
```

这些值后续写入 verifier trust bundle。注意：

- 构建工具版本、Docker base image、源码、依赖版本、Dockerfile、run.sh 都可能影响 PCR。
- 生产信任的 PCR 必须来自固定源码和固定构建环境，并记录可复现构建信息。
- 不要使用 debug mode 产生的 PCR 作为生产信任值。

## 6. 启动父 VM vsock 接收端

打开一个父 VM 终端，监听 Enclave 发回的 fixture：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture
export OUT_TGZ=aliyun-vtpm-fixture.tgz

rm -f "$OUT_TGZ"

sudo ./socat-vsock -u \
  vsock-listen:5005,reuseaddr,fork \
  OPEN:"$OUT_TGZ",creat,trunc
```

这个命令会阻塞等待 Enclave 连接。保持该终端不关闭。

## 7. 启动 Enclave

另开一个父 VM 终端：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture
export EIF_FILE=aliyun-vtpm-fixture.eif
export OUT_TGZ=aliyun-vtpm-fixture.tgz

sudo enclave-cli describe-enclaves

sudo enclave-cli run-enclave \
  --cpu-count 2 \
  --memory 2048 \
  --eif-path "$EIF_FILE"
```

记录输出中的：

- `EnclaveID`
- `EnclaveCID`
- `ProcessID`

确认运行中：

```bash
sudo enclave-cli describe-enclaves
```

等待第 6 步的 vsock listener 退出或当前目录出现文件：

```bash
ls -lh "$OUT_TGZ"
tar tzf "$OUT_TGZ"
```

预期包含：

```text
tee.proof.json
request.bin
response.bin
metadata.txt
```

提取：

```bash
rm -rf out
mkdir out
tar xzf "$OUT_TGZ" -C out

cat out/metadata.txt
jq '.profile, .evidence.quote_report.pcr_info.pcr_update_counter' out/tee.proof.json
```

## 8. 提取真实 `QuoteReport.Cert`

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture

jq -r '.evidence.quote_report.cert_b64' out/tee.proof.json | base64 -d > out/QuoteReport.Cert.der

openssl x509 -inform DER -in out/QuoteReport.Cert.der -out out/QuoteReport.Cert.pem

openssl x509 -in out/QuoteReport.Cert.pem -noout \
  -subject \
  -issuer \
  -serial \
  -fingerprint -sha256

openssl x509 -in out/QuoteReport.Cert.pem -noout -text \
  | sed -n '/Subject:/,/Subject Public Key Info:/p'
```

需要确认：

- `Subject CN` 是否符合 Enclave vTPM 格式，例如 `i-xxxxxxx-01`。
- `Issuer` 是否指向阿里云 TPM EKMF intermediate。
- 证书能否被 Node verifier 解析。
- 如果 CN 格式与当前默认 pattern 不一致，需要更新 trust bundle 的 `enclaveSubjectCnPattern`。

## 9. 准备 verifier trust bundle

下载阿里云 TPM CA：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture
mkdir -p trust

curl -L \
  https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt \
  -o trust/root-ca.crt

curl -L \
  https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt \
  -o trust/ekmf-ca.crt

openssl x509 -in trust/root-ca.crt -noout -fingerprint -sha256
openssl x509 -in trust/ekmf-ca.crt -noout -fingerprint -sha256
```

已知指纹应为：

```text
root-ca.crt  = 870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f
ekmf-ca.crt  = 141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0
```

从 `build-measurements.log` 提取 PCR。下面命令假设日志中 JSON 从第一行 `{` 开始到文件结束；如果提取结果为空或为 `null`，不要继续生成 trust bundle，先人工检查 `build-measurements.log`：

```bash
PCR8=$(sed -n '/^{/,$p' build-measurements.log | jq -r '.Measurements.PCR8')
PCR9=$(sed -n '/^{/,$p' build-measurements.log | jq -r '.Measurements.PCR9')
PCR11=$(sed -n '/^{/,$p' build-measurements.log | jq -r '.Measurements.PCR11')

printf 'PCR8=%s\nPCR9=%s\nPCR11=%s\n' "$PCR8" "$PCR9" "$PCR11"

test -n "$PCR8" && test "$PCR8" != "null"
test -n "$PCR9" && test "$PCR9" != "null"
test -n "$PCR11" && test "$PCR11" != "null"
```

生成 trust bundle：

```bash
cat > trust/aliyun-vtpm-trust.json <<EOF
{
  "profile": "aliyun-vtpm",
  "requirePlatformTrust": true,
  "expectedPcrs": {
    "sha256:8": "$PCR8",
    "sha256:9": "$PCR9",
    "sha256:11": "$PCR11"
  },
  "platformTrust": {
    "mode": "cert-chain",
    "rootCertificatesPem": [],
    "intermediateCertificatesPem": [],
    "rootFingerprintsSha256": [
      "870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f"
    ],
    "intermediateFingerprintsSha256": [
      "141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0"
    ],
    "enclaveSubjectCnPattern": "^i-[A-Za-z0-9][A-Za-z0-9-]*-[0-9]{2}$",
    "revocation": {
      "required": false,
      "method": "crl"
    }
  }
}
EOF
```

把 CA PEM 内容写入 trust bundle：

```bash
jq \
  --rawfile root trust/root-ca.crt \
  --rawfile ekmf trust/ekmf-ca.crt \
  '.platformTrust.rootCertificatesPem = [$root]
   | .platformTrust.intermediateCertificatesPem = [$ekmf]' \
  trust/aliyun-vtpm-trust.json \
  > trust/aliyun-vtpm-trust.with-ca.json

mv trust/aliyun-vtpm-trust.with-ca.json trust/aliyun-vtpm-trust.json
```

如果第 8 步看到真实 CN 不匹配默认 pattern，先按实际 CN 调整：

```bash
jq '.platformTrust.enclaveSubjectCnPattern = "^<YOUR_REAL_PATTERN>$"' \
  trust/aliyun-vtpm-trust.json > trust/tmp.json
mv trust/tmp.json trust/aliyun-vtpm-trust.json
```

## 10. 组装 full bundle 并验证

`verify-real-bundle.ts` 需要 request bytes、response bytes 和 proof。组装：

```bash
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture

REQ_B64=$(base64 -w0 out/request.bin)
RESP_B64=$(base64 -w0 out/response.bin)

jq -n \
  --arg req "$REQ_B64" \
  --arg resp "$RESP_B64" \
  --slurpfile proof out/tee.proof.json \
  '{requestBody_b64: $req, responseBody_b64: $resp, proof: $proof[0]}' \
  > out/bundle.json

NONCE_B64=$(grep '^nonce_b64=' out/metadata.txt | cut -d= -f2-)
```

如果 `base64 -w0` 不支持，改用：

```bash
REQ_B64=$(base64 out/request.bin | tr -d '\n')
RESP_B64=$(base64 out/response.bin | tr -d '\n')
```

运行 verifier：

```bash
cd ~/proof-of-observation/verifier
npm ci

npx tsx verify-real-bundle.ts \
  ../deploy/aliyun-vtpm-fixture/out/bundle.json \
  --trust ../deploy/aliyun-vtpm-fixture/trust/aliyun-vtpm-trust.json \
  --nonce-b64 "$NONCE_B64" \
  --host api.example.com
```

预期关键检查：

- `proof wire` 通过。
- `Evidence profile` 为 `aliyun-vtpm`。
- `QuoteReport 字段` 通过。
- `quote 结构` 通过。
- `quote 签名` 通过。
- `quote challenge` 通过。
- `PCRInfo` 通过。
- `PCR digest` 通过。
- `PCR allowlist` 通过。
- `sha256:8/9/11 比对` 通过。
- `平台证明链` 通过。
- `nonce 新鲜性` 通过。
- `响应签名` 通过。
- `请求绑定` 通过。

如果失败：

- `平台证明链` 失败：检查 CA 文件、fingerprint、CN pattern、证书有效期。
- `PCR allowlist` 或 `sha256:* 比对` 失败：检查 trust JSON 是否填了本次 EIF 的 PCR。
- `quote challenge` 失败：检查 `aliyun-proof` 和 verifier 是否同一分支、同一 challenge canonicalization。
- `nonce 新鲜性` 失败：检查 `--nonce-b64` 是否来自本次 `metadata.txt`。

## 11. 收集本次校准产物

建议保存：

```text
deploy/aliyun-vtpm-fixture/build-measurements.log
deploy/aliyun-vtpm-fixture/out/tee.proof.json
deploy/aliyun-vtpm-fixture/out/QuoteReport.Cert.der
deploy/aliyun-vtpm-fixture/out/QuoteReport.Cert.pem
deploy/aliyun-vtpm-fixture/out/metadata.txt
deploy/aliyun-vtpm-fixture/trust/aliyun-vtpm-trust.json
```

并记录：

- ECS 实例规格、地域、镜像。
- `enclave-cli` 版本。
- Docker 版本。
- Go 版本或 builder 镜像 digest。
- 当前 git commit。
- Docker base image digest。
- `QuoteReport.Cert` subject / issuer / serial / sha256 fingerprint。
- `PCR8/PCR9/PCR11`。

## 12. 停止 Enclave

```bash
sudo enclave-cli describe-enclaves
sudo enclave-cli terminate-enclave --enclave-id <EnclaveID>
sudo enclave-cli describe-enclaves
```

如果 CLI 使用的是 `stop-enclave` 而不是 `terminate-enclave`，按本机 `enclave-cli --help` 输出为准。

## 13. 当前版本不能证明的内容

这个 fixture 链路能证明：

- 当前 Enclave 环境可以生成真实阿里云 vTPM `QuoteReport`。
- verifier 能解析并验证真实 `QuoteReport.Cert`、quote、PCR、challenge、Ed25519 statement。
- 可以拿到真实 `QuoteReport.Cert` 样本，用来校准 CN pattern 和证书链。

这个 fixture 链路不能证明：

- 完整 streaming relay 已经接入。
- 用户真实请求已经在 Enclave 内终结上游 TLS。
- 上游响应已经边流式返回边 hash。
- CRL 已经被生产 verifier 检查。

完整生产链路还需要：

1. 在 Enclave 内实现或移植 streaming relay。
2. relay 读取 verifier/requester nonce，并传入 `proof.GenerateFromHashes`。
3. Enclave 内终结上游 TLS，验证上游证书。
4. 流式转发响应，同时增量计算 request/response hash。
5. 流末追加 `event: tee.proof`。
6. 用户侧用 `tee-verify-proxy --enforce --trust ... --nonce-header ...` 或离线 bundle verifier 做强校验。
7. 接入 CRL appraiser，或把 CRL 解析加入 Node verifier。
