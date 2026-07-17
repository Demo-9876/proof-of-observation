# 阿里云 Enclave runtime 部署与 fixture 校准 Runbook

本文分成两条互相独立的流程，避免把正式 runtime 部署和旧 fixture 校准混在一起：

- **流程 A：正式 runtime 部署**
  用于当前主路径。构建并运行 `deploy/aliyun-vtpm-runtime/`，Enclave 内启动 Rust relay + Go proof helper daemon，后续由父 VM relay adapter（例如 `ai-platform-newapi`）通过 `TEE Relay Frame Protocol v1` 调用。
- **流程 B：历史 fixture 校准**
  只用于重现早期真实硬件校准过程，拿 `QuoteReport.Cert` / TPM quote / PCR / verifier fixture。它会构建 `deploy/aliyun-vtpm-fixture/`，使用样本 request/response bytes 生成 proof，再通过 vsock tar 包发回父 VM。**这不是当前正式部署路径。**

当前版本状态：

- 已实现：正式阿里云 Enclave runtime，位于 `deploy/aliyun-vtpm-runtime/`，由 Rust relay、Go proof helper daemon 和阿里云 vTPM proof 生成逻辑组成。
- 已实现：Node verifier 的 `aliyun-vtpm` profile，可验证 quote 签名、challenge、PCR digest、PCR allowlist、`QuoteReport.Cert` root/intermediate 链和 Enclave EK CN。
- 已校准：真实阿里云 Enclave fixture 已完成端到端验证，Node verifier 对真实 `QuoteReport.Cert` / TPM quote / PCR / request-response binding 全部通过。
- 未实现：TypeScript 内置 CRL 解析。当前 verifier 可配置 `revocation.required=false` 先完成链路校准；生产前需要外部 CRL appraiser 或内置 CRL 检查。

## 0. 该走哪条流程

如果你的目标是部署当前可用的阿里云 Enclave proof-of-observation runtime：

```text
走流程 A：第 1 到第 5 节
```

如果你的目标是重新生成历史校准 fixture，或者排查 `QuoteReport.Cert` / TPM quote / verifier 解析问题：

```text
走流程 B：第 6 到第 15 节
```

不要把两条流程混用：

- 正式 runtime 不需要手工创建 `deploy/aliyun-vtpm-fixture/run.sh`。
- 正式 runtime 不需要在 Enclave 内用 `socat-vsock` 把 tar 包发回父 VM。
- fixture 流程不能证明真实用户请求已经经过完整 streaming relay。
- fixture 流程产生的 EIF / PCR 不应作为正式 runtime 的 trust bundle。

如果你只是要部署当前正式 runtime，可以跳过下一节校准记录，直接从 **第 1 节：通用前提** 开始执行。

## 校准记录（非部署步骤）：真实阿里云 Enclave fixture

本节记录 2026-07-16 前后在真实阿里云 Enclave 上完成的关键验证过程和结论，避免后续只看代码或 runbook 时丢失上下文。

### A.1 代码状态

当前阿里云 vTPM profile 相关关键提交：

```text
0aea403 feat: add aliyun vtpm evidence profile
4b0386f fix: calibrate aliyun vtpm verifier
c17829b fix: accept aliyun tpms attest wrapper
```

父 VM / Enclave fixture 使用当前分支 `feature/aliyun-vtpm-evidence-profile`。如果后续部署机器还停留在 `0aea403`，必须至少更新到包含 `4b0386f` 和 `c17829b` 的版本，否则真实 `QuoteReport.Quoted` 可能因为 `TPM2B_ATTEST` 包装解析失败。

### A.2 真实证书样本

从真实 fixture 的 `out/tee.proof.json` 提取 `QuoteReport.Cert`：

```bash
jq -r '.evidence.quote_report.cert_b64' out/tee.proof.json | base64 -d > out/QuoteReport.Cert.der
openssl x509 -inform DER -in out/QuoteReport.Cert.der -out out/QuoteReport.Cert.pem
openssl x509 -in out/QuoteReport.Cert.pem -noout \
  -subject \
  -issuer \
  -serial \
  -fingerprint -sha256
```

真实输出：

```text
subject= /C=CN/O=Aliyun/OU=TPM Endorsement Key Certificate/CN=i-bp124j9zt94mo16k7bu2-enclave-1
issuer= /C=CN/O=Aliyun/OU=Aliyun TPM Endorsement Key Manufacture CA/CN=Aliyun TPM EKMF CA
serial=0656B93ED9C6B7C962B6D0BB682AE880DC7F44
SHA256 Fingerprint=0D:05:89:D7:5A:CC:6C:86:2C:D5:59:03:E0:EB:D4:01:00:E7:0C:5D:68:11:97:E4:08:86:A6:15:12:C6:5B:C6
```

结论：

- `QuoteReport.Cert` 是可解析的 DER X.509 证书。
- 真实 Enclave vTPM EK CN 形态为 `i-<instance-id>-enclave-<index>`，当前默认 verifier pattern `^i-[A-Za-z0-9][A-Za-z0-9-]*-enclave-[0-9]+$` 与该样本匹配。
- Issuer 指向 `Aliyun TPM EKMF CA`，符合阿里云技术人员给出的 EKMF intermediate 方向。

### A.3 阿里云 TPM CA 与证书链

阿里云技术人员确认的 CA 文件：

```text
EK intermediate CA:
https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt

EK root CA:
https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt
```

已观察并写入 trust bundle 的 SHA-256 指纹：

```text
root-ca.crt = 870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f
ekmf-ca.crt = 141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0
```

真实 verifier 已验证：

- `QuoteReport.Cert` 能 chain 到上述阿里云 TPM root / EKMF intermediate。
- trust bundle 中的 root/intermediate fingerprint pin 生效。
- EK CN pattern 检查生效。

### A.4 QuoteReport.Quoted 格式校准

第一次在真实 fixture 上运行 verifier 时失败点为：

```text
❌ quote 结构 unexpected TPM magic: 0x91ff54
❌ quote 签名 QuoteReport.Cert public key 验证 quote signature 失败
❌ PCR digest quote 未解析，无法核对 PCR digest
```

排查结论：

- 阿里云 SDK 产出的 `QuoteReport.Quoted` 真实格式可能是 `TPM2B_ATTEST`，前 2 字节为 big-endian size，内部才是 `TPMS_ATTEST`。
- verifier 需要接受两种输入：
  - bare `TPMS_ATTEST`，开头 magic 为 `0xff544347`；
  - wrapped `TPM2B_ATTEST`，剥离 2 字节 size 后再按 `TPMS_ATTEST` 解析。
- TPM quote signature 验证必须覆盖内层 `TPMS_ATTEST` bytes。

修复后 verifier 输出包含：

```text
✅ QuoteReport 字段 quoted/signature/Cert DER 已解码，Cert 可解析为 X.509；quoted 为 TPM2B_ATTEST，已剥离 size 前缀
✅ quote 结构 TPMS_ATTEST quote 结构可解析
✅ quote 签名 QuoteReport.Cert public key 验证 quote signature 通过
```

### A.5 真实 fixture 完整验证命令

父 VM fixture 解包后组装 `bundle.json`，并用真实 nonce 运行 verifier：

```bash
cd ~/proof-of-observation/verifier

NONCE_B64=$(grep '^nonce_b64=' ../deploy/aliyun-vtpm-fixture/out/metadata.txt | cut -d= -f2-)

npx tsx verify-real-bundle.ts \
  ../deploy/aliyun-vtpm-fixture/out/bundle.json \
  --trust ../deploy/aliyun-vtpm-fixture/trust/aliyun-vtpm-trust.json \
  --nonce-b64 "$NONCE_B64" \
  --host api.example.com
```

最终真实硬件验证结果：

```text
── 真硬件 · 完整产品离线验证 (v2) ──
Evidence profile profile=aliyun-vtpm
QuoteReport 字段 quoted/signature/Cert DER 已解码，Cert 可解析为 X.509；quoted 为 TPM2B_ATTEST，已剥离 size 前缀
quote 结构 TPMS_ATTEST quote 结构可解析
quote 签名 QuoteReport.Cert public key 验证 quote signature 通过
quote challenge quote extraData == sha256(challenge_payload)
PCRInfo parsed
PCR selection Quote PCR selection == PCRInfo.PCRSelectionOut
PCR digest quote 内 PCR digest == PCRInfo.PCRValues 重算值
PCR allowlist required PCR allowlist contains sha256:8, sha256:9, sha256:11
sha256:8 / sha256:9 / sha256:11 均等于 allowlist
平台证明链 QuoteReport.Cert chains to Aliyun TPM root; EK CN=i-bp124j9zt94mo16k7bu2-enclave-1
nonce 新鲜性 proof.nonce == verifier/requester expectedNonce
上游 host 签名覆盖的上游 host == api.example.com(path /v1/messages)
响应签名 声明验签通过,且你收到的响应体哈希吻合
请求绑定 你发的请求体哈希 == 签名覆盖值
判定: ✅ 全过
```

该结果说明当前 `aliyun-vtpm` proof 生成核心和 Node verifier 已经完成真实硬件 fixture 校准。它仍不等价于“完整 streaming relay 已完成”，因为 fixture 的 request/response bytes 是样本数据，不是真实用户请求流。

## 1. 通用前提

父 VM 需要满足：

- 已购买支持 Enclave 的阿里云 ECS 实例。
- 已安装并可运行 `enclave-cli`。
- 已安装 Docker。
- 已安装 `git`，并已拉取当前分支代码到父 VM。
- 父 VM 上有 `jq`、`openssl`、`tar`、`base64`。

额外要求按流程区分：

- 流程 A 正式 runtime：
  - 不需要 fixture tar 包回传。
  - 后续真实请求链路需要父 VM 上有 egress proxy，例如 `socat-vsock` 或等价实现，把 Enclave 的 `CID=3:egress_port` 字节流转发到真实上游。
  - 后续与中转站联调请看 `docs/ai-platform-newapi-aliyun-enclave-deployment.md`。
- 流程 B 历史 fixture：
  - 父 VM 上必须有一个可用的 `socat-vsock`，用于 Enclave 将 fixture tar 包发回父 VM。
  - verifier 机器上需要 Node.js，并可安装/运行 `verifier` 目录依赖。

如果阿里云父 VM 没有 `git`，先安装：

```bash
command -v git || sudo yum install -y git
git --version
```

如果当前镜像的包管理器不是 `yum`，按系统实际情况改用对应命令，例如 `dnf install -y git` 或 `apt-get install -y git`。

拉取当前分支代码。首次部署时执行：

```bash
cd ~

git clone git@github.com:Demo-9876/proof-of-observation.git
cd proof-of-observation
git fetch origin feature/aliyun-vtpm-evidence-profile
git checkout feature/aliyun-vtpm-evidence-profile
git pull --ff-only origin feature/aliyun-vtpm-evidence-profile
```

如果父 VM 无法使用 GitHub SSH key，也可以临时改用 HTTPS：

```bash
git clone https://github.com/Demo-9876/proof-of-observation.git
```

如果仓库目录已经存在，更新到当前分支：

```bash
cd ~/proof-of-observation

git fetch origin feature/aliyun-vtpm-evidence-profile
git checkout feature/aliyun-vtpm-evidence-profile
git pull --ff-only origin feature/aliyun-vtpm-evidence-profile
```

确认代码版本。阿里云父 VM 上至少需要包含 `aliyun-vtpm` profile、真实 QuoteReport 校准和正式 runtime 相关提交：

```bash
git log --oneline -5
git rev-parse --short HEAD
```

基础环境检查：

```bash
sudo enclave-cli describe-enclaves
docker version
git --version
jq --version
openssl version
```

如果 `describe-enclaves` 返回 `[]`，说明当前没有运行中的 Enclave，这是正常的。

## 2. 流程 A：构建正式 runtime

正式 runtime 是当前主路径。它不再手工拼 `aliyun-proof` fixture，而是直接构建 `deploy/aliyun-vtpm-runtime/`。

构建镜像：

```bash
cd ~/proof-of-observation

sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

构建完成后，runtime 镜像内已经包含：

- Rust Enclave relay 可执行文件 `/attest`
- Go proof helper daemon `/usr/bin/aliyun-proof-helper`
- 启动脚本 `/run.sh`

如果构建失败在 `docker.io/library/golang` 或 `docker.io/library/rust`，并出现类似下面的错误：

```text
failed to resolve source metadata for docker.io/library/golang@sha256:...
Head "https://registry-1.docker.io/v2/library/golang/manifests/...": i/o timeout
```

这不是 Dockerfile 语法问题，而是父 VM 访问 Docker Hub 超时。正式 runtime 的 Dockerfile 默认钉死了 Go/Rust builder image digest；builder image 会影响最终 EIF/PCR，因此不要随意替换成来源不明的镜像。可选处理方式：

方式一，配置可信 Docker Hub mirror 后重试构建。使用阿里云控制台分配给当前账号的镜像加速地址，或企业内部可信 mirror：

```bash
sudo mkdir -p /etc/docker

sudo tee /etc/docker/daemon.json >/dev/null <<'JSON'
{
  "registry-mirrors": [
    "https://<your-trusted-dockerhub-mirror>"
  ]
}
JSON

sudo systemctl daemon-reload
sudo systemctl restart docker

sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

方式二，从能访问 Docker Hub 的可信环境拉取默认 builder 镜像并 `docker save`，上传到父 VM 后 `docker load`。这可以保留默认 digest pin：

```bash
docker pull docker.io/library/golang@sha256:98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d
docker pull docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5

docker save \
  docker.io/library/golang@sha256:98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d \
  docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5 \
  -o aliyun-vtpm-builder-images.tar

scp aliyun-vtpm-builder-images.tar <user>@<aliyun-parent-vm>:~/
```

父 VM 上执行：

```bash
sudo docker load -i ~/aliyun-vtpm-builder-images.tar

cd ~/proof-of-observation

sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

方式三，将这两个 builder 镜像同步到企业可信 ACR，并通过 build args 指定。注意：同步后的镜像版本必须记录到部署记录中，因为它会影响可复现构建和最终 PCR。

如果父 VM 已经能通过 `docker pull docker.io/library/golang@sha256:...` 或其它可信网络环境拉到 builder 镜像，可以按下面步骤上传到 ACR。以下示例中的 `<your-acr-registry>`、`<your-namespace>` 替换成实际 ACR 地址和命名空间：

```bash
export ACR_REGISTRY=<your-acr-registry>
export ACR_NAMESPACE=<your-namespace>

sudo docker image ls --digests | grep -E 'golang|rust'
```

Rust 官方镜像这里要特别注意：

- `sha256:19817ead3289c8c631c73df281e18b59b172f6a31f4f563290f69cddd06c30e9` 是 multi-arch OCI index。
- `sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5` 是该 index 下的 `linux/amd64` image manifest。
- `Platform: unknown/unknown` 且 `vnd.docker.reference.type: attestation-manifest` 的 digest 不是可运行镜像，不能用于 builder。
- 阿里云 Enclave 父 VM 是 `linux/amd64`，推送 ACR 和构建 runtime 时必须使用 `linux/amd64` builder 镜像。

登录 ACR。公网版一般是：

```bash
sudo docker login registry.cn-hangzhou.aliyuncs.com
```

企业版/专有实例或 VPC 地址按实际地址登录，例如：

```bash
sudo docker login <instance-id>-registry.cn-hangzhou.cr.aliyuncs.com
sudo docker login <instance-id>-registry-vpc.cn-hangzhou.cr.aliyuncs.com
```

给本地 Go builder digest 镜像打 ACR tag，并推送：

```bash
sudo docker tag \
  docker.io/library/golang@sha256:98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d \
  "$ACR_REGISTRY/$ACR_NAMESPACE/golang:amd64-sha256-98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d"

sudo docker push \
  "$ACR_REGISTRY/$ACR_NAMESPACE/golang:amd64-sha256-98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d"
```

Rust builder 也需要同样上传：

```bash
sudo docker pull docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5

sudo docker image inspect \
  docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5 \
  --format '{{.Os}}/{{.Architecture}}'

sudo docker tag \
  docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5 \
  "$ACR_REGISTRY/$ACR_NAMESPACE/rust:amd64-sha256-64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5"

sudo docker push \
  "$ACR_REGISTRY/$ACR_NAMESPACE/rust:amd64-sha256-64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5"
```

使用 ACR builder 镜像构建正式 runtime：

```bash
sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  --build-arg GO_BUILDER_IMAGE="$ACR_REGISTRY/$ACR_NAMESPACE/golang:amd64-sha256-98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d" \
  --build-arg GO_MODULE_PROXY=https://goproxy.cn,direct \
  --build-arg GO_SUMDB=sum.golang.google.cn \
  --build-arg RUST_BUILDER_IMAGE="$ACR_REGISTRY/$ACR_NAMESPACE/rust:amd64-sha256-64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5" \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

如果构建失败在 `go mod download`，并出现类似下面的错误：

```text
Get "https://proxy.golang.org/...": i/o timeout
```

说明父 VM 访问默认 Go module proxy 超时。使用上面的 `GO_MODULE_PROXY` / `GO_SUMDB` build args 后重试即可。默认 Dockerfile 仍使用官方 `https://proxy.golang.org,direct` 和 `sum.golang.org`；在国内网络构建时建议显式传：

```bash
--build-arg GO_MODULE_PROXY=https://goproxy.cn,direct
--build-arg GO_SUMDB=sum.golang.google.cn
```

不要直接设置 `GOSUMDB=off`，除非只是临时排查网络问题；关闭校验会降低依赖完整性保障。若后续构建继续卡在 Rust builder 的 `apt-get update`，说明父 VM 访问 Debian 源不稳定，需要给 Rust builder 配置可信 Debian mirror，或把已安装依赖的 Rust builder 镜像固化后推送到企业 ACR。

构建记录中至少保存：

- 原始 Docker Hub digest：
  - `docker.io/library/golang@sha256:98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d`
  - `docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5`
- ACR tag：
  - `$ACR_REGISTRY/$ACR_NAMESPACE/golang:amd64-sha256-98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d`
  - `$ACR_REGISTRY/$ACR_NAMESPACE/rust:amd64-sha256-64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5`
- `docker build` 使用的 `--build-arg`。
  - `GO_MODULE_PROXY`
  - `GO_SUMDB`
- 本次 `build-enclave` 输出的 PCR8/PCR9/PCR11。

## 3. 流程 A：构建 EIF 并记录 PCR

```bash
cd ~/proof-of-observation

export RUNTIME_IMAGE=proof-of-observation-aliyun-vtpm:latest
export RUNTIME_EIF=aliyun-vtpm-runtime.eif
```

构建 EIF：

```bash
cd ~/proof-of-observation

sudo enclave-cli build-enclave \
  --docker-dir . \
  --docker-uri "$RUNTIME_IMAGE" \
  --output-file "$RUNTIME_EIF" \
  | tee build-measurements.log
```

记录 `build-measurements.log` 中的 PCR8/PCR9/PCR11，并把它们写入用户侧 verifier trust bundle。注意：

- 每次改动 Dockerfile、Rust、Go helper、依赖、base image、构建工具版本后，都必须重新 `build-enclave`，记录新 PCR。
- debug mode 下 measurements 全零，不能作为生产 trust bundle。
- 正式 runtime 的 PCR 与历史 fixture EIF 的 PCR 不同，不能混用。

## 4. 流程 A：启动正式 runtime

```bash
cd ~/proof-of-observation

export RUNTIME_EIF=aliyun-vtpm-runtime.eif
```

启动：

```bash
sudo enclave-cli run-enclave \
  --cpu-count 2 \
  --memory 2048 \
  --eif-path "$RUNTIME_EIF"
```

记录输出中的 `EnclaveCID`，例如：

```text
"EnclaveCID": 4
```

确认运行中：

```bash
sudo enclave-cli describe-enclaves
```

正式 runtime 启动后会在 Enclave 内监听：

```text
业务 relay vsock port: 5005
metrics vsock port: 5006
```

下一步不在本文内继续展开：父 VM 上的中转站需要连接 `EnclaveCID:5005`，并提供 egress proxy。以 `ai-platform-newapi` 为例，继续阅读：

```text
docs/ai-platform-newapi-aliyun-enclave-deployment.md
```

## 5. 流程 A：正式 runtime 最小验收

最小验收项：

- `sudo enclave-cli describe-enclaves` 显示 Enclave `RUNNING`。
- `build-measurements.log` 已保存，并记录 PCR8/PCR9/PCR11。
- 用户侧 trust bundle 使用正式 runtime EIF 的 PCR，而不是 fixture EIF 的 PCR。
- 父 VM relay adapter 使用当前 `EnclaveCID` 和端口 `5005`。
- 父 VM egress proxy 已启动，`egress_port` 指向父 VM vsock 端口，而不是上游 HTTPS `443`。
- 真实请求通过 relay adapter 后，用户侧 verifier 能验证 `profile=aliyun-vtpm` 的 `tee.proof`。

下面开始的流程 B 仅用于历史 fixture 校准，不是当前主部署路径。

## 6. 流程 B：准备旧 fixture 变量

在父 VM 的仓库根目录执行：

```bash
cd ~/proof-of-observation

export IMAGE_NAME=proof-observation-aliyun-vtpm-fixture:latest
export EIF_FILE=aliyun-vtpm-fixture.eif
export OUT_TGZ=aliyun-vtpm-fixture.tgz
```

如果仓库路径不同，后续命令中的 `~/proof-of-observation` 替换为实际路径。
后续每打开一个新的父 VM 终端，都需要重新执行这些 `export`，或直接把命令中的变量替换为实际文件名。
fixture 流程中的 vsock 接收端口固定为 `5005`；如果要改端口，必须同时修改父 VM listener 和 Enclave 内 `run.sh` 的 `vsock-connect:3:5005`。

## 7. 流程 B：准备最小 fixture Enclave 镜像上下文

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

## 8. 流程 B：构建 fixture EIF 并记录 PCR

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

这些值只写入 fixture verifier trust bundle。注意：

- 构建工具版本、Docker base image、源码、依赖版本、Dockerfile、run.sh 都可能影响 PCR。
- 生产信任的 PCR 必须来自固定源码和固定构建环境，并记录可复现构建信息。
- 不要使用 debug mode 产生的 PCR 作为生产信任值。
- fixture EIF 的 PCR 不能用于正式 runtime trust bundle。

## 9. 流程 B：启动父 VM vsock 接收端

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

## 10. 流程 B：启动 fixture Enclave

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

等待第 9 节的 vsock listener 退出或当前目录出现文件：

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

## 11. 流程 B：提取真实 `QuoteReport.Cert`

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

你这次真实样本输出为：

```text
subject= /C=CN/O=Aliyun/OU=TPM Endorsement Key Certificate/CN=i-bp124j9zt94mo16k7bu2-enclave-1
issuer= /C=CN/O=Aliyun/OU=Aliyun TPM Endorsement Key Manufacture CA/CN=Aliyun TPM EKMF CA
serial=0656B93ED9C6B7C962B6D0BB682AE880DC7F44
SHA256 Fingerprint=0D:05:89:D7:5A:CC:6C:86:2C:D5:59:03:E0:EB:D4:01:00:E7:0C:5D:68:11:97:E4:08:86:A6:15:12:C6:5B:C6
```

需要确认：

- `Subject CN` 是否符合 Enclave vTPM 格式，例如 `i-xxxxxxx-enclave-1`。
- `Issuer` 是否指向阿里云 TPM EKMF intermediate。
- 证书能否被 Node verifier 解析。
- 如果 CN 格式与当前默认 pattern 不一致，需要更新 trust bundle 的 `enclaveSubjectCnPattern`。

## 12. 流程 B：准备 fixture verifier trust bundle

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

生成 fixture trust bundle：

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
    "enclaveSubjectCnPattern": "^i-[A-Za-z0-9][A-Za-z0-9-]*-enclave-[0-9]+$",
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

如果第 11 节看到真实 CN 不匹配默认 pattern，先按实际 CN 调整：

```bash
jq '.platformTrust.enclaveSubjectCnPattern = "^<YOUR_REAL_PATTERN>$"' \
  trust/aliyun-vtpm-trust.json > trust/tmp.json
mv trust/tmp.json trust/aliyun-vtpm-trust.json
```

## 13. 流程 B：组装 fixture full bundle 并验证

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

运行 verifier 前需要 Node.js / npm。注意：`npm` 只用于用户侧 verifier 校验；前面生成 Enclave fixture、提取 `QuoteReport.Cert` 不依赖 npm。

Alibaba Cloud Linux 2 / CentOS 7 系父 VM 通常是 glibc 2.17，官方 Node 20/22 Linux x64 预编译包可能无法运行。如果看到下面错误，不要升级系统 glibc：

```text
node: /lib64/libstdc++.so.6: version `GLIBCXX_3.4.21' not found
node: /lib64/libm.so.6: version `GLIBC_2.27' not found
node: /lib64/libc.so.6: version `GLIBC_2.28' not found
```

这种情况下推荐把 fixture 产物拷回本地有 Node.js/npm 的机器验证，而不是在父 VM 上安装 Node：

```bash
# 在父 VM 上打包 verifier 输入
cd ~/proof-of-observation/deploy/aliyun-vtpm-fixture
tar czf aliyun-vtpm-verifier-inputs.tgz out trust build-measurements.log

# 在本地机器拉回。按实际跳板机/SSH 方式调整 scp 命令。
scp <user>@<aliyun-parent-vm>:~/proof-of-observation/deploy/aliyun-vtpm-fixture/aliyun-vtpm-verifier-inputs.tgz .
```

本地解包后，在本地仓库执行本节的 verifier 命令，路径按实际解包目录调整。

如果必须在父 VM 上运行 verifier，不要使用官方 Node 22 包。先检查 glibc：

```bash
ldd --version | head -1
```

glibc 2.17 环境需要使用兼容 glibc-217 的 Node 构建，例如 unofficial build。该方式只用于验证工具链，不进入 Enclave 镜像、不作为 TCB：

```bash
command -v node || true
command -v npm || true

cd /tmp

curl -L \
  https://unofficial-builds.nodejs.org/download/release/v20.19.0/node-v20.19.0-linux-x64-glibc-217.tar.xz \
  -o node-v20.19.0-linux-x64-glibc-217.tar.xz

command -v xz || sudo yum install -y xz
sudo tar -C /opt -xJf node-v20.19.0-linux-x64-glibc-217.tar.xz

export PATH=/opt/node-v20.19.0-linux-x64-glibc-217/bin:$PATH
node -v
npm -v
```

如果需要后续 shell 也能直接使用 `node` / `npm`，把 PATH 写入当前用户 shell 配置：

```bash
echo 'export PATH=/opt/node-v20.19.0-linux-x64-glibc-217/bin:$PATH' >> ~/.bashrc
```

确认 `npm` 可用后运行 verifier：

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

## 14. 流程 B：收集本次 fixture 校准产物

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

## 15. 停止 Enclave

```bash
sudo enclave-cli describe-enclaves
sudo enclave-cli terminate-enclave --enclave-id <EnclaveID>
sudo enclave-cli describe-enclaves
```

如果 CLI 使用的是 `stop-enclave` 而不是 `terminate-enclave`，按本机 `enclave-cli --help` 输出为准。

## 16. fixture 校准链路不能证明的内容

这个 fixture 链路能证明：

- 当前 Enclave 环境可以生成真实阿里云 vTPM `QuoteReport`。
- verifier 能解析并验证真实 `QuoteReport.Cert`、quote、PCR、challenge、Ed25519 statement。
- 可以拿到真实 `QuoteReport.Cert` 样本，用来校准 CN pattern 和证书链。

这个 fixture 链路不能证明：

- 完整 streaming relay 已经接入。
- 用户真实请求已经在 Enclave 内终结上游 TLS。
- 上游响应已经边流式返回边 hash。
- CRL 已经被生产 verifier 检查。

正式 runtime 链路应继续验证：

1. Rust relay 是否按标准 frame protocol 接收真实用户请求。
2. relay 是否读取 verifier/requester nonce，并传给 Go proof helper。
3. Enclave 内是否终结上游 TLS，并验证上游证书。
4. 响应是否边流式转发边增量计算 `response_body_sha256`。
5. 流末是否追加 `event: tee.proof` 或等价 `RESP_TRAILER`。
6. 用户侧是否用 `tee-verify-proxy --enforce --trust ... --nonce-header ...` 或离线 bundle verifier 做强校验。
7. 生产 verifier 是否接入 CRL appraiser，或把 CRL 解析加入 Node verifier。
