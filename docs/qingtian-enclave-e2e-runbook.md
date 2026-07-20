# QingTian Enclave End-to-End Runbook

本文档记录在真实 Huawei Cloud QingTian Enclave 机器上验证正式 `proof-of-observation` 业务镜像的端到端步骤。

目标：

- 构建 QingTian 业务 Docker image。
- 使用官方 `qt enclave make-img --private-key --signing-certificate` 路径生成 signed EIF。
- 在 normal mode 启动 QingTian Enclave。
- 通过现有父虚机 relay 发起真实业务请求，并返回与 Nitro 版兼容的 `tee.proof`。
- 使用 Node CLI verifier 完成 QingTian QTSM evidence、PCR0/PCR8、公钥、nonce、statement 签名和响应字节 hash 校验。
- 采集后续 release manifest 需要的发布材料。

## 1. 前置假设

示例命令假设：

- 父虚机用户：`ansible`
- 仓库目录：`~/proof-of-observation`
- 分支：`feature/qingtian-enclave-technical-plan`
- QingTian enclave CID：`4`
- Enclave control port：`5005`
- QingTian parent CID：`3`
- 系统：Huawei Cloud EulerOS 2.0

如果你的机器或 relay 配置不同，只替换对应变量，不改变 proof wire 协议。

## 2. 基础环境确认

```bash
hostname
date -Iseconds
cat /etc/os-release
uname -a
lscpu | grep -E 'Architecture|CPU\(s\)|Model name|NUMA'

docker version
qt enclave -h
qt enclave query
systemctl status qt-enclave-env.service --no-pager -l
```

如有旧 enclave，先停掉：

```bash
qt enclave query
qt enclave stop --enclave-id 0 2>/dev/null || true
qt enclave query
```

如普通用户执行 `qt` 遇到日志权限问题，修复：

```bash
sudo mkdir -p /var/run/enclave /var/log/qingtian_enclaves
sudo chown -R "$USER:$USER" /var/run/enclave /var/log/qingtian_enclaves
sudo chmod 755 /var/run/enclave /var/log/qingtian_enclaves
sudo chmod 644 /var/log/qingtian_enclaves/qingtian-tool.log 2>/dev/null || true
```

## 3. 准备仓库和 QingTian SDK

```bash
cd ~
git clone https://github.com/Demo-9876/proof-of-observation.git
cd ~/proof-of-observation

git fetch origin
git checkout feature/qingtian-enclave-technical-plan

mkdir -p third_party
git clone https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git third_party/qingtian-sdk
git -C third_party/qingtian-sdk rev-parse HEAD
test -f third_party/qingtian-sdk/enclave/qtsm/lib/Makefile
```

建议固定到已校准过的 SDK commit：

```bash
git -C third_party/qingtian-sdk checkout 516a3f4531d0ff6cbde6e19764fb6319650b9fc5
```

正式发布时，release manifest 必须记录 SDK commit 或 tarball hash。

## 4. 准备 EIF 签名材料

正式发布应使用项目方固定 release key/cert。先验证私钥和证书匹配：

```bash
openssl x509 -in server.pem -pubkey -noout > /tmp/qingtian-cert.pub
openssl pkey -in private-key.pem -pubout > /tmp/qingtian-key.pub
diff /tmp/qingtian-cert.pub /tmp/qingtian-key.pub
```

`diff` 无输出才继续。

仅用于本次端到端临时验证时，可以生成测试签名材料：

```bash
openssl ecparam -out private-key.pem -name secp384r1 -genkey
openssl req -new -key private-key.pem -out qingtian.csr \
  -subj "/CN=proof-of-observation-qingtian-e2e"
openssl x509 -req -days 3650 -in qingtian.csr \
  -signkey private-key.pem -out server.pem
```

不要把测试 key/cert 用作生产发布材料。

## 5. 配置 QingTian 构建参数

```bash
cp deploy/qingtian-runtime/qingtian.env.example deploy/qingtian-runtime/qingtian.env

cat > deploy/qingtian-runtime/qingtian.env <<'EOF'
QINGTIAN_IMAGE=proof-observation-qingtian:e2e
QINGTIAN_EIF=proof-observation-qingtian.e2e.signed.eif
QINGTIAN_CID=4
QINGTIAN_CPUS=2
QINGTIAN_MEM=4096
QINGTIAN_PARENT_CIDS=3
QTSM_SDK_DIR=third_party/qingtian-sdk
APT_MIRROR=https://repo.huaweicloud.com/debian
CARGO_REGISTRY_MIRROR=sparse+https://rsproxy.cn/index/
QINGTIAN_PRIVATE_KEY=private-key.pem
QINGTIAN_SIGNING_CERTIFICATE=server.pem
QINGTIAN_START_EXTRA_ARGS=
EOF
```

`QINGTIAN_PARENT_CIDS` 会被写入 EIF 环境变量并影响 `PCR0`。生产发布时必须固定并记录。

`CARGO_REGISTRY_MIRROR` 只影响 Docker 构建阶段的 Rust 依赖下载，不会写入最终运行镜像；如果 ECS 能直接访问 `index.crates.io`，可以留空。

## 6. 构建 Docker Image、生成 Signed EIF、启动 Enclave

```bash
bash deploy/qingtian-runtime/run.sh deploy/qingtian-runtime/qingtian.env \
  | tee qingtian-e2e-build-start.log
```

确认 enclave 运行中：

```bash
qt enclave query | tee qingtian-e2e-query.log
qt enclave query-eif --eif proof-observation-qingtian.e2e.signed.eif \
  | tee qingtian-e2e-query-eif.log
```

检查点：

- `qt enclave query` 返回 `Status: Running`。
- `query-eif` 输出 `PCR0` 和 `PCR8`。
- `PCR8` 必须非 0；如果为全 0，说明 EIF 没有按签名路径生成。

## 7. 生成 QingTian Trust Config

将 `qingtian-e2e-query-eif.log` 中的 `PCR0` / `PCR8` 替换到下面模板：

```bash
cat > qingtian-trust.e2e.json <<'EOF'
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "<PCR0_FROM_QUERY_EIF>",
    "sha384:8": "<PCR8_FROM_QUERY_EIF>"
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

Huawei QingTian root 来源：

```text
https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip
zip sha256: 99e9203a64cfb0c6495afd815051e97bea8a37895dc083d715674af64adeadfe
root sha256 fingerprint: F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581
```

可用命令复核：

```bash
curl -L -o huawei_qingtian-enclaves_root-G1.zip \
  https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip
sha256sum huawei_qingtian-enclaves_root-G1.zip
unzip -o huawei_qingtian-enclaves_root-G1.zip
openssl x509 -in root.pem -noout -subject -issuer -dates -fingerprint -sha256
```

## 8. 启动现有父虚机 Relay

使用 Nitro 版同一套 relay，只需要把 enclave 目标改成 QingTian：

```bash
export TEE_ENCLAVE_CID=4
export TEE_ENCLAVE_PORT=5005
export TEE_EVIDENCE_PROFILE=qingtian
export TEE_TRUST_CONFIG="$PWD/qingtian-trust.e2e.json"

# 使用你的现有 relay 启动命令；关键是连接 cid=4 port=5005。
# 示例：
# ./relay --enclave-cid 4 --enclave-port 5005 ...
```

如果现有 relay 有 egress-vsock 监听配置，保持 Nitro 版相同端口即可。enclave 会根据 request head 中的 `egress_port` 连接父虚机，默认 parent CID 为 `3`。

## 9. 发真实业务请求并保存完整响应

流式 SSE：

```bash
curl -N https://<你的-relay-domain>/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -d '{
    "model": "<model>",
    "max_tokens": 64,
    "stream": true,
    "messages": [{"role":"user","content":"Say hello from QingTian e2e"}]
  }' \
  > response.qingtian.e2e.sse
```

非流式 multipart：

```bash
curl -sS https://<你的-relay-domain>/v1/messages \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "x-wokey-tee-proof-mode: multipart" \
  -d '{
    "model": "<model>",
    "max_tokens": 64,
    "stream": false,
    "messages": [{"role":"user","content":"Say hello from QingTian multipart e2e"}]
  }' \
  > response.qingtian.e2e.multipart
```

确认响应里有 proof：

```bash
grep -a 'tee.proof' response.qingtian.e2e.sse | tail -n 2
grep -a '"profile":"qingtian"' response.qingtian.e2e.sse response.qingtian.e2e.multipart
```

如果没有 `tee.proof` 或 proof 中没有 `"profile":"qingtian"`，先排查 relay 是否连接到 QingTian enclave、是否启用了 proof 模式、以及 enclave 日志。

## 10. 使用 Node CLI Verifier 验证

```bash
cd verifier
npm ci
```

验证流式响应：

```bash
npx tsx tee-verify-stream.ts ../response.qingtian.e2e.sse \
  --trust ../qingtian-trust.e2e.json \
  | tee ../verify-qingtian-e2e-sse.log
```

验证 multipart 响应：

```bash
npx tsx tee-verify-stream.ts ../response.qingtian.e2e.multipart \
  --trust ../qingtian-trust.e2e.json \
  | tee ../verify-qingtian-e2e-multipart.log
```

期望关键检查通过：

- `QingTian evidence 格式`
- `QingTian COSE 签名`
- `QingTian 证书链`
- `PCR0 比对`
- `PCR8 比对`
- `公钥绑定`
- `nonce 绑定`
- `响应签名`

任一失败都不要发布该 PCR/EIF。

## 11. 采集发布材料

```bash
cd ~/proof-of-observation

sha256sum proof-observation-qingtian.e2e.signed.eif \
  | tee qingtian-eif-sha256.txt

docker image inspect proof-observation-qingtian:e2e \
  > qingtian-image-inspect.json

docker run --rm --entrypoint sha256sum proof-observation-qingtian:e2e \
  /attest /usr/local/lib/libqtsm.so \
  | tee qingtian-runtime-sha256.txt

git rev-parse HEAD | tee source-revision.txt
git -C third_party/qingtian-sdk rev-parse HEAD | tee qingtian-sdk-revision.txt

qt enclave query-eif --eif proof-observation-qingtian.e2e.signed.eif \
  | tee qingtian-release-pcrs.json
```

建议归档：

```text
qingtian-e2e-build-start.log
qingtian-e2e-query.log
qingtian-e2e-query-eif.log
qingtian-trust.e2e.json
response.qingtian.e2e.sse
response.qingtian.e2e.multipart
verify-qingtian-e2e-sse.log
verify-qingtian-e2e-multipart.log
qingtian-eif-sha256.txt
qingtian-image-inspect.json
qingtian-runtime-sha256.txt
source-revision.txt
qingtian-sdk-revision.txt
qingtian-release-pcrs.json
```

## 12. 成功判定

满足以下条件后，可以认为 QingTian 正式业务镜像端到端闭环：

- signed EIF normal mode 启动成功。
- `PCR8` 非 0。
- 真实业务请求返回与 Nitro 版兼容的 `tee.proof`。
- proof 中 `profile` 为 `qingtian`。
- Node CLI verifier 使用 `qingtian-trust.e2e.json` 验证 SSE 和 multipart 均通过。
- 发布材料包含 source revision、SDK revision、Docker image digest、EIF sha256、PCR0、PCR8、trust config 和完整 proof bundle。
