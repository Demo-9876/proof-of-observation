# QingTian Enclave Migration Design

本文是 `proof-of-observation` 从 AWS Nitro Enclave 扩展到 Huawei Cloud QingTian Enclave 的改造技术方案。

目标不是替换现有 Nitro 实现，而是在保留现有完整能力的前提下新增 QingTian Enclave 部署能力。改造完成后：

- 现有 AWS Nitro Enclave 构建、运行、验证和文档链路继续可用。
- QingTian Enclave 部署对外提供的接口能力与当前 Nitro 部署保持一致。
- 已经接入过 Nitro 版 `proof-of-observation` 的第三方中转站，原则上不需要调整 relay-facing HTTP / stream / proof 交付协议即可接入 QingTian 部署。
- verifier 能根据 evidence profile 校验不同云厂商的远程证明，但应用层 proof、Ed25519 签名声明和响应字节绑定保持同一套语义。

相关前置验证记录见 [`docs/qingtian-enclave-validation-notes.md`](qingtian-enclave-validation-notes.md)。该记录只保留已确认支持 Enclave 的 Huawei Cloud EulerOS 2.0 机器验证结果。

真实 QingTian 机器上的正式业务镜像端到端验证步骤见 [`docs/qingtian-enclave-e2e-runbook.md`](qingtian-enclave-e2e-runbook.md)。

本方案引用的官方资料：

- QingTian Enclave 应用开发主入口：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1414.html`
- QingTian Enclave 密码学证明：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1411.html`
- QingTian attestation document 签名验证：`https://support.huaweicloud.com/usermanual-ecs/ecs_03_1412.html`
- QingTian SDK：`https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian/tree/master/enclave`

## 1. 背景与约束

### 1.1 当前 Nitro 版能力边界

当前仓库的核心信任链是：

```text
AWS Nitro root
  -> Nitro attestation COSE / certificate chain
  -> PCR0 image measurement
  -> attested Ed25519 public key + nonce
  -> tee-exchange-v2 statement signature
  -> request/response body digest + signed upstream facts
```

飞地内 Rust 程序负责：

1. 通过 vsock 接收父虚机 relay 发来的请求头、请求体和 nonce。
2. 在飞地内建立到上游 API 的 TLS 连接。
3. 逐块回传上游响应，同时计算响应体 SHA-256。
4. 用飞地内启动时生成的 Ed25519 私钥签署 `tee-exchange-v2` statement。
5. 调用 Nitro NSM attestation，把同一把 Ed25519 公钥和同一个 nonce 放进硬件证明。
6. 通过原有 `RESP_TRAILER` 帧把 proof JSON 回传给父虚机。

父虚机和客户端看到的 proof 交付形态是：

- 流式响应：末尾追加 `event: tee.proof`。
- 非流式 proof mode：`multipart/mixed`，第一段是 raw response bytes，第二段是 proof JSON。
- verification：客户端/CLI/browser 剥离 proof 后，对剩余响应字节重新计算哈希并校验 proof。

这些接口能力是本次 QingTian 改造必须保持的兼容面。

### 1.2 当前代码中的 Nitro 耦合点

当前 `enclave/src/main.rs` 中存在直接 Nitro 耦合：

- 直接依赖 `aws_nitro_enclaves_nsm_api`。
- `attest()` 调用 `Request::Attestation`。
- `write_attested_trailer()` 直接生成 Nitro attestation，并把结果写入 `attestation` 字段。
- worker 上下文中保存 `nsm_fd` / `nsm_lock`。

当前 verifier 中存在直接 Nitro 耦合：

- `verifier/tee-verify-core.ts` 默认直接调用 `verify-attestation-cose.mjs`。
- `AttestationVerdict` 命名和检查项固定描述为 AWS Nitro root / PCR0。
- `verifier/verify-attestation-cose.mjs` 是 Nitro COSE_Sign1 + AWS Nitro root 的专用实现。

### 1.3 参考分支

远端分支 `origin/feature/aliyun-vtpm-evidence-profile` 已经完成一轮阿里云 Enclave vTPM profile 化改造，可以作为本次设计参考。

该分支的关键思路：

- 在 verifier 侧引入 `EvidenceProfileVerifier` / `EvidenceTrust` 抽象。
- 将 Nitro 验证移动到 `evidence-nitro.ts`。
- 新增阿里云 profile 的独立 evidence verifier。
- proof wire 中新增可选 `profile` 字段；历史 Nitro proof 缺省视为 `nitro`。
- 应用层 `tee-exchange-v2` statement、Ed25519 签名、响应 hash 绑定保持不变。
- 飞地侧把“生成 profile-specific evidence/proof”的能力从主代理逻辑中抽出来。

QingTian 改造应沿用这个分层方式，但 QingTian 证据形态不同于阿里云 vTPM：QingTian 使用 QTSM 设备返回的 COSE/CBOR attestation document，而不是 TPM quote。

## 2. 已验证的 QingTian 事实

以下事实来自支持 Enclave 的华为云机器 `ansible@shihuo-enclave-hw02`，宿主机系统为 Huawei Cloud EulerOS 2.0。

已验证：

- HCE 2.0 父虚机可以安装并运行 QingTian Enclave 相关组件。
- Docker 18.09.0 可配合 `qt enclave make-img` 完成 smoke 镜像到 EIF 的构建。
- `qt enclave start` 可启动 debug 和 normal / production 模式 enclave。
- debug 模式可通过 console 观察输出。
- normal / production 模式没有 console，应通过 vsock 回传输出和证明材料。
- enclave 内 QTSM 设备可用，`qtsm_get_attestation` 可以返回 attestation document。
- production 模式下已通过 vsock 从 enclave 回传 attestation sample。
- 已通过华为官方 `make-img --private-key --signing-certificate` 路径生成可启动 signed EIF，并取得非 0 `PCR8`。
- 已取得绑定真实 Ed25519 SPKI DER public key 与 32 字节 nonce 的 official-signed QTSM fixture。
- Node verifier 已基于该 fixture 完成 QingTian COSE/CBOR 解析、证书链、COSE 签名、PCR0/PCR8、公钥和 nonce 校验。
- `CMD ["/root/run_attest_vsock.sh"]` 这类直接脚本入口可稳定运行；`CMD ["sh", "-c", "..."]` 在前序 smoke 中表现不稳定，应避免作为生产入口模式。

早期 production smoke 样本：

```text
EIF: qt-attest-vsock.eif
digest: SHA384
PCR0: be0555479ab87dd7c50800c4f1fca30cffb20e483771285a8ed7c2046708e1d0cc7dbf58429dd6a76c952b4e6b1ffe4b
PCR8: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
launch_mode: production
nonce: poo-qingtian-nonce-prod-001
pubkey: poo-public-key-placeholder
user_data: poo-qingtian-user-data-prod-001
COSE size: 4942
COSE SHA256: 09131035d3d5f8b99fdbd6a6458585e992cc3bb6cc6738f72dd145c5dc60bf0b
```

注意：

- 上述 smoke 样本的 `pubkey` 是 placeholder，不是 `proof-of-observation` 真实 Ed25519 公钥。
- 上述 EIF 未签名，所以 `PCR8` 为全 0，仅可用于开发 smoke，不可作为生产信任策略。
- 生产 verifier 正例应优先使用 official-signed fixture 或正式业务镜像采集结果。

已取得的 official-signed fixture：

```text
EIF: qt-qtsm-fixture.official-signed.eif
launch_mode: normal
digest: SHA384
PCR0: 74d6c5fa10418d50e62c5e0422b868a5912d664c7721a9742e2ffdae3ec49c6a4030e3a1f73c37c5ccd297730a77ec89
PCR8: 5d130027a732cb97a378d0dd0563b7a1e43cb220699a2739870558753fb5620bb71e7c9053310aee01ec50c00f502e03
nonce_b64: oFZzAsbVdJowTthtuz7U7/bdnU58V163ytEbxVz9VZI=
public_key_spki_b64: MCowBQYDK2VwAyEA1JXf/Ijtcl5W+VsW5aByVdey3y5m7yFuR8vdrjFk2Mc=
attestation_sha256: ec62dc507e87c99c93306f1c83ce951e01a52618c4f0c73cd3cb5ffdd12a316a
```

证书链 root fingerprint：

```text
F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581
```

## 3. 目标架构

### 3.1 分层目标

改造后的信任链按两层拆分：

```text
应用层 proof，跨云保持一致
  tee-exchange-v2 statement
  Ed25519 signing key
  nonce
  upstream host/path/method/status/content-type
  request_body_sha256
  response_body_sha256

Evidence profile，按云厂商切换
  nitro: AWS Nitro NSM COSE attestation
  qingtian: Huawei QingTian QTSM COSE attestation
  aliyun-vtpm: Alibaba Cloud vTPM quote，参考分支已有实验实现
```

这样客户端最终校验逻辑保持不变：

1. 验证 evidence profile 的硬件证明和测量值。
2. 确认证明中绑定的 Ed25519 公钥等于 proof 顶层 `public_key`。
3. 确认证明中绑定的 nonce 等于 proof 顶层 `nonce`。
4. 用 `public_key` 验证 `tee-exchange-v2` statement 签名。
5. 对请求/响应字节重算哈希并与 statement 覆盖字段比对。

### 3.2 QingTian 信任链

QingTian 目标信任链：

```text
Huawei QingTian attestation root / certificate chain
  -> QTSM attestation COSE signature
  -> QTSM attestation payload
  -> PCR0 / PCR8 measurements
  -> attested Ed25519 public key + nonce
  -> tee-exchange-v2 statement signature
  -> request/response body digest + signed upstream facts
```

QTSM API 绑定字段：

```c
qtsm_get_attestation(
  fd,
  user_data, user_data_len,
  nonce, nonce_len,
  pubkey, pubkey_len,
  out_buf, out_len
)
```

业务实现应使用：

- `nonce`: proof 顶层 `nonce` 解码后的原始字节。
- `pubkey`: 飞地内 Ed25519 public key 的 SPKI DER 字节，与 proof 顶层 `public_key` 完全一致。
- `user_data`: 可选，建议第一阶段为空或填入 profile/version 诊断数据，不参与应用层强绑定。

v1 QingTian profile 不把 `user_data` 纳入安全绑定。后续如果要使用 `user_data` 承载额外业务声明，必须先更新 `docs/evidence-profile-qingtian.md`、新增测试向量，并明确它与 `tee-exchange-v2` statement 的关系；不能在实现里临时把未规范化字段加入 trust path。

### 3.3 对外接口兼容性

父虚机 relay 与飞地之间保持现有帧协议：

- `REQ_HEAD`
- `REQ_BODY`
- `RESP_HEAD`
- `RESP_CHUNK`
- `RESP_TRAILER`
- `ERR`
- `STATS`

父虚机 relay 对客户端保持现有 HTTP 交付方式：

- SSE 流末 `event: tee.proof` 不改名。
- multipart proof part 的 content type / disposition 兼容当前实现。
- `proof_unavailable` 降级语义不变。

proof JSON 保持现有字段，并新增兼容字段：

```json
{
  "v": 2,
  "profile": "qingtian",
  "alg": "ed25519",
  "public_key": "<base64 SPKI>",
  "nonce": "<base64>",
  "upstream_host": "api.example.com",
  "upstream_path": "/v1/messages",
  "http_method": "POST",
  "http_status": 200,
  "resp_content_type": "text/event-stream",
  "request_body_sha256": "<hex>",
  "response_body_sha256": "<hex>",
  "signature": "<base64 Ed25519 signature>",
  "attestation": "<base64 QingTian QTSM COSE evidence>",
  "pcr0": "<optional advisory PCR0>",
  "pcr8": "<optional advisory PCR8>"
}
```

兼容规则：

- 历史 Nitro proof 可以不带 `profile`，verifier 缺省按 `nitro` 处理。
- QingTian proof 必须带 `profile: "qingtian"`，避免 verifier 把 QingTian COSE 误送 Nitro 解析器。
- `attestation` 字段继续承载 base64 evidence，保持现有 relay 只透传 JSON 的能力。
- `pcr0` / `pcr8` 顶层字段只作展示或诊断，可信值必须来自已验证的 attestation payload。

对“之前接入过 AWS Nitro Enclave 的中转站不需要改造”的解释：

- 如果中转站只负责把请求转给飞地、把响应和 proof 透传给客户端，则无需改造。
- 如果中转站自己硬编码解析 Nitro attestation 或硬编码要求 `profile` 缺失，则需要升级 verifier/配置。这属于 verifier 端信任策略变化，不应影响 relay-facing 传输协议。
- 本仓库提供的 parent relay / proxy 应通过配置选择 `nitro` 或 `qingtian` 运行时，默认保持 Nitro 行为。
- “无需改造”只承诺 HTTP 接入协议、proof 交付形态和 relay 透传语义不变；部署编排层仍需要从 Nitro CLI 切换到 `qt enclave`，包括 EIF 生成/签名、CID、CPU/hugepage 资源预留和 QingTian 日志/设备权限处理。

## 4. Enclave 侧改造方案

### 4.1 Evidence provider 抽象

新增飞地内 evidence provider 抽象，避免主业务逻辑继续依赖某一家云厂商 SDK。

建议接口形态：

```rust
trait EvidenceProvider: Send + Sync {
    fn profile(&self) -> &'static str;

    fn attest(
        &self,
        public_key_spki_der: &[u8],
        nonce: &[u8],
    ) -> Result<Evidence, String>;
}

struct Evidence {
    profile: &'static str,
    attestation: Vec<u8>,
    measurements: BTreeMap<String, String>,
}
```

第一阶段可以更保守，只让 provider 返回：

```rust
struct Evidence {
    profile: &'static str,
    attestation: Vec<u8>,
    pcr0: Option<String>,
    pcr8: Option<String>,
}
```

`write_attested_trailer()` 不再直接调用 NSM，而是：

1. 构造并签名 `tee-exchange-v2` statement。
2. 调用当前 provider 的 `attest(spki, nonce)`。
3. 根据 provider 返回值组装 proof JSON。

### 4.2 Nitro provider

将现有 Nitro 逻辑原样迁移到 `NitroEvidenceProvider`：

- 保留 `nsm_init()`。
- 保留 `nsm_fd`。
- 保留 `nsm_lock`，避免并发调用 NSM 的不确定问题。
- 保留 `Request::Attestation { user_data: None, nonce, public_key }`。
- 保留现有 Nitro proof 字段形态，`profile` 可暂不输出或输出 `"nitro"`。

验收要求：

- 不改动现有 Nitro 构建脚本语义。
- 现有 Nitro verifier fixture 和单测继续通过。
- Nitro 部署生成的旧 proof 仍能被旧 verifier 和新 verifier 校验。

### 4.3 QingTian provider

QingTian provider 负责在 enclave 内调用 QTSM library。

推荐实现路径：

1. 在 `enclave/` 中新增 `qingtian` feature。
2. 新增 `enclave/src/evidence_qingtian.rs`。
3. 使用 Rust FFI 链接 QTSM C library，或封装一个极小 C helper 后由 Rust 调用。
4. provider 初始化时打开 QTSM 设备并保存 fd。
5. 每次 proof trailer 生成时调用 `qtsm_get_attestation()`。

实现时必须先固定 feature gating：

- `nitro` 和 `qingtian` provider 应是互斥运行时 profile，避免同一个 enclave 二进制同时初始化 NSM 和 QTSM。
- 默认 feature 保持当前 Nitro 行为；只有显式构建 QingTian 镜像时才启用 `qingtian`。
- QingTian 构建不应要求 AWS Nitro NSM 运行时库存在；Nitro 构建不应要求 QTSM headers / `libqtsm.so` 存在。
- `TEE_PROFILE` 只能选择已编入的 provider；配置值与二进制能力不匹配时启动即失败。`POO_EVIDENCE_PROFILE` 仅作为兼容别名保留，不建议在新部署中使用。

QTSM SDK 来源：

- GitHub `https://github.com/huaweicloud/huawei-qingtian.git` 当前不包含 `enclave/qtsm` 所需内容。
- 已验证可用来源为 Gitee：`https://gitee.com/HuaweiCloudDeveloper/huawei-qingtian.git`。
- 本次校准使用的 Gitee commit：`516a3f4531d0ff6cbde6e19764fb6319650b9fc5`。
- Gitee 仓库顶层和 `enclave/qtsm` 采用 Apache-2.0 许可。开源仓库可以 vendoring SDK，或在发布流水线下载并校验固定 commit/tarball hash。
- release manifest 必须记录 SDK commit 或 tarball hash，不能只记录“使用最新 master”。

构建期依赖：

- `huawei-qingtian/enclave/qtsm/include/qtsm_lib.h`
- `huawei-qingtian/enclave/qtsm/include/qtsm_lib_comm.h`
- `huawei-qingtian/enclave/qtsm/lib/libqtsm.so`
- `libcbor`
- `openssl` / `libcrypto`，如 QTSM lib 构建需要。

QTSM SDK API 和边界来自 `enclave/qtsm/include/qtsm_lib.h` 与 `qtsm_lib_comm.h`：

```c
int qtsm_get_attestation(const int fd,
    const uint8_t *user_data, const uint32_t user_data_len,
    const uint8_t *nonce_data, const uint32_t nonce_data_len,
    const uint8_t *pubkey_data, const uint32_t pubkey_len,
    uint8_t *att_doc_data, uint32_t *att_doc_data_len);
```

```text
QTSM_PCR_MAX_LENGTH        = 64
QTSM_MAX_PCR_COUNT         = 32
QTSM_MODULE_ID_MAX_SIZE    = 128
QTSM_CERTIFICATE_MAX_SIZE  = 4096
QTSM_CERTIFICATE_MAX_DEPTH = 4
QTSM_PUBLIC_KEY_MAX_SIZE   = 1024
QTSM_USER_DATA_MAX_SIZE    = 512
QTSM_NONCE_MAX_SIZE        = 512
QTSM_SIGNATURE_MAX_SIZE    = 128
```

实现要求：

- enclave 侧必须在调用 QTSM 前检查 `nonce` 和 SPKI DER `public_key` 长度，超过 SDK 上限时 fail closed。
- v1 不使用 `user_data` 做安全绑定；如果未来启用，长度上限为 `512`，且必须先更新 profile 规范和测试向量。
- verifier 侧必须限制 attestation COSE bytes 最大长度，防止无界 CBOR/X.509 输入。当前 Node verifier 限制 `128 KiB`，大于 SDK response buffer 和真实样本大小。
- QTSM lib 内部打开 `/dev/qtsm`；该设备只应在 enclave 内存在。宿主机普通 Docker 运行 `qtsm_lib_init failed` 是预期诊断结果，不表示 EIF 内失败。
- QTSM lib 的 `QTSM_RESPONSE_MAX_SIZE` 为 `0x6000`，内核驱动响应上限为 `0x8000`；当前 provider 分配 `64 KiB` 输出 buffer 有足够余量。

runtime library packaging checklist：

- 决定 QTSM 依赖采用动态链接还是静态链接；第一阶段建议动态链接，便于与华为 SDK 保持一致。
- 如果动态链接，Dockerfile 必须把 `libqtsm.so`、`libcbor.so`、`libcrypto.so` / `libssl.so` 等运行时依赖复制到镜像内固定路径，例如 `/usr/local/lib` 或 `/usr/lib64`。
- 设置 `LD_LIBRARY_PATH`、`ldconfig` 配置，或在 Rust/C wrapper 链接时设置 rpath，确保 enclave 启动后不依赖 shell 环境也能找到动态库。
- QingTian Dockerfile 构建阶段必须执行 `ldd /usr/local/bin/proof-of-observation-enclave` 或等效检查，并保存输出到构建日志。
- EIF smoke 启动失败时，优先检查动态库缺失、符号版本和 `/dev/qtsm` 初始化错误，避免误判为 attestation 逻辑错误。
- 生产发布 manifest 应记录 QTSM SDK commit/tarball hash、`libqtsm.so` hash 和基础镜像 digest。

当前实现状态：

- `enclave/src/evidence_qingtian.rs` 已实现 `QingTianEvidenceProvider`。
- provider 初始化调用 `qtsm_lib_init()`，保存 fd，并在 drop 时调用 `qtsm_lib_exit()`。
- 每次 proof trailer 生成时调用 `qtsm_get_attestation(fd, NULL, 0, nonce, nonce_len, spki, spki_len, out, out_len)`。
- `TEE_PROFILE=qingtian` 或 `POO_EVIDENCE_PROFILE=qingtian` 选择 QingTian provider；默认仍为 Nitro。

QingTian provider 输出：

- `profile = "qingtian"`
- `attestation = QTSM COSE document bytes`
- `measurements` 至少包含：
  - `sha384:0` 或 `pcr0`
  - `sha384:8` 或 `pcr8`

第一阶段如果 provider 不解析自身 attestation，可只返回 COSE bytes，由 verifier 解析 PCR；顶层 `pcr0/pcr8` 可以省略。为了诊断友好，可以在飞地内或父虚机发布流程中填充 advisory copy，但 verifier 不信任 advisory copy。

### 4.4 进程入口与运行时

已验证 QingTian 中 `CMD ["sh", "-c", "..."]` 入口不稳定。生产 Dockerfile 应使用直接入口：

```dockerfile
CMD ["/usr/local/bin/proof-of-observation-enclave"]
```

或：

```dockerfile
ENTRYPOINT ["/usr/local/bin/proof-of-observation-enclave"]
```

需要避免依赖 shell loop 来保持进程存活。主进程应直接监听 vsock 并阻塞运行。

### 4.5 vsock 与端口

保持现有 vsock 端口：

- control port: `5005`
- metrics/admin port: `5006`
- parent CID：官方 QingTian qproxy 和 SDK Rust wrapper 均默认 `3`。当前实现保留 `POO_PARENT_CIDS` / `POO_PARENT_CID` 配置，默认值包含 `3`，用于兼容和诊断。

建议将以下值配置化：

```text
POO_PARENT_CIDS=3
POO_CONTROL_PORT=5005
POO_METRICS_PORT=5006
TEE_PROFILE=qingtian
```

默认值保持当前 Nitro 行为，避免破坏已有部署。QingTian 发布版应在 manifest 中记录实际启动使用的 `--cid`、父 CID 候选、control port 和 relay 连接配置，因为这些值进入镜像环境变量时会影响 `PCR0`。

## 5. Verifier 侧改造方案

### 5.1 Evidence profile dispatcher

参考阿里云分支，引入统一接口：

```ts
interface EvidenceTrust {
  profile?: 'nitro' | 'qingtian' | string;
  expectedPcr0?: string;
  expectedPcr8?: string;
  expectedPcrs?: Record<string, string>;
  platformTrust?: {
    rootCertificatesPem?: string[];
    rootFingerprintsSha256?: string[];
    intermediateCertificatesPem?: string[];
    intermediateFingerprintsSha256?: string[];
    revocation?: {
      required?: boolean;
      method?: string;
      checkedExternally?: boolean;
    };
  };
}

interface EvidenceVerdict {
  ok: boolean;
  profile: string;
  checks: TeeCheck[];
  moduleId?: string;
  pcr0?: string | null;
  pcr8?: string | null;
  measurements?: Record<string, string>;
  publicKey?: string | null;
  nonce?: string | null;
}
```

`verifyTeeExchange()` 改为：

1. 从 trust config 或 proof `profile` 选择 evidence verifier。
2. 缺省：`profile` 缺失时按 `nitro` 处理。
3. 如果 proof `profile` 与 trust config `profile` 不一致，fail closed。
4. 调用 profile verifier 校验 evidence。
5. 后续公钥绑定、nonce 绑定、PCR/measurement 比对、statement 签名和 body hash 逻辑继续复用。

profile 选择必须遵守以下安全边界：

- 只有 Nitro legacy 兼容路径可以在 proof 缺失 `profile` 时默认按 `nitro` 处理。
- Nitro legacy CLI 仍可只传 `--pcr0 <hex>`，由 verifier 转成 `{ "profile": "nitro", "expectedPcr0": "<hex>" }`。
- QingTian proof 不能只依赖 proof 自报的 `"profile": "qingtian"` 进入信任路径；verifier 必须显式提供 `--trust <trust.json>` 或等效 trust config。
- QingTian trust config 的 `profile` 必须是 `"qingtian"`，并且必须包含 PCR0/PCR8 allowlist 和 platform trust 配置；缺失时 fail closed。
- 对所有非 Nitro profile，proof `profile` 与 trust config `profile` 不一致时 fail closed。

在进入完整 verifier 实现前，必须先完成一组真实二进制绑定 fixture：

- 使用 `proof-of-observation` 真实启动时 Ed25519 public key 的 SPKI DER 字节作为 `qtsm_get_attestation(..., pubkey, pubkey_len, ...)` 输入。
- 使用 proof 顶层 `nonce` base64 解码后的原始字节作为 `qtsm_get_attestation(..., nonce, nonce_len, ...)` 输入。
- verifier fixture 必须证明从 QingTian payload 中提取出的 attested public key 字节，base64 后等于 proof 顶层 `public_key`。
- verifier fixture 必须证明从 QingTian payload 中提取出的 attested nonce 字节，base64 后等于 proof 顶层 `nonce`。
- 禁止用 base64 文本、ASCII placeholder 或 raw Ed25519 key 代替 SPKI DER；这三者混用会破坏 Nitro/QingTian 之间的 proof 兼容语义。

### 5.2 Nitro verifier 保持兼容

将现有 `verify-attestation-cose.mjs` 封装为 `evidence-nitro.ts`。

保持：

- AWS Nitro root pin。
- COSE_Sign1 / ES384 校验。
- cert chain 校验。
- certificate validity window。
- PCR0 比对。
- `public_key` / `nonce` 绑定。

现有 CLI 参数 `--pcr0 <hex>` 继续可用，等价于：

```json
{
  "profile": "nitro",
  "expectedPcr0": "<hex>"
}
```

### 5.3 QingTian verifier

新增 `verifier/evidence-qingtian.ts`。

QingTian attestation 初步按 COSE_Sign1 + CBOR payload 处理。根据已验证 QTSM sample 和 QTSM SDK，应解析并校验以下字段：

| 字段 | 校验要求 |
|---|---|
| COSE protected header | 必须是预期签名算法，预期为 ES384 / P-384 / SHA-384 路径，实际以样本解析为准 |
| payload | 必须是有界 CBOR map |
| certificate | DER leaf certificate，作为 COSE signature 公钥来源 |
| cabundle | DER certificate chain，链到 Huawei QingTian attestation root |
| pcrs | 至少包含 PCR0；生产应包含并校验 PCR8 |
| public_key | 必须等于 proof 顶层 `public_key` |
| nonce | 必须等于 proof 顶层 `nonce` |
| user_data | 可选，第一阶段不作为安全绑定来源 |
| timestamp / module_id / digest | 如存在则解析展示并纳入格式校验 |

QingTian verifier 必须执行：

1. 限制 attestation base64 和 COSE bytes 最大长度。
2. 解析 COSE_Sign1 四元组。
3. 解析 CBOR protected header 和 payload。
4. 用 leaf certificate public key 校验 COSE signature。
5. 校验证书链到 verifier 本地 pin 的 Huawei QingTian root。
6. 校验证书有效期。
7. 校验 root / intermediate fingerprint。
8. 提取 PCR0、PCR8，并与 trust config allowlist 比对。
9. 提取 attested public key，与 proof 顶层 `public_key` 比对。
10. 提取 attested nonce，与 proof 顶层 `nonce` 比对。
11. 生产模式拒绝 debug evidence 或 debug measurement；debug fixture 仅用于 parser 单测。

真实 fixture 校准出的签名细节：

- COSE protected header 为 ES384 / `-35`。
- 被签数据为标准 COSE `Sig_structure = ["Signature1", protected, h'', payload]`。
- QTSM 返回的 96 字节 ECDSA signature 需要将 `r`、`s` 两个 48 字节分量分别反转字节序后，再按 OpenSSL/Node 期望的 P-1363/DER 形式验证。
- verifier 实现必须保留该字节序兼容逻辑，并用 official-signed fixture 防回归。

### 5.4 QingTian trust config

建议 QingTian 生产 trust config：

```json
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "<official PCR0>",
    "sha384:8": "<official PCR8>"
  },
  "platformTrust": {
    "mode": "cert-chain",
    "trustAnchorId": "huawei-qingtian-prod",
    "rootCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "intermediateCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "rootFingerprintsSha256": [
      "F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581"
    ],
    "intermediateFingerprintsSha256": ["<sha256 fingerprint>"],
    "revocation": {
      "required": false,
      "method": "crl-or-ocsp",
      "checkedExternally": false
    }
  }
}
```

Huawei QingTian attestation root 的官方获取和校验方式：

```text
root zip URL:
https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip

root zip sha256:
99e9203a64cfb0c6495afd815051e97bea8a37895dc083d715674af64adeadfe

root subject:
C=CN, ST=Guizhou, L=Guiyang, O=Huawei Technologies, OU=Huawei Cloud, CN=huaweicloud.qingtian-enclaves

root sha256 fingerprint:
F23443B4EB52A70719DF49BDDA0E57BB25F1C04530885DBECDBDE241C8C4F581
```

生成/复核 root fingerprint 的命令：

```bash
curl -L -o huawei_qingtian-enclaves_root-G1.zip \
  https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip
sha256sum huawei_qingtian-enclaves_root-G1.zip
unzip huawei_qingtian-enclaves_root-G1.zip
openssl x509 -in root.pem -noout -subject -issuer -dates -fingerprint -sha256
```

生产 trust config 必须 pin root fingerprint。`rootCertificatesPem` 可以作为人工审计和离线校验材料保留，但 verifier 的 fail-closed 判断不能只依赖 proof 自带 cabundle。

开发 smoke 可以临时允许：

```json
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "be0555479ab87dd7c50800c4f1fca30cffb20e483771285a8ed7c2046708e1d0cc7dbf58429dd6a76c952b4e6b1ffe4b",
    "sha384:8": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

但 smoke config 不能进入生产文档或默认配置。

### 5.5 Trust anchor calibration

QingTian production verifier 开发前，需要单独完成 trust anchor calibration，并把产物纳入仓库 fixture / docs。该步骤不改变协议，但决定 verifier 能否 fail closed。当前 official-signed fixture 已完成第一轮校准；正式业务镜像发布时必须重新采集业务 proof bundle 和发布 manifest。

必须产出：

- Huawei QingTian attestation root PEM 的官方来源 URL、下载日期、zip hash 和 root fingerprint。
- 从真实 QTSM evidence 的 `cabundle` 中提取 intermediate PEM，并记录 subject/issuer/notBefore/notAfter/fingerprint。
- 至少一份 production mode QingTian COSE payload 的字段 dump，包含字段名、CBOR 类型、字节长度和十六进制摘要。
- 字段映射表：`PCR0`、`PCR8`、`public_key`、`nonce`、`certificate`、`cabundle`、`timestamp`、`module_id`、`digest` 在 payload 中的准确 key。
- chain 顺序说明：当前样本中 `cabundle` 为 root、region、grid、instance 四个 DER 证书，leaf certificate 单独位于 `certificate` 字段；verifier 仍必须按 subject/issuer 重排和校验，不能依赖数组顺序。
- 正例 fixture：完整链、PCR0/PCR8、公钥和 nonce 均匹配。
- 反例 fixture：root fingerprint mismatch、PCR mismatch、公钥 mismatch、nonce mismatch、过期证书。
- revocation policy：如果暂不做 CRL/OCSP，trust config 必须显式记录 `revocation.required=false`；如果要求吊销检查，则必须提供外部检查命令或内置实现。

在正式业务产物完成前，QingTian verifier 可以标记为 Node CLI verifier 可用，但不能把 smoke PCR0/PCR8 写入生产 trust config。

### 5.6 Browser verifier

第一阶段可以让 browser verifier 对 `qingtian` 显示“profile unsupported”，但 CLI verifier 必须先支持完整 QingTian 校验。

原因：

- QingTian COSE/CBOR 解析可以复用现有 JS 有界 CBOR 实现。
- X.509 chain 校验、CRL/OCSP 策略在 browser 环境更复杂。
- 先保证 Node CLI 和 relay-side verification 完整，再把纯前端 verifier 补齐。

如果要保持浏览器验签体验同等可用，后续应：

- 将 QingTian COSE parser 做成浏览器可运行的纯 TS。
- 使用 WebCrypto 或纯 JS 实现 P-384 / SHA-384 验签。
- 将 Huawei root / intermediate pin 以内置常量或用户 trust bundle 形式提供。

## 6. 协议文档改造

需要更新 [`docs/proof-of-observation-protocol-v1.md`](proof-of-observation-protocol-v1.md)：

1. 在 §6 Evidence profile 中增加 QingTian profile 的 non-normative 或 experimental profile note。
2. 在 §7 Proof Wire Format 中增加可选 `profile` 字段说明。
3. 明确历史 proof 缺失 `profile` 时默认 `nitro`。
4. 明确非 Nitro profile 必须显式带 `profile`，verifier 不实现则 fail closed。
5. 明确 `attestation` 字段仍是 base64 evidence，profile 决定其内部格式。
6. 明确 `pcr0/pcr8` 顶层字段是 advisory，可信 measurement 必须来自 evidence。

建议单独新增：

- `docs/evidence-profile-qingtian.md`：QingTian profile 规范。
- `docs/qingtian-enclave-deployment.md`：部署手册。
- `docs/qingtian-enclave-release-manifest.md`：官方 signed EIF 发布与第三方中转站接入说明。

## 7. 构建与部署方案

### 7.1 目录建议

新增目录建议：

```text
deploy/qingtian-runtime/
  Dockerfile
  run.sh
  qingtian.env.example

qingtian-enclave/
  README.md
  Dockerfile.attest-smoke
  smoke/
```

如果最终选择把 QingTian provider 直接编入现有 `enclave/`，则不需要单独 `qingtian-enclave/` 业务实现目录，只保留部署和 smoke 目录。

### 7.2 Build matrix

QingTian 和 Nitro 的构建目标需要显式分开，避免因为本地能编译而在目标云运行时缺少设备或动态库。

| Profile | Target runtime | Expected arch | Cargo feature | Evidence device | Build inputs | Output |
|---|---|---|---|---|---|---|
| `nitro` | AWS Nitro Enclave | 当前生产路径保持不变，README 中为 aarch64 build host | default / `nitro` | NSM | AWS Nitro CLI + 当前 reproducible build inputs | Nitro EIF |
| `qingtian` | Huawei QingTian Enclave on HCE 2.0 | 已验证机器为 `linux/amd64`；如新增 arm64 机型需单独验证 | `qingtian` | `/dev/qtsm` in enclave | QTSM headers + `libqtsm.so` + QingTian tool | QingTian EIF |

构建约束：

- Nitro reproducible build 的脚本、Dockerfile 和 PCR0 发布流程保持原样。
- QingTian Dockerfile 单独维护，显式复制或构建 QTSM SDK，避免污染 Nitro 镜像。
- CI 至少要覆盖 Nitro 默认 feature 和一种 QingTian 编译路径。
- 真正的 EIF 构建和 attestation 采集必须在对应云厂商 Enclave 宿主机上完成；普通 CI 只能做语法、类型和单元测试。

CI 对 QTSM SDK 依赖需要选择一个明确策略：

- **推荐策略：vendored SDK。** 发布时固定 Gitee commit 或 tarball hash，把 headers 和构建脚本放入 `third_party/qingtian-sdk/` 或由 CI 在受控步骤下载并校验 hash。普通 CI 和 release CI 都跑真实 QingTian feature：

  ```bash
  cargo check
  QTSM_SDK_DIR=third_party/qingtian-sdk cargo check --no-default-features --features qingtian
  ```

- **备选策略：stub feature。** 新增 `qingtian-stub` 或 mock FFI，只编译 provider 接口和 proof 拼装逻辑，不链接真实 `libqtsm.so`。普通 CI 跑 stub，release CI / QingTian Dockerfile 必须跑真实 `qingtian` feature：

  ```bash
  cargo check
  cargo check --no-default-features --features qingtian-stub
  QTSM_SDK_DIR=third_party/qingtian-sdk cargo check --no-default-features --features qingtian
  ```

- 不允许 CI 静默跳过 QingTian feature；如果缺少 `QTSM_SDK_DIR` 或 stub feature，应明确失败并提示修复方式。

### 7.3 QingTian 父虚机准备

父虚机要求：

- Huawei Cloud ECS 创建时勾选 Enclave 能力。
- OS：Huawei Cloud EulerOS 2.0。
- 安装 `qt-enclave-bootstrap`、`virtio-qtbox`、`qingtian-tool`。
- 安装 Docker。
- 启动 `qt-enclave-env.service` 并预留 CPU / hugepage。
- 普通运行用户具备 Docker socket 和 `/var/run/enclave`、`/var/log/qingtian_enclaves` 权限。

部署前检查命令以验证记录文档为准：

```bash
qt enclave -h
docker version
systemctl status qt-enclave-env.service --no-pager -l
qt enclave query
```

### 7.4 Docker image -> EIF

开发构建：

```bash
docker build --no-cache -f deploy/qingtian-runtime/Dockerfile -t proof-observation-qingtian:<version> .
qt enclave make-img --docker-uri proof-observation-qingtian:<version> --eif proof-observation-qingtian.eif
qt enclave query-eif --eif proof-observation-qingtian.eif
```

生产构建应使用签名 EIF。当前验证记录和华为云快速入门路径使用 `make-img` 直接传入 signing material：

```bash
qt enclave make-img \
  --docker-uri proof-observation-qingtian:<version> \
  --eif proof-observation-qingtian.signed.eif \
  --private-key private-key.pem \
  --signing-certificate server.pem
```

如果当前 `qt` 版本提供独立 `sign-eif` 子命令，可以作为发布流水线的备选实现，但必须先在 QingTian 机器上执行以下命令确认参数和 PCR8 行为：

```bash
qt enclave make-img -h
qt enclave sign-eif -h
qt enclave query-eif -h
```

发布文档只能记录已在目标机器验证过的签名命令。

### 7.5 PCR0 / PCR8 发布策略

QingTian 的发布策略：

- `PCR0`：由 EIF 镜像内容决定，用于证明运行的是官方审计过的代码。
- `PCR8`：由 EIF 签名证书度量得到，用于证明使用官方发布证书签名。

关于跨机器一致性：

- 相同 signed EIF 在不同支持 QingTian Enclave 的机器上部署，预期 `PCR0/PCR8` 一致。
- `PCR8` 与签名证书相关；同一份 `server.pem` 可产生相同 `PCR8`。
- 但 `private-key.pem` 必须与 `server.pem` 匹配，不能用不匹配私钥签同一证书。
- 不应把发布私钥分发给第三方中转站。

开源后推荐第三方中转站接入模式：

1. 项目方公开源码、Docker image digest、signed EIF、PCR0/PCR8 manifest。
2. 项目方用 release signing key 对 manifest 签名。
3. 第三方中转站直接部署官方 signed EIF。
4. verifier trust config 只接受官方 manifest 中的 PCR0/PCR8。

这样第三方中转站不需要自己签 EIF，也不需要持有发布私钥，且不同中转站的 PCR0/PCR8 可以保持一致。

### 7.6 启动命令

父虚机启动 QingTian enclave：

```bash
qt enclave start \
  --mem 4096 \
  --cpus 2 \
  --eif proof-observation-qingtian.signed.eif \
  --cid 4
```

生产不要加 `--debug-mode`。

父虚机 relay 需要连接 enclave CID `4` 和现有 control port `5005`。如果现有 relay 默认参数已经是该组合，则无需调整；否则仅通过部署配置调整，不改变对外 HTTP API。

## 8. 兼容性策略

### 8.1 不能改变的行为

以下行为必须保持：

- `tee-exchange-v2` statement 字段和 canonicalization 不变。
- `public_key` 使用 base64 SPKI DER，不改成 raw Ed25519。
- `nonce` 使用 base64，且 evidence 中绑定的是同一批原始 nonce bytes。
- `request_body_sha256` / `response_body_sha256` 仍为 lowercase hex SHA-256。
- `signature` 仍为 Ed25519 over statement。
- SSE proof event 名称仍为 `tee.proof`。
- multipart proof part 语义不变。
- `proof_unavailable` 行为不变。
- 没有 proof 的响应仍按当前 verifier/代理策略处理。

### 8.2 可以新增的字段

允许新增：

- `profile`
- `evidence`
- `pcr8`
- `measurements`

但新增字段不能进入 `tee-exchange-v2` statement，除非升级 statement version。第一阶段不升级 statement version。

### 8.3 Nitro 兼容

新 verifier 必须兼容：

- 旧 Nitro proof：不带 `profile`。
- 新 Nitro proof：带 `profile: "nitro"`。
- 当前 Nitro test fixture。
- 当前 CLI `--pcr0` 参数。
- 当前 browser verifier 至少保持 Nitro path 可用。

新 enclave 构建必须兼容：

- 现有 Nitro reproducible build 流程。
- 现有 Nitro deployment/runbook。
- 现有 Nitro PCR0 发布逻辑。

## 9. 测试计划

### 9.1 单元测试

新增 verifier 单测：

- QingTian COSE envelope 格式错误 -> fail。
- CBOR payload 缺 `certificate` -> fail。
- COSE signature 不匹配 -> fail。
- certificate chain 不到 Huawei pinned root -> fail。
- certificate 过期 -> fail。
- PCR0 mismatch -> fail。
- PCR8 mismatch -> fail。
- attested public key != proof public_key -> fail。
- attested nonce != proof nonce -> fail。
- unknown profile -> fail。
- missing profile + Nitro legacy proof -> pass Nitro path。

新增 enclave 单测：

- provider dispatcher 选择 Nitro。
- provider dispatcher 选择 QingTian。
- proof JSON 保留 v2 required fields。
- `profile` 字段按 provider 输出。
- `write_attested_trailer()` 不改变 statement 字节。
- QTSM provider FFI 参数顺序和长度转换正确。

### 9.2 fixture

应纳入仓库的 fixture：

- QingTian production smoke attestation COSE base64。
- 对应 meta JSON：PCR0、PCR8、nonce、public_key、COSE SHA256、launch mode。
- 真实二进制绑定 fixture：`nonce` 必须是 proof 顶层 base64 nonce 解码后的原始字节，`public_key` 必须是 Ed25519 SPKI DER 字节。
- debug attestation sample 可作为 parser fixture，但必须标记为 `debug-only`，不能进入 production trust test。

当前 smoke sample 使用 placeholder public key，因此只能用于 parser/chain/PCR 解析校准，不能用于完整 `proof-of-observation` end-to-end proof 验签。

完成业务镜像后必须重新采集：

- 真实 Ed25519 SPKI DER 绑定样本。
- 真实 response proof bundle。
- signed EIF 的非 0 PCR8 样本。

### 9.3 集成测试

QingTian 机器上执行：

1. 构建 `proof-observation-qingtian` Docker image。
2. 生成 unsigned EIF，确认 PCR0。
3. 使用发布证书签名 EIF，确认 PCR8 非 0。
4. production 模式启动 enclave。
5. 父虚机 relay 通过 vsock 发起真实 upstream 请求。
6. 客户端捕获 SSE 或 multipart response。
7. 使用 Node CLI verifier + QingTian trust config 校验：
   - evidence chain。
   - PCR0/PCR8。
   - public key 绑定。
   - nonce 绑定。
   - response hash。
   - request hash。
   - upstream host/path。

回归 Nitro：

```bash
cd verifier
npm test
```

以及当前 Nitro reproducible build / real bundle 校验流程。

## 10. 实施阶段

### Phase 0：文档和样本固化

产出：

- `docs/qingtian-enclave-validation-notes.md`
- `docs/qingtian-enclave-migration-design.md`

状态：

- 当前阶段只写文档，不改代码。

### Phase 1：Verifier profile 抽象

改造文件：

- `verifier/evidence-profile.ts`
- `verifier/evidence-nitro.ts`
- `verifier/trust-config.ts`
- `verifier/tee-verify-core.ts`
- `verifier/tee-verify-stream.ts`
- `verifier/tee-verify-proxy.ts`
- `verifier/verify-real-bundle.ts`
- verifier tests

目标：

- Nitro 行为不变。
- 旧 `--pcr0` 参数继续工作。
- 新 `--trust <trust.json>` 支持 profile。
- unknown profile fail closed。

### Phase 2a：QingTian parser 和 trust calibration

改造文件：

- `verifier/evidence-qingtian.ts`
- `verifier/evidence-qingtian.test.ts`
- `fixtures/qingtian/*`
- `docs/evidence-profile-qingtian.md`

目标：

- 完成 QTSM COSE/CBOR parser。
- 完成 COSE signature 校验。
- 完成 Huawei QingTian root / chain pin。
- 完成 trust anchor calibration 产物归档。
- 使用 smoke fixture 完成 PCR0/PCR8、public key、nonce 字段提取和反例测试。
- 明确该阶段只达到 parser / calibration complete；由于 smoke fixture 使用 placeholder，不标记为 production complete。

### Phase 2b：真实 proof verification

依赖：

- Phase 4 产出真实 QingTian provider。
- 已生成 signed EIF，且 PCR8 非 0。
- 已采集真实 SPKI DER 和 base64 nonce 原始字节绑定的 response proof bundle。

改造文件：

- `verifier/evidence-qingtian.ts`
- `verifier/tee-verify-core.ts`
- `verifier/tee-verify-stream.ts`
- `fixtures/qingtian/real-proof/*`
- `docs/evidence-profile-qingtian.md`

目标：

- Node verifier 使用 release trust config 校验真实 signed EIF 产出的 QingTian proof bundle。
- 完成 public key 绑定、nonce 绑定、PCR0/PCR8、response hash、request hash 和 upstream host/path 的端到端正例。
- 补齐至少一组真实 bundle 的公钥 mismatch、nonce mismatch、PCR mismatch 反例。

### Phase 3：Enclave evidence provider 抽象

改造文件：

- `enclave/src/main.rs`
- `enclave/src/evidence.rs`
- `enclave/src/evidence_nitro.rs`
- `enclave/Cargo.toml`

目标：

- 把 Nitro NSM 调用从主业务逻辑中拆出。
- Nitro build 和 runtime 行为保持不变。

### Phase 4：QingTian provider 和 runtime

改造文件：

- `enclave/src/evidence_qingtian.rs`
- `enclave/build.rs` 或构建脚本
- `deploy/qingtian-runtime/Dockerfile`
- `deploy/qingtian-runtime/run.sh`
- `docs/qingtian-enclave-deployment.md`

目标：

- 编译并链接 QTSM library。
- 飞地内调用 `qtsm_get_attestation()`。
- 真实 proof 中绑定 Ed25519 SPKI 和 nonce。
- production 模式通过 vsock 完成 end-to-end proof。
- 使用已验证的 signed EIF 生成命令产出非 0 PCR8。

### Phase 5：发布与第三方接入

产出：

- signed EIF。
- Docker image digest。
- PCR0/PCR8 manifest。
- manifest signature。
- production mode signed EIF response proof bundle。
- third-party relay runbook。

目标：

- 第三方中转站无需持有签名私钥。
- 不同中转站部署相同 signed EIF 时 PCR0/PCR8 相同。
- verifier trust config 可直接引用官方 manifest。

## 11. 风险与阻塞点

### 11.1 仍需确认

以下信息仍需要在实现阶段确认：

- Huawei QingTian attestation root / intermediate certificate 的官方获取方式、版本轮换和吊销策略。
- attestation payload 中是否有明确 launch mode / debug 标识；若没有，需要依赖生产 PCR allowlist 和部署流程拒绝 debug。
- QingTian 父 CID 是否在所有实例上稳定为 `3`，否则需要配置化。
- QTSM library 的许可证、二进制分发方式、是否适合直接 vendoring 到开源仓库。
- CRL/OCSP 或华为云官方吊销检查方式。

这些不是“是否能开始改造”的阻塞点，但会影响 production verifier 的最终 fail-closed 策略。

### 11.2 主要风险

- **误把早期 smoke 样本当生产信任值。** 早期 placeholder 样本 `PCR8=0`，只能用于开发；official-signed fixture 或正式业务镜像采集值才可进入 verifier trust 示例。
- **第三方自行签 EIF 导致 PCR8 分裂。** 应通过官方 signed EIF + manifest 避免不同中转站各自签名。
- **proof profile 被 relay 硬编码。** 本仓库 relay 应只透传 proof；如果外部中转站自己解析 Nitro proof，需要升级 verifier 逻辑。
- **QTSM SDK 来源不稳定。** 需要固定 Gitee commit 或发布 tarball，并记录 hash。
- **浏览器 verifier 滞后。** 第一阶段 Node CLI 可以先支持完整 QingTian；浏览器端需明确 unsupported，避免误判。
- **证书吊销策略缺失。** 如果暂不做 CRL/OCSP，生产 trust config 必须明确 revocation policy，而不是假装已检查。

## 12. 验收标准

### 12.1 功能验收

- Nitro 现有全部测试通过。
- Nitro 旧 proof 不带 `profile` 仍能校验。
- Nitro 新 proof 带 `profile: "nitro"` 也能校验。
- QingTian proof 带 `profile: "qingtian"`，Node CLI verifier 能完整校验。
- QingTian 部署能完成真实 upstream 请求，并返回同样的 `tee.proof`。
- 中转站 HTTP 对外接口无需新增 header、path 或 body schema。

### 12.2 安全验收

- QingTian evidence chain 校验到 pinned Huawei root。
- PCR0 必须来自 verified evidence。
- PCR8 必须来自 verified evidence，并与官方发布证书对应。
- public key 必须来自 verified evidence，并等于 proof 顶层公钥。
- nonce 必须来自 verified evidence，并等于 proof 顶层 nonce。
- Ed25519 statement 签名必须覆盖与 Nitro 相同的字段。
- response body hash 必须基于客户端实际收到的字节重算。

### 12.3 发布验收

- 发布文档包含源码 revision、Docker image digest、signed EIF digest、PCR0、PCR8。
- release manifest 有项目方签名。
- 发布必须包含至少一个由 signed EIF 在 production mode 生成的完整 response proof bundle，并能用 Node verifier + release trust config 通过。
- 同一 release 下 Nitro 回归门槛必须通过：Nitro verifier tests、Nitro legacy proof fixture、Nitro reproducible build 文档/脚本保持可用或明确证明未受 QingTian 改造影响。
- 第三方中转站部署文档不要求持有 EIF signing private key。
- verifier trust config 示例只使用非 debug、非 smoke 的 PCR0/PCR8。

## 13. 推荐下一步

1. 固定 QTSM SDK vendoring / release tarball 策略，并记录源码 commit、`libqtsm.so` hash 和依赖库 hash。
2. 增加 QingTian Dockerfile / build script，确保 `libqtsm.so`、`libcbor`、`libcrypto` 等运行时依赖进入 EIF。
3. 在真实 QingTian 机器上用 `TEE_PROFILE=qingtian` 构建并启动 `proof-of-observation` 业务镜像。
4. 采集完整业务 proof bundle：真实 upstream response、proof JSON、QTSM attestation、PCR0/PCR8、release trust config。
5. 用 Node verifier 对真实业务 proof bundle 做端到端正例，并补充 response tamper、PCR mismatch、nonce mismatch、公钥 mismatch 反例。
