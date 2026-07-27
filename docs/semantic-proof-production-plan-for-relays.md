# 字段级 Proof 中转站生产化技术方案

本文是对前一版方案的收敛版修订。

目标不再是把各类中转站的完整协议转换逻辑整体搬进 `proof-of-observation`，而是面向长期生产部署，建立一套 **低侵入、可跨多个第三方中转站复用的字段级 proof 方案**：

- 只在 `proof-of-observation` 内完成关键请求字段、关键响应字段的提取、规范化、加签与验证。
- 重点覆盖 **未发生跨协议转换** 的场景。
- `proof-of-observation` 统一升级到新版本字段级 proof 协议，不再保留旧版本兼容分支。
- 字段级 proof 必须兼容现有 AWS Nitro Enclave、阿里云 Enclave、华为 QingTian Enclave 三种 proof 加签与验证部署方案。
- 允许中转站继续保留现有业务流程、路由、鉴权、计费与响应包装能力。
- proof 保证的是“关键语义字段未被篡改”，而不是“整个 HTTP 请求/响应字节完全一致”。

适用对象：

- [QuantumNous/new-api](https://github.com/QuantumNous/new-api)
- [Demo-9876/sub2api](https://github.com/Demo-9876/sub2api)（公开上游 README 实际对应 [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api)）
- [Wei-Shaw/claude-relay-service](https://github.com/Wei-Shaw/claude-relay-service)
- [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)

---

## 1. 方案结论

### 1.1 核心结论

对于多个外部第三方中转站的低成本接入，不建议要求它们把请求改写、响应改写、协议翻译逻辑全面迁入 TEE。

更现实、可规模化落地的生产方案是：

1. 在 `proof-of-observation` 中新增 **字段提取与字段签名能力**。
2. `proof-of-observation` 以新版本协议为准，后续中转站统一升级，不再保留旧版本兼容分支。
3. proof 组件从 Enclave 已观察到的上游请求与上游响应中抽取各协议里约定的关键字段，做稳定 canonicalize 后加签。
4. proof statement 保留 `request_body_sha256` 和 `response_body_sha256`，但在字段级模式下它们只作为关联提示字段，不作为整体验证的主失败条件。
5. verifier 从用户实际请求/实际响应中再次提取关键字段，与 proof 中的字段声明比对；主判定基于 `upstream_request_fields_sha256` 与 `upstream_response_fields_sha256`。
6. 字段级 verifier 不要求完整 body 字节一致；body hash 不通过时只提示，不影响整体验证结果。
7. verifier 入口必须是统一调度器，由它自动识别 proof 所属的 TEE 平台并分发到对应平台规则；调用方不得手工指定 Nitro / 阿里云 / 华为分支。

因此，字段级 proof 是 `proof-of-observation` 新版本协议的核心能力。

### 1.2 适用边界

本方案优先适用于以下场景：

- 客户端协议与上游协议属于同一协议族。
- 中转站可能改写字段顺序、补默认值、变更包装结构、统一 usage/error/stream 事件，但 **不做跨协议语义翻译**。
- 中转站可能做模型别名映射、路由切换、账号池切换，但最终请求和响应仍可落在同一协议字段模型内。

对于以下场景，本方案仍允许中转站调用同一套字段级 proof 链路、正常产出 proof，但必须降级为 **弱保证模式**：

- OpenAI `chat/completions` -> Claude `messages`
- OpenAI -> Gemini `generateContent`
- Claude -> OpenAI `responses`
- 任何需要证明“两种协议语义等价”的转换链

弱保证模式下：

- proof 仍可提取请求侧关键字段和响应侧关键字段并加签。
- proof 仍可证明“Enclave 确实观察到了某些字段值”。
- 但 verifier **不承诺最终一定验证通过**。
- 即使验证通过，也 **不应被解释为跨协议语义等价已被证明**。

这类场景后续若要获得强保证，仍需单独推进完整语义级 proof。

### 1.3 生产承诺

本方案的生产承诺必须明确限制为：

> proof 只证明“被列入签名清单的关键字段”在 Enclave 上游观测值与 verifier 本地提取值之间满足 field policy 声明的约束。

不能对外表述成：

- “整个响应完全可信”
- “任何字段都没有改动”
- “任何协议转换都被证明正确”

---

## 2. 为什么选择字段级 Proof

### 2.1 相比完整语义 proof 的优势

字段级 proof 更适合当前推进路径，原因是：

- 对中转站改动最小
- 易于接入多个外部第三方仓库
- 不要求中转站重构主调用链
- 不要求把全量 translator/renderer 沉到 `proof-of-observation`
- 可以分接口、分协议逐步覆盖

### 2.2 相比原始字节 proof 的优势

原始字节 proof 的问题在于，中转站哪怕只做这些轻微改动，也会让 proof 失效：

- 字段顺序变化
- 空值删除
- 默认值补齐
- stream chunk 聚合方式调整
- `usage`、`error`、`id`、`created` 等包装字段重写

字段级 proof 允许这些“非关键字节变化”存在，只关注真正需要保证的语义字段。

### 2.3 必须接受的限制

字段级 proof 也有天然边界：

1. 没被列入签名清单的字段，默认不可信。
2. 它不能证明跨协议语义等价；跨协议场景最多只能提供弱保证。
3. 它不能证明中转站的所有业务逻辑都正确。
4. 它只能证明“字段值符合声明”，不能自动证明“字段背后的策略合理”。

---

## 3. 生产目标与非目标

### 3.1 生产目标

本方案的生产目标是：

1. 为主流大模型协议定义一套稳定的字段提取规范。
2. 让 `proof-of-observation` 能独立完成字段抽取、规范化、签名。
3. 让第三方中转站统一按新版本 `proof-of-observation` 字段级 proof 协议接入。
4. 让 verifier 能根据协议类型校验请求字段与响应字段。
5. 在不破坏 JSON/SSE 客户端兼容性的前提下长期稳定运行。

### 3.2 非目标

以下内容不在本期方案范围内：

- 跨协议语义转换的强保证证明
- 对 tool 调用结果内容做业务正确性证明
- 对图像、音频、视频二进制内容做全量结构化语义证明
- 对中转站鉴权、计费、配额策略本身做正确性证明
- 强制所有中转站返回 `multipart/mixed` 或 SSE 尾部 proof

---

## 4. 整体架构

### 4.1 总体思路

生产环境推荐把 `proof-of-observation` 扩展为：

```text
proof-of-observation/
  extractor/
  canonical/
  signer/
  verifier/
  verifier/platform/
  protocol-registry/
  tee-platform/
```

其中：

- `extractor/`
  - 按协议提取关键请求字段与关键响应字段
- `canonical/`
  - 对提取结果做稳定排序、归一化、哈希
- `signer/`
  - 在 Enclave 内签名字段级声明
- `verifier/`
  - 校验签名、平台 measurement、字段哈希与字段值
- `verifier/platform/`
  - 按 TEE 平台验证 evidence、信任根、公钥绑定与度量值
- `protocol-registry/`
  - 管理每种协议的字段规范版本
- `tee-platform/`
  - 抽象 AWS Nitro Enclave、阿里云 Enclave、华为 QingTian Enclave 的证明模型

### 4.2 中转站侧接入要求

字段级 proof 按新版本协议统一升级，不再要求兼容旧版本接入行为。

默认接入方式为：

1. 中转站按新版本 `proof-of-observation` 协议把请求交给 Enclave。
2. Enclave 请求上游、接收上游响应、生成 proof。
3. Enclave 在生成 proof 时，额外从它已经观察到的请求/响应字节中提取关键字段。
4. proof 使用新版本 proof 包装、proof id、proof 获取接口和返回方式。

也就是说，对统一升级后的中转站：

- 不新增必传字段
- 不改变 vsock / HTTP 调用协议
- 不要求中转站新增 `client_request_capture`、`downstream_response_capture` 等 hook

如果某个中转站愿意提供更多上下文，可以作为可选增强传入，例如：

- `client_protocol_family`
- `downstream_protocol_family`
- `logical_model`
- `route_class`
- `provider_family`
- `assurance_hint`

但这些字段只能作为增强信息，不能成为字段级 proof 的强制接入条件。

### 4.3 协议识别优先级

为了让字段提取结果稳定，协议族按可识别信息的优先级判定。

Enclave / verifier 应按以下优先级识别协议：

1. upstream host/path 映射
   - 例如 `/v1/chat/completions` -> `openai.chat_completions`。
2. 可选增强字段
   - 例如 `client_protocol_family`、`downstream_protocol_family`。
3. 显式配置
   - 由部署配置、channel 配置或 proof runtime 配置指定。
4. body shape 推断
   - 例如存在 `messages` + `max_tokens` 且 Anthropic header 命中时推断为 `anthropic.messages`。
5. unknown
   - 无法识别时，不生成可用于主校验的 `field_claims`，字段级验证结果为 `UNSUPPORTED`。

协议识别结果必须写入 proof 元数据。只要成功识别出协议，就按对应协议字段清单提取字段；如果无法识别，则本次 proof 只能展示 `request_body_sha256` / `response_body_sha256` 等 advisory 观测信息，不能作为字段级生产 proof 通过。

如果多个来源识别出的协议互相冲突，必须按上述优先级取最高优先级结果。高优先级来源一旦命中，低优先级结果只能记录为 diagnostic，不允许反向覆盖最终协议裁决。

其中 `client_protocol_family`、`downstream_protocol_family` 这类可选增强字段默认视为不可信输入，只能在 host/path 无法唯一裁决时作为辅助信号，并且必须落在版本化 allowlist 内；一旦与显式配置冲突，仍以更高优先级来源为准，冲突仅作 diagnostic。

### 4.4 生产推荐交付模式

新版本默认仍推荐使用 **detached proof**：

- 正常 JSON/SSE 响应保持原样
- 中转站返回新版本 proof id / proof 查询接口 / proof 包装格式
- 字段级 proof 信息作为新版本 proof payload 的标准字段出现
- 客户端或验证代理通过新版本 proof 获取方式拉取 proof

不建议生产默认内联：

- `multipart/mixed`
- SSE 尾部 `event: tee.proof`

原因仍然是客户端兼容性太差，尤其是第三方 SDK、CLI、浏览器扩展和企业代理链路。

### 4.5 TEE 平台适配层

当前代码已支持 AWS Nitro Enclave、阿里云 Enclave、华为 QingTian Enclave 三种 proof 加签与验证部署方案。字段级 proof 必须建立在现有三平台能力之上，不能把字段级能力绑定到某一个平台的证明格式。

生产设计按两层拆分：

1. 字段级 proof 协议层
   - 负责 `field_claims`、canonical statement、字段哈希、`rewrite_claims`、error policy。
   - 对三种 TEE 平台保持一致。
2. TEE evidence 平台层
   - 负责验证平台远程证明、信任根、度量值、公钥绑定、nonce 绑定。
   - 由平台插件完成，字段级 proof 不直接解析平台私有证明格式。

这里要严格区分两个概念：

- `attestation`
  - 平台返回的原始远程证明载荷、证明链或证明封装。
  - 这是“证明材料本身”。
- `evidence`
  - 从 `attestation` 解包后得到的结构化校验输入。
  - 这是“verifier 真正拿来比对的证据”。

平台插件只负责把原始 `attestation` 解析并验证成统一的 `evidence` 结果；`verifier/core` 不应依赖任何云厂商私有结构。

平台 profile 生产默认如下：

| 平台 | `tee_platform` | `tee_profile` | 主要 evidence | 主度量字段 |
| --- | --- | --- | --- | --- |
| AWS Nitro Enclave | `aws` | `aws-nitro` | Nitro attestation document / COSE 证明链 | `PCR0` |
| 阿里云 Enclave | `aliyun` | `aliyun-enclave` 或现有 `aliyun-vtpm` profile | vTPM quote / platform evidence / 证书链 | 平台 quote 中的 PCR 或 measurement |
| 华为 QingTian Enclave | `huawei` | `huawei-qingtian` | QingTian attestation report / quote / 证书链 | QingTian report 中的 measurement |

字段级 proof 只要求平台插件输出统一验证结果：

```json
{
  "tee_platform": "aws",
  "tee_profile": "aws-nitro",
  "evidence_format": "cose-nsm",
  "trust_anchor_id": "aws-nitro-root-g1",
  "measurement_type": "PCR0",
  "reported_measurement": "...",
  "trusted_measurement": "...",
  "attestation_verified": true,
  "measurement_checked": true,
  "measurement_matched": true,
  "public_key_bound": true,
  "nonce_bound": true,
  "revocation_checked": true
}
```

其中：

- `reported_measurement`
  - 由平台 attestation / evidence 实际带回的度量值。
- `trusted_measurement`
  - 由发布矩阵或信任配置提供的受信度量值。
- `measurement_checked`
  - 是否存在平台 measurement / PCR 检查项；不代表检查通过。
- `measurement_matched`
  - `reported_measurement` 与 `trusted_measurement` 是否一致。
- `attestation_verified`
  - 原始 attestation 是否通过结构与链路验证。
- `public_key_bound`
  - 平台证明是否把签名公钥绑定到该 proof。
- `nonce_bound`
  - 平台证明是否把 nonce 绑定到该 proof。
- `revocation_checked`
  - 平台 trust anchor 或证书链是否做了吊销检查。

不同平台的原始 attestation / evidence 可以继续保留在 proof 中，但 verifier 主流程只依赖平台插件产出的统一结果。这样字段级 proof 的开发只需要接入统一接口，不需要分别理解 Nitro COSE、阿里云 vTPM quote、华为 QingTian report 的内部结构。

### 4.6 三平台部署兼容要求

字段级 proof 接入三种 Enclave 部署时必须满足：

1. 同一份 `field_claims` 结构在三平台完全一致。
2. 同一份 canonical statement 在三平台完全一致。
3. 三平台都必须使用 TEE 内生成或 TEE 内保护的签名私钥。
4. 远程证明必须把签名公钥与平台度量绑定。
5. `nonce` 必须同时绑定 proof statement 与平台 evidence，防止 proof/evidence 拼接。
6. release matrix 必须按平台分别维护受信 measurement。
7. relay 接入代码不能根据云平台分叉字段级 proof 行为；只允许配置不同的 `tee_profile`、连接地址、egress proxy 和部署参数。

部署差异只允许存在于以下层面：

- 父实例与 Enclave 的通信方式
- Enclave 镜像格式与构建工具链
- 平台 evidence 获取 API
- 平台 trust anchor / 证书链 / quote 验证逻辑
- egress proxy、DNS、TLS 出口配置
- 监控指标采集方式

部署差异不得影响：

- 字段提取规则
- canonical JSON 规则
- `field_policy_id`
- `upstream_request_fields_sha256`
- `upstream_response_fields_sha256`
- `rewrite_claims`
- verifier 字段级主判定

---

## 5. 字段级 Proof 的声明模型

### 5.1 Proof Statement

字段级声明是新版本 `proof-of-observation` 的主声明结构。

建议做法是：

- proof 顶层继续保留 `request_body_sha256`、`response_body_sha256`、`signature`、`attestation` 等基础字段
- proof payload 必须包含 `field_claims`
- verifier 统一按新版本规则识别并验证 `field_claims`
- Ed25519 `signature` 必须覆盖完整 canonical statement，包括基础字段和 `field_claims`
- 未进入 canonical statement 的未知字段只能作为展示元数据，不能参与 verifier 主判定
- `request_body_sha256` 与 `response_body_sha256` 作为边界观测关联字段保留，只用于对账和提示，不作为主失败条件
- `upstream_request_fields_sha256` 与 `upstream_response_fields_sha256` 必须来自 Enclave 内观察到的上游请求/响应字段视图，不能由 relay 提供或覆盖
- `request_body_verdict`、`response_body_verdict` 不进入签名声明，统一由 verifier 在本地请求/响应比对后产出
- proof 顶层必须携带 `tee_platform` / `tee_profile` 或等价 profile 字段，用于选择 AWS Nitro、阿里云 Enclave、华为 QingTian 的平台 verifier
- 平台原始 evidence 由现有三平台 proof 实现继续产生；字段级 proof 只要求签名公钥、nonce、measurement 的统一验证结果成立

示例结构：

```json
{
  "alg": "ed25519",
  "tee_platform": "aws",
  "tee_profile": "aws-nitro",
  "attestation": "...",
  "evidence": {...},
  "nonce": "...",
  "request_body_sha256": "...",
  "response_body_sha256": "...",
  "signature": "...",
  "field_claims": {
    "v": 1,
    "proof_type": "field-proof",
    "protocol_family": "openai.chat_completions",
    "assurance_level": "strong",
    "upstream_request_fields_sha256": "...",
    "upstream_response_fields_sha256": "...",
    "body_hash_policy": "advisory"
  }
}
```

签名边界必须固定为 canonical statement。生产实现中，canonical statement 至少包含：

- 基础证明字段：`alg`、`nonce`、`upstream_host`、`upstream_path`、`http_method`、`http_status`、`request_body_sha256`、`response_body_sha256`
- 字段级声明：完整 `field_claims`
- 版本绑定字段：`proof_schema_version`、`field_policy_id`、`request_schema_version`、`response_schema_version`
- 运行环境绑定字段：`tee_platform`、`tee_profile`、平台 evidence 中背书的签名公钥、平台度量信息

未进入 canonical statement 的字段只能用于展示、排障或 UI 提示。verifier 不得基于这些字段给出主通过结论。

`field_claims` 必须进入 Enclave 内签名声明，建议结构如下：

```json
{
  "v": 1,
  "proof_type": "field-proof",
  "nonce": "...",
  "protocol_family": "openai.chat_completions",
  "assurance_level": "strong",
  "verification_mode": "field_claims",
  "cross_protocol": false,
  "semantic_equivalence_not_proven": false,
  "request_schema_version": "openai.chat_completions.v1",
  "response_schema_version": "openai.chat_completions.v1",
  "upstream_host": "api.openai.com",
  "upstream_path": "/v1/chat/completions",
  "http_method": "POST",
  "http_status": 200,
  "field_policy_id": "openai.chat_completions.default@2026-07-27",
  "upstream_request_fields_sha256": "...",
  "upstream_response_fields_sha256": "...",
  "request_body_sha256_severity": "advisory",
  "response_body_sha256_severity": "advisory",
  "request_field_diff_policy": "allow_defaults_only",
  "response_field_diff_policy": "allow_wrapper_only",
  "rewrite_claims": {
    "logical_model": "gpt-4o",
    "physical_model": "gpt-4o-2024-11-20",
    "usage_source": "upstream"
  },
  "body_hash_policy": "advisory",
  "streaming": false
}
```

`request_body_verdict` 与 `response_body_verdict` 不是 Enclave 可提前判断的事实，不得进入 proof statement。它们只能由 verifier 在拿到用户本地实际请求/响应后输出。

### 5.2 核验目标

verifier 至少校验：

1. attestation 是否可信
2. 平台 measurement 是否落在受信版本清单
3. 协议族与 schema version 是否匹配
4. 提取出的字段集合是否与签名覆盖值一致
5. 请求字段差异是否仅发生在允许改写的字段上
6. 响应字段差异是否仅发生在允许改写的字段上

其中：

- `upstream_request_fields_sha256` 和 `upstream_response_fields_sha256` 属于主校验字段，失败应影响整体验证结果。
- verifier 需要从用户本地实际请求/实际响应中提取同协议字段视图，再按同一 `field_policy_id` 规范化后与 proof 中的上游字段哈希比对。
- `request_body_sha256` 和 `response_body_sha256` 属于关联提示字段，失败只应生成提示，不应把整体验证直接判成失败。

### 5.3 字段差异策略

建议为每种协议定义三类字段：

- `must_match`
  - 必须一致，任何变化都导致 proof 失败
- `allow_rewrite`
  - 允许由 relay 改写，但必须有可审计证据与策略约束
- `advisory`
  - 只用于提示和对账，不影响整体通过结果

字段哈希必须基于“应用 field policy 后的 verification view”计算，而不是简单对原始字段全集计算。也就是说：

- `must_match` 字段进入主哈希，verifier 侧必须与 Enclave 侧一致。
- `allow_rewrite` 字段需要先按策略归一化为可验证声明，例如 `logical_model -> physical_model` 映射、默认值补齐来源、usage 来源。
- `advisory` 字段不进入主失败判定，可进入 diagnostic hash 或明细报告。

如果没有这层 verification view，模型别名、默认值补齐、usage 包装等合法改写会误伤主校验。

`allow_rewrite` 的可信依据必须同时满足：

1. 版本化 `field_policy_id` 中显式定义该字段允许改写，以及允许改写的约束。
2. 当前请求实例的改写事实能被 verifier 复算或校验，例如来自 Enclave 签名覆盖的 `rewrite_claims`：

```json
{
  "logical_model": "gpt-4o",
  "physical_model": "gpt-4o-2024-11-20",
  "default_value_source": "relay_config",
  "usage_source": "upstream",
  "wrapper_fields": ["id", "created", "object"]
}
```

`rewrite_claims` 不能独立证明改写合法，只能证明“本次请求声明发生了这类改写”。verifier 必须继续用 `field_policy_id`、受信路由配置或公开映射表校验该改写是否被允许。

如果某个字段没有同时满足上述条件，就不能把它归为 `allow_rewrite`，只能按 `must_match` 或 `advisory` 处理。

例如：

- `temperature` 可视为 `must_match`
- `model` 在存在别名映射时可视为 `allow_rewrite`，但需记录 `logical_model` 和 `physical_model`
- `usage.total_tokens` 可作为 `allow_rewrite`，但需注明来源是 upstream 还是 relay 估算
- `request_body_sha256` 和 `response_body_sha256` 可视为 `advisory`

### 5.4 验证结果状态

verifier 应至少返回以下状态之一：

- `PASS`
  - 主校验字段通过，advisory 字段也通过
- `PASS_WITH_ADVISORY_WARNING`
  - 主校验字段通过，但 `request_body_sha256` 或 `response_body_sha256` 不一致
- `FAIL`
  - 主校验字段失败，或 evidence / measurement / 协议族 / schema version 校验失败
- `UNSUPPORTED`
  - 无法识别协议族，或字段级 proof 不适用于该路径

---

## 6. 规范化规则

### 6.1 Canonicalize 规则

同一协议下，字段提取后统一按以下规则规范化：

1. 采用 RFC 8785 JSON Canonicalization Scheme（JCS）作为默认 canonical JSON 算法。
2. 对象 key 按字典序排序。
3. 数组保持语义顺序，不额外排序。
4. 省略未出现字段，不补空值。
5. 数字保持原始数值语义，不转字符串。
6. 布尔值保持布尔类型。
7. 文本不做 trim，不改换行。
8. JSON 序列化统一 UTF-8、无额外空格。

如某协议因历史原因无法直接使用 JCS，则必须定义独立 `canonicalizer_version`，并把该版本纳入 `field_policy_id` 和 verifier 兼容矩阵，不能在不同实现间自由漂移。

### 6.2 内容块规范

对于多模态或分块内容，统一抽取为稳定内容块：

```json
[
  {"type": "text", "text": "..."},
  {"type": "image_url", "url": "..."},
  {"type": "input_audio", "mime_type": "...", "sha256": "..."}
]
```

如果二进制内容体积过大，不直接入签名对象，改为：

- 媒体类型
- 引用方式
- 内容哈希

### 6.3 流式响应规范

流式请求不对原始 chunk 字节逐帧加签，而是对以下两部分分别签名：

1. 最终聚合后的语义响应字段
2. 流式元信息摘要

建议流式元信息摘要至少包括：

- `streaming=true`
- `event_sequence_type`
- `finish_reason`
- `usage`
- `tool_calls`
- `content_text_aggregate`

这样可以容忍 chunk 拆分方式不同，但不容忍最终语义内容变化。

---

## 7. 协议覆盖范围

本方案按 **协议族** 覆盖主流模型厂商，而不是按厂商名称逐个复制一套规则。

本章字段清单采用两类存在性语义：

- `required_presence`
  - 协议识别成功后必须存在；缺失说明请求/响应不满足该协议字段级 proof 的最低结构要求，字段级验证应失败或返回 `UNSUPPORTED`。
- `required_if_present`
  - 字段只要出现在请求/响应中，extractor 就必须纳入规范化与哈希；字段未出现不单独构成失败。

除每节明确列为 `required_presence` 的字段外，下方“请求侧 required_if_present 字段”和“响应侧 required_if_present 字段”中的字段均按 `required_if_present` 处理。

各协议最低 `required_presence` 生产默认如下；如需调整，必须通过新的 `field_policy_id` 发布，不能在同一 policy 下静默变更：

| 协议族 | 请求侧 required_presence | 响应侧 required_presence |
| --- | --- | --- |
| `openai.chat_completions` | `model`、`messages` | `choices` |
| `openai.responses` | `model`、`input` | `output` 或 `status` |
| `anthropic.messages` | `model`、`messages`、`max_tokens` | `content`、`stop_reason` |
| `google.gemini.generate_content` | `contents` | `candidates` |
| `alibaba.dashscope.generation` | `model`、`input` | `output` |
| `aws.bedrock.converse` | `modelId`、`messages` | `output` 或 `stopReason` |
| `cohere.chat` | `model`、`messages` | `message` 或 `finish_reason` |

这些最低字段只用于判断该协议的字段级 proof 是否具备可验证结构。其它参数只要出现，就应按 `required_if_present` 纳入提取，避免 relay 删除、替换或遗漏关键可选参数。

### 7.1 OpenAI Compatible Chat Completions

适用厂商与平台：

- OpenAI Chat Completions
- Azure OpenAI Chat Completions
- DashScope OpenAI 兼容模式
- DeepSeek OpenAI 兼容接口
- Groq OpenAI 兼容接口
- xAI / Mistral / Together / OpenRouter 等 OpenAI 兼容 Chat 接口

协议标识建议：

- `openai.chat_completions`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "messages": [
    {
      "role": "...",
      "name": "...",
      "content": "... or content_parts"
    }
  ],
  "tools": [...],
  "tool_choice": "...",
  "response_format": {...},
  "temperature": 0.7,
  "top_p": 1.0,
  "max_tokens": 1024,
  "presence_penalty": 0,
  "frequency_penalty": 0,
  "parallel_tool_calls": true,
  "stream": false,
  "stop": ["..."],
  "seed": 123
}
```

#### 请求侧建议提取字段

- `user`
- `reasoning_effort`
- `service_tier`
- `modalities`
- `audio.format`
- `audio.voice`

#### 响应侧 required_if_present 字段

```json
{
  "model": "...",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "... or content_parts",
        "tool_calls": [...]
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1,
    "completion_tokens": 2,
    "total_tokens": 3
  }
}
```

#### 响应侧建议提取字段

- `choices[].message.refusal`
- `choices[].message.annotations`
- `choices[].logprobs`
- `system_fingerprint`
- `service_tier`
- `reasoning_content` 或等效思维字段

#### 允许改写字段

- `id`
- `created`
- `object`
- `request_id`
- `x-request-id`
- 非关键 header

---

### 7.2 OpenAI Responses API

适用厂商与平台：

- OpenAI Responses
- Codex / Claude Code / 部分代理面向 OpenAI Responses 的兼容接口
- 一些 relay 的 `/v1/responses` 或 `wire_api=responses`

协议标识建议：

- `openai.responses`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "input": "... or structured_input",
  "instructions": "...",
  "tools": [...],
  "tool_choice": "...",
  "temperature": 0.7,
  "top_p": 1.0,
  "max_output_tokens": 1024,
  "stream": false,
  "parallel_tool_calls": true,
  "truncation": "...",
  "text": {
    "format": {...}
  }
}
```

#### 请求侧建议提取字段

- `metadata`
- `reasoning.effort`
- `store`
- `include`

#### 响应侧 required_if_present 字段

```json
{
  "model": "...",
  "output": [...],
  "status": "...",
  "incomplete_details": {...},
  "usage": {
    "input_tokens": 1,
    "output_tokens": 2,
    "total_tokens": 3
  }
}
```

#### 响应侧建议提取字段

- `output_text`
- `output[].content`
- `output[].tool_calls`
- `reasoning`

#### 允许改写字段

- `id`
- `created_at`
- `object`
- 仅用于兼容客户端的包装字段

---

### 7.3 Anthropic Messages

适用厂商与平台：

- Anthropic Claude Messages API
- 任何保持 Claude Messages 协议不变的 relay

协议标识建议：

- `anthropic.messages`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "system": "... or content_blocks",
  "messages": [
    {
      "role": "...",
      "content": "... or content_blocks"
    }
  ],
  "tools": [...],
  "tool_choice": {...},
  "temperature": 0.7,
  "top_p": 1.0,
  "top_k": 50,
  "max_tokens": 1024,
  "stop_sequences": ["..."],
  "stream": false
}
```

#### 请求侧建议提取字段

- `thinking`
- `metadata.user_id`
- `container`
- `mcp_servers`

#### 响应侧 required_if_present 字段

```json
{
  "model": "...",
  "type": "message",
  "role": "assistant",
  "content": [...],
  "stop_reason": "...",
  "stop_sequence": "...",
  "usage": {
    "input_tokens": 1,
    "output_tokens": 2
  }
}
```

#### 响应侧建议提取字段

- `content[].text`
- `content[].tool_use`
- `thinking`
- `container`

#### 允许改写字段

- `id`
- `type` 的兼容包装值
- 中转站注入的 header 与 trace id

---

### 7.4 Google Gemini GenerateContent

适用厂商与平台：

- Google Gemini `generateContent`
- Google Gemini `streamGenerateContent`
- Vertex AI Gemini 的同协议面

协议标识建议：

- `google.gemini.generate_content`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "contents": [...],
  "systemInstruction": {...},
  "tools": [...],
  "toolConfig": {...},
  "generationConfig": {
    "temperature": 0.7,
    "topP": 1.0,
    "topK": 40,
    "maxOutputTokens": 1024,
    "stopSequences": ["..."],
    "responseMimeType": "application/json",
    "responseSchema": {...}
  },
  "safetySettings": [...]
}
```

#### 请求侧建议提取字段

- `cachedContent`
- `labels`
- `thinkingConfig`

#### 响应侧 required_if_present 字段

```json
{
  "candidates": [
    {
      "content": {...},
      "finishReason": "...",
      "safetyRatings": [...]
    }
  ],
  "usageMetadata": {
    "promptTokenCount": 1,
    "candidatesTokenCount": 2,
    "totalTokenCount": 3
  }
}
```

#### 响应侧建议提取字段

- `candidates[].content.parts`
- `candidates[].groundingMetadata`
- `promptFeedback`
- `modelVersion`

#### 允许改写字段

- HTTP 包装层字段
- relay 补充的 request id

---

### 7.5 DashScope Native Generation / MultiModal

适用厂商与平台：

- 阿里云百炼 DashScope 原生文本生成接口
- 阿里云百炼原生多模态对话接口

说明：

如果实际接入走的是 DashScope OpenAI 兼容模式，应归入 `openai.chat_completions`。
只有在中转站直连 DashScope 原生协议时，才使用本节规则。

协议标识建议：

- `alibaba.dashscope.generation`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "input": {...},
  "parameters": {
    "temperature": 0.7,
    "top_p": 1.0,
    "top_k": 50,
    "max_tokens": 1024,
    "result_format": "message",
    "incremental_output": false,
    "stop": ["..."],
    "tools": [...],
    "tool_choice": "auto"
  }
}
```

#### 请求侧建议提取字段

- `system`
- `messages`
- `response_format`
- `thinking_budget`

#### 响应侧 required_if_present 字段

```json
{
  "output": {...},
  "usage": {
    "input_tokens": 1,
    "output_tokens": 2,
    "total_tokens": 3
  }
}
```

#### 响应侧建议提取字段

- `output.text`
- `output.choices`
- `output.finish_reason`
- `request_id`

#### 允许改写字段

- 非关键 wrapper
- relay 补充 headers

---

### 7.6 AWS Bedrock Converse

适用厂商与平台：

- AWS Bedrock `Converse`
- AWS Bedrock `ConverseStream`

协议标识建议：

- `aws.bedrock.converse`

#### 请求侧 required_if_present 字段

```json
{
  "modelId": "...",
  "system": [...],
  "messages": [...],
  "toolConfig": {...},
  "inferenceConfig": {
    "maxTokens": 1024,
    "temperature": 0.7,
    "topP": 1.0,
    "stopSequences": ["..."]
  },
  "additionalModelRequestFields": {...}
}
```

#### 请求侧建议提取字段

- `promptVariables`
- `guardrailConfig`
- `additionalModelResponseFieldPaths`

#### 响应侧 required_if_present 字段

```json
{
  "output": {...},
  "stopReason": "...",
  "usage": {
    "inputTokens": 1,
    "outputTokens": 2,
    "totalTokens": 3
  }
}
```

#### 响应侧建议提取字段

- `output.message`
- `metrics.latencyMs`
- `additionalModelResponseFields`

#### 允许改写字段

- AWS request id 包装
- relay trace 字段

---

### 7.7 Cohere Chat v2

适用厂商与平台：

- Cohere Chat API
- 保持 Cohere Chat 协议不变的 relay

协议标识建议：

- `cohere.chat`

#### 请求侧 required_if_present 字段

```json
{
  "model": "...",
  "messages": [...],
  "tools": [...],
  "tool_choice": "...",
  "temperature": 0.7,
  "p": 0.75,
  "k": 0,
  "max_tokens": 1024,
  "stop_sequences": ["..."],
  "stream": false,
  "response_format": {...}
}
```

#### 请求侧建议提取字段

- `documents`
- `safety_mode`
- `metadata`

#### 响应侧 required_if_present 字段

```json
{
  "message": {...},
  "finish_reason": "...",
  "usage": {
    "input_tokens": 1,
    "output_tokens": 2
  }
}
```

#### 响应侧建议提取字段

- `message.content`
- `message.tool_calls`
- `citations`

#### 允许改写字段

- `id`
- 追踪字段

---

### 7.8 Error Responses

所有协议都必须单独定义 error response policy。生产场景不能把错误响应视为“未定义边界”。

适用范围：

- 上游返回 4xx / 5xx
- rate limit / quota exceeded
- auth / permission denied
- model not found
- safety / policy block
- upstream timeout / unavailable

错误响应校验规则：

1. 先按协议族判断是否为 error response。
2. 错误响应必须落入协议定义的 `error_response` 字段集。
3. `http_status`、错误对象主体、错误码、错误分类都应纳入对应协议的 error policy。
4. relay 不得在没有 field policy 支撑的情况下重写错误分类或错误原因。
5. 若错误响应结构无法识别，只能返回 `UNSUPPORTED`，不能伪装成成功 proof。

生产默认最少字段：

- OpenAI 族：`error.message`、`error.type`、`error.code`、`error.param`
- Anthropic：`type`、`error.type`、`error.message`
- Gemini：`error.code`、`error.message`、`error.status`
- DashScope / Bedrock / Cohere：按各自原生 error object 定义单独 policy

错误响应同样遵循 `request_body_sha256 / response_body_sha256` 仅作 advisory 的原则，但错误对象本身的语义字段应进入主校验视图。

---

## 8. 多模态字段提取约定

### 8.1 文本

文本内容必须原样纳入字段 proof，不做：

- trim
- 空白折叠
- 标点归一化
- Markdown 渲染前处理

### 8.2 图片

图片内容按以下优先级提取：

1. 外部 URL
2. 文件 ID / 引用 ID
3. 二进制哈希

不对图片像素语义做 proof，只对引用或哈希做 proof。

### 8.3 音频与视频

音频、视频统一提取：

- `mime_type`
- `source_type`
- `sha256 or file_id`

### 8.4 工具调用

tool 调用至少提取：

- `tool_name`
- `tool_call_id`
- `arguments`

对于 tool 结果是否真实、是否正确，不在本方案证明范围内。

---

## 9. 流式与非流式的字段校验方式

### 9.1 非流式

非流式最简单：

1. Enclave 提取上游请求关键字段，生成 `upstream_request_fields_sha256`
2. Enclave 提取上游完整响应关键字段，生成 `upstream_response_fields_sha256`
3. Enclave 将两个字段哈希、协议族、schema version、field policy 和基础证明字段一起纳入 canonical statement 加签
4. verifier 从用户本地实际请求/实际响应中提取字段视图，按同一 `field_policy_id` 规范化
5. verifier 将本地字段视图与 proof 中被签名覆盖的上游字段哈希进行主校验

因此，Enclave 不需要观察 relay 最终返回给客户端的下游响应，也不能把“下游字段哈希”作为可信输入。下游响应只在 verifier 侧用于本地比对。

### 9.2 流式

流式不建议逐帧严格比较 chunk 字节。

推荐方式：

1. Enclave 记录上游流式事件序列类型
2. Enclave 聚合上游文本增量
3. Enclave 聚合上游 tool_call 增量
4. Enclave 聚合上游最终 `finish_reason`
5. Enclave 聚合上游最终 `usage`
6. Enclave 对聚合后的上游语义响应字段签名
7. verifier 对用户实际收到的流式响应做同样聚合，再与 proof 中的上游字段哈希比对

### 9.3 流式允许的差异

允许：

- chunk 切分边界不同
- 空 delta 插入
- usage 在末尾单独下发
- `[DONE]` 前后的辅助 header 差异

不允许：

- 最终文本内容不同
- tool 参数不同
- `finish_reason` 不一致
- 关键 usage 字段不一致且未声明来源差异

---

## 10. 四个仓库的接入策略

### 10.1 new-api

#### 适配判断

`new-api` 支持很多跨协议能力。本方案对它分两类处理：

- 强保证模式：同协议族路径
- 弱保证模式：跨协议路径也可接入同一套字段级 proof，但不承诺最终可验证通过

强保证模式优先覆盖：

- OpenAI Chat -> OpenAI Chat
- OpenAI Responses -> OpenAI Responses
- Claude Messages -> Claude Messages
- Gemini -> Gemini
- DashScope OpenAI 兼容 -> OpenAI Chat

#### 最小接入方式

建议只新增独立包：

```text
relay/fieldproof/
```

并在现有 handler / adaptor 链路中调用新版本 `proof-of-observation` 字段级 proof 接口即可，不要求新增强制 hook。

如果某个仓库后续愿意补充更细上下文，可以作为可选参数透传，但不得改变新版本字段级 proof 的主协议。

#### 本期不要做的事

- 不要把 OpenAI -> Claude translator 搬入 proof
- 不要把 Gemini -> OpenAI renderer 搬入 proof
- 不要因为 proof 改造打断现有 channel/provider 架构

#### 跨协议路径的处理方式

对于：

- OpenAI -> Claude
- OpenAI -> Gemini
- Claude -> OpenAI
- Gemini -> OpenAI

仍允许：

1. 进入同一套字段提取链路
2. 生成 proof
3. 返回 detached proof 句柄

但必须在 proof 元数据中显式标记：

- `assurance_level=weak`
- `cross_protocol=true`
- `semantic_equivalence_not_proven=true`

### 10.2 sub2api

#### 适配判断

`sub2api` 更偏账号池与调度平台，本方案里把它视为：

- 可能有轻度请求包装
- 可能有轻度响应包装
- 重点关注路由后的同协议直连链路

#### 最小接入方式

统一接入新版本 `proof-of-observation` 字段级 proof 协议即可。若要增强可审计性，可补充这些路由摘要：

- `route_class`
- `provider_family`
- `sticky_session_key_present`
- `proxy_mode`

这些字段不是语义内容，但会显著影响请求落到哪个真实上游。

### 10.3 claude-relay-service

#### 适配判断

它更适合作为遗留兼容层接入，不建议为它做复杂扩展。

#### 最小接入方式

- Claude 原生路径按 `anthropic.messages`
- Gemini 原生路径按 `google.gemini.generate_content`
- `/openai/` 兼容路径按 `openai.responses` 或 `openai.chat_completions`

只做字段级提取，不重构其老的转发主链，也不要求它新增 proof 专用 hook。

### 10.4 CLIProxyAPI

#### 适配判断

它适合成为插件化接入样板。

#### 最小接入方式

在其 `proof-of-observation` 对接点上挂接新版本字段级 proof 即可。
如果它本身已经有 request/response translator 或 interceptor，也可复用这些现有点做字段提取，但不强制新增插件接口。

---

## 11. verifier 设计要求

### 11.1 verifier 输入

verifier 应支持输入：

- proof 文件
- 原始客户端请求
- 原始客户端响应
- 协议族标识
- 可选的受信 measurement 列表
- 可选的允许改写策略版本
- 可选的 `tee_profile` 约束
- 可选的 trust anchor / 发布矩阵

其中 `tee_platform` 不应作为调用方的必传路由参数；统一 verifier 必须自行识别平台并完成分发。`tee_profile` 仅在调用方希望限制可接受平台范围时才作为约束条件使用。

### 11.2 verifier 输出

至少输出：

- attestation 是否通过
- TEE 平台 evidence 是否通过
- measurement evidence 是否通过
- reported_measurement 与 trusted_measurement 是否一致
- 请求字段主校验是否通过
- 响应字段主校验是否通过
- `request_body_verdict`
- `response_body_verdict`
- 是否存在 advisory 警告
- 哪些字段是 `must_match`
- 哪些字段是 `allow_rewrite`
- 哪些字段是 `advisory`
- 哪些字段未被 proof 覆盖
- 协议识别来源与命中顺序
- `rewrite_claims` 是否被采用
- 错误响应是否命中对应 error policy
- `tee_platform`
- `tee_profile`
- `measurement_type`
- `attestation_verified`
- `measurement_checked`
- `public_key_bound`
- `nonce_bound`
- `revocation_checked`
- `reported_measurement`
- `trusted_measurement`
- `measurement_matched`
- `trust_anchor_id`

`request_body_verdict` 与 `response_body_verdict` 只允许使用以下枚举：

- `PASS`
  - body hash 与 verifier 本地输入一致
- `ADVISORY_WARNING`
  - body hash 与 verifier 本地输入不一致，但不影响字段级主校验结果
- `NOT_CHECKED`
  - verifier 未提供对应本地 body，无法对账

### 11.3 verifier 的产品边界

verifier 必须明确告诉用户：

- “本次 proof 覆盖了哪些字段”
- “哪些字段未覆盖”
- “是否存在 relay 合法改写”
- “哪些字段的不一致只会触发提示，不会让整体验证失败”

不能只输出一个模糊的 `PASS/FAIL`。

### 11.4 平台 verifier 插件

字段级 verifier 必须拆成两层：

```text
verifier/core
  - canonical statement 验签
  - field_claims 校验
  - request/response 字段提取与比对

verifier/platform/aws_nitro
  - Nitro evidence 验证
  - PCR0 / 公钥 / nonce 绑定

verifier/platform/aliyun_enclave
  - 阿里云 Enclave evidence 验证
  - vTPM quote / measurement / 公钥 / nonce 绑定

verifier/platform/huawei_qingtian
  - QingTian evidence 验证
  - report / measurement / 公钥 / nonce 绑定
```

平台插件必须对 core 暴露统一结果：

```json
{
  "ok": true,
  "tee_platform": "aliyun",
  "tee_profile": "aliyun-vtpm",
  "measurement_type": "vtpm-pcr",
  "attestation_verified": true,
  "measurement_checked": true,
  "public_key_bound": true,
  "nonce_bound": true,
  "revocation_checked": true,
  "reported_measurement": "...",
  "trusted_measurement": "...",
  "measurement_matched": true,
  "trust_anchor_id": "...",
  "detection_source": "tee_platform",
  "freshness_status": "valid",
  "revocation_status": "checked"
}
```

`verifier/core` 只消费上述统一结果，不直接解析云厂商私有 evidence。新增字段级 proof 时，三平台已有 proof 加签和验证代码只需要保证这个统一结果继续可用。

### 11.5 统一 verifier 路由

生产 verifier 必须提供单一入口，例如：

```text
verifier/
  core/
  platform/
    aws_nitro/
    aliyun_enclave/
    huawei_qingtian/
  router/
```

其中 `verifier/router` 负责自动识别 proof 的平台来源，再分发给对应平台插件。识别优先级必须固定：

1. proof 顶层显式字段
   - `tee_platform`
   - `tee_profile`
2. evidence 形状与签名封装特征
   - 例如 COSE / quote / report 的类型特征
3. measurement 命名空间与平台专有字段
4. 部署配置中的平台默认值

`trust_anchor_id` 不参与平台路由决策，只在平台已经识别完成后，作为该平台下的信任锚校验条件进入发布矩阵比对。若出现冲突，必须以更高优先级来源为准；若仍然无法唯一确定平台，则 verifier 直接返回 `UNSUPPORTED`，不得“猜一个平台继续验”。

统一 verifier 的返回结果必须包含：

- `detected_tee_platform`
- `detected_tee_profile`
- `detection_source`
- `attestation_verified`
- `reported_measurement`
- `trusted_measurement`
- `measurement_checked`
- `measurement_matched`
- `public_key_bound`
- `nonce_bound`
- `revocation_checked`
- `platform_verifier_version`

这样上层调用只面对一个 verifier 入口，不需要自己判断这份 proof 是 AWS、阿里云还是华为生成的。

---

## 12. 版本管理与生产治理

### 12.1 协议字段规范版本

每种协议的字段清单都必须单独版本化，例如：

- `openai.chat_completions.v1`
- `openai.responses.v1`
- `anthropic.messages.v1`
- `google.gemini.generate_content.v1`

字段清单一旦变化：

- proof schema version 必须变化
- verifier 必须支持当前生产激活的 proof schema version、field policy version 与 proof runtime version
- Enclave、relay 接入包和 verifier 必须按同一生产版本矩阵锁步发布

### 12.2 TEE measurement 与发布版本管理

生产环境必须维护：

- `proof runtime version`
- `field policy version`
- `proof schema version`
- `verifier version`
- `tee_platform`
- `tee_profile`
- `measurement_type`
- `trusted_measurement`
- `trust_anchor_id`
- `enclave image digest`

这些版本与度量信息的对应关系要能被审计与回溯。建议维护一张生产发布矩阵：

| 字段 | 说明 |
| --- | --- |
| `proof_runtime_version` | Enclave 内 proof 程序版本 |
| `proof_schema_version` | proof statement 的结构版本 |
| `field_policy_id` | 字段提取、归一化、允许改写策略版本 |
| `verifier_version` | 能验证该 schema/policy 的 verifier 版本 |
| `tee_platform` | `aws` / `aliyun` / `huawei` |
| `tee_profile` | `aws-nitro` / `aliyun-enclave` / `aliyun-vtpm` / `huawei-qingtian` |
| `measurement_type` | 平台度量类型，例如 Nitro `PCR0`、阿里云 vTPM PCR、QingTian measurement |
| `reported_measurement` | 平台 attestation 实际报告出的度量值 |
| `trusted_measurement` | 对应该平台、该镜像、该版本的受信度量值 |
| `trust_anchor_id` | 平台 evidence 的信任锚标识 |
| `evidence_verifier_version` | 平台 evidence verifier 版本 |
| `enclave_image_digest` | EIF、阿里云 Enclave 镜像或 QingTian Enclave 镜像构建产物摘要 |
| `release_status` | `observe` / `verify_optional` / `verify_enforced` / `retired` |

生产 verifier 只信任发布矩阵中处于激活状态的组合。矩阵外的 schema、policy、measurement、trust anchor 或 runtime 组合必须失败，不能降级为通过。

三平台发布矩阵示例：

| `tee_profile` | `measurement_type` | `trusted_measurement` 来源 | 备注 |
| --- | --- | --- | --- |
| `aws-nitro` | `PCR0` | 可复现构建得到的 Nitro EIF PCR0 | 继续沿用现有 Nitro proof 验证链 |
| `aliyun-vtpm` | `vtpm-pcr` | 阿里云 Enclave/vTPM quote 中审计通过的 PCR 或 measurement | 继续沿用现有阿里云 proof 验证链 |
| `huawei-qingtian` | `qingtian-measurement` | QingTian attestation report 中审计通过的 measurement | 继续沿用现有华为 proof 验证链 |

### 12.3 灰度策略

建议分三阶段：

1. `observe`
   - 只提取字段，不对外启用验证
2. `verify_optional`
   - 对外下发 detached proof，但业务不依赖验证结果
3. `verify_enforced`
   - 对指定客户、指定接口强校验

灰度期间必须观测并告警：

- `UNSUPPORTED` 占比
- `PASS_WITH_ADVISORY_WARNING` 占比
- 协议识别冲突次数
- `required_presence` 缺失次数
- `must_match` 字段不一致次数
- evidence / reported_measurement / trusted_measurement / signature 失败次数
- trust anchor 不匹配次数
- nonce 绑定失败次数
- public key 绑定失败次数

这些指标应按 provider、协议族、relay 实例、field policy version、`tee_platform`、`tee_profile`、measurement version 维度聚合，避免把协议规则问题误判成单个客户请求问题，也避免把某个平台的 evidence 验证问题误判成字段级 proof 问题。

### 12.4 接口原则

字段级 proof 按新版本协议落地，重点保证：

1. 字段提取规则、签名规则、verifier 规则一致。
2. 协议识别规则一致。
3. `field_claims` 的结构与含义固定。
4. 主校验字段与提示字段的边界固定。

不再为旧 verifier、旧 proof 包装或旧 relay 接入协议保留兼容分支。

---

## 13. 明确不支持与弱保证场景

### 13.1 弱保证场景

以下场景允许生成 proof，但必须标记为弱保证，不能承诺 verifier 最终通过：

1. OpenAI -> Claude 跨协议转换
2. OpenAI -> Gemini 跨协议转换
3. Claude -> OpenAI 跨协议转换
4. Gemini -> OpenAI 跨协议转换

这些场景下：

- Enclave 可提取上游请求/响应关键字段
- verifier 可提取客户端实际请求/响应关键字段
- 可照常生成 proof
- 可交给 verifier 校验
- 但校验失败是预期内结果之一

### 13.2 仍然不支持的场景

以下场景在本方案里仍应直接标注为“不支持”或“降级为无 proof”：

1. relay 在 proof 之后又继续改写关键语义字段
2. verifier 无法获取用户实际收到的下游响应，或该响应无法被稳定提取字段
3. tool 调用参数经过业务代码二次合成且无可追溯原始来源
4. 无法确定请求所属协议族
5. 响应内容经过不可逆二次加工且无法提取稳定字段

---

## 14. 最终建议

### 14.1 当前阶段建议

当前阶段建议把这套方案定义为：

**面向多中转站推广的字段级 proof 标准。**

先解决这件事：

> 在不要求大规模改造中转站的前提下，证明主流模型协议中的关键请求字段和关键响应字段没有被未声明篡改。

### 14.2 推荐实施顺序

1. 先实现 `openai.chat_completions`
2. 再实现 `openai.responses`
3. 再实现 `anthropic.messages`
4. 再实现 `google.gemini.generate_content`
5. 再补 `dashscope native / bedrock converse / cohere chat`

### 14.3 对外沟通口径

对客户、合作方、第三方 relay 开发者，建议统一口径：

- 这不是完整协议透明证明
- 这不是跨协议语义等价证明
- 跨协议路径即使返回 proof，也默认只是弱保证
- `request_body_sha256` / `response_body_sha256` 不一致时只告警，不代表主校验失败
- 这是“关键字段级、低侵入、可规模化接入”的生产 proof 方案

一句话总结：

> 本方案把 proof 的目标从“证明所有字节完全不变”收敛为“证明主流模型协议中的关键字段内容未被未声明篡改”，以换取跨多个第三方中转站可接受的接入成本与长期生产可运维性。
