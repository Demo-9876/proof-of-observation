# 自证验证侧 + golden 向量(v2 字段分解)

> 总纲见 [`../docs/TEE.md`](../docs/TEE.md);签名设计见 [`../docs/tee-signing-v2-design.md`](../docs/tee-signing-v2-design.md)。
>
> 真飞地核是 Rust([`../enclave/`](../enclave),装进 Nitro EIF、真 NSM attestation COSE/ECDSA-P384)。
> 本目录是**验证侧**:签名承重墙、共享验证核、客户端验证器、golden 向量。

## 文件

| 文件 | 角色 |
|---|---|
| `signing.ts` | v2 声明 `buildV2Statement`(承重墙;与飞地 Rust `build_v2_statement` 逐字节一致) |
| `tee-verify-core.ts` | 共享验证核:按 Evidence profile 验证明材料 + 重建 v2 声明验签 + body 哈希核对 + 读 host;各验证器共用、零漂移 |
| `evidence-profile.ts` | Evidence profile 抽象:保留 Nitro,并允许新增 TEE profile |
| `evidence-nitro.ts` | `nitro` profile:包装真 Nitro attestation(COSE_Sign1 / ECDSA-P384 / X.509 链到 AWS 根)验证器 |
| `evidence-aliyun-vtpm.ts` | `aliyun-vtpm` profile:验证 `QuoteReport` quote 签名、challenge、PCR digest、PCR allowlist,以及本地配置的 Aliyun TPM EK 证书链和 Enclave EK CN |
| `verify-attestation-cose.mjs` | 真 Nitro attestation(COSE_Sign1 / ECDSA-P384 / X.509 链到 AWS 根)验证器 |
| `tee-verify-stream.ts` | CLI 抓包抽查(response-only):SSE / multipart → 验 v2 proof + **读出签名覆盖的 host** |
| `verify-real-bundle.ts` | CLI 整 bundle 离线验(full 档):多一项请求绑定 |
| `tee-verify-proxy.ts` | 本地校验代理:把客户端 baseURL 指过来,每调透明验 |
| `signing-vectors.{gen,test}.ts` + `../enclave/signing-vectors.json` | golden 向量(`cases_v2`) |
| `test-cose-browser.mjs` | 浏览器 COSE 验证逻辑对齐自查 |

## 验证(客户端)

```bash
# 抓一段完整响应(SSE 或 multipart/mixed)→ 验
npx tsx tee-verify-stream.ts captured-response --pcr0 <规范 PCR0>
#   → 链到 AWS 根 + PCR0==公布值 + 公钥绑定 + nonce 绑定 + 声明验签 + 读出签名覆盖的 host

# 阿里云 aliyun-vtpm profile → 用本地 trust bundle 验
npx tsx tee-verify-stream.ts captured-response --trust aliyun-vtpm-trust.json --nonce-b64 <本次挑战 nonce>
```
支持两种 capture:

- 流式 SSE:保存完整上游 SSE 字节,末尾包含 `event: tee.proof`。
- 非流式 proof mode:保存完整 `multipart/mixed` body,第一段是 raw response bytes,第二段是 proof；也支持终端保存的 raw body + proof 尾段。

或浏览器:开 [`../docs/tee-verify.html`](../docs/tee-verify.html) 贴流式 SSE 或非流式 proof 响应；终端保存的 body+proof 尾段也兼容。规范 PCR0 见
[`../docs/tee-reproducible-build.md`](../docs/tee-reproducible-build.md)。

## Evidence profiles

当前生产 profile 仍是 `nitro`。旧 proof 不带 `profile` 字段时默认按 `nitro` 验证,行为与原实现兼容。

本目录还包含实验性 `aliyun-vtpm` profile。它用于阿里云 Enclave vTPM 接入,可以验证 `QuoteReport` quote 签名、JCS challenge 绑定、PCR digest、PCR8/PCR9/PCR11 allowlist,以及本地配置的 `QuoteReport.Cert` root/intermediate 证书链和 Enclave EK CN 规则。CRL 检查目前需要外部完成；若配置 `revocation.required=true` 但没有声明 `checkedExternally=true`,verifier 会 fail closed。第一阶段浏览器 verifier 不支持该 profile。详见 [`../docs/evidence-profile-aliyun-vtpm.md`](../docs/evidence-profile-aliyun-vtpm.md)。

`tee-verify-stream.ts`、`verify-real-bundle.ts` 和 `tee-verify-proxy.ts` 均支持:

- `--pcr0 <hex>`: legacy Nitro 兼容入口。
- `--trust <trust.json>`: profile 化 trust bundle,用于 `aliyun-vtpm` 等非 Nitro profile。
- `--nonce-b64 <b64>`: 离线/抓包验证时强制 proof nonce 等于用户本次挑战 nonce。
- `tee-verify-proxy.ts --nonce-header <header>`: 代理每请求生成 nonce,通过该 header 发给 relay,并要求返回 proof 使用同一个 nonce；需要 relay/Enclave 侧配合读取该 header。
- `tee-verify-proxy.ts --enforce`: fail closed；缺少 proof 或 proof 验证失败都会返回 502。

`aliyun-vtpm` trust bundle 至少应包含:

```json
{
  "profile": "aliyun-vtpm",
  "requirePlatformTrust": true,
  "expectedPcrs": {
    "sha256:8": "<PCR8>",
    "sha256:9": "<PCR9>",
    "sha256:11": "<PCR11>"
  },
  "platformTrust": {
    "mode": "cert-chain",
    "rootCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "intermediateCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "rootFingerprintsSha256": [
      "870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f"
    ],
    "intermediateFingerprintsSha256": [
      "141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0"
    ],
    "enclaveSubjectCnPattern": "^i-[A-Za-z0-9][A-Za-z0-9-]*-enclave-[0-9]+$",
    "revocation": { "required": false, "method": "crl" }
  }
}
```

## golden 向量(承重墙防漂移)

`../enclave/signing-vectors.json` 的 `cases_v2` 是**三处共同答案卡**:飞地 Rust(`../enclave/src/main.rs` 的
`#[cfg(test)] mod golden`)、TS(`signing-vectors.test.ts`)、浏览器各自重算都必须 == 它,任一处把 v2 声明
布局改歪即红。**只在有意改 v2 布局时**重跑 `npx tsx signing-vectors.gen.ts`(破坏性 → 验证器需重发 + PCR0 变)。
