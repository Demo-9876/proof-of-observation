# 自证验证侧 + golden 向量(v2 字段分解)

> 总纲见 [`../docs/TEE.md`](../docs/TEE.md);签名设计见 [`../docs/tee-signing-v2-design.md`](../docs/tee-signing-v2-design.md)。
>
> 真飞地核是 Rust([`../enclave/`](../enclave),默认装进 Nitro EIF、真 NSM attestation COSE/ECDSA-P384)。
> 本目录是**验证侧**:签名承重墙、共享验证核、客户端验证器、golden 向量。

## 文件

| 文件 | 角色 |
|---|---|
| `signing.ts` | v2 声明 `buildV2Statement`(承重墙;与飞地 Rust `build_v2_statement` 逐字节一致) |
| `tee-verify-core.ts` | 共享验证核:按 Evidence profile 验证明材料 + 重建 v2 声明验签 + body 哈希核对 + 读 host;各验证器共用、零漂移 |
| `evidence-profile.ts` | Evidence profile 抽象:保留 Nitro,并允许新增 TEE profile |
| `evidence-nitro.ts` | `nitro` profile:包装真 Nitro attestation(COSE_Sign1 / ECDSA-P384 / X.509 链到 AWS 根)验证器 |
| `verify-attestation-cose.mjs` | Nitro COSE/P-384/X.509 链验证器 |
| `tee-verify-stream.ts` | CLI 抓包抽查(response-only):SSE / multipart → 验 v2 proof + **读出签名覆盖的 host** |
| `verify-real-bundle.ts` | CLI 整 bundle 离线验(full 档):多一项请求绑定 |
| `tee-verify-proxy.ts` | 本地校验代理:把客户端 baseURL 指过来,每调透明验 |
| `trust-config.ts` | `--pcr0` legacy Nitro 与 `--trust <trust.json>` profile trust config 入口 |
| `signing-vectors.{gen,test}.ts` + `../enclave/signing-vectors.json` | golden 向量(`cases_v2`) |
| `test-cose-browser.mjs` | 浏览器 COSE 验证逻辑对齐自查 |

## 验证(客户端)

```bash
# 抓一段完整响应(SSE 或 multipart/mixed)→ 验
npx tsx tee-verify-stream.ts captured-response --pcr0 <规范 PCR0>
#   → 链到 AWS 根 + PCR0==公布值 + 公钥绑定 + nonce 绑定 + 声明验签 + 读出签名覆盖的 host

# QingTian 等非 Nitro profile → 用本地 trust bundle 验；离线/抓包场景可带本次挑战 nonce
npx tsx tee-verify-stream.ts captured-response --trust qingtian-trust.json --nonce-b64 <本次挑战 nonce>
```
支持两种 capture:

- 流式 SSE:保存完整上游 SSE 字节,末尾包含 `event: tee.proof`。
- 非流式 proof mode:保存完整 `multipart/mixed` body,第一段是 raw response bytes,第二段是 proof；也支持终端保存的 raw body + proof 尾段。

或浏览器:开 [`../docs/tee-verify.html`](../docs/tee-verify.html) 贴流式 SSE 或非流式 proof 响应；终端保存的 body+proof 尾段也兼容。规范 PCR0 见
[`../docs/tee-reproducible-build.md`](../docs/tee-reproducible-build.md)。

## Evidence profiles

当前生产 profile 仍是 `nitro`。旧 proof 不带 `profile` 字段时默认按 `nitro` 验证,行为与原实现兼容。

`tee-verify-stream.ts`、`verify-real-bundle.ts` 和 `tee-verify-proxy.ts` 均支持:

- `--pcr0 <hex>`: legacy Nitro 兼容入口。
- `--trust <trust.json>`: profile 化 trust bundle,用于 `qingtian` 等非 Nitro profile。
- `--nonce-b64 <b64>`: 离线/抓包验证时强制 proof nonce 等于用户本次挑战 nonce。
- `tee-verify-proxy.ts --nonce-header <header>`: 代理每请求生成 nonce,通过该 header 发给 relay,并要求返回 proof 使用同一个 nonce；需要 relay/Enclave 侧配合读取该 header。
- `tee-verify-proxy.ts --enforce`: fail closed；缺少 proof 或 proof 验证失败都会返回 502。该模式支持流式 SSE 和非流式 multipart proof。

QingTian provider / verifier 必须显式注册对应 profile verifier；未实现或未配置 trust 时会 fail closed。

QingTian trust bundle 最小模板：

```json
{
  "profile": "qingtian",
  "expectedPcrs": {
    "sha384:0": "<official signed EIF PCR0>",
    "sha384:8": "<official signing certificate PCR8>"
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
```

Huawei QingTian root 来源：

```text
https://qingtian-enclave.obs.myhuaweicloud.com/huawei_qingtian-enclaves_root-G1.zip
zip sha256: 99e9203a64cfb0c6495afd815051e97bea8a37895dc083d715674af64adeadfe
```

正式发布时不要使用 smoke PCR；`expectedPcrs` 必须来自项目方发布的 official signed EIF manifest。

## golden 向量(承重墙防漂移)

`../enclave/signing-vectors.json` 的 `cases_v2` 是**三处共同答案卡**:飞地 Rust(`../enclave/src/main.rs` 的
`#[cfg(test)] mod golden`)、TS(`signing-vectors.test.ts`)、浏览器各自重算都必须 == 它,任一处把 v2 声明
布局改歪即红。**只在有意改 v2 布局时**重跑 `npx tsx signing-vectors.gen.ts`(破坏性 → 验证器需重发 + PCR0 变)。
