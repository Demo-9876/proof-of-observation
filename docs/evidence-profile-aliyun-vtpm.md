# Evidence Profile: `aliyun-vtpm`

Status: **Node verifier supports experimental quote/PCR verification and local
certificate-chain appraisal. Production rollout still requires real
`QuoteReport.Cert` fixtures and CRL checking integration.**

This document defines the Alibaba Cloud Enclave vTPM evidence profile for
`proof-of-observation`.

The production trust path for this profile is:

```text
QuoteReport.Cert -> Alibaba Cloud root/intermediate certificate chain
QuoteReport.Cert public key -> TPM quote signature
TPM quote QualifyingData -> proof challenge payload
TPM quote PCR digest -> PCR values
PCR values -> user allowlist
challenge payload -> tee-exchange-v2 statement facts
Ed25519 statement signature -> response/request bytes
```

This profile does **not** call Alibaba Cloud remote attestation service to obtain
an OIDC/JWT token during proof generation. Earlier research on
`attest.<region>.aliyuncs.com` and `trusted-server.<region>.aliyuncs.com` remains
background only and is not part of the selected production path.

## Trust Boundary

The application statement layer stays the same as the Nitro implementation:

- `tee-exchange-v2` is signed with an Ed25519 key generated inside the Enclave.
- The signed statement binds nonce, upstream host/path, method/status/content-type,
  request hash, and response hash.
- The verifier recomputes request/response hashes from bytes it holds.

The `aliyun-vtpm` evidence layer is separate:

- PCR values prove code/image identity only.
- TPM quote self-consistency proves the quote was signed by the key in
  `QuoteReport.Cert`.
- Alibaba Cloud platform identity is proven only when `QuoteReport.Cert` chains
  to the configured Alibaba Cloud TPM root/intermediate certificates and the EK
  certificate subject identifies an Enclave vTPM.

## Wire Shape

Existing Nitro proofs omit `profile`, so the verifier treats them as `nitro`.
Alibaba Cloud proofs set:

```json
{
  "v": 2,
  "profile": "aliyun-vtpm",
  "alg": "ed25519",
  "public_key": "<base64 Ed25519 SPKI>",
  "nonce": "<base64 verifier nonce>",
  "upstream_host": "api.example.com",
  "upstream_path": "/v1/messages",
  "http_method": "POST",
  "http_status": 200,
  "resp_content_type": "text/event-stream",
  "request_body_sha256": "<hex>",
  "response_body_sha256": "<hex>",
  "signature": "<base64 Ed25519 signature>",
  "attestation": "<base64 JSON evidence envelope>",
  "evidence": {
    "profile": "aliyun-vtpm",
    "version": 1,
    "attester": {
      "sdk": "github.com/aliyun/acs-apsara-enclave/sdk/attest",
      "sdk_commit": "f81674a6b341e7b835d33ee5da9cb2add6a24379",
      "quote_handle": "SigningEKRSAHandle"
    },
    "quote_report": {
      "quoted_b64": "<base64 TPMS_ATTEST>",
      "signature_b64": "<base64 TPMT_SIGNATURE>",
      "pcr_info": {
        "pcr_values_b64": "<base64 TPML_DIGEST>",
        "pcr_selection_out_b64": "<base64 TPML_PCR_SELECTION>",
        "pcr_update_counter": 0
      },
      "cert_b64": "<base64 DER certificate>"
    },
    "challenge": {
      "alg": "sha256",
      "payload_b64": "<base64 canonical challenge payload>",
      "qualifying_data_hex": "<hex sha256(payload)>"
    },
    "platform_attestation": {
      "mode": "missing",
      "cert_chain_pem": [],
      "trust_anchor_id": null,
      "revocation": {
        "checked": false,
        "method": null
      }
    }
  }
}
```

The structured `evidence` field is preferred. `attestation` may carry the same
JSON envelope as base64 for transport compatibility.

The verifier must choose the evidence profile from local trust configuration.
`proof.profile` is only an on-wire consistency field. If `proof.profile` is
present and differs from `trust.profile`, verification must fail closed. Only
legacy Nitro verification may default missing profile information to `nitro`.

`attester.sdk`, `attester.sdk_commit`, and `attester.quote_handle` are diagnostic
metadata supplied by the proof. They are not trusted inputs and must not directly
drive trust decisions. SDK/tool versions are trusted only indirectly through PCR
allowlists, reproducible build records, and verifier trust configuration.

`platform_attestation.cert_chain_pem`, when present, is untrusted input. It may
help diagnostics, but trust anchors, fingerprints, accepted CN pattern, and
revocation policy must come from the verifier trust configuration, never from
the proof itself.

## Alibaba Cloud TPM CA Material

Alibaba Cloud confirmed that Enclave vTPM uses the TPM 2.0 SigningEK flow. The
`QuoteReport.Cert` is the TPM EK certificate for the key that signs the quote.
It should be verified as a normal TPM quote certificate chain.

Official CA material:

- EK intermediate CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt`
- EK root CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt`

Observed SHA-256 fingerprints from the official CA files:

- Root CA:
  `870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f`
- EKMF intermediate CA:
  `141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0`

The official `.crt` objects are ASCII certificate dumps containing a PEM block.
For verifier configuration, either provide the PEM block itself or the complete
downloaded text; the Node verifier extracts the PEM block.

The EK certificate CN distinguishes ordinary vTPM and Enclave vTPM. Alibaba
Cloud guidance says ordinary vTPM CN is the ECS instance id such as `i-xxxxx`,
while Enclave EK CN has an Enclave suffix, for example `i-xxxxxxx-01`. The
default verifier CN pattern is:

```text
^i-[A-Za-z0-9][A-Za-z0-9-]*-[0-9]{2}$
```

Override `platformTrust.enclaveSubjectCnPattern` if a real certificate sample
shows a narrower or different production format.

Revocation uses CRL. The CRL files are in the same OSS bucket. The current
TypeScript verifier does not parse CRLs; when `revocation.required=true`, it
fails closed unless the caller sets `revocation.checkedExternally=true` after
performing an external CRL check. This prevents silently treating an unchecked
CRL requirement as satisfied.

## Alibaba Cloud Technical Reply Summary

The following items came from Alibaba Cloud technical support and should be kept
with the profile so the trust decisions are not lost:

1. Enclave vTPM uses TPM 2.0 SigningEK. `QuoteReport.Cert` is the EK
   certificate for the key that signs the quote.
2. The evidence is a normal TPM quote. Verification should follow the standard
   TPM quote path: verify the EK certificate chain, use the EK public key to
   verify the quote signature, check `QualifyingData`, and compare PCR values
   against the verifier allowlist.
3. No special KeyUsage or policy OID was identified for this integration beyond
   rooting the EK certificate to Alibaba Cloud's TPM CA chain.
4. Ordinary ECS vTPM and Enclave vTPM can be distinguished from the EK
   certificate subject CN. Ordinary vTPM uses an instance id such as `i-xxxxx`;
   Enclave vTPM uses a suffixed form such as `i-xxxxxxx-01`. A real certificate
   sample should still be collected to confirm the exact production pattern.
5. Revocation uses CRL files in the same `aliyun-tpm-ca` OSS bucket. Alibaba
   Cloud stated there is no known key-leak issue and the CRL is empty at the
   time of the reply, but production verifiers should still have a CRL policy.
6. TPM `userData` / `QualifyingData` length is limited, so the recommended
   practice is to pass a hash. This profile uses
   `sha256(canonical_challenge_payload)`.
7. PCR8/PCR9/PCR10 semantics are documented in the Enclave CLI reference. The
   current verifier allowlist requires PCR8/PCR9/PCR11 because those are the
   measurements observed and used in the current implementation. PCR12 can be
   added later if the deployment or KMS support requires it.
8. Debug mode must never be accepted for production proofs. Alibaba Cloud's
   Enclave CLI documentation says debug mode is what enables
   `enclave-cli console`, and measurements produced in debug mode are all zero
   and cannot pass remote attestation.
9. Alibaba Cloud did not provide sample verifier code; implementation should
   follow standard TPM quote and certificate-chain verification practice.

## Challenge Binding

The verifier rebuilds the quote challenge from signed statement fields:

```json
{
  "profile": "aliyun-vtpm",
  "nonce": "<proof.nonce>",
  "statement_public_key_sha256": "<sha256(proof.public_key SPKI DER)>",
  "request_body_sha256": "<proof.request_body_sha256>",
  "response_body_sha256": "<proof.response_body_sha256>",
  "upstream_host": "<proof.upstream_host>",
  "upstream_path": "<proof.upstream_path>",
  "http_method": "<proof.http_method>",
  "http_status": 200,
  "resp_content_type": "<proof.resp_content_type>"
}
```

Canonicalization is byte-level and must be identical in the Enclave and verifier:

```text
challenge_payload = RFC 8785 JCS canonical JSON bytes
qualifying_data = sha256(challenge_payload)
```

Rules:

- UTF-8 only.
- The field set is exactly the fields shown above; extra fields are not included
  in the hash.
- `nonce` is the proof top-level base64 nonce string.
- `statement_public_key_sha256` is SHA-256 over `proof.public_key` decoded as
  SPKI DER, encoded as lowercase hex.
- `http_status` is a JSON number; all other fields are JSON strings.
- The hash input is the canonical JSON bytes, not pretty JSON and not a base64
  string.

`QuoteReport.quoted` must contain a TPM quote whose `extraData` /
`QualifyingData` equals `qualifying_data`.

## Verifier Checks

The verifier must perform these checks:

1. Parse the `aliyun-vtpm` evidence envelope.
2. Decode `QuoteReport.quoted`, `QuoteReport.signature`,
   `QuoteReport.pcrInfo`, and `QuoteReport.cert`.
3. Rebuild the expected canonical challenge payload from the signed proof fields.
4. Verify `base64decode(challenge.payload_b64)` equals the rebuilt canonical
   challenge payload bytes.
5. Verify `challenge.qualifying_data_hex == sha256(rebuilt challenge payload)`.
6. Parse `QuoteReport.Cert` and extract its public key.
7. If `requirePlatformTrust=true`, verify `QuoteReport.Cert` chains to the
   configured Alibaba Cloud TPM root/intermediate certificates.
8. Verify certificate validity, configured root/intermediate fingerprints,
   Enclave EK subject CN pattern, and revocation status according to verifier
   trust configuration.
9. If the chain is missing, report `platform_trust_missing`; if the chain is
   configured but fails, report `platform_trust_invalid`.
10. `platform_trust_missing` may pass only in experimental mode when
    `requirePlatformTrust=false`; `platform_trust_invalid` should fail closed by
    default even in experimental mode.
11. Verify the TPM quote signature with the EK certificate public key.
12. Verify quote `extraData` equals `sha256(challenge_payload)`.
13. Recompute the PCR digest from `PCRInfo.PCRValues` and
   `PCRInfo.PCRSelectionOut`.
14. Compare PCR8/PCR9/PCR11 against the configured allowlist.
15. Verify the `tee-exchange-v2` Ed25519 statement signature.
16. Verify response bytes and optional request bytes match signed hashes.

The current TypeScript verifier cannot directly import `google/go-tpm-tools`.
Implementation should either:

- add a small Go verifier helper/library that uses `google/go-tpm-tools/quote`
  and returns stable JSON to TypeScript; or
- implement equivalent TPM quote parsing/checks in TypeScript and calibrate it
  against fixtures produced by `google/go-tpm-tools`.

The core verifier must not depend on shelling out to `tpm2_checkquote`.

The browser verifier does not support `aliyun-vtpm` in the first implementation
phase. It should report the profile as unsupported. Browser support requires a
pure TypeScript or WASM implementation of quote and certificate-chain
verification; it cannot rely on the local Go helper.

## Enclave-Side Proof Generator

The first Alibaba Cloud Enclave-side implementation lives in
`aliyun-enclave/`.

It contains:

- `internal/proof`: shared proof construction for `tee-exchange-v2`, canonical
  `aliyun-vtpm` challenge payload, evidence envelope, and Ed25519 signature.
- `internal/attester`: vTPM attester interface plus an Alibaba Cloud SDK adapter
  behind the `aliyun_enclave` build tag.
- `cmd/aliyun-proof`: file-based CLI that signs known request/response bytes and
  emits the verifier-compatible proof JSON.

The SDK adapter follows the official `acs-apsara-enclave/sdk/attest` flow:

```go
tpmGuest, err := attest.NewTPMGuest()
defer tpmGuest.Close()
err = tpmGuest.CreateEK(attest.SigningEKRSATemplate, attest.SigningEKRSAHandle)
quoteReport, err := tpmGuest.GetQuote(attest.SigningEKRSAHandle, qualifyingData)
```

At commit `f81674a6b341e7b835d33ee5da9cb2add6a24379`, the SDK serializes the
TPM quote as `QuoteReport.Quoted`, the TPM signature as
`QuoteReport.Signature`, accompanying PCR material as `QuoteReport.PCRInfo`, and
the signing EK certificate read from `SigningEKCertNVHandle` as
`QuoteReport.Cert`. The SDK quote selection covers SHA-256 PCR 0-23; the
verifier currently requires allowlist entries for PCR8, PCR9, and PCR11.

This CLI is not yet the final streaming proxy. The final proxy should reuse
`internal/proof.GenerateFromHashes` after it has streamed the upstream response
and has the request/response SHA-256 digests, then attach the returned proof as
the existing `tee.proof` trailer/event.

## Verifier Trust Configuration

Experimental configuration:

```json
{
  "profile": "aliyun-vtpm",
  "requirePlatformTrust": false,
  "expectedPcrs": {
    "sha256:8": "<PCR8>",
    "sha256:9": "<PCR9>",
    "sha256:11": "<PCR11>"
  },
  "platformTrust": {
    "mode": "missing"
  }
}
```

Production configuration:

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
    "trustAnchorId": "aliyun-ecs-enclave-vtpm-prod",
    "rootCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "intermediateCertificatesPem": ["-----BEGIN CERTIFICATE-----..."],
    "rootFingerprintsSha256": [
      "870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f"
    ],
    "intermediateFingerprintsSha256": [
      "141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0"
    ],
    "enclaveSubjectCnPattern": "^i-[A-Za-z0-9][A-Za-z0-9-]*-[0-9]{2}$",
    "revocation": {
      "required": false,
      "method": "crl",
      "checkedExternally": false
    }
  }
}
```

Set `revocation.required=true` only after wiring a CRL checker or after an
external verifier has checked the CRL and set `checkedExternally=true`.

The Node verifier CLIs accept this trust bundle with `--trust <trust.json>`.
For replay protection, pass the verifier/requester challenge nonce with
`--nonce-b64 <b64>`. The local verification proxy also supports
`--nonce-header <header>`: it generates a fresh nonce per request, sends it to
the relay in that header, and requires the returned proof to use the same nonce.
That mode requires the relay/Enclave side to read and honor the configured
header. When the proxy runs with `--enforce`, missing proof and failed proof
verification both fail closed with HTTP 502.

## PCR And Debug-Mode Notes

Alibaba Cloud confirmed that PCR8/PCR9/PCR10 are described in the Enclave CLI
reference. The current allowlist requires PCR8/PCR9/PCR11, matching the
measurement set observed during the live vTPM experiment. PCR12 can be added
later if the deployment starts relying on it; Alibaba Cloud KMS did not support
PCR12 at the time of this note.

Debug mode must not be used for production proofs. The Enclave CLI reference
states that only debug mode allows `enclave-cli console`, and that measurements
generated in debug mode are all zero and cannot pass remote attestation.

## Remaining Production Work

Remaining production work:

- collect a real `QuoteReport.Cert` from Alibaba Cloud Enclave and confirm the
  exact CN shape;
- wire CRL parsing/checking or an external CRL appraisal step;
- calibrate the TypeScript TPM parser against a real SDK `QuoteReport` fixture
  and, ideally, cross-check with `google/go-tpm-tools`;
- decide whether `pcr_update_counter` requires policy appraisal beyond being
  included in the evidence envelope.
