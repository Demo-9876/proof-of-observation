# Alibaba Cloud Enclave proof generator

[中文版](README.zh-CN.md)

This module is the Alibaba Cloud Enclave-side proof generation prototype for the
`aliyun-vtpm` evidence profile.

It preserves the existing `tee-exchange-v2` statement format and replaces the
Nitro NSM attestation document with an Alibaba Cloud Enclave vTPM QuoteReport
envelope.

## Trust path

The intended production path is:

```text
QuoteReport.Cert -> Alibaba Cloud root/intermediate certificate chain
QuoteReport.Cert public key -> TPM quote signature
TPM quote QualifyingData -> sha256(challenge_payload)
challenge_payload -> tee-exchange-v2 statement facts
PCR values -> verifier allowlist
Ed25519 statement signature -> request/response bytes
```

This generator does not call Alibaba Cloud remote attestation service for an
OIDC/JWT token. The verifier appraises `QuoteReport.Cert` locally against the
Alibaba Cloud TPM EK root/intermediate chain and the Enclave EK certificate CN
rule.

Official CA material confirmed by Alibaba Cloud:

- EK intermediate CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/ekmf-ca.crt`
- EK root CA:
  `https://aliyun-tpm-ca.oss-cn-beijing.aliyuncs.com/pki001/root-ca.crt`

Pinned SHA-256 fingerprints observed from those official CA files:

- Root CA:
  `870d6e888c3531b69983f0aebb7b9802aa097065ae01a825913ad398ce96252f`
- EKMF intermediate CA:
  `141805f04cd9b89bfbcd30cb792d5ca3a0a2382db6ee35720e6e27e4189e43a0`

## Build

Local tests do not require Alibaba Cloud hardware or SDK access:

```bash
cd aliyun-enclave
go test ./...
```

The real vTPM adapter is behind the `aliyun_enclave` build tag. Inside the
Alibaba Cloud Enclave build environment, add the official SDK module and build:

```bash
cd aliyun-enclave
go get github.com/aliyun/acs-apsara-enclave/sdk/attest@f81674a6b341e7b835d33ee5da9cb2add6a24379
go build -tags aliyun_enclave ./cmd/aliyun-proof
go build -tags aliyun_enclave ./cmd/aliyun-proof-helper
```

## Generate a proof

`aliyun-proof` signs existing request/response bytes and asks the vTPM for a
QuoteReport over the canonical challenge payload.

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

Streaming callers can avoid buffering or writing the response body by passing
the already-computed digests:

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

For local experiments only, `--generate-nonce` can create a nonce. Production
callers should pass a verifier/requester nonce and verify that the returned proof
contains the same nonce.

The command writes the same top-level proof shape consumed by
`verifier/tee-verify-core.ts`, including both:

- `evidence`: structured `aliyun-vtpm` evidence envelope;
- `attestation`: base64 JSON encoding of the same envelope for transport
  compatibility.

The reusable library also exposes `proof.GenerateFromHashes`. A production
streaming proxy should use that API after hashing request and response bytes
incrementally, so it does not need to buffer the full upstream response before
creating the proof.

## Helper daemon

`aliyun-proof-helper` is the Enclave-local daemon used by the Rust streaming
relay. It listens on a Unix domain socket, owns the in-process Ed25519 signing
key, reuses the Alibaba Cloud vTPM attester, and returns a complete
`aliyun-vtpm` `tee.proof` for request/response hashes supplied by the relay.

```bash
aliyun-proof-helper --socket /run/aliyun-proof-helper.sock
```

The relay should set:

```bash
export TEE_PROFILE=aliyun-vtpm
export ALIYUN_PROOF_HELPER_SOCKET=/run/aliyun-proof-helper.sock
```

A startup script can wait for readiness with:

```bash
aliyun-proof-helper --socket /run/aliyun-proof-helper.sock --health-check
```

The helper protocol is a 4-byte big-endian length prefix followed by JSON. The
request payload is capped at 64 KiB and the response payload at 4 MiB.

## Runtime image

The combined Alibaba Cloud Enclave runtime lives in
`deploy/aliyun-vtpm-runtime/`:

- `deploy/aliyun-vtpm-runtime/Dockerfile`
- `deploy/aliyun-vtpm-runtime/run.sh`

Build it from the repo root with:

```bash
sudo docker build --network host \
  -f deploy/aliyun-vtpm-runtime/Dockerfile \
  -t proof-of-observation-aliyun-vtpm:latest \
  .
```

## Current limits

- This is the Enclave-side proof generation core plus the helper daemon used by
  the Rust streaming relay. Full production rollout still requires building and
  validating the combined Rust relay + helper EIF on Alibaba Cloud Enclave.
- Production verifier release still needs CRL checking or an external CRL
  appraisal step.
- Browser verifier support for `aliyun-vtpm` is intentionally out of scope for
  the first phase.
