// 统一 proof verifier CLI。
//
// 自动识别 proof 属于 Nitro / aliyun-vtpm / QingTian 哪个平台，然后复用
// verifier/tee-verify-core.ts 已有的 evidence profile verifier 做真实校验。

import { readFileSync } from 'node:fs';
import { parseTeeProofCapture } from './tee-verify-core.ts';
import { verifyUnifiedExchange, type UnifiedProofWire } from './unified-verifier.ts';
import type { EvidenceTrust } from './evidence-profile.ts';
import { resolveLegacyNitroPcr0 } from './trust-config.ts';

const args = process.argv.slice(2);
const flag = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);

const proofPath = flag('--proof');
const responsePath = flag('--response');
const requestPath = flag('--request');
const trustPath = flag('--trust');
const host = flag('--host');
const trustedMeasurement = flag('--trusted-measurement') ?? flag('--pcr0');
const expectedNonceB64 = flag('--nonce-b64');
const now = flag('--now') ? Number(flag('--now')) : undefined;

if (!responsePath) {
  console.error('用法: tsx verify-unified-proof.ts --response <resp.bin> [--proof <proof.json>] [--request <req.bin>] [--trust <trust.json>] [--host <upstream-host>] [--trusted-measurement <value>] [--nonce-b64 <b64>] [--now <epoch-ms>]');
  process.exit(2);
}

const detachedProof = proofPath ? readProofFile(proofPath) : undefined;
const responseCapture = readFileSync(responsePath);
const parsedCapture = parseTeeProofCapture(responseCapture);
if (detachedProof && parsedCapture.proof && stableJson(detachedProof) !== stableJson(parsedCapture.proof)) {
  console.error('ERROR detached proof does not match tee.proof embedded in response capture');
  process.exit(1);
}
const proof = detachedProof ?? (parsedCapture.proof as UnifiedProofWire | undefined);
if (!proof) {
  console.error('ERROR no proof provided: pass --proof <proof.json>, or provide a response capture containing tee.proof');
  process.exit(1);
}
const responseBody = parsedCapture.body;
const requestBody = requestPath ? readFileSync(requestPath) : undefined;
const trust = trustPath ? JSON.parse(readFileSync(trustPath, 'utf8')) as EvidenceTrust : undefined;
const effectiveTrustedMeasurement = trustedMeasurement ?? resolveLegacyNitroPcr0(trust);

const result = verifyUnifiedExchange({
  proof,
  responseBody,
  requestBody,
  trust,
  expectedHost: host,
  expectedNonceB64,
  trustedMeasurement: effectiveTrustedMeasurement,
  now,
});

console.log('proof-of-observation unified verifier');
console.log(`proof source      : ${detachedProof ? (parsedCapture.proof ? 'detached+embedded' : 'detached') : 'embedded response'}`);
console.log(`response bytes    : ${responseBody.byteLength}`);
console.log(`detected platform : ${result.platform.detected_tee_platform}`);
console.log(`detected profile  : ${result.platform.detected_tee_profile ?? '<none>'}`);
console.log(`detection source  : ${result.platform.detection_source}`);
console.log(`proof mode        : ${result.mode}`);
console.log(`platform version  : ${result.platform.platform_verifier_version}`);
console.log(`trusted measure   : ${result.platform.trusted_measurement ?? '<none>'}`);
console.log(`reported measure  : ${result.platform.reported_measurement ?? '<none>'}`);
console.log(`measurement match : ${result.platform.measurement_matched}`);
console.log(`attestation ok    : ${result.platform.attestation_verified}`);
console.log(`measurement checks: ${result.platform.measurement_checked}`);
console.log(`public key bound  : ${result.platform.public_key_bound}`);
console.log(`nonce bound       : ${result.platform.nonce_bound}`);
console.log(`revocation check  : ${result.platform.revocation_checked}`);
console.log(`upstream          : ${result.core.provenance.upstreamHost}${result.core.provenance.upstreamPath}`);
for (const c of result.checks) {
  const prefix = c.skipped ? 'SKIP' : (c.ok ? 'PASS' : 'FAIL');
  console.log(`${prefix} ${c.name}: ${c.detail}`);
}
console.log(result.ok ? 'PASS unified proof verification' : 'FAIL unified proof verification');
process.exit(result.ok ? 0 : 1);

function readProofFile(path: string): UnifiedProofWire {
  const proofRaw = JSON.parse(readFileSync(path, 'utf8'));
  return (proofRaw.proof ?? proofRaw) as UnifiedProofWire;
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortJson(v)]),
    );
  }
  return value;
}
