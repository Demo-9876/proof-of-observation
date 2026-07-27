import { describe, expect, it } from 'vitest';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { computeV2SigningMaterial } from './signing.ts';
import type { AttestationVerifier } from './tee-verify-core.ts';
import type { EvidenceProfileVerifier } from './evidence-profile.ts';
import { buildFieldClaims } from './field-proof.ts';
import { detectProofPlatform, verifyUnifiedExchange, type UnifiedProofWire } from './unified-verifier.ts';

const NONCE = Buffer.from('a-fresh-16b-nonce').toString('base64');
const PCR0 = 'aeb9e595deadbeef';
const HOST = 'api.example.com';
const PATH = '/v1/chat/completions';
const REQUEST_BODY = Buffer.from('{"model":"example","messages":[{"role":"user","content":"hi"}],"stream":false}', 'utf8');
const RESPONSE_BODY = Buffer.from('{"model":"example","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}', 'utf8');

function makeSignedProof(): { proof: UnifiedProofWire; pubB64: string; requestBody: Buffer; responseBody: Buffer } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const field = buildFieldClaims({
    nonceB64: NONCE,
    upstreamHost: HOST,
    upstreamPath: PATH,
    httpMethod: 'POST',
    httpStatus: 200,
    requestBody: REQUEST_BODY,
    responseBody: RESPONSE_BODY,
  });
  const { statement, digests } = computeV2SigningMaterial({
    nonceB64: NONCE,
    upstreamHost: HOST,
    upstreamPath: PATH,
    httpMethod: 'POST',
    httpStatus: 200,
    respContentType: 'application/json',
    requestBody: REQUEST_BODY,
    responseBody: RESPONSE_BODY,
    fieldClaims: field!.claims,
  });
  return {
    proof: {
      v: 2,
      alg: 'ed25519',
      public_key: pubB64,
      nonce: NONCE,
      upstream_host: HOST,
      upstream_path: PATH,
      http_method: 'POST',
      http_status: 200,
      resp_content_type: 'application/json',
      request_body_sha256: digests.requestBody.toString('hex'),
      response_body_sha256: digests.responseBody.toString('hex'),
      field_claims: field!.claims,
      signature: edSign(null, statement, privateKey).toString('base64'),
      attestation: 'AA==',
      pcr0: PCR0,
    },
    pubB64,
    requestBody: REQUEST_BODY,
    responseBody: RESPONSE_BODY,
  };
}

function stubNitro(overrides: Partial<ReturnType<AttestationVerifier>> & { publicKey?: string } = {}): AttestationVerifier {
  return () => ({
    ok: true,
    sigOk: true,
    chainOk: true,
    rootSelf: true,
    rootPinned: true,
    timeValid: true,
    leafNotAfter: '2099-01-01T00:00:00Z',
    moduleId: 'i-test-enc',
    pcr0: PCR0,
    nonce: NONCE,
    rootFingerprint: '64:1A:03:21',
    publicKey: overrides.publicKey ?? null,
    ...overrides,
  });
}

function stubEvidence(profile: string, pubB64: string): EvidenceProfileVerifier {
  return {
    profile,
    verifyEvidence({ proof }) {
      return {
        ok: true,
        profile,
        checks: [
          { name: 'Evidence 格式', ok: true, detail: `${profile} fixture evidence ok` },
          { name: 'PCR0 比对', ok: true, detail: 'PCR0 == trust allowlist' },
          { name: '公钥绑定', ok: true, detail: 'public key bound' },
          { name: 'nonce 绑定', ok: true, detail: 'nonce bound' },
          { name: '平台证明链', ok: true, detail: 'platform trust ok' },
        ],
        moduleId: `${profile}-module`,
        pcr0: PCR0,
        publicKey: pubB64,
        nonce: proof.nonce,
        platformTrust: {
          ok: true,
          mode: 'cert-chain',
          issuer: `${profile}-root`,
          detail: 'platform trust ok',
        },
      };
    },
  };
}

describe('detectProofPlatform', () => {
  it('does not let trust_anchor_id override tee_platform routing', () => {
    const { proof } = makeSignedProof();
    const detected = detectProofPlatform({
      ...proof,
      tee_platform: 'aws',
      trust_anchor_id: 'aliyun-root-g1',
      evidence: { profile: 'aliyun-vtpm' },
    });
    expect(detected.platform).toBe('aws');
    expect(detected.profile).toBe('nitro');
    expect(detected.source).toBe('tee_platform');
  });

  it('normalises documented tee_profile values to existing verifier profiles', () => {
    expect(detectProofPlatform({ tee_profile: 'aws-nitro' }).profile).toBe('nitro');
    expect(detectProofPlatform({ tee_profile: 'aliyun-enclave' }).profile).toBe('aliyun-vtpm');
    expect(detectProofPlatform({ tee_profile: 'huawei-qingtian' }).profile).toBe('qingtian');
  });
});

describe('verifyUnifiedExchange', () => {
  it('keeps legacy Nitro proofs working through the unified verifier', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const r = verifyUnifiedExchange(
      { proof, requestBody, responseBody, expectedHost: HOST, trustedMeasurement: PCR0 },
      { verifyAttestationDoc: stubNitro({ publicKey: pubB64 }) },
    );
    expect(r.platform.detected_tee_platform).toBe('aws');
    expect(r.platform.detected_tee_profile).toBe('nitro');
    expect(r.platform.public_key_bound).toBe(true);
    expect(r.platform.nonce_bound).toBe(true);
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('accepts Nitro trust bundles that only pin expectedPcrs.sha384:0', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const r = verifyUnifiedExchange(
      {
        proof,
        requestBody,
        responseBody,
        expectedHost: HOST,
        trust: { profile: 'nitro', expectedPcrs: { 'sha384:0': PCR0 } },
      },
      { verifyAttestationDoc: stubNitro({ publicKey: pubB64 }) },
    );
    expect(r.platform.trusted_measurement).toBe(PCR0);
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('routes Alibaba proofs to the aliyun-vtpm evidence verifier', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const aliyunProof = {
      ...proof,
      tee_platform: 'aliyun',
      tee_profile: 'aliyun-vtpm',
      profile: 'aliyun-vtpm',
      evidence: { profile: 'aliyun-vtpm' },
    };
    const r = verifyUnifiedExchange(
      { proof: aliyunProof, requestBody, responseBody, expectedHost: HOST, trust: { profile: 'aliyun-vtpm', expectedPcr0: PCR0 } },
      { evidenceVerifiers: { 'aliyun-vtpm': stubEvidence('aliyun-vtpm', pubB64) } },
    );
    expect(r.platform.detected_tee_platform).toBe('aliyun');
    expect(r.platform.detected_tee_profile).toBe('aliyun-vtpm');
    expect(r.platform.measurement_matched).toBe(true);
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('routes Huawei proofs to the qingtian evidence verifier', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const qingtianProof = {
      ...proof,
      tee_platform: 'huawei',
      tee_profile: 'huawei-qingtian',
      profile: 'qingtian',
      evidence: { profile: 'qingtian' },
    };
    const r = verifyUnifiedExchange(
      { proof: qingtianProof, requestBody, responseBody, expectedHost: HOST, trust: { profile: 'qingtian', expectedPcr0: PCR0 } },
      { evidenceVerifiers: { qingtian: stubEvidence('qingtian', pubB64) } },
    );
    expect(r.platform.detected_tee_platform).toBe('huawei');
    expect(r.platform.detected_tee_profile).toBe('qingtian');
    expect(r.platform.revocation_checked).toBe(false);
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('fails unified verification when field_claims are missing', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const legacyProof = { ...proof };
    delete (legacyProof as Partial<UnifiedProofWire>).field_claims;
    const r = verifyUnifiedExchange(
      { proof: legacyProof as UnifiedProofWire, requestBody, responseBody, expectedHost: HOST, trustedMeasurement: PCR0 },
      { verifyAttestationDoc: stubNitro({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '字段级 proof')?.ok).toBe(false);
  });

  it('auto-routes proof-declared non-Nitro profiles without local trust.profile', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const aliyunProof = {
      ...proof,
      tee_platform: 'aliyun',
      tee_profile: 'aliyun-vtpm',
      profile: 'aliyun-vtpm',
      evidence: { profile: 'aliyun-vtpm' },
    };
    const r = verifyUnifiedExchange(
      { proof: aliyunProof, requestBody, responseBody, expectedHost: HOST },
      { evidenceVerifiers: { 'aliyun-vtpm': stubEvidence('aliyun-vtpm', pubB64) } },
    );
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.platform.detected_tee_platform).toBe('aliyun');
    expect(r.platform.detected_tee_profile).toBe('aliyun-vtpm');
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.ok).toBe(true);
  });

  it('fails closed when tee_platform and explicit proof profile conflict', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSignedProof();
    const conflictingProof = {
      ...proof,
      tee_platform: 'aws',
      profile: 'qingtian',
    };
    const r = verifyUnifiedExchange(
      { proof: conflictingProof, requestBody, responseBody, expectedHost: HOST, trustedMeasurement: PCR0 },
      { verifyAttestationDoc: stubNitro({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'TEE 平台识别')?.detail).toContain('冲突');
  });
});
