// 共享验证核心(v2 字段分解)+ 流式 proof 解析的单测。
//
// attestation 半边(真 COSE/P-384)用**注入桩**覆盖 —— 无法伪造真 Nitro 文档,但能完整测
// 编排 + 公钥绑定/PCR0/nonce 三项;真文档半边由 verify-real-bundle 对真 bundle 验。
// 签名半边用真 Ed25519(自生成密钥)+ signing.ts 真 v2 声明,验的是真验签逻辑。

import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as edSign, X509Certificate } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildAliyunVtpmChallengeHex, buildAliyunVtpmChallengePayload } from './evidence-aliyun-vtpm.ts';
import {
  verifyTeeExchange,
  parseTeeProofCapture,
  parseTeeProofEvent,
  parseTeeProofMultipartResponse,
  TEE_PROOF_EVENT,
  WOKEY_SSE_TRANSPORT_KEEPALIVE_V1,
  type TeeProofWire,
  type AttestationVerifier,
} from './tee-verify-core.ts';
import type { EvidenceProfileVerifier } from './evidence-profile.ts';
import { buildFieldClaims } from './field-proof.ts';
import { computeV2SigningMaterial, sha256 } from './signing.ts';

const NONCE = Buffer.from('a-fresh-16b-nonce').toString('base64');
const PCR0 = 'aeb9e595deadbeef';
const HOST = 'api.example.com';
const PATH = '/v1/messages';
const REQUEST_BODY = Buffer.from('{"model":"example","stream":true}', 'utf8');
const RESPONSE_BODY = Buffer.from('event: message_stop\ndata: {}\n\n', 'utf8');

// 用真 Ed25519 + 真 v2 声明造一个签名合法的 proof;att 桩声称背书这把公钥/PCR0/nonce。
function makeSigned(overrides: { requestBody?: Buffer; responseBody?: Buffer } = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const requestBody = overrides.requestBody ?? REQUEST_BODY;
  const responseBody = overrides.responseBody ?? RESPONSE_BODY;
  const { statement, digests } = computeV2SigningMaterial({
    nonceB64: NONCE,
    upstreamHost: HOST,
    upstreamPath: PATH,
    httpMethod: 'POST',
    httpStatus: 200,
    respContentType: 'text/event-stream',
    requestBody,
    responseBody,
  });
  const signature = edSign(null, statement, privateKey).toString('base64');
  const proof: TeeProofWire = {
    v: 2,
    alg: 'ed25519',
    public_key: pubB64,
    nonce: NONCE,
    upstream_host: HOST,
    upstream_path: PATH,
    http_method: 'POST',
    http_status: 200,
    resp_content_type: 'text/event-stream',
    request_body_sha256: digests.requestBody.toString('hex'),
    response_body_sha256: digests.responseBody.toString('hex'),
    signature,
    attestation: 'AA==', // 桩忽略内容
    pcr0: PCR0,
  };
  return { proof, pubB64, requestBody, responseBody };
}

function stubAtt(over: Partial<ReturnType<AttestationVerifier>> & { publicKey?: string }): AttestationVerifier {
  return () => ({
    ok: true, sigOk: true, chainOk: true, rootSelf: true, rootPinned: true, timeValid: true,
    leafNotAfter: '2099-01-01T00:00:00Z', moduleId: 'i-test-enc', pcr0: PCR0, nonce: NONCE,
    rootFingerprint: '64:1A:03:21', ...over,
  });
}

describe('verifyTeeExchange v2 (full mode)', () => {
  it('passes every check for a genuine exchange (incl. host + request binding)', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.mode).toBe('full');
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === '上游 host')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === '请求绑定')?.ok).toBe(true);
    expect(r.provenance.upstreamHost).toBe(HOST);
    expect(r.provenance.upstreamPath).toBe(PATH);
  });

  it('fails the signature check when the response body is tampered', () => {
    const { proof, pubB64, requestBody } = makeSigned();
    const tampered = Buffer.from('event: message_stop\ndata: {"evil":1}\n\n', 'utf8');
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody, responseBody: tampered, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '响应签名')?.ok).toBe(false);
  });

  it('fails request binding when a different request body is presented', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const otherReq = Buffer.from('{"model":"cheap"}', 'utf8');
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody: otherReq, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '请求绑定')?.ok).toBe(false);
  });

  it('passes field-level proof when body bytes differ but covered fields match', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const upstreamPath = '/v1/chat/completions';
    const upstreamRequest = Buffer.from('{"model":"gpt-test","messages":[{"role":"user","content":"hi"}],"temperature":0.7}', 'utf8');
    const upstreamResponse = Buffer.from('{"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":2}}', 'utf8');
    const localRequest = Buffer.from('{"messages":[{"content":"hi","role":"user"}],"temperature":0.7,"model":"gpt-test","relay_only":"ignored"}', 'utf8');
    const localResponse = Buffer.from('{"id":"relay-wrapper","usage":{"total_tokens":2},"choices":[{"finish_reason":"stop","message":{"content":"ok","role":"assistant"},"index":0}],"model":"gpt-test"}', 'utf8');
    const field = buildFieldClaims({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
    });
    expect(field).toBeTruthy();
    const { statement, digests } = computeV2SigningMaterial({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      respContentType: 'application/json',
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
      fieldClaims: field!.claims,
    });
    const proof: TeeProofWire = {
      v: 2,
      alg: 'ed25519',
      public_key: pubB64,
      nonce: NONCE,
      upstream_host: HOST,
      upstream_path: upstreamPath,
      http_method: 'POST',
      http_status: 200,
      resp_content_type: 'application/json',
      request_body_sha256: digests.requestBody.toString('hex'),
      response_body_sha256: digests.responseBody.toString('hex'),
      field_claims: field!.claims,
      signature: edSign(null, statement, privateKey).toString('base64'),
      attestation: 'AA==',
      pcr0: PCR0,
    };
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody: localRequest, responseBody: localResponse, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === '请求字段绑定')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === '响应字段绑定')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === '请求 body hash(advisory)')?.detail).toContain('WARN');
    expect(r.checks.find((c) => c.name === '响应 body hash(advisory)')?.detail).toContain('WARN');
  });

  it('fails field-level proof when field_claims metadata disagrees with proof envelope', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const upstreamPath = '/v1/chat/completions';
    const upstreamRequest = Buffer.from('{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}', 'utf8');
    const upstreamResponse = Buffer.from('{"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}', 'utf8');
    const field = buildFieldClaims({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
    });
    expect(field).toBeTruthy();
    field!.claims.upstream_path = '/v1/other';
    const { statement, digests } = computeV2SigningMaterial({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      respContentType: 'application/json',
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
      fieldClaims: field!.claims,
    });
    const proof: TeeProofWire = {
      v: 2,
      alg: 'ed25519',
      public_key: pubB64,
      nonce: NONCE,
      upstream_host: HOST,
      upstream_path: upstreamPath,
      http_method: 'POST',
      http_status: 200,
      resp_content_type: 'application/json',
      request_body_sha256: digests.requestBody.toString('hex'),
      response_body_sha256: digests.responseBody.toString('hex'),
      field_claims: field!.claims,
      signature: edSign(null, statement, privateKey).toString('base64'),
      attestation: 'AA==',
      pcr0: PCR0,
    };
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, requestBody: upstreamRequest, responseBody: upstreamResponse, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '字段级 proof')?.detail ?? '').toContain('upstream_path');
  });

  it('fails host binding when expectedHost differs', () => {
    const { proof, pubB64, requestBody, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: 'api.different.com', requestBody, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '上游 host')?.ok).toBe(false);
  });
});

describe('verifyTeeExchange v2 (response-only mode)', () => {
  it('verifies untampered response from captured bytes alone; host is displayed (ok)', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    expect(r.mode).toBe('response-only');
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    // response-only 没有请求绑定项
    expect(r.checks.find((c) => c.name === '请求绑定')).toBeUndefined();
    // host 这关只展示(无 expectedHost),ok=true 且 detail 带签名覆盖的 host
    const hostCheck = r.checks.find((c) => c.name === '上游 host');
    expect(hostCheck?.ok).toBe(true);
    expect(hostCheck?.detail).toContain(HOST);
  });

  it('marks request field binding as skipped for response-only field-level proof', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const upstreamPath = '/v1/chat/completions';
    const upstreamRequest = Buffer.from('{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}', 'utf8');
    const upstreamResponse = Buffer.from('{"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}', 'utf8');
    const field = buildFieldClaims({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
    });
    expect(field).toBeTruthy();
    const { statement, digests } = computeV2SigningMaterial({
      nonceB64: NONCE,
      upstreamHost: HOST,
      upstreamPath,
      httpMethod: 'POST',
      httpStatus: 200,
      respContentType: 'application/json',
      requestBody: upstreamRequest,
      responseBody: upstreamResponse,
      fieldClaims: field!.claims,
    });
    const proof: TeeProofWire = {
      v: 2,
      alg: 'ed25519',
      public_key: pubB64,
      nonce: NONCE,
      upstream_host: HOST,
      upstream_path: upstreamPath,
      http_method: 'POST',
      http_status: 200,
      resp_content_type: 'application/json',
      request_body_sha256: digests.requestBody.toString('hex'),
      response_body_sha256: digests.responseBody.toString('hex'),
      field_claims: field!.claims,
      signature: edSign(null, statement, privateKey).toString('base64'),
      attestation: 'AA==',
      pcr0: PCR0,
    };
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, expectedHost: HOST, responseBody: upstreamResponse, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );
    const requestCheck = r.checks.find((c) => c.name === '请求字段绑定');
    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(requestCheck?.ok).toBe(true);
    expect(requestCheck?.skipped).toBe(true);
    expect(requestCheck?.detail).toContain('未检查');
  });

  it('rejects unsupported proof wire versions', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    proof.v = 1;
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.detail).toContain('proof.v');
  });

  it('rejects unsupported proof algorithms', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    proof.alg = 'ed448';
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.detail).toContain('proof.alg');
  });

  it('fails closed instead of throwing when proof fields are malformed', () => {
    const { proof, responseBody } = makeSigned();
    (proof as any).upstream_host = 123;
    (proof as any).request_body_sha256 = 'not-hex';
    const r = verifyTeeExchange({
      expectedPcr0: PCR0,
      expectedHost: HOST,
      responseBody,
      proof,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.detail).toContain('upstream_host must be string');
    expect(r.provenance.upstreamHost).toBe('');
  });

  it('fails closed instead of throwing when proof is not an object', () => {
    const r = verifyTeeExchange({
      expectedPcr0: PCR0,
      responseBody: RESPONSE_BODY,
      proof: null as any,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'proof wire')?.detail).toContain('JSON object');
  });

  it('rejects a wrong-image PCR0', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: 'cafe0000', responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, pcr0: 'deadbeef' }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'PCR0 比对')?.ok).toBe(false);
  });

  it('rejects an unbound signing key (attestation endorses a different pubkey)', () => {
    const { proof, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: 'c29tZS1vdGhlci1rZXk=' }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '公钥绑定')?.ok).toBe(false);
  });

  it('rejects a spliced attestation (att.nonce != proof.nonce)', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, nonce: Buffer.from('other-nonce!!!').toString('base64') }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'nonce 绑定')?.ok).toBe(false);
  });

  it('accepts a verifier-supplied expected nonce when it matches proof.nonce', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof, expectedNonceB64: NONCE },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === 'nonce 新鲜性')?.ok).toBe(true);
  });

  it('rejects replay when verifier-supplied expected nonce differs', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof, expectedNonceB64: Buffer.from('fresh-from-user').toString('base64') },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64 }) },
    );

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'nonce 新鲜性')?.ok).toBe(false);
  });

  it('fails the attestation chain when the doc does not verify', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    const r = verifyTeeExchange(
      { expectedPcr0: PCR0, responseBody, proof },
      { verifyAttestationDoc: stubAtt({ publicKey: pubB64, chainOk: false, sigOk: false }) },
    );
    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '远程证明')?.ok).toBe(false);
  });

  it('auto-routes proof-declared non-Nitro profiles and then verifies evidence', () => {
    const { proof, responseBody } = makeSigned();
    proof.profile = 'qingtian';
    const r = verifyTeeExchange({ responseBody, proof });

    expect(r.ok).toBe(false);
    expect(r.attestation.profile).toBe('qingtian');
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === 'QingTian evidence 格式')?.ok).toBe(false);
  });

  it('fails closed when proof profile and trust profile differ', () => {
    const { proof, responseBody } = makeSigned();
    proof.profile = 'qingtian';
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: { profile: 'nitro', expectedPcr0: PCR0 },
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.detail).toContain('不一致');
  });

  it('uses a non-Nitro trust profile even when proof.profile is omitted', () => {
    const { proof, responseBody } = makeSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        profile: 'qingtian',
        expectedPcrs: { 'sha384:0': PCR0, 'sha384:8': '00' },
        platformTrust: { mode: 'cert-chain' },
      },
    });

    expect(r.ok).toBe(false);
    expect(r.attestation.profile).toBe('qingtian');
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === 'QingTian evidence 格式')?.ok).toBe(false);
  });

  it('fails closed for a trusted but unsupported evidence profile', () => {
    const { proof, responseBody } = makeSigned();
    proof.profile = 'made-up-tee';
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        profile: 'made-up-tee',
        expectedPcrs: { 'sha384:0': PCR0, 'sha384:8': '00' },
        platformTrust: { mode: 'cert-chain' },
      },
    });

    expect(r.ok).toBe(false);
    expect(r.attestation.profile).toBe('made-up-tee');
    expect(r.checks.find((c) => c.name === '远程证明')?.detail).toContain('unsupported evidence profile');
  });

  it('routes non-Nitro profiles through the evidence verifier registry', () => {
    const { proof, pubB64, responseBody } = makeSigned();
    proof.profile = 'qingtian';
    const qingtianVerifier: EvidenceProfileVerifier = {
      profile: 'qingtian',
      verifyEvidence({ proof }) {
        return {
          ok: true,
          profile: 'qingtian',
          checks: [{ name: 'QingTian evidence', ok: true, detail: 'mock qtsm evidence accepted' }],
          pcr0: PCR0,
          pcr8: '11'.repeat(48),
          measurements: { 'sha384:0': PCR0, 'sha384:8': '11'.repeat(48) },
          publicKey: proof.public_key,
          nonce: proof.nonce,
          platformTrust: { ok: true, mode: 'cert-chain', status: 'ok', detail: 'mock platform trust' },
        };
      },
    };

    const r = verifyTeeExchange(
      {
        responseBody,
        proof,
        trust: {
          profile: 'qingtian',
          expectedPcrs: { 'sha384:0': PCR0, 'sha384:8': '11'.repeat(48) },
          platformTrust: { mode: 'cert-chain' },
        },
      },
      { evidenceVerifiers: { qingtian: qingtianVerifier } },
    );

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.attestation.profile).toBe('qingtian');
    expect(r.attestation.publicKey).toBe(pubB64);
    expect(r.attestation.pcr8).toBe('11'.repeat(48));
    expect(r.attestation.platformTrust?.ok).toBe(true);
  });
});

describe('verifyTeeExchange aliyun-vtpm profile (experimental local quote mode)', () => {
  it('verifies QuoteReport signature, challenge, PCR digest, and PCR allowlist without platform trust', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.attestation.profile).toBe('aliyun-vtpm');
    expect(r.attestation.measurements?.['sha256:8']).toBe(expectedPcrs['sha256:8']);
    expect(r.checks.find((c) => c.name === '平台证明链')?.ok).toBe(true);
    expect(r.attestation.platformTrust?.status).toBe('platform_trust_missing');
  });

  it('accepts QuoteReport.quoted_b64 encoded as TPM2B_ATTEST with a size prefix', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const evidence = proof.evidence as any;
    const quoteMsg = Buffer.from(evidence.quote_report.quoted_b64, 'base64');
    evidence.quote_report.quoted_b64 = tpm2b(quoteMsg).toString('base64');
    proof.attestation = Buffer.from(JSON.stringify(evidence), 'utf8').toString('base64');

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === 'QuoteReport 字段')?.detail).toContain('TPM2B_ATTEST');
    expect(r.checks.find((c) => c.name === 'quote 结构')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === 'quote 签名')?.ok).toBe(true);
  });

  it('fails closed when platform trust is required but no QuoteReport.Cert chain is present', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs, { requirePlatformTrust: true }),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '平台证明链')?.ok).toBe(false);
    expect(r.attestation.platformTrust?.status).toBe('platform_trust_missing');
  });

  it('rejects a synthetic SPKI cert unless tests explicitly allow it', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: { profile: 'aliyun-vtpm', expectedPcrs, requirePlatformTrust: false },
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'QuoteReport 字段')?.ok).toBe(false);
  });

  it('rejects missing required PCR allowlist entries', () => {
    const { proof, responseBody } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        profile: 'aliyun-vtpm',
        requirePlatformTrust: false,
        allowSyntheticQuoteReportCertForTest: true,
      },
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'PCR allowlist')?.ok).toBe(false);
  });

  it('verifies QuoteReport.Cert against configured Aliyun TPM root/intermediate and Enclave CN', () => {
    const { proof, responseBody, expectedPcrs, chain } = makeAliyunSignedWithX509Chain('i-testabcdef-enclave-1');
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        ...aliyunTrust(expectedPcrs, { allowSyntheticQuoteReportCertForTest: false }),
        requirePlatformTrust: true,
        platformTrust: {
          mode: 'cert-chain',
          rootCertificatesPem: [chain.rootPem],
          intermediateCertificatesPem: [chain.intermediatePem],
          rootFingerprintsSha256: [certFingerprint(chain.rootPem)],
          intermediateFingerprintsSha256: [certFingerprint(chain.intermediatePem)],
          revocation: { required: false, method: 'crl' },
        },
      },
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.attestation.platformTrust?.status).toBe('ok');
    expect(r.checks.find((c) => c.name === '平台证明链')?.ok).toBe(true);
  });

  it('rejects a QuoteReport.Cert chain whose EK CN does not identify an Enclave vTPM', () => {
    const { proof, responseBody, expectedPcrs, chain } = makeAliyunSignedWithX509Chain('i-testabcdef');
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        ...aliyunTrust(expectedPcrs, { allowSyntheticQuoteReportCertForTest: false }),
        requirePlatformTrust: true,
        platformTrust: {
          mode: 'cert-chain',
          rootCertificatesPem: [chain.rootPem],
          intermediateCertificatesPem: [chain.intermediatePem],
          revocation: { required: false, method: 'crl' },
        },
      },
    });

    expect(r.ok).toBe(false);
    expect(r.attestation.platformTrust?.status).toBe('platform_trust_invalid');
    expect(r.checks.find((c) => c.name === '平台证明链')?.detail).toContain('CN');
  });

  it('fails closed when CRL revocation is required but has not been checked externally', () => {
    const { proof, responseBody, expectedPcrs, chain } = makeAliyunSignedWithX509Chain('i-testabcdef-01');
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        ...aliyunTrust(expectedPcrs, { allowSyntheticQuoteReportCertForTest: false }),
        requirePlatformTrust: true,
        platformTrust: {
          mode: 'cert-chain',
          rootCertificatesPem: [chain.rootPem],
          intermediateCertificatesPem: [chain.intermediatePem],
          revocation: { required: true, method: 'crl' },
        },
      },
    });

    expect(r.ok).toBe(false);
    expect(r.attestation.platformTrust?.status).toBe('platform_trust_invalid');
    expect(r.checks.find((c) => c.name === '平台证明链')?.detail).toContain('CRL');
  });

  it('fails closed when a cert-chain trust mode is configured but the root pin does not match', () => {
    const { proof, responseBody, expectedPcrs, chain } = makeAliyunSignedWithX509Chain('i-testabcdef-01');
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        ...aliyunTrust(expectedPcrs, { allowSyntheticQuoteReportCertForTest: false }),
        platformTrust: {
          mode: 'cert-chain',
          rootCertificatesPem: [chain.rootPem],
          intermediateCertificatesPem: [chain.intermediatePem],
          rootFingerprintsSha256: ['00'.repeat(32)],
        },
      },
    });

    expect(r.ok).toBe(false);
    expect(r.attestation.platformTrust?.status).toBe('platform_trust_invalid');
    expect(r.checks.find((c) => c.name === '平台证明链')?.ok).toBe(false);
  });

  it('auto-routes proof.profile to aliyun-vtpm while still requiring PCR allowlists', () => {
    const { proof, responseBody } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.ok).toBe(true);
    expect(r.checks.find((c) => c.name === 'PCR allowlist')?.ok).toBe(false);
  });

  it('fails closed when trust.profile and proof.profile disagree', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    proof.profile = 'nitro';
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'Evidence profile')?.ok).toBe(false);
  });

  it('rejects a PCR allowlist mismatch', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: {
        profile: 'aliyun-vtpm',
        expectedPcrs: { ...expectedPcrs, 'sha256:9': '00'.repeat(32) },
        requirePlatformTrust: false,
        allowSyntheticQuoteReportCertForTest: true,
      },
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'sha256:9 比对')?.ok).toBe(false);
  });

  it('rejects a challenge that was not rebuilt from the signed statement fields', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    (proof.evidence as any).challenge.qualifying_data_hex = '11'.repeat(32);

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'qualifying data')?.ok).toBe(false);
  });

  it('rejects a non-sha256 challenge algorithm', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    (proof.evidence as any).challenge.alg = 'sha1';

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'challenge alg')?.ok).toBe(false);
  });

  it('rejects payload_b64 tampering even if qualifying_data_hex is unchanged', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    (proof.evidence as any).challenge.payload_b64 = Buffer.from('{"profile":"aliyun-vtpm"}', 'utf8').toString('base64');

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'challenge payload')?.ok).toBe(false);
  });

  it('rejects a corrupted quote signature', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    const evidence = proof.evidence as any;
    const sig = Buffer.from(evidence.quote_report.signature_b64, 'base64');
    sig[sig.length - 1] ^= 0xff;
    evidence.quote_report.signature_b64 = sig.toString('base64');

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'quote 签名')?.ok).toBe(false);
  });

  it('rejects an evidence envelope with the wrong profile id', () => {
    const { proof, responseBody, expectedPcrs } = makeAliyunSigned();
    (proof.evidence as any).profile = 'nitro';

    const r = verifyTeeExchange({
      responseBody,
      proof,
      trust: aliyunTrust(expectedPcrs),
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'Evidence 格式')?.ok).toBe(false);
  });
});

describe('parseTeeProofEvent', () => {
  it('splits the trailing tee.proof event from the upstream bytes', () => {
    const upstream = 'event: message_start\ndata: {"a":1}\n\nevent: message_stop\ndata: {}\n\n';
    const { proof, pubB64 } = makeSigned();
    const stream = upstream + `event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`;
    const parsed = parseTeeProofEvent(stream);
    expect(parsed.body.toString('utf8')).toBe(upstream); // 逐字节还原上游原文
    expect(parsed.proof?.public_key).toBe(pubB64);
    expect(parsed.proof?.upstream_host).toBe(HOST);
  });

  it('splits proof from buffers without re-encoding the signed upstream bytes', () => {
    const upstream = Buffer.concat([
      Buffer.from('event: response.output_text.delta\r\ndata: {"delta":"', 'utf8'),
      Buffer.from([0xff, 0x00, 0xfe]),
      Buffer.from('"}\r\n\r\n', 'utf8'),
    ]);
    const { proof } = makeSigned({ responseBody: upstream });
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\r\ndata: ${JSON.stringify(proof)}\r\n\r\n`, 'utf8');
    const parsed = parseTeeProofEvent(Buffer.concat([upstream, suffix]));

    expect(parsed.body).toEqual(upstream);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('does not strip an invalid tee.proof-looking suffix', () => {
    const upstream = Buffer.from('event: response.output_text.delta\ndata: {"delta":"ok"}\n\n', 'utf8');
    const invalidSuffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: {not-json}\n\n`, 'utf8');
    const whole = Buffer.concat([upstream, invalidSuffix]);

    const parsed = parseTeeProofEvent(whole);

    expect(parsed.proof).toBeUndefined();
    expect(parsed.body).toEqual(whole);
  });

  it('does not accept a proof event with unsigned trailing bytes', () => {
    const upstream = Buffer.from('event: response.output_text.delta\ndata: {"delta":"ok"}\n\n', 'utf8');
    const { proof } = makeSigned();
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`, 'utf8');
    const trailing = Buffer.from('event: response.output_text.delta\ndata: {"delta":"unsigned"}\n\n', 'utf8');
    const whole = Buffer.concat([upstream, suffix, trailing]);

    const parsed = parseTeeProofEvent(whole);

    expect(parsed.proof).toBeUndefined();
    expect(parsed.body).toEqual(whole);
  });

  it('returns no proof when the stream was not attested', () => {
    const upstream = 'event: message_stop\ndata: {}\n\n';
    const parsed = parseTeeProofEvent(upstream);
    expect(parsed.proof).toBeUndefined();
    expect(parsed.body.toString('utf8')).toBe(upstream);
  });

  it('parses multipart captures with raw response bytes and tee proof', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json; charset=utf-8',
      proof,
      boundary: 'proof-observation-test',
    });

    const parsed = parseTeeProofMultipartResponse(multipart.body, multipart.contentType);

    expect(parsed?.body).toEqual(rawBody);
    expect(parsed?.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('parses multipart captures by boundary when response Content-Length is stale', () => {
    const originalBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\n', 'utf8');
    const mutatedBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"xok"}]}\n', 'utf8');
    const { proof } = makeSigned({ responseBody: originalBody });
    const multipart = formatMultipart({
      rawBody: mutatedBody,
      rawContentType: 'application/json; charset=utf-8',
      proof,
      boundary: 'proof-observation-stale-length',
      contentLengthOverride: originalBody.byteLength,
    });

    const parsed = parseTeeProofMultipartResponse(multipart.body, multipart.contentType);

    expect(mutatedBody.byteLength).toBe(originalBody.byteLength + 1);
    expect(parsed?.body).toEqual(mutatedBody);
    expect(parsed?.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('infers multipart boundary from the captured body when headers were not saved', () => {
    const rawBody = Buffer.from('event: response.completed\ndata: {"type":"response.completed"}\n\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'text/event-stream',
      proof,
      boundary: 'proof-observation-body-boundary',
    });

    const parsed = parseTeeProofCapture(multipart.body);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.public_key).toBe(proof.public_key);
  });

  it('strips full HTTP response headers before parsing a multipart capture', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json; charset=utf-8',
      proof,
      boundary: 'proof-observation-http-response',
    });
    const capture = Buffer.concat([
      Buffer.from([
        'HTTP/1.1 200 OK',
        `Content-Type: ${multipart.contentType}`,
        `Content-Length: ${multipart.body.byteLength}`,
        'Date: Tue, 14 Jul 2026 00:00:00 GMT',
        '',
        '',
      ].join('\r\n'), 'utf8'),
      multipart.body,
    ]);

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.bodyContentType).toBe('application/json; charset=utf-8');
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('skips command text before a full multipart capture', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json',
      proof,
      boundary: 'proof-observation-prefixed-boundary',
    });
    const capture = Buffer.concat([Buffer.from('curl -N https://api.example.com/v1/messages\n', 'utf8'), multipart.body]);

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('parses terminal-copied captures that start with raw response then proof part', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const capture = formatProofTailCapture({
      rawBody,
      proof,
      boundary: 'proof-observation-tail-boundary',
    });

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('ignores pasted leading blank lines in body+proof captures only when the signed hash proves it', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[{"type":"text","text":"ok"}]}', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const capture = Buffer.concat([
      Buffer.from('\n\n', 'utf8'),
      formatProofTailCapture({
        rawBody,
        proof,
        boundary: 'proof-observation-tail-leading-blanks',
      }),
    ]);

    const parsed = parseTeeProofCapture(capture);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.ignoredLeadingBlankBytes).toBe(2);
    expect(parsed.proof?.response_body_sha256).toBe(proof.response_body_sha256);
  });

  it('strips relay transport keepalive comments only when the signed response hash proves it', () => {
    const rawBody = Buffer.from('event: message_stop\ndata: {}\n\n', 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const keepalive = Buffer.from(WOKEY_SSE_TRANSPORT_KEEPALIVE_V1.repeat(2), 'utf8');
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`, 'utf8');

    const parsed = parseTeeProofCapture(Buffer.concat([keepalive, rawBody, suffix]));

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.ignoredTransportKeepaliveCount).toBe(2);
    expect(parsed.ignoredTransportKeepaliveBytes).toBe(keepalive.byteLength);
  });

  it('keeps an upstream leading comment when that exact body was signed', () => {
    const rawBody = Buffer.from(`${WOKEY_SSE_TRANSPORT_KEEPALIVE_V1}event: message_stop\ndata: {}\n\n`, 'utf8');
    const { proof } = makeSigned({ responseBody: rawBody });
    const suffix = Buffer.from(`event: ${TEE_PROOF_EVENT}\ndata: ${JSON.stringify(proof)}\n\n`, 'utf8');

    const parsed = parseTeeProofCapture(Buffer.concat([rawBody, suffix]));

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.ignoredTransportKeepaliveCount).toBeUndefined();
    expect(parsed.ignoredTransportKeepaliveBytes).toBeUndefined();
  });

  it('returns the raw multipart response body when the proof part says unavailable', () => {
    const rawBody = Buffer.from('{"id":"msg_1","content":[]}', 'utf8');
    const multipart = formatMultipart({
      rawBody,
      rawContentType: 'application/json',
      proof: { type: 'tee.proof_unavailable', code: 'proof_unavailable', message: 'no proof', attested: false },
      boundary: 'proof-observation-unavailable',
    });

    const parsed = parseTeeProofCapture(multipart.body);

    expect(parsed.body).toEqual(rawBody);
    expect(parsed.proof).toBeUndefined();
  });
});

function formatMultipart(params: {
  rawBody: Buffer;
  rawContentType: string;
  proof: TeeProofWire | { type: 'tee.proof_unavailable'; code: string; message: string; attested: false };
  boundary: string;
  contentLengthOverride?: number;
}) {
  const proofBody = Buffer.from(JSON.stringify(params.proof), 'utf8');
  const responseHead = Buffer.from([
    `--${params.boundary}`,
    `Content-Type: ${params.rawContentType}`,
    'Content-Disposition: inline; name="response"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${params.contentLengthOverride ?? params.rawBody.byteLength}`,
    '',
    '',
  ].join('\r\n'), 'utf8');
  const proofHead = Buffer.from([
    '',
    `--${params.boundary}`,
    'Content-Type: application/vnd.proof-observation.proof+json',
    'Content-Disposition: attachment; name="proof"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${proofBody.byteLength}`,
    '',
    '',
  ].join('\r\n'), 'utf8');
  const end = Buffer.from(`\r\n--${params.boundary}--\r\n`, 'utf8');
  return {
    body: Buffer.concat([responseHead, params.rawBody, proofHead, proofBody, end]),
    contentType: `multipart/mixed; boundary=${params.boundary}`,
  };
}

function formatProofTailCapture(params: {
  rawBody: Buffer;
  proof: TeeProofWire;
  boundary: string;
}) {
  const proofBody = Buffer.from(JSON.stringify(params.proof), 'utf8');
  const proofPart = Buffer.from([
    '',
    `--${params.boundary}`,
    'Content-Type: application/vnd.proof-observation.proof+json',
    'Content-Disposition: attachment; name="proof"',
    'Content-Transfer-Encoding: binary',
    `Content-Length: ${proofBody.byteLength}`,
    '',
    '',
  ].join('\n'), 'utf8');
  const end = Buffer.from(`\n--${params.boundary}--`, 'utf8');
  return Buffer.concat([params.rawBody, proofPart, proofBody, end]);
}

function makeAliyunSigned() {
  const { proof, requestBody, responseBody } = makeSigned();
  proof.profile = 'aliyun-vtpm';
  const { publicKey: akPublicKey, privateKey: akPrivateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pcrValues = {
    'sha256:8': '7b0dc879a95df8afea46aa7f1e681a5b36f80adf2a37aa34c8e4856a4e3ffb39',
    'sha256:9': 'b5753ad8242e1c3b8150caf7098f0aea082f64bcc49f04ae440bef5401e02575',
    'sha256:11': 'f9dadb71385c36fff43e70e4796073b76ec5cb85a44705ad368433c79c12f894',
  };
  const pcrDigest = sha256(Buffer.concat([
    Buffer.from(pcrValues['sha256:8'], 'hex'),
    Buffer.from(pcrValues['sha256:9'], 'hex'),
    Buffer.from(pcrValues['sha256:11'], 'hex'),
  ]));
  const challengePayload = buildAliyunVtpmChallengePayload(proof);
  const challengeHex = buildAliyunVtpmChallengeHex(proof);
  const quoteMsg = buildSyntheticTpmQuoteMessage(Buffer.from(challengeHex, 'hex'), pcrDigest);
  const quoteSig = buildSyntheticTpmRsassaSignature(edSign('sha256', quoteMsg, akPrivateKey));
  const pcrSelectionOut = buildSyntheticPcrSelection();
  const pcrValuesRaw = buildSyntheticTpmlDigest([
    Buffer.from(pcrValues['sha256:8'], 'hex'),
    Buffer.from(pcrValues['sha256:9'], 'hex'),
    Buffer.from(pcrValues['sha256:11'], 'hex'),
  ]);
  const evidence = {
    profile: 'aliyun-vtpm',
    version: 1,
    quote_report: {
      quoted_b64: quoteMsg.toString('base64'),
      signature_b64: quoteSig.toString('base64'),
      cert_b64: akPublicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
      pcr_info: {
        pcr_values_b64: pcrValuesRaw.toString('base64'),
        pcr_selection_out_b64: pcrSelectionOut.toString('base64'),
        pcr_update_counter: 0,
      },
    },
    challenge: {
      alg: 'sha256',
      payload_b64: Buffer.from(challengePayload, 'utf8').toString('base64'),
      qualifying_data_hex: challengeHex,
    },
    platform_attestation: {
      mode: 'missing',
      cert_chain_pem: [],
      verification_note: 'QuoteReport.Cert root/intermediate chain is not configured in experimental mode.',
    },
  };
  proof.evidence = evidence;
  proof.attestation = Buffer.from(JSON.stringify(evidence), 'utf8').toString('base64');
  return { proof, requestBody, responseBody, expectedPcrs: pcrValues, challengeHex };
}

function makeAliyunSignedWithX509Chain(cn: string) {
  const base = makeAliyunSigned();
  const chain = makeTestCertificateChain(cn);
  const evidence = base.proof.evidence as any;
  const quoteMsg = Buffer.from(evidence.quote_report.quoted_b64, 'base64');
  evidence.quote_report.signature_b64 = buildSyntheticTpmRsassaSignature(edSign('sha256', quoteMsg, chain.leafKeyPem)).toString('base64');
  evidence.quote_report.cert_b64 = new X509Certificate(chain.leafPem).raw.toString('base64');
  evidence.platform_attestation.mode = 'cert-chain';
  base.proof.attestation = Buffer.from(JSON.stringify(evidence), 'utf8').toString('base64');
  return { ...base, chain };
}

function makeTestCertificateChain(cn: string) {
  const dir = mkdtempSync(join(tmpdir(), 'aliyun-vtpm-cert-chain-'));
  const rootKey = join(dir, 'root.key');
  const rootPem = join(dir, 'root.pem');
  const intermediateKey = join(dir, 'intermediate.key');
  const intermediateCsr = join(dir, 'intermediate.csr');
  const intermediatePem = join(dir, 'intermediate.pem');
  const leafKey = join(dir, 'leaf.key');
  const leafCsr = join(dir, 'leaf.csr');
  const leafPem = join(dir, 'leaf.pem');
  const caExt = join(dir, 'ca.ext');
  const leafExt = join(dir, 'leaf.ext');

  writeFileSync(caExt, [
    '[v3_ca]',
    'basicConstraints=critical,CA:true',
    'keyUsage=critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier=hash',
    '',
  ].join('\n'));
  writeFileSync(leafExt, [
    '[v3_leaf]',
    'basicConstraints=critical,CA:false',
    'keyUsage=critical,digitalSignature',
    'subjectKeyIdentifier=hash',
    '',
  ].join('\n'));

  execFileSync('openssl', ['genrsa', '-out', rootKey, '2048'], { stdio: 'ignore' });
  execFileSync('openssl', [
    'req', '-x509', '-new', '-nodes', '-key', rootKey, '-sha384', '-days', '3650',
    '-subj', '/C=CN/O=Aliyun/OU=Aliyun TPM Root CA/CN=Aliyun TPM Root CA',
    '-out', rootPem,
    '-addext', 'basicConstraints=critical,CA:true',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
  ], { stdio: 'ignore' });
  execFileSync('openssl', ['genrsa', '-out', intermediateKey, '2048'], { stdio: 'ignore' });
  execFileSync('openssl', [
    'req', '-new', '-key', intermediateKey,
    '-subj', '/C=CN/O=Aliyun/OU=Aliyun TPM Endorsement Key Manufacture CA/CN=Aliyun TPM EKMF CA',
    '-out', intermediateCsr,
  ], { stdio: 'ignore' });
  execFileSync('openssl', [
    'x509', '-req', '-in', intermediateCsr, '-CA', rootPem, '-CAkey', rootKey, '-CAcreateserial',
    '-out', intermediatePem, '-days', '3650', '-sha384', '-extfile', caExt, '-extensions', 'v3_ca',
  ], { stdio: 'ignore' });
  execFileSync('openssl', ['genrsa', '-out', leafKey, '2048'], { stdio: 'ignore' });
  execFileSync('openssl', [
    'req', '-new', '-key', leafKey,
    '-subj', `/C=CN/O=Aliyun/OU=Aliyun TPM Signing EK/CN=${cn}`,
    '-out', leafCsr,
  ], { stdio: 'ignore' });
  execFileSync('openssl', [
    'x509', '-req', '-in', leafCsr, '-CA', intermediatePem, '-CAkey', intermediateKey, '-CAcreateserial',
    '-out', leafPem, '-days', '365', '-sha256', '-extfile', leafExt, '-extensions', 'v3_leaf',
  ], { stdio: 'ignore' });

  return {
    rootPem: readFileSync(rootPem, 'utf8'),
    intermediatePem: readFileSync(intermediatePem, 'utf8'),
    leafPem: readFileSync(leafPem, 'utf8'),
    leafKeyPem: readFileSync(leafKey, 'utf8'),
  };
}

function certFingerprint(pem: string) {
  return new X509Certificate(pem).fingerprint256.replace(/:/g, '').toLowerCase();
}

function aliyunTrust(expectedPcrs: Record<string, string>, overrides: Record<string, unknown> = {}) {
  return {
    profile: 'aliyun-vtpm',
    expectedPcrs,
    requirePlatformTrust: false,
    allowSyntheticQuoteReportCertForTest: true,
    ...overrides,
  };
}

function buildSyntheticTpmQuoteMessage(extraData: Buffer, pcrDigest: Buffer): Buffer {
  return Buffer.concat([
    u32(0xff544347), // TPM_GENERATED_VALUE
    u16(0x8018), // TPM_ST_ATTEST_QUOTE
    tpm2b(Buffer.alloc(0)), // qualifiedSigner
    tpm2b(extraData),
    Buffer.alloc(17), // TPMS_CLOCK_INFO
    Buffer.alloc(8), // firmwareVersion
    u32(1), // TPML_PCR_SELECTION count
    u16(0x000b), // TPM_ALG_SHA256
    Buffer.from([3, 0x00, 0x0b, 0x00]), // sizeofSelect=3, PCR 8/9/11
    tpm2b(pcrDigest),
  ]);
}

function buildSyntheticPcrSelection(): Buffer {
  return Buffer.concat([
    u32(1), // TPML_PCR_SELECTION count
    u16(0x000b), // TPM_ALG_SHA256
    Buffer.from([3, 0x00, 0x0b, 0x00]), // sizeofSelect=3, PCR 8/9/11
  ]);
}

function buildSyntheticTpmlDigest(digests: Buffer[]): Buffer {
  return Buffer.concat([
    u32(digests.length),
    ...digests.map(tpm2b),
  ]);
}

function buildSyntheticTpmRsassaSignature(signature: Buffer): Buffer {
  return Buffer.concat([
    u16(0x0014), // TPM_ALG_RSASSA
    u16(0x000b), // TPM_ALG_SHA256
    tpm2b(signature),
  ]);
}

function tpm2b(value: Buffer): Buffer {
  return Buffer.concat([u16(value.length), value]);
}

function u16(value: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(value);
  return b;
}

function u32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value);
  return b;
}
