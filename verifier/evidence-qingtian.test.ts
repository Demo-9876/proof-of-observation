import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { qingtianEvidenceVerifier } from './evidence-qingtian.ts';
import type { EvidenceTrust } from './evidence-profile.ts';
import type { TeeProofWire } from './tee-verify-core.ts';

type QingTianFixture = {
  profile: 'qingtian';
  launchMode: 'normal';
  digest: 'SHA384';
  pcr0: string;
  pcr8: string;
  nonceB64: string;
  publicKeySpkiB64: string;
  attestationB64: string;
  attestationSha256: string;
  certificateFingerprintsSha256: {
    root: string;
    region: string;
    grid: string;
    instance: string;
    leaf: string;
  };
};

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/qingtian/official-signed.fixture.json', import.meta.url), 'utf8'),
) as QingTianFixture;

const evidenceTime = Date.parse('2026-07-20T11:23:26.196Z');

function coseSign1TaggedAttestationB64(): string {
  return Buffer.concat([
    Buffer.from([0xd2]), // CBOR tag(18), COSE_Sign1
    Buffer.from(fixture.attestationB64, 'base64'),
  ]).toString('base64');
}

function proof(overrides: Partial<TeeProofWire> = {}): TeeProofWire {
  return {
    v: 2,
    profile: 'qingtian',
    alg: 'ed25519',
    public_key: fixture.publicKeySpkiB64,
    nonce: fixture.nonceB64,
    upstream_host: 'api.example.com',
    upstream_path: '/v1/messages',
    http_method: 'POST',
    http_status: 200,
    resp_content_type: 'application/json',
    request_body_sha256: '00'.repeat(32),
    response_body_sha256: '11'.repeat(32),
    signature: 'AA==',
    attestation: fixture.attestationB64,
    ...overrides,
  };
}

function trust(overrides: Partial<EvidenceTrust> = {}): EvidenceTrust {
  return {
    profile: 'qingtian',
    expectedPcr0: fixture.pcr0,
    expectedPcr8: fixture.pcr8,
    requirePlatformTrust: true,
    platformTrust: {
      mode: 'cert-chain',
      rootFingerprintsSha256: [fixture.certificateFingerprintsSha256.root],
      intermediateFingerprintsSha256: [
        fixture.certificateFingerprintsSha256.region,
        fixture.certificateFingerprintsSha256.grid,
        fixture.certificateFingerprintsSha256.instance,
      ],
      revocation: { required: false, method: 'crl' },
    },
    ...overrides,
  };
}

describe('qingtianEvidenceVerifier', () => {
  it('verifies a production QingTian QTSM attestation fixture', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust(),
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.profile).toBe('qingtian');
    expect(r.moduleId).toBe('4662b7a3-7898-46c9-a6c5-20e9025e50bc.enc-37d1e07b3da3c427');
    expect(r.pcr0).toBe(fixture.pcr0);
    expect(r.pcr8).toBe(fixture.pcr8);
    expect(r.publicKey).toBe(fixture.publicKeySpkiB64);
    expect(r.nonce).toBe(fixture.nonceB64);
    expect(r.measurements?.['sha384:0']).toBe(fixture.pcr0);
    expect(r.measurements?.['sha384:8']).toBe(fixture.pcr8);
    expect(r.platformTrust?.ok).toBe(true);
  });

  it('uses the signed QTSM timestamp for certificate validity when verifying archived evidence', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust(),
      now: Date.parse('2036-01-01T00:00:00.000Z'),
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
    expect(r.checks.find((c) => c.name === 'QingTian timestamp')?.detail).toContain('2026-07-20T11:23:26.196Z');
  });

  it('accepts a COSE_Sign1 tagged QingTian attestation', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof({ attestation: coseSign1TaggedAttestationB64() }),
      trust: trust(),
      now: evidenceTime,
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('normalizes common PCR allowlist formatting', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust({
        expectedPcr0: fixture.pcr0.toUpperCase(),
        expectedPcr8: fixture.pcr8.match(/.{1,2}/g)?.join(':').toUpperCase(),
      }),
      now: evidenceTime,
    });

    expect(r.ok, JSON.stringify(r.checks)).toBe(true);
  });

  it('fails closed on PCR8 mismatch', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust({ expectedPcr8: '00'.repeat(48) }),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'PCR8 比对')?.ok).toBe(false);
  });

  it('fails closed on public key mismatch', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof({ public_key: Buffer.from('other-key').toString('base64') }),
      trust: trust(),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === '公钥绑定')?.ok).toBe(false);
  });

  it('fails closed on nonce mismatch', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof({ nonce: Buffer.from('fresh-but-wrong').toString('base64') }),
      trust: trust(),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'nonce 绑定')?.ok).toBe(false);
  });

  it('fails closed when the pinned root fingerprint is missing', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust({ platformTrust: { mode: 'cert-chain', rootFingerprintsSha256: ['AA'.repeat(32)] } }),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'QingTian 证书链')?.ok).toBe(false);
  });

  it('fails closed when revocation checking is required but not externally checked', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof(),
      trust: trust({
        platformTrust: {
          mode: 'cert-chain',
          rootFingerprintsSha256: [fixture.certificateFingerprintsSha256.root],
          revocation: { required: true, method: 'crl' },
        },
      }),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'QingTian 证书链')?.detail).toContain('revocation checking is required');
  });

  it('fails closed on malformed attestation bytes', () => {
    const r = qingtianEvidenceVerifier.verifyEvidence({
      proof: proof({ attestation: 'AA==' }),
      trust: trust(),
      now: evidenceTime,
    });

    expect(r.ok).toBe(false);
    expect(r.checks.find((c) => c.name === 'QingTian evidence 格式')?.ok).toBe(false);
  });
});
