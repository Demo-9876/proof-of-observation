import type { AttestationVerifier, TeeCheck, TeeProofWire, TeeVerifyResult } from './tee-verify-core.ts';
import { verifyTeeExchange } from './tee-verify-core.ts';
import type { EvidenceProfileVerifier, EvidenceTrust } from './evidence-profile.ts';
import { resolveLegacyNitroPcr0 } from './trust-config.ts';

export type TeePlatformId = 'aws' | 'aliyun' | 'huawei' | 'unknown';
export type DetectionSource =
  | 'tee_platform'
  | 'tee_profile'
  | 'profile'
  | 'evidence_shape'
  | 'measurement_type'
  | 'platform_default'
  | 'unsupported';

export interface UnifiedProofWire extends TeeProofWire {
  tee_platform?: string;
  tee_profile?: string;
  trust_anchor_id?: string;
  measurement_type?: string;
}

export interface PlatformDetection {
  platform: TeePlatformId;
  profile?: string;
  source: DetectionSource;
}

export interface UnifiedPlatformResult {
  ok: boolean;
  detected_tee_platform: TeePlatformId;
  detected_tee_profile?: string;
  detection_source: DetectionSource;
  attestation_verified: boolean;
  measurement_checked: boolean;
  public_key_bound: boolean;
  nonce_bound: boolean;
  revocation_checked: boolean;
  reported_measurement?: string | null;
  trusted_measurement?: string | null;
  measurement_matched: boolean;
  trust_anchor_id?: string | null;
  platform_verifier_version: string;
}

export interface UnifiedVerifyInput {
  proof: UnifiedProofWire;
  responseBody: Buffer;
  requestBody?: Buffer;
  expectedHost?: string;
  expectedNonceB64?: string;
  trustedMeasurement?: string;
  trust?: EvidenceTrust;
  defaultPlatform?: TeePlatformId;
  now?: number;
}

export interface UnifiedVerifierDeps {
  verifyAttestationDoc?: AttestationVerifier;
  evidenceVerifier?: EvidenceProfileVerifier;
  evidenceVerifiers?: Record<string, EvidenceProfileVerifier>;
}

export interface UnifiedVerifyResult {
  ok: boolean;
  mode: TeeVerifyResult['mode'];
  detection: PlatformDetection;
  platform: UnifiedPlatformResult;
  core: TeeVerifyResult;
  checks: TeeCheck[];
}

const PLATFORM_VERIFIER_VERSION = 'unified-verifier-router-v1';

export function detectProofPlatform(
  proof: Partial<UnifiedProofWire>,
  opts: { defaultPlatform?: TeePlatformId } = {},
): PlatformDetection {
  const byPlatform = platformIdFromString(proof.tee_platform);
  if (byPlatform !== 'unknown') return { platform: byPlatform, profile: canonicalProfileForPlatform(byPlatform), source: 'tee_platform' };

  const byTeeProfile = platformIdFromProfile(proof.tee_profile);
  if (byTeeProfile !== 'unknown') return { platform: byTeeProfile, profile: normaliseEvidenceProfile(proof.tee_profile), source: 'tee_profile' };

  const byLegacyProfile = platformIdFromProfile(proof.profile);
  if (byLegacyProfile !== 'unknown') return { platform: byLegacyProfile, profile: normaliseEvidenceProfile(proof.profile), source: 'profile' };

  const byEvidenceShape = platformIdFromEvidenceShape(proof);
  if (byEvidenceShape !== 'unknown') return { platform: byEvidenceShape, profile: canonicalProfileForPlatform(byEvidenceShape), source: 'evidence_shape' };

  const byMeasurementType = platformIdFromMeasurementType(proof.measurement_type);
  if (byMeasurementType !== 'unknown') return { platform: byMeasurementType, profile: canonicalProfileForPlatform(byMeasurementType), source: 'measurement_type' };

  if (opts.defaultPlatform && opts.defaultPlatform !== 'unknown') {
    return { platform: opts.defaultPlatform, profile: canonicalProfileForPlatform(opts.defaultPlatform), source: 'platform_default' };
  }
  return { platform: 'unknown', profile: proof.profile ?? proof.tee_profile, source: 'unsupported' };
}

export function verifyUnifiedExchange(
  input: UnifiedVerifyInput,
  deps: UnifiedVerifierDeps = {},
): UnifiedVerifyResult {
  const detection = detectProofPlatform(input.proof, { defaultPlatform: input.defaultPlatform });
  const conflict = declaredProfileConflict(input.proof, detection);
  const detectionCheck: TeeCheck = detection.platform === 'unknown'
    ? { name: 'TEE 平台识别', ok: false, detail: '无法识别 proof 所属 TEE 平台' }
    : conflict
      ? { name: 'TEE 平台识别', ok: false, detail: conflict }
    : { name: 'TEE 平台识别', ok: true, detail: `${detection.platform}/${detection.profile ?? '<none>'} via ${detection.source}` };

  const profile = detection.profile ?? profileForPlatform(detection.platform, input.proof);
  const proof: TeeProofWire = {
    ...input.proof,
    profile: input.proof.profile ?? profile,
  };
  const trust = buildTrust(input, detection.platform);
  const core = detection.platform === 'unknown' || !detectionCheck.ok
    ? failedUnknownPlatformResult(proof, input, detectionCheck)
    : verifyTeeExchange(
      {
        proof,
        responseBody: input.responseBody,
        requestBody: input.requestBody,
        expectedHost: input.expectedHost,
        expectedNonceB64: input.expectedNonceB64,
        expectedPcr0: trust.expectedPcr0,
        requireFieldClaims: true,
        trust,
        now: input.now,
      },
      deps,
    );
  const platform = summarisePlatform(
    core,
    detection,
    proof,
    trust,
    detection.platform === 'aws' ? input.trustedMeasurement : undefined,
    input.proof.trust_anchor_id,
  );
  const checks = [detectionCheck, ...core.checks];
  const ok = detectionCheck.ok && core.ok && platform.ok;
  return { ok, mode: core.mode, detection, platform, core, checks };
}

function buildTrust(input: UnifiedVerifyInput, platform: TeePlatformId): EvidenceTrust {
  const trust: EvidenceTrust = { ...(input.trust ?? {}) };
  if (!trust.profile) {
    const profile = canonicalProfileForPlatform(platform);
    if (profile) trust.profile = profile;
  }
  if (platform === 'aws' && !trust.expectedPcr0) {
    trust.expectedPcr0 = resolveLegacyNitroPcr0(trust) ?? input.trustedMeasurement;
  }
  return trust;
}

function failedUnknownPlatformResult(
  proof: TeeProofWire,
  input: UnifiedVerifyInput,
  detectionCheck: TeeCheck,
): TeeVerifyResult {
  return {
    ok: false,
    mode: input.requestBody !== undefined ? 'full' : 'response-only',
    checks: [detectionCheck],
    attestation: { profile: proof.profile },
    provenance: {
      upstreamHost: proof.upstream_host,
      upstreamPath: proof.upstream_path,
      httpMethod: proof.http_method,
      httpStatus: proof.http_status,
      respContentType: proof.resp_content_type,
    },
  };
}

function summarisePlatform(
  core: TeeVerifyResult,
  detection: PlatformDetection,
  proof: TeeProofWire,
  trust: EvidenceTrust,
  trustedMeasurement?: string,
  trustAnchorId?: string,
): UnifiedPlatformResult {
  const measurementChecks = core.checks.filter(isMeasurementCheck);
  const attestationChecks = core.checks.filter(isAttestationCheck);
  const attestationVerified = attestationChecks.length > 0 && attestationChecks.every((c) => c.ok);
  const measurementChecked = measurementChecks.length > 0;
  const measurementMatched = measurementChecks.length > 0 && measurementChecks.every((c) => c.ok);
  const publicKeyBound = findOk(core.checks, '公钥绑定') || (!!core.attestation.publicKey && core.attestation.publicKey === proof.public_key);
  const nonceBound = findOk(core.checks, 'nonce 绑定') || (!!core.attestation.nonce && core.attestation.nonce === proof.nonce);
  const platformTrust = core.attestation.platformTrust;
  const revocationChecked = Boolean(trust.platformTrust?.revocation?.checkedExternally);
  const reportedMeasurement = core.attestation.pcr0 ?? core.attestation.pcr8 ?? firstMeasurement(core.attestation.measurements) ?? null;
  const trusted = trustedMeasurement ?? trust.expectedPcr0 ?? trust.expectedPcr8 ?? firstMeasurement(trust.expectedPcrs) ?? null;
  const ok = attestationVerified && measurementMatched && publicKeyBound && nonceBound && (platformTrust ? platformTrust.ok : true);

  return {
    ok,
    detected_tee_platform: detection.platform,
    detected_tee_profile: detection.profile ?? core.attestation.profile,
    detection_source: detection.source,
    attestation_verified: attestationVerified,
    measurement_checked: measurementChecked,
    public_key_bound: publicKeyBound,
    nonce_bound: nonceBound,
    revocation_checked: revocationChecked,
    reported_measurement: reportedMeasurement,
    trusted_measurement: trusted,
    measurement_matched: measurementMatched,
    trust_anchor_id: trustAnchorId ?? platformTrust?.issuer ?? null,
    platform_verifier_version: PLATFORM_VERIFIER_VERSION,
  };
}

function isAttestationCheck(check: TeeCheck): boolean {
  if (isMeasurementCheck(check)) return false;
  return [
    '远程证明',
    '证书有效期',
    'Evidence 格式',
    'challenge alg',
    'challenge payload',
    'qualifying data',
    'QuoteReport 字段',
    'quote 结构',
    'quote 签名',
    'quote challenge',
    'PCRInfo',
    'PCR selection',
    'PCR digest',
    '平台证明链',
    'QingTian evidence 格式',
    'QingTian COSE alg',
    'QingTian COSE 签名',
    'QingTian digest',
    'QingTian timestamp',
    'QingTian 证书链',
  ].includes(check.name);
}

function isMeasurementCheck(check: TeeCheck): boolean {
  return /^(PCR\d+ 比对|sha(256|384):\d+ 比对)$/i.test(check.name);
}

function findOk(checks: TeeCheck[], name: string): boolean {
  return checks.some((c) => c.name === name && c.ok);
}

function firstMeasurement(measurements: Record<string, string> | undefined): string | null {
  if (!measurements) return null;
  const first = Object.values(measurements)[0];
  return first ?? null;
}

function profileForPlatform(platform: TeePlatformId, proof: Partial<UnifiedProofWire>): string | undefined {
  const explicit = normaliseEvidenceProfile(proof.tee_profile) ?? normaliseEvidenceProfile(proof.profile);
  if (explicit) return explicit;
  return canonicalProfileForPlatform(platform);
}

function canonicalProfileForPlatform(platform: TeePlatformId): string | undefined {
  if (platform === 'aws') return 'nitro';
  if (platform === 'aliyun') return 'aliyun-vtpm';
  if (platform === 'huawei') return 'qingtian';
  return undefined;
}

function declaredProfileConflict(proof: Partial<UnifiedProofWire>, detection: PlatformDetection): string | undefined {
  if (detection.platform === 'unknown') return undefined;
  const expected = detection.profile ?? canonicalProfileForPlatform(detection.platform);
  if (!expected) return undefined;
  const declared = [
    ['tee_profile', normaliseEvidenceProfile(proof.tee_profile)],
    ['profile', normaliseEvidenceProfile(proof.profile)],
  ] as const;
  for (const [field, value] of declared) {
    if (value && value !== expected) {
      return `${field}=${value} 与 ${detection.source} 识别的平台 ${detection.platform}/${expected} 冲突`;
    }
  }
  return undefined;
}

function normaliseEvidenceProfile(value: unknown): string | undefined {
  const s = typeof value === 'string' ? value.toLowerCase() : '';
  if (s === 'nitro' || s === 'aws-nitro' || s === 'aws_nitro') return 'nitro';
  if (s === 'aliyun-vtpm' || s === 'aliyun_vtpm' || s === 'aliyun-enclave') return 'aliyun-vtpm';
  if (s === 'qingtian' || s === 'huawei-qingtian' || s === 'huawei_qingtian') return 'qingtian';
  return undefined;
}

function platformIdFromString(value: unknown): TeePlatformId {
  const s = typeof value === 'string' ? value.toLowerCase() : '';
  if (['aws', 'nitro', 'aws-nitro', 'aws_nitro'].includes(s)) return 'aws';
  if (['aliyun', 'alibaba', 'aliyun-enclave', 'aliyun-vtpm', 'aliyun_vtpm'].includes(s)) return 'aliyun';
  if (['huawei', 'qingtian', 'huawei-qingtian', 'huawei_qingtian'].includes(s)) return 'huawei';
  return 'unknown';
}

function platformIdFromProfile(value: unknown): TeePlatformId {
  const s = typeof value === 'string' ? value.toLowerCase() : '';
  if (s === 'nitro' || s.includes('aws-nitro')) return 'aws';
  if (s.includes('aliyun') || s.includes('vtpm')) return 'aliyun';
  if (s.includes('qingtian') || s.includes('huawei')) return 'huawei';
  return 'unknown';
}

function platformIdFromMeasurementType(value: unknown): TeePlatformId {
  const s = typeof value === 'string' ? value.toLowerCase() : '';
  if (s === 'pcr0' || s.includes('nitro')) return 'aws';
  if (s.includes('vtpm') || s.includes('aliyun')) return 'aliyun';
  if (s.includes('qingtian') || s.includes('huawei')) return 'huawei';
  return 'unknown';
}

function platformIdFromEvidenceShape(proof: Partial<UnifiedProofWire>): TeePlatformId {
  const evidence = isRecord(proof.evidence) ? proof.evidence : undefined;
  const explicit = platformIdFromString(evidence?.tee_platform ?? evidence?.platform);
  if (explicit !== 'unknown') return explicit;
  const profile = platformIdFromProfile(evidence?.tee_profile ?? evidence?.profile);
  if (profile !== 'unknown') return profile;
  if (typeof proof.attestation === 'string' && proof.public_key && proof.signature && (proof.pcr0 || !proof.profile)) return 'aws';
  return 'unknown';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
