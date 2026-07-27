import { constants, createHash, createPublicKey, verify as nodeVerify, X509Certificate } from 'node:crypto';
import type { TeeProofWire } from './tee-verify-core.ts';
import type { EvidenceProfileVerifier, EvidenceTrust } from './evidence-profile.ts';
import { fieldClaimsSha256Hex } from './field-proof.ts';

const MAX_FIELD_BYTES = 256 * 1024;
const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_QUOTE = 0x8018;
const TPM_ALG_SHA256 = 0x000b;
const TPM_ALG_RSASSA = 0x0014;
const TPM_ALG_RSAPSS = 0x0016;
const REQUIRED_ALIYUN_PCRS = ['sha256:8', 'sha256:9', 'sha256:11'];

type PcrSelection = {
  hashAlg: number;
  pcrs: number[];
};

type ParsedQuote = {
  extraData: Buffer;
  selections: PcrSelection[];
  pcrDigest: Buffer;
};

type AliyunVtpmEvidence = {
  profile?: string;
  version?: number;
  quote_report?: {
    quoted_b64?: string;
    signature_b64?: string;
    cert_b64?: string;
    pcr_info?: {
      pcr_values_b64?: string;
      pcr_selection_out_b64?: string;
      pcr_update_counter?: number;
    };
  };
  challenge?: {
    alg?: string;
    payload_b64?: string;
    qualifying_data_hex?: string;
  };
  platform_attestation?: {
    mode?: 'missing' | 'cert-chain';
    cert_chain_pem?: string[];
    verification_note?: string;
  } | null;
  attester?: {
    sdk?: string;
    sdk_commit?: string;
    quote_handle?: string;
  };
};

type CertInfo = {
  publicKey: ReturnType<typeof createPublicKey>;
  isX509: boolean;
  cert?: X509Certificate;
  fingerprintSha256?: string;
};

export function buildAliyunVtpmChallengePayload(proof: TeeProofWire): string {
  const publicKeySha256 = createHash('sha256').update(decodeBase64(proof.public_key, 'public_key')).digest('hex');
  return jcsCanonicalize({
    http_method: proof.http_method,
    http_status: proof.http_status,
    nonce: proof.nonce,
    profile: 'aliyun-vtpm',
    request_body_sha256: proof.request_body_sha256,
    resp_content_type: proof.resp_content_type,
    response_body_sha256: proof.response_body_sha256,
    statement_public_key_sha256: publicKeySha256,
    upstream_host: proof.upstream_host,
    upstream_path: proof.upstream_path,
    ...(proof.field_claims ? { field_claims_sha256: fieldClaimsSha256Hex(proof.field_claims) } : {}),
  });
}

export function buildAliyunVtpmChallengeHex(proof: TeeProofWire): string {
  return createHash('sha256').update(buildAliyunVtpmChallengePayload(proof), 'utf8').digest('hex');
}

export const aliyunVtpmEvidenceVerifier: EvidenceProfileVerifier = {
  profile: 'aliyun-vtpm',
  verifyEvidence({ proof, trust, now }) {
    const checks = [];
    let evidence: AliyunVtpmEvidence;
    try {
      evidence = parseEvidence(proof);
      checks.push({ name: 'Evidence 格式', ok: true, detail: 'aliyun-vtpm QuoteReport evidence envelope 可解析' });
    } catch (err) {
      checks.push({ name: 'Evidence 格式', ok: false, detail: (err as Error).message });
      return { ok: false, profile: 'aliyun-vtpm', checks };
    }

    const rebuiltPayload = Buffer.from(buildAliyunVtpmChallengePayload(proof), 'utf8');
    const qualifyingData = createHash('sha256').update(rebuiltPayload).digest();

    try {
      const algOk = evidence.challenge?.alg === 'sha256';
      checks.push({
        name: 'challenge alg',
        ok: algOk,
        detail: algOk ? 'challenge.alg == sha256' : `unsupported challenge.alg: ${String(evidence.challenge?.alg)}`,
      });

      const payload = decodeBase64(required(evidence.challenge?.payload_b64, 'challenge.payload_b64'), 'challenge.payload_b64');
      const payloadOk = payload.equals(rebuiltPayload);
      checks.push({
        name: 'challenge payload',
        ok: payloadOk,
        detail: payloadOk ? 'payload_b64 == verifier 重建的 RFC8785/JCS canonical payload' : 'payload_b64 与 verifier 重建 payload 不一致',
      });

      const claimedQualifyingData = normaliseHex(required(evidence.challenge?.qualifying_data_hex, 'challenge.qualifying_data_hex'));
      const expectedQualifyingData = qualifyingData.toString('hex');
      const qualifyingOk = claimedQualifyingData === expectedQualifyingData;
      checks.push({
        name: 'qualifying data',
        ok: qualifyingOk,
        detail: qualifyingOk ? 'qualifying_data_hex == sha256(challenge_payload)' : 'qualifying_data_hex 与 sha256(challenge_payload) 不一致',
      });
    } catch (err) {
      checks.push({ name: 'challenge payload', ok: false, detail: (err as Error).message });
    }

    let quote: Buffer | undefined;
    let signature: Buffer | undefined;
    let certInfo: CertInfo | undefined;
    try {
      const quoteRaw = decodeBase64(required(evidence.quote_report?.quoted_b64, 'quote_report.quoted_b64'), 'quote_report.quoted_b64');
      quote = normalizeQuotedAttest(quoteRaw);
      signature = decodeBase64(required(evidence.quote_report?.signature_b64, 'quote_report.signature_b64'), 'quote_report.signature_b64');
      const certDer = decodeBase64(required(evidence.quote_report?.cert_b64, 'quote_report.cert_b64'), 'quote_report.cert_b64');
      certInfo = parseQuoteReportCert(certDer, !!trust.allowSyntheticQuoteReportCertForTest);
      checks.push({
        name: 'QuoteReport 字段',
        ok: true,
        detail: certInfo.isX509
          ? `quoted/signature/Cert DER 已解码，Cert 可解析为 X.509${quoteRaw.length === quote.length ? '' : '；quoted 为 TPM2B_ATTEST，已剥离 size 前缀'}`
          : `quoted/signature 已解码；测试 fixture 使用 SPKI public key 代替 X.509 Cert${quoteRaw.length === quote.length ? '' : '；quoted 为 TPM2B_ATTEST，已剥离 size 前缀'}`,
      });
    } catch (err) {
      checks.push({ name: 'QuoteReport 字段', ok: false, detail: (err as Error).message });
    }

    let parsedQuote: ParsedQuote | undefined;
    if (quote) {
      try {
        parsedQuote = parseTpmsAttestQuote(quote);
        checks.push({ name: 'quote 结构', ok: true, detail: 'TPMS_ATTEST quote 结构可解析' });
      } catch (err) {
        checks.push({ name: 'quote 结构', ok: false, detail: (err as Error).message });
      }
    }

    if (quote && signature && certInfo) {
      try {
        const signatureOk = verifyTpmRsaSignature(certInfo.publicKey, quote, signature);
        checks.push({
          name: 'quote 签名',
          ok: signatureOk,
          detail: signatureOk ? 'QuoteReport.Cert public key 验证 quote signature 通过' : 'QuoteReport.Cert public key 验证 quote signature 失败',
        });
      } catch (err) {
        checks.push({ name: 'quote 签名', ok: false, detail: (err as Error).message });
      }
    }

    if (parsedQuote) {
      const quoteChallengeOk = parsedQuote.extraData.equals(qualifyingData);
      checks.push({
        name: 'quote challenge',
        ok: quoteChallengeOk,
        detail: quoteChallengeOk ? 'quote extraData == sha256(challenge_payload)' : 'quote extraData 与 sha256(challenge_payload) 不一致',
      });
    }

    const pcrParse = parsePcrInfo(evidence);
    checks.push({ name: 'PCRInfo', ok: pcrParse.ok, detail: pcrParse.detail });

    if (parsedQuote && pcrParse.ok) {
      const selectionOk = sameSelections(parsedQuote.selections, pcrParse.selections);
      checks.push({
        name: 'PCR selection',
        ok: selectionOk,
        detail: selectionOk ? 'Quote PCR selection == PCRInfo.PCRSelectionOut' : 'Quote PCR selection 与 PCRInfo.PCRSelectionOut 不一致',
      });
    }

    const pcrValues = pcrParse.values;
    const digestResult = parsedQuote ? verifyQuotedPcrDigest(parsedQuote, pcrValues) : { ok: false, detail: 'quote 未解析，无法核对 PCR digest' };
    checks.push({
      name: 'PCR digest',
      ok: digestResult.ok,
      detail: digestResult.detail,
    });

    const expectedPcrs = normaliseExpectedPcrs(trust.expectedPcrs ?? {});
    const missingExpectedPcrs = REQUIRED_ALIYUN_PCRS.filter((key) => !expectedPcrs[key]);
    checks.push({
      name: 'PCR allowlist',
      ok: missingExpectedPcrs.length === 0,
      detail: missingExpectedPcrs.length === 0
        ? 'required PCR allowlist contains sha256:8, sha256:9, sha256:11'
        : `missing required PCR allowlist entries: ${missingExpectedPcrs.join(', ')}`,
    });

    for (const [normalisedKey, expected] of Object.entries(expectedPcrs)) {
      const actual = pcrValues[normalisedKey];
      const ok = !!actual && actual === expected;
      checks.push({
        name: `${normalisedKey} 比对`,
        ok,
        detail: ok ? `${normalisedKey} == allowlist` : `${normalisedKey} 不符: ${String(actual).slice(0, 12)}… ≠ ${expected.slice(0, 12)}…`,
      });
    }

    const platform = evaluatePlatformTrust(evidence, trust, certInfo, now);
    checks.push(platform.check);

    return {
      ok: checks.every((c) => c.ok),
      profile: 'aliyun-vtpm',
      checks,
      measurements: pcrValues,
      publicKey: proof.public_key,
      nonce: proof.nonce,
      platformTrust: platform.platformTrust,
    };
  },
};

function evaluatePlatformTrust(evidence: AliyunVtpmEvidence, trust: EvidenceTrust, certInfo: CertInfo | undefined, now?: number) {
  const mode = trust.platformTrust?.mode ?? evidence.platform_attestation?.mode ?? 'missing';
  if (mode === 'cert-chain') {
    return evaluateCertChainTrust(trust, certInfo, now);
  }

  const ok = !trust.requirePlatformTrust;
  const detail = ok
    ? 'QuoteReport.Cert root/intermediate chain 未配置；实验模式仅验证 quote/challenge/PCR'
    : 'QuoteReport.Cert root/intermediate chain 未配置；生产模式失败';
  return {
    check: { name: '平台证明链', ok, detail },
    platformTrust: {
      ok: false,
      mode: 'missing' as const,
      status: 'platform_trust_missing' as const,
      detail,
    },
  };
}

function evaluateCertChainTrust(trust: EvidenceTrust, certInfo: CertInfo | undefined, now?: number) {
  const invalid = (detail: string) => ({
    check: { name: '平台证明链', ok: false, detail },
    platformTrust: {
      ok: false,
      mode: 'cert-chain' as const,
      status: 'platform_trust_invalid' as const,
      detail,
    },
  });

  if (!certInfo?.cert) return invalid('QuoteReport.Cert is not a parseable X.509 certificate; fail closed');

  const platformTrust = trust.platformTrust ?? {};
  if (platformTrust.revocation?.required && !platformTrust.revocation.checkedExternally) {
    return invalid('CRL revocation checking is required but not implemented by this TypeScript verifier; provide checkedExternally=true only after an external CRL check');
  }

  let roots: X509Certificate[];
  let intermediates: X509Certificate[];
  try {
    roots = parseCertificates(platformTrust.rootCertificatesPem ?? []);
    intermediates = parseCertificates(platformTrust.intermediateCertificatesPem ?? []);
  } catch (err) {
    return invalid(`trust certificate parse failed: ${(err as Error).message}`);
  }
  if (roots.length === 0) return invalid('platformTrust.rootCertificatesPem is required for cert-chain mode');
  if (intermediates.length === 0) return invalid('platformTrust.intermediateCertificatesPem is required for cert-chain mode');

  const at = now ? new Date(now) : new Date();
  const leaf = certInfo.cert;
  if (!certValidAt(leaf, at)) return invalid(`QuoteReport.Cert is not valid at ${at.toISOString()}`);

  const rootPins = (platformTrust.rootFingerprintsSha256 ?? []).map(normaliseHex);
  const intermediatePins = (platformTrust.intermediateFingerprintsSha256 ?? []).map(normaliseHex);

  for (const root of roots) {
    if (!certValidAt(root, at)) continue;
    if (!root.verify(root.publicKey)) continue;
    const rootFp = fingerprint(root);
    if (rootPins.length > 0 && !rootPins.includes(rootFp)) continue;
    for (const intermediate of intermediates) {
      if (!certValidAt(intermediate, at)) continue;
      if (!issuedAndVerified(intermediate, root)) continue;
      const intermediateFp = fingerprint(intermediate);
      if (intermediatePins.length > 0 && !intermediatePins.includes(intermediateFp)) continue;
      if (!issuedAndVerified(leaf, intermediate)) continue;

      const cn = subjectComponent(leaf.subject, 'CN');
      const cnPattern = platformTrust.enclaveSubjectCnPattern ?? '^i-[A-Za-z0-9][A-Za-z0-9-]*-enclave-[0-9]+$';
      if (!cn || !new RegExp(cnPattern).test(cn)) {
        return invalid(`QuoteReport.Cert subject CN does not match Alibaba Enclave EK pattern: ${cn ?? '<missing>'}`);
      }

      const detail = `QuoteReport.Cert chains to Aliyun TPM root; EK CN=${cn}; root=${rootFp.slice(0, 12)}... intermediate=${intermediateFp.slice(0, 12)}...`;
      return {
        check: { name: '平台证明链', ok: true, detail },
        platformTrust: {
          ok: true,
          mode: 'cert-chain' as const,
          status: 'ok' as const,
          issuer: leaf.issuer,
          detail,
        },
      };
    }
  }

  return invalid('QuoteReport.Cert does not chain to configured Alibaba Cloud TPM root/intermediate certificates');
}

function parseEvidence(proof: TeeProofWire): AliyunVtpmEvidence {
  if (proof.evidence && typeof proof.evidence === 'object') {
    const evidence = proof.evidence as AliyunVtpmEvidence;
    validateEvidenceProfile(evidence);
    return evidence;
  }
  const raw = decodeBase64(proof.attestation, 'attestation').toString('utf8');
  const parsed = JSON.parse(raw) as AliyunVtpmEvidence;
  if (!parsed || typeof parsed !== 'object') throw new Error('aliyun-vtpm evidence must be an object');
  validateEvidenceProfile(parsed);
  return parsed;
}

function validateEvidenceProfile(evidence: AliyunVtpmEvidence): void {
  if (evidence.profile && evidence.profile !== 'aliyun-vtpm') throw new Error(`unexpected evidence profile: ${evidence.profile}`);
  if (evidence.version !== undefined && evidence.version !== 1) throw new Error(`unsupported aliyun-vtpm evidence version: ${evidence.version}`);
}

function parseQuoteReportCert(certDer: Buffer, allowSyntheticQuoteReportCertForTest: boolean): CertInfo {
  try {
    const cert = new X509Certificate(certDer);
    return {
      publicKey: cert.publicKey,
      isX509: true,
      cert,
      fingerprintSha256: cert.fingerprint256.replace(/:/g, '').toLowerCase(),
    };
  } catch {
    if (!allowSyntheticQuoteReportCertForTest) {
      throw new Error('quote_report.cert_b64 must be a DER X.509 certificate');
    }
    return {
      publicKey: createPublicKey({ key: certDer, format: 'der', type: 'spki' }),
      isX509: false,
    };
  }
}

function parseCertificates(pems: string[]): X509Certificate[] {
  return pems.map((pem, i) => {
    try {
      return new X509Certificate(extractCertificatePem(pem));
    } catch (err) {
      throw new Error(`certificate[${i}]: ${(err as Error).message}`);
    }
  });
}

function extractCertificatePem(input: string): string {
  const match = input.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  return match ? match[0] : input;
}

function fingerprint(cert: X509Certificate): string {
  return cert.fingerprint256.replace(/:/g, '').toLowerCase();
}

function certValidAt(cert: X509Certificate, at: Date): boolean {
  const validFrom = x509Date(cert, 'validFromDate', cert.validFrom);
  const validTo = x509Date(cert, 'validToDate', cert.validTo);
  if (!validFrom || !validTo) return false;
  return validFrom.getTime() <= at.getTime() && at.getTime() <= validTo.getTime();
}

function x509Date(cert: X509Certificate, dateProperty: 'validFromDate' | 'validToDate', fallback: string): Date | undefined {
  const value = (cert as X509Certificate & Partial<Record<typeof dateProperty, Date>>)[dateProperty];
  const parsed = value instanceof Date ? value : new Date(fallback);
  return Number.isFinite(parsed.getTime()) ? parsed : undefined;
}

function issuedAndVerified(child: X509Certificate, issuer: X509Certificate): boolean {
  return child.checkIssued(issuer) && child.verify(issuer.publicKey);
}

function subjectComponent(subject: string, key: string): string | undefined {
  const lines = subject.split(/\n+/);
  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    if (line.slice(0, idx).trim() === key) return line.slice(idx + 1).trim();
  }
  return undefined;
}

function parsePcrInfo(evidence: AliyunVtpmEvidence): {
  ok: boolean;
  detail: string;
  values: Record<string, string>;
  selections: PcrSelection[];
} {
  try {
    const pcrValuesRaw = decodeBase64(required(evidence.quote_report?.pcr_info?.pcr_values_b64, 'quote_report.pcr_info.pcr_values_b64'), 'quote_report.pcr_info.pcr_values_b64');
    const pcrSelectionRaw = decodeBase64(required(evidence.quote_report?.pcr_info?.pcr_selection_out_b64, 'quote_report.pcr_info.pcr_selection_out_b64'), 'quote_report.pcr_info.pcr_selection_out_b64');
    const selections = parseTpmlPcrSelection(pcrSelectionRaw);
    const digests = parseTpmlDigest(pcrValuesRaw);
    const pcrs = selections.flatMap((s) => s.hashAlg === TPM_ALG_SHA256 ? s.pcrs.map((pcr) => ({ pcr, hashAlg: s.hashAlg })) : []);
    if (digests.length !== pcrs.length) throw new Error(`PCRValues digest count ${digests.length} does not match PCRSelectionOut count ${pcrs.length}`);
    const values: Record<string, string> = {};
    for (let i = 0; i < pcrs.length; i++) values[`sha256:${pcrs[i].pcr}`] = digests[i].toString('hex');
    return {
      ok: true,
      detail: `PCRInfo parsed (${Object.keys(values).join(', ')})`,
      values,
      selections,
    };
  } catch (err) {
    return {
      ok: false,
      detail: (err as Error).message,
      values: {},
      selections: [],
    };
  }
}

function normalizeQuotedAttest(buf: Buffer): Buffer {
  if (buf.length >= 4 && buf.readUInt32BE(0) === TPM_GENERATED_VALUE) return buf;
  if (buf.length >= 6) {
    const size = buf.readUInt16BE(0);
    if (size === buf.length - 2 && buf.readUInt32BE(2) === TPM_GENERATED_VALUE) return buf.subarray(2);
  }
  return buf;
}

function parseTpmsAttestQuote(buf: Buffer): ParsedQuote {
  const r = new Reader(buf);
  const magic = r.u32();
  if (magic !== TPM_GENERATED_VALUE) throw new Error(`unexpected TPM magic: 0x${magic.toString(16)}`);
  const type = r.u16();
  if (type !== TPM_ST_ATTEST_QUOTE) throw new Error(`unexpected attestation type: 0x${type.toString(16)}`);
  r.tpm2b(); // qualifiedSigner
  const extraData = r.tpm2b();
  r.bytes(17); // TPMS_CLOCK_INFO
  r.bytes(8); // firmwareVersion
  const selections = readPcrSelections(r);
  const pcrDigest = r.tpm2b();
  r.done();
  return { extraData, selections, pcrDigest };
}

function parseTpmlPcrSelection(buf: Buffer): PcrSelection[] {
  const r = new Reader(buf);
  const selections = readPcrSelections(r);
  r.done();
  return selections;
}

function parseTpmlDigest(buf: Buffer): Buffer[] {
  const r = new Reader(buf);
  const count = r.u32();
  if (count < 1 || count > 32) throw new Error('invalid PCRValues digest count');
  const digests = [];
  for (let i = 0; i < count; i++) digests.push(r.tpm2b());
  r.done();
  return digests;
}

function readPcrSelections(r: Reader): PcrSelection[] {
  const selectionCount = r.u32();
  if (selectionCount < 1 || selectionCount > 8) throw new Error('invalid PCR selection count');
  const selections = [];
  for (let i = 0; i < selectionCount; i++) {
    const hashAlg = r.u16();
    const sizeOfSelect = r.u8();
    if (sizeOfSelect < 1 || sizeOfSelect > 8) throw new Error('invalid PCR select size');
    const select = r.bytes(sizeOfSelect);
    selections.push({ hashAlg, pcrs: pcrsFromSelect(select) });
  }
  return selections;
}

function verifyTpmRsaSignature(publicKey: ReturnType<typeof createPublicKey>, quoteMsg: Buffer, signatureBlob: Buffer): boolean {
  const r = new Reader(signatureBlob);
  const sigAlg = r.u16();
  const hashAlg = r.u16();
  if (hashAlg !== TPM_ALG_SHA256) throw new Error(`unsupported TPM signature hash algorithm: 0x${hashAlg.toString(16)}`);
  const sig = r.tpm2b();
  r.done();
  if (sigAlg === TPM_ALG_RSASSA) return nodeVerify('sha256', quoteMsg, publicKey, sig);
  if (sigAlg === TPM_ALG_RSAPSS) {
    return nodeVerify('sha256', quoteMsg, { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, sig);
  }
  throw new Error(`unsupported TPM signature algorithm: 0x${sigAlg.toString(16)}`);
}

function verifyQuotedPcrDigest(parsedQuote: ParsedQuote, pcrValues: Record<string, string>) {
  const sha256Selection = parsedQuote.selections.find((s) => s.hashAlg === TPM_ALG_SHA256);
  if (!sha256Selection) return { ok: false, detail: 'quote 未包含 sha256 PCR selection' };
  const chunks = [];
  for (const pcr of sha256Selection.pcrs) {
    const value = pcrValues[`sha256:${pcr}`];
    if (!value) return { ok: false, detail: `缺少 quote selection 中的 sha256:${pcr} PCR 值` };
    chunks.push(Buffer.from(value, 'hex'));
  }
  const calculated = createHash('sha256').update(Buffer.concat(chunks)).digest();
  const ok = calculated.equals(parsedQuote.pcrDigest);
  return {
    ok,
    detail: ok ? 'quote 内 PCR digest == PCRInfo.PCRValues 重算值' : `PCR digest 不符: calc=${calculated.toString('hex').slice(0, 12)}… quote=${parsedQuote.pcrDigest.toString('hex').slice(0, 12)}…`,
  };
}

function sameSelections(a: PcrSelection[], b: PcrSelection[]): boolean {
  return JSON.stringify(selectionSummary(a)) === JSON.stringify(selectionSummary(b));
}

function selectionSummary(selections: PcrSelection[]) {
  return selections.map((s) => ({ hashAlg: s.hashAlg, pcrs: [...s.pcrs].sort((x, y) => x - y) }))
    .sort((x, y) => x.hashAlg - y.hashAlg);
}

function pcrsFromSelect(select: Buffer): number[] {
  const pcrs = [];
  for (let byte = 0; byte < select.length; byte++) {
    for (let bit = 0; bit < 8; bit++) {
      if (select[byte] & (1 << bit)) pcrs.push(byte * 8 + bit);
    }
  }
  return pcrs;
}

function normalisePcrKey(key: string): string {
  const m = key.toLowerCase().match(/^(?:sha256:)?(\d+)$/);
  if (m) return `sha256:${Number(m[1])}`;
  if (/^sha256:\d+$/.test(key.toLowerCase())) return key.toLowerCase();
  return key.toLowerCase();
}

function normaliseExpectedPcrs(values: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) out[normalisePcrKey(key)] = normaliseHex(value);
  return out;
}

function normaliseHex(value: string): string {
  return value.replace(/^0x/i, '').toLowerCase();
}

function required(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function decodeBase64(value: string, label: string): Buffer {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be non-empty base64`);
  const b = Buffer.from(value, 'base64');
  if (b.length === 0 || b.length > MAX_FIELD_BYTES) throw new Error(`${label} too large or empty`);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) throw new Error(`${label} is not valid base64`);
  return b;
}

function jcsCanonicalize(value: unknown): string {
  if (value === null || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcsCanonicalize).join(',')}]`;
  if (typeof value !== 'object') throw new Error('unsupported JCS value');
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${jcsCanonicalize(obj[key])}`).join(',')}}`;
}

class Reader {
  private offset = 0;

  constructor(private readonly buf: Buffer) {}

  u8(): number {
    this.need(1);
    return this.buf[this.offset++];
  }

  u16(): number {
    this.need(2);
    const v = this.buf.readUInt16BE(this.offset);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const v = this.buf.readUInt32BE(this.offset);
    this.offset += 4;
    return v;
  }

  bytes(n: number): Buffer {
    this.need(n);
    const out = this.buf.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  tpm2b(): Buffer {
    const len = this.u16();
    return this.bytes(len);
  }

  done(): void {
    if (this.offset !== this.buf.length) throw new Error(`trailing bytes: ${this.buf.length - this.offset}`);
  }

  private need(n: number): void {
    if (this.offset + n > this.buf.length) throw new Error('unexpected EOF while parsing TPM structure');
  }
}
