import { createHash, verify as nodeVerify, X509Certificate } from 'node:crypto';
import type { EvidenceProfileVerifier, EvidenceTrust } from './evidence-profile.ts';

const COSE_ALG_ES384 = -35;
const EXPECTED_DIGEST = 'SHA384';
const MAX_ATTESTATION_BYTES = 128 * 1024;

type CborValue = number | string | Buffer | CborValue[] | Map<CborValue, CborValue> | { tag: number; value: CborValue } | boolean | null;

type ParsedQingTianEvidence = {
  protected: Buffer;
  protectedHeader: Map<CborValue, CborValue>;
  payloadBytes: Buffer;
  payload: Map<CborValue, CborValue>;
  signature: Buffer;
  moduleId: string;
  timestamp: number;
  digest: string;
  pcrs: Map<CborValue, CborValue>;
  certificate: Buffer;
  cabundle: Buffer[];
  userData: Buffer;
  nonce: Buffer;
  publicKey: Buffer;
};

type ChainVerdict = {
  ok: boolean;
  detail: string;
  rootFingerprint?: string;
  intermediateFingerprints: string[];
  leafNotAfter?: string;
};

const b64 = (s: string): Buffer => Buffer.from(s, 'base64');
const b64str = (b: Buffer): string => b.toString('base64');
const hex = (b: Buffer): string => b.toString('hex');
const sha256Hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex').toUpperCase();
const normaliseHex = (s: string): string => s.replace(/:/g, '').toUpperCase();
const normaliseMeasurementHex = (s: string | undefined): string | undefined => s?.replace(/[:\s]/g, '').toLowerCase();

export const qingtianEvidenceVerifier: EvidenceProfileVerifier = {
  profile: 'qingtian',
  verifyEvidence({ proof, trust, now }) {
    const checks: { name: string; ok: boolean; detail: string }[] = [];
    let evidence: ParsedQingTianEvidence;
    try {
      evidence = parseQingTianEvidence(b64(proof.attestation));
      checks.push({ name: 'QingTian evidence 格式', ok: true, detail: 'COSE_Sign1/QTSM payload 可解析' });
    } catch (err) {
      checks.push({ name: 'QingTian evidence 格式', ok: false, detail: (err as Error).message });
      return { ok: false, profile: 'qingtian', checks };
    }

    try {
      const alg = evidence.protectedHeader.get(1);
      const algOk = alg === COSE_ALG_ES384;
      checks.push({
        name: 'QingTian COSE alg',
        ok: algOk,
        detail: algOk ? 'protected.alg == ES384(-35)' : `unsupported COSE alg: ${String(alg)}`,
      });

      const leaf = new X509Certificate(evidence.certificate);
      const sigStructure = encodeCbor(['Signature1', evidence.protected, Buffer.alloc(0), evidence.payloadBytes]);
      const sigOk = verifyEs384(sigStructure, leaf, evidence.signature);
      checks.push({
        name: 'QingTian COSE 签名',
        ok: sigOk,
        detail: sigOk ? 'COSE_Sign1 signature verified by attested leaf certificate' : 'COSE_Sign1 signature verification failed',
      });

      const digestOk = evidence.digest === EXPECTED_DIGEST;
      checks.push({
        name: 'QingTian digest',
        ok: digestOk,
        detail: digestOk ? 'payload.digest == SHA384' : `unsupported payload.digest: ${evidence.digest}`,
      });

      const evidenceTimeOk = Number.isSafeInteger(evidence.timestamp) && evidence.timestamp > 0;
      checks.push({
        name: 'QingTian timestamp',
        ok: evidenceTimeOk,
        detail: evidenceTimeOk
          ? `payload.timestamp = ${new Date(evidence.timestamp).toISOString()}`
          : `invalid payload.timestamp: ${String(evidence.timestamp)}`,
      });

      const evidenceTime = evidenceTimeOk ? evidence.timestamp : now ?? Date.now();
      const chain = verifyCertificateChain(leaf, evidence.cabundle.map((c) => new X509Certificate(c)), trust, evidenceTime);
      checks.push({
        name: 'QingTian 证书链',
        ok: chain.ok,
        detail: chain.detail,
      });

      const pcr0 = pcrHex(evidence.pcrs, 0);
      const pcr8 = pcrHex(evidence.pcrs, 8);
      const expectedPcr0 = normaliseMeasurementHex(trust.expectedPcr0 ?? trust.expectedPcrs?.['sha384:0']);
      const expectedPcr8 = normaliseMeasurementHex(trust.expectedPcr8 ?? trust.expectedPcrs?.['sha384:8']);
      const pcr0Ok = !!expectedPcr0 && pcr0 === expectedPcr0;
      const pcr8Ok = !!expectedPcr8 && pcr8 === expectedPcr8;
      checks.push({
        name: 'PCR0 比对',
        ok: pcr0Ok,
        detail: pcr0Ok ? 'PCR0 == QingTian trust allowlist' : `PCR0 不符或未配置: ${pcr0.slice(0, 12)}… ≠ ${String(expectedPcr0).slice(0, 12)}…`,
      });
      checks.push({
        name: 'PCR8 比对',
        ok: pcr8Ok,
        detail: pcr8Ok ? 'PCR8 == QingTian signing certificate allowlist' : `PCR8 不符或未配置: ${pcr8.slice(0, 12)}… ≠ ${String(expectedPcr8).slice(0, 12)}…`,
      });

      const pubB64 = b64str(evidence.publicKey);
      const pubOk = pubB64 === proof.public_key;
      checks.push({
        name: '公钥绑定',
        ok: pubOk,
        detail: pubOk ? '签名公钥 == QingTian evidence 背书的 public_key' : '签名公钥与 QingTian evidence public_key 不符',
      });

      const nonceB64 = b64str(evidence.nonce);
      const nonceOk = nonceB64 === proof.nonce;
      checks.push({
        name: 'nonce 绑定',
        ok: nonceOk,
        detail: nonceOk ? 'QingTian evidence nonce == proof 顶层 nonce' : `nonce 不符:proof=${proof.nonce.slice(0, 10)}… evidence=${nonceB64.slice(0, 10)}…`,
      });

      const measurements: Record<string, string> = {};
      for (const [k, v] of evidence.pcrs.entries()) {
        if (typeof k === 'number' && Buffer.isBuffer(v)) measurements[`sha384:${k}`] = hex(v);
      }

      return {
        ok: checks.every((c) => c.ok),
        profile: 'qingtian',
        checks,
        moduleId: evidence.moduleId,
        pcr0,
        pcr8,
        measurements,
        publicKey: pubB64,
        nonce: nonceB64,
        platformTrust: {
          ok: chain.ok,
          mode: 'cert-chain',
          status: chain.ok ? 'ok' : 'platform_trust_invalid',
          issuer: chain.rootFingerprint,
          detail: chain.detail,
        },
      };
    } catch (err) {
      checks.push({ name: 'QingTian evidence 校验', ok: false, detail: (err as Error).message });
      return { ok: false, profile: 'qingtian', checks };
    }
  },
};

export function parseQingTianEvidence(attestation: Buffer): ParsedQingTianEvidence {
  if (attestation.byteLength > MAX_ATTESTATION_BYTES) {
    throw new Error(`attestation exceeds ${MAX_ATTESTATION_BYTES} bytes`);
  }
  const decoded = decodeCbor(attestation);
  if (decoded.offset !== attestation.byteLength) throw new Error('trailing bytes after COSE_Sign1');
  const cose = unwrapCoseSign1(decoded.value);
  if (!Array.isArray(cose) || cose.length !== 4) {
    throw new Error('QingTian attestation must be COSE_Sign1 array[4]');
  }
  const [protectedBytes, protectedMap, payloadBytes, signature] = cose;
  if (!Buffer.isBuffer(protectedBytes)) throw new Error('COSE protected header must be bstr');
  if (!(protectedMap instanceof Map) || protectedMap.size !== 0) throw new Error('COSE unprotected header must be empty map');
  if (!Buffer.isBuffer(payloadBytes)) throw new Error('COSE payload must be bstr');
  if (!Buffer.isBuffer(signature)) throw new Error('COSE signature must be bstr');
  if (signature.byteLength !== 96) throw new Error(`ES384 signature must be 96-byte raw r||s, got ${signature.byteLength}`);

  const protectedDecoded = decodeCbor(protectedBytes);
  if (!(protectedDecoded.value instanceof Map)) throw new Error('COSE protected header must decode to map');
  const payloadDecoded = decodeCbor(payloadBytes);
  if (!(payloadDecoded.value instanceof Map)) throw new Error('QingTian payload must decode to map');

  const payload = payloadDecoded.value;
  const cabundle = requiredArray(payload, 'cabundle');
  return {
    protected: protectedBytes,
    protectedHeader: protectedDecoded.value,
    payloadBytes,
    payload,
    signature,
    moduleId: requiredString(payload, 'module_id'),
    timestamp: requiredNumber(payload, 'timestamp'),
    digest: requiredString(payload, 'digest'),
    pcrs: requiredMap(payload, 'pcrs'),
    certificate: requiredBytes(payload, 'certificate'),
    cabundle: cabundle.map((c, i) => {
      if (!Buffer.isBuffer(c)) throw new Error(`cabundle[${i}] must be bstr DER certificate`);
      return c;
    }),
    userData: requiredBytes(payload, 'user_data'),
    nonce: requiredBytes(payload, 'nonce'),
    publicKey: requiredBytes(payload, 'public_key'),
  };
}

function unwrapCoseSign1(value: CborValue): CborValue {
  if (
    typeof value === 'object' &&
    value !== null &&
    !Buffer.isBuffer(value) &&
    !Array.isArray(value) &&
    'tag' in value &&
    value.tag === 18
  ) {
    return value.value;
  }
  return value;
}

function verifyCertificateChain(leaf: X509Certificate, cabundle: X509Certificate[], trust: EvidenceTrust, nowMs: number): ChainVerdict {
  if (trust.platformTrust?.mode !== 'cert-chain' || !trust.platformTrust.rootFingerprintsSha256?.length) {
    return { ok: false, detail: 'QingTian trust config must pin platformTrust.rootFingerprintsSha256', intermediateFingerprints: [] };
  }
  if (trust.platformTrust.revocation?.required && !trust.platformTrust.revocation.checkedExternally) {
    return {
      ok: false,
      detail: 'QingTian revocation checking is required but not implemented by this verifier; set checkedExternally=true only after an external CRL/OCSP check',
      intermediateFingerprints: [],
    };
  }
  const chain = [leaf];
  let current = leaf;
  const remaining = [...cabundle];
  for (let depth = 0; depth < cabundle.length + 1; depth++) {
    if (current.subject === current.issuer) break;
    const nextIndex = remaining.findIndex((candidate) => current.issuer === candidate.subject);
    if (nextIndex < 0) return { ok: false, detail: `issuer certificate not found for ${current.subject}`, intermediateFingerprints: [] };
    const [issuer] = remaining.splice(nextIndex, 1);
    chain.push(issuer);
    current = issuer;
  }

  const root = chain[chain.length - 1];
  const rootFingerprint = sha256Hex(root.raw);
  const pinnedRoots = trust.platformTrust.rootFingerprintsSha256.map(normaliseHex);
  if (!pinnedRoots.includes(rootFingerprint)) {
    return { ok: false, detail: `root fingerprint not pinned: ${rootFingerprint}`, rootFingerprint, intermediateFingerprints: [] };
  }
  if (root.subject !== root.issuer || !root.verify(root.publicKey)) {
    return { ok: false, detail: 'root certificate is not self-signed/self-verifiable', rootFingerprint, intermediateFingerprints: [] };
  }

  for (let i = 0; i < chain.length - 1; i++) {
    const cert = chain[i];
    const issuer = chain[i + 1];
    if (!cert.verify(issuer.publicKey)) {
      return { ok: false, detail: `certificate signature failed: ${cert.subject}`, rootFingerprint, intermediateFingerprints: [] };
    }
  }

  const timeBad = chain.find((cert) => !timeValid(cert, nowMs));
  if (timeBad) {
    return { ok: false, detail: `certificate not valid at evidence time: ${timeBad.subject}`, rootFingerprint, intermediateFingerprints: [] };
  }

  const intermediateFingerprints = chain.slice(1, -1).map((cert) => sha256Hex(cert.raw));
  const pinnedIntermediates = trust.platformTrust.intermediateFingerprintsSha256?.map(normaliseHex) ?? [];
  const missingIntermediate = pinnedIntermediates.find((fp) => !intermediateFingerprints.includes(fp));
  if (missingIntermediate) {
    return { ok: false, detail: `pinned intermediate not present in chain: ${missingIntermediate}`, rootFingerprint, intermediateFingerprints };
  }

  return {
    ok: true,
    detail: `QingTian certificate chain verified to pinned root ${rootFingerprint.slice(0, 12)}…`,
    rootFingerprint,
    intermediateFingerprints,
    leafNotAfter: leaf.validTo,
  };
}

function timeValid(cert: X509Certificate, nowMs: number): boolean {
  return Date.parse(cert.validFrom) <= nowMs && nowMs <= Date.parse(cert.validTo);
}

function pcrHex(pcrs: Map<CborValue, CborValue>, index: number): string {
  const value = pcrs.get(index);
  if (!Buffer.isBuffer(value) || value.byteLength !== 48) throw new Error(`PCR${index} missing or not SHA384-sized`);
  return hex(value);
}

export function verifyEs384(data: Buffer, cert: X509Certificate, signature: Buffer): boolean {
  if (nodeVerify('sha384', data, { key: cert.publicKey, dsaEncoding: 'ieee-p1363' }, signature)) {
    return true;
  }
  if (signature.byteLength === 96) {
    // QTSM emits ES384 as two fixed-width r/s limbs; real fixtures show each limb
    // serialized little-endian, while Node/OpenSSL expects IEEE-P1363 big-endian.
    const qtsmSignature = reverseEcdsaHalves(signature);
    if (nodeVerify('sha384', data, { key: cert.publicKey, dsaEncoding: 'ieee-p1363' }, qtsmSignature)) {
      return true;
    }
    if (nodeVerify('sha384', data, cert.publicKey, rawEcdsaToDer(qtsmSignature))) {
      return true;
    }
    return nodeVerify('sha384', data, cert.publicKey, rawEcdsaToDer(signature));
  }
  return false;
}

function reverseEcdsaHalves(raw: Buffer): Buffer {
  const half = raw.byteLength / 2;
  return Buffer.concat([Buffer.from(raw.subarray(0, half)).reverse(), Buffer.from(raw.subarray(half)).reverse()]);
}

function rawEcdsaToDer(raw: Buffer): Buffer {
  const half = raw.byteLength / 2;
  return derSequence([derInteger(raw.subarray(0, half)), derInteger(raw.subarray(half))]);
}

function derInteger(raw: Buffer): Buffer {
  let value = Buffer.from(raw);
  while (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) value = value.subarray(1);
  if (value[0] & 0x80) value = Buffer.concat([Buffer.from([0]), value]);
  return Buffer.concat([Buffer.from([0x02]), derLength(value.length), value]);
}

function derSequence(items: Buffer[]): Buffer {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}

function derLength(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function requiredString(map: Map<CborValue, CborValue>, key: string): string {
  const value = map.get(key);
  if (typeof value !== 'string') throw new Error(`${key} must be string`);
  return value;
}

function requiredNumber(map: Map<CborValue, CborValue>, key: string): number {
  const value = map.get(key);
  if (typeof value !== 'number') throw new Error(`${key} must be number`);
  return value;
}

function requiredBytes(map: Map<CborValue, CborValue>, key: string): Buffer {
  const value = map.get(key);
  if (!Buffer.isBuffer(value)) throw new Error(`${key} must be bytes`);
  return value;
}

function requiredMap(map: Map<CborValue, CborValue>, key: string): Map<CborValue, CborValue> {
  const value = map.get(key);
  if (!(value instanceof Map)) throw new Error(`${key} must be map`);
  return value;
}

function requiredArray(map: Map<CborValue, CborValue>, key: string): CborValue[] {
  const value = map.get(key);
  if (!Array.isArray(value)) throw new Error(`${key} must be array`);
  return value;
}

function decodeCbor(buf: Buffer, offset = 0): { value: CborValue; offset: number } {
  if (offset >= buf.byteLength) throw new Error('unexpected end of CBOR');
  const first = buf[offset++];
  const major = first >> 5;
  const ai = first & 0x1f;
  const readLen = () => readCborLength(buf, offset, ai);
  if (major === 0) {
    const [value, next] = readLen();
    return { value, offset: next };
  }
  if (major === 1) {
    const [value, next] = readLen();
    return { value: -1 - value, offset: next };
  }
  if (major === 2 || major === 3) {
    const [len, next] = readLen();
    const end = next + len;
    if (end > buf.byteLength) throw new Error('CBOR byte/text string exceeds input');
    const bytes = buf.subarray(next, end);
    return { value: major === 2 ? Buffer.from(bytes) : bytes.toString('utf8'), offset: end };
  }
  if (major === 4) {
    const [len, next] = readLen();
    const value = [];
    let p = next;
    for (let i = 0; i < len; i++) {
      const item = decodeCbor(buf, p);
      value.push(item.value);
      p = item.offset;
    }
    return { value, offset: p };
  }
  if (major === 5) {
    const [len, next] = readLen();
    const value = new Map<CborValue, CborValue>();
    let p = next;
    for (let i = 0; i < len; i++) {
      const key = decodeCbor(buf, p);
      const val = decodeCbor(buf, key.offset);
      value.set(key.value, val.value);
      p = val.offset;
    }
    return { value, offset: p };
  }
  if (major === 6) {
    const [tag, next] = readLen();
    const tagged = decodeCbor(buf, next);
    return { value: { tag, value: tagged.value }, offset: tagged.offset };
  }
  if (major === 7) {
    if (ai === 20) return { value: false, offset };
    if (ai === 21) return { value: true, offset };
    if (ai === 22) return { value: null, offset };
  }
  throw new Error(`unsupported CBOR major=${major} ai=${ai}`);
}

function readCborLength(buf: Buffer, offset: number, ai: number): [number, number] {
  if (ai < 24) return [ai, offset];
  if (ai === 24) return [buf[offset], offset + 1];
  if (ai === 25) return [buf.readUInt16BE(offset), offset + 2];
  if (ai === 26) return [buf.readUInt32BE(offset), offset + 4];
  if (ai === 27) {
    const value = Number(buf.readBigUInt64BE(offset));
    if (!Number.isSafeInteger(value)) throw new Error('CBOR uint64 is not safe integer');
    return [value, offset + 8];
  }
  throw new Error(`unsupported CBOR length ai=${ai}`);
}

export function encodeCbor(value: string | number | Buffer | Array<string | number | Buffer | unknown>): Buffer {
  if (typeof value === 'number') {
    if (value >= 0) return Buffer.concat([encodeCborHead(0, value)]);
    return Buffer.concat([encodeCborHead(1, -1 - value)]);
  }
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    return Buffer.concat([encodeCborHead(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([encodeCborHead(2, value.length), value]);
  if (Array.isArray(value)) {
    return Buffer.concat([encodeCborHead(4, value.length), ...value.map((v) => encodeCbor(v as any))]);
  }
  throw new Error('unsupported CBOR encode value');
}

function encodeCborHead(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 0xff) return Buffer.from([(major << 5) | 24, value]);
  if (value <= 0xffff) {
    const out = Buffer.alloc(3);
    out[0] = (major << 5) | 25;
    out.writeUInt16BE(value, 1);
    return out;
  }
  const out = Buffer.alloc(5);
  out[0] = (major << 5) | 26;
  out.writeUInt32BE(value, 1);
  return out;
}
