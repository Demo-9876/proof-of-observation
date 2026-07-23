// 真硬件客户端 verifier 的**纯核心**(让自证成立的那一半,可复用)—— v2 字段分解版。
//
// 设计见 docs/tee-signing-v2-design.md。与 mock 的 verifier.ts 不同:这里走真路径 ——
// attestation 是 COSE/P-384 链到 AWS 根(verify-attestation-cose.mjs),响应签名是 Ed25519
// 覆盖「字段分解声明」(signing.ts buildV2Statement)。verify-real-bundle.ts / 客户端 CLI /
// 校验代理 / tee-verify.html 都对齐本逻辑,杜绝漂移。
//
// 用户拿到 (收到的完整响应 + proof[,可选:自己发的请求体]) 后独立校验:
//   ① attestation 链到 AWS 根 + 证书有效期 + PCR0 == 审计公布值(跑的是审计镜像)
//   ② proof 签名公钥 == attestation 背书的公钥
//   ③ nonce 绑定:att 内嵌 nonce == proof 顶层 nonce(均被签名覆盖;relay 端 nonce,一致性核对)
//   ④ 上游 host:**直接读**签名覆盖的 upstream_host(给了 expectedHost 则比对,否则展示由你判断)
//   ⑤ 响应签名:用绑定公钥对「重建的声明」验签 + 收到的字节哈希 == 签名覆盖的 response_body_sha256
//   ⑥ 请求绑定(给了 requestBody 才做):你发的 body 哈希 == 签名覆盖的 request_body_sha256
// 全过 = 不是黑箱。任一不过 = 当场识破。
//
// 两档:full(给了 requestBody)= 多一项请求绑定(答的就是你这条请求);response-only = 只验响应未篡改 + 读 host。

import { createPublicKey, verify as edVerify } from 'node:crypto';
import { aliyunVtpmEvidenceVerifier } from './evidence-aliyun-vtpm.ts';
import { createNitroEvidenceVerifier, nitroEvidenceVerifier } from './evidence-nitro.ts';
import type { EvidenceProfileVerifier, EvidenceTrust } from './evidence-profile.ts';
import { qingtianEvidenceVerifier } from './evidence-qingtian.ts';
import { buildV2Statement, sha256 } from './signing.ts';

// v2 proof 线格式(docs/tee-signing-v2-design.md §5)。前 9 字段(nonce…response_body_sha256)即签名载荷。
export interface TeeProofWire {
  v?: number; // 2
  profile?: string; // 缺省 nitro；aliyun-vtpm/qingtian 等新 profile 走 evidence layer
  alg?: string;
  public_key: string; // base64 SPKI
  nonce: string; // base64
  upstream_host: string;
  upstream_path: string;
  http_method: string;
  http_status: number;
  resp_content_type: string;
  request_body_sha256: string; // hex
  response_body_sha256: string; // hex
  signature: string; // base64 Ed25519(覆盖重建声明)
  attestation: string; // base64 COSE_Sign1 文档
  evidence?: unknown; // profile-specific structured evidence；Nitro 旧 proof 可为空
  pcr0?: string;
  pcr8?: string;
}

// verify-attestation-cose.mjs verifyAttestationDoc 的返回形状(只取核验用得到的字段)。
export interface AttestationVerdict {
  ok: boolean;
  sigOk: boolean;
  chainOk: boolean;
  rootSelf: boolean;
  rootPinned: boolean;
  timeValid: boolean;
  leafNotAfter?: string;
  moduleId?: string;
  pcr0?: string | null;
  publicKey?: string | null;
  nonce?: string | null;
  rootFingerprint?: string;
}

export type AttestationVerifier = (doc: Buffer, opts?: { now?: number }) => AttestationVerdict;

export interface TeeVerifyInput {
  expectedPcr0?: string; // legacy Nitro shorthand: hex,审计公布、可由 reproducible-build 复算
  trust?: EvidenceTrust; // 新 profile 化 trust bundle；缺省从 expectedPcr0 推导 Nitro
  responseBody: Buffer; // 你实际收到的完整响应体(已剥掉 tee.proof 流末事件)
  proof: TeeProofWire;
  // 可选(full 档):你**自己发的请求体**,用来核对请求绑定(⑥)。
  requestBody?: Buffer;
  // 可选:核对签名覆盖的 upstream_host;不给则只展示由你判断(④)。
  expectedHost?: string;
  // 可选:由 verifier/requester 预先生成的 nonce。给了就强制 proof.nonce 完全一致,防重放。
  expectedNonceB64?: string;
  now?: number; // 证书有效期判定基准(测试可注)
}

export interface TeeCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface TeeVerifyResult {
  ok: boolean;
  mode: 'full' | 'response-only';
  checks: TeeCheck[];
  attestation: {
    profile?: string;
    moduleId?: string;
    pcr0?: string | null;
    pcr8?: string | null;
    measurements?: Record<string, string>;
    publicKey?: string | null;
    nonce?: string | null;
    platformTrust?: {
      ok: boolean;
      mode: string;
      issuer?: string;
      detail: string;
    };
  };
  // 签名覆盖的来源事实,供展示(验签过即可信)。
  provenance: {
    upstreamHost: string;
    upstreamPath: string;
    httpMethod: string;
    httpStatus: number;
    respContentType: string;
  };
}

const b64 = (s: string): Buffer => Buffer.from(s, 'base64');
const MAX_PROOF_STRING_BYTES = 1024 * 1024;

/**
 * 纯核验:无 I/O、无 console、无 process.exit。`deps.verifyAttestationDoc` 默认走真
 * COSE 实现;单测可注入桩以独立验证签名/摘要/nonce/host 半边(无需伪造真 Nitro 文档)。
 */
export function verifyTeeExchange(
  input: TeeVerifyInput,
  deps: {
    verifyAttestationDoc?: AttestationVerifier;
    evidenceVerifier?: EvidenceProfileVerifier; // legacy single-profile injection kept for existing tests/callers
    evidenceVerifiers?: Record<string, EvidenceProfileVerifier>;
  } = {},
): TeeVerifyResult {
  const t = input.proof;
  const full = input.requestBody !== undefined;
  const mode: TeeVerifyResult['mode'] = full ? 'full' : 'response-only';
  const checks: TeeCheck[] = [];
  const wireCheck = verifyWireEnvelope(t);
  checks.push(wireCheck);
  if (!wireCheck.ok) return failedWireResult(t, mode, checks);

  const profile = configuredProfile(input.trust, t);
  const trust: EvidenceTrust = {
    ...(input.trust ?? {}),
    profile,
    expectedPcr0: input.trust?.expectedPcr0 ?? input.expectedPcr0,
  };

  const profileCheck = verifyConfiguredProfile(profile, t, !!input.trust?.profile);
  checks.push(profileCheck);

  const evidenceVerifier = profileCheck.ok ? resolveEvidenceVerifier(profile, deps) : undefined;
  const evidence = evidenceVerifier?.verifyEvidence({ proof: t, trust, now: input.now });
  if (evidence) checks.push(...evidence.checks);
  else if (profileCheck.ok) checks.push({ name: '远程证明', ok: false, detail: `unsupported evidence profile: ${profile}` });

  if (input.expectedNonceB64) {
    const nonceOk = t.nonce === input.expectedNonceB64;
    checks.push({
      name: 'nonce 新鲜性',
      ok: nonceOk,
      detail: nonceOk ? 'proof.nonce == verifier/requester expectedNonce' : 'proof.nonce 与 verifier/requester expectedNonce 不一致',
    });
  }

  // ④ 上游 host:签名覆盖、直接读。给了 expectedHost 则比对,否则展示由你判断。
  if (input.expectedHost) {
    const hostOk = t.upstream_host.toLowerCase() === input.expectedHost.toLowerCase();
    checks.push({ name: '上游 host', ok: hostOk, detail: hostOk ? `签名覆盖的上游 host == ${input.expectedHost}(path ${t.upstream_path})` : `上游 host = ${t.upstream_host},≠ 期望的 ${input.expectedHost}` });
  } else {
    checks.push({ name: '上游 host', ok: true, detail: `签名覆盖的上游 host = ${t.upstream_host}(path ${t.upstream_path};请自行核对是否官方端点)` });
  }

  // ⑤ 响应签名:对「重建声明」验签 + 收到字节哈希核对。
  checks.push(verifySignatureCheck(t, input.responseBody));

  // ⑥ 请求绑定(full 档):你发的 body 哈希 == 签名覆盖的 request_body_sha256。
  if (full) {
    const reqOk = sha256(input.requestBody!).toString('hex') === t.request_body_sha256;
    checks.push({ name: '请求绑定', ok: reqOk, detail: reqOk ? '你发的请求体哈希 == 签名覆盖值(答的就是你这条请求)' : '你的请求体哈希 ≠ 签名覆盖值(请求被改 / 不是这条)' });
  }

  const ok = checks.length > 0 && checks.every((c) => c.ok);
  return {
    ok,
    mode,
    checks,
    attestation: {
      profile,
      moduleId: evidence?.moduleId,
      pcr0: evidence?.pcr0,
      pcr8: evidence?.pcr8,
      measurements: evidence?.measurements,
      publicKey: evidence?.publicKey,
      nonce: evidence?.nonce,
      platformTrust: evidence?.platformTrust,
    },
    provenance: {
      upstreamHost: t.upstream_host,
      upstreamPath: t.upstream_path,
      httpMethod: t.http_method,
      httpStatus: t.http_status,
      respContentType: t.resp_content_type,
    },
  };
}

function configuredProfile(trust: EvidenceTrust | undefined, proof: TeeProofWire): string {
  if (trust?.profile) return trust.profile;
  if (!proof.profile || proof.profile === 'nitro') return 'nitro';
  return proof.profile;
}

function verifyWireEnvelope(proof: unknown): TeeCheck {
  if (!isRecord(proof)) {
    return {
      name: 'proof wire',
      ok: false,
      detail: 'proof must be a JSON object',
    };
  }

  const errors: string[] = [];
  if (proof.v !== 2) {
    errors.push(`unsupported proof.v: ${String(proof.v)}; expected 2`);
  }
  if (proof.alg !== 'ed25519') {
    errors.push(`unsupported proof.alg: ${String(proof.alg)}; expected ed25519`);
  }

  for (const field of REQUIRED_PROOF_STRING_FIELDS) {
    const value = proof[field];
    if (typeof value !== 'string') {
      errors.push(`${field} must be string`);
      continue;
    }
    if (Buffer.byteLength(value, 'utf8') > MAX_PROOF_STRING_BYTES) {
      errors.push(`${field} exceeds ${MAX_PROOF_STRING_BYTES} bytes`);
    }
  }

  if (typeof proof.http_status !== 'number' || !Number.isInteger(proof.http_status) || proof.http_status < 100 || proof.http_status > 599) {
    errors.push('http_status must be an integer HTTP status code');
  }
  if (proof.profile !== undefined && typeof proof.profile !== 'string') {
    errors.push('profile must be string when present');
  }
  if (proof.evidence !== undefined && !isRecord(proof.evidence)) {
    errors.push('evidence must be an object when present');
  }
  if (typeof proof.request_body_sha256 === 'string' && !/^[0-9a-f]{64}$/.test(proof.request_body_sha256)) {
    errors.push('request_body_sha256 must be lowercase hex sha256');
  }
  if (typeof proof.response_body_sha256 === 'string' && !/^[0-9a-f]{64}$/.test(proof.response_body_sha256)) {
    errors.push('response_body_sha256 must be lowercase hex sha256');
  }

  if (errors.length > 0) {
    return {
      name: 'proof wire',
      ok: false,
      detail: errors.join('; '),
    };
  }
  return {
    name: 'proof wire',
    ok: true,
    detail: 'proof.v == 2 且 proof.alg == ed25519',
  };
}

const REQUIRED_PROOF_STRING_FIELDS = [
  'public_key',
  'nonce',
  'upstream_host',
  'upstream_path',
  'http_method',
  'resp_content_type',
  'request_body_sha256',
  'response_body_sha256',
  'signature',
  'attestation',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function failedWireResult(proof: unknown, mode: TeeVerifyResult['mode'], checks: TeeCheck[]): TeeVerifyResult {
  return {
    ok: false,
    mode,
    checks,
    attestation: {
      profile: stringField(proof, 'profile'),
    },
    provenance: {
      upstreamHost: stringField(proof, 'upstream_host') ?? '',
      upstreamPath: stringField(proof, 'upstream_path') ?? '',
      httpMethod: stringField(proof, 'http_method') ?? '',
      httpStatus: numberField(proof, 'http_status') ?? 0,
      respContentType: stringField(proof, 'resp_content_type') ?? '',
    },
  };
}

function stringField(value: unknown, field: string): string | undefined {
  return isRecord(value) && typeof value[field] === 'string' ? value[field] : undefined;
}

function numberField(value: unknown, field: string): number | undefined {
  return isRecord(value) && typeof value[field] === 'number' ? value[field] : undefined;
}

function verifyConfiguredProfile(profile: string, proof: TeeProofWire, hasConfiguredProfile: boolean): TeeCheck {
  if (profile !== 'nitro' && !hasConfiguredProfile) {
    return {
      name: 'Evidence profile',
      ok: false,
      detail: `非 Nitro profile=${profile} 必须由本地 trust.profile 显式选择`,
    };
  }
  if (proof.profile && proof.profile !== profile) {
    return {
      name: 'Evidence profile',
      ok: false,
      detail: `proof.profile=${proof.profile} 与 trust.profile=${profile} 不一致`,
    };
  }
  if (profile !== 'nitro' && !proof.profile) {
    return {
      name: 'Evidence profile',
      ok: false,
      detail: `trust.profile=${profile} 但 proof 未声明同一 profile`,
    };
  }
  return {
    name: 'Evidence profile',
    ok: true,
    detail: proof.profile ? `profile=${profile}` : 'legacy Nitro proof defaults to profile=nitro',
  };
}

function resolveEvidenceVerifier(
  profile: string,
  deps: {
    verifyAttestationDoc?: AttestationVerifier;
    evidenceVerifier?: EvidenceProfileVerifier;
    evidenceVerifiers?: Record<string, EvidenceProfileVerifier>;
  },
): EvidenceProfileVerifier | undefined {
  if (deps.evidenceVerifiers?.[profile]) return deps.evidenceVerifiers[profile];
  if (deps.evidenceVerifier?.profile === profile) return deps.evidenceVerifier;
  if (profile === 'nitro') return deps.verifyAttestationDoc ? createNitroEvidenceVerifier(deps.verifyAttestationDoc) : nitroEvidenceVerifier;
  if (profile === 'aliyun-vtpm') return aliyunVtpmEvidenceVerifier;
  if (profile === 'qingtian') return qingtianEvidenceVerifier;
  return undefined;
}

// 重建 v2 声明(用 proof 自报的字段值)→ 用绑定公钥验签;再核对收到的字节哈希 == 签名覆盖的响应体哈希。
function verifySignatureCheck(t: TeeProofWire, responseBody: Buffer): TeeCheck {
  try {
    const statement = buildV2Statement({
      nonceB64: t.nonce,
      upstreamHost: t.upstream_host,
      upstreamPath: t.upstream_path,
      httpMethod: t.http_method,
      httpStatus: t.http_status,
      respContentType: t.resp_content_type,
      requestBodySha256Hex: t.request_body_sha256,
      responseBodySha256Hex: t.response_body_sha256,
    });
    const pub = createPublicKey({ key: b64(t.public_key), format: 'der', type: 'spki' });
    const sigOk = edVerify(null, statement, pub, b64(t.signature));
    if (!sigOk) return { name: '响应签名', ok: false, detail: '验签失败:声明与签名不符(被改过)' };
    const bodyOk = sha256(responseBody).toString('hex') === t.response_body_sha256;
    if (!bodyOk) {
      return { name: '响应签名', ok: false, detail: '签名有效但你收到的响应体哈希 ≠ 签名覆盖值(响应被改过)' };
    }
    return { name: '响应签名', ok: true, detail: '声明验签通过,且你收到的响应体哈希吻合' };
  } catch (err) {
    return { name: '响应签名', ok: false, detail: `验签异常:${(err as Error).message}` };
  }
}

// production 流式下发:relay 原生透传的上游 SSE 字节之后附一条流末事件
//   event: tee.proof\ndata: {json}\n\n
// 验证方必须先剥掉这条末尾事件,再对**其余字节**(= 飞地签名的上游原文)重算 H(respBody)。
// 从末尾定位(proof 永远是最后一条事件),避免上游内容里偶现同名字串。
export const TEE_PROOF_EVENT = 'tee.proof';

export interface ParsedTeeProofStream {
  body: Buffer; // 上游原文(飞地签名的字节)
  proof?: TeeProofWire; // 末尾 tee.proof 事件(无则 undefined)
  bodyContentType?: string; // multipart 第一段的原始 Content-Type
  ignoredLeadingBlankBytes?: number; // 粘贴 body+proof 尾段时用户手动多加的开头空行,经 proof hash 证明后忽略
}

type MultipartPart = {
  headers: string;
  body: Buffer;
  nextBoundaryOffset: number;
};

export function parseTeeProofEvent(stream: string | Buffer | Uint8Array): ParsedTeeProofStream {
  const bytes = teeCaptureBytes(stream);
  const lfMarker = Buffer.from(`event: ${TEE_PROOF_EVENT}\n`, 'utf8');
  const crlfMarker = Buffer.from(`event: ${TEE_PROOF_EVENT}\r\n`, 'utf8');
  const lfIdx = bytes.lastIndexOf(lfMarker);
  const crlfIdx = bytes.lastIndexOf(crlfMarker);
  const idx = Math.max(lfIdx, crlfIdx);
  if (idx < 0) return { body: bytes };
  const eventBlock = bytes.subarray(idx).toString('utf8');
  const match = eventBlock.match(/^event: tee\.proof\r?\ndata: ([^\r\n]+)\r?\n\r?\n[\t\n\r ]*$/);
  if (!match) return { body: bytes };
  try {
    const proof = JSON.parse(match[1]) as TeeProofWire;
    return { body: bytes.subarray(0, idx), proof };
  } catch {
    return { body: bytes };
  }
}

export function parseTeeProofCapture(stream: string | Buffer | Uint8Array, contentType?: string): ParsedTeeProofStream {
  const parsedSse = parseTeeProofEvent(stream);
  if (parsedSse.proof) return parsedSse;
  return parseTeeProofMultipartResponse(stream, contentType) ?? parsedSse;
}

export function parseTeeProofMultipartResponse(
  stream: string | Buffer | Uint8Array,
  contentType?: string,
): ParsedTeeProofStream | undefined {
  const bytes = teeCaptureBytes(stream);
  const first = firstMultipartBoundary(bytes);
  const boundary = multipartBoundary(bytes, contentType, first);
  if (!boundary) return undefined;
  const boundaryBytes = Buffer.from(`--${boundary}`, 'utf8');
  const startOffset = first?.boundary === boundary ? first.offset : 0;
  if (startOffset > 0) {
    const tailCapture = parseTeeProofMultipartTailCapture(bytes, boundaryBytes, startOffset);
    if (tailCapture) return tailCapture;
  }
  const capture = bytes.subarray(startOffset);
  const firstBoundary = readMultipartBoundary(capture, boundaryBytes, 0);
  if (!firstBoundary || firstBoundary.closing) return undefined;
  const responsePart = readMultipartPart(capture, boundaryBytes, firstBoundary.nextOffset);
  if (!responsePart) return undefined;
  const proofBoundary = readMultipartBoundary(capture, boundaryBytes, responsePart.nextBoundaryOffset);
  if (!proofBoundary || proofBoundary.closing) return undefined;
  const proofPart = readMultipartPart(capture, boundaryBytes, proofBoundary.nextOffset);
  if (!proofPart) return undefined;
  const closingBoundary = readMultipartBoundary(capture, boundaryBytes, proofPart.nextBoundaryOffset);
  if (!closingBoundary?.closing) return undefined;

  let proof: TeeProofWire | undefined;
  try {
    const parsed = JSON.parse(proofPart.body.toString('utf8'));
    if (parsed?.type !== 'tee.proof_unavailable') proof = parsed as TeeProofWire;
  } catch {
    proof = undefined;
  }
  return { body: responsePart.body, proof, bodyContentType: multipartContentType(responsePart.headers) };
}

function parseTeeProofMultipartTailCapture(bytes: Buffer, boundaryBytes: Buffer, boundaryOffset: number): ParsedTeeProofStream | undefined {
  if (boundaryOffset <= 0) return undefined;
  const capture = bytes.subarray(boundaryOffset);
  const proofBoundary = readMultipartBoundary(capture, boundaryBytes, 0);
  if (!proofBoundary || proofBoundary.closing) return undefined;
  const proofPart = readMultipartPart(capture, boundaryBytes, proofBoundary.nextOffset);
  if (!proofPart || !isProofPartHeaders(proofPart.headers)) return undefined;
  const closingBoundary = readMultipartBoundary(capture, boundaryBytes, proofPart.nextBoundaryOffset);
  if (!closingBoundary?.closing) return undefined;

  let proof: TeeProofWire | undefined;
  try {
    const parsed = JSON.parse(proofPart.body.toString('utf8'));
    if (parsed?.type !== 'tee.proof_unavailable') proof = parsed as TeeProofWire;
  } catch {
    proof = undefined;
  }
  const normalized = removeLeadingBlankLinesIfSignedHashMatches(
    stripBoundarySeparatorLineEnding(bytes.subarray(0, boundaryOffset)),
    proof,
  );
  return { body: normalized.body, proof, ignoredLeadingBlankBytes: normalized.ignoredLeadingBlankBytes };
}

function teeCaptureBytes(stream: string | Buffer | Uint8Array): Buffer {
  return typeof stream === 'string'
    ? Buffer.from(stream, 'utf8')
    : Buffer.isBuffer(stream)
      ? stream
      : Buffer.from(stream);
}

function multipartBoundary(bytes: Buffer, contentType?: string, first = firstMultipartBoundary(bytes)): string | undefined {
  const fromContentType = contentType?.match(/boundary="?([^";]+)"?/i)?.[1];
  if (fromContentType) return fromContentType;
  return first?.boundary;
}

function firstMultipartBoundary(bytes: Buffer): { boundary: string; offset: number } | undefined {
  let start = bytes.subarray(0, 2).equals(Buffer.from('--')) ? 0 : -1;
  if (start < 0) {
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 10 && bytes[i + 1] === 45 && bytes[i + 2] === 45) {
        start = i + 1;
        break;
      }
    }
  }
  if (start < 0) return undefined;
  const lineEnd = bytes.indexOf(0x0a, start);
  if (lineEnd < 0) return undefined;
  let firstLine = bytes.subarray(start, lineEnd).toString('utf8');
  if (firstLine.endsWith('\r')) firstLine = firstLine.slice(0, -1);
  if (!firstLine.startsWith('--') || firstLine.endsWith('--')) return undefined;
  return { boundary: firstLine.slice(2), offset: start };
}

function readMultipartBoundary(bytes: Buffer, boundaryBytes: Buffer, offset: number): { closing: boolean; nextOffset: number } | undefined {
  if (!bytes.subarray(offset, offset + boundaryBytes.length).equals(boundaryBytes)) return undefined;
  let p = offset + boundaryBytes.length;
  const closing = bytes[p] === 45 && bytes[p + 1] === 45;
  if (closing) p += 2;
  if (closing && p === bytes.length) return { closing, nextOffset: p };
  const nextOffset = consumeLineEnding(bytes, p);
  if (nextOffset < 0) return undefined;
  return { closing, nextOffset };
}

function readMultipartPart(bytes: Buffer, boundaryBytes: Buffer, offset: number): MultipartPart | undefined {
  const headerEnd = multipartHeaderEnd(bytes, offset);
  if (!headerEnd) return undefined;
  const headers = bytes.subarray(offset, headerEnd.headerEnd).toString('utf8');
  const length = multipartContentLength(headers);
  const bodyStart = headerEnd.bodyStart;
  let bodyEnd = -1;
  let nextBoundaryOffset = -1;
  if (length !== undefined) {
    const expectedEnd = bodyStart + length;
    if (expectedEnd <= bytes.length) {
      const expectedNext = consumeLineEnding(bytes, expectedEnd);
      if (expectedNext >= 0 && bytes.subarray(expectedNext, expectedNext + boundaryBytes.length).equals(boundaryBytes)) {
        bodyEnd = expectedEnd;
        nextBoundaryOffset = expectedNext;
      }
    }
  }
  if (bodyEnd < 0) {
    const crlfBoundary = bytes.indexOf(Buffer.concat([Buffer.from('\r\n', 'utf8'), boundaryBytes]), bodyStart);
    const lfBoundary = bytes.indexOf(Buffer.concat([Buffer.from('\n', 'utf8'), boundaryBytes]), bodyStart);
    let marker = -1;
    let markerLength = 0;
    if (crlfBoundary >= 0 && (lfBoundary < 0 || crlfBoundary <= lfBoundary)) {
      marker = crlfBoundary;
      markerLength = 2;
    } else if (lfBoundary >= 0) {
      marker = lfBoundary;
      markerLength = 1;
    }
    if (marker < 0) return undefined;
    bodyEnd = marker;
    nextBoundaryOffset = marker + markerLength;
  }
  return {
    headers,
    body: Buffer.from(bytes.subarray(bodyStart, bodyEnd)),
    nextBoundaryOffset,
  };
}

function multipartHeaderEnd(bytes: Buffer, offset: number): { headerEnd: number; bodyStart: number } | undefined {
  const crlf = bytes.indexOf(Buffer.from('\r\n\r\n', 'utf8'), offset);
  const lf = bytes.indexOf(Buffer.from('\n\n', 'utf8'), offset);
  if (crlf >= 0 && (lf < 0 || crlf < lf)) return { headerEnd: crlf, bodyStart: crlf + 4 };
  if (lf >= 0) return { headerEnd: lf, bodyStart: lf + 2 };
  return undefined;
}

function multipartContentLength(headers: string): number | undefined {
  for (const line of headers.split(/\r?\n/)) {
    const match = line.match(/^content-length:\s*(\d+)\s*$/i);
    if (!match) continue;
    const value = Number.parseInt(match[1], 10);
    return Number.isFinite(value) && value >= 0 ? value : undefined;
  }
  return undefined;
}

function multipartContentType(headers: string): string | undefined {
  for (const line of headers.split(/\r?\n/)) {
    const match = line.match(/^content-type:\s*(.+?)\s*$/i);
    if (match) return match[1];
  }
  return undefined;
}

function consumeLineEnding(bytes: Buffer, offset: number): number {
  if (bytes[offset] === 13 && bytes[offset + 1] === 10) return offset + 2;
  if (bytes[offset] === 10) return offset + 1;
  return -1;
}

function isProofPartHeaders(headers: string): boolean {
  return /content-disposition:\s*[^;\r\n]*(?:;\s*)?name="?proof"?/i.test(headers)
    || /content-type:\s*application\/[^;\r\n]*proof[^;\r\n]*/i.test(headers);
}

function stripBoundarySeparatorLineEnding(bytes: Buffer): Buffer {
  if (bytes.length >= 2 && bytes[bytes.length - 2] === 13 && bytes[bytes.length - 1] === 10) {
    return Buffer.from(bytes.subarray(0, bytes.length - 2));
  }
  if (bytes.length >= 1 && bytes[bytes.length - 1] === 10) {
    return Buffer.from(bytes.subarray(0, bytes.length - 1));
  }
  return Buffer.from(bytes);
}

function removeLeadingBlankLinesIfSignedHashMatches(
  body: Buffer,
  proof?: TeeProofWire,
): { body: Buffer; ignoredLeadingBlankBytes?: number } {
  const expected = typeof proof?.response_body_sha256 === 'string'
    ? proof.response_body_sha256.toLowerCase()
    : '';
  if (!/^[a-f0-9]{64}$/.test(expected)) return { body };
  if (sha256(body).toString('hex') === expected) return { body };

  let offset = 0;
  for (;;) {
    const next = consumeLeadingBlankLine(body, offset);
    if (next <= offset) return { body };
    offset = next;
    const candidate = Buffer.from(body.subarray(offset));
    if (sha256(candidate).toString('hex') === expected) {
      return { body: candidate, ignoredLeadingBlankBytes: offset };
    }
  }
}

function consumeLeadingBlankLine(bytes: Buffer, offset: number): number {
  let p = offset;
  while (bytes[p] === 32 || bytes[p] === 9) p++;
  if (bytes[p] === 13 && bytes[p + 1] === 10) return p + 2;
  if (bytes[p] === 10) return p + 1;
  return -1;
}
