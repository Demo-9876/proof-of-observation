import type { AttestationVerifier } from './tee-verify-core.ts';
import type { EvidenceProfileVerifier } from './evidence-profile.ts';
// @ts-expect-error 纯 JS 零依赖模块
import { verifyAttestationDoc as realVerifyAttestationDoc } from './verify-attestation-cose.mjs';

const b64 = (s: string): Buffer => Buffer.from(s, 'base64');

export function createNitroEvidenceVerifier(
  verifyAttestationDoc: AttestationVerifier = realVerifyAttestationDoc as AttestationVerifier,
): EvidenceProfileVerifier {
  return {
    profile: 'nitro',
    verifyEvidence({ proof, trust, now }) {
      const checks = [];
      const expectedPcr0 = trust.expectedPcr0;
      let att;
      try {
        att = verifyAttestationDoc(b64(proof.attestation), { now });
      } catch (err) {
        checks.push({ name: '远程证明', ok: false, detail: `attestation 解析/验证异常:${(err as Error).message}` });
      }

      if (!att) {
        return { ok: false, profile: 'nitro', checks };
      }

      const chainOk = att.sigOk && att.chainOk && att.rootSelf && att.rootPinned;
      checks.push({
        name: '远程证明',
        ok: chainOk,
        detail: chainOk ? `COSE/P-384 链到 AWS 根(指纹 ${att.rootFingerprint?.slice(0, 11)}…)` : 'attestation 链校验失败',
      });
      checks.push({
        name: '证书有效期',
        ok: !!att.timeValid,
        detail: att.timeValid ? `链上证书均在有效期内(叶 notAfter ${att.leafNotAfter})` : `证书过期/未生效(叶 notAfter ${att.leafNotAfter})——无法确认新鲜`,
      });
      const pcr0Ok = !!expectedPcr0 && att.pcr0 === expectedPcr0;
      checks.push({
        name: 'PCR0 比对',
        ok: pcr0Ok,
        detail: pcr0Ok ? 'PCR0 == 审计值(跑的是审计镜像)' : `PCR0 不符: ${String(att.pcr0).slice(0, 12)}… ≠ ${String(expectedPcr0).slice(0, 12)}…`,
      });
      const bound = !!att.publicKey && att.publicKey === proof.public_key;
      checks.push({
        name: '公钥绑定',
        ok: bound,
        detail: bound ? '签名公钥 == attestation 背书的公钥' : '签名公钥与 attestation 不符(换了把没被认证的钥匙)',
      });
      const nonceOk = att.nonce === proof.nonce;
      checks.push({
        name: 'nonce 绑定',
        ok: nonceOk,
        detail: nonceOk ? 'att 内嵌 nonce == proof 顶层 nonce(均被签名覆盖)' : `nonce 不符:proof=${String(proof.nonce).slice(0, 10)}… att=${String(att.nonce).slice(0, 10)}…(拼接/伪造)`,
      });

      return {
        ok: checks.every((c) => c.ok),
        profile: 'nitro',
        checks,
        moduleId: att.moduleId,
        pcr0: att.pcr0,
        publicKey: att.publicKey,
        nonce: att.nonce,
        platformTrust: {
          ok: chainOk,
          mode: 'offline-chain',
          detail: chainOk ? 'AWS Nitro PKI root pinned' : 'AWS Nitro attestation chain failed',
        },
      };
    },
  };
}

export const nitroEvidenceVerifier = createNitroEvidenceVerifier();
