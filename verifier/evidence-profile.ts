import type { TeeCheck, TeeProofWire } from './tee-verify-core.ts';

export interface EvidenceTrust {
  profile?: string;
  expectedPcr0?: string;
  expectedPcr8?: string;
  expectedPcrs?: Record<string, string>;
  requirePlatformTrust?: boolean;
  platformTrust?: {
    mode?: 'missing' | 'cert-chain';
    rootFingerprintsSha256?: string[];
    intermediateFingerprintsSha256?: string[];
    rootCertificatesPem?: string[];
    intermediateCertificatesPem?: string[];
    revocation?: {
      required?: boolean;
      method?: string;
      checkedExternally?: boolean;
    };
  };
}

export interface EvidenceVerdict {
  ok: boolean;
  profile: string;
  checks: TeeCheck[];
  moduleId?: string;
  pcr0?: string | null;
  pcr8?: string | null;
  measurements?: Record<string, string>;
  publicKey?: string | null;
  nonce?: string | null;
  platformTrust?: {
    ok: boolean;
    mode: 'offline-chain' | 'cert-chain' | 'missing';
    status?: 'ok' | 'platform_trust_missing' | 'platform_trust_invalid';
    issuer?: string;
    detail: string;
  };
}

export interface EvidenceProfileVerifier {
  profile: string;
  verifyEvidence(input: {
    proof: TeeProofWire;
    trust: EvidenceTrust;
    now?: number;
  }): EvidenceVerdict;
}
