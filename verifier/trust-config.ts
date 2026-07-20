import { readFileSync } from 'node:fs';
import type { EvidenceTrust } from './evidence-profile.ts';

export function loadTrustConfig(path: string | undefined, expectedPcr0: string | undefined): EvidenceTrust | undefined {
  if (!path) {
    if (!expectedPcr0) return undefined;
    return { profile: 'nitro', expectedPcr0 };
  }
  const trust = JSON.parse(readFileSync(path, 'utf8')) as EvidenceTrust;
  if (expectedPcr0 && !trust.expectedPcr0) trust.expectedPcr0 = expectedPcr0;
  return trust;
}

export function requirePcr0OrTrust(params: {
  pcr0?: string;
  trustPath?: string;
  usage: string;
}): void {
  if (params.pcr0 || params.trustPath) return;
  console.error(params.usage);
  console.error('  Nitro legacy: pass --pcr0 <hex>.');
  console.error('  Evidence profiles such as qingtian: pass --trust <trust.json>.');
  process.exit(2);
}
