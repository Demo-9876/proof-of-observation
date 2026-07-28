// Build a full offline verification bundle from the exact request body and a
// captured response that contains tee.proof (SSE tail event, multipart/mixed,
// or a non-streaming JSON top-level proof field).
//
//   npx tsx make-real-bundle.ts <request.json> <captured-response> <bundle.json>
//
// The output is consumed by verify-real-bundle.ts and enables full verification:
// attestation + response signature + request binding.

import { readFileSync, writeFileSync } from 'node:fs';
import { parseTeeProofCapture } from './tee-verify-core.ts';

const usage = '用法: tsx make-real-bundle.ts <request.json> <captured-response> <bundle.json>';
const [requestPath, responsePath, bundlePath] = process.argv.slice(2);

if (!requestPath || !responsePath || !bundlePath) {
  console.error(usage);
  process.exit(2);
}

let requestBody: Buffer;
let captured: Buffer;
try {
  requestBody = readFileSync(requestPath);
  captured = readFileSync(responsePath);
} catch (err) {
  console.error(`读取输入文件失败: ${(err as Error).message}`);
  process.exit(1);
}

const { body: responseBody, proof } = parseTeeProofCapture(captured);
if (!proof) {
  console.error('no tee.proof found in captured response');
  process.exit(1);
}

writeFileSync(
  bundlePath,
  `${JSON.stringify({
    requestBody_b64: requestBody.toString('base64'),
    responseBody_b64: responseBody.toString('base64'),
    proof,
  }, null, 2)}\n`,
);

console.log(`wrote ${bundlePath}`);
