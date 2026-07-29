import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export type ProtocolFamily =
  | 'openai.chat_completions'
  | 'openai.responses'
  | 'anthropic.messages'
  | 'google.gemini.generate_content'
  | 'alibaba.dashscope.generation'
  | 'aws.bedrock.converse'
  | 'cohere.chat'
  | 'unknown';

const SUPPORTED_PROTOCOLS: Exclude<ProtocolFamily, 'unknown'>[] = [
  'openai.chat_completions',
  'openai.responses',
  'anthropic.messages',
  'google.gemini.generate_content',
  'alibaba.dashscope.generation',
  'aws.bedrock.converse',
  'cohere.chat',
];

interface FieldPolicyRegistry {
  policy: string;
  default: string;
  protocol_versions: Record<Exclude<ProtocolFamily, 'unknown'>, string>;
}

const FIELD_POLICY_REGISTRY = loadFieldPolicyRegistry();

export interface FieldClaims {
  v: number;
  proof_type: 'field-proof';
  nonce: string;
  protocol_family: ProtocolFamily;
  assurance_level: 'strong' | 'weak';
  verification_mode: 'field_claims';
  cross_protocol: boolean;
  semantic_equivalence_not_proven: boolean;
  request_schema_version: string;
  response_schema_version: string;
  upstream_host: string;
  upstream_path: string;
  http_method: string;
  http_status: number;
  field_policy_id: string;
  upstream_request_fields_sha256: string;
  upstream_response_fields_sha256: string;
  request_body_sha256_severity: 'advisory';
  response_body_sha256_severity: 'advisory';
  body_hash_policy: 'advisory';
  streaming: boolean;
}

export interface FieldHashInput {
  upstreamHost: string;
  upstreamPath: string;
  httpMethod: string;
  httpStatus: number;
  nonceB64: string;
  requestBody: Buffer;
  responseBody: Buffer;
  enhancedProtocolFamily?: ProtocolFamily;
  configuredProtocolFamily?: ProtocolFamily;
}

export interface FieldHashResult {
  claims: FieldClaims;
  requestView: unknown;
  responseView: unknown;
}

export interface FieldVerifyResult {
  protocolFamily: ProtocolFamily;
  requestChecked: boolean;
  requestOk: boolean;
  responseOk: boolean;
  requestHash?: string;
  responseHash: string;
}

export interface FieldProofContext {
  nonce: string;
  upstream_host: string;
  upstream_path: string;
  http_method: string;
  http_status: number;
  resp_content_type: string;
}

export function buildFieldClaims(input: FieldHashInput): FieldHashResult | undefined {
  const protocol = detectProtocolFamily(input.upstreamHost, input.upstreamPath, input.requestBody, {
    enhancedProtocolFamily: input.enhancedProtocolFamily,
    configuredProtocolFamily: input.configuredProtocolFamily,
  });
  if (protocol === 'unknown') return undefined;
  const requestView = extractFieldView(protocol, 'request', input.requestBody, input.upstreamPath);
  const responseView = extractFieldView(protocol, 'response', input.responseBody, input.upstreamPath);
  if (!hasRequiredPresence(protocol, 'request', requestView)) return undefined;
  if (!hasRequiredPresence(protocol, 'response', responseView)) return undefined;
  const claims: FieldClaims = {
    v: 1,
    proof_type: 'field-proof',
    nonce: input.nonceB64,
    protocol_family: protocol,
    assurance_level: 'strong',
    verification_mode: 'field_claims',
    cross_protocol: false,
    semantic_equivalence_not_proven: false,
    request_schema_version: schemaVersion(protocol),
    response_schema_version: schemaVersion(protocol),
    upstream_host: input.upstreamHost.toLowerCase(),
    upstream_path: pathWithoutQuery(input.upstreamPath),
    http_method: input.httpMethod.toUpperCase(),
    http_status: input.httpStatus,
    field_policy_id: fieldPolicyId(protocol),
    upstream_request_fields_sha256: sha256Hex(Buffer.from(canonicalJson(requestView), 'utf8')),
    upstream_response_fields_sha256: sha256Hex(Buffer.from(canonicalJson(responseView), 'utf8')),
    request_body_sha256_severity: 'advisory',
    response_body_sha256_severity: 'advisory',
    body_hash_policy: 'advisory',
    streaming: looksLikeSse(input.responseBody),
  };
  return { claims, requestView, responseView };
}

export function verifyFieldClaims(
  claims: unknown,
  requestBody: Buffer | undefined,
  responseBody: Buffer,
  proof?: FieldProofContext,
): FieldVerifyResult {
  if (!isRecord(claims)) throw new Error('field_claims must be an object');
  const protocol = protocolFamilyFromValue(claims.protocol_family);
  if (protocol === 'unknown') throw new Error(`unsupported protocol_family: ${String(claims.protocol_family)}`);
  if (claims.proof_type !== 'field-proof') throw new Error('field_claims.proof_type must be field-proof');
  if (claims.verification_mode !== 'field_claims') throw new Error('field_claims.verification_mode must be field_claims');
  validateFieldClaimsEnvelope(protocol, claims, proof);
  if (!hasRequiredPresence(protocol, 'response', extractFieldView(protocol, 'response', responseBody, proof?.upstream_path))) {
    throw new Error(`response does not satisfy required_presence for ${protocol}`);
  }
  const responseHash = hashFieldView(protocol, 'response', responseBody, proof?.upstream_path);
  const expectedResponse = stringField(claims, 'upstream_response_fields_sha256');
  if (!expectedResponse) throw new Error('field_claims.upstream_response_fields_sha256 is required');
  let requestHash: string | undefined;
  let requestOk = true;
  let requestChecked = false;
  if (requestBody) {
    requestChecked = true;
    if (!hasRequiredPresence(protocol, 'request', extractFieldView(protocol, 'request', requestBody, proof?.upstream_path))) {
      throw new Error(`request does not satisfy required_presence for ${protocol}`);
    }
    requestHash = hashFieldView(protocol, 'request', requestBody, proof?.upstream_path);
    const expectedRequest = stringField(claims, 'upstream_request_fields_sha256');
    if (!expectedRequest) throw new Error('field_claims.upstream_request_fields_sha256 is required');
    requestOk = requestHash === expectedRequest;
  }
  return {
    protocolFamily: protocol,
    requestChecked,
    requestOk,
    responseOk: responseHash === expectedResponse,
    requestHash,
    responseHash,
  };
}

export function fieldClaimsSha256Hex(claims: unknown): string {
  return sha256Hex(Buffer.from(canonicalJson(claims), 'utf8'));
}

export function detectProtocolFamily(
  host: string,
  path: string,
  body?: Buffer,
  opts: { enhancedProtocolFamily?: ProtocolFamily; configuredProtocolFamily?: ProtocolFamily } = {},
): ProtocolFamily {
  const p = pathWithoutQuery(path).toLowerCase();
  const h = host.toLowerCase();
  if (p.endsWith('/chat/completions') || p.includes('/chat/completions')) return 'openai.chat_completions';
  if (p.endsWith('/responses') || p.includes('/responses')) return 'openai.responses';
  if (p.endsWith('/messages') || h.includes('anthropic')) return 'anthropic.messages';
  if (p.includes(':generatecontent') || p.includes('generatecontent')) return 'google.gemini.generate_content';
  if (p.includes('/services/aigc/text-generation/generation')) return 'alibaba.dashscope.generation';
  if (p.includes('/converse')) return 'aws.bedrock.converse';
  if (p.endsWith('/chat') || p.includes('/v2/chat') || h.includes('cohere')) return 'cohere.chat';
  if (opts.enhancedProtocolFamily && opts.enhancedProtocolFamily !== 'unknown') return opts.enhancedProtocolFamily;
  if (opts.configuredProtocolFamily && opts.configuredProtocolFamily !== 'unknown') return opts.configuredProtocolFamily;
  if (body) return inferProtocolFromBody(body);
  return 'unknown';
}

export function hashFieldView(protocol: ProtocolFamily, kind: 'request' | 'response', body: Buffer, upstreamPath?: string): string {
  return sha256Hex(Buffer.from(canonicalJson(extractFieldView(protocol, kind, body, upstreamPath)), 'utf8'));
}

export function extractFieldView(protocol: ProtocolFamily, kind: 'request' | 'response', body: Buffer, upstreamPath?: string): unknown {
  const parsed = looksLikeSse(body) ? parseSseData(body) : parseJsonBody(body);
  if (protocol === 'openai.chat_completions') return openaiChatView(kind, parsed);
  if (protocol === 'openai.responses') return openaiResponsesView(kind, parsed);
  if (protocol === 'anthropic.messages') return anthropicMessagesView(kind, parsed);
  if (protocol === 'google.gemini.generate_content') return geminiGenerateContentView(kind, parsed, upstreamPath);
  if (protocol === 'alibaba.dashscope.generation') return dashscopeGenerationView(kind, parsed);
  if (protocol === 'aws.bedrock.converse') return bedrockConverseView(kind, parsed, upstreamPath);
  if (protocol === 'cohere.chat') return cohereChatView(kind, parsed);
  return parsed;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

function openaiChatView(kind: 'request' | 'response', parsed: unknown): unknown {
  if (kind === 'request') {
    return pick(parsed, ['model', 'messages']);
  }
  if (Array.isArray(parsed)) {
    return aggregateOpenAIChatStream(parsed);
  }
  return pick(parsed, ['model', 'choices', 'usage', 'error']);
}

function aggregateOpenAIChatStream(chunks: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const choices = new Map<number, Record<string, unknown>>();
  for (const chunk of chunks) {
    if (!isRecord(chunk)) continue;
    if (out.model === undefined && typeof chunk.model === 'string') out.model = chunk.model;
    if (chunk.usage !== undefined) out.usage = chunk.usage;
    if (chunk.error !== undefined) out.error = chunk.error;
    const rawChoices = Array.isArray(chunk.choices) ? chunk.choices : [];
    for (let i = 0; i < rawChoices.length; i++) {
      const rawChoice = rawChoices[i];
      if (!isRecord(rawChoice)) continue;
      const index = typeof rawChoice.index === 'number' ? rawChoice.index : i;
      const choice = choices.get(index) ?? { index, message: {} };
      const message = isRecord(choice.message) ? choice.message : {};
      if (isRecord(rawChoice.delta)) mergeOpenAIChatDelta(message, rawChoice.delta);
      if (isRecord(rawChoice.message)) mergeObject(message, rawChoice.message);
      choice.message = message;
      if (rawChoice.finish_reason !== undefined && rawChoice.finish_reason !== null) choice.finish_reason = rawChoice.finish_reason;
      if (rawChoice.logprobs !== undefined) choice.logprobs = rawChoice.logprobs;
      choices.set(index, choice);
    }
  }
  if (choices.size > 0) out.choices = Array.from(choices.values()).sort((a, b) => Number(a.index) - Number(b.index));
  return out;
}

function openaiResponsesView(kind: 'request' | 'response', parsed: unknown): unknown {
  if (kind === 'request') {
    return pick(parsed, ['model', 'input']);
  }
  if (Array.isArray(parsed)) return aggregateOpenAIResponsesStream(parsed);
  return pick(parsed, ['model', 'status', 'output', 'output_text', 'usage', 'error']);
}

function aggregateOpenAIResponsesStream(events: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const outputItems = new Map<number, Record<string, unknown>>();
  for (const event of events) {
    if (!isRecord(event)) continue;
    const type = typeof event.type === 'string' ? event.type : '';
    if (isRecord(event.response)) {
      mergeObject(out, pick(event.response, ['model', 'status', 'output', 'output_text', 'usage', 'error']) as Record<string, unknown>);
    }
    if (type === 'response.output_item.added' || type === 'response.output_item.done') {
      const index = numberOrDefault(event.output_index, outputItems.size);
      const item = outputItems.get(index) ?? {};
      if (isRecord(event.item)) mergeObject(item, event.item);
      outputItems.set(index, item);
    } else if (type === 'response.content_part.added' || type === 'response.content_part.done') {
      const item = ensureIndexedObject(outputItems, event.output_index);
      mergeOpenAIResponseContentPart(item, event.content_index, event.part);
    } else if (type === 'response.output_text.delta' || type === 'response.output_text.done') {
      const item = ensureIndexedObject(outputItems, event.output_index);
      const part = mergeOpenAIResponseContentPart(item, event.content_index, { type: 'output_text' });
      if (type.endsWith('.done')) setStringField(part, 'text', event.text);
      else appendStringField(part, 'text', event.delta);
    } else if (type === 'response.refusal.delta' || type === 'response.refusal.done') {
      const item = ensureIndexedObject(outputItems, event.output_index);
      const part = mergeOpenAIResponseContentPart(item, event.content_index, { type: 'refusal' });
      if (type.endsWith('.done')) setStringField(part, 'refusal', event.refusal);
      else appendStringField(part, 'refusal', event.delta);
    } else if (type === 'response.reasoning_text.delta' || type === 'response.reasoning_text.done') {
      const item = ensureIndexedObject(outputItems, event.output_index);
      const part = mergeOpenAIResponseContentPart(item, event.content_index, { type: 'reasoning_text' });
      if (type.endsWith('.done')) setStringField(part, 'text', event.text);
      else appendStringField(part, 'text', event.delta);
    } else if (type === 'response.function_call_arguments.delta' || type === 'response.function_call_arguments.done') {
      const item = ensureIndexedObject(outputItems, event.output_index);
      if (type.endsWith('.done')) setStringField(item, 'arguments', event.arguments);
      else appendStringField(item, 'arguments', event.delta);
    } else if (type === 'response.completed' && out.status === undefined) {
      out.status = 'completed';
    } else if (type === 'response.failed' && event.error !== undefined) {
      out.error = event.error;
    }
  }
  if (outputItems.size > 0 && (!Array.isArray(out.output) || out.output.length === 0)) {
    out.output = Array.from(outputItems.entries())
      .sort(([a], [b]) => a - b)
      .map(([, item]) => item);
  }
  return pick(out, ['model', 'status', 'output', 'output_text', 'usage', 'error']);
}

function anthropicMessagesView(kind: 'request' | 'response', parsed: unknown): unknown {
  if (kind === 'request') {
    return pick(parsed, ['model', 'messages', 'system']);
  }
  if (Array.isArray(parsed)) return aggregateAnthropicMessagesStream(parsed);
  return pick(parsed, ['type', 'role', 'model', 'content', 'stop_reason', 'usage', 'error']);
}

function aggregateAnthropicMessagesStream(events: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const contentBlocks = new Map<number, Record<string, unknown>>();
  for (const event of events) {
    if (!isRecord(event)) continue;
    const type = typeof event.type === 'string' ? event.type : '';
    if (type === 'message_start' && isRecord(event.message)) {
      mergeObject(out, pick(event.message, ['type', 'role', 'model', 'stop_reason', 'usage']) as Record<string, unknown>);
      seedAnthropicContentBlocks(contentBlocks, event.message.content);
    } else if (type === 'content_block_start' && isRecord(event.content_block)) {
      const index = typeof event.index === 'number' ? event.index : contentBlocks.size;
      contentBlocks.set(index, { ...event.content_block });
    } else if (type === 'content_block_delta' && isRecord(event.delta)) {
      const index = typeof event.index === 'number' ? event.index : contentBlocks.size;
      const block = contentBlocks.get(index) ?? {};
      mergeAnthropicContentDelta(block, event.delta);
      contentBlocks.set(index, block);
    } else if (type === 'message_delta' && isRecord(event.delta)) {
      mergeObject(out, pick(event.delta, ['stop_reason', 'stop_sequence']) as Record<string, unknown>);
      mergeNestedObject(out, 'usage', event.usage);
    } else if (type === 'error') {
      out.error = event.error ?? event;
    }
  }
  if (contentBlocks.size > 0) {
    out.content = Array.from(contentBlocks.entries())
      .sort(([a], [b]) => a - b)
      .map(([, block]) => block);
  }
  return pick(out, ['type', 'role', 'model', 'content', 'stop_reason', 'usage', 'error']);
}

function geminiGenerateContentView(kind: 'request' | 'response', parsed: unknown, upstreamPath?: string): unknown {
  if (kind === 'request') {
    const view = pick(parsed, ['model', 'contents', 'systemInstruction']);
    if (isRecord(view) && view.model === undefined) {
      const model = geminiModelFromPath(upstreamPath);
      if (model) view.model = model;
    }
    return view;
  }
  if (Array.isArray(parsed)) return aggregateGeminiGenerateContentStream(parsed);
  return pick(parsed, ['candidates', 'promptFeedback', 'usageMetadata', 'error', 'modelVersion']);
}

function aggregateGeminiGenerateContentStream(chunks: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const candidates = new Map<number, Record<string, unknown>>();
  for (const chunk of chunks) {
    if (!isRecord(chunk)) continue;
    if (chunk.promptFeedback !== undefined) out.promptFeedback = chunk.promptFeedback;
    if (chunk.usageMetadata !== undefined) out.usageMetadata = chunk.usageMetadata;
    if (chunk.error !== undefined) out.error = chunk.error;
    if (chunk.modelVersion !== undefined) out.modelVersion = chunk.modelVersion;
    const rawCandidates = Array.isArray(chunk.candidates) ? chunk.candidates : [];
    for (let i = 0; i < rawCandidates.length; i++) {
      const rawCandidate = rawCandidates[i];
      if (!isRecord(rawCandidate)) continue;
      const index = numberOrDefault(rawCandidate.index, i);
      const candidate = candidates.get(index) ?? { index };
      mergeGeminiCandidate(candidate, rawCandidate);
      candidates.set(index, candidate);
    }
  }
  if (candidates.size > 0) {
    out.candidates = Array.from(candidates.values()).sort((a, b) => Number(a.index) - Number(b.index));
  }
  return pick(out, ['candidates', 'promptFeedback', 'usageMetadata', 'error', 'modelVersion']);
}

function dashscopeGenerationView(kind: 'request' | 'response', parsed: unknown): unknown {
  if (kind === 'request') return pick(parsed, ['model', 'input', 'system', 'messages']);
  if (Array.isArray(parsed)) return aggregateDashscopeGenerationStream(parsed);
  return pick(parsed, ['output', 'usage', 'request_id', 'code', 'message']);
}

function aggregateDashscopeGenerationStream(chunks: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const output: Record<string, unknown> = {};
  const choices = new Map<number, Record<string, unknown>>();
  for (const chunk of chunks) {
    if (!isRecord(chunk)) continue;
    for (const key of ['usage', 'request_id', 'code', 'message']) {
      if (chunk[key] !== undefined) out[key] = chunk[key];
    }
    if (!isRecord(chunk.output)) continue;
    for (const [key, value] of Object.entries(chunk.output)) {
      if (key !== 'choices') output[key] = value;
    }
    const rawChoices = Array.isArray(chunk.output.choices) ? chunk.output.choices : [];
    for (let i = 0; i < rawChoices.length; i++) {
      const rawChoice = rawChoices[i];
      if (!isRecord(rawChoice)) continue;
      const index = numberOrDefault(rawChoice.index, i);
      const choice = choices.get(index) ?? { index, message: {} };
      const message = isRecord(choice.message) ? choice.message : {};
      if (isRecord(rawChoice.message)) mergeDashscopeMessage(message, rawChoice.message);
      if (isRecord(rawChoice.delta)) mergeDashscopeMessage(message, rawChoice.delta);
      choice.message = message;
      for (const [key, value] of Object.entries(rawChoice)) {
        if (!['index', 'message', 'delta'].includes(key) && value !== null && value !== undefined) choice[key] = value;
      }
      choices.set(index, choice);
    }
  }
  if (choices.size > 0) {
    output.choices = Array.from(choices.values()).sort((a, b) => Number(a.index) - Number(b.index));
  }
  if (Object.keys(output).length > 0) out.output = output;
  return pick(out, ['output', 'usage', 'request_id', 'code', 'message']);
}

function seedAnthropicContentBlocks(blocks: Map<number, Record<string, unknown>>, content: unknown): void {
  if (!Array.isArray(content)) return;
  for (let i = 0; i < content.length; i++) {
    if (isRecord(content[i]) && !blocks.has(i)) blocks.set(i, { ...content[i] });
  }
}

function mergeAnthropicContentDelta(block: Record<string, unknown>, delta: Record<string, unknown>): void {
  if (block.type === undefined && typeof delta.type === 'string') {
    block.type = delta.type.replace(/_delta$/, '');
  }
  appendStringField(block, 'text', delta.text);
  appendStringField(block, 'thinking', delta.thinking);
  appendStringField(block, 'signature', delta.signature);
  appendStringField(block, 'input_json', delta.partial_json);
}

function mergeOpenAIChatDelta(message: Record<string, unknown>, delta: Record<string, unknown>): void {
  if (typeof delta.role === 'string' && message.role === undefined) message.role = delta.role;
  appendStringField(message, 'content', delta.content);
  appendStringField(message, 'reasoning_content', delta.reasoning_content);
  if (delta.tool_calls !== undefined) {
    message.tool_calls = mergeToolCalls(Array.isArray(message.tool_calls) ? message.tool_calls : [], delta.tool_calls);
  }
}

function mergeToolCalls(existing: unknown[], deltaValue: unknown): unknown[] {
  if (!Array.isArray(deltaValue)) return existing;
  const out = existing.map((item) => isRecord(item) ? { ...item } : item);
  for (const raw of deltaValue) {
    if (!isRecord(raw)) continue;
    const index = typeof raw.index === 'number' ? raw.index : out.length;
    const current = isRecord(out[index]) ? { ...(out[index] as Record<string, unknown>) } : {};
    for (const [key, value] of Object.entries(raw)) {
      if (key === 'function' && isRecord(value)) {
        const fn = isRecord(current.function) ? { ...current.function } : {};
        appendStringField(fn, 'name', value.name);
        appendStringField(fn, 'arguments', value.arguments);
        current.function = fn;
      } else if (key !== 'index') {
        current[key] = value;
      }
    }
    out[index] = current;
  }
  return out;
}

function ensureIndexedObject(map: Map<number, Record<string, unknown>>, rawIndex: unknown): Record<string, unknown> {
  const index = numberOrDefault(rawIndex, map.size);
  const item = map.get(index) ?? {};
  map.set(index, item);
  return item;
}

function mergeOpenAIResponseContentPart(item: Record<string, unknown>, rawIndex: unknown, rawPart: unknown): Record<string, unknown> {
  const content = Array.isArray(item.content) ? [...item.content] : [];
  const index = numberOrDefault(rawIndex, content.length);
  const part = isRecord(content[index]) ? { ...(content[index] as Record<string, unknown>) } : {};
  if (isRecord(rawPart)) mergeObject(part, rawPart);
  content[index] = part;
  item.content = content;
  return part;
}

function mergeGeminiCandidate(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) {
    if (key === 'index') continue;
    if (key === 'content' && isRecord(value)) {
      const content = isRecord(target.content) ? { ...target.content } : {};
      for (const [contentKey, contentValue] of Object.entries(value)) {
        if (contentKey === 'parts' && Array.isArray(contentValue)) {
          content.parts = mergeIndexedParts(Array.isArray(content.parts) ? content.parts : [], contentValue);
        } else if (contentValue !== null && contentValue !== undefined) {
          content[contentKey] = contentValue;
        }
      }
      target.content = content;
    } else if (value !== null && value !== undefined) {
      target[key] = value;
    }
  }
}

function mergeIndexedParts(existing: unknown[], incoming: unknown[]): unknown[] {
  const out = existing.map((item) => isRecord(item) ? { ...item } : item);
  for (let i = 0; i < incoming.length; i++) {
    if (!isRecord(incoming[i])) {
      out[i] = incoming[i];
      continue;
    }
    const current = isRecord(out[i]) ? { ...(out[i] as Record<string, unknown>) } : {};
    mergeSemanticPart(current, incoming[i] as Record<string, unknown>);
    out[i] = current;
  }
  return out;
}

function mergeSemanticPart(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) {
    if (key === 'text' || key === 'thinking' || key === 'signature') {
      appendStringField(target, key, value);
    } else if (isRecord(target[key]) && isRecord(value)) {
      target[key] = { ...(target[key] as Record<string, unknown>), ...value };
    } else if (value !== null && value !== undefined) {
      target[key] = value;
    }
  }
}

function mergeDashscopeMessage(target: Record<string, unknown>, source: Record<string, unknown>): void {
  appendStringField(target, 'content', source.content);
  appendStringField(target, 'reasoning_content', source.reasoning_content);
  if (source.tool_calls !== undefined) {
    target.tool_calls = mergeToolCalls(Array.isArray(target.tool_calls) ? target.tool_calls : [], source.tool_calls);
  }
  for (const [key, value] of Object.entries(source)) {
    if (!['content', 'reasoning_content', 'tool_calls'].includes(key) && value !== null && value !== undefined) {
      target[key] = value;
    }
  }
}

function mergeBedrockContentDelta(block: Record<string, unknown>, delta: Record<string, unknown>): void {
  appendStringField(block, 'text', delta.text);
  if (delta.text !== undefined && block.type === undefined) block.type = 'text';
  if (isRecord(delta.reasoningContent)) {
    block.reasoningContent = mergeNestedSemanticObject(block.reasoningContent, delta.reasoningContent, ['text', 'signature']);
  }
  if (isRecord(delta.toolUse)) {
    block.toolUse = mergeNestedSemanticObject(block.toolUse, delta.toolUse, ['input']);
  }
  if (isRecord(delta.citationsContent)) {
    block.citationsContent = mergeNestedSemanticObject(block.citationsContent, delta.citationsContent, ['text']);
  }
  for (const [key, value] of Object.entries(delta)) {
    if (!['text', 'reasoningContent', 'toolUse', 'citationsContent'].includes(key) && value !== null && value !== undefined) {
      block[key] = value;
    }
  }
}

function mergeNestedSemanticObject(existing: unknown, incoming: Record<string, unknown>, appendFields: string[]): Record<string, unknown> {
  const out = isRecord(existing) ? { ...existing } : {};
  for (const [key, value] of Object.entries(incoming)) {
    if (appendFields.includes(key)) appendStringField(out, key, value);
    else if (isRecord(out[key]) && isRecord(value)) out[key] = { ...(out[key] as Record<string, unknown>), ...value };
    else if (value !== null && value !== undefined) out[key] = value;
  }
  return out;
}

function mergeCohereMessageDelta(
  message: Record<string, unknown>,
  contentBlocks: Map<number, Record<string, unknown>>,
  rawMessage: unknown,
): void {
  if (!isRecord(rawMessage)) return;
  for (const [key, value] of Object.entries(rawMessage)) {
    if (key !== 'content' && value !== null && value !== undefined) message[key] = value;
  }
  const rawContent = rawMessage.content;
  if (Array.isArray(rawContent)) {
    for (let i = 0; i < rawContent.length; i++) mergeCohereContentBlock(contentBlocks, i, rawContent[i]);
  } else if (isRecord(rawContent)) {
    mergeCohereContentBlock(
      contentBlocks,
      numberOrDefault(rawContent.index, contentBlocks.size === 0 ? 0 : contentBlocks.size - 1),
      rawContent,
    );
  } else if (typeof rawContent === 'string') {
    const block = contentBlocks.get(0) ?? { type: 'text' };
    appendStringField(block, 'text', rawContent);
    contentBlocks.set(0, block);
  }
}

function mergeCohereContentBlock(blocks: Map<number, Record<string, unknown>>, index: number, rawBlock: unknown): void {
  if (!isRecord(rawBlock)) return;
  const block = blocks.get(index) ?? {};
  mergeSemanticPart(block, rawBlock);
  blocks.set(index, block);
}

function appendStringField(target: Record<string, unknown>, field: string, value: unknown): void {
  if (typeof value !== 'string') return;
  target[field] = typeof target[field] === 'string' ? `${target[field]}${value}` : value;
}

function setStringField(target: Record<string, unknown>, field: string, value: unknown): void {
  if (typeof value !== 'string') return;
  target[field] = value;
}

function mergeObject(target: Record<string, unknown>, source: Record<string, unknown>): void {
  for (const [key, value] of Object.entries(source)) target[key] = value;
}

function mergeNestedObject(target: Record<string, unknown>, field: string, value: unknown): void {
  if (value === undefined) return;
  if (isRecord(target[field]) && isRecord(value)) {
    target[field] = { ...target[field], ...value };
  } else {
    target[field] = value;
  }
}

function bedrockConverseView(kind: 'request' | 'response', parsed: unknown, upstreamPath?: string): unknown {
  if (kind !== 'request') {
    if (Array.isArray(parsed)) return aggregateBedrockConverseStream(parsed);
    return pick(parsed, ['output', 'stopReason', 'usage', 'error']);
  }
  const view = pick(parsed, ['modelId', 'messages', 'system']);
  if (isRecord(view) && view.modelId === undefined) {
    const modelId = bedrockModelIdFromPath(upstreamPath);
    if (modelId) view.modelId = modelId;
  }
  return view;
}

function aggregateBedrockConverseStream(events: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const message: Record<string, unknown> = {};
  const contentBlocks = new Map<number, Record<string, unknown>>();
  for (const event of events) {
    if (!isRecord(event)) continue;
    if (isRecord(event.messageStart) && event.messageStart.role !== undefined) {
      message.role = event.messageStart.role;
    }
    if (isRecord(event.contentBlockStart)) {
      const index = numberOrDefault(event.contentBlockStart.contentBlockIndex, contentBlocks.size);
      const block = contentBlocks.get(index) ?? {};
      if (isRecord(event.contentBlockStart.start)) mergeObject(block, event.contentBlockStart.start);
      contentBlocks.set(index, block);
    }
    if (isRecord(event.contentBlockDelta)) {
      const index = numberOrDefault(event.contentBlockDelta.contentBlockIndex, contentBlocks.size);
      const block = contentBlocks.get(index) ?? {};
      if (isRecord(event.contentBlockDelta.delta)) mergeBedrockContentDelta(block, event.contentBlockDelta.delta);
      contentBlocks.set(index, block);
    }
    if (isRecord(event.messageStop)) {
      if (event.messageStop.stopReason !== undefined) out.stopReason = event.messageStop.stopReason;
      if (event.messageStop.additionalModelResponseFields !== undefined) {
        out.additionalModelResponseFields = event.messageStop.additionalModelResponseFields;
      }
    }
    if (isRecord(event.metadata)) {
      if (event.metadata.usage !== undefined) out.usage = event.metadata.usage;
    }
    if (isRecord(event.output)) mergeObject(out, pick(event, ['output', 'stopReason', 'usage', 'error']) as Record<string, unknown>);
    if (event.error !== undefined) out.error = event.error;
  }
  if (contentBlocks.size > 0) {
    message.content = Array.from(contentBlocks.entries())
      .sort(([a], [b]) => a - b)
      .map(([, block]) => block);
  }
  if (Object.keys(message).length > 0 && out.output === undefined) {
    out.output = { message };
  }
  return pick(out, ['output', 'stopReason', 'usage', 'error']);
}

function cohereChatView(kind: 'request' | 'response', parsed: unknown): unknown {
  if (kind === 'request') {
    return pick(parsed, ['model', 'messages', 'message']);
  }
  if (Array.isArray(parsed)) return aggregateCohereChatStream(parsed);
  return pick(parsed, ['message', 'text', 'finish_reason', 'usage', 'error']);
}

function aggregateCohereChatStream(events: unknown[]): unknown {
  const out: Record<string, unknown> = {};
  const message: Record<string, unknown> = {};
  const contentBlocks = new Map<number, Record<string, unknown>>();
  let text = '';
  for (const event of events) {
    if (!isRecord(event)) continue;
    const type = stringValue(event.type) ?? stringValue(event.event_type) ?? stringValue(event.eventType) ?? '';
    if (isRecord(event.response)) mergeObject(out, pick(event.response, ['message', 'text', 'finish_reason', 'usage', 'error']) as Record<string, unknown>);
    const delta = isRecord(event.delta) ? event.delta : undefined;
    if (delta && isRecord(delta.message)) mergeCohereMessageDelta(message, contentBlocks, delta.message);
    if (type === 'text-generation' && typeof event.text === 'string') text += event.text;
    if (type === 'message-end' && delta) {
      if (delta.finish_reason !== undefined) {
        out.finish_reason = delta.finish_reason;
        message.finish_reason = delta.finish_reason;
      }
      if (delta.usage !== undefined) out.usage = delta.usage;
    }
    if (event.finish_reason !== undefined) {
      out.finish_reason = event.finish_reason;
      message.finish_reason = event.finish_reason;
    }
    if (event.error !== undefined) out.error = event.error;
  }
  if (contentBlocks.size > 0) {
    message.content = Array.from(contentBlocks.entries())
      .sort(([a], [b]) => a - b)
      .map(([, block]) => block);
  } else if (text) {
    message.content = [{ type: 'text', text }];
    out.text = text;
  }
  if (Object.keys(message).length > 0 && out.message === undefined) out.message = message;
  return pick(out, ['message', 'text', 'finish_reason', 'usage', 'error']);
}

function geminiModelFromPath(path?: string): string | undefined {
  if (!path) return undefined;
  const parts = pathWithoutQuery(path).split('/');
  const modelIdx = parts.indexOf('models');
  if (modelIdx < 0 || modelIdx + 1 >= parts.length) return undefined;
  const raw = parts[modelIdx + 1] || undefined;
  return raw?.split(':')[0];
}

function bedrockModelIdFromPath(path?: string): string | undefined {
  if (!path) return undefined;
  const parts = pathWithoutQuery(path).split('/');
  const modelIdx = parts.indexOf('model');
  if (modelIdx < 0 || modelIdx + 2 >= parts.length) return undefined;
  const operation = parts[modelIdx + 2].toLowerCase();
  if (operation !== 'converse' && operation !== 'converse-stream') return undefined;
  return parts[modelIdx + 1] || undefined;
}

function hasRequiredPresence(protocol: ProtocolFamily, kind: 'request' | 'response', view: unknown): boolean {
  if (kind === 'response' && isErrorResponseView(protocol, view)) return true;
  const groups = requiredPresence(protocol, kind);
  return groups.every((alternatives) => alternatives.some((path) => hasPresentPath(view, path)));
}

function isErrorResponseView(protocol: ProtocolFamily, view: unknown): boolean {
  if (protocol === 'alibaba.dashscope.generation') return hasPresentPath(view, 'code') && hasPresentPath(view, 'message');
  return hasPresentPath(view, 'error');
}

function requiredPresence(protocol: ProtocolFamily, kind: 'request' | 'response'): string[][] {
  if (protocol === 'openai.chat_completions') return kind === 'request' ? [['model'], ['messages']] : [['choices']];
  if (protocol === 'openai.responses') return kind === 'request' ? [['model'], ['input']] : [['output', 'status']];
  if (protocol === 'anthropic.messages') return kind === 'request' ? [['model'], ['messages']] : [['content']];
  if (protocol === 'google.gemini.generate_content') return kind === 'request' ? [['model'], ['contents']] : [['candidates', 'promptFeedback']];
  if (protocol === 'alibaba.dashscope.generation') return kind === 'request' ? [['model'], ['input']] : [['output']];
  if (protocol === 'aws.bedrock.converse') return kind === 'request' ? [['modelId'], ['messages']] : [['output']];
  if (protocol === 'cohere.chat') return kind === 'request' ? [['model'], ['messages', 'message']] : [['message', 'text']];
  return [];
}

function hasPresentPath(value: unknown, path: string): boolean {
  let current = value;
  for (const part of path.split('.')) {
    if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, part)) return false;
    current = current[part];
  }
  if (current === null || current === undefined) return false;
  if (Array.isArray(current)) return current.length > 0;
  if (typeof current === 'string') return current.length > 0;
  return true;
}

function validateFieldClaimsEnvelope(protocol: ProtocolFamily, claims: Record<string, unknown>, proof?: FieldProofContext): void {
  const expectedSchema = `${protocol}.v1`;
  if (stringField(claims, 'request_schema_version') !== expectedSchema) {
    throw new Error(`field_claims.request_schema_version must be ${expectedSchema}`);
  }
  if (stringField(claims, 'response_schema_version') !== expectedSchema) {
    throw new Error(`field_claims.response_schema_version must be ${expectedSchema}`);
  }
  if (stringField(claims, 'field_policy_id') !== fieldPolicyId(protocol)) {
    throw new Error(`field_claims.field_policy_id must be ${fieldPolicyId(protocol)}`);
  }
  if (stringField(claims, 'assurance_level') !== 'strong') {
    throw new Error('field_claims.assurance_level must be strong');
  }
  if (booleanField(claims, 'cross_protocol') !== false) {
    throw new Error('field_claims.cross_protocol must be false');
  }
  if (booleanField(claims, 'semantic_equivalence_not_proven') !== false) {
    throw new Error('field_claims.semantic_equivalence_not_proven must be false');
  }
  if (stringField(claims, 'body_hash_policy') !== 'advisory') {
    throw new Error('field_claims.body_hash_policy must be advisory');
  }
  if (stringField(claims, 'request_body_sha256_severity') !== 'advisory') {
    throw new Error('field_claims.request_body_sha256_severity must be advisory');
  }
  if (stringField(claims, 'response_body_sha256_severity') !== 'advisory') {
    throw new Error('field_claims.response_body_sha256_severity must be advisory');
  }
  if (proof) {
    if (stringField(claims, 'nonce') !== proof.nonce) throw new Error('field_claims.nonce must match proof.nonce');
    if (stringField(claims, 'upstream_host') !== proof.upstream_host.toLowerCase()) {
      throw new Error('field_claims.upstream_host must match proof.upstream_host');
    }
    if (stringField(claims, 'upstream_path') !== pathWithoutQuery(proof.upstream_path)) {
      throw new Error('field_claims.upstream_path must match proof.upstream_path');
    }
    if (stringField(claims, 'http_method') !== proof.http_method.toUpperCase()) {
      throw new Error('field_claims.http_method must match proof.http_method');
    }
    if (numberField(claims, 'http_status') !== proof.http_status) {
      throw new Error('field_claims.http_status must match proof.http_status');
    }
  }
}

function parseJsonBody(body: Buffer): unknown {
  const text = body.toString('utf8').trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw_sha256: sha256Hex(body), parse_error: 'invalid_json' };
  }
}

function parseSseData(body: Buffer): unknown[] {
  const out: unknown[] = [];
  let dataLines: string[] = [];
  const flush = () => {
    if (dataLines.length === 0) return;
    const data = dataLines.join('\n');
    dataLines = [];
    if (!data.trim() || data.trim() === '[DONE]') return;
    try {
      out.push(JSON.parse(data));
    } catch {
      out.push({ raw_data_sha256: sha256Hex(Buffer.from(data, 'utf8')), parse_error: 'invalid_sse_json' });
    }
  };
  for (const rawLine of body.toString('utf8').split('\n')) {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (line === '') {
      flush();
      continue;
    }
    if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
  }
  flush();
  return out;
}

function looksLikeSse(body: Buffer): boolean {
  const prefix = body.subarray(0, Math.min(body.byteLength, 512)).toString('utf8');
  return /^event:|^data:/m.test(prefix);
}

function pick(value: unknown, keys: string[]): unknown {
  if (Array.isArray(value)) return value.map((item) => pick(item, keys));
  if (!isRecord(value)) return value;
  const out: Record<string, unknown> = {};
  for (const key of keys) if (Object.prototype.hasOwnProperty.call(value, key)) out[key] = value[key];
  return out;
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isRecord(value)) return value;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) out[key] = sortJson(value[key]);
  return out;
}

function inferProtocolFromBody(body: Buffer): ProtocolFamily {
  const parsed = parseJsonBody(body);
  if (!isRecord(parsed)) return 'unknown';
  if (Array.isArray(parsed.messages) && typeof parsed.model === 'string' && parsed.max_tokens !== undefined) return 'anthropic.messages';
  if (Array.isArray(parsed.messages) && typeof parsed.model === 'string') return 'openai.chat_completions';
  if (parsed.input !== undefined && typeof parsed.model === 'string') return 'openai.responses';
  if (parsed.contents !== undefined) return 'google.gemini.generate_content';
  return 'unknown';
}

function protocolFamilyFromValue(value: unknown): ProtocolFamily {
  const s = typeof value === 'string' ? value : 'unknown';
  return [
    'openai.chat_completions',
    'openai.responses',
    'anthropic.messages',
    'google.gemini.generate_content',
    'alibaba.dashscope.generation',
    'aws.bedrock.converse',
    'cohere.chat',
  ].includes(s) ? s as ProtocolFamily : 'unknown';
}

function schemaVersion(protocol: ProtocolFamily): string {
  return `${protocol}.v1`;
}

function fieldPolicyId(protocol: ProtocolFamily): string {
  if (protocol === 'unknown') return `${protocol}.${FIELD_POLICY_REGISTRY.policy}@unknown`;
  const version = FIELD_POLICY_REGISTRY.protocol_versions[protocol];
  if (typeof version !== 'string' || version.length === 0) {
    throw new Error(`missing field policy version for supported protocol: ${protocol}`);
  }
  return `${protocol}.${FIELD_POLICY_REGISTRY.policy}@${version}`;
}

function pathWithoutQuery(path: string): string {
  const i = path.indexOf('?');
  return i >= 0 ? path.slice(0, i) : path;
}

function sha256Hex(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

function loadFieldPolicyRegistry(): FieldPolicyRegistry {
  const raw = readFileSync(new URL('../enclave/field-policy-registry.json', import.meta.url), 'utf8');
  const parsed = JSON.parse(raw) as Partial<FieldPolicyRegistry>;
  if (typeof parsed.policy !== 'string' || parsed.policy.length === 0) {
    throw new Error('field-policy-registry.policy must be a non-empty string');
  }
  if (typeof parsed.default !== 'string') {
    throw new Error('field-policy-registry.default must be a string');
  }
  if (!parsed.protocol_versions || typeof parsed.protocol_versions !== 'object') {
    throw new Error('field-policy-registry.protocol_versions must be an object');
  }
  for (const protocol of SUPPORTED_PROTOCOLS) {
    const version = (parsed.protocol_versions as Record<string, unknown>)[protocol];
    if (typeof version !== 'string' || version.length === 0) {
      throw new Error(`field-policy-registry.protocol_versions missing supported protocol: ${protocol}`);
    }
  }
  return {
    policy: parsed.policy,
    default: parsed.default,
    protocol_versions: parsed.protocol_versions as Record<Exclude<ProtocolFamily, 'unknown'>, string>,
  };
}

function stringField(value: Record<string, unknown>, field: string): string | undefined {
  return typeof value[field] === 'string' ? value[field] : undefined;
}

function numberField(value: Record<string, unknown>, field: string): number | undefined {
  return typeof value[field] === 'number' ? value[field] : undefined;
}

function booleanField(value: Record<string, unknown>, field: string): boolean | undefined {
  return typeof value[field] === 'boolean' ? value[field] : undefined;
}

function numberOrDefault(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
