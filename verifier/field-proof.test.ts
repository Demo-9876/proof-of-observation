import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { buildFieldClaims, extractFieldView, hashFieldView, verifyFieldClaims } from './field-proof.ts';

const requestBody = Buffer.from(JSON.stringify({
  model: 'gpt-test',
  messages: [{ role: 'user', content: 'hi' }],
  stream: true,
}), 'utf8');

describe('field-level proof extraction', () => {
  it('does not build strong claims when required request fields are missing', () => {
    const claims = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'api.example.com',
      upstreamPath: '/v1/chat/completions',
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: Buffer.from('{"model":"gpt-test"}', 'utf8'),
      responseBody: Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8'),
    });

    expect(claims).toBeUndefined();
  });

  it('normalizes OpenAI chat SSE chunks into the same semantic response hash', () => {
    const splitChunks = Buffer.from([
      'data: {"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"你"},"finish_reason":null}]}',
      '',
      'data: {"model":"gpt-test","choices":[{"index":0,"delta":{"content":"好"},"finish_reason":null}]}',
      '',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
      '',
      'data: {"choices":[],"usage":{"total_tokens":3}}',
      '',
      'data: [DONE]',
      '',
    ].join('\n'), 'utf8');
    const mergedChunk = Buffer.from([
      'data: {"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"你好"},"finish_reason":null}]}',
      '',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"total_tokens":3}}',
      '',
      'data: [DONE]',
      '',
    ].join('\n'), 'utf8');

    expect(hashFieldView('openai.chat_completions', 'response', splitChunks))
      .toBe(hashFieldView('openai.chat_completions', 'response', mergedChunk));
  });

  it('extracts Bedrock Converse modelId from the upstream path', () => {
    const request = Buffer.from(JSON.stringify({
      messages: [{ role: 'user', content: [{ text: 'hi' }] }],
      inferenceConfig: { maxTokens: 64 },
    }), 'utf8');
    const response = Buffer.from(JSON.stringify({
      output: { message: { role: 'assistant', content: [{ text: 'ok' }] } },
      stopReason: 'end_turn',
      usage: { inputTokens: 1, outputTokens: 1 },
    }), 'utf8');
    const path = '/model/anthropic.claude-3-sonnet-20240229-v1%3A0/converse';

    const field = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'bedrock-runtime.us-east-1.amazonaws.com',
      upstreamPath: path,
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: request,
      responseBody: response,
    });

    expect(field).toBeTruthy();
    expect(field!.requestView).toMatchObject({
      modelId: 'anthropic.claude-3-sonnet-20240229-v1%3A0',
      messages: [{ role: 'user' }],
    });
    const result = verifyFieldClaims(field!.claims, request, response, {
      nonce: field!.claims.nonce,
      upstream_host: field!.claims.upstream_host,
      upstream_path: field!.claims.upstream_path,
      http_method: field!.claims.http_method,
      http_status: field!.claims.http_status,
      resp_content_type: 'application/json',
    });
    expect(result.requestOk).toBe(true);
    expect(result.responseOk).toBe(true);
  });

  it('normalizes Anthropic Messages SSE chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'event: message_start',
      'data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-test","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":3}}}',
      '',
      'event: content_block_start',
      'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}',
      '',
      'event: content_block_delta',
      'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你"}}',
      '',
      'event: content_block_delta',
      'data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"好"}}',
      '',
      'event: content_block_stop',
      'data: {"type":"content_block_stop","index":0}',
      '',
      'event: message_delta',
      'data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}',
      '',
      'event: message_stop',
      'data: {"type":"message_stop"}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      id: 'msg_1',
      type: 'message',
      role: 'assistant',
      model: 'claude-test',
      content: [{ type: 'text', text: '你好' }],
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: { input_tokens: 3, output_tokens: 2 },
    }), 'utf8');

    expect(hashFieldView('anthropic.messages', 'response', stream))
      .toBe(hashFieldView('anthropic.messages', 'response', merged));
  });

  it('normalizes OpenAI Responses SSE chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'data: {"type":"response.created","response":{"id":"resp_1","status":"in_progress","output":[]}}',
      '',
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}',
      '',
      'data: {"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}}',
      '',
      'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"你"}',
      '',
      'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"好"}',
      '',
      'data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"你好"}]}],"usage":{"total_tokens":3}}}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      id: 'resp_1',
      status: 'completed',
      output: [{ id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '你好' }] }],
      usage: { total_tokens: 3 },
    }), 'utf8');

    expect(hashFieldView('openai.responses', 'response', stream))
      .toBe(hashFieldView('openai.responses', 'response', merged));
  });

  it('treats OpenAI Responses done events as final values instead of deltas', () => {
    const stream = Buffer.from([
      'data: {"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}',
      '',
      'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"你"}',
      '',
      'data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"好"}',
      '',
      'data: {"type":"response.output_text.done","output_index":0,"content_index":0,"text":"你好"}',
      '',
      'data: {"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"total_tokens":3}}}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      id: 'resp_1',
      status: 'completed',
      output: [{ id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '你好' }] }],
      usage: { total_tokens: 3 },
    }), 'utf8');

    expect(hashFieldView('openai.responses', 'response', stream))
      .toBe(hashFieldView('openai.responses', 'response', merged));
  });

  it('ignores instructions when hashing OpenAI Responses request fields', () => {
    const withInstructions = Buffer.from(JSON.stringify({
      model: 'qwen3.7-plus',
      input: [{ role: 'user', content: 'hi' }],
      instructions: 'answer carefully',
      temperature: 0.7,
      stream: false,
    }), 'utf8');
    const withoutInstructions = Buffer.from(JSON.stringify({
      model: 'qwen3.7-plus',
      input: [{ role: 'user', content: 'hi' }],
      temperature: 0.7,
      stream: false,
    }), 'utf8');

    expect(hashFieldView('openai.responses', 'request', withInstructions))
      .toBe(hashFieldView('openai.responses', 'request', withoutInstructions));
  });

  it('ignores relay default parameters when hashing core request fields', () => {
    const cases = [
      {
        protocol: 'openai.chat_completions',
        core: { model: 'gpt-test', messages: [{ role: 'user', content: 'hi' }] },
        withDefaults: { model: 'gpt-test', messages: [{ role: 'user', content: 'hi' }], temperature: 0.2, top_p: 0.9, stream: false, metadata: { relay: 'default' } },
      },
      {
        protocol: 'openai.responses',
        core: { model: 'gpt-test', input: [{ role: 'user', content: 'hi' }] },
        withDefaults: { model: 'gpt-test', input: [{ role: 'user', content: 'hi' }], instructions: 'relay-added compatibility text', temperature: 0.7, stream: false, store: true },
      },
      {
        protocol: 'anthropic.messages',
        core: { model: 'claude-test', system: 'be concise', messages: [{ role: 'user', content: 'hi' }] },
        withDefaults: { model: 'claude-test', system: 'be concise', messages: [{ role: 'user', content: 'hi' }], max_tokens: 128, temperature: 0.5, tools: [], stream: false },
      },
      {
        protocol: 'google.gemini.generate_content',
        core: { model: 'gemini-test', contents: [{ role: 'user', parts: [{ text: 'hi' }] }], systemInstruction: { parts: [{ text: 'be concise' }] } },
        withDefaults: { model: 'gemini-test', contents: [{ role: 'user', parts: [{ text: 'hi' }] }], systemInstruction: { parts: [{ text: 'be concise' }] }, generationConfig: { temperature: 0.7 }, tools: [], safetySettings: [] },
      },
      {
        protocol: 'alibaba.dashscope.generation',
        core: { model: 'qwen-test', input: { messages: [{ role: 'user', content: 'hi' }] }, system: 'be concise', messages: [{ role: 'user', content: 'hi' }] },
        withDefaults: { model: 'qwen-test', input: { messages: [{ role: 'user', content: 'hi' }] }, system: 'be concise', messages: [{ role: 'user', content: 'hi' }], parameters: { temperature: 0.7, stream: false }, response_format: { type: 'text' }, thinking_budget: 0 },
      },
      {
        protocol: 'aws.bedrock.converse',
        core: { modelId: 'anthropic.claude-test', system: [{ text: 'be concise' }], messages: [{ role: 'user', content: [{ text: 'hi' }] }] },
        withDefaults: { modelId: 'anthropic.claude-test', system: [{ text: 'be concise' }], messages: [{ role: 'user', content: [{ text: 'hi' }] }], inferenceConfig: { temperature: 0.7, maxTokens: 128 }, toolConfig: { tools: [] }, additionalModelRequestFields: {} },
      },
      {
        protocol: 'cohere.chat',
        core: { model: 'command-test', messages: [{ role: 'user', content: 'hi' }], message: 'hi' },
        withDefaults: { model: 'command-test', messages: [{ role: 'user', content: 'hi' }], message: 'hi', temperature: 0.7, stream: false, tools: [], safety_mode: 'CONTEXTUAL' },
      },
    ] as const;

    for (const item of cases) {
      const core = Buffer.from(JSON.stringify(item.core), 'utf8');
      const withDefaults = Buffer.from(JSON.stringify(item.withDefaults), 'utf8');
      expect(hashFieldView(item.protocol, 'request', withDefaults))
        .toBe(hashFieldView(item.protocol, 'request', core));
    }
  });

  it('ignores relay response ids when hashing core response fields', () => {
    const cases = [
      {
        protocol: 'openai.responses',
        withId: { id: 'resp_relay', status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'ok' }] }], usage: { total_tokens: 3 } },
        withoutId: { status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: 'ok' }] }], usage: { total_tokens: 3 } },
      },
      {
        protocol: 'anthropic.messages',
        withId: { id: 'msg_relay', type: 'message', role: 'assistant', model: 'claude-test', content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', usage: { output_tokens: 1 } },
        withoutId: { type: 'message', role: 'assistant', model: 'claude-test', content: [{ type: 'text', text: 'ok' }], stop_reason: 'end_turn', usage: { output_tokens: 1 } },
      },
      {
        protocol: 'cohere.chat',
        withId: { id: 'chat_relay', message: { role: 'assistant', content: [{ type: 'text', text: 'ok' }] }, finish_reason: 'COMPLETE', usage: { total_tokens: 3 } },
        withoutId: { message: { role: 'assistant', content: [{ type: 'text', text: 'ok' }] }, finish_reason: 'COMPLETE', usage: { total_tokens: 3 } },
      },
    ] as const;

    for (const item of cases) {
      const withId = Buffer.from(JSON.stringify(item.withId), 'utf8');
      const withoutId = Buffer.from(JSON.stringify(item.withoutId), 'utf8');
      expect(hashFieldView(item.protocol, 'response', withId))
        .toBe(hashFieldView(item.protocol, 'response', withoutId));
    }
  });

  it('extracts Gemini request model from the upstream path for core field proof', () => {
    const request = Buffer.from(JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: 'hi' }] }],
      generationConfig: { temperature: 0.7 },
    }), 'utf8');

    expect(extractFieldView(
      'google.gemini.generate_content',
      'request',
      request,
      '/v1beta/models/gemini-2.5-pro:generateContent',
    )).toMatchObject({
      model: 'gemini-2.5-pro',
      contents: [{ role: 'user' }],
    });
  });

  it('uses protocol-specific field policy versions', () => {
    const openaiChat = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'api.example.com',
      upstreamPath: '/v1/chat/completions',
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: Buffer.from(JSON.stringify({
        model: 'gpt-test',
        messages: [{ role: 'user', content: 'hi' }],
      }), 'utf8'),
      responseBody: Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8'),
    });
    const responses = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'api.example.com',
      upstreamPath: '/v1/responses',
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody: Buffer.from(JSON.stringify({
        model: 'gpt-test',
        input: [{ role: 'user', content: 'hi' }],
      }), 'utf8'),
      responseBody: Buffer.from(JSON.stringify({
        status: 'completed',
        output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'ok' }] }],
      }), 'utf8'),
    });

    expect(openaiChat?.claims.field_policy_id).toBe('openai.chat_completions.core@2026-07-29');
    expect(responses?.claims.field_policy_id).toBe('openai.responses.core@2026-07-29');
  });

  it('requires explicit field policy versions for every supported protocol', () => {
    const registry = JSON.parse(
      readFileSync(new URL('../enclave/field-policy-registry.json', import.meta.url), 'utf8'),
    ) as { protocol_versions?: Record<string, string> };

    expect(registry.protocol_versions).toMatchObject({
      'openai.chat_completions': expect.any(String),
      'openai.responses': expect.any(String),
      'anthropic.messages': expect.any(String),
      'google.gemini.generate_content': expect.any(String),
      'alibaba.dashscope.generation': expect.any(String),
      'aws.bedrock.converse': expect.any(String),
      'cohere.chat': expect.any(String),
    });
  });

  it('parses multi-line SSE data as one event', () => {
    const stream = Buffer.from([
      'data: {"model":"gpt-test","choices":[{"index":0,',
      'data: "delta":{"role":"assistant","content":"你好"},"finish_reason":null}]}',
      '',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from([
      'data: {"model":"gpt-test","choices":[{"index":0,"delta":{"role":"assistant","content":"你好"},"finish_reason":null}]}',
      '',
      'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}',
      '',
    ].join('\n'), 'utf8');

    expect(hashFieldView('openai.chat_completions', 'response', stream))
      .toBe(hashFieldView('openai.chat_completions', 'response', merged));
  });

  it('normalizes Gemini generateContent SSE chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'data: {"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"你"}]}}]}',
      '',
      'data: {"candidates":[{"index":0,"content":{"parts":[{"text":"好"}]},"finishReason":"STOP"}],"usageMetadata":{"totalTokenCount":3}}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      candidates: [{ index: 0, content: { role: 'model', parts: [{ text: '你好' }] }, finishReason: 'STOP' }],
      usageMetadata: { totalTokenCount: 3 },
    }), 'utf8');

    expect(hashFieldView('google.gemini.generate_content', 'response', stream))
      .toBe(hashFieldView('google.gemini.generate_content', 'response', merged));
  });

  it('normalizes DashScope generation SSE chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'data: {"output":{"choices":[{"message":{"role":"assistant","content":"你"},"finish_reason":null}]}}',
      '',
      'data: {"output":{"choices":[{"message":{"content":"好"},"finish_reason":"stop"}]},"usage":{"total_tokens":3},"request_id":"req_1"}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      output: { choices: [{ index: 0, message: { role: 'assistant', content: '你好' }, finish_reason: 'stop' }] },
      usage: { total_tokens: 3 },
      request_id: 'req_1',
    }), 'utf8');

    expect(hashFieldView('alibaba.dashscope.generation', 'response', stream))
      .toBe(hashFieldView('alibaba.dashscope.generation', 'response', merged));
  });

  it('normalizes Bedrock ConverseStream chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'data: {"messageStart":{"role":"assistant"}}',
      '',
      'data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"你"}}}',
      '',
      'data: {"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"好"}}}',
      '',
      'data: {"messageStop":{"stopReason":"end_turn"}}',
      '',
      'data: {"metadata":{"usage":{"inputTokens":1,"outputTokens":2},"metrics":{"latencyMs":42}}}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      output: { message: { role: 'assistant', content: [{ type: 'text', text: '你好' }] } },
      stopReason: 'end_turn',
      usage: { inputTokens: 1, outputTokens: 2 },
      metrics: { latencyMs: 42 },
    }), 'utf8');

    expect(hashFieldView('aws.bedrock.converse', 'response', stream))
      .toBe(hashFieldView('aws.bedrock.converse', 'response', merged));
  });

  it('normalizes Cohere chat SSE chunks into the same semantic response hash', () => {
    const stream = Buffer.from([
      'data: {"type":"message-start","delta":{"message":{"role":"assistant"}}}',
      '',
      'data: {"type":"content-start","delta":{"message":{"content":{"type":"text","text":""}}}}',
      '',
      'data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"你"}}}}',
      '',
      'data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"好"}}}}',
      '',
      'data: {"type":"message-end","delta":{"finish_reason":"COMPLETE","usage":{"total_tokens":3}}}',
      '',
    ].join('\n'), 'utf8');
    const merged = Buffer.from(JSON.stringify({
      message: { role: 'assistant', content: [{ type: 'text', text: '你好' }], finish_reason: 'COMPLETE' },
      finish_reason: 'COMPLETE',
      usage: { total_tokens: 3 },
    }), 'utf8');

    expect(hashFieldView('cohere.chat', 'response', stream))
      .toBe(hashFieldView('cohere.chat', 'response', merged));
  });

  it('rejects local responses that do not satisfy required_presence', () => {
    const field = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'api.example.com',
      upstreamPath: '/v1/chat/completions',
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody,
      responseBody: Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8'),
    });

    expect(field).toBeTruthy();
    expect(() => verifyFieldClaims(field!.claims, requestBody, Buffer.from('{"model":"gpt-test"}', 'utf8')))
      .toThrow(/required_presence/);
  });

  it('rejects unsupported field policy versions', () => {
    const field = buildFieldClaims({
      nonceB64: Buffer.from('nonce').toString('base64'),
      upstreamHost: 'api.example.com',
      upstreamPath: '/v1/chat/completions',
      httpMethod: 'POST',
      httpStatus: 200,
      requestBody,
      responseBody: Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8'),
    });

    expect(field).toBeTruthy();
    field!.claims.field_policy_id = 'openai.chat_completions.core@2099-01-01';
    expect(() => verifyFieldClaims(field!.claims, requestBody, Buffer.from('{"choices":[{"message":{"content":"ok"}}]}', 'utf8')))
      .toThrow(/field_policy_id/);
  });
});
