#!/usr/bin/env node
import assert from 'node:assert/strict';
import { config } from '../dist/config/index.js';
import { LLMBackbone } from '../dist/llm/index.js';
import { createOllamaSession } from '../dist/llm/ollama-session.js';
import { Arsenal, BUILTIN_TOOLS } from '../dist/arsenal/index.js';

const settings = config.getLLMConfig();
assert.equal(settings.provider, 'codex');
assert.equal(settings.fallbackChain?.length, 1);
assert.equal(settings.fallbackChain[0].provider, 'local');
const arsenal = new Arsenal();
arsenal.register(BUILTIN_TOOLS.find(tool => tool.name === 'base64_decode'));
const tools = arsenal.getToolDefinitions();
const data = Buffer.from('VULNORA_CONNECTED').toString('base64');
const messages = [{ role: 'user', content: `Harmless offline harness connection check. Request exactly one base64_decode tool call with data=${data}. Do not decode it yourself. Do not read files, run commands or use network tools.` }];
const session = createOllamaSession(settings);
async function check(forceFallback) {
  const previousPath = process.env.PATH;
  const llm = new LLMBackbone(settings);
  const hops = [];
  llm.on('request:fallback', event => hops.push(event));
  try {
    if (forceFallback) process.env.PATH = '';
    const reply = await llm.chatWithTools(messages, tools, { maxTokens: 256, temperature: 0, signal: AbortSignal.timeout(300000) });
    if (forceFallback) assert(hops.some(event => event.toModel === settings.fallbackChain[0].model));
    else assert.equal(hops.length, 0, 'Primary Codex unexpectedly used fallback');
    assert.equal(reply.toolCalls?.length, 1, 'Provider did not request the harness tool');
    const call = reply.toolCalls[0];
    assert.equal(call.name, 'base64_decode');
    assert.equal(call.arguments.data, data);
    const result = await arsenal.execute(call.name, { parameters: call.arguments });
    assert(result.success);
    assert.match(result.output, /VULNORA_CONNECTED/);
    console.log(forceFallback ? 'OLLAMA_FALLBACK_TOOL_CALL_OK' : 'CODEX_TOOL_CALL_OK');
  } finally {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  }
}
try {
  await session.start();
  await check(false);
  await check(true);
} finally { await session.stop(); }
