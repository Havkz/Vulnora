import type { EvidenceRecord } from '../orchestrator/tool-orchestrator.js';
import type { ToolResult } from '../types/index.js';

export interface WebsiteInput { url: string; param: string }
export interface WebsiteSurface {
  reviewedUrls: string[];
  inputTargets: WebsiteInput[];
  authentication: { url: string; status: number }[];
  postForms: number;
}

/** Inventory observed public routes; never invent parameters or submit login/write forms. */
export async function reviewWebsiteSurface(url: string, records: EvidenceRecord[], read: (url: string) => Promise<{ status: number; body: string }>): Promise<ToolResult> {
  const root = new URL(url);
  const pages = new Map<string, { status: number; body: string }>();
  const candidates = new Set([root.href]);
  const inputs = new Map<string, WebsiteInput>();
  const authentication = new Map<string, { url: string; status: number }>();
  let postForms = 0;
  const resolve = (value: string, base = root.href): URL | undefined => {
    try {
      const candidate = new URL(value.replace(/&amp;/g, '&'), base); candidate.hash = '';
      return candidate.origin === root.origin && !candidate.username && !candidate.password ? candidate : undefined;
    } catch { return undefined; }
  };
  const addInputs = (candidate: URL) => {
    for (const param of candidate.searchParams.keys()) {
      if (/token|password|secret|csrf|logout|delete/i.test(param + candidate.pathname)) continue;
      inputs.set(`${candidate.href}:${param}`, { url: candidate.href, param });
    }
  };
  for (const record of records) {
    const address = resolve(record.target);
    if (!address || record.executionStatus !== 'executed' || record.status !== 'success') continue;
    addInputs(address);
    const body = record.result?.metadata?.responseBody ?? record.parsedOutput?.responseBody;
    if (typeof body === 'string' && record.toolCategory === 'http_fetch') pages.set(address.href, { status: record.responseStatus || 200, body });
    if (record.responseStatus === 401 || record.responseStatus === 403) authentication.set(address.href, { url: address.href, status: record.responseStatus });
    if (/^(?:api_endpoint_discovery|dir_bruteforce|katana_tool)$/.test(record.toolName)) {
      for (const match of record.rawOutput.matchAll(/^\s*(\/\S*)\s*(?:->|→)\s*(2\d\d|401|403)\b/gm)) {
        const found = resolve(match[1]); if (!found) continue;
        const status = Number(match[2]);
        if (status === 401 || status === 403) authentication.set(found.href, { url: found.href, status });
        else candidates.add(found.href);
      }
    }
  }
  for (const address of candidates) {
    if (!pages.has(address)) {
      const page = await read(address); pages.set(address, page);
    }
  }
  for (const [address, page] of pages) {
    if (page.status === 401 || page.status === 403) authentication.set(address, { url: address, status: page.status });
    for (const link of page.body.matchAll(/\bhref\s*=\s*["']([^"']+)["']/gi)) {
      const found = resolve(link[1], address); if (found) addInputs(found);
    }
    // Splitting completed forms avoids quadratic matching on hostile, unterminated markup.
    for (const fragment of page.body.split(/<\/form\s*>/gi).slice(0, -1)) {
      const start = fragment.search(/<form\b/i); const end = fragment.indexOf('>', start);
      if (start < 0 || end < 0) continue;
      const attributes = fragment.slice(start + 5, end);
      const method = attributes.match(/\bmethod\s*=\s*["']?([a-z]+)/i)?.[1] || 'get';
      const action = attributes.match(/\baction\s*=\s*["']([^"']*)["']/i)?.[1] || address;
      const found = resolve(action, address); if (!found) continue;
      if (/password|\/(?:auth|login|signin)(?:\/|$)/i.test(fragment + found.pathname)) authentication.set(address, { url: address, status: page.status });
      if (method.toLowerCase() !== 'get') { postForms++; continue; }
      for (const part of fragment.slice(end + 1).split('>')) {
        const field = part.slice(part.lastIndexOf('<'));
        if (!/^<(?:input|select|textarea)\b/i.test(field) || /\btype\s*=\s*["']?(?:password|hidden|submit)/i.test(field)) continue;
        const name = field.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1];
        if (name) { const input = new URL(found); input.searchParams.set(name, ''); addInputs(input); }
      }
    }
    try {
      const document = JSON.parse(page.body) as { paths?: Record<string, { get?: { parameters?: { name?: string; in?: string }[] } }> };
      for (const [path, endpoint] of Object.entries(document.paths || {})) {
        if (path.includes('{')) continue;
        const found = resolve(path, address); if (!found) continue;
        for (const parameter of endpoint.get?.parameters || []) {
          if (parameter.in === 'query' && typeof parameter.name === 'string') {
            const input = new URL(found); input.searchParams.set(parameter.name, ''); addInputs(input);
          }
        }
      }
    } catch { /* HTML and non-OpenAPI responses have no machine-readable parameter schema. */ }
  }
  if ([...pages.values()].some(page => page.status >= 500)) return { success: false, error: 'Website surface review encountered a server error; inspection is incomplete.' };
  const surface: WebsiteSurface = { reviewedUrls: [...pages.keys()], inputTargets: [...inputs.values()], authentication: [...authentication.values()], postForms };
  return { success: true, output: `Public website surface reviewed: ${pages.size} response(s), ${inputs.size} GET input(s), ${authentication.size} authentication boundary/entry point(s).\n`
    + [...inputs.values()].map(input => `${input.url} · parameter ${input.param}`).join('\n')
    + '\nAnonymous authentication boundaries only; authenticated flows require test credentials. POST forms were not submitted.', metadata: { websiteSurface: surface } };
}
