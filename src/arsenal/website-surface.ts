import { parse, type DefaultTreeAdapterMap } from 'parse5';
import type { EvidenceRecord } from '../orchestrator/tool-orchestrator.js';
import type { ToolResult } from '../types/index.js';

export interface WebsiteInput { url: string; param: string }
export interface WebsiteSurface {
  reviewedUrls: string[];
  inputTargets: WebsiteInput[];
  authentication: { url: string; status: number }[];
  postForms: number;
  forms?: { url: string; action: string; method: string; fields: { name: string; type: string }[]; hasCsrf: boolean }[];
  links?: string[];
  scripts?: string[];
  apiHints?: string[];
  complete?: boolean;
  limitations?: string[];
}

type Page = { status: number; body: string; url?: string; contentType?: string };
const MAX_PAGES = 32;
const MAX_BODY_CHARS = 256 * 1024;
const MAX_INPUTS = 128;
const sensitive = /token|password|secret|csrf|logout|signout|delete|remove|unsubscribe/i;

/** Bounded, same-origin public discovery. Scripts are read as text, never evaluated. */
export async function reviewWebsiteSurface(url: string, records: EvidenceRecord[], read: (url: string) => Promise<Page>, signal?: AbortSignal): Promise<ToolResult> {
  const root = new URL(url);
  const pages = new Map<string, Page>();
  const candidates = new Set([root.href]);
  const inputs = new Map<string, WebsiteInput>();
  const authentication = new Map<string, { url: string; status: number }>();
  const links = new Set<string>(); const scripts = new Set<string>(); const apiHints = new Set<string>();
  const forms: NonNullable<WebsiteSurface['forms']> = [];
  const limitations = new Set<string>();
  const resolve = (value: string, base = root.href): URL | undefined => {
    try {
      const candidate = new URL(value, base); candidate.hash = '';
      return candidate.origin === root.origin && !candidate.username && !candidate.password ? candidate : undefined;
    } catch { return undefined; }
  };
  const addInputs = (candidate: URL) => {
    if (sensitive.test(candidate.pathname) || [...candidate.searchParams.keys()].some(key => sensitive.test(key))) return;
    for (const param of candidate.searchParams.keys()) {
      if (sensitive.test(param + candidate.pathname)) continue;
      if (inputs.size >= MAX_INPUTS) { limitations.add('Input inventory reached its 128-parameter limit.'); break; }
      inputs.set(`${candidate.href}:${param}`, { url: candidate.href, param });
    }
  };
  const enqueue = (candidate: URL) => {
    if (sensitive.test(candidate.pathname + candidate.search)) return;
    if (candidates.size >= MAX_PAGES && !candidates.has(candidate.href)) { limitations.add('Public discovery reached its 32-response limit.'); return; }
    candidates.add(candidate.href);
  };
  const scriptHints = (body: string, base: string) => {
    // Literal URL hints only; method and reachability remain unknown until separately observed.
    for (const match of body.matchAll(/(?:fetch\s*\(|axios\.(?:get|post|put|delete|patch)\s*\()\s*["']([^"'\r\n]{1,2048})["']/g)) {
      const found = resolve(match[1], base);
      if (found && apiHints.size < MAX_INPUTS) apiHints.add(found.href);
    }
  };
  for (const record of records) {
    const address = resolve(record.target);
    if (!address || record.executionStatus !== 'executed' || record.status !== 'success') continue;
    if (record.toolCategory === 'http_fetch') {
      addInputs(address);
      const body = record.result?.metadata?.responseBody ?? record.parsedOutput?.responseBody;
      if (typeof body === 'string' && pages.size < MAX_PAGES) {
        pages.set(address.href, { status: record.responseStatus || 200, body, contentType: record.responseHeaders?.['content-type'] });
        enqueue(address);
      }
    }
    if (record.responseStatus === 401 || record.responseStatus === 403) authentication.set(address.href, { url: address.href, status: record.responseStatus });
    if (/^(?:api_endpoint_discovery|dir_bruteforce|katana_tool)$/.test(record.toolName)) {
      for (const match of record.rawOutput.matchAll(/^\s*(\/\S*)\s*(?:->|→)\s*(2\d\d|401|403)\b/gm)) {
        const found = resolve(match[1]); if (!found) continue;
        const status = Number(match[2]);
        if (status === 401 || status === 403) authentication.set(found.href, { url: found.href, status });
        else enqueue(found);
      }
    }
  }
  const reviewed: string[] = []; let usableResponses = 0;
  for (const requested of candidates) {
    signal?.throwIfAborted();
    let page: Page;
    try { page = pages.get(requested) || await read(requested); }
    catch { signal?.throwIfAborted(); limitations.add(`Response unavailable: ${requested}`); continue; }
    const address = resolve(page.url || requested);
    if (!address) { limitations.add(`Redirect left the reviewed origin: ${requested}`); continue; }
    reviewed.push(address.href);
    if (page.status >= 500 || page.status === 429) { limitations.add(`HTTP ${page.status}: ${address.href}`); continue; }
    if (page.status === 401 || page.status === 403) { usableResponses++; authentication.set(address.href, { url: address.href, status: page.status }); continue; }
    if (page.status < 200 || page.status >= 300) continue;
    usableResponses++;
    if (page.body.length > MAX_BODY_CHARS) limitations.add(`Response truncated for parsing: ${address.href}`);
    const body = page.body.slice(0, MAX_BODY_CHARS);
    const isScript = scripts.has(requested) || /(?:javascript|ecmascript)/i.test(page.contentType || '');
    if (isScript) { scriptHints(body, root.href); continue; }
    addInputs(address);
    if (/json/i.test(page.contentType || '') || /^[\s]*\{/.test(body)) {
      try {
        const document = JSON.parse(body) as { paths?: Record<string, { parameters?: { name?: string; in?: string }[]; get?: { parameters?: { name?: string; in?: string }[] } }> };
        for (const [path, endpoint] of Object.entries(document?.paths || {})) {
          const found = resolve(path, address.href);
          if (!found || path.includes('{') || !endpoint?.get) continue;
          if (apiHints.size < MAX_INPUTS) apiHints.add(found.href);
          for (const parameter of [...(endpoint.parameters || []), ...(endpoint.get.parameters || [])]) {
            if (parameter.in === 'query' && typeof parameter.name === 'string') {
              const input = new URL(found); input.searchParams.set(parameter.name, ''); addInputs(input);
            }
          }
        }
      } catch { /* Non-OpenAPI JSON is not a parameter schema. */ }
      continue;
    }
    if (page.contentType && !/html/i.test(page.contentType)) continue;
    const document = parse(body);
    const elements: DefaultTreeAdapterMap['element'][] = [];
    const queue: DefaultTreeAdapterMap['node'][] = [document];
    for (let index = 0; index < queue.length && index < 10000; index++) {
      const node = queue[index];
      if ('tagName' in node) elements.push(node);
      if ('childNodes' in node) queue.push(...node.childNodes);
    }
    if (queue.length > 10000) limitations.add(`HTML node limit reached: ${address.href}`);
    const attr = (node: DefaultTreeAdapterMap['element'], name: string) => node.attrs.find(item => item.name === name)?.value;
    const baseHref = elements.find(node => node.tagName === 'base' && attr(node, 'href') !== undefined);
    let base = address.href;
    if (baseHref) { try { base = new URL(attr(baseHref, 'href') || '', address).href; } catch { /* Invalid base is ignored. */ } }
    const pageForms = new Map<DefaultTreeAdapterMap['element'], NonNullable<WebsiteSurface['forms']>[number]>();
    const formsById = new Map<string, DefaultTreeAdapterMap['element']>();
    for (const node of elements) {
      if (node.tagName === 'form') {
        const action = resolve(attr(node, 'action') || address.href, base); if (!action) continue;
        const declaredMethod = (attr(node, 'method') || 'get').toLowerCase();
        const method = ['post', 'dialog'].includes(declaredMethod) ? declaredMethod : 'get';
        const form = { url: address.href, action: action.href, method, fields: [] as { name: string; type: string }[], hasCsrf: false };
        if (forms.length >= MAX_INPUTS) { limitations.add('Form inventory reached its 128-form limit.'); continue; }
        pageForms.set(node, form); forms.push(form);
        const id = attr(node, 'id'); if (id !== undefined && !formsById.has(id)) formsById.set(id, node);
      }
      if (node.tagName === 'a' || node.tagName === 'area') {
        const href = attr(node, 'href'); const found = href === undefined ? undefined : resolve(href, base);
        if (found) { if (links.size < MAX_INPUTS) links.add(found.href); addInputs(found); enqueue(found); }
      }
      if (node.tagName === 'script') {
        const source = attr(node, 'src');
        if (source) { const found = resolve(source, base); if (found) { if (scripts.size < MAX_INPUTS) scripts.add(found.href); enqueue(found); } }
        else scriptHints(node.childNodes.filter(child => 'value' in child).map(child => 'value' in child ? child.value : '').join(''), address.href);
      }
    }
    for (const node of elements) {
      if (!['input', 'select', 'textarea'].includes(node.tagName) || attr(node, 'disabled') !== undefined) continue;
      const name = attr(node, 'name'); if (!name) continue;
      const ownerId = attr(node, 'form');
      let owner = ownerId === undefined ? node.parentNode : formsById.get(ownerId);
      if (ownerId === undefined) while (owner && !('tagName' in owner && owner.tagName === 'form')) owner = 'parentNode' in owner ? owner.parentNode : null;
      const form = owner && 'tagName' in owner ? pageForms.get(owner) : undefined; if (!form) continue;
      const type = node.tagName === 'input' ? (attr(node, 'type') || 'text').toLowerCase() : node.tagName;
      if (form.fields.length >= MAX_INPUTS) { limitations.add(`Form field limit reached: ${address.href}`); continue; }
      form.fields.push({ name, type });
      if (type === 'hidden' && /csrf|token/i.test(name)) form.hasCsrf = true;
      if (type === 'password' || /\/(?:auth|login|signin)(?:\/|$)/i.test(form.action)) authentication.set(address.href, { url: address.href, status: page.status });
      if (form.method !== 'get' || ['password', 'hidden', 'submit', 'button', 'file', 'reset', 'image'].includes(type)) continue;
      const input = new URL(form.action); input.searchParams.set(name, ''); addInputs(input);
    }
  }
  const surface: WebsiteSurface = { reviewedUrls: [...new Set(reviewed)], inputTargets: [...inputs.values()], authentication: [...authentication.values()],
    postForms: forms.filter(form => form.method !== 'get').length, forms, links: [...links], scripts: [...scripts], apiHints: [...apiHints], complete: limitations.size === 0, limitations: [...limitations] };
  return { success: usableResponses > 0, error: usableResponses ? undefined : 'Website surface review could not read a public response.',
    output: `Public website surface reviewed: ${surface.reviewedUrls.length} response(s), ${inputs.size} GET input(s), ${authentication.size} authentication boundary/entry point(s).\n`
      + [...inputs.values()].map(input => `${input.url} · parameter ${input.param}`).join('\n')
      + `\nForms: ${forms.length}; linked scripts: ${scripts.size}; unverified API URL hints: ${apiHints.size}.`
      + '\nAnonymous boundaries only; authenticated flows need credentials. Forms were not submitted and JavaScript was not executed.'
      + (limitations.size ? `\nIncomplete review:\n${[...limitations].join('\n')}` : ''), metadata: { websiteSurface: surface } };
}
