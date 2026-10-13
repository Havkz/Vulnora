interface TargetHeaderConfig {
  origin: string;
  headers: Headers;
}

const FORBIDDEN_TARGET_HEADERS = new Set([
  'connection', 'content-length', 'host', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

/** Parse an exact-origin binding and its default headers. Invalid configuration fails closed. */
export function parseTargetHeaderConfig(): TargetHeaderConfig | null {
  const rawOrigin = process.env.VULNORA_TARGET_ORIGIN?.trim();
  const rawHeaders = process.env.VULNORA_TARGET_HEADERS?.trim();
  if (!rawOrigin || !rawHeaders) return null;

  try {
    const target = new URL(rawOrigin);
    if (!['http:', 'https:'].includes(target.protocol)
      || target.username || target.password
      || target.pathname !== '/' || target.search || target.hash) {
      return null;
    }

    const parsed: unknown = JSON.parse(rawHeaders);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

    const headers = new Headers();
    for (const [name, value] of Object.entries(parsed)) {
      if (typeof value !== 'string' || FORBIDDEN_TARGET_HEADERS.has(name.toLowerCase())) return null;
      headers.set(name, value);
    }
    return headers.keys().next().done ? null : { origin: target.origin, headers };
  } catch {
    return null;
  }
}

export function targetHeadersForUrl(url: string | URL, explicit?: RequestInit['headers']): Headers | undefined {
  const merged = new Headers();
  const config = parseTargetHeaderConfig();
  try {
    if (config && new URL(url).origin === config.origin) {
      config.headers.forEach((value, name) => merged.set(name, value));
    }
  } catch {
    // Let fetch or curl report malformed URLs; they simply receive no configured secrets.
  }
  new Headers(explicit).forEach((value, name) => merged.set(name, value));
  return merged.keys().next().done ? undefined : merged;
}

export function redactConfiguredSecrets<T>(result: T): T {
  const config = parseTargetHeaderConfig();
  const secrets = config ? [...config.headers.values()].filter(Boolean) : [];
  if (secrets.length === 0) return result;

  const redact = (value: unknown): unknown => {
    if (typeof value === 'string') {
      return secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), value);
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, redact(nested)]));
    }
    return value;
  };
  return redact(result) as T;
}
