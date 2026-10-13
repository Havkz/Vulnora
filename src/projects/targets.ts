import { isIP } from 'node:net';

export interface ProjectTarget { input: string; kind: 'url' | 'ip' | 'hostname'; hostname: string }

export function validateProjectName(input: string): string {
  const name = input.trim();
  if (!name || name.length > 120 || /[\p{Cc}\p{Cf}]/u.test(name)) throw new Error('Use a project name of 1–120 visible characters.');
  return name;
}

export function validateProjectTarget(input: string): ProjectTarget {
  const value = input.trim();
  if (!value || /[\p{Cc}\p{Cf}\\]/u.test(input) || /\s/u.test(value)) throw new Error('Enter a valid HTTP/HTTPS URL, IP address or hostname.');
  if (/^https?:\/\//i.test(value)) {
    let url: URL;
    try { url = new URL(value); } catch { throw new Error('Invalid HTTP/HTTPS target URL.'); }
    if (url.username || url.password) throw new Error('Configure target authentication separately; credentials are not allowed in the target URL.');
    if (url.hash) throw new Error('Remove the URL fragment; it is not sent to the server.');
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!isIP(host) && !validHostname(host)) throw new Error('Invalid target hostname.');
    return { input, kind: 'url', hostname: host };
  }
  const bracketed = value.startsWith('[') && value.endsWith(']');
  const ip = bracketed ? value.slice(1, -1) : value;
  if (isIP(ip)) return { input, kind: 'ip', hostname: ip };
  if (validHostname(value)) return { input, kind: 'hostname', hostname: value };
  throw new Error('Enter a valid HTTP/HTTPS URL, IPv4/IPv6 address or hostname.');
}

function validHostname(value: string): boolean {
  const hostname = value.endsWith('.') ? value.slice(0, -1) : value;
  if (!hostname || hostname.length > 253 || /^[\d.]+$/.test(hostname)) return false;
  return hostname.split('.').every(label => label.length <= 63 && /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label));
}
