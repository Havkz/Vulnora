import type { MissionFamily } from '../resources/index.js';

export const DEFAULT_WEB_WORDLIST = '/usr/share/dirb/wordlists/common.txt';

export type ToolCategory =
  | 'core'
  | 'osint'
  | 'dns'
  | 'network'
  | 'web'
  | 'api'
  | 'vulnerability'
  | 'supply_chain'
  | 'cloud'
  | 'container'
  | 'ai_agent'
  | 'smart_contract'
  | 'crypto'
  | 'fuzzing'
  | 'mobile'
  | 'secrets'
  | 'reverse'
  | 'forensics'
  | 'credentials'
  | 'post_exploitation'
  | 'reporting';

export type ToolRisk = 'local_read' | 'passive' | 'active' | 'intrusive' | 'credential' | 'dangerous';
export type ToolExecutionMode = 'safe_command' | 'receipt_required' | 'import_only' | 'catalog_only';

export interface ToolAdapter {
  id: string;
  supportedPlatforms?: NodeJS.Platform[];
  binary: string;
  name: string;
  category: ToolCategory;
  families: MissionFamily[];
  risk: ToolRisk;
  execution: ToolExecutionMode;
  networked: boolean;
  evidenceKinds: string[];
  outputFormats: string[];
  installHint: string;
  commandHint: string;
  parserStatus: 'structured' | 'text' | 'planned';
  notes: string;
}

const WEB_FAMILIES: MissionFamily[] = ['web_api', 'reporting_remediation'];

export const FRONTIER_ARSENAL_MILESTONE = 23;

export const TOOL_ADAPTERS: ToolAdapter[] = [
  {
    id: 'file',
    binary: 'file',
    name: 'file',
    category: 'core',
    families: WEB_FAMILIES,
    risk: 'local_read',
    execution: 'safe_command',
    networked: false,
    evidenceKinds: ['artifact_fingerprint'],
    outputFormats: ['text'],
    installHint: 'Usually preinstalled on Unix-like systems.',
    commandHint: 'file downloaded-response.bin',
    parserStatus: 'text',
    notes: 'Identify downloaded web responses and uploaded test artifacts.',
  },
  {
    id: 'curl',
    binary: 'curl',
    name: 'curl',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['http_request', 'http_response', 'header_probe'],
    outputFormats: ['text', 'headers'],
    installHint: 'Usually preinstalled on macOS and Linux.',
    commandHint: 'curl -I https://example.com',
    parserStatus: 'text',
    notes: 'General HTTP probe. External targets require ScopeGuard receipts.',
  },
  {
    id: 'dig',
    binary: 'dig',
    name: 'dig',
    category: 'dns',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['dns_record'],
    outputFormats: ['text'],
    installHint: 'Install bind utilities, e.g. `brew install bind` or OS package equivalent.',
    commandHint: 'dig +short example.com',
    parserStatus: 'text',
    notes: 'DNS record collection for scoped targets.',
  },
  {
    id: 'host',
    binary: 'host',
    name: 'host',
    category: 'dns',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['dns_record'],
    outputFormats: ['text'],
    installHint: 'Install bind utilities, e.g. `brew install bind` or OS package equivalent.',
    commandHint: 'host example.com',
    parserStatus: 'text',
    notes: 'Simple DNS lookup companion to dig.',
  },
  {
    id: 'whois',
    binary: 'whois',
    name: 'whois',
    category: 'osint',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['registration_record'],
    outputFormats: ['text'],
    installHint: 'Usually preinstalled, or install via OS package manager.',
    commandHint: 'whois example.com',
    parserStatus: 'text',
    notes: 'Passive registration context for scoped assets.',
  },
  {
    id: 'nmap',
    binary: 'nmap',
    name: 'Nmap',
    category: 'network',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['open_port', 'service_fingerprint'],
    outputFormats: ['text', 'xml'],
    installHint: 'brew install nmap',
    commandHint: 'nmap -sV --top-ports 100 --open 127.0.0.1',
    parserStatus: 'text',
    notes: 'Primary scoped port and service discovery engine.',
  },
  {
    id: 'subfinder',
    binary: 'subfinder',
    name: 'Subfinder',
    category: 'osint',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['subdomain'],
    outputFormats: ['text', 'jsonl'],
    installHint: 'brew install projectdiscovery/tap/subfinder',
    commandHint: 'subfinder -d example.com -silent',
    parserStatus: 'planned',
    notes: 'High-value passive asset discovery adapter.',
  },
  {
    id: 'httpx',
    binary: 'httpx',
    name: 'httpx',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['http_service', 'technology_fingerprint'],
    outputFormats: ['jsonl', 'text'],
    installHint: 'brew install projectdiscovery/tap/httpx',
    commandHint: 'httpx -u https://example.com -status-code -title -tech-detect -json',
    parserStatus: 'structured',
    notes: 'HTTP probing and technology detection for discovered assets.',
  },
  {
    id: 'naabu',
    binary: 'naabu',
    name: 'Naabu',
    category: 'network',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['open_port'],
    outputFormats: ['jsonl', 'text'],
    installHint: 'brew install projectdiscovery/tap/naabu',
    commandHint: 'naabu -host 127.0.0.1 -top-ports 100',
    parserStatus: 'planned',
    notes: 'Fast scoped port discovery; pair with nmap for service verification.',
  },
  {
    id: 'katana',
    binary: 'katana',
    name: 'Katana',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['endpoint', 'crawl_result'],
    outputFormats: ['jsonl', 'text'],
    installHint: 'brew install projectdiscovery/tap/katana',
    commandHint: 'katana -u https://example.com -jsonl -silent',
    parserStatus: 'structured',
    notes: 'Crawler for endpoint discovery and attack-surface mapping.',
  },
  {
    id: 'nuclei',
    binary: 'nuclei',
    name: 'Nuclei',
    category: 'vulnerability',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['scanner_finding', 'template_match'],
    outputFormats: ['jsonl'],
    installHint: 'brew install projectdiscovery/tap/nuclei',
    commandHint: 'nuclei -u https://example.com -severity medium,high,critical -jsonl',
    parserStatus: 'structured',
    notes: 'Template-driven scanner; findings should flow into validation and retest.',
  },
  {
    id: 'ffuf',
    binary: 'ffuf',
    name: 'FFUF',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['content_discovery'],
    outputFormats: ['json'],
    installHint: 'brew install ffuf',
    commandHint: 'ffuf -u https://example.com/FUZZ -w wordlist.txt -of json',
    parserStatus: 'structured',
    notes: 'Content and parameter discovery. Rate-limit on real targets.',
  },
  {
    id: 'gobuster',
    binary: 'gobuster',
    name: 'Gobuster',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['content_discovery', 'dns_bruteforce'],
    outputFormats: ['text'],
    installHint: 'brew install gobuster',
    commandHint: 'gobuster dir -u https://example.com -w wordlist.txt',
    parserStatus: 'text',
    notes: 'Directory and DNS brute-force companion to ffuf.',
  },
  {
    id: 'feroxbuster',
    binary: 'feroxbuster',
    name: 'Feroxbuster',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['content_discovery'],
    outputFormats: ['json', 'text'],
    installHint: 'brew install feroxbuster',
    commandHint: 'feroxbuster -u https://example.com --json',
    parserStatus: 'planned',
    notes: 'Recursive content discovery; useful when ffuf finds nested paths.',
  },
  {
    id: 'nikto',
    binary: 'nikto',
    name: 'Nikto',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['scanner_finding'],
    outputFormats: ['text', 'json'],
    installHint: 'brew install nikto',
    commandHint: 'nikto -h https://example.com',
    parserStatus: 'text',
    notes: 'Legacy web server checks; validate findings before reporting.',
  },
  {
    id: 'dalfox',
    binary: 'dalfox',
    name: 'Dalfox',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['xss_probe', 'scanner_finding'],
    outputFormats: ['json', 'text'],
    installHint: 'brew install dalfox',
    commandHint: 'dalfox url https://example.com?q=test -o result.json --format json',
    parserStatus: 'structured',
    notes: 'XSS validation adapter for scoped endpoints.',
  },
  {
    id: 'sqlmap',
    binary: 'sqlmap',
    name: 'SQLMap',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'intrusive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['sqli_validation'],
    outputFormats: ['text'],
    installHint: 'brew install sqlmap',
    commandHint: 'sqlmap -u "https://example.com/item?id=1" --batch --level=1 --risk=1',
    parserStatus: 'text',
    notes: 'Keep level/risk low unless the mission receipt explicitly permits intrusive testing.',
  },
  {
    id: 'whatweb',
    binary: 'whatweb',
    name: 'WhatWeb',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['technology_fingerprint', 'http_service'],
    outputFormats: ['json', 'text'],
    installHint: 'brew install whatweb  # or: gem install whatweb',
    commandHint: 'whatweb --log-json=- https://example.com',
    parserStatus: 'text',
    notes: 'Web stack fingerprinting (CMS, framework, server) to seed targeted follow-up.',
  },
  {
    id: 'wafw00f',
    binary: 'wafw00f',
    name: 'wafw00f',
    category: 'web',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'safe_command',
    networked: true,
    evidenceKinds: ['waf_fingerprint'],
    outputFormats: ['json', 'text'],
    installHint: 'pipx install wafw00f',
    commandHint: 'wafw00f https://example.com -f json -o -',
    parserStatus: 'text',
    notes: 'Detects and fingerprints the WAF in front of a target so probes can be tuned or throttled.',
  },
  {
    id: 'amass',
    binary: 'amass',
    name: 'OWASP Amass',
    category: 'osint',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'receipt_required',
    networked: true,
    evidenceKinds: ['subdomain', 'asn', 'dns_record'],
    outputFormats: ['jsonl', 'text'],
    installHint: 'brew install amass',
    commandHint: 'amass enum -passive -d example.com',
    parserStatus: 'text',
    notes: 'Deep passive attack-surface mapping; complements subfinder with ASN and infra correlation.',
  },
  {
    id: 'dnsx',
    binary: 'dnsx',
    name: 'dnsx',
    category: 'dns',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'safe_command',
    networked: true,
    evidenceKinds: ['dns_record', 'subdomain'],
    outputFormats: ['jsonl', 'text'],
    installHint: 'brew install projectdiscovery/tap/dnsx',
    commandHint: 'dnsx -d example.com -a -aaaa -cname -resp -json',
    parserStatus: 'text',
    notes: 'Fast DNS resolution/validation to confirm live records from discovered candidate hosts.',
  },
  {
    id: 'testssl',
    binary: 'testssl.sh',
    name: 'testssl.sh',
    category: 'crypto',
    families: WEB_FAMILIES,
    risk: 'active',
    execution: 'safe_command',
    networked: true,
    evidenceKinds: ['tls_config', 'cipher_weakness', 'certificate_finding'],
    outputFormats: ['json', 'text'],
    installHint: 'brew install testssl',
    commandHint: 'testssl.sh --jsonfile-pretty - https://example.com:443',
    parserStatus: 'text',
    notes: 'TLS/SSL posture check (protocols, ciphers, cert, known CVEs) against an authorized endpoint.',
  },
  {
    id: 'waybackurls',
    binary: 'waybackurls',
    name: 'waybackurls',
    category: 'osint',
    families: WEB_FAMILIES,
    risk: 'passive',
    execution: 'safe_command',
    networked: true,
    evidenceKinds: ['historical_url', 'endpoint'],
    outputFormats: ['text'],
    installHint: 'go install github.com/tomnomnom/waybackurls@latest',
    commandHint: 'waybackurls example.com',
    parserStatus: 'text',
    notes: 'Pulls historical URLs from the Wayback Machine to surface forgotten endpoints and parameters.',
  },
];

export const SAFE_COMMANDS = [
  ...new Set(
    TOOL_ADAPTERS
      .filter(adapter => adapter.execution !== 'catalog_only' && adapter.execution !== 'import_only')
      .map(adapter => adapter.binary)
  ),
].sort();

export const NETWORK_COMMANDS = new Set(
  TOOL_ADAPTERS
    .filter(adapter => adapter.networked && adapter.execution !== 'catalog_only' && adapter.execution !== 'import_only')
    .map(adapter => adapter.binary)
);

export function adaptersForFamily(family?: string): ToolAdapter[] {
  return family
    ? TOOL_ADAPTERS.filter(adapter => adapter.families.includes(family as MissionFamily))
    : TOOL_ADAPTERS;
}

export function adapterForBinary(binary: string): ToolAdapter | undefined {
  return TOOL_ADAPTERS.find(adapter => adapter.binary === binary || adapter.id === binary);
}

export function summarizeToolCatalog(adapters = TOOL_ADAPTERS): Record<string, unknown> {
  const commandReady = adapters.filter(adapter => adapter.execution === 'safe_command' || adapter.execution === 'receipt_required').length;
  const byExecution = adapters.reduce<Record<string, number>>((acc, adapter) => {
    acc[adapter.execution] = (acc[adapter.execution] || 0) + 1;
    return acc;
  }, {});
  const byRisk = adapters.reduce<Record<string, number>>((acc, adapter) => {
    acc[adapter.risk] = (acc[adapter.risk] || 0) + 1;
    return acc;
  }, {});
  const byCategory = adapters.reduce<Record<string, number>>((acc, adapter) => {
    acc[adapter.category] = (acc[adapter.category] || 0) + 1;
    return acc;
  }, {});
  return {
    total: adapters.length,
    commandReady,
    catalogOnly: adapters.filter(adapter => adapter.execution === 'catalog_only').length,
    importOnly: adapters.filter(adapter => adapter.execution === 'import_only').length,
    unmodeled: adapters.length === 0 || commandReady === 0,
    byExecution,
    byRisk,
    byCategory,
  };
}
