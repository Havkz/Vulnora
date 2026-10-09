import { describe, it, expect } from 'vitest';
import { TOOL_ADAPTERS } from '../arsenal/catalog.js';
import { BUILTIN_TOOLS, EXTERNAL_TOOLS } from '../arsenal/index.js';
import { adapterToCustomTool, buildAdapterTools, isMintable, type AdapterToolDeps } from '../arsenal/adapter-tools.js';

const deps: AdapterToolDeps = {
  isToolAvailable: async () => true,
  runSubprocess: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
};

describe('website/API arsenal registration', () => {
  it('registers the advertised 32 default and 23 external tools without duplicates', () => {
    const defaults = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS];
    const adapters = buildAdapterTools(TOOL_ADAPTERS, deps, new Set(defaults.map(tool => tool.name)));
    const tools = [...defaults, ...adapters];
    expect(defaults).toHaveLength(32);
    expect(adapters).toHaveLength(23);
    expect(tools).toHaveLength(55);
    expect(new Set(tools.map(tool => tool.name)).size).toBe(tools.length);
    for (const tool of tools) expect(typeof tool.handler).toBe('function');
  });

  it('only advertises callable website/API adapters', () => {
    for (const adapter of TOOL_ADAPTERS) {
      expect(adapter.families).toEqual(['web_api', 'reporting_remediation']);
      expect(isMintable(adapter)).toBe(true);
      expect(adapterToCustomTool(adapter, deps)).not.toBeNull();
    }
    expect(TOOL_ADAPTERS.filter(adapter => ['mobile', 'cloud', 'smart_contract', 'reverse', 'post_exploitation'].includes(adapter.category))).toEqual([]);
    const names = [...BUILTIN_TOOLS, ...EXTERNAL_TOOLS].map(tool => tool.name);
    for (const name of ['hash_crack', 'cidr_expand', 'network_trace', 'metasploit_module', 'hydra_bruteforce']) {
      expect(names).not.toContain(name);
    }
  });
});
