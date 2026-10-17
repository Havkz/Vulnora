import { describe, expect, it } from 'vitest';
import { maxToolCallsPerTask } from '../agent/index.js';

describe('agent expensive-tool budget', () => {
  it('leaves scans unrestricted unless an operator explicitly supplies a tool cap', () => {
    expect(maxToolCallsPerTask('nmap_scan')).toBeUndefined();
    expect(maxToolCallsPerTask('port_scan')).toBeUndefined();
    expect(maxToolCallsPerTask('nuclei_scan')).toBeUndefined();
    expect(maxToolCallsPerTask('curl_request')).toBeUndefined();
  });
});
