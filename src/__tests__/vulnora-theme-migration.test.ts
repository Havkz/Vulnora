import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { stripVTControlCharacters } from 'node:util';
import { migrateEnvironment, migrateLegacyData } from '../config/migration.js';
import { THEME_TOKENS, createTheme, renderLogo, visibleWidth } from '../ui/theme.js';

describe('Vulnora theme', () => {
  it('centers the original browser and lock with steel-blue colors', () => {
    expect(THEME_TOKENS).toEqual({ accent: 75, secondary: 109, border: 67, foreground: 7,
      bright: 15, muted: 244, detail: 247, active: 80, success: 2, error: 1, warning: 3 });
    const lines = renderLogo(80, createTheme(3));
    expect(lines).toHaveLength(12);
    expect(lines[0]).toContain('\u001b[38;5;75m');
    expect(stripVTControlCharacters(lines[10]).trim()).toBe('V U L N O R A');
    expect(stripVTControlCharacters(lines[11]).trim()).toBe('website pentesting tool');
    expect(lines.map(line => stripVTControlCharacters(line))).toMatchSnapshot();
    for (const width of [10, 24, 25, 40, 80, 120]) {
      expect(renderLogo(width, createTheme(0)).every(line => visibleWidth(line) <= width)).toBe(true);
    }
  });
});

describe('Vulnora safe namespace migration', () => {
  it('accepts old environment inputs while preserving explicit new values', () => {
    const env = { TEMPEST_LOCAL_MODEL: 'old', VULNORA_LOCAL_MODEL: 'new', T3MP3ST_CONFIG_DIR: '/old', OTHER: 'untouched' };
    migrateEnvironment(env);
    expect(env).toMatchObject({ VULNORA_LOCAL_MODEL: 'new', VULNORA_CONFIG_DIR: '/old', OTHER: 'untouched' });
  });
  it('preserves legacy files and new settings, migrates histories once, excludes runtimes and credentials', () => {
    const root = mkdtempSync(join(tmpdir(), 'vulnora-migrate-'));
    try {
      const old = join(root, 'old'); const current = join(root, 'new');
      mkdirSync(join(old, 'reports'), { recursive: true }); mkdirSync(join(old, 'sandbox'));
      mkdirSync(join(old, '.codex')); mkdirSync(current);
      writeFileSync(join(old, 'config.json'), 'legacy'); writeFileSync(join(current, 'config.json'), 'current');
      writeFileSync(join(old, '.env'), 'LOCAL_MODEL=existing');
      writeFileSync(join(old, 'reports', 'report.md'), 'all evidence');
      writeFileSync(join(old, '.codex', 'auth.json'), 'never touch');
      const entries = migrateLegacyData([old], current);
      expect(entries).toHaveLength(2);
      expect(readFileSync(join(current, 'config.json'), 'utf8')).toBe('current');
      expect(readFileSync(join(old, 'reports', 'report.md'), 'utf8')).toBe('all evidence');
      expect(readFileSync(join(current, 'reports', 'report.md'), 'utf8')).toBe('all evidence');
      expect(existsSync(join(current, 'sandbox'))).toBe(false);
      expect(existsSync(join(current, '.codex'))).toBe(false);
      expect(migrateLegacyData([old], current)).toEqual([]);
      expect(JSON.parse(readFileSync(join(current, 'migration-v1.json'), 'utf8')).version).toBe(1);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
