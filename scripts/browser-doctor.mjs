import { chromium } from 'playwright-core';

try {
  const browser = await chromium.launch({ headless: true, chromiumSandbox: true, timeout: 15000 });
  try { console.log(`Sandboxed Chromium ${browser.version()} is ready.`); }
  finally { await browser.close(); }
} catch (error) {
  console.error(String(error.message));
  console.error('Install with npm run browser:install. Linux dependencies and sandbox requirements: docs/BROWSER.md');
  process.exitCode = 1;
}
