import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: { globalSetup: './scripts/test-config.mjs' },
});
