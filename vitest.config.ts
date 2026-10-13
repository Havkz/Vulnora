import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Bound scanner-module workers so local-model memory pressure does not starve subprocess tests.
  test: { globalSetup: './scripts/test-config.mjs', maxWorkers: 4 },
});
