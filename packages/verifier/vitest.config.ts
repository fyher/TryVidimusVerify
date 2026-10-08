import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts'],
      // docs/testing.md : couverture ≥ 90 % sur les primitives de preuve.
      thresholds: { lines: 90, functions: 90, branches: 85, statements: 90 },
    },
  },
});
