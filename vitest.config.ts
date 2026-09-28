import { defineConfig } from 'vitest/config';

export default defineConfig({
  oxc: {
    jsx: { runtime: 'automatic', importSource: 'preact' },
  },
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // The scenario suite builds real SQLite databases; give it room.
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
