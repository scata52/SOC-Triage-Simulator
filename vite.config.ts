import { defineConfig } from 'vite';

// When built for GitHub Pages (project site), assets must be served from the
// repository sub-path. The deploy workflow sets GITHUB_PAGES=1.
export default defineConfig({
  base: process.env.GITHUB_PAGES ? '/SOC-Triage-Simulator/' : '/',
  oxc: {
    jsx: { runtime: 'automatic', importSource: 'preact' },
  },
  worker: {
    format: 'es',
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
});
