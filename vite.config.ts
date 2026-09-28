import { defineConfig, type Plugin } from 'vite';

// When built for GitHub Pages (project site), assets must be served from the
// repository sub-path. The deploy workflow sets GITHUB_PAGES=1.
const base = process.env.GITHUB_PAGES ? '/SOC-Triage-Simulator/' : '/';
const buildId = Date.now().toString(36);

// Lists every emitted file the app needs offline (the page, scripts, styles,
// the query worker, the SQLite WebAssembly and the Latin font subsets) so the
// service worker can precache them on first visit.
function precacheList(): Plugin {
  return {
    name: 'precache-list',
    apply: 'build',
    generateBundle(_opts, bundle) {
      const files = Object.keys(bundle).filter((f) => {
        if (f.endsWith('.map') || f.startsWith('.vite/')) return false;
        if (/\.(woff2?|ttf)$/.test(f)) return f.endsWith('.woff2') && /-latin(-ext)?-/.test(f);
        return true;
      });
      const shell = ['./', 'icon.svg', 'manifest.webmanifest'];
      this.emitFile({ type: 'asset', fileName: 'precache.json', source: JSON.stringify({ version: buildId, files: [...shell, ...files.filter((f) => f !== 'index.html')] }) });
    },
  };
}

export default defineConfig({
  base,
  define: { __BUILD_ID__: JSON.stringify(buildId) },
  plugins: [precacheList()],
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
