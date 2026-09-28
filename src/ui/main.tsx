import { render } from 'preact';
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/500.css';
import '@fontsource/ibm-plex-mono/600.css';
import './styles/tokens.css';
import './styles/base.css';
import './styles/components.css';
import './styles/screens.css';
import { App } from './App.tsx';

const root = document.getElementById('app');
if (!root) throw new Error('#app root not found');
render(<App />, root);

// Offline support in production builds (the dev server is always online).
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js?v=${__BUILD_ID__}`, { scope: import.meta.env.BASE_URL }).catch(() => {
      /* offline support is best-effort */
    });
  });
}
