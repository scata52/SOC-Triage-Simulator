// Hash routing: works from file://, GitHub Pages sub-paths and offline.

import { signal } from '@preact/signals';

export type Route =
  | { name: 'home' }
  | { name: 'practice' }
  | { name: 'case'; slug: string; seed: string; study?: boolean }
  | { name: 'daily' }
  | { name: 'vuln' }
  | { name: 'vuln-case'; slug: string; seed: string }
  | { name: 'study' }
  | { name: 'shift' }
  | { name: 'shift-alert'; alertId: string }
  | { name: 'handover' }
  | { name: 'intel' }
  | { name: 'stats' }
  | { name: 'help'; section?: string }
  | { name: 'settings' }
  | { name: 'not-found'; path: string };

export function parse(hash: string): Route {
  const path = hash.replace(/^#\/?/, '').replace(/\/+$/, '');
  const parts = path.split('/').map((p) => decodeURIComponent(p));
  switch (parts[0]) {
    case '':
      return { name: 'home' };
    case 'practice':
      return { name: 'practice' };
    case 'case':
      if (parts[1] && parts[2]) return { name: 'case', slug: parts[1], seed: parts[2], study: parts[3] === 'study' };
      break;
    case 'daily':
      return { name: 'daily' };
    case 'vuln':
      if (parts[1] && parts[2]) return { name: 'vuln-case', slug: parts[1], seed: parts[2] };
      if (!parts[1]) return { name: 'vuln' };
      break;
    case 'study':
      return { name: 'study' };
    case 'shift':
      return parts[1] ? { name: 'shift-alert', alertId: parts[1] } : { name: 'shift' };
    case 'handover':
      return { name: 'handover' };
    case 'intel':
      return { name: 'intel' };
    case 'stats':
      return { name: 'stats' };
    case 'help':
      return { name: 'help', section: parts[1] };
    case 'settings':
      return { name: 'settings' };
  }
  return { name: 'not-found', path };
}

export function href(r: Route): string {
  switch (r.name) {
    case 'home':
      return '#/';
    case 'case':
      return `#/case/${encodeURIComponent(r.slug)}/${encodeURIComponent(r.seed)}${r.study ? '/study' : ''}`;
    case 'vuln-case':
      return `#/vuln/${encodeURIComponent(r.slug)}/${encodeURIComponent(r.seed)}`;
    case 'shift-alert':
      return `#/shift/${encodeURIComponent(r.alertId)}`;
    case 'help':
      return r.section ? `#/help/${encodeURIComponent(r.section)}` : '#/help';
    case 'not-found':
      return '#/';
    default:
      return `#/${r.name}`;
  }
}

export const route = signal<Route>(typeof location !== 'undefined' ? parse(location.hash) : { name: 'home' });

if (typeof window !== 'undefined') {
  window.addEventListener('hashchange', () => {
    route.value = parse(location.hash);
  });
}

export function navigate(r: Route | string, opts: { replace?: boolean } = {}): void {
  const h = typeof r === 'string' ? r : href(r);
  if (opts.replace) {
    history.replaceState(null, '', h);
    route.value = parse(h);
  } else if (location.hash === h) {
    route.value = parse(h);
  } else {
    location.hash = h;
  }
}
