// Offline support. On install, precache every file the build lists in
// precache.json; afterwards serve assets cache-first (their names are
// content-hashed) and the page network-first, falling back to the cache.
const VERSION = new URL(self.location.href).searchParams.get('v') || 'dev';
const CACHE = `soc-triage-${VERSION}`;

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const res = await fetch('precache.json', { cache: 'no-store' });
      const { files } = await res.json();
      const cache = await caches.open(CACHE);
      await cache.addAll(files);
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // Keep the previous version's cache too: a tab still running the old
      // build may yet load its lazy chunks (editor, worker, WebAssembly).
      // Versions are base-36 timestamps, so names sort by age.
      const ours = (await caches.keys()).filter((k) => k.startsWith('soc-triage-')).sort();
      const keep = new Set([CACHE, ...ours.filter((k) => k !== CACHE).slice(-1)]);
      for (const key of ours) if (!keep.has(key)) await caches.delete(key);
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  if (req.mode === 'navigate') {
    event.respondWith(
      (async () => {
        try {
          const fresh = await fetch(req);
          // Only a real page may replace the offline shell (not a 404).
          if (fresh.ok) (await caches.open(CACHE)).put('./', fresh.clone());
          return fresh;
        } catch {
          return (await caches.match('./', { ignoreVary: true })) || Response.error();
        }
      })(),
    );
    return;
  }
  event.respondWith(
    (async () => {
      // ignoreVary: the page's crossorigin module/style requests carry an Origin
      // header the precache requests did not; assets are content-hashed anyway.
      const hit = await caches.match(req, { ignoreVary: true });
      if (hit) return hit;
      const res = await fetch(req);
      if (res.ok && new URL(req.url).pathname.includes('/assets/')) (await caches.open(CACHE)).put(req, res.clone());
      return res;
    })(),
  );
});
