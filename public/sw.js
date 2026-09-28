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
      for (const key of await caches.keys()) if (key.startsWith('soc-triage-') && key !== CACHE) await caches.delete(key);
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
          const cache = await caches.open(CACHE);
          cache.put('./', fresh.clone());
          return fresh;
        } catch {
          return (await caches.match('./')) || Response.error();
        }
      })(),
    );
    return;
  }
  event.respondWith(
    (async () => {
      const hit = await caches.match(req, { ignoreSearch: false });
      if (hit) return hit;
      const res = await fetch(req);
      if (res.ok && new URL(req.url).pathname.includes('/assets/')) (await caches.open(CACHE)).put(req, res.clone());
      return res;
    })(),
  );
});
