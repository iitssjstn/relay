// Relay service worker — houdt het simpel: cache de statische schil
// (HTML/manifest/iconen) zodat de app ook zonder verbinding opstart, en
// laat alles wat met echte data te maken heeft (API-calls, AI-aanroepen)
// altijd gewoon rechtstreeks naar het netwerk gaan. Een service worker is
// ook een harde vereiste van Chrome/Android om de installatie-prompt
// (beforeinstallprompt) te tonen.

const CACHE_NAME = 'relay-shell-v2';
const SHELL_FILES = [
  '/',
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(SHELL_FILES))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Nooit API-aanroepen of externe AI-providers cachen — die moeten
  // altijd live en actueel zijn.
  if (req.method !== 'GET' || req.url.includes('/api/')) return;

  // Netwerk-eerst, niet cache-eerst: anders blijft iedereen na een update
  // vastzitten aan een verouderde versie van de app totdat de cache om
  // een andere reden verloopt. Alleen als het netwerk écht niet bereikbaar
  // is (offline), valt dit terug op wat er nog in de cache staat.
  event.respondWith(
    fetch(req).then((res) => {
      if (res && res.ok && req.url.startsWith(self.location.origin)) {
        const clone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
      }
      return res;
    }).catch(() => caches.match(req))
  );
});
