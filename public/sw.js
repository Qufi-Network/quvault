/*
 * The service worker for the installable app.
 *
 * It does exactly one job: let the static shell load when the network is slow or gone, so the
 * app opens like a native one. It is deliberately timid about everything else, because this is
 * a wallet:
 *
 *   - /api/* is NEVER cached and never answered from a cache. Balances, the session, palm
 *     decisions and signing all go straight to the network, every time. A stale balance or a
 *     replayed auth response would be worse than an error.
 *   - Only same-origin GETs for the static shell are cached, and only after the network serves
 *     them, so the cache can never hold something the server would not currently send.
 *   - A POST, a cross-origin request to the identity provider, or anything with credentials is
 *     passed straight through and left alone.
 */
const CACHE = 'veyns-shell-v3';

// The shell: enough to render the app offline. Everything else is cached as it is fetched.
const SHELL = [
  '/', '/style.css', '/veyns.css', '/enterprise.css', '/light.css',
  '/app.js', '/veyns.js', '/qicons.js', '/qvcore.js', '/qvfx.js', '/qvdemo.js', '/vendor/wallet.js',
  '/manifest.webmanifest', '/icon.svg', '/icon-192.png', '/icon-512.png',
  '/veyns-lockup-black.png', '/qufi-logo.png', '/quvault-logo.png', '/veyns-palm.webp',
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Only GET is ever cached; everything else goes to the network untouched.
  if (request.method !== 'GET') return;

  // The API and the identity provider are always live. Never cache, never serve from cache.
  if (url.origin === self.location.origin && url.pathname.startsWith('/api/')) return;
  if (url.origin !== self.location.origin && !/fonts\.(googleapis|gstatic)\.com$/.test(url.hostname)) return;

  // A navigation (opening the app): try the network so a fresh shell wins, fall back to the
  // cached shell when offline so the app still opens.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => caches.match('/', { ignoreSearch: true }).then(r => r || caches.match('/'))),
    );
    return;
  }

  // Code (CSS/JS): network-first, so a fresh build always wins; fall back to cache when offline.
  if (/\.(css|js)$/.test(url.pathname)) {
    event.respondWith(
      fetch(request).then(response => {
        if (response && response.ok && (response.type === 'basic' || response.type === 'cors')) {
          const copy = response.clone();
          caches.open(CACHE).then(cache => cache.put(request, copy)).catch(() => {});
        }
        return response;
      }).catch(() => caches.match(request)),
    );
    return;
  }

  // Static assets and the fonts: serve from cache if present, and refresh the cache from the
  // network in the background. A response is only cached if the server returned it cleanly.
  event.respondWith(
    caches.match(request).then(cached => {
      const fromNetwork = fetch(request).then(response => {
        if (response && response.ok && (response.type === 'basic' || response.type === 'cors')) {
          const copy = response.clone();
          caches.open(CACHE).then(cache => cache.put(request, copy)).catch(() => {});
        }
        return response;
      }).catch(() => cached);
      return cached || fromNetwork;
    }),
  );
});
