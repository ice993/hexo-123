const CACHE_NAME = "liangy-blog-v1";
const STATIC_ASSETS = [
    "/",
    "/css/main.css",
    "/js/main.js",
    "/js/lib/click-effect.js",
    "/images/background.jpg",
    "/images/loading.gif",
    "/images/lty.png",
];

self.addEventListener("install", (e) => {
    e.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

self.addEventListener("activate", (e) => {
    e.waitUntil(
        caches.keys().then((keys) =>
            Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
        )
    );
    self.clients.claim();
});

self.addEventListener("fetch", (e) => {
    const url = new URL(e.request.url);
    // Only cache same-origin GET requests
    if (e.request.method !== "GET" || url.origin !== location.origin) return;

    // Network-first for HTML pages
    if (e.request.headers.get("accept") && e.request.headers.get("accept").includes("text/html")) {
        e.respondWith(
            fetch(e.request)
                .then((res) => {
                    const clone = res.clone();
                    caches.open(CACHE_NAME).then((c) => c.put(e.request, clone));
                    return res;
                })
                .catch(() => caches.match(e.request))
        );
        return;
    }

    // Cache-first for static assets
    e.respondWith(
        caches.match(e.request).then((cached) => {
            if (cached) return cached;
            return fetch(e.request).then((res) => {
                if (!res || res.status !== 200) return res;
                const clone = res.clone();
                caches.open(CACHE_NAME).then((c) => c.put(e.request, clone));
                return res;
            });
        })
    );
});
