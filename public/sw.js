const CACHE='chat-platform-v5';
const SHELL=['/','/style.css','/app.js?v=5','/manifest.json'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(SHELL)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  if(event.request.method!=='GET'||event.request.url.includes('/api/')) return;
  const url=new URL(event.request.url);
  if(url.pathname==='/app.js'||url.pathname==='/style.css'||url.pathname==='/') {
    event.respondWith(fetch(event.request,{cache:'no-store'}).then(r=>{const copy=r.clone();caches.open(CACHE).then(c=>c.put(event.request,copy));return r}).catch(()=>caches.match(event.request)));
    return;
  }
  event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)));
});
