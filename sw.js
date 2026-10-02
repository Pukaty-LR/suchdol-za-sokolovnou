/* Service worker webu pod heslem: požadavky na stránky a podklady stáhne šifrované (d/<sha256 cesty>) a dešifruje klíčem
   z IndexedDB (uloží ho přihlašovací stránka po ověření hesla). Bez klíče propustí požadavek beze změny (přihlašovací stránka). */
const SCOPE = new URL(self.registration.scope).pathname;
const TYP = { html: "text/html; charset=utf-8", css: "text/css; charset=utf-8", js: "text/javascript; charset=utf-8", json: "application/json; charset=utf-8",
  svg: "image/svg+xml", webp: "image/webp", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", mp4: "video/mp4", m3u8: "application/vnd.apple.mpegurl",
  ts: "video/mp2t", zip: "application/zip", txt: "text/plain; charset=utf-8", ico: "image/x-icon" };
const PLATNOST = 30 * 24 * 3600 * 1000;
let klic = null;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => { if (e.data === "zamknout") klic = null; });

function db() {
  return new Promise((ok, ko) => { const r = indexedDB.open("zs-zamek", 1); r.onupgradeneeded = () => r.result.createObjectStore("k"); r.onsuccess = () => ok(r.result); r.onerror = () => ko(r.error); });
}
async function nactiKlic() {
  if (klic) return klic;
  try {
    const d = await db();
    const v = await new Promise((ok) => { const t = d.transaction("k").objectStore("k").get("klic"); t.onsuccess = () => ok(t.result); t.onerror = () => ok(null); });
    if (v && v.key && Date.now() - v.t < PLATNOST) { klic = v.key; return klic; }
  } catch (e) { /* bez IndexedDB */ }
  return null;
}
async function jmeno(rel) {
  const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("zs:" + rel));
  return Array.from(new Uint8Array(h)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 40);
}

self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== "GET" || !u.pathname.startsWith(SCOPE)) return;
  let rel = decodeURIComponent(u.pathname.slice(SCOPE.length));
  if (rel === "" || rel.endsWith("/")) rel += "index.html";
  if (rel === "sw.js" || rel.startsWith("d/") || rel === "robots.txt") return;
  e.respondWith(odpoved(e.request, rel));
});

async function odpoved(req, rel) {
  const k = await nactiKlic();
  if (!k) return fetch(req);
  const r = await fetch(SCOPE + "d/" + (await jmeno(rel)), { cache: "default" });
  if (!r.ok) {
    if (req.mode === "navigate") return odpoved(new Request(SCOPE + "index.html"), "index.html");
    return new Response("Nenalezeno", { status: 404 });
  }
  const buf = new Uint8Array(await r.arrayBuffer());
  let data;
  try { data = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: buf.slice(0, 12) }, k, buf.slice(12))); }
  catch (err) { return fetch(req); }                                     // klíč neplatí (nové heslo) -> přihlášení
  const ext = rel.split(".").pop().toLowerCase(); const typ = TYP[ext] || "application/octet-stream";
  const range = req.headers.get("range");
  if (range) {
    const m = /bytes=(\d*)-(\d*)/.exec(range); let a = m && m[1] ? +m[1] : 0, b = m && m[2] ? +m[2] : data.length - 1;
    if (m && !m[1] && m[2]) { a = data.length - +m[2]; b = data.length - 1; }
    b = Math.min(b, data.length - 1);
    return new Response(data.slice(a, b + 1), { status: 206, headers: { "Content-Type": typ, "Content-Range": `bytes ${a}-${b}/${data.length}`, "Content-Length": String(b - a + 1), "Accept-Ranges": "bytes" } });
  }
  return new Response(data, { status: 200, headers: { "Content-Type": typ, "Content-Length": String(data.length), "Accept-Ranges": "bytes", "Cache-Control": "no-store" } });
}
