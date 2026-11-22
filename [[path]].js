// RubyGFN login function for Cloudflare Pages. Same login logic as server.js.
// Needs a KV binding named RGFN. Tokens stay in KV and are never sent to the browser.
// Endpoints/constants come from the OpenNOW project docs. NOT TESTED against live NVIDIA.
const NV = {
  base: "https://login.nvidia.com",
  clientId: "ZU7sPN-miLujMD95LfOQ453IB0AtjM8sMyvgJ9wCXEQ",
  scope: "openid consent email tk_client age",
  origin: "https://nvfile"
};
const json = (code, obj, headers = {}) => new Response(JSON.stringify(obj), { status: code, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
const clip = s => String(s || "").slice(0, 240);

async function nv(path, form) {
  const r = await fetch(NV.base + path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: NV.origin, Accept: "application/json" },
    body: new URLSearchParams(form)
  });
  const text = await r.text(); let j = null; try { j = JSON.parse(text); } catch {}
  return { status: r.status, json: j, text };
}

export async function onRequest({ request, env }) {
  if (!env.RGFN) return json(500, { error: "KV binding RGFN is missing. Add it under the Pages project's Settings > Bindings, then redeploy." });
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/auth\//, "");

  let sid = (/(?:^|;\s*)rgfn_sid=([a-f0-9]{48})/.exec(request.headers.get("Cookie") || "") || [])[1], fresh = false;
  if (!sid) { sid = [...crypto.getRandomValues(new Uint8Array(24))].map(b => b.toString(16).padStart(2, "0")).join(""); fresh = true; }
  const cookie = fresh ? { "Set-Cookie": `rgfn_sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/` } : {};
  const key = "s:" + sid;
  const s = (await env.RGFN.get(key, "json")) || {};
  const save = () => env.RGFN.put(key, JSON.stringify(s), { expirationTtl: 60 * 60 * 24 * 30 });
  const reply = (c, o) => json(c, o, cookie);

  if (route === "status") return reply(200, { signedIn: !!s.tokens });
  if (request.method !== "POST") return reply(405, { error: "Use POST" });
  const o = request.headers.get("Origin");
  if (o && new URL(o).host !== url.host) return reply(403, { error: "Cross-site request refused" });

  try {
    if (route === "device/start") {
      const r = await nv("/device/authorize", { client_id: NV.clientId, scope: NV.scope });
      const j = r.json;
      if (!j || !j.device_code || !j.user_code) return reply(502, { error: `NVIDIA didn't return a device code (HTTP ${r.status}): ${clip(r.text)}` });
      s.pending = { dc: j.device_code, iv: j.interval || 5, exp: Date.now() + (j.expires_in || 600) * 1000 };
      await save();
      return reply(200, { user_code: j.user_code, verification_uri: j.verification_uri, verification_uri_complete: j.verification_uri_complete, expires_in: j.expires_in || 600, interval: s.pending.iv });
    }
    if (route === "device/poll") {
      if (!s.pending) return reply(400, { error: "No login in progress" });
      if (Date.now() > s.pending.exp) { delete s.pending; await save(); return reply(200, { status: "expired" }); }
      const r = await nv("/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: s.pending.dc, client_id: NV.clientId });
      if (r.json && r.json.access_token) {
        s.tokens = { access: r.json.access_token, refresh: r.json.refresh_token, id: r.json.id_token, at: Date.now() };
        delete s.pending; await save(); return reply(200, { status: "ok" });
      }
      const e = r.json && r.json.error;
      if (e === "authorization_pending") return reply(200, { status: "pending", interval: s.pending.iv });
      if (e === "slow_down") { s.pending.iv += 5; await save(); return reply(200, { status: "pending", interval: s.pending.iv }); }
      if (e === "expired_token") { delete s.pending; await save(); return reply(200, { status: "expired" }); }
      if (e === "access_denied") { delete s.pending; await save(); return reply(200, { status: "denied" }); }
      return reply(200, { status: "error", error: `NVIDIA replied (HTTP ${r.status}): ${clip(e ? e + " " + (r.json.error_description || "") : r.text)}` });
    }
    if (route === "logout") { await env.RGFN.delete(key); return reply(200, { ok: true }); }
    return reply(404, { error: "Unknown route" });
  } catch (e) { return reply(502, { error: clip(e.message) }); }
}
