export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }), request);

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return cors(json({ ok: true, service: "nova-customer-worker" }), request);
    }

    if (request.method !== "POST" || url.pathname !== "/verify") {
      return cors(json({ ok: false, code: "NOT_FOUND", msg: "Use POST /verify" }, 404), request);
    }

    const allow = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin") || "";
    if (allow.length && origin && !allow.includes(origin)) {
      return cors(json({ ok: false, code: "ORIGIN_BLOCKED", msg: "Origin not allowed" }, 403), request);
    }

    let body = {};
    try {
      body = await request.json();
    } catch {
      return cors(json({ ok: false, code: "BAD_JSON", msg: "Invalid JSON body" }, 400), request);
    }

    const key = String(body.key || "").trim();
    const device_id = String(body.device_id || "").trim();
    if (!key) return cors(json({ ok: false, code: "MISSING_KEY", msg: "Missing key" }, 400), request);
    if (!device_id) return cors(json({ ok: false, code: "MISSING_DEVICE_ID", msg: "Missing device_id" }, 400), request);

    const verifyUrl = env.SUPABASE_VERIFY_URL || env.VERIFY_URL;
    const username = env.NOVA_USERNAME || "";
    const userSecret = env.NOVA_USER_HMAC_SECRET || "";
    if (!verifyUrl || !username || !userSecret) {
      return cors(json({ ok: false, code: "SERVER_MISCONFIG", msg: "Missing worker env" }, 500), request);
    }

    const ts = Math.floor(Date.now() / 1000);
    const message = `${username}|${key}|${device_id}|${ts}`;
    const sig_user = await hmacHex(userSecret, message);

    const headers = { "Content-Type": "application/json" };
    if (env.NOVA_HMAC_HEADER) headers["Hmac"] = env.NOVA_HMAC_HEADER;

    const upstream = await fetch(verifyUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ username, key, device_id, ts, sig_user }),
    });

    const text = await upstream.text();
    return cors(new Response(text, { status: upstream.status, headers: { "Content-Type": "application/json" } }), request);
  },
};

async function hmacHex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

function cors(response, request) {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", request.headers.get("Origin") || "*");
  headers.set("Access-Control-Allow-Headers", "Content-Type");
  headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  return new Response(response.body, { status: response.status, headers });
}
