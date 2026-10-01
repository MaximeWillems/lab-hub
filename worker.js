// Worker du hub : sert le site statique et réserve /admin à PIKI (mot de passe).
// Secrets à définir dans Cloudflare : ADMIN_PASSWORD et SESSION_SECRET.

const COOKIE = "pk_session";
const SESSION_DAYS = 30;
const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if ((path === "/login" || path === "/login/") && request.method === "POST") {
      return login(request, env, url);
    }

    if (path === "/logout") {
      return redirect(`${url.origin}/`, clearCookie());
    }

    if (path.startsWith("/admin") && !(await isLoggedIn(request, env))) {
      return redirect(`${url.origin}/login/`);
    }

    return env.ASSETS.fetch(request);
  }
};

async function login(request, env, url) {
  const form = await request.formData();
  const password = String(form.get("password") || "");

  // Sans secrets configurés, personne ne peut se connecter
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return redirect(`${url.origin}/login/?erreur=1`);

  const ok = sameBytes(await sha256(password), await sha256(env.ADMIN_PASSWORD));
  if (!ok) return redirect(`${url.origin}/login/?erreur=1`);

  const exp = Date.now() + SESSION_DAYS * 86400000;
  const token = `${exp}.${await sign(String(exp), env)}`;

  return redirect(`${url.origin}/admin/`, sessionCookie(token));
}

// Le jeton de session = date d'expiration + signature, impossible à fabriquer sans SESSION_SECRET
async function isLoggedIn(request, env) {
  if (!env.SESSION_SECRET) return false;

  const token = readCookie(request);
  if (!token) return false;

  const [exp, sig] = token.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;

  return sameBytes(enc.encode(sig), enc.encode(await sign(exp, env)));
}

async function sign(text, env) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`session:${text}`));

  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

// Comparaison en temps constant : ne révèle pas à partir de quel caractère ça diffère
function sameBytes(a, b) {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];

  return diff === 0;
}

function readCookie(request) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));

  return match ? match[1] : null;
}

// Cookie limité au hub pour l'instant ; pour le partager aux sous-sites plus tard : ajouter "; Domain=pikilab.app"
function sessionCookie(token) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

function clearCookie() {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function redirect(location, cookie) {
  const headers = { Location: location };
  if (cookie) headers["Set-Cookie"] = cookie;

  return new Response(null, { status: 303, headers });
}
