// Worker du hub : sert le site statique et gère les comptes (inscription, connexion).
// /admin est réservé aux comptes de rôle "admin".
// À configurer dans Cloudflare : le secret SESSION_SECRET et la base D1 liée sous le nom DB.

const COOKIE = "pk_session";
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000; // maximum accepté par Cloudflare Workers
const enc = new TextEncoder();
let schemaReady = false;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const isPost = request.method === "POST";

    if (isPost && (path === "/login" || path === "/login/")) return login(request, env, url);
    if (isPost && (path === "/signup" || path === "/signup/")) return signup(request, env, url);
    if (path === "/logout") return redirect(`${url.origin}/`, clearCookie());
    if (path === "/api/me") return me(request, env);

    if (path.startsWith("/admin")) {
      const user = await currentUser(request, env);
      if (!user) return redirect(`${url.origin}/login/?next=/admin/`);
      if (user.role !== "admin") return redirect(`${url.origin}/`);
    }

    return env.ASSETS.fetch(request);
  }
};

async function signup(request, env, url) {
  const form = await request.formData();
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  const confirm = String(form.get("confirm") || "");
  const fail = (code) => redirect(`${url.origin}/signup/?erreur=${code}`);

  if (!env.SESSION_SECRET) return fail("config");
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) return fail("pseudo");
  if (password.length < 8) return fail("court");
  if (password !== confirm) return fail("confirm");

  await ensureSchema(env);

  // Le pseudo est unique sans tenir compte des majuscules : la base refuse un doublon
  try {
    const res = await env.DB.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
      .bind(username, await hashPassword(password))
      .run();

    return startSession(url, env, res.meta.last_row_id, "/");
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return fail("pris");
    throw e;
  }
}

async function login(request, env, url) {
  const form = await request.formData();
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  const next = safeNext(form.get("next"));
  const fail = redirect(`${url.origin}/login/?erreur=1&next=${encodeURIComponent(next)}`);

  if (!env.SESSION_SECRET) return fail;

  await ensureSchema(env);
  const user = await env.DB.prepare("SELECT id, password FROM users WHERE username = ?").bind(username).first();
  if (!user || !(await checkPassword(password, user.password))) return fail;

  return startSession(url, env, user.id, next);
}

async function me(request, env) {
  const user = await currentUser(request, env);
  const body = user ? { user: user.username, admin: user.role === "admin" } : { user: null };

  return Response.json(body, { headers: { "Cache-Control": "no-store" } });
}

// Jeton de session = id du compte + date d'expiration + signature, impossible à fabriquer sans SESSION_SECRET
async function startSession(url, env, uid, next) {
  const payload = `${uid}.${Date.now() + SESSION_DAYS * 86400000}`;
  const token = `${payload}.${await sign(payload, env)}`;

  return redirect(`${url.origin}${next}`, sessionCookie(token));
}

async function currentUser(request, env) {
  if (!env.SESSION_SECRET) return null;

  const token = readCookie(request);
  if (!token) return null;

  const [uid, exp, sig] = token.split(".");
  if (!uid || !exp || !sig || Number(exp) < Date.now()) return null;
  if (!sameBytes(enc.encode(sig), enc.encode(await sign(`${uid}.${exp}`, env)))) return null;

  await ensureSchema(env);

  return env.DB.prepare("SELECT username, role FROM users WHERE id = ?").bind(Number(uid)).first();
}

// Crée la table des comptes au premier besoin, une fois par instance du Worker
async function ensureSchema(env) {
  if (schemaReady) return;

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  schemaReady = true;
}

// Mot de passe stocké sous forme "sel:empreinte" (PBKDF2), jamais en clair
async function hashPassword(password, saltHex) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS }, key, 256
  );

  return `${toHex(salt)}:${toHex(new Uint8Array(bits))}`;
}

async function checkPassword(password, stored) {
  const [saltHex] = stored.split(":");

  return sameBytes(enc.encode(await hashPassword(password, saltHex)), enc.encode(stored));
}

async function sign(text, env) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`session:${text}`));

  return toHex(new Uint8Array(sig));
}

// Comparaison en temps constant : ne révèle pas à partir de quel caractère ça diffère
function sameBytes(a, b) {
  if (a.length !== b.length) return false;

  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];

  return diff === 0;
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  return new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
}

// Après connexion, on ne renvoie que vers une page du hub (pas vers un autre site)
function safeNext(value) {
  const next = String(value || "/");

  return /^\/(?![\/\\])/.test(next) ? next : "/";
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
