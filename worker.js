// Worker du hub : sert le site statique, gère les comptes (inscription, connexion)
// et les cartes du hub (stockées en base, gérées depuis /admin, réservé au rôle "admin").
// À configurer dans Cloudflare : le secret SESSION_SECRET et la base D1 liée sous le nom DB.

const COOKIE = "pk_session";
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 100000; // maximum accepté par Cloudflare Workers
const enc = new TextEncoder();
let schemaReady = false;

// Cartes écrites en dur dans la page avant la gestion par l'admin : recopiées en base à la création de la table
const SEED_CARDS = [
  ["🃏", "Card Viewer", "Classeur virtuel de cartes Pokémon : parcours et organise ta collection.", "https://cardviewer.pikilab.app"],
  ["🕵️", "Undercover", "Le jeu de bluff entre amis : démasque l'imposteur avant qu'il ne devine le mot.", "https://undercover.pikilab.app"],
  ["🎬", "Random Movie", "Pas d'idée pour ce soir ? Tire un film au hasard et lance la séance.", "https://random-movie.pikilab.app"],
  ["🎧", "Anime Blind Test", "Reconnais l'opening d'animé le plus vite possible et marque des points.", "https://anime-blindtest.pikilab.app"],
  ["⚔️", "Donjon Survivor", "Roguelite d'action : descends les étages, améliore ton perso et survis le plus longtemps.", "https://donjon-survivor.pikilab.app"],
  ["🖱️", "Clicker", "Jeu incrémental : clique, accumule et débloque des améliorations sans fin.", "https://clicker.pikilab.app"],
  ["🗣️", "Language Learner", "Apprends du vocabulaire et révise à ton rythme, une session à la fois.", "https://language.pikilab.app"]
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const isPost = request.method === "POST";

    if (isPost && (path === "/login" || path === "/login/")) return login(request, env, url);
    if (isPost && (path === "/signup" || path === "/signup/")) return signup(request, env, url);
    if (path === "/logout") return redirect(`${url.origin}/`, clearCookie());
    if (path === "/api/me") return me(request, env);
    if (path === "/" && request.method === "GET") return renderHub(env, url);

    if (path === "/api/cards" && request.method === "GET") return json(await listCards(env));
    if (path === "/api/cards" && isPost) return addCard(request, env, url);
    if (path === "/api/cards/order" && isPost) return reorderCards(request, env, url);

    const cardId = path.match(/^\/api\/cards\/(\d+)$/);
    if (cardId && request.method === "PUT") return updateCard(request, env, url, Number(cardId[1]));
    if (cardId && request.method === "DELETE") return deleteCard(request, env, url, Number(cardId[1]));

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

  return json(user ? { user: user.username, admin: user.role === "admin" } : { user: null });
}

// Page d'accueil : on insère les cartes de la base à la place du repère <!-- CARTES -->
async function renderHub(env, url) {
  const cards = await listCards(env);
  const page = await env.ASSETS.fetch(new Request(`${url.origin}/`));
  const html = (await page.text()).replace("<!-- CARTES -->", cards.map(cardHtml).join(""));

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" }
  });
}

function cardHtml(card) {
  return `
      <a class="card" href="${escapeHtml(card.url)}" target="_blank" rel="noopener">
        <span class="emoji">${escapeHtml(card.emoji)}</span>
        <h2>${escapeHtml(card.title)}</h2>
        <p>${escapeHtml(card.description)}</p>
        <span class="url">${escapeHtml(shortUrl(card.url))}</span>
      </a>`;
}

// "https://clicker.pikilab.app/" -> "clicker.pikilab.app"
function shortUrl(link) {
  const u = new URL(link);

  return (u.host + u.pathname).replace(/\/$/, "");
}

function escapeHtml(text) {
  const chars = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

  return String(text).replace(/[&<>"']/g, (c) => chars[c]);
}

async function listCards(env) {
  await ensureSchema(env);
  const { results } = await env.DB
    .prepare("SELECT id, emoji, title, description, url FROM cards ORDER BY position, id")
    .all();

  return results;
}

async function addCard(request, env, url) {
  const denied = await requireAdmin(request, env, url);
  if (denied) return denied;

  const { card, error } = readCard(await request.json().catch(() => ({})));
  if (error) return json({ error }, 400);

  // Nouvelle carte placée en dernier
  await ensureSchema(env);
  await env.DB.prepare(`INSERT INTO cards (emoji, title, description, url, position)
    VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM cards))`)
    .bind(card.emoji, card.title, card.description, card.url)
    .run();

  return json({ ok: true });
}

async function updateCard(request, env, url, id) {
  const denied = await requireAdmin(request, env, url);
  if (denied) return denied;

  const { card, error } = readCard(await request.json().catch(() => ({})));
  if (error) return json({ error }, 400);

  await ensureSchema(env);
  await env.DB.prepare("UPDATE cards SET emoji = ?, title = ?, description = ?, url = ? WHERE id = ?")
    .bind(card.emoji, card.title, card.description, card.url, id)
    .run();

  return json({ ok: true });
}

// Reçoit la liste des id dans le nouvel ordre et renumérote les positions
async function reorderCards(request, env, url) {
  const denied = await requireAdmin(request, env, url);
  if (denied) return denied;

  const { ids } = await request.json().catch(() => ({}));
  if (!Array.isArray(ids) || !ids.every(Number.isInteger)) return json({ error: "Ordre invalide." }, 400);

  await ensureSchema(env);
  if (ids.length) {
    await env.DB.batch(ids.map((id, i) =>
      env.DB.prepare("UPDATE cards SET position = ? WHERE id = ?").bind(i + 1, id)
    ));
  }

  return json({ ok: true });
}

async function deleteCard(request, env, url, id) {
  const denied = await requireAdmin(request, env, url);
  if (denied) return denied;

  await ensureSchema(env);
  await env.DB.prepare("DELETE FROM cards WHERE id = ?").bind(id).run();

  return json({ ok: true });
}

// Vérifie et nettoie les champs d'une carte envoyés par le formulaire admin
function readCard(data) {
  const card = {
    emoji: String(data.emoji || "").trim() || "🧪",
    title: String(data.title || "").trim(),
    description: String(data.description || "").trim(),
    url: String(data.url || "").trim()
  };

  if (!card.title || card.title.length > 60) return { error: "Le titre est obligatoire (60 caractères max)." };
  if (card.description.length > 200) return { error: "La description est trop longue (200 caractères max)." };
  if ([...card.emoji].length > 8) return { error: "L'emoji est trop long." };

  // Accepte "monsite.pikilab.app" sans https://
  if (!/^https?:\/\//i.test(card.url)) card.url = `https://${card.url}`;

  try {
    const u = new URL(card.url);
    if (!u.hostname.includes(".")) return { error: "Le lien n'est pas valide." };
    card.url = u.toString();
  } catch {
    return { error: "Le lien n'est pas valide." };
  }

  return { card };
}

// Modifications réservées à l'admin, et seulement depuis le hub lui-même (pas depuis un autre site ou sous-domaine)
async function requireAdmin(request, env, url) {
  if (request.headers.get("Origin") !== url.origin) return json({ error: "Requête refusée." }, 403);

  const user = await currentUser(request, env);
  if (!user || user.role !== "admin") return json({ error: "Réservé à l'admin." }, 403);

  return null;
}

function json(body, status = 200) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
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

// Crée les tables au premier besoin, une fois par instance du Worker
async function ensureSchema(env) {
  if (schemaReady) return;

  const hadCards = await env.DB
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'cards'")
    .first();

  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS cards (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      emoji       TEXT NOT NULL,
      title       TEXT NOT NULL,
      description TEXT NOT NULL,
      url         TEXT NOT NULL,
      position    INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    )`)
  ]);

  // Table des cartes toute neuve : on y recopie les cartes d'origine (id fixes, donc pas de doublon si deux instances le font)
  if (!hadCards) {
    await env.DB.batch(SEED_CARDS.map(([emoji, title, description, link], i) =>
      env.DB.prepare("INSERT OR IGNORE INTO cards (id, emoji, title, description, url, position) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(i + 1, emoji, title, description, link, i + 1)
    ));
  }

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
