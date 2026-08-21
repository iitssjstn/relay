const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { getSecret } = require('./secrets');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const COOKIE_NAME = 'relay_session';

// JWT secret: via Docker Secret/env var indien opgegeven (optioneel),
// anders genereren we er zelf één en bewaren die in de data-map zodat
// sessies een herstart van de container overleven. Hier is dus geen
// handmatige stap voor nodig.
let JWT_SECRET = getSecret('jwt_secret', 'JWT_SECRET');
if (!JWT_SECRET) {
  const secretFile = path.join(DATA_DIR, '.jwt_secret');
  if (fs.existsSync(secretFile)) {
    JWT_SECRET = fs.readFileSync(secretFile, 'utf8').trim();
  } else {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(secretFile, JWT_SECRET, { mode: 0o600 });
  }
}

const app = express();
// Security headers — CSP is bewust afgestemd op precies wat deze app nodig
// heeft: alle logica zit in één inline <script>/<style> in index.html (dus
// 'unsafe-inline' nodig, er zijn hier geen nonces toegepast), plus drie
// vaste CDN-bibliotheken (marked/DOMPurify/JSZip) en Google Fonts. Externe
// AI-providers worden nooit rechtstreeks vanuit de browser aangeroepen —
// dat loopt allemaal via /api/relay-proxy — dus connect-src blijft 'self'.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'self'"]
    }
  },
  // Uitgeschakeld omdat dit vereist dat cross-origin bronnen (zoals de
  // CDN-scripts hierboven) expliciet CORP/CORS-headers meesturen — dat
  // risico op het onterecht blokkeren van die scripts weegt hier niet op
  // tegen de beperkte meerwaarde voor een self-hosted, persoonlijke tool.
  crossOriginEmbedderPolicy: false
}));
// 25mb i.p.v. 5mb — gesprekken kunnen nu base64-gecodeerde afbeeldingen
// bevatten, die aanmerkelijk groter zijn dan platte tekst.
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.set('trust proxy', 1); // NPM zit ervoor als reverse proxy

// Beperkt brute-force-pogingen op inloggen/registreren — ruim genoeg voor
// eigen typefouten, maar blokkeert herhaald geautomatiseerd gokken.
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Te veel pogingen — probeer het over een kwartier opnieuw.' }
});

// ---------- Health endpoints (voor Docker HEALTHCHECK en eventuele monitoring) ----------

// Simpele "leeft het proces nog"-check, zonder afhankelijkheden te raken —
// blijft dus ook OK als de database bijvoorbeeld héél even niet reageert.
app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok' }));

// "Is de app daadwerkelijk klaar om verzoeken af te handelen" — controleert
// of de database bereikbaar is, wat healthz bewust niet doet.
app.get('/readyz', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.status(200).json({ status: 'ok' });
  } catch (e) {
    res.status(503).json({ status: 'niet klaar', error: e.message });
  }
});

// ---------- Settings helpers (registratiecode leeft in de database) ----------

function getSetting(key){
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value){
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}
function deleteSetting(key){
  db.prepare('DELETE FROM settings WHERE key = ?').run(key);
}
function userCount(){
  return db.prepare('SELECT COUNT(*) as n FROM users').get().n;
}

// ---------- Auth helpers ----------

function signToken(user) {
  return jwt.sign({ uid: user.id, username: user.username, isAdmin: !!user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'Niet ingelogd.' });
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Sessie verlopen, log opnieuw in.' });
  }
  // Het cookie zelf blijft geldig ondertekend nadat een account is
  // verwijderd (of geblokkeerd) — check daarom bij elk verzoek of het
  // account nog echt bestaat, i.p.v. alleen op de handtekening te vertrouwen.
  const user = db.prepare('SELECT id, username, is_admin FROM users WHERE id = ?').get(payload.uid);
  if (!user) {
    res.clearCookie(COOKIE_NAME);
    return res.status(401).json({ error: 'Dit account bestaat niet meer.' });
  }
  req.user = { uid: user.id, username: user.username, isAdmin: !!user.is_admin };
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) return res.status(403).json({ error: 'Alleen voor beheerders.' });
  next();
}

function setSessionCookie(res, user) {
  res.cookie(COOKIE_NAME, signToken(user), {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.FORCE_SECURE_COOKIE !== 'false',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

// ---------- Auth routes ----------

// Publiek: laat de frontend weten of dit de allereerste (beheerders)
// registratie is, zodat het registratiecode-veld dan verborgen kan worden.
app.get('/api/auth/bootstrap-status', (req, res) => {
  res.json({ bootstrap: userCount() === 0 });
});

app.post('/api/auth/register', authRateLimit, (req, res) => {
  const { username, password, registrationCode } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Vul gebruikersnaam en wachtwoord in.' });
  }
  if (username.length < 3 || password.length < 8) {
    return res.status(400).json({ error: 'Gebruikersnaam min. 3 tekens, wachtwoord min. 8 tekens.' });
  }

  const isFirstUser = userCount() === 0;

  if (!isFirstUser) {
    const codeHash = getSetting('registration_code_hash');
    if (!codeHash) {
      return res.status(403).json({ error: 'Registratie is momenteel gesloten. Vraag de beheerder om een registratiecode in te stellen.' });
    }
    if (!registrationCode || !bcrypt.compareSync(registrationCode, codeHash)) {
      return res.status(403).json({ error: 'Onjuiste registratiecode.' });
    }
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Gebruikersnaam is al in gebruik.' });

  const hash = bcrypt.hashSync(password, 12);
  const info = db.prepare(
    'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)'
  ).run(username, hash, isFirstUser ? 1 : 0, Date.now());
  const user = { id: info.lastInsertRowid, username, is_admin: isFirstUser ? 1 : 0 };
  db.prepare('INSERT INTO node_configs (user_id, config) VALUES (?, ?)')
    .run(user.id, JSON.stringify({ nodes: [], activeIndex: -1 }));

  setSessionCookie(res, user);
  res.json({ id: user.id, username: user.username, isAdmin: !!user.is_admin, isFirstUser });
});

app.post('/api/auth/login', authRateLimit, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Vul gebruikersnaam en wachtwoord in.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Onjuiste gebruikersnaam of wachtwoord.' });
  }
  setSessionCookie(res, user);
  res.json({ id: user.id, username: user.username, isAdmin: !!user.is_admin });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.uid, username: req.user.username, isAdmin: !!req.user.isAdmin });
});

// ---------- Conversations ----------

app.get('/api/conversations', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT id, title, updated_at as updatedAt FROM conversations WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.user.uid);
  res.json(rows);
});

app.get('/api/conversations/:id', requireAuth, (req, res) => {
  const row = db.prepare(
    'SELECT id, title, updated_at as updatedAt, messages FROM conversations WHERE id = ? AND user_id = ?'
  ).get(req.params.id, req.user.uid);
  if (!row) return res.status(404).json({ error: 'Gesprek niet gevonden.' });
  res.json({ ...row, messages: JSON.parse(row.messages) });
});

function upsertConversation(userId, convId, title, messages){
  const now = Date.now();
  const existing = db.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?')
    .get(convId, userId);
  if (existing) {
    db.prepare('UPDATE conversations SET title = ?, updated_at = ?, messages = ? WHERE id = ? AND user_id = ?')
      .run(title || 'Nieuw gesprek', now, JSON.stringify(messages), convId, userId);
  } else {
    db.prepare('INSERT INTO conversations (id, user_id, title, updated_at, messages) VALUES (?, ?, ?, ?, ?)')
      .run(convId, userId, title || 'Nieuw gesprek', now, JSON.stringify(messages));
  }
  return now;
}

app.put('/api/conversations/:id', requireAuth, (req, res) => {
  const { title, messages } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).json({ error: 'messages moet een array zijn.' });
  const updatedAt = upsertConversation(req.user.uid, req.params.id, title, messages);
  res.json({ ok: true, updatedAt });
});

// Speciaal voor navigator.sendBeacon() — die kan alleen POST versturen,
// geen PUT, en stuurt geen JSON-Content-Type mee als de payload een Blob
// is. Wordt uitsluitend gebruikt als laatste redmiddel vlak vóórdat de
// pagina verdwijnt (herlaadbeurt/sluiten), zodat een in-progress AI-
// antwoord niet volledig verloren gaat — zie het 'beforeunload'-gedrag
// aan de voorkant. Zelfde opslaglogica en autorisatie als de PUT hierboven.
app.post('/api/conversations/:id/beacon', requireAuth, (req, res) => {
  const { title, messages } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).end();
  upsertConversation(req.user.uid, req.params.id, title, messages);
  res.status(204).end();
});

app.delete('/api/conversations/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM conversations WHERE id = ? AND user_id = ?').run(req.params.id, req.user.uid);
  res.json({ ok: true });
});

// ---------- Node / provider config ----------

app.get('/api/nodes', requireAuth, (req, res) => {
  const row = db.prepare('SELECT config FROM node_configs WHERE user_id = ?').get(req.user.uid);
  res.json(row ? JSON.parse(row.config) : { nodes: [], activeIndex: -1 });
});

app.put('/api/nodes', requireAuth, (req, res) => {
  const { nodes, activeIndex } = req.body || {};
  if (!Array.isArray(nodes)) return res.status(400).json({ error: 'nodes moet een array zijn.' });
  const config = JSON.stringify({ nodes, activeIndex: typeof activeIndex === 'number' ? activeIndex : -1 });
  const existing = db.prepare('SELECT user_id FROM node_configs WHERE user_id = ?').get(req.user.uid);
  if (existing) {
    db.prepare('UPDATE node_configs SET config = ? WHERE user_id = ?').run(config, req.user.uid);
  } else {
    db.prepare('INSERT INTO node_configs (user_id, config) VALUES (?, ?)').run(req.user.uid, config);
  }
  res.json({ ok: true });
});

// ---------- Geheugen (gestructureerd: losse, benoemde items per categorie) ----------

const MEMORY_ENTRY_MAX_CHARS = 3000;
const MEMORY_TITLE_MAX_CHARS = 80;
const MEMORY_MAX_ENTRIES = 40; // redelijke bovengrens, voorkomt een oneindig groeiend systeembericht
const MEMORY_CATEGORIES = ['profile', 'topic', 'area'];

app.get('/api/memory-settings', requireAuth, (req, res) => {
  const row = db.prepare('SELECT memory_auto_update FROM users WHERE id = ?').get(req.user.uid);
  res.json({ autoUpdate: !!(row && row.memory_auto_update) });
});

app.put('/api/memory-settings', requireAuth, (req, res) => {
  const autoUpdate = req.body && req.body.autoUpdate ? 1 : 0;
  db.prepare('UPDATE users SET memory_auto_update = ? WHERE id = ?').run(autoUpdate, req.user.uid);
  res.json({ autoUpdate: !!autoUpdate });
});

app.get('/api/memory-entries', requireAuth, (req, res) => {
  const rows = db.prepare(
    'SELECT id, category, title, content, updated_at as updatedAt FROM memory_entries WHERE user_id = ? ORDER BY updated_at DESC'
  ).all(req.user.uid);
  res.json(rows);
});

function validateMemoryEntry(body){
  const category = MEMORY_CATEGORIES.includes(body.category) ? body.category : 'topic';
  const title = (body.title || '').toString().trim().slice(0, MEMORY_TITLE_MAX_CHARS);
  const content = (body.content || '').toString().slice(0, MEMORY_ENTRY_MAX_CHARS);
  if (!title) return null;
  return { category, title, content };
}

app.post('/api/memory-entries', requireAuth, (req, res) => {
  const entry = validateMemoryEntry(req.body || {});
  if (!entry) return res.status(400).json({ error: 'Titel is verplicht.' });
  const count = db.prepare('SELECT COUNT(*) as n FROM memory_entries WHERE user_id = ?').get(req.user.uid).n;
  if (count >= MEMORY_MAX_ENTRIES) {
    return res.status(400).json({ error: `Maximaal ${MEMORY_MAX_ENTRIES} geheugen-items.` });
  }
  const now = Date.now();
  const info = db.prepare(
    'INSERT INTO memory_entries (user_id, category, title, content, updated_at) VALUES (?, ?, ?, ?, ?)'
  ).run(req.user.uid, entry.category, entry.title, entry.content, now);
  res.json({ id: info.lastInsertRowid, ...entry, updatedAt: now });
});

app.put('/api/memory-entries/:id', requireAuth, (req, res) => {
  const entry = validateMemoryEntry(req.body || {});
  if (!entry) return res.status(400).json({ error: 'Titel is verplicht.' });
  const existing = db.prepare('SELECT id FROM memory_entries WHERE id = ? AND user_id = ?').get(req.params.id, req.user.uid);
  if (!existing) return res.status(404).json({ error: 'Niet gevonden.' });
  const now = Date.now();
  db.prepare(
    'UPDATE memory_entries SET category = ?, title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?'
  ).run(entry.category, entry.title, entry.content, now, req.params.id, req.user.uid);
  res.json({ id: Number(req.params.id), ...entry, updatedAt: now });
});

app.delete('/api/memory-entries/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM memory_entries WHERE id = ? AND user_id = ?').run(req.params.id, req.user.uid);
  res.json({ ok: true });
});

// ---------- GitHub-integratie ----------
//
// Optioneel per account: een GitHub Personal Access Token, nodig voor
// privé-repo's en om de (vrij lage) anonieme rate limit van GitHub te
// omzeilen. De token wordt nooit teruggegeven aan de browser na het
// opslaan — alleen of er wel/niet één is ingesteld.

function parseGithubFileUrl(rawUrl){
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  const parts = u.pathname.split('/').filter(Boolean);
  if (u.hostname === 'github.com' && parts.length >= 5 && parts[2] === 'blob') {
    return { owner: parts[0], repo: parts[1], branch: parts[3], path: parts.slice(4).join('/') };
  }
  if (u.hostname === 'raw.githubusercontent.com' && parts.length >= 4) {
    return { owner: parts[0], repo: parts[1], branch: parts[2], path: parts.slice(3).join('/') };
  }
  return null;
}

function parseGithubRepoUrl(rawUrl){
  let u;
  try { u = new URL(rawUrl); } catch { return null; }
  if (u.hostname !== 'github.com') return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  // Alleen echte repo-(sub)paden toestaan, geen /blob/-links (die zijn al
  // eerder afgehandeld) en geen andere GitHub-secties zoals /settings etc.
  if (parts[2] && !['tree', 'blob'].includes(parts[2])) return null;
  const owner = parts[0], repo = parts[1];
  const branch = (parts[2] === 'tree' && parts[3]) ? parts[3] : null;
  return { owner, repo, branch };
}

async function ghApiFetch(url, token){
  return fetch(url, {
    headers: {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'Relay-App',
      ...(token ? { Authorization: `token ${token}` } : {})
    }
  });
}

const GH_SKIP_DIR_PATTERN = /(^|\/)(node_modules|\.git|dist|build|vendor|coverage|__pycache__|\.next|\.venv|venv|target|out|bin|obj)(\/|$)/i;
const GH_BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|svg|bmp|pdf|zip|tar|gz|7z|rar|mp3|mp4|mov|avi|woff2?|ttf|eot|otf|exe|dll|so|dylib|class|jar|wasm|lock|ttf)$/i;

app.get('/api/github-token', requireAuth, (req, res) => {
  const row = db.prepare('SELECT github_token FROM users WHERE id = ?').get(req.user.uid);
  res.json({ hasToken: !!(row && row.github_token) });
});

app.put('/api/github-token', requireAuth, (req, res) => {
  const { token } = req.body || {};
  db.prepare('UPDATE users SET github_token = ? WHERE id = ?').run(token || null, req.user.uid);
  res.json({ ok: true });
});

// ---------- E2B (code laten draaien in een externe, geïsoleerde sandbox) ----------

app.get('/api/e2b-token', requireAuth, (req, res) => {
  const row = db.prepare('SELECT e2b_api_key FROM users WHERE id = ?').get(req.user.uid);
  res.json({ hasToken: !!(row && row.e2b_api_key) });
});

app.put('/api/e2b-token', requireAuth, (req, res) => {
  const { token } = req.body || {};
  db.prepare('UPDATE users SET e2b_api_key = ? WHERE id = ?').run(token || null, req.user.uid);
  res.json({ ok: true });
});

// Talen die E2B's code-interpreter native ondersteunt. Andere bestands-
// talen (bv. yaml, html) zijn geen "uitvoerbare taal" en komen dus niet in
// aanmerking voor de uitvoer-knop aan de voorkant.
const E2B_LANGUAGES = ['python', 'javascript', 'typescript', 'r', 'java', 'bash'];
const EXECUTE_TIMEOUT_MS = 45000; // ruim genoeg voor een script, geen langlopende dienst

app.post('/api/execute', requireAuth, async (req, res) => {
  const { language, content } = req.body || {};
  if (!language || !E2B_LANGUAGES.includes(language)) {
    return res.status(400).json({ error: 'Deze taal wordt niet ondersteund voor uitvoering.' });
  }
  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'Geen code om uit te voeren.' });
  }
  const row = db.prepare('SELECT e2b_api_key FROM users WHERE id = ?').get(req.user.uid);
  const apiKey = row && row.e2b_api_key;
  if (!apiKey) {
    return res.status(400).json({ error: 'Nog geen E2B API-key ingesteld. Voeg die eerst toe via het accountmenu.' });
  }

  let sandbox = null;
  const timer = setTimeout(() => {
    // Vangnet: mocht E2B zelf onverhoopt blijven hangen, sluit de sandbox
    // en het verzoek toch netjes af in plaats van de gebruiker eindeloos
    // te laten wachten.
    if (sandbox) sandbox.kill().catch(() => {});
  }, EXECUTE_TIMEOUT_MS);

  try {
    const { Sandbox } = require('@e2b/code-interpreter');
    sandbox = await Sandbox.create({ apiKey, timeoutMs: EXECUTE_TIMEOUT_MS });
    const execution = await sandbox.runCode(content, { language });
    res.json({
      stdout: (execution.logs && execution.logs.stdout || []).join('\n'),
      stderr: (execution.logs && execution.logs.stderr || []).join('\n'),
      error: execution.error ? (execution.error.name + ': ' + execution.error.value) : null,
      results: (execution.results || []).map(r => r.text).filter(Boolean)
    });
  } catch (e) {
    const msg = /api ?key/i.test(e.message || '') ? 'Ongeldige E2B API-key.' : ('Uitvoering mislukt: ' + e.message);
    res.status(502).json({ error: msg });
  } finally {
    clearTimeout(timer);
    if (sandbox) sandbox.kill().catch(() => {});
  }
});

app.post('/api/github/fetch', requireAuth, async (req, res) => {
  const { url } = req.body || {};
  const row = db.prepare('SELECT github_token FROM users WHERE id = ?').get(req.user.uid);
  const token = row && row.github_token;

  // Eerst proberen als link naar één specifiek bestand...
  const fileParsed = parseGithubFileUrl(url || '');
  if (fileParsed) {
    return handleGithubFileFetch(fileParsed, token, res);
  }

  // ...anders proberen als link naar een hele repo.
  const repoParsed = parseGithubRepoUrl(url || '');
  if (repoParsed) {
    return handleGithubRepoFetch(repoParsed, token, res);
  }

  res.status(400).json({ error: 'Kon geen geldige GitHub-link herkennen. Gebruik een link naar een bestand (…/blob/…) of naar een hele repo (github.com/eigenaar/repo).' });
});

async function handleGithubFileFetch(parsed, token, res){
  const apiUrl = `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/contents/${parsed.path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(parsed.branch)}`;
  try {
    const ghRes = await ghApiFetch(apiUrl, token);
    if (!ghRes.ok) {
      const errBody = await ghRes.json().catch(() => ({}));
      const msg = ghRes.status === 404
        ? 'Bestand niet gevonden (of privé zonder geldige token).'
        : (errBody.message || ('GitHub gaf status ' + ghRes.status));
      return res.status(ghRes.status).json({ error: msg });
    }
    const data = await ghRes.json();
    if (Array.isArray(data)) {
      return res.status(400).json({ error: 'Dit is een map, geen bestand. Geef een link naar een specifiek bestand, of naar de repo als geheel.' });
    }
    let content;
    if (data.content && data.encoding === 'base64') {
      content = Buffer.from(data.content, 'base64').toString('utf-8');
    } else if (data.download_url) {
      const rawRes = await fetch(data.download_url, { headers: { 'User-Agent': 'Relay-App' } });
      content = await rawRes.text();
    } else {
      return res.status(400).json({ error: 'Kon de inhoud van dit bestand niet ophalen (mogelijk een binair bestand).' });
    }
    const MAX_CHARS = 60000;
    let truncated = false;
    if (content.length > MAX_CHARS) { content = content.slice(0, MAX_CHARS); truncated = true; }
    res.json({ kind: 'file', name: data.name, path: data.path, content, truncated });
  } catch (e) {
    res.status(502).json({ error: 'Kon GitHub niet bereiken: ' + e.message });
  }
}

async function handleGithubRepoFetch(parsed, token, res){
  try {
    let branch = parsed.branch;
    if (!branch) {
      const repoRes = await ghApiFetch(`https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`, token);
      if (!repoRes.ok) {
        const errBody = await repoRes.json().catch(() => ({}));
        const msg = repoRes.status === 404
          ? 'Repo niet gevonden (of privé zonder geldige token).'
          : (errBody.message || ('GitHub gaf status ' + repoRes.status));
        return res.status(repoRes.status).json({ error: msg });
      }
      branch = (await repoRes.json()).default_branch;
    }

    const treeRes = await ghApiFetch(`https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`, token);
    if (!treeRes.ok) {
      const errBody = await treeRes.json().catch(() => ({}));
      return res.status(treeRes.status).json({ error: errBody.message || ('GitHub gaf status ' + treeRes.status) });
    }
    const treeData = await treeRes.json();
    if (!treeData.tree) return res.status(400).json({ error: 'Kon de bestandsstructuur niet ophalen.' });

    const allBlobs = treeData.tree.filter(item => item.type === 'blob');
    let candidates = allBlobs.filter(item =>
      !GH_SKIP_DIR_PATTERN.test(item.path) &&
      !GH_BINARY_EXT.test(item.path) &&
      (item.size == null || item.size < 100000)
    );

    // Belangrijke bestanden eerst (README, package.json, etc.), dan
    // gewoon bestanden in de hoofdmap, dan de rest.
    const priority = (p) => {
      const lower = p.toLowerCase();
      if (/^readme/.test(lower)) return 0;
      if (/^(package\.json|requirements\.txt|go\.mod|cargo\.toml|pyproject\.toml)$/.test(lower)) return 1;
      if (!lower.includes('/')) return 2;
      return 3;
    };
    candidates = candidates.sort((a, b) => priority(a.path) - priority(b.path));

    const MAX_FILES = 40;
    const MAX_TOTAL_CHARS = 150000;
    let totalChars = 0;
    const files = [];
    let skippedCount = 0;

    for (const item of candidates) {
      if (files.length >= MAX_FILES || totalChars >= MAX_TOTAL_CHARS) { skippedCount++; continue; }
      try {
        const blobRes = await ghApiFetch(`https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/git/blobs/${item.sha}`, token);
        if (!blobRes.ok) { skippedCount++; continue; }
        const blobData = await blobRes.json();
        if (blobData.encoding !== 'base64') { skippedCount++; continue; }
        let content;
        try { content = Buffer.from(blobData.content, 'base64').toString('utf-8'); }
        catch { skippedCount++; continue; }
        if (content.includes('\u0000')) { skippedCount++; continue; } // ruwe binaire-detectie
        if (totalChars + content.length > MAX_TOTAL_CHARS) {
          content = content.slice(0, MAX_TOTAL_CHARS - totalChars);
        }
        totalChars += content.length;
        files.push({ path: item.path, content });
      } catch { skippedCount++; }
    }

    res.json({
      kind: 'repo',
      owner: parsed.owner, repo: parsed.repo, branch,
      files,
      totalFilesInRepo: allBlobs.length,
      includedCount: files.length,
      skippedCount,
      totalChars
    });
  } catch (e) {
    res.status(502).json({ error: 'Kon GitHub niet bereiken: ' + e.message });
  }
}

// ---------- Admin: toegang & gebruikersbeheer ----------

app.get('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  res.json({
    registrationOpen: !!getSetting('registration_code_hash'),
    // Alleen zichtbaar voor beheerders — nodig om de uitnodigingslink op
    // elk moment opnieuw te kunnen tonen, niet alleen direct na instellen.
    code: getSetting('registration_code_plain') || null
  });
});

app.put('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  const { code } = req.body || {};
  if (!code || code.length < 6) {
    return res.status(400).json({ error: 'Kies een registratiecode van minstens 6 tekens.' });
  }
  setSetting('registration_code_hash', bcrypt.hashSync(code, 12));
  setSetting('registration_code_plain', code);
  res.json({ ok: true });
});

app.delete('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  deleteSetting('registration_code_hash');
  deleteSetting('registration_code_plain');
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, is_admin as isAdmin, created_at as createdAt FROM users ORDER BY created_at ASC').all();
  res.json(rows.map(r => ({ ...r, isAdmin: !!r.isAdmin })));
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.user.uid) {
    return res.status(400).json({ error: 'Je kunt je eigen account hier niet verwijderen.' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  res.json({ ok: true });
});

// ---------- AI-provider proxy ----------
//
// Sommige providers (o.a. Groq) staan geen rechtstreekse browser->API-
// aanroepen toe (CORS-blokkade). De server heeft daar geen last van, dus
// alle AI-aanroepen lopen voortaan via deze proxy: browser -> Relay-server
// -> provider -> (gestreamd) terug naar de browser. De API-key van de
// gebruiker gaat hierbij alleen naar de provider zelf, nooit ergens anders
// heen — Relay leest of bewaart de inhoud van het antwoord niet.

const RATE_LIMIT_HEADER_ALLOWLIST = [
  'content-type',
  'x-ratelimit-limit-requests', 'x-ratelimit-remaining-requests', 'x-ratelimit-reset-requests',
  'x-ratelimit-limit-tokens', 'x-ratelimit-remaining-tokens', 'x-ratelimit-reset-tokens',
  'anthropic-ratelimit-requests-limit', 'anthropic-ratelimit-requests-remaining', 'anthropic-ratelimit-requests-reset',
  'anthropic-ratelimit-tokens-limit', 'anthropic-ratelimit-tokens-remaining', 'anthropic-ratelimit-tokens-reset',
  'anthropic-ratelimit-input-tokens-limit', 'anthropic-ratelimit-input-tokens-remaining'
];

function isBlockedProxyTarget(urlStr){
  let u;
  try { u = new URL(urlStr); } catch { return true; }
  if (u.protocol !== 'https:') return true;
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1') return true;
  if (/^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) || /^169\.254\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  return false;
}

app.post('/api/relay-proxy', requireAuth, async (req, res) => {
  const { url, headers, body } = req.body || {};
  if (!url || isBlockedProxyTarget(url)) {
    return res.status(400).json({ error: 'Ongeldige of niet-toegestane proxy-bestemming.' });
  }

  // Breekt de browser de verbinding met Relay zelf af (bv. via de
  // stopknop), dan breken we ook de aanroep naar de AI-provider zelf af
  // — anders blijft de server zinloos doorlezen en tokens verbruiken bij
  // een AI die niemand meer luistert.
  const upstreamController = new AbortController();
  res.on('close', () => { if (!res.writableEnded) upstreamController.abort(); });

  try {
    const providerRes = await fetch(url, {
      method: 'POST',
      headers: headers || {},
      body: typeof body === 'string' ? body : JSON.stringify(body),
      signal: upstreamController.signal
    });

    res.status(providerRes.status);
    // Zonder deze header buffert nginx (bv. via NPM ervoor) dit soort
    // doorlopend binnenkomende responses standaard, waardoor tekst in
    // klonten aankomt in plaats van vloeiend te streamen. Dit zet dat
    // uit, specifiek voor deze aanroep.
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Cache-Control', 'no-cache');
    for (const [key, value] of providerRes.headers.entries()) {
      if (RATE_LIMIT_HEADER_ALLOWLIST.includes(key.toLowerCase())) res.setHeader(key, value);
    }
    res.flushHeaders();
    if (res.socket) res.socket.setNoDelay(true); // Nagle's algoritme uit: kleine stukjes niet laten wachten

    if (!providerRes.body) { res.end(); return; }
    const reader = providerRes.body.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(value);
    }
    res.end();
  } catch (e) {
    // Headers al verstuurd (bv. streaming was al bezig toen het misging)?
    // Dan kan er geen nette JSON-foutmelding meer bij — gewoon afsluiten
    // i.p.v. crashen op "Cannot set headers after they are sent".
    if (!res.headersSent) {
      res.status(502).json({ error: 'Kon de AI-provider niet bereiken: ' + e.message });
    } else if (!res.writableEnded) {
      res.end();
    }
  }
});

// ---------- Static frontend ----------

app.use(express.static(path.join(__dirname, '..', 'src')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'index.html'));
});

// Vangt elke onverwachte serverfout op (bv. een databasetabel die nog
// ontbreekt door een niet-volledig doorgevoerde update) en geeft een
// duidelijke, leesbare JSON-foutmelding terug in plaats van een kale
// 500-crash — belangrijk voor `/api/...`-routes, die de frontend anders
// niet netjes kan tonen. Moet als allerlaatste middleware staan.
app.use((err, req, res, next) => {
  console.error('Onverwachte serverfout bij', req.method, req.path, ':', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Interne serverfout: ' + (err && err.message ? err.message : 'onbekend') });
});

app.listen(PORT, () => {
  console.log(`Relay-server luistert op poort ${PORT}`);
});