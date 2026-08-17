const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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
// 25mb i.p.v. 5mb — gesprekken kunnen nu base64-gecodeerde afbeeldingen
// bevatten, die aanmerkelijk groter zijn dan platte tekst.
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());
app.set('trust proxy', 1); // NPM zit ervoor als reverse proxy

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

app.post('/api/auth/register', (req, res) => {
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

app.post('/api/auth/login', (req, res) => {
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

app.put('/api/conversations/:id', requireAuth, (req, res) => {
  const { title, messages } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).json({ error: 'messages moet een array zijn.' });
  const now = Date.now();
  const existing = db.prepare('SELECT id FROM conversations WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.uid);
  if (existing) {
    db.prepare('UPDATE conversations SET title = ?, updated_at = ?, messages = ? WHERE id = ? AND user_id = ?')
      .run(title || 'Nieuw gesprek', now, JSON.stringify(messages), req.params.id, req.user.uid);
  } else {
    db.prepare('INSERT INTO conversations (id, user_id, title, updated_at, messages) VALUES (?, ?, ?, ?, ?)')
      .run(req.params.id, req.user.uid, title || 'Nieuw gesprek', now, JSON.stringify(messages));
  }
  res.json({ ok: true, updatedAt: now });
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

// ---------- Geheugen (notities over jezelf, gaan mee in elk gesprek) ----------

const MEMORY_MAX_CHARS = 4000;

app.get('/api/memory', requireAuth, (req, res) => {
  const row = db.prepare('SELECT memory FROM users WHERE id = ?').get(req.user.uid);
  res.json({ memory: row ? row.memory : '' });
});

app.put('/api/memory', requireAuth, (req, res) => {
  let { memory } = req.body || {};
  if (typeof memory !== 'string') memory = '';
  if (memory.length > MEMORY_MAX_CHARS) {
    return res.status(400).json({ error: `Maximaal ${MEMORY_MAX_CHARS} tekens.` });
  }
  db.prepare('UPDATE users SET memory = ? WHERE id = ?').run(memory, req.user.uid);
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
  try {
    const providerRes = await fetch(url, {
      method: 'POST',
      headers: headers || {},
      body: typeof body === 'string' ? body : JSON.stringify(body)
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
    res.status(502).json({ error: 'Kon de AI-provider niet bereiken: ' + e.message });
  }
});

// ---------- Static frontend ----------

app.use(express.static(path.join(__dirname, '..', 'src')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Relay-server luistert op poort ${PORT}`);
});
