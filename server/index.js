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
app.use(express.json({ limit: '5mb' }));
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
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Sessie verlopen, log opnieuw in.' });
  }
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

// ---------- Admin: toegang & gebruikersbeheer ----------

app.get('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  res.json({ registrationOpen: !!getSetting('registration_code_hash') });
});

app.put('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  const { code } = req.body || {};
  if (!code || code.length < 6) {
    return res.status(400).json({ error: 'Kies een registratiecode van minstens 6 tekens.' });
  }
  setSetting('registration_code_hash', bcrypt.hashSync(code, 12));
  res.json({ ok: true });
});

app.delete('/api/admin/access', requireAuth, requireAdmin, (req, res) => {
  deleteSetting('registration_code_hash');
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

// ---------- Static frontend ----------

app.use(express.static(path.join(__dirname, '..', 'src')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'src', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Relay-server luistert op poort ${PORT}`);
});
