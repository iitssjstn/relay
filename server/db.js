const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'relay.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL DEFAULT 'Nieuw gesprek',
    updated_at INTEGER NOT NULL,
    messages TEXT NOT NULL DEFAULT '[]'
  );
  CREATE INDEX IF NOT EXISTS idx_conversations_user ON conversations(user_id);

  CREATE TABLE IF NOT EXISTS node_configs (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    config TEXT NOT NULL DEFAULT '{"nodes":[],"activeIndex":-1}'
  );

  -- Losse key/value-instellingen, o.a. de gehashte registratiecode.
  -- Wordt door de beheerder ingesteld vanuit de app zelf (geen bestand
  -- of env-var nodig op de VPS).
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  -- Gestructureerd geheugen, net als bij Claude zelf: losse, benoemde
  -- stukjes (Profiel/Topics/Areas) i.p.v. één grote lap tekst.
  CREATE TABLE IF NOT EXISTS memory_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL DEFAULT 'topic',
    title TEXT NOT NULL,
    content TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_memory_entries_user ON memory_entries(user_id);
`);

// Migratie: 'memory' kolom toevoegen aan bestaande installaties die 'm nog
// niet hebben (CREATE TABLE IF NOT EXISTS raakt bestaande tabellen niet aan).
const userColumns = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
if (!userColumns.includes('memory')) {
  db.exec("ALTER TABLE users ADD COLUMN memory TEXT NOT NULL DEFAULT ''");
}
if (!userColumns.includes('github_token')) {
  db.exec("ALTER TABLE users ADD COLUMN github_token TEXT");
}
if (!userColumns.includes('memory_auto_update')) {
  db.exec("ALTER TABLE users ADD COLUMN memory_auto_update INTEGER NOT NULL DEFAULT 1");
}
if (!userColumns.includes('e2b_api_key')) {
  db.exec("ALTER TABLE users ADD COLUMN e2b_api_key TEXT");
}

// Eenmalige migratie: bestaande (oude, ongestructureerde) geheugentekst
// overzetten naar één topic-item, zodat niemand data kwijtraakt bij de
// overstap naar gestructureerd geheugen.
const usersWithOldMemory = db.prepare(
  "SELECT id, memory FROM users WHERE memory IS NOT NULL AND trim(memory) != ''"
).all();
for (const u of usersWithOldMemory) {
  const already = db.prepare('SELECT COUNT(*) as n FROM memory_entries WHERE user_id = ?').get(u.id).n;
  if (already === 0) {
    db.prepare(
      'INSERT INTO memory_entries (user_id, category, title, content, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).run(u.id, 'topic', 'Eerdere notities', u.memory, Date.now());
  }
}

module.exports = db;
