// Database setup. Everything is stored in a single SQLite file (data/rota.db).
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const file = process.env.DB_FILE || path.join(__dirname, 'data', 'rota.db');
fs.mkdirSync(path.dirname(file), { recursive: true });

const db = new DatabaseSync(file);

db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('manager', 'staff')),
    must_change_password INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
  );

  -- A week is identified by its Monday. A row exists once a week is published.
  CREATE TABLE IF NOT EXISTS weeks (
    start_date TEXT PRIMARY KEY,
    published_at TEXT
  );

  CREATE TABLE IF NOT EXISTS shifts (
    id INTEGER PRIMARY KEY,
    week_start TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS shifts_week ON shifts(week_start);
  CREATE INDEX IF NOT EXISTS shifts_user ON shifts(user_id, date);

  CREATE TABLE IF NOT EXISTS swap_requests (
    id INTEGER PRIMARY KEY,
    shift_id INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,
    from_user_id INTEGER NOT NULL REFERENCES users(id),
    to_user_id INTEGER NOT NULL REFERENCES users(id),
    note TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'approved', 'declined', 'cancelled')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    decided_at TEXT
  );
`);

db.exec(`DELETE FROM sessions WHERE expires_at < datetime('now')`);

// Run several statements as one all-or-nothing change.
function transaction(fn) {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

module.exports = { db, transaction };
