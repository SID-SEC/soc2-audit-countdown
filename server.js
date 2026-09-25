'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookie = require('cookie');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ALLOWED_DOMAIN = 'elliotsystems.com';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

if (!ADMIN_PASSWORD) {
  console.warn('[WARN] ADMIN_PASSWORD is not set. Set it in Render env vars, or /admin/login will always reject.');
}

// ---------------- DB ----------------
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'access.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    domain_ok INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
`);

const insertLog = db.prepare(
  'INSERT INTO access_log (email, domain_ok, ip, user_agent) VALUES (?, ?, ?, ?)'
);
const listLogs = db.prepare(
  'SELECT id, email, domain_ok, ip, user_agent, created_at FROM access_log ORDER BY id DESC LIMIT 500'
);
const insertSession = db.prepare(
  'INSERT INTO sessions (token, expires_at) VALUES (?, ?)'
);
const getSession = db.prepare(
  'SELECT token, expires_at FROM sessions WHERE token = ?'
);
const deleteSession = db.prepare('DELETE FROM sessions WHERE token = ?');
const pruneSessions = db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')");

// ---------------- App ----------------
const app = express();
app.set('trust proxy', true);
app.use(express.json({ limit: '10kb' }));

function isAllowedEmail(email) {
  if (typeof email !== 'string') return false;
  const trimmed = email.trim().toLowerCase();
  const at = trimmed.lastIndexOf('@');
  if (at === -1) return false;
  const domain = trimmed.slice(at + 1);
  return domain === ALLOWED_DOMAIN;
}

function requireAdmin(req, res, next) {
  pruneSessions.run();
  const cookies = cookie.parse(req.headers.cookie || '');
  const token = cookies.admin_session;
  if (!token) return res.status(401).json({ ok: false, error: 'Not logged in' });
  const row = getSession.get(token);
  if (!row) return res.status(401).json({ ok: false, error: 'Session expired' });
  next();
}

// Log a gate attempt (called whether or not the domain matched, for visibility)
app.post('/api/access', (req, res) => {
  const email = (req.body && req.body.email) || '';
  const ok = isAllowedEmail(email);
  const ip = req.ip || '';
  const ua = req.headers['user-agent'] || '';
  try {
    insertLog.run(String(email).slice(0, 200), ok ? 1 : 0, ip, ua);
  } catch (e) {
    console.error('Failed to log access attempt:', e);
  }
  res.json({ ok });
});

app.post('/api/admin/login', (req, res) => {
  const password = (req.body && req.body.password) || '';
  if (!ADMIN_PASSWORD || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok: false, error: 'Wrong password' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  insertSession.run(token, expiresAt);
  res.setHeader('Set-Cookie', cookie.serialize('admin_session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS / 1000,
  }));
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  const cookies = cookie.parse(req.headers.cookie || '');
  if (cookies.admin_session) deleteSession.run(cookies.admin_session);
  res.setHeader('Set-Cookie', cookie.serialize('admin_session', '', { path: '/', maxAge: 0 }));
  res.json({ ok: true });
});

app.get('/api/admin/session', requireAdmin, (req, res) => {
  res.json({ ok: true });
});

app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const rows = listLogs.all();
  res.json({ ok: true, rows });
});

// ---------------- Static site ----------------
app.use(express.static(path.join(__dirname, 'public')));

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`SOC 2 countdown server listening on port ${PORT}`);
});
