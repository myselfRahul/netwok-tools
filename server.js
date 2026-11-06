'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { WebSocketServer, WebSocket } = require('ws');
const {
  parseAuthorizedCIDRs, expandTargetInput, parsePorts, safeEqual, hashToken
} = require('./src/security');
const { scanHost } = require('./src/scanner');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

const config = {
  host: process.env.HOST || '127.0.0.1',
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || 'development',
  adminUser: process.env.ADMIN_USER || '',
  adminPassword: process.env.ADMIN_PASSWORD || '',
  authorized: parseAuthorizedCIDRs(process.env.AUTHORIZED_CIDRS || ''),
  maxTargets: Number(process.env.MAX_TARGETS || 128),
  maxConcurrency: Number(process.env.MAX_CONCURRENCY || 8),
  maxPorts: Number(process.env.MAX_PORTS || 32),
  connectTimeoutMs: Number(process.env.CONNECT_TIMEOUT_MS || 1200),
  bannerTimeoutMs: Number(process.env.BANNER_TIMEOUT_MS || 700)
};

if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) throw new Error('Invalid PORT');
if (!Number.isInteger(config.maxTargets) || config.maxTargets < 1 || config.maxTargets > 1024) throw new Error('MAX_TARGETS must be 1..1024');
if (!Number.isInteger(config.maxConcurrency) || config.maxConcurrency < 1 || config.maxConcurrency > 32) throw new Error('MAX_CONCURRENCY must be 1..32');
if (!config.adminUser || config.adminUser.length > 64 || config.adminPassword.length < 16) {
  throw new Error('Set ADMIN_USER and a strong ADMIN_PASSWORD (at least 16 characters) in .env');
}
if (config.nodeEnv === 'production' && config.host !== '127.0.0.1' && config.host !== '::1') {
  console.warn('WARNING: bind address is not loopback. Put this service behind a TLS reverse proxy and configure firewall restrictions.');
}

const db = new DatabaseSync(path.join(DATA_DIR, 'assessment.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    target_input TEXT NOT NULL,
    status TEXT NOT NULL,
    total INTEGER NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
  );
  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    reachable INTEGER NOT NULL,
    open_ports_json TEXT NOT NULL,
    scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const scrypt = (password, salt) => crypto.scryptSync(password, salt, 64).toString('hex');
const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(config.adminUser);
if (!existing) {
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO users(username,password_salt,password_hash) VALUES(?,?,?)')
    .run(config.adminUser, salt, scrypt(config.adminPassword, salt));
}

// Jobs cannot resume after a process restart; mark stale executions explicitly.
db.prepare("UPDATE jobs SET status='INTERRUPTED', finished_at=CURRENT_TIMESTAMP WHERE status IN ('RUNNING','PAUSED','CANCELLING','QUEUED')").run();

const sessions = new Map();
const jobs = new Map();
const rateLimits = new Map();
const DEFAULT_PORTS = [22, 80, 443, 445, 3389, 8080, 8443];

function log(event, details = {}) {
  process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), event, ...details })}\n`);
}
function audit(username, event, detail) {
  db.prepare('INSERT INTO audit(username,event,detail) VALUES(?,?,?)').run(username, event, String(detail).slice(0, 500));
}
function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(body));
}
function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}
function getSession(req) {
  const token = parseCookies(req.headers.cookie).sid;
  if (!token) return null;
  const key = hashToken(token);
  const session = sessions.get(key);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(key);
    return null;
  }
  return { ...session, key };
}
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  try {
    const parsed = new URL(origin);
    const host = req.headers.host;
    return parsed.host === host && ['http:', 'https:'].includes(parsed.protocol);
  } catch { return false; }
}
function rateLimit(req, bucket, limit, windowMs) {
  const ip = req.socket.remoteAddress || 'unknown';
  const key = `${bucket}:${ip}`;
  const now = Date.now();
  const item = rateLimits.get(key) || { count: 0, reset: now + windowMs };
  if (now > item.reset) { item.count = 0; item.reset = now + windowMs; }
  item.count++;
  rateLimits.set(key, item);
  return item.count <= limit;
}
async function readJson(req, maxBytes = 16 * 1024) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > maxBytes) throw new Error('Request body too large');
  }
  try { return JSON.parse(body || '{}'); } catch { throw new Error('Invalid JSON'); }
}
function requireCsrf(req, session) {
  const supplied = req.headers['x-csrf-token'];
  return supplied && safeEqual(supplied, session.csrf);
}
function cookieHeader(token, clear = false) {
  const secure = config.nodeEnv === 'production' ? '; Secure' : '';
  return `sid=${clear ? '' : encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${clear ? 0 : 8 * 60 * 60}${secure}`;
}
function publicJob(job) {
  return { id: job.id, targetInput: job.targetInput, status: job.status, total: job.targets.length, completed: job.completed, ports: job.ports, createdAt: job.createdAt };
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  try {
    if (req.method === 'GET' && pathname === '/healthz') return sendJson(res, 200, { status: 'ok' });

    if (req.method === 'POST' && pathname === '/api/login') {
      if (!originAllowed(req) || !rateLimit(req, 'login', 10, 60_000)) return sendJson(res, 403, { error: 'Request rejected' });
      const body = await readJson(req);
      if (typeof body.username !== 'string' || typeof body.password !== 'string' || body.username.length > 64 || body.password.length > 256) {
        return sendJson(res, 400, { error: 'Invalid credentials format' });
      }
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(body.username);
      const candidateSalt = user?.password_salt || crypto.randomBytes(16).toString('hex');
      const candidateHash = scrypt(body.password, candidateSalt);
      if (!user || !safeEqual(candidateHash, user.password_hash)) {
        audit('anonymous', 'login_failed', 'Invalid credentials');
        return sendJson(res, 401, { error: 'Invalid username or password' });
      }
      const token = crypto.randomBytes(32).toString('base64url');
      const key = hashToken(token);
      const session = { username: user.username, csrf: crypto.randomBytes(24).toString('base64url'), expiresAt: Date.now() + 8 * 60 * 60 * 1000 };
      sessions.set(key, session);
      audit(user.username, 'login', 'Session created');
      return sendJson(res, 200, { username: user.username, csrf: session.csrf }, { 'Set-Cookie': cookieHeader(token) });
    }

    const session = getSession(req);
    if (req.method === 'GET' && pathname === '/api/session') {
      return session ? sendJson(res, 200, { authenticated: true, username: session.username, csrf: session.csrf })
        : sendJson(res, 200, { authenticated: false });
    }
    if (!session) return pathname.startsWith('/api/') ? sendJson(res, 401, { error: 'Authentication required' }) : serveStatic(pathname, res);

    if (req.method === 'POST' && pathname === '/api/logout') {
      if (!originAllowed(req) || !requireCsrf(req, session)) return sendJson(res, 403, { error: 'CSRF validation failed' });
      sessions.delete(session.key);
      audit(session.username, 'logout', 'Session destroyed');
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', true) });
    }

    if (req.method === 'GET' && pathname === '/api/jobs') {
      const rows = db.prepare('SELECT id,target_input,status,total,completed,created_at,finished_at FROM jobs WHERE username=? ORDER BY created_at DESC LIMIT 100').all(session.username);
      return sendJson(res, 200, { jobs: rows });
    }
    const csvMatch = pathname.match(/^\/api\/jobs\/([a-f0-9-]{36})\/csv$/);
    if (req.method === 'GET' && csvMatch) {
      const job = db.prepare('SELECT * FROM jobs WHERE id=? AND username=?').get(csvMatch[1], session.username);
      if (!job) return sendJson(res, 404, { error: 'Job not found' });
      const results = db.prepare('SELECT ip,reachable,open_ports_json,scanned_at FROM results WHERE job_id=? ORDER BY ip').all(job.id);
      const quote = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
      const lines = [['IP','Reachable','Open Ports','Scanned At'].map(quote).join(',')];
      for (const row of results) lines.push([row.ip, row.reachable ? 'YES' : 'NO', row.open_ports_json, row.scanned_at].map(quote).join(','));
      res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="assessment-${job.id}.csv"`, 'Cache-Control': 'no-store' });
      return res.end(lines.join('\r\n'));
    }

    if (req.method === 'GET' && pathname === '/') return serveStatic('/index.html', res);
    return sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    log('http_error', { message: err.message });
    return sendJson(res, 400, { error: err.message || 'Request failed' });
  }
});

function serveStatic(pathname, res) {
  const allowed = new Map([['/index.html','index.html'], ['/app.js','app.js'], ['/styles.css','styles.css']]);
  const file = allowed.get(pathname);
  if (!file) {
    res.writeHead(302, { Location: '/index.html', 'Cache-Control': 'no-store' });
    return res.end();
  }
  const full = path.join(ROOT, 'public', file);
  res.writeHead(200, {
    'Content-Type': file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });
  fs.createReadStream(full).on('error', () => { res.writeHead(404); res.end('Not found'); }).pipe(res);
}

const wss = new WebSocketServer({ noServer: true, maxPayload: 16 * 1024, perMessageDeflate: false });
server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws' || !originAllowed(req)) return socket.destroy();
  const session = getSession(req);
  if (!session) return socket.destroy();
  wss.handleUpgrade(req, socket, head, (ws) => {
    ws.session = session;
    wss.emit('connection', ws);
  });
});

function wsSend(ws, type, payload) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type, payload }));
}
function broadcastJob(job, type, payload) {
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN && client.session?.username === job.username) wsSend(client, type, payload);
  }
}

async function executeJob(job) {
  const controller = new AbortController();
  job.controller = controller;
  let next = 0;
  const worker = async () => {
    while (!controller.signal.aborted) {
      if (job.paused) {
        await new Promise((resolve) => { job.resumeWaiters.push(resolve); });
        continue;
      }
      const index = next++;
      if (index >= job.targets.length) return;
      const ip = job.targets[index];
      try {
        const result = await scanHost(ip, job.ports, config, controller.signal);
        db.prepare('INSERT INTO results(job_id,ip,reachable,open_ports_json) VALUES(?,?,?,?)')
          .run(job.id, ip, result.reachable ? 1 : 0, JSON.stringify(result.openPorts));
        job.completed++;
        db.prepare('UPDATE jobs SET completed=? WHERE id=?').run(job.completed, job.id);
        broadcastJob(job, 'result', { jobId: job.id, result });
        broadcastJob(job, 'progress', { jobId: job.id, completed: job.completed, total: job.targets.length });
      } catch (err) {
        log('scan_target_error', { jobId: job.id, ip, message: err.message });
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(job.concurrency, job.targets.length) }, worker));
  job.status = controller.signal.aborted ? 'CANCELLED' : 'COMPLETED';
  job.finishedAt = new Date().toISOString();
  db.prepare('UPDATE jobs SET status=?,finished_at=CURRENT_TIMESTAMP,completed=? WHERE id=?').run(job.status, job.completed, job.id);
  audit(job.username, 'scan_finished', `${job.id}:${job.status}`);
  broadcastJob(job, 'job_done', { id: job.id, status: job.status, completed: job.completed, total: job.targets.length });
}

wss.on('connection', (ws) => {
  wsSend(ws, 'welcome', { message: 'Authenticated' });
  ws.on('message', async (raw) => {
    try {
      if (ws.session.expiresAt < Date.now()) { ws.close(1008, 'Session expired'); return; }
      const message = JSON.parse(raw.toString('utf8'));
      if (!message || typeof message.cmd !== 'string' || !message.data || typeof message.data !== 'object') throw new Error('Invalid message schema');
      if (message.cmd === 'start') {
        const active = [...jobs.values()].find((j) => j.username === ws.session.username && ['QUEUED','RUNNING','PAUSED'].includes(j.status));
        if (active) throw new Error('You already have an active scan');
        const targets = expandTargetInput(message.data.target, config.authorized, config.maxTargets);
        const ports = parsePorts(message.data.ports || DEFAULT_PORTS, config.maxPorts);
        const concurrency = Number(message.data.concurrency || Math.min(4, config.maxConcurrency));
        if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > config.maxConcurrency) throw new Error(`Concurrency must be 1..${config.maxConcurrency}`);
        const job = {
          id: crypto.randomUUID(), username: ws.session.username, targetInput: message.data.target,
          targets, ports, concurrency, completed: 0, status: 'RUNNING', createdAt: Date.now(),
          paused: false, resumeWaiters: []
        };
        jobs.set(job.id, job);
        db.prepare('INSERT INTO jobs(id,username,target_input,status,total) VALUES(?,?,?,?,?)')
          .run(job.id, job.username, job.targetInput, 'RUNNING', targets.length);
        audit(job.username, 'scan_started', `${job.id}:${targets.length} targets`);
        wsSend(ws, 'job_started', publicJob(job));
        executeJob(job).catch((err) => log('job_error', { jobId: job.id, message: err.message }));
      } else {
        const job = jobs.get(message.data.jobId);
        if (!job || job.username !== ws.session.username) throw new Error('Job not found');
        if (message.cmd === 'pause' && job.status === 'RUNNING') {
          job.paused = true; job.status = 'PAUSED';
          db.prepare('UPDATE jobs SET status=? WHERE id=?').run('PAUSED', job.id);
          wsSend(ws, 'paused', { jobId: job.id });
        } else if (message.cmd === 'resume' && job.status === 'PAUSED') {
          job.paused = false; job.status = 'RUNNING';
          for (const resolve of job.resumeWaiters.splice(0)) resolve();
          db.prepare('UPDATE jobs SET status=? WHERE id=?').run('RUNNING', job.id);
          wsSend(ws, 'resumed', { jobId: job.id });
        } else if (message.cmd === 'cancel' && ['RUNNING','PAUSED'].includes(job.status)) {
          job.status = 'CANCELLING';
          job.controller.abort();
          for (const resolve of job.resumeWaiters.splice(0)) resolve();
          wsSend(ws, 'cancelling', { jobId: job.id });
        } else {
          throw new Error('Unsupported command or invalid job state');
        }
      }
    } catch (err) {
      wsSend(ws, 'error', { message: err.message });
    }
  });
});

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
function shutdown() {
  log('shutdown', { message: 'Stopping server' });
  for (const job of jobs.values()) job.controller?.abort();
  wss.close();
  server.close(() => { db.close(); process.exit(0); });
  setTimeout(() => process.exit(1), 5000).unref();
}

server.listen(config.port, config.host, () => {
  log('server_started', { host: config.host, port: config.port, authorizedRanges: process.env.AUTHORIZED_CIDRS });
});
