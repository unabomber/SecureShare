import http from 'node:http';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { openDb } from './db.js';
import { createPow } from './pow.js';
import { createLimiter } from './ratelimit.js';
import { maxBlobBytes, minBlobBytes } from './config.js';

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "worker-src 'none'",
].join('; ');

const SEC_HEADERS = {
  'content-security-policy': CSP,
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy':
    'camera=(), microphone=(), geolocation=(), payment=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
};

const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const SPA_RE = /^\/(d|r)\/[A-Za-z0-9_-]{22}$|^\/about$/;

function loadStatic(dir) {
  const files = new Map();
  const walk = (d, prefix) => {
    for (const name of readdirSync(d)) {
      const full = join(d, name);
      if (statSync(full).isDirectory()) walk(full, `${prefix}${name}/`);
      else {
        const buf = readFileSync(full);
        files.set(`/${prefix}${name}`, {
          buf,
          type: MIME[extname(name)] || 'application/octet-stream',
          sha256: createHash('sha256').update(buf).digest('hex'),
        });
      }
    }
  };
  walk(dir, '');
  return files;
}

export function createApp(cfg, { now = Date.now } = {}) {
  const db = openDb(cfg.dbPath);
  const pow = createPow({ bits: cfg.powBits, now });
  const limiters = {
    general: createLimiter({ ...cfg.limits.general, now }),
    create: createLimiter({ ...cfg.limits.create, now }),
    submit: createLimiter({ ...cfg.limits.submit, now }),
  };
  const statics = loadStatic(cfg.publicDir);
  const integrity = Object.fromEntries([...statics].map(([p, f]) => [p, f.sha256]));
  const blobMax = maxBlobBytes(cfg.maxSecretBytes);
  const bodyMax = Math.ceil((blobMax * 4) / 3) + 1024;
  const nowSec = () => Math.floor(now() / 1000);

  const clientIp = (req) => {
    if (cfg.clientIpHeader) {
      const v = req.headers[cfg.clientIpHeader];
      if (typeof v === 'string' && v) return v.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  };

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { ...SEC_HEADERS, ...headers, 'content-length': Buffer.byteLength(body ?? '') });
    res.end(body);
  };
  const json = (res, status, obj) =>
    send(res, status, JSON.stringify(obj), { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  const empty = (res, status) => send(res, status, '', { 'cache-control': 'no-store' });
  const fail = (res, status, error) => json(res, status, { error });

  const readJson = (req) =>
    new Promise((resolve, reject) => {
      let size = 0;
      let tooBig = false;
      const chunks = [];
      req.on('data', (c) => {
        if (tooBig) return;
        size += c.length;
        if (size > bodyMax) {
          tooBig = true;
          chunks.length = 0;
          reject(Object.assign(new Error('too large'), { status: 413 }));
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        if (tooBig) return;
        try {
          const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error();
          resolve(v);
        } catch {
          reject(Object.assign(new Error('bad json'), { status: 400 }));
        }
      });
      req.on('error', reject);
    });

  const tokenOk = (row, req) => {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || '');
    if (!m) return false;
    const h = Buffer.from(createHash('sha256').update(Buffer.from(m[1], 'base64url')).digest('base64url'));
    const expected = Buffer.from(row.token_hash);
    return h.length === expected.length && timingSafeEqual(h, expected);
  };

  async function api(req, res, path) {
    if (!limiters.general.take(clientIp(req))) return fail(res, 429, 'rate_limited');
    const method = req.method;

    if (path === '/api/config' && method === 'GET') {
      return json(res, 200, {
        maxSecretBytes: cfg.maxSecretBytes,
        ttls: cfg.ttls,
        powBits: cfg.powBits,
      });
    }
    if (path === '/api/integrity' && method === 'GET') return json(res, 200, { sha256: integrity });

    if (path === '/api/pow' && method === 'GET') {
      const purpose = new URL(req.url, 'http://x').searchParams.get('purpose');
      if (purpose !== 'create' && purpose !== 'submit') return fail(res, 400, 'bad_purpose');
      return json(res, 200, pow.issue(purpose));
    }

    if (path === '/api/drops' && method === 'POST') {
      if (!limiters.create.take(clientIp(req))) return fail(res, 429, 'rate_limited');
      const b = await readJson(req);
      if (typeof b.tokenHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b.tokenHash)) return fail(res, 400, 'bad_token_hash');
      if (!cfg.ttls.includes(b.ttl)) return fail(res, 400, 'bad_ttl');
      if (!pow.verify('create', b.pow)) return fail(res, 403, 'bad_pow');
      if (db.count() >= cfg.maxDrops) return fail(res, 503, 'capacity');
      const id = randomBytes(16).toString('base64url');
      const expiresAt = nowSec() + b.ttl;
      db.create(id, b.tokenHash, expiresAt);
      return json(res, 201, { id, expiresAt });
    }

    const m = /^\/api\/drops\/([^/]+)(?:\/(secret))?$/.exec(path);
    if (!m || !ID_RE.test(m[1])) return fail(res, 404, 'not_found');
    const [, id, sub] = m;

    if (!sub && method === 'GET') {
      const row = db.get(id, nowSec());
      if (!row) return fail(res, 404, 'not_found');
      return json(res, 200, { state: row.ciphertext ? 'filled' : 'empty', expiresAt: row.expires_at });
    }

    if (sub === 'secret' && method === 'POST') {
      if (!limiters.submit.take(clientIp(req))) return fail(res, 429, 'rate_limited');
      const b = await readJson(req);
      if (typeof b.ciphertext !== 'string' || !B64U_RE.test(b.ciphertext)) return fail(res, 400, 'bad_ciphertext');
      const blob = Buffer.from(b.ciphertext, 'base64url');
      if (blob.length < minBlobBytes || blob.length > blobMax || blob[0] !== 1) return fail(res, 400, 'bad_ciphertext');
      if (!pow.verify('submit', b.pow)) return fail(res, 403, 'bad_pow');
      const row = db.get(id, nowSec());
      if (!row) return fail(res, 404, 'not_found');
      if (db.fill(id, blob, nowSec()) === 0) return fail(res, 409, 'already_filled');
      return empty(res, 204);
    }

    if (sub === 'secret' && method === 'GET') {
      const row = db.get(id, nowSec());
      if (!row || !tokenOk(row, req) || !row.ciphertext) return fail(res, 404, 'not_found');
      return json(res, 200, { ciphertext: Buffer.from(row.ciphertext).toString('base64url') });
    }

    if (!sub && method === 'DELETE') {
      const row = db.get(id, nowSec());
      if (!row || !tokenOk(row, req)) return fail(res, 404, 'not_found');
      db.remove(id);
      return empty(res, 204);
    }

    return fail(res, 405, 'method_not_allowed');
  }

  function serveStatic(req, res, path) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return fail(res, 405, 'method_not_allowed');
    const key = path === '/' || SPA_RE.test(path) ? '/index.html' : path;
    const f = statics.get(key);
    if (!f) return send(res, 404, 'Not found', { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    const etag = `"${f.sha256.slice(0, 32)}"`;
    const headers = { 'content-type': f.type, 'cache-control': 'no-cache', etag };
    if (req.headers['if-none-match'] === etag) return send(res, 304, '', headers);
    res.writeHead(200, { ...SEC_HEADERS, ...headers, 'content-length': f.buf.length });
    res.end(req.method === 'HEAD' ? undefined : f.buf);
  }

  const server = http.createServer(async (req, res) => {
    try {
      const path = (req.url || '/').split('?')[0];
      if (path === '/healthz') return send(res, 200, 'ok', { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      if (path.startsWith('/api/')) return await api(req, res, path);
      return serveStatic(req, res, path);
    } catch (err) {
      if (res.headersSent) return res.destroy();
      if (err && err.status === 413) {
        // Answer, then drop the connection rather than draining an oversized upload.
        res.setHeader('connection', 'close');
        res.on('finish', () => req.destroy());
        return fail(res, 413, 'too_large');
      }
      if (err && err.status) return fail(res, err.status, 'bad_request');
      console.error('internal error:', err && err.message);
      return fail(res, 500, 'internal');
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 50;

  let ticks = 0;
  const timer = setInterval(() => {
    db.sweep(nowSec());
    pow.sweep();
    for (const l of Object.values(limiters)) l.sweep();
    if (++ticks % 10 === 0) db.checkpoint();
  }, 60_000);
  timer.unref();

  return {
    server,
    db,
    close: () =>
      new Promise((resolve) => {
        clearInterval(timer);
        server.close(() => {
          try {
            db.checkpoint();
            db.close();
          } catch {}
          resolve();
        });
        server.closeAllConnections?.();
      }),
  };
}
