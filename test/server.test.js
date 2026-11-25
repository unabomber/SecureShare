import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../server/config.js';
import { createApp } from '../server/app.js';
import { createPow } from '../server/pow.js';
import { createLimiter } from '../server/ratelimit.js';
import { generateDropKeys, encryptTo, decryptWith, b64u, solvePow } from '../public/crypto.js';

const te = new TextEncoder();
const td = new TextDecoder();
let app, base;

const cfg = {
  ...loadConfig({}),
  dbPath: ':memory:',
  powBits: 8,
  maxSecretBytes: 4096,
  limits: {
    general: { capacity: 1000, perSec: 1000 },
    create: { capacity: 1000, perSec: 1000 },
    submit: { capacity: 1000, perSec: 1000 },
  },
};

before(async () => {
  app = createApp(cfg);
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.server.address().port}`;
});
after(() => app.close());

const call = (path, opts = {}) => fetch(base + path, opts);
const post = (path, body, headers = {}) =>
  call(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const bearer = (t) => ({ authorization: `Bearer ${t}` });

async function pow(purpose) {
  const ch = await (await call(`/api/pow?purpose=${purpose}`)).json();
  return solvePow(ch);
}
async function createDrop(keys, ttl = 3600) {
  const r = await post('/api/drops', { tokenHash: keys.tokenHash, ttl, pow: await pow('create') });
  return { status: r.status, body: await r.json() };
}
async function submit(id, ciphertext, p) {
  return post(`/api/drops/${id}/secret`, { ciphertext: b64u.enc(ciphertext), pow: p ?? (await pow('submit')) });
}

test('full flow: create → submit → fetch → decrypt → burn', async () => {
  const keys = await generateDropKeys();
  const { status, body } = await createDrop(keys);
  assert.equal(status, 201);
  const id = body.id;
  assert.match(id, /^[A-Za-z0-9_-]{22}$/);

  assert.deepEqual((await (await call(`/api/drops/${id}`)).json()).state, 'empty');
  // nothing to fetch yet
  assert.equal((await call(`/api/drops/${id}/secret`, { headers: bearer(keys.readToken) })).status, 404);

  const blob = await encryptTo(keys.publicRaw, te.encode('s3cret!'), id);
  assert.equal((await submit(id, blob)).status, 204);
  assert.equal((await (await call(`/api/drops/${id}`)).json()).state, 'filled');

  // second submit refused
  assert.equal((await submit(id, blob)).status, 409);

  // fetch requires the right token
  assert.equal((await call(`/api/drops/${id}/secret`)).status, 404);
  const other = await generateDropKeys();
  assert.equal((await call(`/api/drops/${id}/secret`, { headers: bearer(other.readToken) })).status, 404);

  const got = await (await call(`/api/drops/${id}/secret`, { headers: bearer(keys.readToken) })).json();
  assert.equal(td.decode(await decryptWith(keys.privateJwk, b64u.dec(got.ciphertext), id)), 's3cret!');

  // fetching does not burn; only authenticated DELETE does
  assert.equal((await call(`/api/drops/${id}/secret`, { headers: bearer(keys.readToken) })).status, 200);
  assert.equal((await call(`/api/drops/${id}`, { method: 'DELETE' })).status, 404);
  assert.equal((await call(`/api/drops/${id}`, { method: 'DELETE', headers: bearer(keys.readToken) })).status, 204);
  assert.equal((await call(`/api/drops/${id}`)).status, 404);
  assert.equal((await call(`/api/drops/${id}/secret`, { headers: bearer(keys.readToken) })).status, 404);
});

test('server only ever stores ciphertext', async () => {
  const keys = await generateDropKeys();
  const { body } = await createDrop(keys);
  const marker = 'PLAINTEXT-MARKER-12345';
  const blob = await encryptTo(keys.publicRaw, te.encode(marker), body.id);
  await submit(body.id, blob);
  const row = app.db.get(body.id, Math.floor(Date.now() / 1000));
  assert.ok(!Buffer.from(row.ciphertext).includes(marker));
  assert.equal(row.token_hash, keys.tokenHash);
});

test('proof of work: missing, forged, wrong purpose, replayed', async () => {
  const keys = await generateDropKeys();
  const mk = (pow) => post('/api/drops', { tokenHash: keys.tokenHash, ttl: 3600, pow });
  assert.equal((await mk(undefined)).status, 403);
  assert.equal((await mk({ c: '9999999999.x', s: 'AAAA', n: '1' })).status, 403);

  const wrong = await solvePow(await (await call('/api/pow?purpose=submit')).json());
  assert.equal((await mk(wrong)).status, 403, 'submit challenge must not work for create');

  const good = await pow('create');
  assert.equal((await mk(good)).status, 201);
  assert.equal((await mk(good)).status, 403, 'replay refused');
  assert.equal((await call('/api/pow?purpose=bogus')).status, 400);
});

test('input validation', async () => {
  const keys = await generateDropKeys();
  assert.equal((await post('/api/drops', { tokenHash: 'short', ttl: 3600, pow: await pow('create') })).status, 400);
  assert.equal((await post('/api/drops', { tokenHash: keys.tokenHash, ttl: 5, pow: await pow('create') })).status, 400);
  assert.equal((await call('/api/drops', { method: 'POST', body: 'not json' })).status, 400);

  const { body } = await createDrop(keys);
  const id = body.id;
  assert.equal((await post(`/api/drops/${id}/secret`, { ciphertext: '!!', pow: await pow('submit') })).status, 400);
  assert.equal((await submit(id, new Uint8Array(10))).status, 400, 'too small');
  assert.equal((await submit(id, new Uint8Array(5300).fill(1))).status, 400, 'over blob limit but under body limit');
  assert.equal((await submit(id, new Uint8Array(20000).fill(1))).status, 413, 'over body limit');
  assert.equal((await call('/api/drops/not-an-id')).status, 404);
  assert.equal((await call('/api/drops/AAAAAAAAAAAAAAAAAAAAAA')).status, 404);
});

test('oversized request body is rejected', async () => {
  const r = await call('/api/drops', { method: 'POST', body: 'x'.repeat(200_000) });
  assert.equal(r.status, 413);
});

test('drops expire', async () => {
  let t = Date.now();
  const clock = createApp({ ...cfg, dbPath: ':memory:' }, { now: () => t });
  await new Promise((r) => clock.server.listen(0, '127.0.0.1', r));
  const b = `http://127.0.0.1:${clock.server.address().port}`;
  const ch = await (await fetch(`${b}/api/pow?purpose=create`)).json();
  const keys = await generateDropKeys();
  const r = await fetch(`${b}/api/drops`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ tokenHash: keys.tokenHash, ttl: 3600, pow: await solvePow(ch) }),
  });
  const { id } = await r.json();
  assert.equal((await fetch(`${b}/api/drops/${id}`)).status, 200);
  t += 3601_000;
  assert.equal((await fetch(`${b}/api/drops/${id}`)).status, 404);
  assert.equal(clock.db.sweep(Math.floor(t / 1000)), 1);
  await clock.close();
});

test('capacity cap', async () => {
  const small = createApp({ ...cfg, dbPath: ':memory:', maxDrops: 1 });
  await new Promise((r) => small.server.listen(0, '127.0.0.1', r));
  const b = `http://127.0.0.1:${small.server.address().port}`;
  const mk = async () => {
    const ch = await (await fetch(`${b}/api/pow?purpose=create`)).json();
    const keys = await generateDropKeys();
    return fetch(`${b}/api/drops`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tokenHash: keys.tokenHash, ttl: 3600, pow: await solvePow(ch) }),
    });
  };
  assert.equal((await mk()).status, 201);
  assert.equal((await mk()).status, 503);
  await small.close();
});

test('rate limiting uses the trusted client-ip header', async () => {
  const lim = createApp({
    ...cfg,
    dbPath: ':memory:',
    clientIpHeader: 'x-real-ip',
    limits: { ...cfg.limits, general: { capacity: 3, perSec: 0 } },
  });
  await new Promise((r) => lim.server.listen(0, '127.0.0.1', r));
  const b = `http://127.0.0.1:${lim.server.address().port}`;
  const hit = (ip) => fetch(`${b}/api/config`, { headers: { 'x-real-ip': ip } }).then((r) => r.status);
  assert.deepEqual([await hit('1.1.1.1'), await hit('1.1.1.1'), await hit('1.1.1.1'), await hit('1.1.1.1')], [200, 200, 200, 429]);
  assert.equal(await hit('2.2.2.2'), 200);
  await lim.close();
});

test('security headers and static serving', async () => {
  const r = await call('/');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  const spa = await call('/d/AAAAAAAAAAAAAAAAAAAAAA');
  assert.equal(spa.status, 200);
  assert.match(spa.headers.get('content-type'), /text\/html/);
  assert.equal((await call('/about')).status, 200);
  assert.equal((await call('/nope')).status, 404);
  assert.equal((await call('/../server/app.js')).status, 404);
  assert.equal((await call('/%2e%2e/server/app.js')).status, 404);
  const etag = r.headers.get('etag');
  assert.equal((await call('/', { headers: { 'if-none-match': etag } })).status, 304);
  const api = await call('/api/config');
  assert.equal(api.headers.get('cache-control'), 'no-store');
  assert.equal((await call('/healthz')).status, 200);
  const integ = await (await call('/api/integrity')).json();
  assert.match(integ.sha256['/crypto.js'], /^[0-9a-f]{64}$/);
});

test('pow unit: expiry', () => {
  let t = 1_000_000;
  const p = createPow({ bits: 0, ttlSec: 10, now: () => t });
  const ch = p.issue('create');
  t += 11_000;
  assert.equal(p.verify('create', { c: ch.c, s: ch.s, n: '1' }), false);
});

test('limiter unit: refills over time', () => {
  let t = 0;
  const l = createLimiter({ capacity: 2, perSec: 1, now: () => t });
  assert.deepEqual([l.take('a'), l.take('a'), l.take('a')], [true, true, false]);
  t += 1000;
  assert.equal(l.take('a'), true);
  assert.equal(l.take('a'), false);
});
