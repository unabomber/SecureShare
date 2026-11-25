import test from 'node:test';
import assert from 'node:assert/strict';
import {
  b64u, generateDropKeys, encryptTo, decryptWith, fingerprint, pad, unpad,
  makeRecoveryFile, openRecoveryFile, sealVault, openVault, keyFromPrf, rand,
  solvePow, leadingZeroBits, sha256, BUCKET,
} from '../public/crypto.js';

const te = new TextEncoder();
const td = new TextDecoder();
const ID = 'AAAAAAAAAAAAAAAAAAAAAA';

test('b64u round-trips arbitrary bytes', () => {
  for (const n of [0, 1, 2, 3, 31, 32, 65, 300]) {
    const b = rand(n);
    assert.deepEqual(b64u.dec(b64u.enc(b)), b);
  }
});

test('encrypt/decrypt round-trip', async () => {
  const k = await generateDropKeys();
  const blob = await encryptTo(k.publicRaw, te.encode('hunter2 — pässwörd'), ID);
  assert.equal(td.decode(await decryptWith(k.privateJwk, blob, ID)), 'hunter2 — pässwörd');
});

test('ciphertext length hides secret length within a bucket', async () => {
  const k = await generateDropKeys();
  const a = await encryptTo(k.publicRaw, te.encode('a'), ID);
  const b = await encryptTo(k.publicRaw, te.encode('x'.repeat(900)), ID);
  const c = await encryptTo(k.publicRaw, te.encode('x'.repeat(1100)), ID);
  assert.equal(a.length, b.length);
  assert.equal(c.length, a.length + BUCKET);
});

test('padding round-trips', () => {
  for (const n of [0, 1, 1022, 1023, 1024, 5000]) {
    const d = rand(n);
    const p = pad(d);
    assert.equal(p.length % BUCKET, 0);
    assert.deepEqual(unpad(p), d);
  }
});

test('each encryption is unique (fresh ephemeral key + iv)', async () => {
  const k = await generateDropKeys();
  const a = await encryptTo(k.publicRaw, te.encode('same'), ID);
  const b = await encryptTo(k.publicRaw, te.encode('same'), ID);
  assert.notDeepEqual(a, b);
});

test('tampering anywhere in the blob is detected', async () => {
  const k = await generateDropKeys();
  const blob = await encryptTo(k.publicRaw, te.encode('secret'), ID);
  for (const i of [1, 40, 66, 70, 100, blob.length - 1]) {
    const t = blob.slice();
    t[i] ^= 1;
    await assert.rejects(decryptWith(k.privateJwk, t, ID), `byte ${i}`);
  }
});

test('ciphertext is bound to its drop id', async () => {
  const k = await generateDropKeys();
  const blob = await encryptTo(k.publicRaw, te.encode('secret'), ID);
  await assert.rejects(decryptWith(k.privateJwk, blob, 'BBBBBBBBBBBBBBBBBBBBBB'));
});

test('another recipient cannot decrypt', async () => {
  const a = await generateDropKeys();
  const b = await generateDropKeys();
  const blob = await encryptTo(a.publicRaw, te.encode('secret'), ID);
  await assert.rejects(decryptWith(b.privateJwk, blob, ID));
});

test('rejects malformed recipient public key', async () => {
  await assert.rejects(encryptTo(rand(65), te.encode('x'), ID));
  await assert.rejects(encryptTo(rand(10), te.encode('x'), ID));
});

test('fingerprint is stable and formatted', async () => {
  const k = await generateDropKeys();
  const f = await fingerprint(k.publicRaw);
  assert.match(f, /^([0-9A-F]{4} ){4}[0-9A-F]{4}$/);
  assert.equal(f, await fingerprint(k.publicRaw));
  assert.notEqual(f, await fingerprint((await generateDropKeys()).publicRaw));
});

test('read token hash matches token', async () => {
  const k = await generateDropKeys();
  assert.equal(k.tokenHash, b64u.enc(await sha256(b64u.dec(k.readToken))));
  assert.equal(k.readToken.length, 43);
  assert.equal(k.tokenHash.length, 43);
});

test('recovery file: correct passphrase restores vault, wrong one fails', async () => {
  const k = await generateDropKeys();
  const vault = { v: 1, dropId: ID, privateJwk: k.privateJwk, readToken: k.readToken };
  const file = await makeRecoveryFile(vault, 'correct horse battery', { iter: 1000 });
  assert.equal(file.dropId, ID);
  assert.deepEqual(await openRecoveryFile(file, 'correct horse battery'), vault);
  await assert.rejects(openRecoveryFile(file, 'wrong passphrase!!'));
  await assert.rejects(openRecoveryFile({ ...file, app: 'other' }, 'correct horse battery'));
  await assert.rejects(openRecoveryFile({ ...file, kdf: { ...file.kdf, iter: 1e9 } }, 'correct horse battery'));
});

test('vault sealed with PRF-derived key', async () => {
  const key = await keyFromPrf(rand(32));
  const sealed = await sealVault({ hello: 'world' }, key);
  assert.deepEqual(await openVault(sealed, key), { hello: 'world' });
  await assert.rejects(openVault(sealed, await keyFromPrf(rand(32))));
});

test('end to end: vault restored from file still decrypts', async () => {
  const k = await generateDropKeys();
  const blob = await encryptTo(k.publicRaw, te.encode('db password'), ID);
  const file = await makeRecoveryFile({ v: 1, dropId: ID, privateJwk: k.privateJwk, readToken: k.readToken }, 'a long passphrase ok', { iter: 1000 });
  const restored = await openRecoveryFile(JSON.parse(JSON.stringify(file)), 'a long passphrase ok');
  assert.equal(td.decode(await decryptWith(restored.privateJwk, blob, ID)), 'db password');
});

test('proof of work solves at the requested difficulty', async () => {
  const sol = await solvePow({ c: '9999999999.abc', s: 'sig', bits: 10 });
  const h = await sha256(te.encode(`9999999999.abc.${sol.n}`));
  assert.ok(leadingZeroBits(h) >= 10);
  assert.equal(leadingZeroBits(Uint8Array.of(0, 0x10)), 11);
  assert.equal(leadingZeroBits(Uint8Array.of(0xff)), 0);
});
