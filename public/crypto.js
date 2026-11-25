// Sealdrop client crypto. Pure WebCrypto, zero dependencies, works in browsers and Node.
//
// Construction (an ECIES / HPKE-style base mode built from standard primitives):
//   recipient key  : ECDH P-256 keypair, generated in the recipient's browser
//   encrypt        : ephemeral ECDH -> HKDF-SHA256 -> AES-256-GCM
//   key derivation : salt = ephemeralPub || recipientPub, info = "sealdrop/v1/<dropId>"
//   AAD            : version || dropId || ephemeralPub   (binds ciphertext to its drop)
//   plaintext      : 2-byte length + data, zero-padded to a 1 KiB boundary (hides length)
//   blob           : 0x01 || ephemeralPub(65) || iv(12) || ciphertext+tag

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
const td = new TextDecoder();
const VERSION = 1;
export const BUCKET = 1024;
const EC = { name: 'ECDH', namedCurve: 'P-256' };

export const b64u = {
  enc(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const p = str.replace(/-/g, '+').replace(/_/g, '/');
    const s = atob(p + '='.repeat((4 - (p.length % 4)) % 4));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

export const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
export const sha256 = async (data) => new Uint8Array(await subtle.digest('SHA-256', data));

// ---- padding -------------------------------------------------------------------
export function pad(data) {
  if (data.length > 0xffff) throw new Error('secret too large');
  const out = new Uint8Array(Math.ceil((data.length + 2) / BUCKET) * BUCKET);
  out[0] = data.length >> 8;
  out[1] = data.length & 0xff;
  out.set(data, 2);
  return out;
}
export function unpad(buf) {
  const n = (buf[0] << 8) | buf[1];
  if (n + 2 > buf.length) throw new Error('bad padding');
  return buf.slice(2, 2 + n);
}

// ---- recipient keys ------------------------------------------------------------
export async function generateDropKeys() {
  const kp = await subtle.generateKey(EC, true, ['deriveBits']);
  const publicRaw = new Uint8Array(await subtle.exportKey('raw', kp.publicKey));
  const privateJwk = await subtle.exportKey('jwk', kp.privateKey);
  const token = rand(32);
  return {
    publicRaw,
    privateJwk,
    readToken: b64u.enc(token),
    tokenHash: b64u.enc(await sha256(token)),
  };
}

export async function fingerprint(publicRaw) {
  const h = await sha256(publicRaw);
  const hex = [...h.slice(0, 10)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return hex.match(/.{4}/g).join(' ');
}

const publicFromJwk = (jwk) => cat(Uint8Array.of(4), b64u.dec(jwk.x), b64u.dec(jwk.y));

async function dropKey(shared, ephPub, recipientPub, dropId) {
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: cat(ephPub, recipientPub), info: te.encode(`sealdrop/v1/${dropId}`) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ---- encrypt / decrypt ----------------------------------------------------------
export async function encryptTo(publicRaw, plaintext, dropId) {
  if (publicRaw.length !== 65 || publicRaw[0] !== 4) throw new Error('bad recipient key');
  const recipient = await subtle.importKey('raw', publicRaw, EC, false, []);
  const eph = await subtle.generateKey(EC, true, ['deriveBits']);
  const ephPub = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256));
  const key = await dropKey(shared, ephPub, publicRaw, dropId);
  const iv = rand(12);
  const aad = cat(Uint8Array.of(VERSION), te.encode(dropId), ephPub);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pad(plaintext)));
  return cat(Uint8Array.of(VERSION), ephPub, iv, ct);
}

export async function decryptWith(privateJwk, blob, dropId) {
  if (blob[0] !== VERSION || blob.length < 1 + 65 + 12 + 16 + BUCKET) throw new Error('bad ciphertext');
  const ephPub = blob.slice(1, 66);
  const iv = blob.slice(66, 78);
  const ct = blob.slice(78);
  const priv = await subtle.importKey('jwk', privateJwk, EC, false, ['deriveBits']);
  const eph = await subtle.importKey('raw', ephPub, EC, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: eph }, priv, 256));
  const key = await dropKey(shared, ephPub, publicFromJwk(privateJwk), dropId);
  const aad = cat(Uint8Array.of(VERSION), te.encode(dropId), ephPub);
  const pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));
  return unpad(pt);
}

// ---- vault (the recipient's private material, at rest) ---------------------------
// vault = { v, dropId, privateJwk, readToken, publicKey(b64u), expiresAt }
const VAULT_AAD = te.encode('sealdrop/vault/v1');

export async function sealVault(vault, key) {
  const iv = rand(12);
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: VAULT_AAD }, key, te.encode(JSON.stringify(vault))),
  );
  return { iv: b64u.enc(iv), ct: b64u.enc(ct) };
}
export async function openVault(sealed, key) {
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: b64u.dec(sealed.iv), additionalData: VAULT_AAD },
    key,
    b64u.dec(sealed.ct),
  );
  return JSON.parse(td.decode(pt));
}

export const PBKDF2_ITER = 600000;
export async function keyFromPassphrase(passphrase, salt, iter = PBKDF2_ITER) {
  const base = await subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function keyFromPrf(prfBytes) {
  const ikm = await subtle.importKey('raw', prfBytes, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode('sealdrop/prf/v1') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function makeRecoveryFile(vault, passphrase, { iter = PBKDF2_ITER } = {}) {
  const salt = rand(16);
  const sealed = await sealVault(vault, await keyFromPassphrase(passphrase, salt, iter));
  return { app: 'sealdrop', v: 1, dropId: vault.dropId, kdf: { name: 'PBKDF2-SHA256', iter, salt: b64u.enc(salt) }, ...sealed };
}

export async function openRecoveryFile(file, passphrase) {
  if (!file || file.app !== 'sealdrop' || file.v !== 1 || file.kdf?.name !== 'PBKDF2-SHA256') throw new Error('not a sealdrop recovery file');
  const iter = file.kdf.iter;
  if (!Number.isInteger(iter) || iter < 1 || iter > 5_000_000) throw new Error('bad kdf parameters');
  return openVault(file, await keyFromPassphrase(passphrase, b64u.dec(file.kdf.salt), iter));
}

// ---- proof of work -----------------------------------------------------------------
export function leadingZeroBits(buf) {
  let n = 0;
  for (const b of buf) {
    if (b === 0) {
      n += 8;
      continue;
    }
    n += Math.clz32(b) - 24;
    break;
  }
  return n;
}

export async function solvePow({ c, s, bits }, onProgress) {
  const BATCH = 256;
  for (let base = 0; ; base += BATCH) {
    const hashes = await Promise.all(Array.from({ length: BATCH }, (_, i) => sha256(te.encode(`${c}.${base + i}`))));
    for (let i = 0; i < BATCH; i++) {
      if (leadingZeroBits(hashes[i]) >= bits) return { c, s, n: String(base + i) };
    }
    if (onProgress && (base / BATCH) % 16 === 0) {
      onProgress(base);
      await new Promise((r) => setTimeout(r));
    }
  }
}
