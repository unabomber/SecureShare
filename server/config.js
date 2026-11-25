import { fileURLToPath } from 'node:url';

const int = (v, d) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) && n >= 0 ? n : d;
};

export function loadConfig(env = process.env) {
  return {
    port: int(env.PORT, 8080),
    host: env.HOST || '0.0.0.0',
    dbPath: env.DB_PATH || './data/sealdrop.db',
    publicDir: env.PUBLIC_DIR || fileURLToPath(new URL('../public', import.meta.url)),
    // Header carrying the real client IP when behind a trusted proxy (e.g. x-real-ip).
    clientIpHeader: (env.CLIENT_IP_HEADER || '').toLowerCase(),
    powBits: int(env.POW_BITS, 17),
    maxSecretBytes: int(env.MAX_SECRET_BYTES, 8192),
    maxDrops: int(env.MAX_DROPS, 20000),
    ttls: [3600, 86400, 604800],
    limits: {
      general: { capacity: 120, perSec: 2 },
      create: { capacity: 10, perSec: 10 / 3600 },
      submit: { capacity: 20, perSec: 20 / 3600 },
    },
  };
}

// Padding bucket and fixed overhead of the ciphertext format (see public/crypto.js).
export const BUCKET = 1024;
export const BLOB_OVERHEAD = 1 + 65 + 12 + 16; // version + ephemeral pubkey + iv + GCM tag

export function maxBlobBytes(maxSecretBytes) {
  return Math.ceil((maxSecretBytes + 2) / BUCKET) * BUCKET + BLOB_OVERHEAD;
}
export const minBlobBytes = BUCKET + BLOB_OVERHEAD;
