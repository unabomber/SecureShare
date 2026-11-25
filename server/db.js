import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Storage holds only: random id, SHA-256 of the recipient's read token, ciphertext,
 * expiry. No public keys, no plaintext, no IPs, no creation timestamps.
 */
export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA secure_delete = ON;
    CREATE TABLE IF NOT EXISTS drops (
      id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL,
      ciphertext BLOB,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS drops_expires ON drops(expires_at);
  `);

  const q = {
    create: db.prepare('INSERT INTO drops (id, token_hash, expires_at) VALUES (?, ?, ?)'),
    get: db.prepare('SELECT id, token_hash, ciphertext, expires_at FROM drops WHERE id = ? AND expires_at > ?'),
    fill: db.prepare('UPDATE drops SET ciphertext = ? WHERE id = ? AND ciphertext IS NULL AND expires_at > ?'),
    remove: db.prepare('DELETE FROM drops WHERE id = ?'),
    sweep: db.prepare('DELETE FROM drops WHERE expires_at <= ?'),
    count: db.prepare('SELECT COUNT(*) AS n FROM drops'),
  };

  return {
    create: (id, tokenHash, expiresAt) => q.create.run(id, tokenHash, expiresAt),
    get: (id, nowSec) => q.get.get(id, nowSec),
    fill: (id, blob, nowSec) => q.fill.run(blob, id, nowSec).changes,
    remove: (id) => q.remove.run(id).changes,
    sweep: (nowSec) => q.sweep.run(nowSec).changes,
    count: () => Number(q.count.get().n),
    checkpoint: () => db.exec('PRAGMA wal_checkpoint(TRUNCATE)'),
    close: () => db.close(),
  };
}
