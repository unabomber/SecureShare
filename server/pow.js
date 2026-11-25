import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

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

/**
 * Stateless-issue, single-use proof-of-work. A challenge is `<expiry>.<random>`
 * authenticated by an HMAC bound to the purpose ("create" | "submit"). A solution is
 * a decimal nonce n with sha256(`${challenge}.${n}`) having `bits` leading zero bits.
 */
export function createPow({ bits, ttlSec = 300, maxUsed = 100000, now = Date.now }) {
  const secret = randomBytes(32);
  const used = new Map();
  const mac = (purpose, c) =>
    createHmac('sha256', secret).update(`${purpose}.${c}`).digest().subarray(0, 16).toString('base64url');

  return {
    bits,
    issue(purpose) {
      const exp = Math.floor(now() / 1000) + ttlSec;
      const c = `${exp}.${randomBytes(12).toString('base64url')}`;
      return { c, s: mac(purpose, c), bits };
    },
    verify(purpose, pow) {
      if (!pow || typeof pow !== 'object') return false;
      const { c, s, n } = pow;
      if (typeof c !== 'string' || typeof s !== 'string' || typeof n !== 'string') return false;
      if (c.length > 64 || s.length > 32 || !/^\d{1,12}$/.test(n)) return false;
      const exp = Number(c.split('.')[0]);
      if (!(exp * 1000 > now())) return false;
      const a = Buffer.from(s);
      const b = Buffer.from(mac(purpose, c));
      if (a.length !== b.length || !timingSafeEqual(a, b)) return false;
      if (used.has(c)) return false;
      const h = createHash('sha256').update(`${c}.${n}`).digest();
      if (leadingZeroBits(h) < bits) return false;
      if (used.size >= maxUsed) this.sweep();
      if (used.size >= maxUsed) return false;
      used.set(c, exp);
      return true;
    },
    sweep() {
      const t = Math.floor(now() / 1000);
      for (const [k, e] of used) if (e <= t) used.delete(k);
    },
  };
}
