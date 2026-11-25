/** In-memory token bucket per key. Fails open (untracked) if the table is saturated. */
export function createLimiter({ capacity, perSec, max = 50000, now = Date.now }) {
  const buckets = new Map();
  const refill = (b, t) => Math.min(capacity, b.tokens + ((t - b.at) / 1000) * perSec);

  return {
    take(key) {
      const t = now();
      let b = buckets.get(key);
      if (!b) {
        if (buckets.size >= max) this.sweep();
        if (buckets.size >= max) return true;
        b = { tokens: capacity, at: t };
        buckets.set(key, b);
      }
      b.tokens = refill(b, t);
      b.at = t;
      if (b.tokens < 1) return false;
      b.tokens -= 1;
      return true;
    },
    sweep() {
      const t = now();
      for (const [k, b] of buckets) if (refill(b, t) >= capacity) buckets.delete(k);
    },
  };
}
