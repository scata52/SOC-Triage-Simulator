// Small, fast, seedable PRNG (mulberry32) so cases are reproducible.
// Enables "Case of the Day" (date-seeded) and deterministic testing.

export interface Rng {
  next(): number; // [0, 1)
  int(minInclusive: number, maxInclusive: number): number;
  pick<T>(items: readonly T[]): T;
  pickWeighted<T>(items: readonly { value: T; weight: number }[]): T;
  bool(probabilityTrue?: number): boolean;
  sample<T>(items: readonly T[], count: number): T[];
  shuffle<T>(items: readonly T[]): T[];
  hex(length: number): string;
}

// Hash an arbitrary string seed to a 32-bit integer (xmur3).
function xmur3(str: string): () => number {
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  return () => {
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    h ^= h >>> 16;
    return h >>> 0;
  };
}

function mulberry32(a: number): () => number {
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function createRng(seed: string | number): Rng {
  const seedStr = typeof seed === 'number' ? String(seed) : seed;
  const seedFn = xmur3(seedStr);
  const rand = mulberry32(seedFn());

  const rng: Rng = {
    next: () => rand(),
    int: (min, max) => {
      if (max < min) [min, max] = [max, min];
      return min + Math.floor(rand() * (max - min + 1));
    },
    pick: (items) => {
      if (items.length === 0) throw new Error('rng.pick from empty array');
      return items[Math.floor(rand() * items.length)];
    },
    pickWeighted: (items) => {
      const total = items.reduce((s, i) => s + i.weight, 0);
      let roll = rand() * total;
      for (const item of items) {
        roll -= item.weight;
        if (roll <= 0) return item.value;
      }
      return items[items.length - 1].value;
    },
    bool: (p = 0.5) => rand() < p,
    sample: (items, count) => rng.shuffle(items).slice(0, Math.max(0, count)),
    shuffle: (items) => {
      const arr = items.slice();
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      return arr;
    },
    hex: (length) => {
      let out = '';
      const chars = '0123456789abcdef';
      for (let i = 0; i < length; i++) out += chars[Math.floor(rand() * 16)];
      return out;
    },
  };
  return rng;
}

// A random-ish seed string for ad-hoc "next case" generation.
export function randomSeed(): string {
  return (
    Date.now().toString(36) +
    Math.floor(Math.random() * 0xffffffff).toString(36)
  );
}

// Stable date seed (local date) for Case of the Day.
export function dailySeed(date = new Date()): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `daily-${y}-${m}-${d}`;
}
