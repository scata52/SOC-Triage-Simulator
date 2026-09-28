// Seedable PRNG (xmur3 seed hash + mulberry32). Everything generated in core/
// flows from one of these so cases, corpora and worlds are reproducible.
// Never use Math.random or Date.now inside core/.

export interface Rng {
  readonly seed: string;
  next(): number; // [0, 1)
  int(minInclusive: number, maxInclusive: number): number;
  float(min: number, max: number): number;
  pick<T>(items: readonly T[]): T;
  pickWeighted<T>(items: readonly { value: T; weight: number }[]): T;
  bool(probabilityTrue?: number): boolean;
  sample<T>(items: readonly T[], count: number): T[];
  shuffle<T>(items: readonly T[]): T[];
  hex(length: number): string;
  alnum(length: number): string;
  gaussian(mean?: number, stdDev?: number): number;
  // An independent stream derived from this seed and a label. Forks are
  // stable: adding draws to the parent does not change a fork's output.
  fork(label: string): Rng;
}

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

const HEX = '0123456789abcdef';
const ALNUM = 'abcdefghijkmnpqrstuvwxyz23456789'; // no l/o/0/1 look-alikes

export function createRng(seed: string | number): Rng {
  const seedStr = String(seed);
  const rand = mulberry32(xmur3(seedStr)());

  const rng: Rng = {
    seed: seedStr,
    next: () => rand(),
    int(min, max) {
      if (max < min) [min, max] = [max, min];
      return min + Math.floor(rand() * (max - min + 1));
    },
    float: (min, max) => min + rand() * (max - min),
    pick(items) {
      if (items.length === 0) throw new Error('rng.pick from empty array');
      return items[Math.floor(rand() * items.length)];
    },
    pickWeighted(items) {
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
    shuffle(items) {
      const arr = items.slice();
      for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      return arr;
    },
    hex(length) {
      let out = '';
      for (let i = 0; i < length; i++) out += HEX[Math.floor(rand() * 16)];
      return out;
    },
    alnum(length) {
      let out = '';
      for (let i = 0; i < length; i++) out += ALNUM[Math.floor(rand() * ALNUM.length)];
      return out;
    },
    gaussian(mean = 0, stdDev = 1) {
      // Box–Muller; clamp u away from 0 so log() is finite.
      const u = Math.max(rand(), 1e-12);
      const v = rand();
      return mean + stdDev * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
    },
    fork: (label) => createRng(`${seedStr}/${label}`),
  };
  return rng;
}
