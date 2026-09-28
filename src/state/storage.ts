// Profile persistence. localStorage can be missing, full, or throw (private
// windows, blocked site data), so every access is guarded and the app runs
// session-only when it has to. The v1 key is never modified: it stays as a
// backup after migration.

import { coerceProfile, defaultProfile, type Profile } from './profile.ts';

export const V2_KEY = 'soc-triage-sim:v2';
export const V1_KEY = 'soc-triage-sim:v1';

export interface KeyValueStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export type LoadSource = 'v2' | 'v1-migrated' | 'new' | 'recovered' | 'memory';

export function browserStorage(): KeyValueStore | null {
  try {
    const s = globalThis.localStorage;
    const probe = '__soc_probe__';
    s.setItem(probe, '1');
    s.removeItem(probe);
    return s;
  } catch {
    return null;
  }
}

export function newWorldSeed(): string {
  const bytes = new Uint8Array(8);
  globalThis.crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(36).padStart(2, '0')).join('').slice(0, 12);
}

export interface LoadContext {
  now: number;
  tzOffsetMinutes: number;
  newWorldSeed: () => string;
}

export function loadProfile(kv: KeyValueStore | null, ctx: LoadContext): { profile: Profile; source: LoadSource } {
  const fresh = () => defaultProfile(ctx.now, ctx.newWorldSeed());
  if (!kv) return { profile: fresh(), source: 'memory' };
  const read = (key: string): unknown => {
    try {
      const raw = kv.getItem(key);
      return raw ? (JSON.parse(raw) as unknown) : undefined;
    } catch {
      return null; // unreadable
    }
  };
  const coerceCtx = { now: ctx.now, tzOffsetMinutes: ctx.tzOffsetMinutes, newWorldSeed: ctx.newWorldSeed() };
  const v2 = read(V2_KEY);
  if (v2 !== undefined) {
    const p = v2 === null ? null : coerceProfile(v2, coerceCtx);
    if (p) return { profile: p, source: 'v2' };
    // Keep the unreadable blob rather than overwrite it on the next save.
    try {
      kv.setItem(`${V2_KEY}:unreadable:${ctx.now}`, kv.getItem(V2_KEY) ?? '');
    } catch {
      /* ignore */
    }
    return { profile: fresh(), source: 'recovered' };
  }
  const v1 = read(V1_KEY);
  if (v1) {
    const p = coerceProfile(v1, coerceCtx);
    if (p) return { profile: p, source: 'v1-migrated' };
  }
  return { profile: fresh(), source: 'new' };
}

export function saveProfile(kv: KeyValueStore | null, p: Profile): boolean {
  if (!kv) return false;
  try {
    kv.setItem(V2_KEY, JSON.stringify(p));
    return true;
  } catch {
    return false;
  }
}

export function exportProfile(p: Profile): string {
  return JSON.stringify(p, null, 2);
}

export function importProfile(json: string, ctx: LoadContext): Profile | null {
  try {
    return coerceProfile(JSON.parse(json) as unknown, { now: ctx.now, tzOffsetMinutes: ctx.tzOffsetMinutes, newWorldSeed: ctx.newWorldSeed() });
  } catch {
    return null;
  }
}
