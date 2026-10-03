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

// What this tab keeps in sessionStorage (never in the profile): case drafts and console text ("draft:", "q:"), vulnerability
// case drafts, finished attempts and console text ("vdraft:", "vdone:", "vq:") and the last shift's handover.
export const HANDOVER_KEY = 'soc-last-handover';
export const SESSION_KEY_PREFIXES = ['draft:', 'q:', 'vdraft:', 'vdone:', 'vq:'] as const;

export interface SessionStore {
  readonly length: number;
  key(index: number): string | null;
  removeItem(key: string): void;
}

// Removes this app's keys from the tab's session store, so "Reset everything" really leaves nothing behind.
// Other keys are left alone. Never throws: an unavailable store is simply skipped.
export function clearTabSession(store?: SessionStore | null): void {
  try {
    const s = store === undefined ? globalThis.sessionStorage : store;
    if (!s) return;
    const mine: string[] = [];
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i);
      if (k !== null && (k === HANDOVER_KEY || SESSION_KEY_PREFIXES.some((p) => k.startsWith(p)))) mine.push(k);
    }
    for (const k of mine) s.removeItem(k);
  } catch {
    /* storage unavailable: nothing to clear */
  }
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
  // A blob that makes migration throw is treated as unreadable, never fatal.
  const coerce = (raw: unknown) => {
    try {
      return coerceProfile(raw, coerceCtx);
    } catch {
      return null;
    }
  };
  const v2 = read(V2_KEY);
  if (v2 !== undefined) {
    const p = v2 === null ? null : coerce(v2);
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
    const p = coerce(v1);
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

// Another tab saved: adopt its copy (null if it cannot be read).
export function parseStored(raw: string | null, ctx: LoadContext): Profile | null {
  if (!raw) return null;
  return importProfile(raw, ctx);
}
