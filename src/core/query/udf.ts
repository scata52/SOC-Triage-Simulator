// JavaScript functions registered into SQLite so KQL semantics survive
// translation: term matching for `has`, case-insensitive string ops, regex,
// extract(), base64 decoding (UTF-16LE aware, for PowerShell -EncodedCommand),
// and aggregates for make_set / make_list / stdev.

import type { Database } from 'sql.js';
import { smartBase64Decode } from '../synth/encoding.ts';

type SqlVal = string | number | null | Uint8Array;

// sql.js ≥ 1.10 has Database.create_aggregate; @types/sql.js predates it.
interface AggregateFns<S> {
  init: () => S;
  step: (state: S, value: SqlVal) => S;
  finalize: (state: S) => string | number | null;
}
function createAggregate<S>(db: Database, name: string, fns: AggregateFns<S>): void {
  (db as unknown as { create_aggregate(n: string, f: AggregateFns<S>): void }).create_aggregate(name, fns);
}

const str = (v: SqlVal): string => (v === null || v === undefined ? '' : typeof v === 'string' ? v : v instanceof Uint8Array ? '' : String(v));

const regexCache = new Map<string, RegExp>();
function regex(pattern: string, flags = ''): RegExp {
  const key = `${flags}/${pattern}`;
  let re = regexCache.get(key);
  if (!re) {
    try {
      re = new RegExp(pattern, flags);
    } catch (e) {
      throw new Error(`Invalid regex ${JSON.stringify(pattern)}: ${(e as Error).message}`);
    }
    if (regexCache.size > 200) regexCache.clear();
    regexCache.set(key, re);
  }
  return re;
}

const isWordChar = (c: string | undefined) => !!c && /[A-Za-z0-9_]/.test(c);

// KQL `has`: the needle must occur as a whole term (bounded by non-word
// characters or the ends of the string).
export function kqlHas(haystack: string, needle: string, caseSensitive: boolean): boolean {
  if (!needle) return true;
  const h = caseSensitive ? haystack : haystack.toLowerCase();
  const n = caseSensitive ? needle : needle.toLowerCase();
  let from = 0;
  for (;;) {
    const i = h.indexOf(n, from);
    if (i < 0) return false;
    const before = h[i - 1];
    const after = h[i + n.length];
    const leftOk = !isWordChar(n[0]) || !isWordChar(before);
    const rightOk = !isWordChar(n[n.length - 1]) || !isWordChar(after);
    if (leftOk && rightOk) return true;
    from = i + 1;
  }
}

export function registerUdfs(db: Database): void {
  db.create_function('kql_contains', (h: SqlVal, n: SqlVal, cs: SqlVal) => {
    const a = str(h);
    const b = str(n);
    return (cs ? a.includes(b) : a.toLowerCase().includes(b.toLowerCase())) ? 1 : 0;
  });
  db.create_function('kql_has', (h: SqlVal, n: SqlVal, cs: SqlVal) => (kqlHas(str(h), str(n), !!cs) ? 1 : 0));
  db.create_function('kql_startswith', (h: SqlVal, n: SqlVal, cs: SqlVal) => {
    const a = str(h);
    const b = str(n);
    return (cs ? a.startsWith(b) : a.toLowerCase().startsWith(b.toLowerCase())) ? 1 : 0;
  });
  db.create_function('kql_endswith', (h: SqlVal, n: SqlVal, cs: SqlVal) => {
    const a = str(h);
    const b = str(n);
    return (cs ? a.endsWith(b) : a.toLowerCase().endsWith(b.toLowerCase())) ? 1 : 0;
  });
  db.create_function('kql_regex', (s: SqlVal, p: SqlVal) => (regex(str(p)).test(str(s)) ? 1 : 0));
  db.create_function('kql_extract', (p: SqlVal, g: SqlVal, s: SqlVal) => {
    const m = regex(str(p)).exec(str(s));
    if (!m) return '';
    return m[Number(g) || 0] ?? '';
  });
  db.create_function('kql_b64decode', (s: SqlVal) => smartBase64Decode(str(s))?.text ?? '');
  db.create_function('kql_countof', (s: SqlVal, sub: SqlVal) => {
    const a = str(s);
    const b = str(sub);
    if (!b) return 0;
    let n = 0;
    for (let i = a.indexOf(b); i >= 0; i = a.indexOf(b, i + b.length)) n++;
    return n;
  });
  db.create_function('kql_split', (s: SqlVal, d: SqlVal, i: SqlVal) => str(s).split(str(d))[Number(i) || 0] ?? '');

  createAggregate(db, 'kql_set', {
    init: () => [] as string[],
    step: (state: string[], v: SqlVal) => {
      const x = str(v);
      if (x !== '' && !state.includes(x) && state.length < 256) state.push(x);
      return state;
    },
    finalize: (state: string[]) => JSON.stringify(state),
  });
  createAggregate(db, 'kql_list', {
    init: () => [] as string[],
    step: (state: string[], v: SqlVal) => {
      if (state.length < 256) state.push(str(v));
      return state;
    },
    finalize: (state: string[]) => JSON.stringify(state),
  });
  createAggregate(db, 'kql_stdev', {
    init: () => [] as number[],
    step: (state: number[], v: SqlVal) => {
      if (typeof v === 'number') state.push(v);
      return state;
    },
    finalize: (state: number[]) => {
      if (state.length < 2) return 0;
      const mean = state.reduce((a, b) => a + b, 0) / state.length;
      const variance = state.reduce((a, b) => a + (b - mean) ** 2, 0) / (state.length - 1);
      return Math.sqrt(variance);
    },
  });
}
