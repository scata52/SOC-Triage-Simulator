// KQL AST → SQLite SQL. Each tabular operator wraps the previous relation in
// a subquery with explicit column lists, so column names and types are always
// known (used for validation, did-you-mean suggestions, datetime arithmetic,
// and carrying RecordId through row-preserving operators so results stay
// pinnable as evidence).

import { KqlError } from './lexer.ts';
import { parseKql } from './parser.ts';
import type { Expr, NamedExpr, Operator, Program, Query, SortKey, Source } from './ast.ts';
import type { ColumnType, TableInfo } from '../../logs/schema.ts';

export type KType = ColumnType | 'timespan' | 'dynamic' | 'unknown';

export interface RelColumn {
  name: string;
  type: KType;
  hidden?: boolean;
}

interface SortRef {
  sql: string;
  refs: string[];
}

interface Rel {
  sql: string;
  cols: RelColumn[];
  sort: SortRef[] | null;
  rowPreserving: boolean;
}

export interface TranspileOptions {
  now: string; // ISO — anchors ago() and now()
  tables: readonly TableInfo[];
}

export interface Transpiled {
  sql: string;
  columns: RelColumn[];
  render: string | null;
  rowPreserving: boolean;
}

interface Ctx {
  opts: TranspileOptions;
  lets: Map<string, Expr>;
  nowMs: number;
}

interface ExprOut {
  sql: string;
  type: KType;
  refs: string[];
}

export function q(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}

function lit(s: string): string {
  return `'${s.replace(/'/g, "''")}'`;
}

function isoOf(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

const toEpoch = (sql: string) => `CAST(strftime('%s', ${sql}) AS INTEGER)`;
const fromEpoch = (sql: string) => `strftime('%Y-%m-%dT%H:%M:%SZ', ${sql}, 'unixepoch')`;

// ------------------------------------------------------------------ suggest
export function levenshtein(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

export function suggest(name: string, candidates: string[]): string | null {
  const exactCi = candidates.find((c) => c.toLowerCase() === name.toLowerCase());
  if (exactCi) return exactCi;
  let best: string | null = null;
  let bestD = Infinity;
  for (const c of candidates) {
    const d = levenshtein(name.toLowerCase(), c.toLowerCase());
    if (d < bestD) {
      bestD = d;
      best = c;
    }
  }
  const prefix = candidates.find((c) => c.toLowerCase().startsWith(name.toLowerCase()) && name.length >= 3);
  if (prefix) return prefix;
  return best && bestD <= Math.max(2, Math.floor(name.length / 4)) ? best : null;
}

// ------------------------------------------------------------------ entry
export function transpileKql(src: string, opts: TranspileOptions): Transpiled {
  return transpileProgram(parseKql(src), opts);
}

export function transpileProgram(p: Program, opts: TranspileOptions): Transpiled {
  const ctx: Ctx = { opts, lets: p.lets, nowMs: Date.parse(opts.now) };
  let render: string | null = null;
  const rel = query(ctx, p.query, (kind) => {
    render = kind;
  });
  const visible = rel.cols;
  return { sql: rel.sql, columns: visible, render, rowPreserving: rel.rowPreserving };
}

function query(ctx: Ctx, qy: Query, onRender: (kind: string) => void): Rel {
  let rel = source(ctx, qy.source);
  for (const op of qy.ops) rel = operator(ctx, rel, op, onRender);
  return rel;
}

function source(ctx: Ctx, s: Source): Rel {
  const tables = ctx.opts.tables;
  if (s.k === 'table') {
    const t = tables.find((x) => x.name === s.name);
    if (!t) {
      const hint = suggest(s.name, tables.map((x) => x.name));
      throw new KqlError(`Unknown table "${s.name}".${hint ? ` Did you mean ${hint}?` : ''}`, s.start, s.end);
    }
    const cols: RelColumn[] = t.columns.map((c) => ({ name: c.name, type: c.type }));
    return { sql: `SELECT * FROM ${q(t.name)}`, cols, sort: null, rowPreserving: true };
  }
  // search: union of every table's rows containing the term.
  const selected = s.tables
    ? s.tables.map((name) => {
        const t = tables.find((x) => x.name === name);
        if (!t) throw new KqlError(`Unknown table "${name}" in search`, s.start, s.end);
        return t;
      })
    : [...tables];
  const needle = lit(s.term.toLowerCase());
  const parts = selected.map((t) => {
    const valueCols = t.columns.filter((c) => c.name !== 'RecordId' && c.name !== 'TimeGenerated');
    const hay = valueCols.map((c) => `COALESCE(CAST(${q(c.name)} AS TEXT), '')`).join(" || '|' || ");
    const details = valueCols
      .map((c) => `CASE WHEN ${q(c.name)} IS NOT NULL AND CAST(${q(c.name)} AS TEXT) <> '' THEN ${lit(c.name + '=')} || CAST(${q(c.name)} AS TEXT) || '  ' ELSE '' END`)
      .join(' || ');
    const time = t.columns.some((c) => c.name === 'TimeGenerated') ? q('TimeGenerated') : 'NULL';
    return `SELECT ${lit(t.name)} AS "$table", ${time} AS "TimeGenerated", ${q('RecordId')} AS "RecordId", substr(${details}, 1, 600) AS "Details" FROM ${q(t.name)} WHERE instr(lower(${hay}), ${needle}) > 0`;
  });
  return {
    sql: `SELECT * FROM (${parts.join(' UNION ALL ')})`,
    cols: [
      { name: '$table', type: 'string' },
      { name: 'TimeGenerated', type: 'datetime' },
      { name: 'Details', type: 'string' },
      { name: 'RecordId', type: 'string' },
    ],
    sort: null,
    rowPreserving: true,
  };
}

function selectList(cols: RelColumn[]): string {
  return cols.map((c) => q(c.name)).join(', ');
}

function orderClause(rel: Rel, cols: RelColumn[]): string {
  if (!rel.sort || rel.sort.length === 0) return '';
  const names = new Set(cols.map((c) => c.name));
  if (!rel.sort.every((k) => k.refs.every((r) => names.has(r)))) return '';
  return ` ORDER BY ${rel.sort.map((k) => k.sql).join(', ')}`;
}

function keepSort(rel: Rel, cols: RelColumn[]): SortRef[] | null {
  if (!rel.sort) return null;
  const names = new Set(cols.map((c) => c.name));
  return rel.sort.every((k) => k.refs.every((r) => names.has(r))) ? rel.sort : null;
}

function withRecordId(rel: Rel, cols: RelColumn[]): RelColumn[] {
  if (!rel.rowPreserving) return cols;
  if (cols.some((c) => c.name === 'RecordId')) return cols;
  const rid = rel.cols.find((c) => c.name === 'RecordId');
  return rid ? [...cols, { name: 'RecordId', type: 'string', hidden: true }] : cols;
}

function matchPattern(pattern: string, name: string): boolean {
  if (!pattern.includes('*')) return pattern === name;
  const re = new RegExp(`^${pattern.split('*').map((p) => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
  return re.test(name);
}

function operator(ctx: Ctx, rel: Rel, op: Operator, onRender: (kind: string) => void): Rel {
  switch (op.op) {
    case 'where': {
      const e = expr(ctx, rel, op.pred);
      return { ...rel, sql: `SELECT ${selectList(rel.cols)} FROM (${rel.sql}) WHERE ${e.sql}${orderClause(rel, rel.cols)}` };
    }
    case 'extend': {
      let cols = [...rel.cols];
      const exprs = new Map<string, string>();
      let auto = 1;
      for (const item of op.items) {
        const current: Rel = { ...rel, cols };
        const e = expr(ctx, current, item.expr);
        const name = item.name ?? `Column${auto++}`;
        exprs.set(name, e.sql);
        const existing = cols.findIndex((c) => c.name === name);
        const col: RelColumn = { name, type: e.type };
        if (existing >= 0) cols[existing] = col;
        else cols.push(col);
      }
      const list = cols.map((c) => (exprs.has(c.name) ? `${exprs.get(c.name)} AS ${q(c.name)}` : q(c.name))).join(', ');
      // Later items may reference earlier ones: nest one SELECT per item if so.
      const refsEarlier = op.items.some((it, i) => i > 0 && exprRefs(it.expr).some((r) => op.items.slice(0, i).some((p) => p.name === r)));
      if (refsEarlier) {
        let acc = rel;
        for (const item of op.items) acc = operator(ctx, acc, { op: 'extend', items: [item], start: op.start, end: op.end }, onRender);
        return acc;
      }
      return { ...rel, sql: `SELECT ${list} FROM (${rel.sql})${orderClause(rel, cols)}`, cols, sort: keepSort(rel, cols) };
    }
    case 'project': {
      const cols: RelColumn[] = [];
      const parts: string[] = [];
      let auto = 1;
      for (const item of op.items) {
        if (item.expr.k === 'star') throw new KqlError('project * is not needed — omit project to keep every column', item.expr.start, item.expr.end);
        const e = expr(ctx, rel, item.expr);
        const name = item.name ?? (item.expr.k === 'ident' ? item.expr.name : `Column${auto++}`);
        if (cols.some((c) => c.name === name)) throw new KqlError(`Column "${name}" appears twice in project`, item.expr.start, item.expr.end);
        cols.push({ name, type: e.type });
        parts.push(item.expr.k === 'ident' && item.name === null ? q(name) : `${e.sql} AS ${q(name)}`);
      }
      const finalCols = withRecordId(rel, cols);
      if (finalCols.length > cols.length) parts.push(q('RecordId'));
      return { ...rel, sql: `SELECT ${parts.join(', ')} FROM (${rel.sql})${orderClause(rel, finalCols)}`, cols: finalCols, sort: keepSort(rel, finalCols) };
    }
    case 'project-away': {
      let cols = [...rel.cols];
      for (const c of op.cols) {
        const matched = cols.filter((x) => matchPattern(c.pattern, x.name));
        if (matched.length === 0) {
          const hint = suggest(c.pattern, cols.map((x) => x.name));
          throw new KqlError(`No column "${c.pattern}" to remove.${hint ? ` Did you mean ${hint}?` : ''}`, c.span.start, c.span.end);
        }
        // RecordId is hidden rather than dropped so rows stay pinnable.
        cols = cols.flatMap((x) => (matched.includes(x) ? (x.name === 'RecordId' && rel.rowPreserving ? [{ ...x, hidden: true }] : []) : [x]));
      }
      return { ...rel, sql: `SELECT ${selectList(cols)} FROM (${rel.sql})${orderClause(rel, cols)}`, cols, sort: keepSort(rel, cols) };
    }
    case 'project-reorder': {
      const first: RelColumn[] = [];
      for (const c of op.cols) {
        const matched = rel.cols.filter((x) => matchPattern(c.pattern, x.name) && !first.includes(x));
        if (matched.length === 0) throw new KqlError(`No column "${c.pattern}"`, c.span.start, c.span.end);
        first.push(...matched);
      }
      const cols = [...first, ...rel.cols.filter((c) => !first.includes(c))];
      return { ...rel, sql: `SELECT ${selectList(cols)} FROM (${rel.sql})${orderClause(rel, cols)}`, cols };
    }
    case 'project-rename': {
      const cols = rel.cols.map((c) => ({ ...c }));
      const parts = new Map<string, string>();
      for (const it of op.items) {
        const col = cols.find((c) => c.name === it.from);
        if (!col) {
          const hint = suggest(it.from, cols.map((c) => c.name));
          throw new KqlError(`No column "${it.from}" to rename.${hint ? ` Did you mean ${hint}?` : ''}`, it.span.start, it.span.end);
        }
        parts.set(it.to, it.from);
        col.name = it.to;
      }
      const list = cols.map((c) => (parts.has(c.name) ? `${q(parts.get(c.name)!)} AS ${q(c.name)}` : q(c.name))).join(', ');
      return { ...rel, sql: `SELECT ${list} FROM (${rel.sql})`, cols, sort: null };
    }
    case 'summarize': {
      const cols: RelColumn[] = [];
      const parts: string[] = [];
      const groups: string[] = [];
      let auto = 1;
      for (const b of op.by) {
        const e = expr(ctx, rel, b.expr);
        const name = b.name ?? byName(b) ?? `Column${auto++}`;
        cols.push({ name, type: e.type });
        parts.push(`${e.sql} AS ${q(name)}`);
        groups.push(e.sql);
      }
      for (const a of op.aggs) {
        const e = expr(ctx, rel, a.expr, true);
        if (!containsAggregate(a.expr)) throw new KqlError('Each summarize item needs an aggregation such as count(), dcount(), min(), max(), sum() or make_set()', a.expr.start, a.expr.end);
        const name = a.name ?? aggName(a.expr) ?? `Column${auto++}`;
        if (cols.some((c) => c.name === name)) throw new KqlError(`Column "${name}" appears twice — name it, e.g. ${name}2 = …`, a.expr.start, a.expr.end);
        cols.push({ name, type: e.type });
        parts.push(`${e.sql} AS ${q(name)}`);
      }
      const group = groups.length ? ` GROUP BY ${groups.join(', ')}` : '';
      return { sql: `SELECT ${parts.join(', ')} FROM (${rel.sql})${group}`, cols, sort: null, rowPreserving: false };
    }
    case 'sort': {
      const keys = op.keys.map((k) => sortRef(ctx, rel, k));
      return { ...rel, sql: `SELECT ${selectList(rel.cols)} FROM (${rel.sql}) ORDER BY ${keys.map((k) => k.sql).join(', ')}`, sort: keys };
    }
    case 'take':
      return { ...rel, sql: `SELECT ${selectList(rel.cols)} FROM (${rel.sql})${orderClause(rel, rel.cols)} LIMIT ${op.n}` };
    case 'top': {
      const key = sortRef(ctx, rel, op.key);
      return { ...rel, sql: `SELECT ${selectList(rel.cols)} FROM (${rel.sql}) ORDER BY ${key.sql} LIMIT ${op.n}`, sort: [key] };
    }
    case 'distinct': {
      if (op.cols === '*') {
        const cols = rel.cols.filter((c) => !c.hidden && c.name !== 'RecordId');
        return { sql: `SELECT DISTINCT ${selectList(cols)} FROM (${rel.sql})`, cols, sort: null, rowPreserving: false };
      }
      const cols: RelColumn[] = [];
      const parts: string[] = [];
      let auto = 1;
      for (const c of op.cols) {
        const e = expr(ctx, rel, c);
        const name = c.k === 'ident' ? c.name : `Column${auto++}`;
        cols.push({ name, type: e.type });
        parts.push(`${e.sql} AS ${q(name)}`);
      }
      return { sql: `SELECT DISTINCT ${parts.join(', ')} FROM (${rel.sql})`, cols, sort: null, rowPreserving: false };
    }
    case 'count':
      return { sql: `SELECT COUNT(*) AS "Count" FROM (${rel.sql})`, cols: [{ name: 'Count', type: 'int' }], sort: null, rowPreserving: false };
    case 'serialize':
      // Freeze the current order: an empty key list lets prev()/next() run.
      return rel.sort ? rel : { ...rel, sort: [] };
    case 'render':
      onRender(op.kind);
      return rel;
    case 'getschema': {
      const visible = rel.cols.filter((c) => !c.hidden);
      const docs = new Map<string, string>();
      for (const t of ctx.opts.tables) for (const c of t.columns) if (!docs.has(c.name)) docs.set(c.name, c.doc);
      const rows = visible.map((c, i) => `(${lit(c.name)}, ${i}, ${lit(c.type)}, ${lit(docs.get(c.name) ?? '')})`).join(', ');
      return {
        sql: `SELECT column1 AS "ColumnName", column2 AS "ColumnOrdinal", column3 AS "ColumnType", column4 AS "Description" FROM (VALUES ${rows})`,
        cols: [
          { name: 'ColumnName', type: 'string' },
          { name: 'ColumnOrdinal', type: 'int' },
          { name: 'ColumnType', type: 'string' },
          { name: 'Description', type: 'string' },
        ],
        sort: null,
        rowPreserving: false,
      };
    }
    case 'join': {
      const right = query(ctx, op.right, () => {});
      for (const k of op.on) {
        if (!rel.cols.some((c) => c.name === k.left)) throw new KqlError(`Left side has no column "${k.left}"`, k.span.start, k.span.end);
        if (!right.cols.some((c) => c.name === k.right)) throw new KqlError(`Right side has no column "${k.right}"`, k.span.start, k.span.end);
      }
      const cond = op.on.map((k) => `l.${q(k.left)} = r.${q(k.right)}`).join(' AND ');
      if (op.kind === 'leftanti' || op.kind === 'leftsemi') {
        const exists = `${op.kind === 'leftanti' ? 'NOT ' : ''}EXISTS (SELECT 1 FROM (${right.sql}) AS r WHERE ${cond})`;
        return { ...rel, sql: `SELECT ${rel.cols.map((c) => `l.${q(c.name)}`).join(', ')} FROM (${rel.sql}) AS l WHERE ${exists}`, sort: null };
      }
      const cols: RelColumn[] = rel.cols.map((c) => ({ ...c }));
      const parts = rel.cols.map((c) => `l.${q(c.name)} AS ${q(c.name)}`);
      for (const c of right.cols) {
        if (c.hidden || c.name === 'RecordId') continue;
        let name = c.name;
        if (cols.some((x) => x.name === name)) name = `${c.name}1`;
        cols.push({ name, type: c.type });
        parts.push(`r.${q(c.name)} AS ${q(name)}`);
      }
      const joinKw = op.kind === 'leftouter' ? 'LEFT JOIN' : 'JOIN';
      return { sql: `SELECT ${parts.join(', ')} FROM (${rel.sql}) AS l ${joinKw} (${right.sql}) AS r ON ${cond}`, cols, sort: null, rowPreserving: rel.rowPreserving };
    }
  }
}

function sortRef(ctx: Ctx, rel: Rel, k: SortKey): SortRef {
  const e = expr(ctx, rel, k.expr);
  // KQL puts nulls last when descending and first when ascending — as SQLite.
  return { sql: `${e.sql} ${k.dir.toUpperCase()}`, refs: e.refs };
}

function byName(b: NamedExpr): string | null {
  const e = b.expr;
  if (e.k === 'ident') return e.name;
  if (e.k === 'call' && ['bin', 'floor', 'startofday', 'startofhour'].includes(e.name.toLowerCase()) && e.args[0]?.k === 'ident') return e.args[0].name;
  return null;
}

const AGG_PREFIX: Record<string, string> = {
  count: 'count_',
  countif: 'countif_',
  dcount: 'dcount_',
  dcountif: 'dcountif_',
  sum: 'sum_',
  sumif: 'sumif_',
  avg: 'avg_',
  avgif: 'avgif_',
  min: 'min_',
  max: 'max_',
  make_set: 'set_',
  make_list: 'list_',
  stdev: 'stdev_',
  take_any: '',
  any: '',
  arg_max: 'max_',
  arg_min: 'min_',
};

function aggName(e: Expr): string | null {
  if (e.k !== 'call') return null;
  const fn = e.name.toLowerCase();
  if (!(fn in AGG_PREFIX)) return null;
  if (fn === 'count' || fn === 'countif') return AGG_PREFIX[fn];
  const a = e.args[0];
  if (a?.k === 'ident') return `${AGG_PREFIX[fn]}${a.name}`;
  return null;
}

const AGGREGATES = new Set(Object.keys(AGG_PREFIX));

function containsAggregate(e: Expr): boolean {
  switch (e.k) {
    case 'call':
      return AGGREGATES.has(e.name.toLowerCase()) || e.args.some(containsAggregate);
    case 'binary':
    case 'strop':
      return containsAggregate(e.l) || containsAggregate(e.r);
    case 'unary':
      return containsAggregate(e.e);
    default:
      return false;
  }
}

function exprRefs(e: Expr): string[] {
  switch (e.k) {
    case 'ident':
      return [e.name];
    case 'call':
      return e.args.flatMap(exprRefs);
    case 'binary':
    case 'strop':
      return [...exprRefs(e.l), ...exprRefs(e.r)];
    case 'unary':
      return exprRefs(e.e);
    case 'in':
      return [...exprRefs(e.e), ...e.list.flatMap(exprRefs)];
    case 'between':
      return [...exprRefs(e.e), ...exprRefs(e.lo), ...exprRefs(e.hi)];
    default:
      return [];
  }
}

// ------------------------------------------------------------------ expressions
function expr(ctx: Ctx, rel: Rel, e: Expr, aggOk = false): ExprOut {
  const x = (sub: Expr) => expr(ctx, rel, sub, aggOk);
  switch (e.k) {
    case 'ident': {
      const col = rel.cols.find((c) => c.name === e.name);
      if (col) return { sql: q(col.name), type: col.type, refs: [col.name] };
      const bound = ctx.lets.get(e.name);
      if (bound) return expr(ctx, rel, bound, aggOk);
      const hint = suggest(e.name, rel.cols.filter((c) => !c.hidden || c.name === 'RecordId').map((c) => c.name));
      const ci = hint && hint.toLowerCase() === e.name.toLowerCase();
      const quoteHint = !hint ? ` If you meant the text "${e.name}", strings need quotes.` : '';
      throw new KqlError(
        `Unknown column "${e.name}".${hint ? ` Did you mean ${hint}?${ci ? ' (column names are case-sensitive)' : ''}` : ''}${quoteHint}`,
        e.start,
        e.end,
      );
    }
    case 'str':
      return { sql: lit(e.v), type: 'string', refs: [] };
    case 'num':
      return { sql: String(e.v), type: Number.isInteger(e.v) ? 'int' : 'real', refs: [] };
    case 'bool':
      return { sql: e.v ? '1' : '0', type: 'bool', refs: [] };
    case 'null':
      return { sql: 'NULL', type: 'unknown', refs: [] };
    case 'timespan':
      return { sql: String(e.seconds), type: 'timespan', refs: [] };
    case 'datetime':
      return { sql: lit(e.iso), type: 'datetime', refs: [] };
    case 'list':
      throw new KqlError('A list is only valid on the right of in / !in', e.start, e.end);
    case 'star':
      throw new KqlError('* is not valid here', e.start, e.end);
    case 'unary': {
      const inner = x(e.e);
      if (e.op === 'not') return { sql: `(NOT (${inner.sql}))`, type: 'bool', refs: inner.refs };
      return { sql: `(-${inner.sql})`, type: inner.type, refs: inner.refs };
    }
    case 'binary':
      return binary(e.op, x(e.l), x(e.r), e);
    case 'strop': {
      const l = x(e.l);
      const r = x(e.r);
      const refs = [...l.refs, ...r.refs];
      const L = `CAST(${l.sql} AS TEXT)`;
      const R = `CAST(${r.sql} AS TEXT)`;
      let sql: string;
      switch (e.op) {
        case 'contains':
          sql = `kql_contains(${L}, ${R}, 0)`;
          break;
        case 'contains_cs':
          sql = `kql_contains(${L}, ${R}, 1)`;
          break;
        case 'has':
          sql = `kql_has(${L}, ${R}, 0)`;
          break;
        case 'has_cs':
          sql = `kql_has(${L}, ${R}, 1)`;
          break;
        case 'startswith':
        case 'hasprefix':
          sql = `kql_startswith(${L}, ${R}, 0)`;
          break;
        case 'startswith_cs':
          sql = `kql_startswith(${L}, ${R}, 1)`;
          break;
        case 'endswith':
        case 'hassuffix':
          sql = `kql_endswith(${L}, ${R}, 0)`;
          break;
        case 'endswith_cs':
          sql = `kql_endswith(${L}, ${R}, 1)`;
          break;
        case 'matches':
          sql = `kql_regex(${L}, ${R})`;
          break;
        default:
          throw new KqlError(`Unsupported operator ${e.op}`, e.start, e.end);
      }
      return { sql: e.negate ? `(NOT ${sql})` : sql, type: 'bool', refs };
    }
    case 'in': {
      const v = x(e.e);
      // A let-bound dynamic([...]) list expands in place.
      const flat = e.list.flatMap((i) => {
        const bound = i.k === 'ident' && !rel.cols.some((c) => c.name === i.name) ? ctx.lets.get(i.name) : undefined;
        return bound?.k === 'list' ? bound.items : [i];
      });
      const items = flat.map((i) => x(i));
      const lhs = e.ci ? `lower(CAST(${v.sql} AS TEXT))` : v.sql;
      const list = items.map((i) => (e.ci ? `lower(CAST(${i.sql} AS TEXT))` : i.sql)).join(', ');
      const sql = `(${lhs} IN (${list}))`;
      return { sql: e.negate ? `(NOT ${sql})` : sql, type: 'bool', refs: [...v.refs, ...items.flatMap((i) => i.refs)] };
    }
    case 'between': {
      const v = x(e.e);
      const lo = x(e.lo);
      const hi = x(e.hi);
      const sql = `(${v.sql} BETWEEN ${lo.sql} AND ${hi.sql})`;
      return { sql: e.negate ? `(NOT ${sql})` : sql, type: 'bool', refs: [...v.refs, ...lo.refs, ...hi.refs] };
    }
    case 'call':
      return call(ctx, rel, e, aggOk);
  }
}

function binary(op: string, l: ExprOut, r: ExprOut, e: Expr): ExprOut {
  const refs = [...l.refs, ...r.refs];
  switch (op) {
    case 'and':
      return { sql: `(${l.sql} AND ${r.sql})`, type: 'bool', refs };
    case 'or':
      return { sql: `(${l.sql} OR ${r.sql})`, type: 'bool', refs };
    case '==':
      return { sql: `(${l.sql} = ${r.sql})`, type: 'bool', refs };
    case '!=':
      return { sql: `(${l.sql} <> ${r.sql})`, type: 'bool', refs };
    case '=~':
      return { sql: `(lower(CAST(${l.sql} AS TEXT)) = lower(CAST(${r.sql} AS TEXT)))`, type: 'bool', refs };
    case '!~':
      return { sql: `(lower(CAST(${l.sql} AS TEXT)) <> lower(CAST(${r.sql} AS TEXT)))`, type: 'bool', refs };
    case '<':
    case '<=':
    case '>':
    case '>=':
      if ((l.type === 'datetime' && r.type === 'timespan') || (l.type === 'timespan' && r.type === 'datetime')) {
        throw new KqlError('Cannot compare a datetime with a timespan — did you mean ago(…)?', e.start, e.end);
      }
      return { sql: `(${l.sql} ${op} ${r.sql})`, type: 'bool', refs };
    case '+':
      if (l.type === 'datetime' && (r.type === 'timespan' || r.type === 'int' || r.type === 'real')) return { sql: fromEpoch(`${toEpoch(l.sql)} + (${r.sql})`), type: 'datetime', refs };
      if (r.type === 'datetime' && l.type === 'timespan') return { sql: fromEpoch(`${toEpoch(r.sql)} + (${l.sql})`), type: 'datetime', refs };
      if (l.type === 'string' || r.type === 'string') throw new KqlError('Use strcat(a, b) to join strings', e.start, e.end);
      return { sql: `(${l.sql} + ${r.sql})`, type: numType(l.type, r.type), refs };
    case '-':
      if (l.type === 'datetime' && r.type === 'datetime') return { sql: `(${toEpoch(l.sql)} - ${toEpoch(r.sql)})`, type: 'timespan', refs };
      if (l.type === 'datetime') return { sql: fromEpoch(`${toEpoch(l.sql)} - (${r.sql})`), type: 'datetime', refs };
      return { sql: `(${l.sql} - ${r.sql})`, type: numType(l.type, r.type), refs };
    case '*':
      return { sql: `(${l.sql} * ${r.sql})`, type: numType(l.type, r.type), refs };
    case '/':
      if (l.type === 'timespan' && r.type === 'timespan') return { sql: `(CAST(${l.sql} AS REAL) / ${r.sql})`, type: 'real', refs };
      return { sql: `(${l.sql} / ${r.sql})`, type: numType(l.type, r.type), refs };
    case '%':
      return { sql: `(${l.sql} % ${r.sql})`, type: 'int', refs };
  }
  throw new KqlError(`Unsupported operator ${op}`, e.start, e.end);
}

function numType(a: KType, b: KType): KType {
  if (a === 'timespan' || b === 'timespan') return 'timespan';
  if (a === 'real' || b === 'real') return 'real';
  if (a === 'int' && b === 'int') return 'int';
  return a === 'unknown' ? b : a;
}

function arity(e: Expr & { k: 'call' }, min: number, max = min): void {
  if (e.args.length < min || e.args.length > max) {
    const want = min === max ? `${min}` : `${min}–${max}`;
    throw new KqlError(`${e.name}() takes ${want} argument${max === 1 ? '' : 's'}, got ${e.args.length}`, e.start, e.end);
  }
}

function timespanArg(ctx: Ctx, rel: Rel, a: Expr, fn: string): number {
  if (a.k === 'timespan') return a.seconds;
  if (a.k === 'unary' && a.op === '-' && a.e.k === 'timespan') return -a.e.seconds;
  if (a.k === 'num') return a.v;
  if (a.k === 'ident' && ctx.lets.has(a.name)) return timespanArg(ctx, rel, ctx.lets.get(a.name)!, fn);
  throw new KqlError(`${fn}() needs a timespan literal such as 1h, 30m or 7d`, a.start, a.end);
}

const UNIT_SECONDS: Record<string, number> = { second: 1, minute: 60, hour: 3600, day: 86400, week: 604800 };

function call(ctx: Ctx, rel: Rel, e: Expr & { k: 'call' }, aggOk: boolean): ExprOut {
  const fn = e.name.toLowerCase();
  const arg = (i: number) => expr(ctx, rel, e.args[i], aggOk);
  const allRefs = () => e.args.flatMap((a) => (a.k === 'star' ? [] : expr(ctx, rel, a, aggOk).refs));

  if (AGGREGATES.has(fn)) {
    if (!aggOk) throw new KqlError(`${e.name}() is an aggregation — use it inside summarize`, e.start, e.end);
    const inner = (i: number) => expr(ctx, rel, e.args[i], false);
    switch (fn) {
      case 'count':
        if (e.args.length > 1) arity(e, 0, 1);
        return { sql: e.args.length ? `COUNT(${inner(0).sql})` : 'COUNT(*)', type: 'int', refs: [] };
      case 'countif':
        arity(e, 1);
        return { sql: `SUM(CASE WHEN ${inner(0).sql} THEN 1 ELSE 0 END)`, type: 'int', refs: inner(0).refs };
      case 'dcount':
        arity(e, 1, 2);
        return { sql: `COUNT(DISTINCT ${inner(0).sql})`, type: 'int', refs: inner(0).refs };
      case 'dcountif':
        arity(e, 2);
        return { sql: `COUNT(DISTINCT CASE WHEN ${inner(1).sql} THEN ${inner(0).sql} END)`, type: 'int', refs: allRefs() };
      case 'sum':
        arity(e, 1);
        return { sql: `SUM(${inner(0).sql})`, type: inner(0).type, refs: inner(0).refs };
      case 'sumif':
        arity(e, 2);
        return { sql: `SUM(CASE WHEN ${inner(1).sql} THEN ${inner(0).sql} ELSE 0 END)`, type: inner(0).type, refs: allRefs() };
      case 'avg':
        arity(e, 1);
        return { sql: `AVG(${inner(0).sql})`, type: 'real', refs: inner(0).refs };
      case 'avgif':
        arity(e, 2);
        return { sql: `AVG(CASE WHEN ${inner(1).sql} THEN ${inner(0).sql} END)`, type: 'real', refs: allRefs() };
      case 'min':
      case 'arg_min':
        return { sql: `MIN(${inner(0).sql})`, type: inner(0).type, refs: inner(0).refs };
      case 'max':
      case 'arg_max':
        return { sql: `MAX(${inner(0).sql})`, type: inner(0).type, refs: inner(0).refs };
      case 'take_any':
      case 'any':
        arity(e, 1);
        return { sql: `MAX(${inner(0).sql})`, type: inner(0).type, refs: inner(0).refs };
      case 'make_set':
        arity(e, 1, 2);
        return { sql: `kql_set(${inner(0).sql})`, type: 'dynamic', refs: inner(0).refs };
      case 'make_list':
        arity(e, 1, 2);
        return { sql: `kql_list(${inner(0).sql})`, type: 'dynamic', refs: inner(0).refs };
      case 'stdev':
        arity(e, 1);
        return { sql: `kql_stdev(${inner(0).sql})`, type: 'real', refs: inner(0).refs };
    }
  }

  switch (fn) {
    case 'ago': {
      arity(e, 1);
      const s = timespanArg(ctx, rel, e.args[0], 'ago');
      return { sql: lit(isoOf(ctx.nowMs - s * 1000)), type: 'datetime', refs: [] };
    }
    case 'now': {
      arity(e, 0, 1);
      const s = e.args.length ? timespanArg(ctx, rel, e.args[0], 'now') : 0;
      return { sql: lit(isoOf(ctx.nowMs + s * 1000)), type: 'datetime', refs: [] };
    }
    case 'bin':
    case 'floor': {
      arity(e, 2);
      const v = arg(0);
      const size = e.args[1].k === 'num' ? e.args[1].v : timespanArg(ctx, rel, e.args[1], fn);
      if (size <= 0) throw new KqlError('bin size must be positive', e.start, e.end);
      if (v.type === 'datetime') {
        const n = Math.max(1, Math.round(size));
        return { sql: fromEpoch(`(${toEpoch(v.sql)} / ${n}) * ${n}`), type: 'datetime', refs: v.refs };
      }
      return { sql: `(CAST((${v.sql}) / ${size} AS INTEGER) * ${size})`, type: v.type, refs: v.refs };
    }
    case 'startofday':
      arity(e, 1);
      return { sql: `strftime('%Y-%m-%dT00:00:00Z', ${arg(0).sql})`, type: 'datetime', refs: arg(0).refs };
    case 'startofhour':
      arity(e, 1);
      return { sql: `strftime('%Y-%m-%dT%H:00:00Z', ${arg(0).sql})`, type: 'datetime', refs: arg(0).refs };
    case 'hourofday':
      arity(e, 1);
      return { sql: `CAST(strftime('%H', ${arg(0).sql}) AS INTEGER)`, type: 'int', refs: arg(0).refs };
    case 'dayofweek':
      arity(e, 1);
      return { sql: `CAST(strftime('%w', ${arg(0).sql}) AS INTEGER)`, type: 'int', refs: arg(0).refs };
    case 'todatetime':
      arity(e, 1);
      return { sql: `strftime('%Y-%m-%dT%H:%M:%SZ', ${arg(0).sql})`, type: 'datetime', refs: arg(0).refs };
    case 'datetime_diff': {
      arity(e, 3);
      const unitExpr = e.args[0];
      if (unitExpr.k !== 'str' || !UNIT_SECONDS[unitExpr.v.toLowerCase()]) throw new KqlError(`datetime_diff unit must be one of ${Object.keys(UNIT_SECONDS).map((u) => `'${u}'`).join(', ')}`, unitExpr.start, unitExpr.end);
      const u = UNIT_SECONDS[unitExpr.v.toLowerCase()];
      const a = arg(1);
      const b = arg(2);
      return { sql: `((${toEpoch(a.sql)} - ${toEpoch(b.sql)}) / ${u})`, type: 'int', refs: [...a.refs, ...b.refs] };
    }
    case 'tolower':
    case 'toupper': {
      arity(e, 1);
      const a = arg(0);
      return { sql: `${fn === 'tolower' ? 'lower' : 'upper'}(${a.sql})`, type: 'string', refs: a.refs };
    }
    case 'strlen':
      arity(e, 1);
      return { sql: `length(${arg(0).sql})`, type: 'int', refs: arg(0).refs };
    case 'substring': {
      arity(e, 2, 3);
      const s = arg(0);
      const start = arg(1);
      const len = e.args.length === 3 ? `, ${arg(2).sql}` : '';
      return { sql: `substr(${s.sql}, (${start.sql}) + 1${len})`, type: 'string', refs: allRefs() };
    }
    case 'strcat':
      if (e.args.length < 1) arity(e, 1, 64);
      return { sql: `(${e.args.map((_, i) => `COALESCE(CAST(${arg(i).sql} AS TEXT), '')`).join(' || ')})`, type: 'string', refs: allRefs() };
    case 'tostring':
      arity(e, 1);
      return { sql: `CAST(${arg(0).sql} AS TEXT)`, type: 'string', refs: arg(0).refs };
    case 'toint':
    case 'tolong':
      arity(e, 1);
      return { sql: `CAST(${arg(0).sql} AS INTEGER)`, type: 'int', refs: arg(0).refs };
    case 'todouble':
    case 'toreal':
      arity(e, 1);
      return { sql: `CAST(${arg(0).sql} AS REAL)`, type: 'real', refs: arg(0).refs };
    case 'isempty':
      arity(e, 1);
      return { sql: `(${arg(0).sql} IS NULL OR CAST(${arg(0).sql} AS TEXT) = '')`, type: 'bool', refs: arg(0).refs };
    case 'isnotempty':
      arity(e, 1);
      return { sql: `(${arg(0).sql} IS NOT NULL AND CAST(${arg(0).sql} AS TEXT) <> '')`, type: 'bool', refs: arg(0).refs };
    case 'isnull':
      arity(e, 1);
      return { sql: `(${arg(0).sql} IS NULL)`, type: 'bool', refs: arg(0).refs };
    case 'isnotnull':
      arity(e, 1);
      return { sql: `(${arg(0).sql} IS NOT NULL)`, type: 'bool', refs: arg(0).refs };
    case 'iff':
    case 'iif': {
      arity(e, 3);
      const c = arg(0);
      const a = arg(1);
      const b = arg(2);
      return { sql: `(CASE WHEN ${c.sql} THEN ${a.sql} ELSE ${b.sql} END)`, type: a.type === 'unknown' ? b.type : a.type, refs: allRefs() };
    }
    case 'case': {
      if (e.args.length < 3 || e.args.length % 2 === 0) throw new KqlError('case(cond1, value1, [cond2, value2, …], else)', e.start, e.end);
      const parts: string[] = [];
      for (let i = 0; i < e.args.length - 1; i += 2) parts.push(`WHEN ${arg(i).sql} THEN ${arg(i + 1).sql}`);
      return { sql: `(CASE ${parts.join(' ')} ELSE ${arg(e.args.length - 1).sql} END)`, type: arg(1).type, refs: allRefs() };
    }
    case 'coalesce':
      if (e.args.length < 2) arity(e, 2, 64);
      return { sql: `COALESCE(${e.args.map((_, i) => arg(i).sql).join(', ')})`, type: arg(0).type, refs: allRefs() };
    case 'abs':
      arity(e, 1);
      return { sql: `abs(${arg(0).sql})`, type: arg(0).type, refs: arg(0).refs };
    case 'round': {
      arity(e, 1, 2);
      const digits = e.args.length === 2 ? arg(1).sql : '0';
      return { sql: `round(${arg(0).sql}, ${digits})`, type: 'real', refs: allRefs() };
    }
    case 'replace_string':
      arity(e, 3);
      return { sql: `replace(${arg(0).sql}, ${arg(1).sql}, ${arg(2).sql})`, type: 'string', refs: allRefs() };
    case 'extract':
      arity(e, 3);
      return { sql: `kql_extract(${arg(0).sql}, ${arg(1).sql}, CAST(${arg(2).sql} AS TEXT))`, type: 'string', refs: allRefs() };
    case 'base64_decode_tostring':
      arity(e, 1);
      return { sql: `kql_b64decode(${arg(0).sql})`, type: 'string', refs: arg(0).refs };
    case 'countof':
      arity(e, 2);
      return { sql: `kql_countof(CAST(${arg(0).sql} AS TEXT), ${arg(1).sql})`, type: 'int', refs: allRefs() };
    case 'indexof':
      arity(e, 2);
      return { sql: `(instr(${arg(0).sql}, ${arg(1).sql}) - 1)`, type: 'int', refs: allRefs() };
    case 'split':
      arity(e, 3);
      return { sql: `kql_split(CAST(${arg(0).sql} AS TEXT), ${arg(1).sql}, ${arg(2).sql})`, type: 'string', refs: allRefs() };
    case 'prev':
    case 'next': {
      arity(e, 1, 3);
      if (!rel.sort) throw new KqlError(`${fn}() needs ordered input — add "| sort by TimeGenerated asc" (or | serialize) before it`, e.start, e.end);
      const v = arg(0);
      const offset = e.args.length >= 2 ? arg(1).sql : '1';
      const dflt = e.args.length === 3 ? `, ${arg(2).sql}` : '';
      const order = rel.sort.map((k) => k.sql).join(', ');
      return { sql: `${fn === 'prev' ? 'LAG' : 'LEAD'}(${v.sql}, ${offset}${dflt}) OVER (${order ? `ORDER BY ${order}` : ''})`, type: v.type, refs: v.refs };
    }
    case 'datetime':
      throw new KqlError('Write datetimes as datetime(2026-09-23T10:00:00Z)', e.start, e.end);
  }
  throw new KqlError(`Unknown function ${e.name}(). See Help → KQL for supported functions.`, e.start, e.end);
}
