// The SIEM: a sql.js database loaded with a corpus, answering KQL or SQL.
// Used inside the Web Worker in the app and directly in Node tests.

import type { Database, SqlJsStatic } from 'sql.js';
import type { Corpus } from '../logs/corpus.ts';
import { TABLES, type Cell, type ColumnType } from '../logs/schema.ts';
import { transpileKql, q, type KType } from './kql/transpile.ts';
import { guardSql } from './sql-guard.ts';
import { registerUdfs } from './udf.ts';
import { KqlError } from './kql/lexer.ts';

export type QueryLang = 'kql' | 'sql';

export interface ResultColumn {
  name: string;
  type: KType;
  hidden: boolean;
}

export interface QueryResult {
  columns: ResultColumn[];
  rows: Cell[][];
  total: number;
  truncated: boolean;
  ms: number;
  sql: string;
  render: string | null;
  recordIdColumn: number;
}

export interface QueryError {
  message: string;
  start: number;
  end: number;
  sql?: string;
}

const SQL_TYPE: Record<ColumnType, string> = {
  datetime: 'TEXT',
  string: 'TEXT',
  int: 'INTEGER',
  real: 'REAL',
  bool: 'INTEGER',
};

const KNOWN_TYPES = new Map<string, ColumnType>();
for (const t of TABLES) for (const c of t.columns) if (!KNOWN_TYPES.has(c.name)) KNOWN_TYPES.set(c.name, c.type);

// determinism-exempt: measures query latency for display only.
const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now()); // determinism-exempt

export class SiemDatabase {
  readonly corpus: Corpus;
  private db: Database;

  constructor(SQL: SqlJsStatic, corpus: Corpus) {
    this.corpus = corpus;
    this.db = new SQL.Database();
    registerUdfs(this.db);
    this.load();
  }

  private load(): void {
    const db = this.db;
    db.run('BEGIN');
    for (const t of TABLES) {
      const data = this.corpus.tables[t.name];
      const cols = t.columns.map((c) => `${q(c.name)} ${SQL_TYPE[c.type]}`).join(', ');
      db.run(`CREATE TABLE ${q(t.name)} (${cols})`);
      if (data.rows.length === 0) continue;
      const stmt = db.prepare(`INSERT INTO ${q(t.name)} VALUES (${t.columns.map(() => '?').join(', ')})`);
      for (const row of data.rows) stmt.run(row);
      stmt.free();
    }
    db.run('COMMIT');
    // Defence in depth behind the SQL guard: SQLite itself refuses writes.
    db.run('PRAGMA query_only = 1');
  }

  // Run exactly one statement (anything after the first is never compiled),
  // returning column names and rows.
  private query(sql: string, params?: (string | number)[]): { columns: string[]; rows: Cell[][] } {
    const stmt = this.db.prepare(sql);
    try {
      if (params) stmt.bind(params);
      const columns = stmt.getColumnNames();
      const rows: Cell[][] = [];
      while (stmt.step()) rows.push(stmt.get() as Cell[]);
      return { columns, rows };
    } finally {
      stmt.free();
    }
  }

  run(text: string, lang: QueryLang, opts: { maxRows?: number } = {}): QueryResult {
    const maxRows = opts.maxRows ?? 1000;
    const t0 = now();
    let sql: string;
    let columns: ResultColumn[] | null = null;
    let render: string | null = null;
    if (lang === 'kql') {
      const tr = transpileKql(text, { now: this.corpus.now, tables: TABLES });
      sql = tr.sql;
      render = tr.render;
      columns = tr.columns.map((c) => ({ name: c.name, type: c.type, hidden: !!c.hidden }));
    } else {
      sql = guardSql(text);
    }

    let res: { columns: string[]; rows: Cell[][] };
    try {
      // The newline keeps a trailing "-- comment" from swallowing the wrapper.
      res = this.query(`SELECT * FROM (${sql}\n) LIMIT ${maxRows + 1}`);
    } catch (e) {
      throw new KqlError(cleanSqliteError((e as Error).message), 0, text.length);
    }
    let rows = res.rows;
    const truncated = rows.length > maxRows;
    if (truncated) rows = rows.slice(0, maxRows);
    let total = rows.length;
    if (truncated) {
      const c = this.query(`SELECT COUNT(*) FROM (${sql}\n)`);
      total = Number(c.rows[0]?.[0] ?? rows.length);
    }
    // Label columns by what SQLite actually returned, taking types (and the
    // hidden flag) from the transpiler where names match.
    const byName = new Map((columns ?? []).map((c) => [c.name, c]));
    const cols: ResultColumn[] = res.columns.map((n, i) => {
      const known = byName.get(n);
      return known ?? { name: n, type: KNOWN_TYPES.get(n) ?? inferType(rows, i), hidden: false };
    });
    return {
      columns: cols,
      rows,
      total,
      truncated,
      ms: Math.round((now() - t0) * 10) / 10,
      sql,
      render,
      recordIdColumn: cols.findIndex((c) => c.name === 'RecordId'),
    };
  }

  // Whole rows by RecordId, from whichever tables hold them (debrief view of
  // evidence the analyst did or did not find).
  lookup(recordIds: readonly string[]): { table: string; columns: string[]; row: Cell[] }[] {
    const ids = [...new Set(recordIds)].filter((id) => /^[A-Za-z0-9]{1,32}$/.test(id));
    if (!ids.length) return [];
    const out: { table: string; columns: string[]; row: Cell[] }[] = [];
    for (const t of TABLES) {
      const r = this.query(`SELECT * FROM ${q(t.name)} WHERE ${q('RecordId')} IN (${ids.map(() => '?').join(', ')})`, ids);
      for (const row of r.rows) out.push({ table: t.name, columns: r.columns, row });
    }
    const order = new Map(ids.map((id, i) => [id, i]));
    return out.sort((a, b) => (order.get(String(a.row.at(-1))) ?? 0) - (order.get(String(b.row.at(-1))) ?? 0));
  }

  close(): void {
    this.db.close();
  }
}

function inferType(rows: Cell[][], i: number): KType {
  for (const r of rows) {
    const v = r[i];
    if (v === null) continue;
    if (typeof v === 'number') return Number.isInteger(v) ? 'int' : 'real';
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v)) return 'datetime';
    return 'string';
  }
  return 'unknown';
}

function cleanSqliteError(msg: string): string {
  const m = msg.replace(/^Error:\s*/, '');
  if (/no such column/i.test(m)) return `${m} — check the column name (SQL mode is not case-sensitive, but names must exist).`;
  if (/no such table/i.test(m)) return `${m} — see the schema panel for table names.`;
  if (/no such function: kql_/i.test(m)) return 'Internal function missing — reload the page.';
  return m;
}

export function toQueryError(e: unknown): QueryError {
  if (e instanceof KqlError) return { message: e.message, start: e.start, end: e.end };
  return { message: (e as Error)?.message ?? String(e), start: 0, end: 0 };
}
