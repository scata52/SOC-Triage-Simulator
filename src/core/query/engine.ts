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

const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

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

    let res;
    try {
      res = this.db.exec(`SELECT * FROM (${sql}) LIMIT ${maxRows + 1}`);
    } catch (e) {
      throw new KqlError(cleanSqliteError((e as Error).message), 0, text.length);
    }
    const first = res[0];
    let names: string[] = first?.columns ?? columns?.map((c) => c.name) ?? [];
    if (!first && !columns) {
      // Empty result in SQL mode: recover column names from a zero-row probe.
      const probe = this.db.prepare(`SELECT * FROM (${sql}) LIMIT 0`);
      names = probe.getColumnNames();
      probe.free();
    }
    let rows = (first?.values ?? []) as Cell[][];
    const truncated = rows.length > maxRows;
    if (truncated) rows = rows.slice(0, maxRows);
    let total = rows.length;
    if (truncated) {
      const c = this.db.exec(`SELECT COUNT(*) FROM (${sql})`);
      total = Number(c[0]?.values[0]?.[0] ?? rows.length);
    }
    const cols: ResultColumn[] =
      columns ??
      names.map((n) => ({ name: n, type: KNOWN_TYPES.get(n) ?? inferType(rows, names.indexOf(n)), hidden: false }));
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
