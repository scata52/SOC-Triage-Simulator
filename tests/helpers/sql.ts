import initSqlJs, { type SqlJsStatic } from 'sql.js';

let cached: Promise<SqlJsStatic> | null = null;

export function sqljs(): Promise<SqlJsStatic> {
  cached ??= initSqlJs();
  return cached;
}
