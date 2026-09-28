// SQL mode is read-only: one SELECT (or WITH … SELECT) statement. The SIEM
// is a teaching instrument, not a scratch database.

import { KqlError } from './kql/lexer.ts';

const FORBIDDEN = /\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE|SAVEPOINT|RELEASE|BEGIN|COMMIT|ROLLBACK)\b|\bREPLACE\s+INTO\b/i;

// Replace string literals and comments with spaces (same length) so keyword
// checks can't be fooled and error positions still line up.
function mask(sql: string): string {
  let out = '';
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (c === '[') {
      // [bracketed identifier]
      const end = sql.indexOf(']', i + 1);
      const stop = end < 0 ? sql.length : end + 1;
      out += ' '.repeat(stop - i);
      i = stop;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const quote = c;
      out += ' ';
      i++;
      while (i < sql.length) {
        if (sql[i] === quote && sql[i + 1] === quote) {
          out += '  ';
          i += 2;
          continue;
        }
        if (sql[i] === quote) {
          out += ' ';
          i++;
          break;
        }
        out += sql[i] === '\n' ? '\n' : ' ';
        i++;
      }
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (c === '/' && sql[i + 1] === '*') {
      const end = sql.indexOf('*/', i + 2);
      const stop = end < 0 ? sql.length : end + 2;
      out += ' '.repeat(stop - i);
      i = stop;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

export function guardSql(sql: string): string {
  const trimmed = sql.trim();
  if (!trimmed) throw new KqlError('Type a SQL query, e.g. SELECT * FROM SigninLogs LIMIT 10', 0, 0);
  const masked = mask(trimmed);
  const body = masked.replace(/;\s*$/, '');
  const semi = body.indexOf(';');
  if (semi >= 0) throw new KqlError('One statement at a time, please', semi, semi + 1);
  const first = /^\s*(\w+)/.exec(body)?.[1]?.toUpperCase();
  if (first !== 'SELECT' && first !== 'WITH' && first !== 'VALUES') {
    throw new KqlError('The SIEM is read-only: queries must start with SELECT or WITH', 0, Math.max(1, first?.length ?? 1));
  }
  const bad = FORBIDDEN.exec(body);
  if (bad) throw new KqlError(`${bad[0].toUpperCase()} is not allowed — the SIEM is read-only`, bad.index, bad.index + bad[0].length);
  return trimmed.replace(/;\s*$/, '');
}
