// KQL tokenizer. Handles the parts of the language that are awkward for a
// plain regex lexer: hyphenated operator names after a pipe (project-away),
// negated word operators (!contains, !in~), timespan literals (5m, 1.5h),
// verbatim strings (@"C:\path"), and datetime(...) with an unquoted body.

export type TokKind = 'ident' | 'string' | 'number' | 'timespan' | 'datetime' | 'op' | 'eof';

export interface Token {
  kind: TokKind;
  value: string;
  num?: number; // numbers and timespans (seconds)
  start: number;
  end: number;
}

export class KqlError extends Error {
  readonly start: number;
  readonly end: number;
  constructor(message: string, start = 0, end = start + 1) {
    super(message);
    this.name = 'KqlError';
    this.start = start;
    this.end = end;
  }
}

const TIMESPAN_UNITS: Record<string, number> = {
  d: 86400,
  day: 86400,
  days: 86400,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  m: 60,
  min: 60,
  minute: 60,
  minutes: 60,
  s: 1,
  sec: 1,
  second: 1,
  seconds: 1,
  ms: 0.001,
  millisecond: 0.001,
  milliseconds: 0.001,
};

const WORD_NEGATABLE = new Set(['contains', 'contains_cs', 'has', 'has_cs', 'startswith', 'startswith_cs', 'endswith', 'endswith_cs', 'in', 'between', 'hasprefix', 'hassuffix']);

const TWO_CHAR_OPS = ['==', '!=', '=~', '!~', '<=', '>=', '..', '<>'];
const ONE_CHAR_OPS = '|,()[]{}.;=<>+-*/%:';

const isIdentStart = (c: string) => /[A-Za-z_$]/.test(c);
const isIdentPart = (c: string) => /[A-Za-z0-9_$]/.test(c);

export function tokenize(src: string): Token[] {
  const toks: Token[] = [];
  let i = 0;
  const lastSignificant = () => toks[toks.length - 1];

  while (i < src.length) {
    const c = src[i];

    // whitespace
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    // comments
    if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }

    // strings: "..." '...' @"..." @'...'
    if (c === '"' || c === "'" || (c === '@' && (src[i + 1] === '"' || src[i + 1] === "'"))) {
      const start = i;
      const verbatim = c === '@';
      if (verbatim) i++;
      const quote = src[i];
      i++;
      let value = '';
      let closed = false;
      while (i < src.length) {
        const ch = src[i];
        if (ch === quote) {
          if (verbatim && src[i + 1] === quote) {
            value += quote;
            i += 2;
            continue;
          }
          closed = true;
          i++;
          break;
        }
        if (!verbatim && ch === '\\' && i + 1 < src.length) {
          const nx = src[i + 1];
          value += nx === 'n' ? '\n' : nx === 't' ? '\t' : nx;
          i += 2;
          continue;
        }
        if (ch === '\n') break;
        value += ch;
        i++;
      }
      if (!closed) throw new KqlError('Unterminated string literal', start, i);
      toks.push({ kind: 'string', value, start, end: i });
      continue;
    }

    // numbers and timespans
    if (/[0-9]/.test(c)) {
      const start = i;
      while (i < src.length && /[0-9]/.test(src[i])) i++;
      if (src[i] === '.' && /[0-9]/.test(src[i + 1] ?? '')) {
        i++;
        while (i < src.length && /[0-9]/.test(src[i])) i++;
      }
      const numText = src.slice(start, i);
      // unit suffix → timespan
      let j = i;
      while (j < src.length && /[a-z]/i.test(src[j])) j++;
      const unit = src.slice(i, j).toLowerCase();
      if (unit && TIMESPAN_UNITS[unit] !== undefined) {
        toks.push({ kind: 'timespan', value: src.slice(start, j), num: Number(numText) * TIMESPAN_UNITS[unit], start, end: j });
        i = j;
        continue;
      }
      if (unit) throw new KqlError(`Unknown number suffix "${unit}" — timespans use d, h, m, s or ms`, i, j);
      toks.push({ kind: 'number', value: numText, num: Number(numText), start, end: i });
      continue;
    }

    // negated word operators: !contains, !has, !in, !in~, !between …
    if (c === '!' && isIdentStart(src[i + 1] ?? '')) {
      const start = i;
      let j = i + 1;
      while (j < src.length && isIdentPart(src[j])) j++;
      const word = src.slice(i + 1, j).toLowerCase();
      if (WORD_NEGATABLE.has(word)) {
        let value = `!${word}`;
        if (word === 'in' && src[j] === '~') {
          value = '!in~';
          j++;
        }
        toks.push({ kind: 'op', value, start, end: j });
        i = j;
        continue;
      }
    }

    // identifiers (with hyphenated operator names right after a pipe)
    if (isIdentStart(c)) {
      const start = i;
      while (i < src.length && isIdentPart(src[i])) i++;
      const prev = lastSignificant();
      if (prev && prev.kind === 'op' && prev.value === '|') {
        while (src[i] === '-' && isIdentStart(src[i + 1] ?? '')) {
          i++;
          while (i < src.length && isIdentPart(src[i])) i++;
        }
      }
      let value = src.slice(start, i);
      if (value === 'in' && src[i] === '~') {
        value = 'in~';
        i++;
      }
      // datetime(2026-09-23T10:00:00Z) — unquoted body
      if (value === 'datetime' && src[i] === '(') {
        const close = src.indexOf(')', i);
        if (close < 0) throw new KqlError('Unclosed datetime(', start, i + 1);
        const body = src.slice(i + 1, close).trim().replace(/^["']|["']$/g, '');
        toks.push({ kind: 'datetime', value: body, start, end: close + 1 });
        i = close + 1;
        continue;
      }
      toks.push({ kind: 'ident', value, start, end: i });
      continue;
    }

    // operators
    const two = src.slice(i, i + 2);
    if (TWO_CHAR_OPS.includes(two)) {
      toks.push({ kind: 'op', value: two === '<>' ? '!=' : two, start: i, end: i + 2 });
      i += 2;
      continue;
    }
    if (ONE_CHAR_OPS.includes(c)) {
      toks.push({ kind: 'op', value: c, start: i, end: i + 1 });
      i++;
      continue;
    }
    throw new KqlError(`Unexpected character "${c}"`, i, i + 1);
  }
  toks.push({ kind: 'eof', value: '', start: src.length, end: src.length });
  return toks;
}
