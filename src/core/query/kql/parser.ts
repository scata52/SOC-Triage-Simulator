// Recursive-descent parser for tabular operators, Pratt parser for
// expressions. Produces the AST in ast.ts with source spans for error
// highlighting in the editor.

import { KqlError, tokenize, type Token } from './lexer.ts';
import type { Expr, NamedExpr, Operator, Program, Query, SortKey, Source } from './ast.ts';

const STR_OPS = new Set(['contains', 'contains_cs', 'has', 'has_cs', 'startswith', 'startswith_cs', 'endswith', 'endswith_cs', 'hasprefix', 'hassuffix']);

// Binding powers (higher binds tighter).
const BP: Record<string, number> = {
  or: 10,
  and: 20,
  '==': 40,
  '!=': 40,
  '=~': 40,
  '!~': 40,
  '<': 40,
  '<=': 40,
  '>': 40,
  '>=': 40,
  '+': 60,
  '-': 60,
  '*': 70,
  '/': 70,
  '%': 70,
};

export const TABULAR_OPERATORS = [
  'where',
  'filter',
  'project',
  'project-away',
  'project-rename',
  'project-reorder',
  'extend',
  'summarize',
  'sort',
  'order',
  'take',
  'limit',
  'top',
  'distinct',
  'count',
  'serialize',
  'getschema',
  'render',
  'join',
] as const;

class Parser {
  private toks: Token[];
  private i = 0;
  private src: string;

  constructor(src: string) {
    this.src = src;
    this.toks = tokenize(src);
  }

  private peek(o = 0): Token {
    return this.toks[Math.min(this.i + o, this.toks.length - 1)];
  }

  private next(): Token {
    return this.toks[this.i++];
  }

  private isOp(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t.kind === 'op' && t.value === v;
  }

  private isWord(v: string, o = 0): boolean {
    const t = this.peek(o);
    return t.kind === 'ident' && t.value.toLowerCase() === v;
  }

  private expectOp(v: string, what?: string): Token {
    const t = this.next();
    if (t.kind !== 'op' || t.value !== v) throw new KqlError(`Expected "${v}"${what ? ` ${what}` : ''} but found ${describe(t)}`, t.start, t.end);
    return t;
  }

  private expectWord(v: string): Token {
    const t = this.next();
    if (t.kind !== 'ident' || t.value.toLowerCase() !== v) throw new KqlError(`Expected "${v}" but found ${describe(t)}`, t.start, t.end);
    return t;
  }

  private ident(what: string): Token {
    const t = this.next();
    if (t.kind !== 'ident') throw new KqlError(`Expected ${what} but found ${describe(t)}`, t.start, t.end);
    return t;
  }

  private intLiteral(what: string): number {
    const t = this.next();
    if (t.kind !== 'number' || !Number.isInteger(t.num)) throw new KqlError(`Expected a whole number for ${what}`, t.start, t.end);
    return t.num!;
  }

  // ------------------------------------------------------------ program
  program(): Program {
    const lets = new Map<string, Expr>();
    while (this.isWord('let')) {
      const letTok = this.next();
      const name = this.ident('a name after let');
      this.expectOp('=');
      if (this.peek().kind === 'ident' && (this.isOp('|', 1) || this.isOp(';', 1)) && /^[A-Z]/.test(this.peek().value)) {
        throw new KqlError('Tabular let statements are not supported here — use a scalar (number, string, timespan, datetime or dynamic list).', letTok.start, this.peek().end);
      }
      const e = this.expr(0);
      this.expectOp(';', 'after the let statement');
      lets.set(name.value, e);
    }
    const query = this.query();
    while (this.isOp(';')) this.next();
    const t = this.peek();
    if (t.kind !== 'eof') throw new KqlError(`Unexpected ${describe(t)} — did you miss a "|"?`, t.start, t.end);
    return { lets, query };
  }

  query(): Query {
    const source = this.source();
    const ops: Operator[] = [];
    while (this.isOp('|')) {
      this.next();
      ops.push(this.operator());
    }
    return { source, ops };
  }

  private source(): Source {
    const t = this.peek();
    if (t.kind === 'ident' && t.value.toLowerCase() === 'search') {
      this.next();
      let tables: string[] | null = null;
      if (this.isWord('in')) {
        this.next();
        this.expectOp('(');
        tables = [];
        do {
          tables.push(this.ident('a table name').value);
        } while (this.isOp(',') && this.next());
        this.expectOp(')');
      }
      const term = this.next();
      if (term.kind !== 'string') throw new KqlError('search needs a quoted term, e.g. search "203.0.113.7"', term.start, term.end);
      return { k: 'search', tables, term: term.value, start: t.start, end: term.end };
    }
    if (t.kind !== 'ident') throw new KqlError(`A query starts with a table name, e.g. SigninLogs — found ${describe(t)}`, t.start, t.end);
    this.next();
    return { k: 'table', name: t.value, start: t.start, end: t.end };
  }

  private operator(): Operator {
    const t = this.next();
    if (t.kind !== 'ident') throw new KqlError(`Expected an operator after "|" (where, project, summarize…) but found ${describe(t)}`, t.start, t.end);
    const name = t.value.toLowerCase();
    const start = t.start;
    const end = () => this.toks[this.i - 1].end;
    switch (name) {
      case 'where':
      case 'filter': {
        const pred = this.expr(0);
        return { op: 'where', pred, start, end: end() };
      }
      case 'project':
        return { op: 'project', items: this.namedList(true), start, end: end() };
      case 'extend': {
        const items = this.namedList(true);
        return { op: 'extend', items, start, end: end() };
      }
      case 'project-away':
      case 'project-reorder': {
        const cols: { pattern: string; span: { start: number; end: number } }[] = [];
        do {
          cols.push(this.columnPattern());
        } while (this.isOp(',') && this.next());
        return name === 'project-away' ? { op: 'project-away', cols, start, end: end() } : { op: 'project-reorder', cols, start, end: end() };
      }
      case 'project-rename': {
        const items: { to: string; from: string; span: { start: number; end: number } }[] = [];
        do {
          const to = this.ident('a new column name');
          this.expectOp('=');
          const from = this.ident('an existing column name');
          items.push({ to: to.value, from: from.value, span: { start: to.start, end: from.end } });
        } while (this.isOp(',') && this.next());
        return { op: 'project-rename', items, start, end: end() };
      }
      case 'summarize': {
        const aggs = this.isWord('by') ? [] : this.namedList(false);
        let by: NamedExpr[] = [];
        if (this.isWord('by')) {
          this.next();
          by = this.namedList(false);
        }
        if (aggs.length === 0 && by.length === 0) throw new KqlError('summarize needs an aggregation (e.g. count()) or a "by" clause', start, end());
        return { op: 'summarize', aggs, by, start, end: end() };
      }
      case 'sort':
      case 'order': {
        this.expectWord('by');
        const keys: SortKey[] = [];
        do {
          keys.push(this.sortKey());
        } while (this.isOp(',') && this.next());
        return { op: 'sort', keys, start, end: end() };
      }
      case 'take':
      case 'limit':
        return { op: 'take', n: this.intLiteral('take'), start, end: end() };
      case 'top': {
        const n = this.intLiteral('top');
        this.expectWord('by');
        return { op: 'top', n, key: this.sortKey(), start, end: end() };
      }
      case 'distinct': {
        if (this.isOp('*')) {
          this.next();
          return { op: 'distinct', cols: '*', start, end: end() };
        }
        const cols: Expr[] = [];
        do {
          cols.push(this.expr(0));
        } while (this.isOp(',') && this.next());
        return { op: 'distinct', cols, start, end: end() };
      }
      case 'count':
        return { op: 'count', start, end: end() };
      case 'serialize':
        return { op: 'serialize', start, end: end() };
      case 'getschema':
        return { op: 'getschema', start, end: end() };
      case 'render': {
        const kind = this.ident('a chart type (timechart, barchart, columnchart, piechart)');
        // Ignore trailing "with (...)" options.
        if (this.isWord('with')) {
          this.next();
          this.expectOp('(');
          let depth = 1;
          while (depth > 0 && this.peek().kind !== 'eof') {
            const x = this.next();
            if (x.kind === 'op' && x.value === '(') depth++;
            if (x.kind === 'op' && x.value === ')') depth--;
          }
        }
        return { op: 'render', kind: kind.value.toLowerCase(), start, end: end() };
      }
      case 'join': {
        let kind = 'inner';
        if (this.isWord('kind')) {
          this.next();
          this.expectOp('=');
          kind = this.ident('a join kind').value.toLowerCase();
          const allowed = ['inner', 'innerunique', 'leftouter', 'leftanti', 'leftsemi'];
          if (!allowed.includes(kind)) throw new KqlError(`Join kind "${kind}" is not supported (use ${allowed.join(', ')})`, this.toks[this.i - 1].start, this.toks[this.i - 1].end);
          if (kind === 'innerunique') kind = 'inner';
        }
        this.expectOp('(', 'to open the right side of the join');
        const right = this.query();
        this.expectOp(')', 'to close the right side of the join');
        this.expectWord('on');
        const on: { left: string; right: string; span: { start: number; end: number } }[] = [];
        do {
          const a = this.ident('a join key');
          if (a.value === '$left') {
            this.expectOp('.');
            const l = this.ident('a column');
            this.expectOp('==');
            const rt = this.ident('$right');
            if (rt.value !== '$right') throw new KqlError('Expected $right', rt.start, rt.end);
            this.expectOp('.');
            const r = this.ident('a column');
            on.push({ left: l.value, right: r.value, span: { start: a.start, end: r.end } });
          } else {
            on.push({ left: a.value, right: a.value, span: { start: a.start, end: a.end } });
          }
        } while (this.isOp(',') && this.next());
        return { op: 'join', kind, right, on, start, end: end() };
      }
      default:
        throw new KqlError(`Unknown or unsupported operator "${t.value}". Supported: ${TABULAR_OPERATORS.join(', ')}`, t.start, t.end);
    }
  }

  private columnPattern() {
    const t = this.next();
    let pattern = '';
    const start = t.start;
    let endPos = t.end;
    if (t.kind === 'ident') pattern = t.value;
    else if (t.kind === 'op' && t.value === '*') pattern = '*';
    else throw new KqlError(`Expected a column name but found ${describe(t)}`, t.start, t.end);
    // Allow wildcards like Initiating*  or *Id
    while (this.isOp('*') || (this.peek().kind === 'ident' && this.peek().start === endPos)) {
      const x = this.next();
      pattern += x.value;
      endPos = x.end;
    }
    return { pattern, span: { start, end: endPos } };
  }

  private sortKey(): SortKey {
    const expr = this.expr(0);
    let dir: 'asc' | 'desc' = 'desc'; // KQL default
    if (this.isWord('asc') || this.isWord('desc')) dir = this.next().value.toLowerCase() as 'asc' | 'desc';
    if (this.isWord('nulls')) {
      this.next();
      this.next();
    }
    return { expr, dir };
  }

  private namedList(allowBareStar: boolean): NamedExpr[] {
    const items: NamedExpr[] = [];
    do {
      if (this.peek().kind === 'ident' && this.isOp('=', 1)) {
        const name = this.next();
        this.next();
        items.push({ name: name.value, expr: this.expr(0) });
      } else {
        if (!allowBareStar && this.isOp('*')) {
          const s = this.next();
          throw new KqlError('Use count() rather than *', s.start, s.end);
        }
        items.push({ name: null, expr: this.expr(0) });
      }
    } while (this.isOp(',') && this.next());
    return items;
  }

  // ------------------------------------------------------------ expressions
  expr(minBp: number): Expr {
    let left = this.prefix();
    for (;;) {
      const t = this.peek();
      // word operators: and/or, string ops, in, between, matches regex
      if (t.kind === 'ident' || (t.kind === 'op' && t.value.startsWith('!') && t.value.length > 2)) {
        const word = t.value.toLowerCase();
        if (word === 'and' || word === 'or') {
          const bp = BP[word];
          if (bp <= minBp) break;
          this.next();
          const right = this.expr(bp);
          left = { k: 'binary', op: word, l: left, r: right, start: left.start, end: right.end };
          continue;
        }
        const negate = word.startsWith('!');
        const base = negate ? word.slice(1) : word;
        if (STR_OPS.has(base)) {
          if (40 <= minBp) break;
          this.next();
          const right = this.expr(40);
          left = { k: 'strop', op: base, negate, l: left, r: right, start: left.start, end: right.end };
          continue;
        }
        if (base === 'in' || base === 'in~') {
          if (40 <= minBp) break;
          this.next();
          const open = this.expectOp('(', 'after in');
          const list: Expr[] = [];
          if (!this.isOp(')')) {
            do {
              const item = this.expr(0);
              if (item.k === 'list') list.push(...item.items);
              else list.push(item);
            } while (this.isOp(',') && this.next());
          }
          const close = this.expectOp(')', 'to close the in (...) list');
          if (list.length === 0) throw new KqlError('in () needs at least one value', open.start, close.end);
          left = { k: 'in', e: left, list, negate, ci: base === 'in~', start: left.start, end: close.end };
          continue;
        }
        if (base === 'between') {
          if (40 <= minBp) break;
          this.next();
          this.expectOp('(', 'after between');
          const lo = this.expr(50);
          this.expectOp('..', 'between the bounds (between (a .. b))');
          const hi = this.expr(50);
          const close = this.expectOp(')');
          left = { k: 'between', e: left, lo, hi, negate, start: left.start, end: close.end };
          continue;
        }
        if (word === 'matches') {
          if (40 <= minBp) break;
          this.next();
          this.expectWord('regex');
          const right = this.expr(40);
          left = { k: 'strop', op: 'matches', negate: false, l: left, r: right, start: left.start, end: right.end };
          continue;
        }
        break;
      }
      if (t.kind === 'op' && BP[t.value] !== undefined) {
        const bp = BP[t.value];
        if (bp <= minBp) break;
        this.next();
        const right = this.expr(bp);
        left = { k: 'binary', op: t.value, l: left, r: right, start: left.start, end: right.end };
        continue;
      }
      if (t.kind === 'op' && t.value === '=') {
        throw new KqlError('Use == to compare (a single = assigns a name)', t.start, t.end);
      }
      break;
    }
    return left;
  }

  private prefix(): Expr {
    const t = this.next();
    switch (t.kind) {
      case 'string':
        return { k: 'str', v: t.value, start: t.start, end: t.end };
      case 'number':
        return { k: 'num', v: t.num!, start: t.start, end: t.end };
      case 'timespan':
        return { k: 'timespan', seconds: t.num!, start: t.start, end: t.end };
      case 'datetime': {
        const d = parseDatetime(t.value);
        if (!d) throw new KqlError(`Could not read datetime(${t.value}) — use e.g. datetime(2026-09-23T10:00:00Z)`, t.start, t.end);
        return { k: 'datetime', iso: d, start: t.start, end: t.end };
      }
      case 'op': {
        if (t.value === '(') {
          const e = this.expr(0);
          this.expectOp(')');
          return e;
        }
        if (t.value === '-') {
          const e = this.expr(80);
          return { k: 'unary', op: '-', e, start: t.start, end: e.end };
        }
        if (t.value === '*') return { k: 'star', start: t.start, end: t.end };
        if (t.value === '[') {
          const items: Expr[] = [];
          if (!this.isOp(']')) {
            do items.push(this.expr(0));
            while (this.isOp(',') && this.next());
          }
          const close = this.expectOp(']');
          return { k: 'list', items, start: t.start, end: close.end };
        }
        throw new KqlError(`Unexpected ${describe(t)} in expression`, t.start, t.end);
      }
      case 'ident': {
        const lower = t.value.toLowerCase();
        if (lower === 'true' || lower === 'false') return { k: 'bool', v: lower === 'true', start: t.start, end: t.end };
        if (lower === 'null') return { k: 'null', start: t.start, end: t.end };
        if (lower === 'not' && this.isOp('(')) {
          this.next();
          const e = this.expr(0);
          const close = this.expectOp(')');
          return { k: 'unary', op: 'not', e, start: t.start, end: close.end };
        }
        if (lower === 'dynamic' && this.isOp('(')) {
          this.next();
          const inner = this.prefix();
          const close = this.expectOp(')');
          if (inner.k !== 'list') throw new KqlError('dynamic(...) supports arrays here, e.g. dynamic(["a", "b"])', t.start, close.end);
          return { ...inner, start: t.start, end: close.end };
        }
        if (this.isOp('(')) {
          this.next();
          const args: Expr[] = [];
          if (!this.isOp(')')) {
            do args.push(this.expr(0));
            while (this.isOp(',') && this.next());
          }
          const close = this.expectOp(')', `to close ${t.value}(`);
          return { k: 'call', name: t.value, args, start: t.start, end: close.end };
        }
        // Qualified names like $left.Col are only valid in join ... on.
        return { k: 'ident', name: t.value, start: t.start, end: t.end };
      }
      case 'eof':
        throw new KqlError('The query ends too early — an expression is missing', this.src.length, this.src.length);
    }
  }
}

function describe(t: Token): string {
  if (t.kind === 'eof') return 'the end of the query';
  if (t.kind === 'string') return `"${t.value}"`;
  return `"${t.value}"`;
}

export function parseDatetime(text: string): string | null {
  const s = text.trim();
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?)?\s*(Z|UTC)?$/i.exec(s);
  if (!m) return null;
  const [, y, mo, d, h = '00', mi = '00', se = '00'] = m;
  const ms = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(se));
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function parseKql(src: string): Program {
  if (!src.trim()) throw new KqlError('Type a query — start with a table name, e.g. SigninLogs | take 10', 0, 0);
  return new Parser(src).program();
}

export function parseKqlQuery(src: string): Query {
  return new Parser(src).query();
}
