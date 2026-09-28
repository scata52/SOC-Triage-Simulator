// KQL abstract syntax tree.

export interface Span {
  start: number;
  end: number;
}

export type Expr =
  | ({ k: 'ident'; name: string } & Span)
  | ({ k: 'str'; v: string } & Span)
  | ({ k: 'num'; v: number } & Span)
  | ({ k: 'bool'; v: boolean } & Span)
  | ({ k: 'null' } & Span)
  | ({ k: 'timespan'; seconds: number } & Span)
  | ({ k: 'datetime'; iso: string } & Span)
  | ({ k: 'list'; items: Expr[] } & Span)
  | ({ k: 'binary'; op: string; l: Expr; r: Expr } & Span)
  | ({ k: 'unary'; op: 'not' | '-'; e: Expr } & Span)
  | ({ k: 'call'; name: string; args: Expr[] } & Span)
  | ({ k: 'in'; e: Expr; list: Expr[]; negate: boolean; ci: boolean } & Span)
  | ({ k: 'between'; e: Expr; lo: Expr; hi: Expr; negate: boolean } & Span)
  | ({ k: 'strop'; op: string; negate: boolean; l: Expr; r: Expr } & Span)
  | ({ k: 'star' } & Span);

export interface NamedExpr {
  name: string | null;
  expr: Expr;
}

export interface SortKey {
  expr: Expr;
  dir: 'asc' | 'desc';
}

export type Operator =
  | ({ op: 'where'; pred: Expr } & Span)
  | ({ op: 'project'; items: NamedExpr[] } & Span)
  | ({ op: 'project-away'; cols: { pattern: string; span: Span }[] } & Span)
  | ({ op: 'project-rename'; items: { to: string; from: string; span: Span }[] } & Span)
  | ({ op: 'project-reorder'; cols: { pattern: string; span: Span }[] } & Span)
  | ({ op: 'extend'; items: NamedExpr[] } & Span)
  | ({ op: 'summarize'; aggs: NamedExpr[]; by: NamedExpr[] } & Span)
  | ({ op: 'sort'; keys: SortKey[] } & Span)
  | ({ op: 'take'; n: number } & Span)
  | ({ op: 'top'; n: number; key: SortKey } & Span)
  | ({ op: 'distinct'; cols: Expr[] | '*' } & Span)
  | ({ op: 'count' } & Span)
  | ({ op: 'serialize' } & Span)
  | ({ op: 'getschema' } & Span)
  | ({ op: 'render'; kind: string } & Span)
  | ({ op: 'join'; kind: string; right: Query; on: { left: string; right: string; span: Span }[] } & Span);

export type Source =
  | ({ k: 'table'; name: string } & Span)
  | ({ k: 'search'; tables: string[] | null; term: string } & Span);

export interface Query {
  source: Source;
  ops: Operator[];
}

export interface Program {
  lets: Map<string, Expr>;
  query: Query;
}
