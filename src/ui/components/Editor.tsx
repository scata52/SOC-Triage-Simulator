// The query editor: CodeMirror 6 with a KQL mode (tokenizer + schema-aware
// autocomplete) and SQL mode. Tab is left to the browser so keyboard users
// can leave the editor; Ctrl/Cmd+Enter runs the query.

import { useEffect, useRef } from 'preact/hooks';
import { EditorState, Compartment, StateEffect, StateField, type Extension } from '@codemirror/state';
import { EditorView, keymap, placeholder as cmPlaceholder, Decoration, type DecorationSet, lineNumbers, highlightActiveLine, drawSelection } from '@codemirror/view';
import { defaultKeymap, history, historyKeymap } from '@codemirror/commands';
import { StreamLanguage, HighlightStyle, syntaxHighlighting, bracketMatching } from '@codemirror/language';
import { autocompletion, closeBrackets, completionKeymap, type CompletionContext, type CompletionResult, type Completion } from '@codemirror/autocomplete';
import { sql, SQLite } from '@codemirror/lang-sql';
import { tags as t } from '@lezer/highlight';
import { TABLES } from '../../core/logs/schema.ts';
import { TABULAR_OPERATORS } from '../../core/query/kql/parser.ts';
import { KQL_KEYWORDS, KQL_REFERENCE, referenceNames } from '../../core/query/kql/reference.ts';
import type { QueryLang } from '../../core/query/engine.ts';

const TABLE_SET = new Set(TABLES.map((x) => x.name.toLowerCase()));
const OPS = new Set<string>([...TABULAR_OPERATORS]);
const WORD_OPS = new Set(['contains', 'contains_cs', 'has', 'has_cs', 'startswith', 'startswith_cs', 'endswith', 'endswith_cs', 'hasprefix', 'hassuffix', 'matches', 'regex', 'in', 'in~', 'between', 'and', 'or', 'not', 'by', 'on', 'kind', 'asc', 'desc', 'let', 'search']);

export const kqlLanguage = StreamLanguage.define<{ afterPipe: boolean }>({
  name: 'kql',
  startState: () => ({ afterPipe: true }),
  token(stream, state) {
    if (stream.eatSpace()) return null;
    if (stream.match('//')) {
      stream.skipToEnd();
      return 'comment';
    }
    if (stream.match(/^@?"(?:[^"\\]|\\.)*"?/) || stream.match(/^@?'(?:[^'\\]|\\.)*'?/)) return 'string';
    if (stream.match(/^\d+(?:\.\d+)?(?:ms|d|h|m|s)?\b/)) return 'number';
    if (stream.match('|')) {
      state.afterPipe = true;
      return 'operator';
    }
    if (stream.match(/^(==|!=|=~|!~|<=|>=|<|>|\.\.|\$left|\$right)/)) return 'operator';
    const m = stream.match(/^!?[A-Za-z_][\w-]*~?/) as RegExpMatchArray | null;
    if (m) {
      const word = m[0].toLowerCase();
      const wasAfterPipe = state.afterPipe;
      state.afterPipe = false;
      if (wasAfterPipe && OPS.has(word)) return 'keyword';
      if (WORD_OPS.has(word.replace(/^!/, ''))) return 'keyword';
      if (TABLE_SET.has(word)) return 'kqlTable';
      if (stream.peek() === '(') return 'kqlFunction';
      if (word === 'true' || word === 'false' || word === 'null') return 'atom';
      return 'variableName';
    }
    state.afterPipe = false;
    stream.next();
    return null;
  },
  languageData: { commentTokens: { line: '//' } },
  tokenTable: { kqlTable: t.typeName, kqlFunction: t.function(t.variableName) },
});

const highlight = HighlightStyle.define([
  { tag: t.keyword, color: 'var(--syn-keyword)' },
  { tag: t.operator, color: 'var(--syn-operator)' },
  { tag: t.string, color: 'var(--syn-string)' },
  { tag: t.number, color: 'var(--syn-number)' },
  { tag: t.atom, color: 'var(--syn-number)' },
  { tag: t.comment, color: 'var(--syn-comment)', fontStyle: 'italic' },
  { tag: t.typeName, color: 'var(--syn-table)' },
  { tag: t.function(t.variableName), color: 'var(--syn-function)' },
]);

function docFor(name: string): string | undefined {
  return KQL_REFERENCE.find((e) => e.name.split(/\s*\/\s*/).includes(name))?.doc;
}

const TABLE_OPTIONS: Completion[] = TABLES.map((x) => ({ label: x.name, type: 'class', detail: x.kind === 'log' ? 'log' : 'context', info: x.doc }));
const OP_OPTIONS: Completion[] = [...TABULAR_OPERATORS].map((o) => ({ label: o, type: 'keyword', info: docFor(o) }));
const FN_OPTIONS: Completion[] = [...referenceNames('scalar'), ...referenceNames('aggregate')].filter((n, i, a) => a.indexOf(n) === i && /^[a-z_]+$/.test(n)).map((n) => ({ label: n, type: 'function', apply: `${n}(`, info: docFor(n) }));
const KW_OPTIONS: Completion[] = [...KQL_KEYWORDS, 'contains', 'has', 'startswith', 'endswith', 'hasprefix', 'hassuffix', 'matches regex', 'in~', '!contains', '!has', '!in'].map((k) => ({ label: k, type: 'keyword' }));

export function kqlComplete(ctx: CompletionContext): CompletionResult | null {
  const word = ctx.matchBefore(/[\w!~-]*/);
  if (!word || (word.from === word.to && !ctx.explicit)) return null;
  const before = ctx.state.sliceDoc(0, word.from);
  const doc = ctx.state.doc.toString();
  // After a pipe: operators. Start of a query: tables. Otherwise columns of
  // the tables mentioned, functions and keywords.
  if (/\|\s*$/.test(before)) return { from: word.from, options: OP_OPTIONS, validFor: /^[\w-]*$/ };
  if (/(^|;|\(|\n)\s*$/.test(before) && !/\|[^\n]*$/.test(before.split('\n').pop() ?? '')) {
    return { from: word.from, options: [...TABLE_OPTIONS, { label: 'search', type: 'keyword' }, { label: 'let', type: 'keyword' }], validFor: /^\w*$/ };
  }
  const mentioned = TABLES.filter((x) => new RegExp(`\\b${x.name}\\b`).test(doc));
  const cols = new Map<string, Completion>();
  for (const tbl of mentioned.length ? mentioned : TABLES) {
    for (const c of tbl.columns) if (!cols.has(c.name)) cols.set(c.name, { label: c.name, type: 'property', detail: c.type, info: c.doc, boost: mentioned.length ? 2 : 0 });
  }
  return { from: word.from, options: [...cols.values(), ...FN_OPTIONS, ...KW_OPTIONS, ...TABLE_OPTIONS], validFor: /^[\w!~-]*$/ };
}

const setError = StateEffect.define<{ from: number; to: number } | null>();
const errorField = StateField.define<DecorationSet>({
  create: () => Decoration.none,
  update(deco, tr) {
    deco = deco.map(tr.changes);
    for (const e of tr.effects) {
      if (e.is(setError)) {
        if (!e.value) deco = Decoration.none;
        else {
          const len = tr.state.doc.length;
          const from = Math.max(0, Math.min(e.value.from, len));
          const to = Math.max(from, Math.min(Math.max(e.value.to, from + 1), len));
          deco = to > from ? Decoration.set([Decoration.mark({ class: 'cm-query-error' }).range(from, to)]) : Decoration.none;
        }
      }
    }
    if (tr.docChanged) deco = Decoration.none;
    return deco;
  },
  provide: (f) => EditorView.decorations.from(f),
});

const theme = EditorView.theme({
  '&': { fontSize: 'var(--editor-font-size, 14px)', backgroundColor: 'var(--bg-sunken)', color: 'var(--text)', height: '100%' },
  '.cm-content': { fontFamily: 'var(--font-mono)', caretColor: 'var(--accent)', padding: '8px 0' },
  '.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.55' },
  '.cm-gutters': { backgroundColor: 'var(--bg-sunken)', color: 'var(--text-faint)', border: 'none' },
  '.cm-activeLine': { backgroundColor: 'var(--row-hover)' },
  '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--text-muted)' },
  '&.cm-focused': { outline: '2px solid var(--focus)', outlineOffset: '-2px' },
  '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, ::selection': { backgroundColor: 'var(--accent-bg) !important' },
  '.cm-cursor': { borderLeftColor: 'var(--accent)' },
  '.cm-placeholder': { color: 'var(--text-faint)' },
  '.cm-query-error': { textDecoration: 'underline wavy var(--bad)', textUnderlineOffset: '3px', backgroundColor: 'var(--bad-bg)' },
  '.cm-tooltip': { backgroundColor: 'var(--surface-3)', border: '1px solid var(--border-strong)', color: 'var(--text)' },
  '.cm-tooltip-autocomplete > ul > li[aria-selected]': { backgroundColor: 'var(--accent-bg)', color: 'var(--text)' },
  '.cm-completionInfo': { maxWidth: '320px', padding: '6px 8px' },
  '.cm-completionDetail': { color: 'var(--text-faint)', fontStyle: 'normal', marginLeft: '8px' },
});

function langExtension(lang: QueryLang): Extension {
  if (lang === 'sql') {
    const schema: Record<string, string[]> = {};
    for (const x of TABLES) schema[x.name] = x.columns.map((c) => c.name);
    return sql({ dialect: SQLite, schema, upperCaseKeywords: true });
  }
  return [kqlLanguage, autocompletion({ override: [kqlComplete], icons: false })];
}

export interface EditorHandle {
  get(): string;
  focus(): void;
  insert(text: string): void;
  set(text: string): void;
}

// Uncontrolled: the editor owns its text. `initial` seeds it once; later
// programmatic changes go through the handle's set()/insert(). (Feeding the
// text back in as a prop races with typing: a render carrying a value one
// keystroke stale rewrites the document and the two versions ping-pong.)
export function Editor({
  initial,
  lang,
  onChange,
  onRun,
  error,
  placeholder,
  handle,
  label,
}: {
  initial: string;
  lang: QueryLang;
  onChange: (v: string) => void;
  onRun: () => void;
  error: { from: number; to: number } | null;
  placeholder?: string;
  handle?: (h: EditorHandle) => void;
  label: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const langComp = useRef(new Compartment());
  const cb = useRef({ onChange, onRun });
  cb.current = { onChange, onRun };

  useEffect(() => {
    const v = new EditorView({
      parent: host.current!,
      state: EditorState.create({
        doc: initial,
        extensions: [
          lineNumbers(),
          history(),
          drawSelection(),
          highlightActiveLine(),
          bracketMatching(),
          closeBrackets(),
          syntaxHighlighting(highlight),
          langComp.current.of(langExtension(lang)),
          errorField,
          theme,
          EditorView.lineWrapping,
          cmPlaceholder(placeholder ?? ''),
          EditorView.contentAttributes.of({ 'aria-label': label, 'aria-multiline': 'true' }),
          keymap.of([
            { key: 'Mod-Enter', run: () => (cb.current.onRun(), true), preventDefault: true },
            { key: 'Shift-Enter', run: () => (cb.current.onRun(), true), preventDefault: true },
            ...completionKeymap,
            ...historyKeymap,
            ...defaultKeymap,
          ]),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) cb.current.onChange(u.state.doc.toString());
          }),
        ],
      }),
    });
    view.current = v;
    handle?.({
      get: () => v.state.doc.toString(),
      focus: () => v.focus(),
      insert: (text) => {
        const sel = v.state.selection.main;
        v.dispatch({ changes: { from: sel.from, to: sel.to, insert: text }, selection: { anchor: sel.from + text.length } });
        v.focus();
      },
      set: (text) => {
        if (v.state.doc.toString() !== text) v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: text }, selection: { anchor: text.length } });
      },
    });
    return () => v.destroy();
  }, []);

  useEffect(() => {
    view.current?.dispatch({ effects: langComp.current.reconfigure(langExtension(lang)) });
  }, [lang]);

  useEffect(() => {
    view.current?.dispatch({ effects: setError.of(error) });
  }, [error]);

  return <div class="editor" ref={host} />;
}
