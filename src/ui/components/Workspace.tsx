// The investigation workspace: alert on the left, SIEM console in the middle,
// verdict on the right. Below 1100px the three become tabs.

import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import type { ResolvedCase } from '../../core/cases/scenario.ts';
import type { QueryLang, QueryResult } from '../../core/query/engine.ts';
import type { Cell } from '../../core/logs/schema.ts';
import type { AlertEntity } from '../../core/cases/model.ts';
import { detectRubricHits, type Verdict } from '../../core/grading/grade.ts';
import { detectKind } from '../../core/grading/indicators.ts';
import { siem, QueryFailure } from '../lib/siem.ts';
import type { SessionInfo } from '../lib/protocol.ts';
import { profile, update, toast, announce } from '../store/app.ts';
import { addQueryHistory } from '../../state/profile.ts';
import { play } from '../lib/sound.ts';
import type { EditorHandle } from './Editor.tsx';
import { LazyEditor } from './LazyEditor.tsx';
import { Results, summarise, type CellAction, type PinMeta } from './Results.tsx';
import { Decoder, QueryHistory, SchemaBrowser } from './Tools.tsx';
import { AlertPanel, VerdictPanel, type EntityAction } from './Panels.tsx';
import { Icon } from './Icon.tsx';
import { Tabs, TabPanel } from './ui.tsx';
import { num } from '../lib/format.ts';

type CenterTab = 'results' | 'schema' | 'decode' | 'history';
type Pane = 'alert' | 'query' | 'verdict';

function kqlLiteral(v: Cell): string {
  if (typeof v === 'number') return String(v);
  const s = String(v ?? '');
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(s)) return `datetime(${s})`;
  if (s.includes('\\') && !s.includes('"')) return `@"${s}"`;
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function sqlLiteral(v: Cell): string {
  if (typeof v === 'number') return String(v);
  return `'${String(v ?? '').replace(/'/g, "''")}'`;
}

function starter(c: ResolvedCase): string {
  const e = c.alert.entities.find((x) => ['host', 'user', 'ip', 'domain'].includes(x.kind)) ?? c.alert.entities[0];
  if (!e) return '// Start from the hypothesis. Pick a table in Schema, or:\nsearch "powershell"\n| take 50';
  const value = e.kind === 'user' && e.value.includes('@') ? e.value.split('@')[0] : e.value;
  const noun: Record<string, string> = { user: 'user', host: 'host', ip: 'IP address', domain: 'domain', url: 'URL', sha256: 'file hash', email: 'address', file: 'file', process: 'process' };
  return `// Where else does this ${noun[e.kind] ?? 'entity'} appear? Ctrl+Enter runs.\nsearch "${value}"\n| take 200`;
}

async function copy(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied.');
  } catch {
    toast('Copy is not available in this browser.');
  }
}

export function Workspace({
  session,
  c,
  draft,
  onDraft,
  onSubmit,
  submitLabel,
  toolbar,
  storageKey,
}: {
  session: SessionInfo;
  c: ResolvedCase;
  draft: Verdict;
  onDraft: (v: Verdict) => void;
  onSubmit: () => void;
  submitLabel: string;
  toolbar?: ComponentChildren;
  storageKey: string;
}) {
  const stored = (() => {
    try {
      return sessionStorage.getItem(`q:${storageKey}`);
    } catch {
      return null;
    }
  })();
  const [text, setText] = useState(stored ?? starter(c));
  const [lang, setLang] = useState<QueryLang>('kql');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<{ message: string; from: number; to: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [tab, setTab] = useState<CenterTab>('results');
  const [pane, setPane] = useState<Pane>('query');
  const [pinMeta, setPinMeta] = useState<Map<string, PinMeta>>(new Map());
  const editor = useRef<EditorHandle | null>(null);
  const draftRef = useRef(draft);
  draftRef.current = draft;

  useEffect(() => {
    try {
      sessionStorage.setItem(`q:${storageKey}`, text);
    } catch {
      /* ignore */
    }
  }, [text]);

  // Pins restored from a saved draft need their summaries.
  useEffect(() => {
    const missing = draft.pins.filter((id) => !pinMeta.has(id));
    if (!missing.length) return;
    siem.lookup(missing).then((rows) => {
      setPinMeta((m) => {
        const next = new Map(m);
        for (const r of rows) {
          const s = summarise(r.columns, r.row, r.table);
          next.set(s.recordId, s);
        }
        return next;
      });
    });
  }, [draft.pins.join(',')]);

  // Read the editor directly: state may lag the last keystroke.
  const run = async (q = editor.current?.get() ?? text, l = lang) => {
    if (!q.trim() || running) return;
    setRunning(true);
    setError(null);
    try {
      const r = await siem.run(q, l, 500);
      setResult(r);
      setTab('results');
      setPane('query');
      update((p) => addQueryHistory(p, q));
      announce(`${r.total} row${r.total === 1 ? '' : 's'}${r.truncated ? `, first ${r.rows.length} shown` : ''}.`);
    } catch (e) {
      const f = e instanceof QueryFailure ? e : new QueryFailure({ message: (e as Error).message, start: 0, end: 0 });
      setError({ message: f.message, from: f.start, to: f.end });
      setResult(null);
      announce(`Query error: ${f.message}`);
    } finally {
      setRunning(false);
    }
  };

  const load = (q: string, l: QueryLang = 'kql', andRun = true) => {
    setLang(l);
    setText(q);
    editor.current?.set(q);
    setPane('query');
    if (andRun) void run(q, l);
    else editor.current?.focus();
  };

  const togglePin = (meta: PinMeta) => {
    const d = draftRef.current;
    const pinned = d.pins.includes(meta.recordId);
    if (!pinned) setPinMeta((m) => new Map(m).set(meta.recordId, meta));
    onDraft({ ...d, pins: pinned ? d.pins.filter((x) => x !== meta.recordId) : [...d.pins, meta.recordId] });
    if (!pinned) play('pin');
    announce(pinned ? 'Unpinned.' : `Pinned as evidence (${d.pins.length + 1}).`);
  };

  const addIndicator = (value: string) => {
    const d = draftRef.current;
    const v = value.trim();
    if (!v) return;
    if (d.indicators.some((i) => i.value.toLowerCase() === v.toLowerCase())) return toast('Already in your indicators.');
    onDraft({ ...d, indicators: [...d.indicators, { kind: detectKind(v), value: v }] });
    toast(`Indicator added: ${v}`);
  };

  const onCell = (a: CellAction, col: string, value: Cell) => {
    const s = String(value ?? '');
    if (a === 'copy') return void copy(s);
    if (a === 'indicator') return addIndicator(s);
    if (a === 'search') return load(`search ${kqlLiteral(s)}\n| take 200`);
    const base = (editor.current?.get() ?? text).replace(/\s*;?\s*$/, '');
    if (lang === 'kql') load(`${base}\n| where ${/^[A-Za-z_]\w*$/.test(col) ? col : `['${col}']`} ${a === 'filter' ? '==' : '!='} ${kqlLiteral(value)}`);
    else load(`SELECT * FROM (\n${base}\n) WHERE "${col.replace(/"/g, '""')}" ${a === 'filter' ? '=' : '<>'} ${sqlLiteral(value)}`, 'sql');
  };

  const onEntity = (e: AlertEntity, a: EntityAction) => {
    if (a === 'copy') return void copy(e.value);
    if (a === 'indicator') return addIndicator(e.value);
    const value = e.kind === 'user' && e.value.includes('@') ? e.value.split('@')[0] : e.value;
    load(`search ${kqlLiteral(value)}\n| take 200`);
  };

  const pins = draft.pins.map((id) => pinMeta.get(id) ?? { recordId: id, time: '', text: 'Loading…' });
  const pinSet = new Set(draft.pins);
  const showRubric = profile.value.settings.showRubricLive;
  const hits = showRubric ? new Set(detectRubricHits(c, draft.notes)) : null;

  const tools: { id: CenterTab; label: ComponentChildren }[] = [
    { id: 'results', label: <>Results{result ? <span class="badge">{num(result.total)}</span> : null}</> },
    { id: 'schema', label: 'Schema' },
    { id: 'decode', label: 'Decoder' },
    { id: 'history', label: 'History' },
  ];

  return (
    <div class="ws" data-pane={pane}>
      <div class="ws-bar">
        {toolbar}
        <div class="ws-panes" role="group" aria-label="Show panel">
          {(
            [
              ['alert', 'Alert'],
              ['query', 'Investigate'],
              ['verdict', 'Verdict'],
            ] as [Pane, string][]
          ).map(([id, label]) => (
            <button type="button" aria-pressed={pane === id} class="ws-pane-btn" onClick={() => setPane(id)}>
              {label}
              {id === 'verdict' && draft.pins.length > 0 ? <span class="badge">{draft.pins.length}</span> : null}
            </button>
          ))}
        </div>
      </div>
      <div class="ws-grid">
        <section class="panel ws-alert" aria-label="Alert">
          <div class="panel-body">
            <AlertPanel
              c={c}
              hintsUsed={draft.hintsUsed}
              onRevealHint={() => onDraft({ ...draftRef.current, hintsUsed: Math.min(c.hints.length, draftRef.current.hintsUsed + 1) })}
              onEntity={onEntity}
              onLoadQuery={(q) => load(q)}
              window={{ start: session.windowStart, end: session.windowEnd }}
            />
          </div>
        </section>

        <section class="panel ws-query" aria-label="SIEM console">
          <div class="panel-head">
            <h2>
              <Icon name="terminal" /> Console
            </h2>
            <span class="spacer" />
            <fieldset class="segmented lang-toggle">
              <legend class="visually-hidden">Query language</legend>
              {(['kql', 'sql'] as QueryLang[]).map((l) => (
                <label>
                  <input type="radio" name={`${storageKey}-lang`} checked={lang === l} onChange={() => setLang(l)} />
                  {l.toUpperCase()}
                </label>
              ))}
            </fieldset>
            <button type="button" class="btn btn-primary btn-sm" onClick={() => run()} disabled={running} aria-keyshortcuts="Control+Enter">
              {running ? <span class="spinner" aria-hidden="true" /> : <Icon name="play" />} Run
            </button>
          </div>
          <div class="editor-wrap">
            <LazyEditor
              initial={text}
              lang={lang}
              onChange={setText}
              onRun={() => run()}
              error={error ? { from: error.from, to: error.to } : null}
              placeholder={lang === 'kql' ? 'SigninLogs | where ResultType != 0 | take 50' : 'SELECT * FROM SigninLogs LIMIT 50'}
              handle={(h) => (editor.current = h)}
              label={`Query editor, ${lang.toUpperCase()}. Press Control+Enter to run.`}
            />
          </div>
          {error && (
            <div class="query-error" role="alert">
              <Icon name="alert" /> <span>{error.message}</span>
            </div>
          )}
          <Tabs tabs={tools} value={tab} onChange={setTab} label="Console tools" idPrefix={`${storageKey}-tools`} />
          <div class="ws-tool">
            <TabPanel idPrefix={`${storageKey}-tools`} id="results" active={tab === 'results'} class="tool-panel">
              {result ? (
                <>
                  <p class="results-meta faint small mono" aria-hidden="true">
                    {num(result.total)} rows{result.truncated ? ` (first ${num(result.rows.length)} shown)` : ''} · {result.ms} ms
                    {result.recordIdColumn < 0 && result.rows.length > 0 ? ' · aggregated rows cannot be pinned' : ''}
                  </p>
                  {lang === 'kql' && (
                    <details class="sql-details">
                      <summary class="faint small">SQL generated from your KQL</summary>
                      <pre class="code-block mono">{result.sql.trim()}</pre>
                    </details>
                  )}
                  <Results result={result} pins={pinSet} onTogglePin={togglePin} onAction={onCell} />
                </>
              ) : (
                !error && (
                  <div class="results-empty muted">
                    <p>
                      Write a query and press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>. New to KQL? Open{' '}
                      <a href="#/help/kql" target="_blank" rel="noopener">
                        the five-minute guide<span class="visually-hidden"> (opens in a new tab)</span>
                      </a>{' '}
                      or browse the Schema tab.
                    </p>
                  </div>
                )
              )}
            </TabPanel>
            <TabPanel idPrefix={`${storageKey}-tools`} id="schema" active={tab === 'schema'} class="tool-panel">
              <SchemaBrowser rowsByTable={session.rowsByTable} onPreview={(t) => load(lang === 'kql' ? `${t}\n| take 50` : `SELECT * FROM ${t} LIMIT 50`, lang)} onInsert={(s) => editor.current?.insert(s)} />
            </TabPanel>
            <TabPanel idPrefix={`${storageKey}-tools`} id="decode" active={tab === 'decode'} class="tool-panel">
              <Decoder />
            </TabPanel>
            <TabPanel idPrefix={`${storageKey}-tools`} id="history" active={tab === 'history'} class="tool-panel">
              <QueryHistory items={profile.value.queryHistory} onLoad={(q) => load(q, /^\s*select\b/i.test(q) ? 'sql' : 'kql', false)} />
            </TabPanel>
          </div>
        </section>

        <section class="panel ws-verdict" aria-label="Verdict">
          <div class="panel-body">
            <VerdictPanel
              v={draft}
              onChange={onDraft}
              pins={pins}
              onUnpin={(id) => onDraft({ ...draftRef.current, pins: draftRef.current.pins.filter((x) => x !== id) })}
              onSubmit={onSubmit}
              submitLabel={submitLabel}
              idPrefix={`${storageKey}-v`}
              rubric={hits ? c.rubric.map((r) => ({ id: r.id, text: r.text, hit: hits.has(r.id) })) : undefined}
            />
          </div>
        </section>
      </div>
    </div>
  );
}
