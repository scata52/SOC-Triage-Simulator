// The SIEM console of a vulnerability case: editor, results (pinnable),
// schema of all tables incl. the six vulnerability ones, decoder and history.

import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import type { QueryLang, QueryResult } from '../../core/query/engine.ts';
import type { TableName } from '../../core/logs/schema.ts';
import { siem, QueryFailure } from '../lib/siem.ts';
import { profile, update } from '../store/app.ts';
import { addQueryHistory } from '../../state/profile.ts';
import type { EditorHandle } from '../components/Editor.tsx';
import { LazyEditor } from '../components/LazyEditor.tsx';
import { Results, type PinMeta } from '../components/Results.tsx';
import { Decoder, QueryHistory, SchemaBrowser } from '../components/Tools.tsx';
import { Icon } from '../components/Icon.tsx';
import { Tabs, TabPanel } from '../components/ui.tsx';
import { num } from '../lib/format.ts';

type Tool = 'results' | 'schema' | 'decode' | 'history';

export const VULN_STARTER = '// Start from the scan. Pick a table in Schema, or:\n// Ctrl+Enter runs.\nVulnFindings\n| take 50';

export function VulnConsole({
  initial,
  onText,
  rowsByTable,
  pins,
  onTogglePin,
  say,
  api,
  nameKey,
}: {
  initial: string;
  onText: (t: string) => void;
  rowsByTable: Record<TableName, number>;
  pins: ReadonlySet<string>;
  onTogglePin: (meta: PinMeta) => void;
  say: (text: string) => void;
  api: { current: { load(q: string): void } | null };
  nameKey: string;
}) {
  const [text, setText] = useState(initial);
  const [lang, setLang] = useState<QueryLang>('kql');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<{ message: string; from: number; to: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [tab, setTab] = useState<Tool>('results');
  const editor = useRef<EditorHandle | null>(null);

  useEffect(() => onText(text), [text]);

  // Read the editor directly: state may lag the last keystroke.
  const run = async (q = editor.current?.get() ?? text, l = lang) => {
    if (!q.trim() || running) return;
    setRunning(true);
    setError(null);
    try {
      const r = await siem.run(q, l, 500);
      setResult(r);
      setTab('results');
      update((p) => addQueryHistory(p, q));
      say(`${r.total} row${r.total === 1 ? '' : 's'}${r.truncated ? `, first ${r.rows.length} shown` : ''}.`);
    } catch (e) {
      const f = e instanceof QueryFailure ? e : new QueryFailure({ message: (e as Error).message, start: 0, end: 0 });
      setError({ message: f.message, from: f.start, to: f.end });
      setResult(null);
      say(`Query error: ${f.message}`);
    } finally {
      setRunning(false);
    }
  };

  const load = (q: string, l: QueryLang = 'kql', andRun = true) => {
    setLang(l);
    setText(q);
    editor.current?.set(q);
    if (andRun) void run(q, l);
    else editor.current?.focus();
  };
  api.current = { load: (q) => load(q) };

  const tools: { id: Tool; label: ComponentChildren }[] = [
    { id: 'results', label: <>Results{result ? <span class="badge">{num(result.total)}</span> : null}</> },
    { id: 'schema', label: 'Schema' },
    { id: 'decode', label: 'Decoder' },
    { id: 'history', label: 'History' },
  ];

  return (
    <div class="vc-console">
      <div class="panel-head">
        <h2>
          <Icon name="terminal" /> Console
        </h2>
        <span class="spacer" />
        <fieldset class="segmented lang-toggle">
          <legend class="visually-hidden">Query language</legend>
          {(['kql', 'sql'] as QueryLang[]).map((l) => (
            <label>
              <input type="radio" name={`${nameKey}-lang`} checked={lang === l} onChange={() => setLang(l)} />
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
          placeholder={lang === 'kql' ? 'VulnFindings | where Severity == "Critical" | take 50' : 'SELECT * FROM VulnFindings LIMIT 50'}
          handle={(h) => (editor.current = h)}
          label={`Query editor, ${lang.toUpperCase()}. Press Control+Enter to run.`}
          schemaMode="vuln"
        />
      </div>
      {error && (
        <div class="query-error" role="alert">
          <Icon name="alert" /> <span>{error.message}</span>
        </div>
      )}
      <Tabs tabs={tools} value={tab} onChange={setTab} label="Console tools" idPrefix="vcq" />
      <div class="vc-tool">
        <TabPanel idPrefix="vcq" id="results" active={tab === 'results'} class="tool-panel">
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
              <Results result={result} pins={pins} onTogglePin={onTogglePin} />
            </>
          ) : (
            !error && (
              <div class="results-empty muted">
                <p>
                  Write a query and press <kbd>Ctrl</kbd>+<kbd>Enter</kbd>. Browse the six vulnerability tables in the Schema tab.
                </p>
              </div>
            )
          )}
        </TabPanel>
        <TabPanel idPrefix="vcq" id="schema" active={tab === 'schema'} class="tool-panel">
          <SchemaBrowser mode="vuln" rowsByTable={rowsByTable} onPreview={(t) => load(lang === 'kql' ? `${t}\n| take 50` : `SELECT * FROM ${t} LIMIT 50`, lang)} onInsert={(s) => editor.current?.insert(s)} />
        </TabPanel>
        <TabPanel idPrefix="vcq" id="decode" active={tab === 'decode'} class="tool-panel">
          <Decoder />
        </TabPanel>
        <TabPanel idPrefix="vcq" id="history" active={tab === 'history'} class="tool-panel">
          <QueryHistory items={profile.value.queryHistory} onLoad={(q) => load(q, /^\s*select\b/i.test(q) ? 'sql' : 'kql', false)} />
        </TabPanel>
      </div>
    </div>
  );
}
