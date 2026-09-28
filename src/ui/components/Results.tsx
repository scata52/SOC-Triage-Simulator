// Query results: a real <table> with a pin toggle per row, a row inspector
// with value actions, paging, and a small chart when the query asks to render.

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { uniqueId } from '../lib/focus.ts';
import type { QueryResult } from '../../core/query/engine.ts';
import type { Cell } from '../../core/logs/schema.ts';
import { Icon } from './Icon.tsx';

export type CellAction = 'filter' | 'exclude' | 'indicator' | 'search' | 'copy';

export interface PinMeta {
  recordId: string;
  time: string;
  text: string;
  table?: string;
}

const PAGE = 100;

export function fmtCell(v: Cell): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(Math.round(v * 1000) / 1000);
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(v)) return `${v.slice(0, 10)} ${v.slice(11, 19)}`;
  return v;
}

export function summarise(columns: string[], row: Cell[], table?: string): PinMeta {
  const idx = (n: string) => columns.indexOf(n);
  const rid = String(row[idx('RecordId')] ?? '');
  const tIdx = idx('TimeGenerated');
  const time = tIdx >= 0 ? fmtCell(row[tIdx]) : '';
  const skip = new Set(['RecordId', 'TimeGenerated', '$table']);
  const parts = columns
    .map((c, i) => [c, row[i]] as const)
    .filter(([c, v]) => !skip.has(c) && v !== null && v !== '' && v !== 0)
    .slice(0, 4)
    .map(([, v]) => fmtCell(v));
  const tb = idx('$table') >= 0 ? String(row[idx('$table')]) : table;
  return { recordId: rid, time, text: parts.join(' · ').slice(0, 160), table: tb };
}

function Chart({ result }: { result: QueryResult }) {
  const cols = result.columns;
  const x = 0;
  const y = cols.findIndex((c, i) => i !== x && ['int', 'real'].includes(c.type));
  if (y < 0 || result.rows.length === 0) return null;
  const isTime = cols[x].type === 'datetime';
  let rows = result.rows.map((r) => ({ k: fmtCell(r[x]), v: Number(r[y]) || 0 }));
  if (isTime) rows.sort((a, b) => (a.k < b.k ? -1 : 1));
  else rows = rows.sort((a, b) => b.v - a.v).slice(0, 20);
  const max = Math.max(1, ...rows.map((r) => r.v));
  const W = 640;
  const H = 180;
  const pad = { l: 36, r: 8, t: 8, b: isTime ? 22 : 8 };
  const bw = (W - pad.l - pad.r) / rows.length;
  const summary = `${result.render ?? 'Chart'} of ${cols[y].name} by ${cols[x].name}: ${rows.length} points, maximum ${max}.`;
  if (!isTime) {
    return (
      <figure class="qchart" aria-label={summary}>
        <div class="bars-h" role="list">
          {rows.map((r) => (
            <div class="bar-h" role="listitem">
              <span class="bar-h-label mono" title={r.k}>
                {r.k || '(empty)'}
              </span>
              <span class="bar-h-track">
                <span style={{ width: `${(r.v / max) * 100}%` }} />
              </span>
              <span class="bar-h-value mono">{r.v}</span>
            </div>
          ))}
        </div>
      </figure>
    );
  }
  return (
    <figure class="qchart">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={summary}>
        <line x1={pad.l} y1={H - pad.b} x2={W - pad.r} y2={H - pad.b} class="axis" />
        <text x={pad.l - 6} y={pad.t + 8} class="tick" text-anchor="end">
          {max}
        </text>
        <text x={pad.l - 6} y={H - pad.b} class="tick" text-anchor="end">
          0
        </text>
        {rows.map((r, i) => {
          const h = ((H - pad.t - pad.b) * r.v) / max;
          return (
            <rect x={pad.l + i * bw + 1} y={H - pad.b - h} width={Math.max(1, bw - 2)} height={h} class="col">
              <title>
                {r.k}: {r.v}
              </title>
            </rect>
          );
        })}
        {rows.length > 0 && (
          <>
            <text x={pad.l} y={H - 6} class="tick">
              {rows[0].k.slice(5, 16)}
            </text>
            <text x={W - pad.r} y={H - 6} class="tick" text-anchor="end">
              {rows[rows.length - 1].k.slice(5, 16)}
            </text>
          </>
        )}
      </svg>
    </figure>
  );
}

export function Results({
  result,
  pins,
  onTogglePin,
  onAction,
}: {
  result: QueryResult;
  pins: ReadonlySet<string>;
  onTogglePin?: (meta: PinMeta) => void;
  onAction?: (a: CellAction, column: string, value: Cell) => void;
}) {
  const [limit, setLimit] = useState(PAGE);
  const [inspect, setInspect] = useState<number | null>(null);
  const [sort, setSort] = useState<{ col: number; dir: 'asc' | 'desc' } | null>(null);
  const [inspectorId] = useState(() => uniqueId('row-inspector'));
  const root = useRef<HTMLDivElement>(null);
  // Closing the inspector returns focus to the row button that opened it.
  const closeInspector = () => {
    const r = inspect;
    setInspect(null);
    if (r !== null) requestAnimationFrame(() => root.current?.querySelector<HTMLElement>(`button[data-inspect="${r}"]`)?.focus());
  };
  useEffect(() => {
    setLimit(PAGE);
    setInspect(null);
    setSort(null);
  }, [result]);

  const names = result.columns.map((c) => c.name);
  const visible = result.columns.map((c, i) => ({ c, i })).filter(({ c }) => !c.hidden);
  const rid = onTogglePin ? result.recordIdColumn : -1;
  // Client-side sort of the rows returned (nulls last; numbers numerically).
  const sorted = useMemo(() => {
    if (!sort) return result.rows;
    const k = sort.col;
    const sign = sort.dir === 'asc' ? 1 : -1;
    return [...result.rows].sort((a, b) => {
      const x = a[k];
      const y = b[k];
      if (x === null || x === '') return y === null || y === '' ? 0 : 1;
      if (y === null || y === '') return -1;
      if (typeof x === 'number' && typeof y === 'number') return (x - y) * sign;
      const xs = String(x);
      const ys = String(y);
      return (xs < ys ? -1 : xs > ys ? 1 : 0) * sign;
    });
  }, [result, sort]);
  const rows = sorted.slice(0, limit);
  const inspected = inspect !== null ? sorted[inspect] : null;
  const toggleSort = (col: number) => {
    setInspect(null);
    setSort((cur) => (!cur || cur.col !== col ? { col, dir: 'asc' } : cur.dir === 'asc' ? { col, dir: 'desc' } : null));
  };

  return (
    <div class="results" ref={root}>
      {result.render && <Chart result={result} />}
      {result.rows.length === 0 ? (
        <p class="results-empty muted">No rows matched. An empty result can be a finding too.</p>
      ) : (
        <div class="table-wrap results-scroll" tabIndex={0} role="region" aria-label="Query results (scrollable)">
          <table class="table results-table">
            <caption class="visually-hidden">
              Query results: {result.total} rows{result.truncated ? `, first ${result.rows.length} shown` : ''}.
              {!onTogglePin ? '' : rid >= 0 ? ' Each row can be pinned as evidence.' : ' This result has no RecordId column, so rows cannot be pinned — project RecordId or query the table directly.'}
            </caption>
            <thead>
              <tr>
                {onTogglePin && (
                  <th scope="col" class="col-pin">
                    <span class="visually-hidden">Pin</span>
                  </th>
                )}
                <th scope="col" class="col-n">
                  #
                </th>
                {visible.map(({ c, i }) => (
                  <th scope="col" title={c.type} aria-sort={sort?.col === i ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}>
                    <button type="button" class="th-sort" onClick={() => toggleSort(i)} aria-label={`${c.name}: sort ${sort?.col === i && sort.dir === 'asc' ? 'descending' : sort?.col === i ? 'off' : 'ascending'}`}>
                      {c.name}
                      <span aria-hidden="true" class="th-sort-mark">
                        {sort?.col === i ? (sort.dir === 'asc' ? '▲' : '▼') : ''}
                      </span>
                    </button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, r) => {
                const id = rid >= 0 ? String(row[rid] ?? '') : '';
                const pinned = !!id && pins.has(id);
                return (
                  <tr class={`${pinned ? 'is-pinned' : ''}${inspect === r ? ' is-inspected' : ''}`}>
                    {onTogglePin && <td class="col-pin">
                      {id ? (
                        <button
                          type="button"
                          class="pin-btn"
                          aria-pressed={pinned}
                          aria-label={`${pinned ? 'Unpin' : 'Pin'} row ${r + 1} as evidence`}
                          title={pinned ? 'Unpin evidence' : 'Pin as evidence'}
                          onClick={() => onTogglePin(summarise(names, row))}
                        >
                          <Icon name={pinned ? 'pinned' : 'pin'} />
                        </button>
                      ) : null}
                    </td>}
                    <td class="col-n">
                      <button type="button" class="link-btn mono" data-inspect={r} onClick={() => (inspect === r ? closeInspector() : setInspect(r))} aria-expanded={inspect === r} aria-controls={inspectorId} aria-label={`Inspect row ${r + 1}`}>
                        {r + 1}
                      </button>
                    </td>
                    {visible.map(({ i }) => {
                      const v = row[i];
                      const text = fmtCell(v);
                      return (
                        <td class={typeof v === 'number' ? 'num' : undefined} title={text.length > 60 ? text : undefined}>
                          {v === null || v === '' ? <span class="faint">—</span> : <span class="cell">{text}</span>}
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {result.rows.length > limit && (
            <div class="results-more">
              <button type="button" class="btn btn-sm" onClick={() => setLimit(limit + PAGE)}>
                Show {Math.min(PAGE, result.rows.length - limit)} more ({result.rows.length - limit} hidden)
              </button>
            </div>
          )}
        </div>
      )}
      {inspected && (
        <section id={inspectorId} class="inspector" aria-label={`Row ${inspect! + 1} details`}>
          <div class="inspector-head">
            <h3>Row {inspect! + 1}</h3>
            <span class="spacer" />
            {rid >= 0 && onTogglePin && (
              <button type="button" class="btn btn-sm" aria-pressed={pins.has(String(inspected[rid]))} onClick={() => onTogglePin(summarise(names, inspected))}>
                <Icon name="pin" /> {pins.has(String(inspected[rid])) ? 'Unpin' : 'Pin as evidence'}
              </button>
            )}
            <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label="Close row details" onClick={closeInspector}>
              <Icon name="x" />
            </button>
          </div>
          <dl class="inspector-grid">
            {result.columns.map((c, i) => {
              const v = inspected[i];
              if (v === null || v === '') return null;
              return (
                <div class="inspector-row">
                  <dt>{c.name}</dt>
                  <dd>
                    <span class="mono break">{fmtCell(v)}</span>
                    {onAction && <span class="value-actions">
                      <button type="button" class="btn btn-ghost btn-icon btn-sm" title="Keep rows with this value" aria-label={`Filter: ${c.name} equals this value`} onClick={() => onAction('filter', c.name, v)}>
                        <Icon name="filter" />
                      </button>
                      <button type="button" class="btn btn-ghost btn-icon btn-sm" title="Exclude rows with this value" aria-label={`Exclude: ${c.name} not equal to this value`} onClick={() => onAction('exclude', c.name, v)}>
                        <Icon name="minus" />
                      </button>
                      <button type="button" class="btn btn-ghost btn-icon btn-sm" title="Search every table for this value" aria-label={`Search all tables for ${c.name} value`} onClick={() => onAction('search', c.name, v)}>
                        <Icon name="search" />
                      </button>
                      <button type="button" class="btn btn-ghost btn-icon btn-sm" title="Add as indicator" aria-label={`Add ${c.name} value as an indicator`} onClick={() => onAction('indicator', c.name, v)}>
                        <Icon name="flag" />
                      </button>
                      <button type="button" class="btn btn-ghost btn-icon btn-sm" title="Copy" aria-label={`Copy ${c.name} value`} onClick={() => onAction('copy', c.name, v)}>
                        <Icon name="copy" />
                      </button>
                    </span>}
                  </dd>
                </div>
              );
            })}
          </dl>
        </section>
      )}
    </div>
  );
}
