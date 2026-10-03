// The findings worklist of a vulnerability case: a table (wide) or cards
// (narrow) in the learner's priority order. The row order IS the submitted
// order. Everything shown comes from scanner columns the learner could query
// anyway (WorklistRow); nothing from the answer key reaches this file.

import type { JSX } from 'preact';
import { useLayoutEffect, useRef, useState } from 'preact/hooks';
import type { VulnFindingAnswer } from '../../core/vuln/grade.ts';
import type { ReasonCode, VulnDecision, VulnSchedule } from '../../core/vuln/model.ts';
import { VULN_DECISIONS, VULN_SCHEDULES } from '../../core/vuln/model.ts';
import {
  DECISION_OPTION_TEXT,
  MAX_REASONS,
  REASON_GROUPS,
  REASON_LABELS,
  SCHEDULE_LABELS,
  SORT_HEADERS,
  SORT_KEYS,
  formatCvss,
  nextSort,
  severityRank,
  sortButtonLabel,
  sortStatus,
  type SortKey,
  type VulnDraft,
  type WorklistRow,
} from '../../core/vuln/worklist.ts';
import { reducedMotion } from '../store/app.ts';

export type MoveTarget = { by: -1 | 1 } | { to: number };

export interface WorklistProps {
  rows: ReadonlyMap<string, WorklistRow>;
  draft: VulnDraft;
  controls: { id: string; kind: string }[];
  pinCounts: Record<string, number>;
  movedId: string | null;
  canUndoSort: boolean;
  narrow: boolean;
  onAnswer(id: string, a: VulnFindingAnswer): void;
  onReason(id: string, code: ReasonCode): void;
  onSort(key: SortKey): void;
  onUndoSort(): void;
  onMove(id: string, target: MoveTarget): void;
}

const EMPTY: VulnFindingAnswer = { decision: null, control: null, schedule: null, reasons: [] };

const SEV_CLASS: Record<string, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'informational' };

const SCHEDULE_OPTION_TEXT: Record<VulnSchedule | '', string> = { '': 'Schedule…', ...SCHEDULE_LABELS };

const val = (e: Event) => (e.target as HTMLSelectElement).value;

// Uncontrolled on purpose: unrelated re-renders must not overwrite what the
// learner is typing. The shown value follows the finding's position only when
// that position changes.
function PriorityInput(p: { id: string; pos: number; n: number; onMove(to: number): void }) {
  const ref = useRef<HTMLInputElement>(null);
  useLayoutEffect(() => {
    if (ref.current) ref.current.value = String(p.pos + 1);
  }, [p.pos]);
  return (
    <input
      ref={ref}
      type="text"
      inputMode="numeric"
      pattern="[0-9]*"
      id={p.id}
      class="input wl-prio"
      size={3}
      defaultValue={String(p.pos + 1)}
      onChange={(e) => {
        const el = e.currentTarget;
        const v = Number.parseInt(el.value, 10);
        const back = () => (el.value = String(p.pos + 1));
        if (!Number.isFinite(v)) return back();
        const to = Math.max(1, Math.min(p.n, v)) - 1;
        if (to === p.pos) return back();
        p.onMove(to);
      }}
    />
  );
}

export function Worklist(p: WorklistProps) {
  const { rows, draft, controls, narrow } = p;
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set());
  const root = useRef<HTMLElement>(null);
  const pendingFocus = useRef<string | null>(null);

  // Remember what was focused just before the DOM changes; a value is never
  // carried over from an earlier render.
  const active = typeof document !== 'undefined' ? document.activeElement : null;
  pendingFocus.current = active && root.current && root.current.contains(active) && active.id ? active.id : null;

  useLayoutEffect(() => {
    const id = pendingFocus.current;
    if (id !== null) {
      const a = document.activeElement;
      if (!a || a === document.body || !a.isConnected) document.getElementById(id)?.focus({ preventScroll: true });
    }
    if (p.movedId) {
      const f = document.activeElement as HTMLElement | null;
      const unit = root.current?.querySelector(`[data-finding-id="${p.movedId}"]`);
      if (f && unit && unit.contains(f)) f.scrollIntoView({ block: 'nearest', behavior: reducedMotion.value ? 'auto' : 'smooth' });
    }
  });

  const order = draft.order.filter((id) => rows.has(id));
  const n = order.length;

  const toggleOpen = (id: string) =>
    setOpen((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  // Alt+ArrowUp / Alt+ArrowDown moves the focused finding, except from a drop-down list.
  const onKeyDown = (e: JSX.TargetedKeyboardEvent<HTMLElement>) => {
    if (!e.altKey || e.ctrlKey || e.metaKey) return;
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
    const t = e.target as HTMLElement;
    if (t.tagName === 'SELECT') return;
    const host = t.closest<HTMLElement>('[data-finding-id]');
    if (!host) return;
    e.preventDefault();
    p.onMove(host.dataset.findingId!, { by: e.key === 'ArrowUp' ? -1 : 1 });
  };

  const sortButton = (k: SortKey) => {
    const dir = nextSort(draft.sort, k).dir;
    const cur = draft.sort?.key === k ? draft.sort.dir : null;
    return (
      <button type="button" id={`wl-sort-${k}`} class="th-sort" aria-label={sortButtonLabel(k, dir)} onClick={() => p.onSort(k)}>
        <span class="th-label">{SORT_HEADERS[k]}</span>
        <span aria-hidden="true" class="th-sort-mark">
          {cur === 'asc' ? '▲' : cur === 'desc' ? '▼' : ''}
        </span>
      </button>
    );
  };

  const ariaSort = (k: SortKey) => (draft.sort?.key === k ? (draft.sort.dir === 'asc' ? ('ascending' as const) : ('descending' as const)) : undefined);

  const name = (r: WorklistRow) => `${r.findingId} on ${r.host}`;

  const decision = (r: WorklistRow) => {
    const a = draft.answers[r.findingId] ?? EMPTY;
    const id = `wl-${r.findingId}`;
    const none = a.decision === 'mitigate' && controls.length === 0;
    return (
      <div class="wl-call">
        <label class="visually-hidden" for={`${id}-decision`}>
          Decision for {name(r)}
        </label>
        <select id={`${id}-decision`} class="select" value={a.decision ?? ''} aria-describedby={none ? `${id}-control-none` : undefined} onChange={(e) => p.onAnswer(r.findingId, { ...a, decision: (val(e) || null) as VulnDecision | null })}>
          {(['', ...VULN_DECISIONS] as (VulnDecision | '')[]).map((d) => (
            <option value={d}>{DECISION_OPTION_TEXT[d]}</option>
          ))}
        </select>
        {a.decision === 'mitigate' &&
          (controls.length > 0 ? (
            <>
              <label class="visually-hidden" for={`${id}-control`}>
                Control for {name(r)}
              </label>
              <select id={`${id}-control`} class="select" value={a.control ?? ''} onChange={(e) => p.onAnswer(r.findingId, { ...a, control: val(e) || null })}>
                <option value="">Choose a control…</option>
                {controls.map((c) => (
                  <option value={c.id}>
                    {c.id} ({c.kind})
                  </option>
                ))}
              </select>
            </>
          ) : (
            <p id={`${id}-control-none`} class="small muted wl-none">
              No controls are listed in ControlInventory.
            </p>
          ))}
        <label class="visually-hidden" for={`${id}-schedule`}>
          Schedule for {name(r)}
        </label>
        <select id={`${id}-schedule`} class="select" value={a.schedule ?? ''} onChange={(e) => p.onAnswer(r.findingId, { ...a, schedule: (val(e) || null) as VulnSchedule | null })}>
          {(['', ...VULN_SCHEDULES] as (VulnSchedule | '')[]).map((s) => (
            <option value={s}>{SCHEDULE_OPTION_TEXT[s]}</option>
          ))}
        </select>
      </div>
    );
  };

  const reasonsButton = (r: WorklistRow) => {
    const a = draft.answers[r.findingId] ?? EMPTY;
    const id = `wl-${r.findingId}`;
    const text = `Reasons (${a.reasons.length} of ${MAX_REASONS})`;
    return (
      <div class="wl-reasons-cell">
        <button type="button" id={`${id}-reasons`} class="btn btn-sm" aria-expanded={open.has(r.findingId)} aria-controls={`${id}-reasons-panel`} aria-label={`${text} for ${name(r)}`} onClick={() => toggleOpen(r.findingId)}>
          {text}
        </button>
        {a.reasons.length > 0 && (
          <ul class="wl-chips">
            {a.reasons.map((c) => (
              <li class="wl-chip">{REASON_LABELS[c]}</li>
            ))}
          </ul>
        )}
      </div>
    );
  };

  const reasonsPanel = (r: WorklistRow) => {
    const a = draft.answers[r.findingId] ?? EMPTY;
    const id = `wl-${r.findingId}`;
    const atCap = a.reasons.length >= MAX_REASONS;
    return (
      <fieldset id={`${id}-reasons-panel`} class="wl-reasons" aria-describedby={`${id}-reasons-status`}>
        <legend>Reasons for {name(r)} (up to {MAX_REASONS})</legend>
        <p id={`${id}-reasons-status`} class="small muted">
          {a.reasons.length} of {MAX_REASONS} chosen.{atCap ? ' Uncheck one to choose another.' : ''}
        </p>
        <div class="wl-reason-groups">
          {REASON_GROUPS.map((g) => (
            <div role="group" aria-label={g.title} class="wl-reason-group">
              <p class="section-label">{g.title}</p>
              {g.codes.map((code) => {
                const checked = a.reasons.includes(code);
                const blocked = atCap && !checked;
                return (
                  <div class="wl-reason">
                    <input
                      type="checkbox"
                      id={`${id}-reason-${code}`}
                      checked={checked}
                      aria-disabled={blocked ? 'true' : undefined}
                      onClick={(e) => {
                        if (blocked) {
                          e.preventDefault();
                          p.onReason(r.findingId, code);
                        }
                      }}
                      onChange={() => p.onReason(r.findingId, code)}
                    />
                    <label for={`${id}-reason-${code}`}>{REASON_LABELS[code]}</label>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </fieldset>
    );
  };

  const priority = (r: WorklistRow, pos: number) => {
    const id = `wl-${r.findingId}`;
    return (
      <div class="wl-priority">
        <button type="button" id={`${id}-up`} class="btn btn-ghost btn-icon btn-sm" aria-label={`Move ${r.findingId} up`} aria-disabled={pos === 0 ? 'true' : undefined} onClick={() => p.onMove(r.findingId, { by: -1 })}>
          <span aria-hidden="true">▲</span>
        </button>
        <button type="button" id={`${id}-down`} class="btn btn-ghost btn-icon btn-sm" aria-label={`Move ${r.findingId} down`} aria-disabled={pos === n - 1 ? 'true' : undefined} onClick={() => p.onMove(r.findingId, { by: 1 })}>
          <span aria-hidden="true">▼</span>
        </button>
        <label class="visually-hidden" for={`${id}-prio`}>
          Priority of {name(r)}
        </label>
        <PriorityInput id={`${id}-prio`} pos={pos} n={n} onMove={(to) => p.onMove(r.findingId, { to })} />
      </div>
    );
  };

  const pins = (r: WorklistRow) => {
    const parts = [r.findingId, r.vulnId, r.host].filter((s) => s !== '');
    return (
      <>
        {p.pinCounts[r.findingId] ?? 0}
        <span class="visually-hidden"> pinned rows mention {parts.join(', ')}</span>
      </>
    );
  };

  const severity = (r: WorklistRow) => <span class={`sev sev-${SEV_CLASS[r.severity.toLowerCase()] ?? 'informational'}`} data-rank={severityRank(r.severity)}>{r.severity}</span>;

  const head = (
    <div class="wl-head">
      <h2 id="wl-h" tabIndex={-1}>
        Findings worklist
      </h2>
      {p.canUndoSort && (
        <button type="button" id="wl-undo-sort" class="btn btn-ghost btn-sm" onClick={p.onUndoSort}>
          Undo sort
        </button>
      )}
      <p class="small muted wl-how">The order of the rows is your priority order, most urgent first. Sort by a column or move rows. Every finding needs a decision and a schedule.</p>
    </div>
  );

  if (narrow) {
    return (
      <section class="vc-worklist card" aria-labelledby="wl-h" ref={root}>
        {head}
        <div class="wl-sortbar" role="group" aria-label="Sort the worklist">
          {SORT_KEYS.map((k) => (
            sortButton(k)
          ))}
        </div>
        <p class="wl-sort-status small">{sortStatus(draft.sort)}</p>
        <ol class="wl-cards" onKeyDown={onKeyDown}>
          {order.map((fid, i) => {
            const r = rows.get(fid)!;
            const id = `wl-${fid}`;
            return (
              <li key={fid} class={`wl-card${p.movedId === fid ? ' is-moved' : ''}`} data-finding-id={fid}>
                <h3 class="wl-card-h">
                  {i + 1}. <span class="mono">{fid}</span> · {r.host}
                </h3>
                <dl class="wl-dl">
                  <dt>Vulnerability</dt>
                  <dd>
                    {r.title}
                    <br />
                    <span class="mono small wl-vid">{r.vulnId || 'no id (configuration check)'}</span>
                  </dd>
                  <dt>Severity (scanner)</dt>
                  <dd>
                    {severity(r)}
                  </dd>
                  <dt>CVSS</dt>
                  <dd class="mono">{formatCvss(r.cvss)}</dd>
                  <dt>First seen</dt>
                  <dd class="mono">{r.firstSeen.slice(0, 10)}</dd>
                  <dt>Pins</dt>
                  <dd>
                    {pins(r)}
                  </dd>
                </dl>
                {decision(r)}
                {reasonsButton(r)}
                <div id={`${id}-reasons-wrap`} hidden={!open.has(fid)}>
                  {reasonsPanel(r)}
                </div>
                {priority(r, i)}
              </li>
            );
          })}
        </ol>
      </section>
    );
  }

  return (
    <section class="vc-worklist card" aria-labelledby="wl-h" ref={root}>
      {head}
      <div class="table-wrap" role="region" tabIndex={0} aria-label="Findings worklist (scrollable)">
        <table class="table worklist wl-table" onKeyDown={onKeyDown}>
          <caption class="visually-hidden">{n} findings in your priority order, most urgent first.</caption>
          <thead>
            <tr>
              <th scope="col">Priority</th>
              <th scope="col" aria-sort={ariaSort('finding')}>
                {sortButton('finding')}
              </th>
              <th scope="col" aria-sort={ariaSort('host')}>
                {sortButton('host')}
              </th>
              <th scope="col" aria-sort={ariaSort('vulnerability')}>
                {sortButton('vulnerability')}
              </th>
              <th scope="col" aria-sort={ariaSort('severity')}>
                {sortButton('severity')}
              </th>
              <th scope="col" aria-sort={ariaSort('cvss')}>
                {sortButton('cvss')}
              </th>
              <th scope="col" aria-sort={ariaSort('firstSeen')}>
                {sortButton('firstSeen')}
              </th>
              <th scope="col">Pins</th>
              <th scope="col">Your call and reasons</th>
            </tr>
          </thead>
          {order.map((fid, i) => {
            const r = rows.get(fid)!;
            return (
              <tbody key={fid} class={`wl-finding${p.movedId === fid ? ' is-moved' : ''}`} data-finding-id={fid}>
                <tr class="wl-row">
                  <td>
                    {priority(r, i)}
                  </td>
                  <td class="mono">{fid}</td>
                  <td>{r.host}</td>
                  <td>
                    {r.title}
                    <br />
                    <span class="mono small wl-vid">{r.vulnId || 'no id (configuration check)'}</span>
                  </td>
                  <td>
                    {severity(r)}
                  </td>
                  <td class="mono">{formatCvss(r.cvss)}</td>
                  <td class="mono">{r.firstSeen.slice(0, 10)}</td>
                  <td class="mono">
                    {pins(r)}
                  </td>
                  <td>
                    <div class="wl-your-call">
                      {decision(r)}
                      {reasonsButton(r)}
                    </div>
                  </td>
                </tr>
                <tr class="wl-reasons-row" hidden={!open.has(fid)}>
                  <td colSpan={9}>
                    {reasonsPanel(r)}
                  </td>
                </tr>
              </tbody>
            );
          })}
        </table>
      </div>
    </section>
  );
}
