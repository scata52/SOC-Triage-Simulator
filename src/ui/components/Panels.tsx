// The alert panel (what fired, context, hints) and the verdict panel
// (evidence, indicators, conclusion).

import { useState } from 'preact/hooks';
import type { ResolvedCase } from '../../core/cases/scenario.ts';
import type { AlertEntity, IndicatorKind } from '../../core/cases/model.ts';
import { ACTION_LABELS, DISPOSITION_LABELS, HINT_PENALTY, SEVERITY_LABELS, type Verdict } from '../../core/grading/grade.ts';
import { detectKind } from '../../core/grading/indicators.ts';
import { ACTION_ORDER, SEVERITY_ORDER, type Disposition } from '../../core/types.ts';
import { TABLE_NAMES } from '../../core/logs/schema.ts';
import { Icon } from './Icon.tsx';
import { Sev } from './ui.tsx';
import { TechniquePicker } from './TechniquePicker.tsx';
import type { PinMeta } from './Results.tsx';
import { utcDateTime } from '../lib/format.ts';

export type EntityAction = 'search' | 'indicator' | 'copy';

const ENTITY_LABEL: Record<AlertEntity['kind'], string> = { user: 'User', host: 'Host', ip: 'IP', domain: 'Domain', url: 'URL', sha256: 'SHA-256', email: 'Email', file: 'File', process: 'Process' };

// A hint that contains a query: from the first table name to the end.
function hintQuery(h: string): { lead: string; kql: string } | null {
  const re = new RegExp(`\\b(${TABLE_NAMES.join('|')})\\b\\s*(\\n\\s*)?\\|`);
  const m = re.exec(h);
  if (!m) return null;
  return { lead: h.slice(0, m.index).trim(), kql: h.slice(m.index).trim() };
}

export function AlertPanel({
  c,
  hintsUsed,
  onRevealHint,
  onEntity,
  onLoadQuery,
  window: win,
}: {
  c: ResolvedCase;
  hintsUsed: number;
  onRevealHint: () => void;
  onEntity: (e: AlertEntity, a: EntityAction) => void;
  onLoadQuery: (kql: string) => void;
  window: { start: string; end: string };
}) {
  const a = c.alert;
  return (
    <div class="alert-panel">
      <header class="alert-head">
        <div class="row">
          <Sev s={a.severity} />
          <span class="faint small mono">{c.alertId}</span>
          <span class="faint small">{a.product}</span>
        </div>
        <h2 class="alert-rule">{a.rule}</h2>
        <p class="faint small mono">{utcDateTime(a.time)}</p>
      </header>
      <p class="alert-summary">{a.summary}</p>

      {a.entities.length > 0 && (
        <section aria-labelledby={`ent-${c.alertId}`}>
          <h3 class="section-label" id={`ent-${c.alertId}`}>
            Entities
          </h3>
          <ul class="entities">
            {a.entities.map((e) => (
              <li class="entity">
                <span class="entity-kind">{e.label ?? ENTITY_LABEL[e.kind]}</span>
                <span class="entity-value mono break">{e.value}</span>
                <span class="entity-actions">
                  <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label={`Search all logs for ${e.value}`} title="Search all logs" onClick={() => onEntity(e, 'search')}>
                    <Icon name="search" />
                  </button>
                  <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label={`Add ${e.value} as an indicator`} title="Add as indicator" onClick={() => onEntity(e, 'indicator')}>
                    <Icon name="flag" />
                  </button>
                  <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label={`Copy ${e.value}`} title="Copy" onClick={() => onEntity(e, 'copy')}>
                    <Icon name="copy" />
                  </button>
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {a.fields.length > 0 && (
        <dl class="kv" style={{ marginTop: 'var(--space-3)' }}>
          {a.fields.map(([k, v]) => (
            <>
              <dt>{k}</dt>
              <dd class="mono">{v}</dd>
            </>
          ))}
        </dl>
      )}

      <section aria-labelledby={`brief-${c.alertId}`} style={{ marginTop: 'var(--space-4)' }}>
        <h3 class="section-label" id={`brief-${c.alertId}`}>
          Context
        </h3>
        <p class="small">{c.briefing}</p>
        <p class="faint small">
          Logs cover <span class="mono">{utcDateTime(win.start)}</span> → <span class="mono">{utcDateTime(win.end)}</span> (UTC). <code>now()</code> is the end of
          that window.
        </p>
      </section>

      {c.attachments.map((att) => (
        <details class="disclosure attachment" open>
          <summary>
            <Icon name="book" /> {att.title}
          </summary>
          <div class="disclosure-body">
            {typeof att.body === 'string' ? (
              <pre class={`attachment-body mono${att.kind === 'email' ? ' is-email' : ''}`}>{att.body}</pre>
            ) : (
              <dl class="kv">
                {att.body.map(([k, v]) => (
                  <>
                    <dt>{k}</dt>
                    <dd class="mono">{v}</dd>
                  </>
                ))}
              </dl>
            )}
            {att.caption && <p class="faint small">{att.caption}</p>}
          </div>
        </details>
      ))}

      <section aria-labelledby={`hints-${c.alertId}`} class="hints">
        <h3 class="section-label" id={`hints-${c.alertId}`}>
          Hints
        </h3>
        {c.hints.slice(0, hintsUsed).map((h, i) => {
          const q = hintQuery(h);
          return (
            <div class="hint">
              <span class="hint-n mono">{i + 1}</span>
              <div>
                {q ? (
                  <>
                    {q.lead && <p class="small">{q.lead}</p>}
                    <pre class="code-block mono">{q.kql}</pre>
                    <button type="button" class="btn btn-sm" onClick={() => onLoadQuery(q.kql)}>
                      <Icon name="terminal" /> Load into editor
                    </button>
                  </>
                ) : (
                  <p class="small">{h}</p>
                )}
              </div>
            </div>
          );
        })}
        {hintsUsed < c.hints.length ? (
          <button type="button" class="btn btn-sm btn-ghost" onClick={onRevealHint}>
            <Icon name="bulb" /> Reveal hint {hintsUsed + 1} of {c.hints.length}
            <span class="faint"> (−{Math.round(HINT_PENALTY * 100)}% evidence score)</span>
          </button>
        ) : (
          <p class="faint small">No more hints.</p>
        )}
      </section>
    </div>
  );
}

const DISPOSITION_HELP: Record<Disposition, string> = {
  'true-positive': 'Malicious activity happened.',
  'false-positive': 'The detection fired wrongly.',
  benign: 'Real activity, but expected or authorised.',
};

const KINDS: IndicatorKind[] = ['ip', 'domain', 'url', 'sha256', 'email', 'user', 'host', 'file'];

export function VerdictPanel({
  v,
  onChange,
  pins,
  onUnpin,
  onSubmit,
  submitLabel,
  idPrefix,
  rubric,
}: {
  v: Verdict;
  onChange: (v: Verdict) => void;
  pins: PinMeta[];
  onUnpin: (id: string) => void;
  onSubmit: () => void;
  submitLabel: string;
  idPrefix: string;
  rubric?: { id: string; text: string; hit: boolean }[];
}) {
  const [indValue, setIndValue] = useState('');
  const [indKind, setIndKind] = useState<IndicatorKind | 'auto'>('auto');
  const missing = [!v.disposition && 'disposition', !v.severity && 'severity', !v.action && 'action'].filter(Boolean) as string[];

  const addIndicator = () => {
    const value = indValue.trim();
    if (!value) return;
    const kind = indKind === 'auto' ? detectKind(value) : indKind;
    if (!v.indicators.some((i) => i.value.toLowerCase() === value.toLowerCase())) onChange({ ...v, indicators: [...v.indicators, { kind, value }] });
    setIndValue('');
  };

  return (
    <form
      class="verdict"
      onSubmit={(e) => {
        e.preventDefault();
        if (!missing.length) onSubmit();
      }}
      aria-label="Your verdict"
    >
      <section aria-labelledby={`${idPrefix}-ev`}>
        <h3 class="section-label" id={`${idPrefix}-ev`}>
          Evidence <span class="badge">{pins.length}</span>
        </h3>
        {pins.length === 0 ? (
          <p class="faint small">
            Pin the log rows that prove your conclusion with <Icon name="pin" /> in the results.
          </p>
        ) : (
          <ul class="pins">
            {pins.map((p) => (
              <li class="pin-item">
                <div class="pin-text">
                  <span class="mono small">
                    {p.table ? `${p.table} · ` : ''}
                    {p.time}
                  </span>
                  <span class="small break">{p.text}</span>
                </div>
                <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label={`Unpin ${p.time} ${p.text}`} onClick={() => onUnpin(p.recordId)}>
                  <Icon name="x" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby={`${idPrefix}-ind`}>
        <h3 class="section-label" id={`${idPrefix}-ind`}>
          Indicators <span class="badge">{v.indicators.length}</span>
        </h3>
        <p class="faint small">What to block (attacker IPs, domains, hashes) and who or what is affected (users, hosts).</p>
        <div class="ind-add">
          <label for={`${idPrefix}-ind-v`} class="visually-hidden">
            Indicator value
          </label>
          <input
            id={`${idPrefix}-ind-v`}
            class="input mono"
            value={indValue}
            placeholder="203.0.113.7, evil[.]com, user@…"
            onInput={(e) => setIndValue((e.target as HTMLInputElement).value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                addIndicator();
              }
            }}
          />
          <label for={`${idPrefix}-ind-k`} class="visually-hidden">
            Indicator type
          </label>
          <select id={`${idPrefix}-ind-k`} class="select" value={indKind} onChange={(e) => setIndKind((e.target as HTMLSelectElement).value as IndicatorKind | 'auto')}>
            <option value="auto">auto</option>
            {KINDS.map((k) => (
              <option value={k}>{k}</option>
            ))}
          </select>
          <button type="button" class="btn btn-icon" onClick={addIndicator} aria-label="Add indicator">
            <Icon name="plus" />
          </button>
        </div>
        {v.indicators.length > 0 && (
          <ul class="indicators">
            {v.indicators.map((i) => (
              <li>
                <span class="badge">{i.kind}</span>
                <span class="mono small break">{i.value}</span>
                <button type="button" class="btn btn-ghost btn-icon btn-sm" aria-label={`Remove indicator ${i.value}`} onClick={() => onChange({ ...v, indicators: v.indicators.filter((x) => x !== i) })}>
                  <Icon name="x" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <fieldset class="segmented verdict-group">
        <legend>Disposition</legend>
        {(['true-positive', 'false-positive', 'benign'] as Disposition[]).map((d) => (
          <label title={DISPOSITION_HELP[d]}>
            <input type="radio" name={`${idPrefix}-disp`} checked={v.disposition === d} onChange={() => onChange({ ...v, disposition: d })} />
            {DISPOSITION_LABELS[d]}
          </label>
        ))}
      </fieldset>
      {v.disposition && <p class="faint small verdict-help">{DISPOSITION_HELP[v.disposition]}</p>}

      <fieldset class="segmented verdict-group">
        <legend>Severity</legend>
        {SEVERITY_ORDER.map((s) => (
          <label>
            <input type="radio" name={`${idPrefix}-sev`} checked={v.severity === s} onChange={() => onChange({ ...v, severity: s })} />
            {SEVERITY_LABELS[s]}
          </label>
        ))}
      </fieldset>

      <fieldset class="segmented verdict-group">
        <legend>Action</legend>
        {[...ACTION_ORDER].reverse().map((a) => (
          <label>
            <input type="radio" name={`${idPrefix}-act`} checked={v.action === a} onChange={() => onChange({ ...v, action: a })} />
            {ACTION_LABELS[a]}
          </label>
        ))}
      </fieldset>

      <div class="field verdict-group">
        <label for={`${idPrefix}-tech`}>MITRE ATT&CK</label>
        <TechniquePicker value={v.techniques} onChange={(t) => onChange({ ...v, techniques: t })} idPrefix={idPrefix} />
        <span class="field-hint">Leave empty if nothing malicious happened.</span>
      </div>

      <div class="field">
        <label for={`${idPrefix}-notes`}>Handover note</label>
        <textarea id={`${idPrefix}-notes`} class="textarea" rows={4} value={v.notes} onInput={(e) => onChange({ ...v, notes: (e.target as HTMLTextAreaElement).value })} placeholder="What happened, what you found, what should happen next." />
      </div>
      {rubric && (
        <ul class="rubric-live" aria-label="Note checklist">
          {rubric.map((r) => (
            <li class={r.hit ? 'is-hit' : undefined}>
              <Icon name={r.hit ? 'check' : 'minus'} /> {r.text}
            </li>
          ))}
        </ul>
      )}

      <button type="submit" class="btn btn-primary btn-lg submit-btn" aria-disabled={missing.length > 0}>
        {submitLabel}
      </button>
      {missing.length > 0 && <p class="faint small">Still needed: {missing.join(', ')}.</p>}
    </form>
  );
}
