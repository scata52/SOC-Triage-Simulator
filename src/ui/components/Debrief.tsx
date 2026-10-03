// The debrief: what it was, how the grade was made up, which findings you
// pinned or missed (with the actual rows), and the reference investigation —
// runnable, against the same logs.

import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
import type { ResolvedCase } from '../../core/cases/scenario.ts';
import { DISPOSITION_LABELS, SEVERITY_LABELS, ACTION_LABELS, type CaseGrade, type Verdict } from '../../core/grading/grade.ts';
import { techniqueName, TACTIC_LABELS } from '../../core/taxonomy/mitre.ts';
import type { QueryResult } from '../../core/query/engine.ts';
import { siem } from '../lib/siem.ts';
import type { LookupRow } from '../lib/protocol.ts';
import { Icon } from './Icon.tsx';
import { Ring } from './ui.tsx';
import { Results, fmtCell } from './Results.tsx';
import { resolveVulnLink } from '../lib/vuln-link.ts';

export function scoreColor(pct: number): string {
  return pct >= 85 ? 'var(--ok)' : pct >= 60 ? 'var(--warn)' : 'var(--bad)';
}

export function EvidenceRows({ ids }: { ids: string[] }) {
  const [rows, setRows] = useState<LookupRow[] | null>(null);
  const [open, setOpen] = useState(false);
  const toggle = async () => {
    if (!open && !rows) setRows(await siem.lookup(ids.slice(0, 25)));
    setOpen(!open);
  };
  const tables = rows ? [...new Set(rows.map((r) => r.table))] : [];
  return (
    <div>
      <button type="button" class="btn btn-sm btn-ghost" aria-expanded={open} onClick={toggle}>
        <Icon name={open ? 'down' : 'right'} /> {open ? 'Hide' : 'Show'} the {ids.length === 1 ? 'row' : `${Math.min(ids.length, 25)} rows`}
      </button>
      {open && rows && (
        <div class="evidence-rows">
          {tables.map((t) => {
            const group = rows.filter((r) => r.table === t);
            const cols = group[0].columns.map((c, i) => ({ c, i })).filter(({ c, i }) => c !== 'RecordId' && group.some((r) => r.row[i] !== null && r.row[i] !== ''));
            return (
              <div class="table-wrap" tabIndex={0} role="region" aria-label={`${t} rows`}>
                <table class="table">
                  <caption class="mono small" style={{ textAlign: 'left', padding: '4px 0' }}>
                    {t}
                  </caption>
                  <thead>
                    <tr>
                      {cols.map(({ c }) => (
                        <th scope="col">{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {group.map((r) => (
                      <tr>
                        {cols.map(({ i }) => (
                          <td class="mono small">{fmtCell(r.row[i])}</td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function StepRunner({ kql, expectEmpty }: { kql: string; expectEmpty?: boolean }) {
  const [res, setRes] = useState<QueryResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div>
      <button
        type="button"
        class="btn btn-sm"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            setRes(await siem.run(kql, 'kql', 200));
            setErr(null);
          } catch (e) {
            setErr((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        <Icon name="play" /> {res ? 'Run again' : 'Run it'}
      </button>
      {err && <p class="query-error small">{err}</p>}
      {res && (
        <div class="step-result">
          <p class="faint small mono">
            {res.total} rows{expectEmpty && res.total === 0 ? ' — the absence is the finding' : ''}
          </p>
          {res.rows.length > 0 && <Results result={res} pins={new Set()} />}
        </div>
      )}
    </div>
  );
}

// Only on the shift alert that a vulnerability case led to, and only here, after the alert is handed over.
function VulnLinkBack({ c }: { c: ResolvedCase }) {
  const l = c.vulnLink ? resolveVulnLink(c.vulnLink) : null;
  if (!l) return null;
  return (
    <p class="small vuln-link-back">
      The host carried <span class="mono">{l.vulnId}</span>, which you marked as {l.decision} / {l.schedule} in the vulnerability case &ldquo;{l.caseTitle}&rdquo;.{' '}
      <a href={l.href}>Open that case: {l.caseTitle}</a>
    </p>
  );
}

export function Debrief({ c, grade, verdict, actions }: { c: ResolvedCase; grade: CaseGrade; verdict: Verdict; actions: ComponentChildren }) {
  const t = c.truth;
  const g = grade;
  return (
    <div class="debrief">
      <section class="card debrief-hero" aria-labelledby="debrief-h">
        <Ring value={g.percent / 100} label={`${g.percent}`} sub="/ 100" color={scoreColor(g.percent)} />
        <div class="debrief-hero-text">
          <p class="eyebrow">Debrief · {c.alert.rule}</p>
          <h1 id="debrief-h">{c.lesson}</h1>
          <p>
            <strong class={g.dispositionCorrect ? 'text-ok' : 'text-bad'}>{g.dispositionCorrect ? 'Right call.' : 'Wrong call.'}</strong> It was{' '}
            <strong>{DISPOSITION_LABELS[t.disposition].toLowerCase()}</strong> — severity {SEVERITY_LABELS[t.severity].toLowerCase()}, action:{' '}
            {ACTION_LABELS[t.action].charAt(0).toLowerCase() + ACTION_LABELS[t.action].slice(1)}.
          </p>
          <p class="faint small">
            +{g.xp} XP{g.rubricHits.length ? ` (incl. ${g.rubricHits.length} note point${g.rubricHits.length === 1 ? '' : 's'})` : ''}
            {verdict.hintsUsed ? ` · ${verdict.hintsUsed} hint${verdict.hintsUsed === 1 ? '' : 's'} used` : ''}
          </p>
          <VulnLinkBack c={c} />
          <div class="btn-row">{actions}</div>
        </div>
      </section>

      <section class="card" aria-labelledby="grade-h">
        <h2 id="grade-h">Score breakdown</h2>
        <table class="table grade-table">
          <caption class="visually-hidden">Points per component</caption>
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col" class="num">
                Points
              </th>
              <th scope="col">Why</th>
            </tr>
          </thead>
          <tbody>
            {g.components.map((x) => (
              <tr>
                <th scope="row">
                  <Icon name={x.ok ? 'check' : x.earned > 0 ? 'minus' : 'x'} class={x.ok ? 'text-ok' : x.earned > 0 ? 'text-warn' : 'text-bad'} /> {x.label}
                </th>
                <td class="num mono">
                  {x.earned}/{x.possible}
                </td>
                <td class="small">{x.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section class="card" aria-labelledby="ev-h">
        <h2 id="ev-h">What the logs showed</h2>
        <ol class="findings">
          {g.evidence.map((e) => (
            <li class={e.found ? 'is-found' : 'is-missed'}>
              <div class="finding-head">
                <span class={`badge ${e.found ? 'badge-ok' : 'badge-bad'}`}>{e.found ? 'pinned' : 'missed'}</span>
                <strong>{e.label}</strong>
              </div>
              <p class="small muted">{e.why}</p>
              <EvidenceRows ids={e.recordIds} />
            </li>
          ))}
        </ol>
        {g.irrelevantPins > 0 && <p class="faint small">{g.irrelevantPins} of your pins were not among the key findings — fine in moderation; the grade tolerates a few.</p>}
      </section>

      <div class="grid grid-2">
        <section class="card" aria-labelledby="ind-h">
          <h2 id="ind-h">Indicators</h2>
          {g.indicators.results.length === 0 && c.indicators.block.length + c.indicators.scope.length === 0 && <p class="small">Nothing needed blocking — the right answer was to report nothing.</p>}
          {g.indicators.results.length > 0 && (
            <ul class="ind-results">
              {g.indicators.results.map((r) => (
                <li>
                  <span class={`badge ${r.verdict === 'correct' ? 'badge-ok' : 'badge-bad'}`}>{r.verdict === 'correct' ? 'correct' : r.verdict === 'must-not' ? 'must not block' : 'unsupported'}</span>{' '}
                  <span class="mono small break">{r.given.value}</span>
                  {r.spec?.note && <span class="faint small"> — {r.spec.note}</span>}
                </li>
              ))}
            </ul>
          )}
          {g.indicators.missedBlock.length + g.indicators.missedScope.length > 0 && (
            <>
              <h3 class="section-label">Missed</h3>
              <ul class="ind-results">
                {[...g.indicators.missedBlock.map((s) => ({ s, what: 'block' })), ...g.indicators.missedScope.map((s) => ({ s, what: 'affected' }))].map(({ s, what }) => (
                  <li>
                    <span class="badge">{what}</span> <span class="mono small break">{s.value}</span>
                    {s.note && <span class="faint small"> — {s.note}</span>}
                  </li>
                ))}
              </ul>
            </>
          )}
          {c.indicators.mustNot.length > 0 && (
            <p class="faint small">
              Traps here: {c.indicators.mustNot.map((m) => m.value).join(', ')} — {c.indicators.mustNot[0].note ?? 'legitimate infrastructure'}.
            </p>
          )}
        </section>

        <section class="card" aria-labelledby="attack-h">
          <h2 id="attack-h">MITRE ATT&CK</h2>
          {t.techniques.length === 0 ? (
            <p class="small">No adversary technique applies — nothing malicious happened.</p>
          ) : (
            <ul class="tech-results">
              {t.techniques.map((id) => {
                const hit = g.techniques.matched.includes(id);
                return (
                  <li>
                    <span class={`badge ${hit ? 'badge-ok' : g.techniques.missed.includes(id) ? 'badge-bad' : 'badge-warn'}`}>{hit ? 'tagged' : g.techniques.missed.includes(id) ? 'missed' : 'related'}</span>{' '}
                    <a href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`} target="_blank" rel="noopener noreferrer" class="mono">
                      {id}
                      <span class="visually-hidden"> (opens in a new tab)</span>
                    </a>{' '}
                    {techniqueName(id)}
                  </li>
                );
              })}
            </ul>
          )}
          {g.techniques.extra.length > 0 && <p class="small">Not supported by the evidence: {g.techniques.extra.map((id) => `${id} ${techniqueName(id)}`).join(', ')}.</p>}
          {g.techniques.accepted.length > 0 && <p class="faint small">Also defensible: {g.techniques.accepted.join(', ')}.</p>}
          {t.tactics.length > 0 && <p class="faint small">Tactics: {t.tactics.map((x) => TACTIC_LABELS[x]).join(' → ')}</p>}
        </section>
      </div>

      <section class="card" aria-labelledby="ref-h">
        <h2 id="ref-h">Reference investigation</h2>
        <p class="muted small">One way to work it. Each query runs against the same logs you had.</p>
        <ol class="steps">
          {c.solution.map((s) => (
            <li>
              <h3>{s.title}</h3>
              <pre class="code-block mono">{s.kql}</pre>
              <p class="small muted">{s.why}</p>
              <StepRunner kql={s.kql} expectEmpty={s.expectEmpty} />
            </li>
          ))}
        </ol>
      </section>

      <div class="grid grid-2">
        <section class="card" aria-labelledby="exp-h">
          <h2 id="exp-h">Why</h2>
          {c.explanation.map((p) => (
            <p class="small">{p}</p>
          ))}
        </section>
        <section class="card" aria-labelledby="pit-h">
          <h2 id="pit-h">Pitfalls</h2>
          <ul class="small">
            {c.pitfalls.map((p) => (
              <li>{p}</li>
            ))}
          </ul>
          {c.rubric.length > 0 && (
            <>
              <h3 class="section-label">A strong handover note covers</h3>
              <ul class="small">
                {c.rubric.map((r) => (
                  <li class={g.rubricHits.includes(r.id) ? 'text-ok' : undefined}>
                    {g.rubricHits.includes(r.id) ? '✓ ' : ''}
                    {r.text}
                  </li>
                ))}
              </ul>
            </>
          )}
          {c.references.length > 0 && (
            <>
              <h3 class="section-label">Read more</h3>
              <ul class="small">
                {c.references.map((r) => (
                  <li>
                    <a href={r.url} target="_blank" rel="noopener noreferrer">
                      {r.label} <Icon name="external" />
                      <span class="visually-hidden"> (opens in a new tab)</span>
                    </a>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
