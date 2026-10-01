// The debrief of a vulnerability case. The only screen that receives the
// resolved case (truth, lesson, rubric): it renders after the submit.

import type { ComponentChildren } from 'preact';
import type { VulnFindingGrade, VulnGrade, VulnSubmission, VulnDecisionVerdict, VulnScheduleVerdict } from '../../core/vuln/grade.ts';
import type { ResolvedVulnCase, ResolvedVulnFinding } from '../../core/vuln/scenario.ts';
import { DECISION_LABELS, REASON_LABELS, SCHEDULE_LABELS, VULN_PASS_PERCENT, type WorklistRow } from '../../core/vuln/worklist.ts';
import { Icon } from '../components/Icon.tsx';
import { Bar, Ring } from '../components/ui.tsx';
import { EvidenceRows, StepRunner, scoreColor } from '../components/Debrief.tsx';

const DECISION_VERDICT: Record<VulnDecisionVerdict, string> = {
  exact: 'Right',
  'also-accepted': 'Also accepted',
  'near-miss': 'Half: near miss',
  'wrong-control': 'Half: wrong or missing control',
  wrong: 'Wrong',
  missing: 'Not decided',
};

const SCHEDULE_VERDICT: Record<VulnScheduleVerdict, string> = {
  exact: 'Right',
  'one-step': 'Half: one step off',
  'emergency-unjustified': 'Half: emergency not needed',
  'sla-breach': 'Later than the SLA allows',
  overflow: 'Over capacity',
  wrong: 'Wrong',
  missing: 'Not scheduled',
};

const reasonText = (codes: readonly string[]) => (codes.length ? codes.map((c) => REASON_LABELS[c as keyof typeof REASON_LABELS] ?? c).join(', ') : 'none');

export function VulnDebrief({
  c,
  grade: g,
  submission,
  rows,
  actions,
}: {
  c: ResolvedVulnCase;
  grade: VulnGrade;
  submission: VulnSubmission;
  rows: ReadonlyMap<string, WorklistRow>;
  actions: ComponentChildren;
}) {
  const passed = g.percent >= VULN_PASS_PERCENT;
  const n = c.findings.length;
  const byId = new Map<string, ResolvedVulnFinding>(c.findings.map((f) => [f.findingId, f]));
  const gradeOf = new Map<string, VulnFindingGrade>(g.findings.map((f) => [f.findingId, f]));
  const where = (id: string) => {
    const host = rows.get(id)?.host;
    return host ? `${id} on ${host}` : id;
  };
  const { dismissed, outsideTopK, decisionPenalty, orderingPenalty } = g.mustNotMiss;
  const topK = c.findings.filter((f) => f.mustNotMiss).length + 1;

  // Dismissed must-not-miss findings first, then the ideal order, then the rest.
  const ordered = [
    ...new Set([...dismissed, ...c.idealOrder, ...c.findings.map((f) => f.findingId).sort()]),
  ].filter((id) => byId.has(id));

  const notesPoints = g.rubricHits.length;

  return (
    <div class="debrief vd">
      <section class="card debrief-hero" aria-labelledby="debrief-h">
        <Ring value={g.percent / 100} label={`${g.percent}`} sub="/ 100" color={scoreColor(g.percent)} />
        <div class="debrief-hero-text">
          <p class="eyebrow">Debrief · {c.title}</p>
          <h1 id="debrief-h">{c.lesson}</h1>
          <p>
            <strong class={passed ? 'text-ok' : 'text-bad'}>{passed ? 'Passed.' : 'Below the pass mark.'}</strong> The pass mark is {VULN_PASS_PERCENT}; you scored {g.percent}.
          </p>
          {dismissed.length > 0 && (
            <p>
              Costly mistake: you dismissed {dismissed.map(where).join(', ')}, a real must-not-miss finding, as a false positive.
            </p>
          )}
          <p class="faint small vd-xp">
            +{g.xp} XP{notesPoints ? ` (incl. ${notesPoints} note point${notesPoints === 1 ? '' : 's'})` : ''}
            {submission.hintsUsed ? ` · ${submission.hintsUsed} hint${submission.hintsUsed === 1 ? '' : 's'} used` : ''}
          </p>
          <div class="btn-row">{actions}</div>
        </div>
      </section>

      {(dismissed.length > 0 || outsideTopK.length > 0) && (
        <section class="card vd-lead" aria-labelledby="vd-lead-h">
          <h2 id="vd-lead-h">What mattered most</h2>
          <ul class="small">
            {dismissed.map((id) => {
              const f = byId.get(id)!;
              const r = rows.get(id);
              return (
                <li>
                  You dismissed <strong>{id}</strong> on <strong>{r?.host ?? 'its host'}</strong> ({r?.title ?? 'finding'}) as a false positive. It is real: the right call was <strong>{DECISION_LABELS[f.truth.decision]}</strong>,{' '}
                  <strong>{SCHEDULE_LABELS[f.truth.schedule].toLowerCase()}</strong>. {g.evidence.find((e) => e.findingId === id)?.why ?? ''}
                </li>
              );
            })}
            {outsideTopK.map((id) => {
              const pos = gradeOf.get(id)?.position;
              return (
                <li>
                  <strong>{where(id)}</strong> was {pos === null || pos === undefined ? 'not ranked' : `at position ${pos + 1}`}; must-not-miss findings belong in the top {topK}.
                </li>
              );
            })}
          </ul>
          <p class="faint small">
            Penalty: −{decisionPenalty} decisions, −{orderingPenalty} ordering (a component never goes below 0).
          </p>
        </section>
      )}

      <section class="card" aria-labelledby="grade-h">
        <h2 id="grade-h">Score breakdown</h2>
        <table class="table grade-table">
          <caption class="visually-hidden">Points per component</caption>
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Points</th>
              <th scope="col">Why</th>
            </tr>
          </thead>
          <tbody>
            {g.components.map((x) => (
              <tr>
                <th scope="row">
                  <Icon name={x.ok ? 'check' : x.earned > 0 ? 'minus' : 'x'} class={x.ok ? 'text-ok' : x.earned > 0 ? 'text-warn' : 'text-bad'} /> {x.label}
                </th>
                <td class="mono">
                  <Bar value={x.possible ? x.earned / x.possible : 0} label={`${x.label}: ${x.earned} of ${x.possible} points`} />
                  <span class="vd-pts">
                    {x.earned}/{x.possible}
                  </span>
                </td>
                <td class="small">{x.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section class="card" aria-labelledby="vd-findings-h">
        <h2 id="vd-findings-h">Finding by finding</h2>
        <ol class="vd-findings">
          {ordered.map((id) => {
            const f = byId.get(id)!;
            const fg = gradeOf.get(id)!;
            const r = rows.get(id);
            const tier = c.tiers.findIndex((t) => t.includes(id));
            const ev = g.evidence.filter((e) => e.findingId === id);
            const t = f.truth;
            const mitigates = t.decision === 'mitigate' || fg.decision.given === 'mitigate';
            const given = submission.answers[id];
            return (
              <li class="card vd-finding" data-finding-id={id}>
                <div class="finding-head">
                  <strong class="mono">{id}</strong>
                  <span>· {r?.host ?? ''} · {r?.title ?? ''}</span>
                  {r?.vulnId ? <span class="mono small">{r.vulnId}</span> : null}
                  {f.mustNotMiss && <span class="badge badge-bad">must-not-miss</span>}
                  <span class="badge">{tier >= 0 ? `urgency tier ${tier + 1}` : 'no urgency tier'}</span>
                </div>
                <dl class="vd-dl">
                  <dt>Decision</dt>
                  <dd data-field="decision">
                    Yours: {fg.decision.given ? DECISION_LABELS[fg.decision.given] : 'not decided'} · Right: {DECISION_LABELS[t.decision]} · <strong>{DECISION_VERDICT[fg.decision.verdict]}</strong>
                    {mitigates && (
                      <>
                        <br />
                        Controls that cover it: {(t.mitigation ?? []).join(', ') || 'none'} · Yours: {given?.control ?? 'none'}
                      </>
                    )}
                  </dd>
                  <dt>Schedule</dt>
                  <dd data-field="schedule">
                    Yours: {fg.schedule.given ? SCHEDULE_LABELS[fg.schedule.given] : 'not scheduled'} · Right: {SCHEDULE_LABELS[t.schedule]} · <strong>{SCHEDULE_VERDICT[fg.schedule.verdict]}</strong>
                    {t.slaLatest && (
                      <>
                        <br />
                        Latest schedule within the SLA: {SCHEDULE_LABELS[t.slaLatest]}
                      </>
                    )}
                  </dd>
                  <dt>Priority</dt>
                  <dd data-field="priority">Your position: {fg.position === null ? 'not ranked' : fg.position + 1} of {n}</dd>
                  <dt>Reasons</dt>
                  <dd data-field="reasons">
                    {fg.reasons.matched.map((code) => (
                      <span class="vd-reason text-ok">✓ {REASON_LABELS[code]} </span>
                    ))}
                    {fg.reasons.missed.map((code) => (
                      <span class="vd-reason">Missed: {REASON_LABELS[code]} </span>
                    ))}
                    {fg.reasons.contradicting.map((code) => (
                      <span class="vd-reason text-bad">✗ {REASON_LABELS[code]} (contradicted by the evidence, −0.25 each) </span>
                    ))}
                    <br />
                    Credit {Math.round(fg.reasons.credit * 100)}%
                  </dd>
                  <dt>Why</dt>
                  <dd data-field="why">Right because: {reasonText(t.reasons)}</dd>
                </dl>
                {ev.map((e) => (
                  <div class="vd-evidence">
                    <div class="finding-head">
                      <span class={`badge ${e.found ? 'badge-ok' : 'badge-bad'}`}>{e.found ? 'pinned' : 'missed'}</span>
                      <strong>{e.label}</strong>
                    </div>
                    <p class="small muted">{e.why}</p>
                    <EvidenceRows ids={e.recordIds} />
                  </div>
                ))}
              </li>
            );
          })}
        </ol>
        {g.irrelevantPins > 0 && <p class="faint small">{g.irrelevantPins} of your pins were not among the key findings. The grade tolerates a few, not a blanket pin of every row.</p>}
      </section>

      {g.overflow.length > 0 && (
        <section class="card" aria-labelledby="vd-over-h">
          <h2 id="vd-over-h">Over capacity</h2>
          <p class="small">
            Your emergency and next-window changes exceeded the capacity of {c.constraints.capacityPerWindow} per window. These findings lost their schedule credit, lowest urgency first:
          </p>
          <ul class="small">
            {g.overflow.map((id) => (
              <li>
                {where(id)}: {SCHEDULE_VERDICT[gradeOf.get(id)?.schedule.verdict ?? 'overflow']}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section class="card" aria-labelledby="ref-h">
        <h2 id="ref-h">Reference investigation</h2>
        <p class="muted small">One way to work it. Each query runs against the same scan results you had.</p>
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
              <h3 class="section-label">A strong stakeholder note covers</h3>
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
