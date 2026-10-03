// The debrief of a vulnerability case. The only screen that receives the
// resolved case (truth, lesson, rubric): it renders after the submit.

import { Fragment, type ComponentChildren } from 'preact';
import type { KeyMissWhy, VulnFindingGrade, VulnGrade, VulnSubmission, VulnDecisionVerdict, VulnScheduleVerdict } from '../../core/vuln/grade.ts';
import type { VulnDecision } from '../../core/vuln/model.ts';
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
  'no-decision': 'No credit: the decision earned nothing',
  wrong: 'Wrong',
  missing: 'Not scheduled',
};

// Why a key finding counts as missed (DESIGN section 5.8), as it reads after "was given".
const MISS_TEXT: Record<KeyMissWhy, string> = {
  undecided: 'no decision',
  'wrong-decision': 'a wrong decision',
  'near-miss': 'a half-right decision (a lesson finding needs the full answer)',
  'wrong-control': 'no control, or one that does not cover the path',
  unscheduled: 'no schedule',
  late: 'a schedule later than its SLA allows',
  'two-steps': 'a schedule two or more steps from the right one',
};

// A duplicate detection is closed as a false positive with the Duplicate root cause reason: the flaw is real and is
// fixed once elsewhere. Only the right call is qualified (the grader scores the decision code alone and the reason under
// Justification), so "Yours" always shows the plain decision label.
const isDuplicate = (t: { decision: VulnDecision; reasons: readonly string[] }) => t.decision === 'false-positive' && t.reasons.includes('duplicate-root-cause');
const rightLabel = (t: { decision: VulnDecision; reasons: readonly string[] }, short = false) =>
  isDuplicate(t) ? `${DECISION_LABELS[t.decision]} (${short ? 'closed as a duplicate' : 'a duplicate: closed with the reason Duplicate root cause'})` : DECISION_LABELS[t.decision];

// Which places of the ideal order a tier fills (tiers are listed most urgent first).
const tierPlaces = (tiers: readonly (readonly string[])[], tier: number) => {
  const first = tiers.slice(0, tier).reduce((sum, t) => sum + t.length, 0) + 1;
  const last = first + tiers[tier].length - 1;
  return first === last ? `place ${first}` : `places ${first}–${last}`;
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
  const { dismissed, late, outsideTopK, decisionPenalty, orderingPenalty } = g.mustNotMiss;
  const { missed, cap, uncapped } = g.gate;
  const binds = cap !== null && uncapped > cap;
  const describeMiss = (m: VulnGrade['gate']['missed'][number]) => `${where(m.findingId)}, ${m.lesson ? 'a finding this case turns on' : 'a must-not-miss finding'}, was given ${MISS_TEXT[m.why]}`;
  const topK = c.findings.filter((f) => f.mustNotMiss).length + 1;
  const penalties = [
    decisionPenalty > 0 && `−${decisionPenalty} points of Decisions (must-not-miss findings left open)`,
    orderingPenalty > 0 && `−${orderingPenalty} points of Ordering (must-not-miss findings outside the top ${topK})`,
  ].filter((x): x is string => x !== false);

  // One bullet per finding: missed key findings first, then dismissed, late, and out-of-place must-not-miss ones.
  const leadIds = [...new Set([...missed.map((m) => m.findingId).filter((id) => !dismissed.includes(id)), ...dismissed, ...late, ...outsideTopK])].filter((id) => byId.has(id));

  // Missed key findings first, then dismissed or late must-not-miss ones, then the ideal order, then the rest.
  const ordered = [
    ...new Set([...missed.map((m) => m.findingId), ...dismissed, ...late, ...c.idealOrder, ...c.findings.map((f) => f.findingId).sort()]),
  ].filter((id) => byId.has(id));

  const notesPoints = g.rubricHits.length;

  return (
    <div class="debrief vd">
      <section class="card debrief-hero" aria-labelledby="debrief-h">
        <Ring value={g.percent / 100} label={`${g.percent}`} sub="/ 100" color={scoreColor(g.percent)} />
        <div class="debrief-hero-text">
          <p class="eyebrow">Debrief · {c.title}</p>
          <h1 id="debrief-h">{c.lesson}</h1>
          {cap !== null && (
            <p class="vd-gate" data-gate="missed">
              <strong class="text-bad">{binds ? `Capped at ${cap} (pass ${VULN_PASS_PERCENT}; ${uncapped} before the cap)` : `A missed key finding caps the score at ${cap} (pass ${VULN_PASS_PERCENT}); yours was ${uncapped} before the cap`}:</strong>{' '}
              {missed.map((m, i) => (
                <Fragment key={m.findingId}>
                  {i > 0 ? '; ' : ''}
                  {describeMiss(m)}
                </Fragment>
              ))}
              .
            </p>
          )}
          <p>
            <strong class={passed ? 'text-ok' : 'text-bad'}>{passed ? 'Passed.' : 'Below the pass mark.'}</strong> The pass mark is {VULN_PASS_PERCENT}; you scored {g.percent}.
          </p>
          {dismissed.length > 0 && (
            <p>
              Costly mistake: you dismissed {dismissed.map(where).join(', ')}, {dismissed.length === 1 ? 'a real must-not-miss finding' : 'real must-not-miss findings'}, as a false positive.
            </p>
          )}
          <p class="faint small vd-xp">
            +{g.xp} XP{notesPoints ? ` (incl. ${notesPoints} note point${notesPoints === 1 ? '' : 's'})` : ''}
            {submission.hintsUsed ? ` · ${submission.hintsUsed} hint${submission.hintsUsed === 1 ? '' : 's'} used` : ''}
          </p>
          <div class="btn-row">{actions}</div>
        </div>
      </section>

      {(missed.length > 0 || dismissed.length > 0 || late.length > 0 || outsideTopK.length > 0) && (
        <section class="card vd-lead" aria-labelledby="vd-lead-h">
          <h2 id="vd-lead-h">What mattered most</h2>
          <ul class="small">
            {leadIds.map((id) => {
              const f = byId.get(id)!;
              const t = f.truth;
              const m = missed.find((x) => x.findingId === id);
              const r = rows.get(id);
              const pos = gradeOf.get(id)?.position;
              return (
                <li data-miss={m ? id : undefined}>
                  {dismissed.includes(id) ? (
                    <>
                      You dismissed <strong>{id}</strong> on <strong>{r?.host ?? 'its host'}</strong> ({r?.title ?? 'finding'}) as a false positive. It is real: the right call was <strong>{rightLabel(t, true)}</strong>,{' '}
                      <strong>{SCHEDULE_LABELS[t.schedule].toLowerCase()}</strong>. {g.evidence.find((e) => e.findingId === id)?.why ?? ''}
                    </>
                  ) : m ? (
                    <>
                      <strong>{where(id)}</strong> {m.lesson ? 'is a finding this case turns on' : 'is a must-not-miss finding'}, and it was given {MISS_TEXT[m.why]}. The right call was <strong>{rightLabel(t, true)}</strong>,{' '}
                      <strong>{SCHEDULE_LABELS[t.schedule].toLowerCase()}</strong>
                      {t.slaLatest ? ` (latest within the SLA: ${SCHEDULE_LABELS[t.slaLatest].toLowerCase()})` : ''}.
                    </>
                  ) : late.includes(id) ? (
                    <>
                      <strong>{where(id)}</strong> was left open: {gradeOf.get(id)?.schedule.given ? 'scheduled later than its SLA allows' : 'not scheduled'}. A real must-not-miss finding has to be fixed in time.
                    </>
                  ) : (
                    <>
                      <strong>{where(id)}</strong> is a must-not-miss finding.
                    </>
                  )}
                  {outsideTopK.includes(id) && (
                    <>
                      {' '}
                      It was {pos === null || pos === undefined ? 'not ranked' : `at position ${pos + 1}`}; must-not-miss findings belong in the top {topK}.
                    </>
                  )}
                </li>
              );
            })}
          </ul>
          {(penalties.length > 0 || cap !== null) && (
            <p class="faint small">
              {penalties.length > 0 && `Penalty: ${penalties.join(', ')} (a component never goes below 0).`}
              {cap !== null && `${penalties.length > 0 ? ' ' : ''}The cap of ${cap} applies to the total, whatever the components add up to.`}
            </p>
          )}
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
        <p class="faint small">
          Unsure what a term here means? <a href="#/help/vuln">Vulnerability terms (Help)</a>.
        </p>
      </section>

      <section class="card" aria-labelledby="vd-findings-h">
        <h2 id="vd-findings-h">Finding by finding</h2>
        <p class="muted small">Missed key findings first, then every finding in the ideal urgency order.</p>
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
                  <h3 class="vd-finding-h">
                    <span class="mono">{id}</span> · {r?.host ?? ''} · {r?.title ?? ''}
                  </h3>
                  {r?.vulnId ? <span class="mono small">{r.vulnId}</span> : null}
                  {f.mustNotMiss && <span class="badge badge-bad">must-not-miss</span>}
                  {fg.lesson && <span class="badge">Lesson finding</span>}
                  {fg.keyMiss !== null && <span class="badge badge-bad">missed key finding</span>}
                  <span class="badge">{tier >= 0 ? `urgency tier ${tier + 1}` : 'no urgency tier'}</span>
                </div>
                <dl class="vd-dl">
                  <dt>Decision</dt>
                  <dd data-field="decision">
                    Yours: {fg.decision.given ? DECISION_LABELS[fg.decision.given] : 'not decided'} · Right: {rightLabel(t)} · <strong>{DECISION_VERDICT[fg.decision.verdict]}</strong>
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
                  <dd data-field="priority">
                    Your position: {fg.position === null ? 'not ranked' : fg.position + 1} of {n} · {tier >= 0 ? `urgency tier ${tier + 1} fills ${tierPlaces(c.tiers, tier)}` : 'no urgency tier: after the tiered findings'}
                  </dd>
                  <dt>Reasons</dt>
                  <dd data-field="reasons">
                    {fg.reasons.matched.map((code) => (
                      <span class="vd-reason text-ok">✓ {REASON_LABELS[code]} </span>
                    ))}
                    {fg.reasons.missed.map((code) => (
                      <span class="vd-reason">Missed: {REASON_LABELS[code]} </span>
                    ))}
                    {fg.reasons.contradicting.map((code) => (
                      <span class="vd-reason text-bad">✗ {REASON_LABELS[code]} (contradicts the evidence: −50% credit) </span>
                    ))}
                    {fg.reasons.unneeded.map((code) => (
                      <span class="vd-reason">− {REASON_LABELS[code]} (not needed here: −25% credit) </span>
                    ))}
                    <br />
                    Credit {Math.round(fg.reasons.credit * 100)}%
                    {fg.reasons.zeroed && ' — no credit: the decision earned nothing, and reasons only qualify a decision'}
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
        {g.irrelevantPins > 0 && (
          <p class="faint small">
            {g.irrelevantPins} of your pins {g.irrelevantPins === 1 ? 'was' : 'were'} not evidence for any finding. The grade frees one such pin per evidence point ({g.evidence.length}) and takes a point off each further one, so a blanket pin of every row does not pay.
          </p>
        )}
      </section>

      {g.overflow.length > 0 && (
        <section class="card" aria-labelledby="vd-over-h">
          <h2 id="vd-over-h">Over capacity</h2>
          <p class="small">
            Your emergency and next-window changes exceeded the capacity of {c.constraints.capacityPerWindow} per window. These findings went over capacity, lowest urgency first; any schedule credit they had is gone:
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
