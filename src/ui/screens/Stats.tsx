import { profile } from '../store/app.ts';
import { Bar, Empty } from '../components/ui.tsx';
import { rankFor, type AttemptRecord } from '../../state/profile.ts';
import { mixUpSentence, vulnStats, type VulnStats } from '../../state/vuln-stats.ts';
import { DECISION_LABELS, VULN_PASS_PERCENT } from '../../core/vuln/worklist.ts';
import { POINTS, type ComponentId } from '../../core/grading/grade.ts';
import { CATEGORY_LABELS } from '../../core/cases/templates/index.ts';
import { templateById } from '../../core/cases/templates/index.ts';
import type { Category } from '../../core/types.ts';
import { ago, duration, num } from '../lib/format.ts';

const COMPONENT_LABELS: Record<ComponentId, string> = {
  disposition: 'Disposition',
  severity: 'Severity',
  action: 'Action',
  attack: 'ATT&CK mapping',
  evidence: 'Evidence found',
  indicators: 'Indicators',
};

function Trend({ attempts }: { attempts: AttemptRecord[] }) {
  const W = 640;
  const H = 150;
  const pad = { l: 28, r: 8, t: 10, b: 18 };
  const n = attempts.length;
  const x = (i: number) => pad.l + (n <= 1 ? (W - pad.l - pad.r) / 2 : (i * (W - pad.l - pad.r)) / (n - 1));
  const y = (v: number) => pad.t + ((100 - v) * (H - pad.t - pad.b)) / 100;
  // Rolling mean of 5 to show the trend under the noise.
  const roll = attempts.map((_, i) => {
    const w = attempts.slice(Math.max(0, i - 4), i + 1);
    return w.reduce((s, a) => s + a.percent, 0) / w.length;
  });
  const line = roll.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const area = `${line} L${x(n - 1).toFixed(1)},${y(0)} L${x(0).toFixed(1)},${y(0)} Z`;
  const avg = Math.round(attempts.reduce((s, a) => s + a.percent, 0) / Math.max(1, n));
  return (
    <figure style={{ margin: 0 }}>
      <svg class="spark" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Scores of your last ${n} cases: average ${avg}, latest ${attempts[n - 1]?.percent ?? 0}. Rolling five-case average shown as a line.`}>
        {[0, 50, 100].map((v) => (
          <>
            <line class="grid-line" x1={pad.l} x2={W - pad.r} y1={y(v)} y2={y(v)} />
            <text x={pad.l - 6} y={y(v) + 3} text-anchor="end">
              {v}
            </text>
          </>
        ))}
        {n > 1 && <path class="area" d={area} />}
        {n > 1 && <path class="line" d={line} />}
        {attempts.map((a, i) => (
          <circle cx={x(i)} cy={y(a.percent)} r={3} class={a.dispositionCorrect ? 'dot-ok' : 'dot-bad'}>
            <title>
              {templateById(a.templateId)?.title}: {a.percent}% ({a.dispositionCorrect ? 'right call' : 'wrong call'})
            </title>
          </circle>
        ))}
      </svg>
      <figcaption class="faint small">
        Dots: each case (green right call, red wrong). Line: rolling average of five.
      </figcaption>
    </figure>
  );
}

const rateColor = (r: number) => (r >= 0.8 ? 'var(--ok)' : r >= 0.55 ? 'var(--warn)' : 'var(--bad)');
const pct = (r: number) => `${Math.round(r * 100)}%`;

// Vulnerability management: domain 2.0 summary, objectives 2.1-2.5, decision confusion matrix.
function VulnSection({ stats }: { stats: VulnStats }) {
  const { summary, objectives, matrix, mixUp } = stats;
  return (
    <section class="card" style={{ marginTop: 'var(--space-4)' }} aria-labelledby="vuln-h">
      <h2 id="vuln-h">Vulnerability management</h2>
      <p class="faint small">CySA+ domain 2.0. A case counts as passed at a score of {VULN_PASS_PERCENT} or more. A case tagged with several objectives counts in each of their rows.</p>
      <div class="grid grid-3">
        {[
          [num(summary.cases), 'cases graded'],
          [summary.passRate === null ? '—' : pct(summary.passRate), `passed (${summary.passed} of ${summary.cases})`],
          [summary.avgScore === null ? '—' : `${Math.round(summary.avgScore)}`, 'average score'],
        ].map(([v, l]) => (
          <div class="card stat">
            <span class="stat-value">{v}</span>
            <span class="stat-label">{l}</span>
          </div>
        ))}
      </div>

      <h3 class="section-label">Objectives</h3>
      <div class="table-wrap" tabIndex={0} role="region" aria-label="Results by CySA+ objective">
        <table class="table">
          <caption class="visually-hidden">Cases, share passed and average score for each CySA+ vulnerability objective, 2.1 to 2.5</caption>
          <thead>
            <tr>
              <th scope="col">Objective</th>
              <th scope="col" class="num">
                Cases
              </th>
              <th scope="col">Passed</th>
              <th scope="col" class="num">
                Avg score
              </th>
            </tr>
          </thead>
          <tbody>
            {objectives.map((o) => (
              <tr>
                <th scope="row" style={{ textTransform: 'none', letterSpacing: 0, color: 'var(--text)', fontWeight: 500, whiteSpace: 'normal' }}>
                  {o.label}
                  <span class="visually-hidden">. {o.title}</span>
                </th>
                {o.passRate === null || o.avgScore === null ? (
                  <td colSpan={3} class="muted small">
                    No cases yet
                  </td>
                ) : (
                  <>
                    <td class="num mono">{o.cases}</td>
                    <td style={{ minWidth: 160 }}>
                      <div class="row" style={{ flexWrap: 'nowrap' }}>
                        <Bar value={o.passRate} label={`${o.label}: ${pct(o.passRate)} passed`} color={rateColor(o.passRate)} />
                        <span class="mono small">{pct(o.passRate)}</span>
                      </div>
                    </td>
                    <td class="num mono">{Math.round(o.avgScore)}</td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 class="section-label">Decision matrix</h3>
      <p class="small" style={{ marginTop: 0 }}>
        {mixUpSentence(mixUp, matrix.findings, matrix.wrongControl)}
      </p>
      <div class="table-wrap" tabIndex={0} role="region" aria-label="Decision matrix: the right decision against the decision you chose">
        <table class="table matrix">
          <caption class="visually-hidden">
            Number of findings by the right decision (rows) and the decision you chose (columns), over all vulnerability cases. A check mark marks the cells where your decision matched the right one. Cells off the diagonal are mix-ups, unless the case also accepted that decision.
          </caption>
          <colgroup>
            <col />
          </colgroup>
          <colgroup span={matrix.givens.length} />
          <thead>
            <tr>
              <th scope="col" rowSpan={2}>
                Right decision
              </th>
              <th scope="colgroup" colSpan={matrix.givens.length} class="matrix-group">
                Your decision
              </th>
            </tr>
            <tr>
              {matrix.givens.map((g) => (
                <th scope="col">{g === null ? 'No decision' : DECISION_LABELS[g]}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.truths.map((t, r) => (
              <tr>
                <th scope="row">{DECISION_LABELS[t]}</th>
                {matrix.givens.map((g, c) => {
                  const n = matrix.counts[r][c];
                  const diag = g === t;
                  return (
                    <td class={`num mono${diag ? ' matrix-diag' : ''}${n === 0 ? ' matrix-zero' : ''}`}>
                      {diag && <span aria-hidden="true">✓ </span>}
                      {n}
                      {diag && <span class="visually-hidden"> (matched the right decision)</span>}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p class="faint small">{num(matrix.findings)} findings in {num(summary.cases)} cases. A ✓ marks the cells where your decision matched the right one.
        {matrix.alternatives > 0 && ` ${matrix.alternatives} off-diagonal ${matrix.alternatives === 1 ? 'answer was an alternative' : 'answers were alternatives'} the case also accepted and earned full credit.`}
      </p>
    </section>
  );
}

export function Stats() {
  const p = profile.value;
  // The SOC sections read SOC attempts only; vulnerability attempts have their own section.
  const a = p.attempts.filter((x) => x.mode !== 'vuln');
  const vuln = vulnStats(p.attempts);
  const rank = rankFor(p.xp);
  const hasSoc = a.length > 0 || p.shifts.length > 0;
  if (!hasSoc && !vuln.hasData) {
    return (
      <div class="page page-narrow">
        <h1>Stats</h1>
        <div class="card">
          <Empty icon="chart">No graded cases yet. Work a case or a shift and this page fills in.</Empty>
        </div>
      </div>
    );
  }
  const graded = a.filter((x) => !x.legacy);
  const correct = a.filter((x) => x.dispositionCorrect).length;
  const avg = Math.round(a.reduce((s, x) => s + x.percent, 0) / Math.max(1, a.length));
  const recent = a.slice(-40);
  const comps = (Object.keys(POINTS) as ComponentId[]).map((id) => {
    const withC = graded.filter((x) => x.components[id] !== undefined);
    const share = withC.length ? withC.reduce((s, x) => s + (x.components[id] ?? 0), 0) / (withC.length * POINTS[id]) : null;
    return { id, share, n: withC.length };
  });
  const cats = [...new Set(a.map((x) => x.category))].map((c) => {
    const list = a.filter((x) => x.category === c);
    return { c, n: list.length, acc: list.filter((x) => x.dispositionCorrect).length / list.length, avg: list.reduce((s, x) => s + x.percent, 0) / list.length };
  });
  const shifts = [...p.shifts].reverse().slice(0, 12);
  const evidenceRate = graded.filter((x) => x.evidenceTotal).length ? graded.reduce((s, x) => s + x.evidenceFound, 0) / Math.max(1, graded.reduce((s, x) => s + x.evidenceTotal, 0)) : null;

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <p class="eyebrow">Stats</p>
          <h1>{p.analystName}</h1>
          <p>
            {rank.current.name} · {num(p.xp)} XP
          </p>
        </div>
      </div>

      {hasSoc ? (
        <>
      <div class="grid grid-4">
        {[
          [num(a.length), 'cases graded'],
          [`${Math.round((correct / Math.max(1, a.length)) * 100)}%`, 'correct dispositions'],
          [`${avg}`, 'average score'],
          [evidenceRate === null ? '—' : `${Math.round(evidenceRate * 100)}%`, 'key findings pinned'],
          [`${p.bestStreak}`, 'best streak of right calls'],
          [num(p.shifts.length), 'shifts worked'],
        ].map(([v, l]) => (
          <div class="card stat">
            <span class="stat-value">{v}</span>
            <span class="stat-label">{l}</span>
          </div>
        ))}
      </div>

      <div class="grid grid-2" style={{ marginTop: 'var(--space-4)' }}>
        <section class="card" aria-labelledby="trend-h">
          <h2 id="trend-h">Recent scores</h2>
          {recent.length ? <Trend attempts={recent} /> : <p class="muted">No cases yet.</p>}
        </section>
        <section class="card" aria-labelledby="where-h">
          <h2 id="where-h">Where the points go</h2>
          <p class="faint small">Share of each component earned, across {graded.length} cases graded by the current rubric.</p>
          <ul class="skill-list">
            {comps.map((x) => (
              <li>
                <span>{COMPONENT_LABELS[x.id]}</span>
                {x.share === null ? <span class="faint small">no data</span> : <Bar value={x.share} label={`${COMPONENT_LABELS[x.id]}: ${Math.round(x.share * 100)}%`} color={x.share >= 0.8 ? 'var(--ok)' : x.share >= 0.55 ? 'var(--warn)' : 'var(--bad)'} />}
                <span class="mono small">{x.share === null ? '' : `${Math.round(x.share * 100)}%`}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section class="card" style={{ marginTop: 'var(--space-4)' }} aria-labelledby="cat-h">
        <h2 id="cat-h">By category</h2>
        <div class="table-wrap" tabIndex={0} role="region" aria-label="Results by category">
          <table class="table">
            <caption class="visually-hidden">Accuracy and average score by alert category</caption>
            <thead>
              <tr>
                <th scope="col">Category</th>
                <th scope="col" class="num">
                  Cases
                </th>
                <th scope="col">Right calls</th>
                <th scope="col" class="num">
                  Avg score
                </th>
              </tr>
            </thead>
            <tbody>
              {cats
                .sort((x, y) => x.acc - y.acc)
                .map((x) => (
                  <tr>
                    <th scope="row" style={{ textTransform: 'none', letterSpacing: 0, color: 'var(--text)', fontWeight: 500 }}>
                      {CATEGORY_LABELS[x.c as Category]}
                    </th>
                    <td class="num mono">{x.n}</td>
                    <td style={{ minWidth: 160 }}>
                      <div class="row" style={{ flexWrap: 'nowrap' }}>
                        <Bar value={x.acc} label={`${Math.round(x.acc * 100)}% right calls`} color={x.acc >= 0.8 ? 'var(--ok)' : x.acc >= 0.55 ? 'var(--warn)' : 'var(--bad)'} />
                        <span class="mono small">{Math.round(x.acc * 100)}%</span>
                      </div>
                    </td>
                    <td class="num mono">{Math.round(x.avg)}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </section>

      <div class="grid grid-2" style={{ marginTop: 'var(--space-4)' }}>
        <section class="card" aria-labelledby="shifts-h">
          <h2 id="shifts-h">Shifts</h2>
          {shifts.length === 0 ? (
            <p class="muted small">No shifts yet.</p>
          ) : (
            <div class="table-wrap" tabIndex={0} role="region" aria-label="Recent shifts">
              <table class="table">
                <caption class="visually-hidden">Recent shifts</caption>
                <thead>
                  <tr>
                    <th scope="col">#</th>
                    <th scope="col" class="num">
                      Score
                    </th>
                    <th scope="col" class="num">
                      Handled
                    </th>
                    <th scope="col" class="num">
                      Missed
                    </th>
                    <th scope="col">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {shifts.map((s) => (
                    <tr>
                      <td class="mono">{s.number + 1}</td>
                      <td class="num mono">{s.score}</td>
                      <td class="num mono">
                        {s.handled}/{s.total}
                      </td>
                      <td class={`num mono${s.missedIncidents ? ' text-bad' : ''}`}>{s.missedIncidents}</td>
                      <td class="small">{duration(s.elapsedSec)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section class="card" aria-labelledby="hist-h">
          <h2 id="hist-h">Latest cases</h2>
          <div class="table-wrap" tabIndex={0} role="region" aria-label="Table of the latest graded cases">
            <table class="table">
              <caption class="visually-hidden">Latest graded cases</caption>
              <thead>
                <tr>
                  <th scope="col">Alert</th>
                  <th scope="col" class="num">
                    Score
                  </th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {[...a]
                  .reverse()
                  .slice(0, 12)
                  .map((x) => (
                    <tr>
                      <td class="small">
                        {templateById(x.templateId)?.title ?? x.templateId} {x.mode !== 'practice' && <span class="badge">{x.mode}</span>}
                      </td>
                      <td class={`num mono ${x.dispositionCorrect ? '' : 'text-bad'}`}>{x.percent}</td>
                      <td class="small faint nowrap">{ago(x.completedAt)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
        </>
      ) : (
        <p class="muted" style={{ marginTop: 'var(--space-4)' }}>
          No SOC cases yet.
        </p>
      )}

      {vuln.hasData && <VulnSection stats={vuln} />}
    </div>
  );
}
