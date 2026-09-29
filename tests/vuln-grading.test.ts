// WP1c: the vulnerability-management grader (DESIGN section 5, its "Clarified
// (WP1c)" notes and ADR-19). Cases are built by hand, so each test isolates one
// rule; the generated tier-3 fixture proves perfect = 100 and empty = 0 on a
// real corpus.
import { describe, expect, it } from 'vitest';
import { DIFFICULTY_MULTIPLIER } from '../src/core/grading/grade.ts';
import { DAY, HOUR } from '../src/core/logs/time.ts';
import { REASON_CODES, VULN_DECISIONS, VULN_SCHEDULES, type FindingTruth, type ReasonCode, type VulnDecision, type VulnSchedule } from '../src/core/vuln/model.ts';
import { buildVulnScenario, type ResolvedVulnCase, type ResolvedVulnFinding } from '../src/core/vuln/scenario.ts';
import { emptyVulnSubmission, gradeVulnCase, perfectVulnSubmission, VULN_MAX_SCORE, VULN_POINTS, type VulnFindingAnswer, type VulnGrade, type VulnSubmission } from '../src/core/vuln/grade.ts';
import { world } from './helpers/scenario-check.ts';
import { fixtureTier3, FIXTURE_TEMPLATE_ID } from './helpers/vuln-fixture.ts';

// ---- builders -----------------------------------------------------------------

const NOW = Date.parse('2026-09-23T13:20:00Z');

function calendar(capacityPerWindow: number): ResolvedVulnCase['constraints'] {
  return {
    windows: [
      { id: 'next', label: 'Next change window', start: NOW + 6 * DAY, end: NOW + 6 * DAY + 4 * HOUR },
      { id: 'cycle', label: 'Standard patch cycle', start: NOW + 20 * DAY, end: NOW + 20 * DAY + 4 * HOUR },
    ],
    slaDays: { critical: 3, high: 14, medium: 30, low: 90 },
    capacityPerWindow,
  };
}

function finding(findingId: string, truth: Partial<FindingTruth> = {}, over: Partial<ResolvedVulnFinding> = {}): ResolvedVulnFinding {
  return { findingId, recordId: `VF-${findingId}`, truth: { decision: 'patch', schedule: 'next-window', reasons: [], ...truth }, weight: 1, mustNotMiss: false, evidence: [], ...over };
}

const point = (id: string, ...recordIds: string[]) => ({ id, label: `Point ${id}`, why: `Why ${id}`, recordIds });

function vcase(findings: ResolvedVulnFinding[], over: Partial<ResolvedVulnCase> = {}): ResolvedVulnCase {
  return {
    id: 'vm-unit~1',
    templateId: 'vm-unit',
    seed: '1',
    difficulty: 'tier2',
    title: 'Unit',
    lesson: 'Unit lesson',
    cysaDomains: ['2.0'],
    objectives: ['2.3'],
    kind: 'vuln',
    now: new Date(NOW).toISOString(),
    briefing: 'Unit briefing',
    attachments: [],
    findings,
    constraints: calendar(3),
    idealOrder: [],
    tiers: [],
    hints: ['h1', 'h2', 'h3'],
    solution: [],
    rubric: [{ id: 'note', text: 'Names the exploited one', keywords: ['known exploited', 'emergency'] }],
    explanation: ['e'],
    pitfalls: ['p'],
    references: [],
    ...over,
  };
}

const answer = (over: Partial<VulnFindingAnswer> = {}): VulnFindingAnswer => ({ decision: null, control: null, schedule: null, reasons: [], ...over });

function submit(answers: Record<string, Partial<VulnFindingAnswer>> = {}, over: Partial<VulnSubmission> = {}): VulnSubmission {
  return { ...emptyVulnSubmission(), answers: Object.fromEntries(Object.entries(answers).map(([id, a]) => [id, answer(a)])), ...over };
}

const part = (g: VulnGrade, id: string) => g.components.find((x) => x.id === id)!;
const earned = (g: VulnGrade, id: string) => part(g, id).earned;
const round1 = (x: number) => Math.round(x * 10) / 10;

// One finding, one answer: the finding's grade (and the whole grade).
function gradeOne(truth: Partial<FindingTruth>, given: Partial<VulnFindingAnswer>, over: Partial<ResolvedVulnFinding> = {}) {
  const g = gradeVulnCase(vcase([finding('F', truth, over)]), submit({ F: given }));
  return { g, f: g.findings[0] };
}

// An independent nDCG (gain p / log2(pos + 2), unranked earns nothing) for
// [relevance, position] pairs, to check the grader against.
function ndcgOf(items: [number, number | null][]): number {
  const ideal = items.map(([r]) => r).sort((a, b) => b - a).reduce((s, r, i) => s + r / Math.log2(i + 2), 0);
  return items.reduce((s, [r, p]) => s + (p === null ? 0 : r / Math.log2(p + 2)), 0) / ideal;
}

// Every ordering of the items (n! of them; only used for n <= 6).
function permutations<T>(items: T[]): T[][] {
  return items.length <= 1 ? [items] : items.flatMap((x, i) => permutations([...items.slice(0, i), ...items.slice(i + 1)]).map((rest) => [x, ...rest]));
}

// A perfect grade says so in every component; the ordering sentence must not
// depend on the last bit of the nDCG sum.
function expectPerfectDetails(g: VulnGrade): void {
  for (const x of g.components) {
    if (x.id === 'evidence') expect(x.detail).toMatch(/^(\d+) of \1 evidence points pinned\.$/);
    else expect(x.detail, x.id).toMatch(/^Correct — /);
  }
}

function deepFreeze<T>(x: T): T {
  if (x !== null && typeof x === 'object' && !Object.isFrozen(x)) {
    Object.freeze(x);
    for (const v of Object.values(x)) deepFreeze(v);
  }
  return x;
}

// ---- DESIGN 5.6 ---------------------------------------------------------------

// The worked example: case vm-kev-internal, four findings, sum of weights 6.
function example(): ResolvedVulnCase {
  return vcase(
    [
      finding('F1', { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['known-exploited', 'public-exploit'] }, { weight: 3, mustNotMiss: true, evidence: [point('kev', 'REC-KEV')] }),
      finding('F2', { decision: 'patch', schedule: 'standard-cycle', reasons: ['low-exploitability'] }),
      finding('F3', { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'] }, { evidence: [point('patched', 'REC-PATCH')] }),
      finding('F4', { decision: 'patch', schedule: 'next-window', reasons: ['low-exploitability'] }, { evidence: [point('epss', 'REC-DEVICE')] }),
    ],
    { difficulty: 'tier1', tiers: [['F1'], ['F4'], ['F2']], idealOrder: ['F1', 'F4', 'F2', 'F3'], hints: ['h1', 'h2'], constraints: calendar(3) },
  );
}

// The analyst who sorts by CVSS: patches everything, F1 next window, F3 scheduled, F3 first.
function sortByCvss(): VulnSubmission {
  return submit(
    {
      F1: { decision: 'patch', schedule: 'next-window' },
      F2: { decision: 'patch', schedule: 'standard-cycle' },
      F3: { decision: 'patch', schedule: 'next-window' },
      F4: { decision: 'patch', schedule: 'next-window' },
    },
    { order: ['F3', 'F1', 'F4', 'F2'], pins: ['REC-KEV'] },
  );
}

describe('DESIGN 5.6 worked examples', () => {
  const c = example();

  it('perfect scores 100 with every component full', () => {
    const g = gradeVulnCase(c, perfectVulnSubmission(c));
    expect(g.score).toBe(100);
    expect(g.percent).toBe(100);
    expect(g.max).toBe(100);
    expect(g.components.map((x) => [x.id, x.earned, x.possible, x.ok])).toEqual([
      ['decisions', 40, 40, true],
      ['ordering', 20, 20, true],
      ['schedule', 10, 10, true],
      ['justification', 15, 15, true],
      ['evidence', 15, 15, true],
    ]);
    expect(g.ndcg).toBeCloseTo(1, 12);
    expect(g.mustNotMiss).toEqual({ dismissed: [], outsideTopK: [], decisionPenalty: 0, orderingPenalty: 0 });
    expect(g.overflow).toEqual([]);
    expect(g.findings.map((f) => [f.decision.verdict, f.schedule.verdict])).toEqual(Array(4).fill(['exact', 'exact']));
    expectPerfectDetails(g);
  });

  it('the sort-by-CVSS analyst scores 57.3', () => {
    const g = gradeVulnCase(c, sortByCvss());
    expect(earned(g, 'decisions')).toBe(33.3);
    expect(g.ndcg).toBeCloseTo(0.698, 3);
    expect(earned(g, 'ordering')).toBe(14);
    expect(earned(g, 'schedule')).toBe(5);
    expect(earned(g, 'justification')).toBe(0);
    expect(earned(g, 'evidence')).toBe(5);
    expect(g.score).toBeCloseTo(57.3, 1);
    expect(Math.abs(g.score - 57.3)).toBeLessThanOrEqual(0.5);
    expect(g.percent).toBe(57);
    // F1 is in the top two places, so no must-not-miss penalty; three windows are in use, within the capacity of 3.
    expect(g.mustNotMiss).toEqual({ dismissed: [], outsideTopK: [], decisionPenalty: 0, orderingPenalty: 0 });
    expect(g.overflow).toEqual([]);
    expect(g.findings.map((f) => f.decision.verdict)).toEqual(['exact', 'exact', 'wrong', 'exact']);
    expect(g.findings.map((f) => f.schedule.verdict)).toEqual(['sla-breach', 'exact', 'wrong', 'exact']);
    expect(g.findings.map((f) => f.position)).toEqual([1, 3, 0, 2]);
    expect(g.findings.map((f) => f.relevance)).toEqual([3, 1, 0, 2]);
    expect(g.components.map((x) => x.detail)).toEqual([
      '3 of 4 decided right; 1 wrong.',
      'Your order earned 69% of the ideal urgency score.', // 0.698, rounded down: 100% is kept for a perfect order
      '2 of 4 scheduled right; 1 later than the SLA allows; 1 wrong.',
      '0 of 4 findings fully justified.',
      '1 of 3 evidence points pinned.',
    ]);
  });

  it('dismissing F1 as a false positive: decisions exactly 15, must-not-miss ordering penalty exactly 4', () => {
    const g = gradeVulnCase(
      c,
      submit({ F1: { decision: 'false-positive' }, F2: { decision: 'patch' }, F3: { decision: 'false-positive' }, F4: { decision: 'patch' } }, { order: ['F4', 'F2'] }),
    );
    expect(earned(g, 'decisions')).toBe(15); // 40 * 3/6 - 5
    expect(g.mustNotMiss).toEqual({ dismissed: ['F1'], outsideTopK: ['F1'], decisionPenalty: 5, orderingPenalty: 4 });
    expect(g.findings[0].decision).toEqual({ given: 'false-positive', truth: 'patch', credit: 0, verdict: 'wrong' });
    // Ordering: 20 x nDCG of [F4, F2] with F1 left out, less the 4 points.
    const ndcg = ndcgOf([[3, null], [2, 0], [1, 1], [0, null]]);
    expect(g.ndcg).toBeCloseTo(ndcg, 12);
    expect(earned(g, 'ordering')).toBe(round1(20 * ndcg - 4));
    expect(earned(g, 'ordering')).toBe(7.1);
    expect(part(g, 'decisions').detail).toBe('3 of 4 decided right; 1 wrong; 1 real must-not-miss finding dismissed as false positive (−5).');
    expect(part(g, 'ordering').detail).toBe('Your order earned 55% of the ideal urgency score; 1 must-not-miss finding outside the top 2 (−4).');
  });

  it('an empty submission scores 0', () => {
    const g = gradeVulnCase(c, emptyVulnSubmission());
    expect(g.score).toBe(0);
    expect(g.percent).toBe(0);
    expect(g.components.map((x) => x.earned)).toEqual([0, 0, 0, 0, 0]);
    expect(g.xp).toBe(0);
  });
});

describe('perfect and empty on the generated tier-3 fixture', () => {
  it.each(['grade-a', 'grade-b', 'grade-c'])('scores 100 and 0 (seed %s)', (seed) => {
    const s = buildVulnScenario({ worldSeed: 'vuln-grade-world', templateId: FIXTURE_TEMPLATE_ID, seed, world: world('vuln-grade-world'), template: fixtureTier3 });
    const perfect = gradeVulnCase(s.case, perfectVulnSubmission(s.case));
    expect(perfect.score, JSON.stringify(perfect.components.filter((x) => !x.ok))).toBe(100);
    expect(perfect.components.every((x) => x.ok)).toBe(true);
    expectPerfectDetails(perfect);
    expect(gradeVulnCase(s.case, emptyVulnSubmission()).score).toBe(0);
    expect(s.case.findings.length).toBeGreaterThanOrEqual(5);
  });

  it('builds the perfect submission from the truth', () => {
    const c = vcase(
      [
        finding('A', { decision: 'mitigate', schedule: 'next-window', mitigation: ['CTL-1', 'CTL-2'], reasons: ['compensating-control-verified'] }, { evidence: [point('a1', 'R1', 'R2'), point('a2', 'R3')] }),
        finding('B', { decision: 'patch', schedule: 'emergency', mitigation: ['CTL-9'], reasons: ['known-exploited', 'public-exploit', 'internet-exposed', 'critical-asset'] }, { evidence: [point('b1', 'R3', 'R4')] }),
        finding('C', { decision: 'mitigate', schedule: 'standard-cycle', reasons: [] }),
      ],
      { idealOrder: ['B', 'A'], tiers: [['B'], ['A']] },
    );
    const p = perfectVulnSubmission(c);
    expect(p.answers.A).toEqual({ decision: 'mitigate', control: 'CTL-1', schedule: 'next-window', reasons: ['compensating-control-verified'] });
    expect(p.answers.B).toEqual({ decision: 'patch', control: null, schedule: 'emergency', reasons: ['known-exploited', 'public-exploit', 'internet-exposed'] });
    expect(p.answers.C.control).toBeNull(); // mitigate with no list of controls: nothing to name
    expect(p.order).toEqual(['B', 'A']);
    expect(p.order).not.toBe(c.idealOrder);
    expect(p.pins).toEqual(['R1', 'R3']); // first row of every point, repeats dropped
    expect(p.notes).toBe('');
    expect(p.hintsUsed).toBe(0);
    expect(emptyVulnSubmission()).toEqual({ answers: {}, order: [], pins: [], notes: '', hintsUsed: 0 });
  });

  it('scores 100 when the truth lists a reason code twice: the first three distinct codes are answered', () => {
    // Taking the first three entries would answer known-exploited twice, and the grader counts it once.
    const c = vcase([finding('A', { reasons: ['known-exploited', 'known-exploited', 'public-exploit', 'internet-exposed'] }, { evidence: [point('a', 'R1')] })], { tiers: [['A']], idealOrder: ['A'] });
    const p = perfectVulnSubmission(c);
    expect(p.answers.A.reasons).toEqual(['known-exploited', 'public-exploit', 'internet-exposed']);
    const g = gradeVulnCase(c, p);
    expect(g.findings[0].reasons.credit).toBe(1);
    expect(g.score).toBe(100);
    expectPerfectDetails(g);
  });

  it('pins nothing for an evidence point that has no row, so a pin is never undefined', () => {
    const c = vcase([
      finding('A', {}, { evidence: [point('empty'), point('a', 'R1', 'R2')] }),
      finding('B', {}, { evidence: [point('only-empty')] }),
      finding('C', {}, { evidence: [point('c', 'R1'), point('c2', 'R3')] }),
    ]);
    const p = perfectVulnSubmission(c);
    expect(p.pins).toEqual(['R1', 'R3']);
    expect(p.pins.every((pin) => typeof pin === 'string')).toBe(true);
    expect(gradeVulnCase(c, p).irrelevantPins).toBe(0); // an undefined pin would count as one
  });
});

// ---- decisions (DESIGN 5.1) -----------------------------------------------------

describe('decisions', () => {
  // truth (row) x given (column). `mitigate` is always given with a control
  // that covers the path, so the control never decides these cells.
  const MATRIX: Record<VulnDecision, Record<VulnDecision, 0 | 0.5 | 1>> = {
    patch: { patch: 1, mitigate: 0.5, avoid: 0, accept: 0, transfer: 0, 'false-positive': 0 },
    mitigate: { patch: 0.5, mitigate: 1, avoid: 0, accept: 0.5, transfer: 0, 'false-positive': 0 },
    avoid: { patch: 0.5, mitigate: 0, avoid: 1, accept: 0, transfer: 0, 'false-positive': 0 },
    accept: { patch: 0, mitigate: 0.5, avoid: 0, accept: 1, transfer: 0.5, 'false-positive': 0 },
    transfer: { patch: 0, mitigate: 0, avoid: 0, accept: 0.5, transfer: 1, 'false-positive': 0 },
    'false-positive': { patch: 0, mitigate: 0, avoid: 0, accept: 0, transfer: 0, 'false-positive': 1 },
  };
  const pairs = VULN_DECISIONS.flatMap((truth) => VULN_DECISIONS.map((given): [VulnDecision, VulnDecision, number] => [truth, given, MATRIX[truth][given]]));

  it('has one cell per truth x given pair', () => {
    expect(pairs).toHaveLength(36);
  });

  it.each(pairs)('truth %s, given %s: credit %s', (truth, given, credit) => {
    const { f } = gradeOne({ decision: truth, mitigation: ['CTL-OK'] }, { decision: given, control: given === 'mitigate' ? 'CTL-OK' : null });
    expect(f.decision).toEqual({ given, truth, credit, verdict: credit === 1 ? 'exact' : credit === 0.5 ? 'near-miss' : 'wrong' });
  });

  it('is asymmetric for avoid: avoid -> patch is a near miss, patch -> avoid is not', () => {
    expect(gradeOne({ decision: 'avoid' }, { decision: 'patch' }).f.decision.credit).toBe(0.5);
    expect(gradeOne({ decision: 'patch' }, { decision: 'avoid' }).f.decision.credit).toBe(0);
  });

  it('scores an unanswered finding 0 ("missing")', () => {
    const { f } = gradeOne({ decision: 'patch' }, {});
    expect(f.decision).toEqual({ given: null, truth: 'patch', credit: 0, verdict: 'missing' });
  });

  it('needs a covering control for mitigate: the wrong or a missing control is half credit', () => {
    const truth = { decision: 'mitigate' as const, mitigation: ['CTL-A', 'CTL-B'] };
    const grade = (control: string | null) => gradeOne(truth, { decision: 'mitigate', control }).f.decision;
    expect(grade('CTL-A')).toEqual({ given: 'mitigate', truth: 'mitigate', credit: 1, verdict: 'exact' });
    expect(grade('CTL-B').credit).toBe(1); // any control on the list will do
    expect(grade('CTL-X')).toEqual({ given: 'mitigate', truth: 'mitigate', credit: 0.5, verdict: 'wrong-control' });
    expect(grade(null)).toEqual({ given: 'mitigate', truth: 'mitigate', credit: 0.5, verdict: 'wrong-control' });
    // A template that lists no controls leaves nothing that could be right.
    expect(gradeOne({ decision: 'mitigate' }, { decision: 'mitigate', control: 'CTL-A' }).f.decision.verdict).toBe('wrong-control');
  });

  it('gives the patch -> mitigate near miss only with a control that covers the path', () => {
    const truth = { decision: 'patch' as const, mitigation: ['CTL-A'] };
    const grade = (control: string | null) => gradeOne(truth, { decision: 'mitigate', control }).f.decision;
    expect(grade('CTL-A')).toEqual({ given: 'mitigate', truth: 'patch', credit: 0.5, verdict: 'near-miss' });
    expect(grade('CTL-X')).toEqual({ given: 'mitigate', truth: 'patch', credit: 0, verdict: 'wrong' });
    expect(grade(null)).toEqual({ given: 'mitigate', truth: 'patch', credit: 0, verdict: 'wrong' });
    expect(gradeOne({ decision: 'patch' }, { decision: 'mitigate', control: 'CTL-A' }).f.decision.credit).toBe(0);
  });

  it('does not look at the control for accept -> mitigate, or for any decision but mitigate', () => {
    expect(gradeOne({ decision: 'accept', mitigation: ['CTL-A'] }, { decision: 'mitigate', control: 'CTL-X' }).f.decision.credit).toBe(0.5);
    expect(gradeOne({ decision: 'accept' }, { decision: 'mitigate', control: null }).f.decision.credit).toBe(0.5);
    expect(gradeOne({ decision: 'patch' }, { decision: 'patch', control: 'CTL-X' }).f.decision.credit).toBe(1);
    expect(gradeOne({ decision: 'mitigate', mitigation: ['CTL-A'] }, { decision: 'patch', control: 'CTL-X' }).f.decision.credit).toBe(0.5);
  });

  it('accepts alsoAccept at full credit, an also-accepted mitigate still needs its control', () => {
    const t = { decision: 'patch' as const, alsoAccept: ['mitigate' as const, 'avoid' as const], mitigation: ['CTL-A'] };
    expect(gradeOne(t, { decision: 'mitigate', control: 'CTL-A' }).f.decision).toEqual({ given: 'mitigate', truth: 'patch', credit: 1, verdict: 'also-accepted' });
    // Rule b comes before the near miss: the wrong control is half credit (not the 0 of a non-covering patch -> mitigate).
    expect(gradeOne(t, { decision: 'mitigate', control: 'CTL-X' }).f.decision).toEqual({ given: 'mitigate', truth: 'patch', credit: 0.5, verdict: 'wrong-control' });
    expect(gradeOne(t, { decision: 'mitigate', control: null }).f.decision.verdict).toBe('wrong-control');
    expect(gradeOne(t, { decision: 'avoid' }).f.decision).toEqual({ given: 'avoid', truth: 'patch', credit: 1, verdict: 'also-accepted' });
    expect(gradeOne(t, { decision: 'patch' }).f.decision.verdict).toBe('exact');
    expect(gradeOne(t, { decision: 'accept' }).f.decision.credit).toBe(0);
    expect(gradeOne({ decision: 'accept', alsoAccept: ['transfer'] }, { decision: 'transfer' }).f.decision.verdict).toBe('also-accepted');
  });

  it('weights findings: 40 x sum(w x credit) / sum(w)', () => {
    const c = vcase([finding('A', { mitigation: ['CTL'] }, { weight: 3 }), finding('B', {}, { weight: 1 })]);
    expect(earned(gradeVulnCase(c, submit({ A: { decision: 'patch' }, B: { decision: 'accept' } })), 'decisions')).toBe(30);
    expect(earned(gradeVulnCase(c, submit({ A: { decision: 'accept' }, B: { decision: 'patch' } })), 'decisions')).toBe(10);
    // A half-credit near miss on the heavy finding: 40 x (3 x 0.5 + 1) / 4.
    expect(earned(gradeVulnCase(c, submit({ A: { decision: 'mitigate', control: 'CTL' }, B: { decision: 'patch' } })), 'decisions')).toBe(25);
  });

  it('scores 0 rather than NaN when the weights sum to 0', () => {
    const c = vcase([finding('A', {}, { weight: 0 })], { tiers: [['A']], idealOrder: ['A'] });
    const g = gradeVulnCase(c, perfectVulnSubmission(c));
    expect(earned(g, 'decisions')).toBe(0);
    expect(earned(g, 'justification')).toBe(0);
    expect(Number.isFinite(g.score)).toBe(true);
  });
});

describe('false positive on a must-not-miss finding (DESIGN 5.1)', () => {
  // Three must-not-miss findings and seven ordinary ones, all weight 1, all patch.
  const ids = ['M1', 'M2', 'M3', 'P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7'];
  const c = vcase(ids.map((id) => finding(id, {}, { mustNotMiss: id.startsWith('M') })));
  const grade = (given: Record<string, VulnDecision>) => gradeVulnCase(c, submit(Object.fromEntries(ids.map((id) => [id, { decision: given[id] ?? 'patch' }]))));

  it('takes 5 for one, 10 for two, and stops at 10 for three', () => {
    const one = grade({ M1: 'false-positive' });
    const two = grade({ M1: 'false-positive', M2: 'false-positive' });
    const three = grade({ M1: 'false-positive', M2: 'false-positive', M3: 'false-positive' });
    expect(earned(grade({}), 'decisions')).toBe(40);
    expect(earned(one, 'decisions')).toBe(31); // 36 - 5
    expect(earned(two, 'decisions')).toBe(22); // 32 - 10
    expect(earned(three, 'decisions')).toBe(18); // 28 - 10, not 28 - 15
    expect([one, two, three].map((g) => g.mustNotMiss.decisionPenalty)).toEqual([5, 10, 10]);
    expect(three.mustNotMiss.dismissed).toEqual(['M1', 'M2', 'M3']);
  });

  it('applies only to a real must-not-miss finding given false-positive', () => {
    // An ordinary finding dismissed: credit lost, no penalty.
    const ordinary = grade({ P1: 'false-positive' });
    expect(earned(ordinary, 'decisions')).toBe(36);
    expect(ordinary.mustNotMiss.dismissed).toEqual([]);
    // Any other wrong answer on a must-not-miss finding, accept included: credit lost, no penalty.
    const accept = grade({ M1: 'accept' });
    expect(earned(accept, 'decisions')).toBe(36);
    expect(accept.mustNotMiss).toMatchObject({ dismissed: [], decisionPenalty: 0 });
    // A must-not-miss finding whose truth is itself a false positive: full credit, no penalty.
    const fp = vcase([finding('M1', { decision: 'false-positive' }, { mustNotMiss: true }), finding('P1')]);
    const g = gradeVulnCase(fp, submit({ M1: { decision: 'false-positive' }, P1: { decision: 'patch' } }));
    expect(earned(g, 'decisions')).toBe(40);
    expect(g.mustNotMiss.dismissed).toEqual([]);
  });

  it('cannot take the component below 0', () => {
    const only = vcase([finding('M1', {}, { mustNotMiss: true })]);
    const g = gradeVulnCase(only, submit({ M1: { decision: 'false-positive' } }));
    expect(earned(g, 'decisions')).toBe(0);
    expect(g.mustNotMiss.decisionPenalty).toBe(5);
  });
});

// ---- schedule (DESIGN 5.3) --------------------------------------------------------

describe('schedule', () => {
  const grade = (truth: VulnSchedule, given: VulnSchedule | null, slaLatest?: VulnSchedule) => gradeOne({ schedule: truth, slaLatest }, { schedule: given }).f.schedule;

  // truth (row) x given (column), no SLA limit: exact 1; an emergency change
  // that was not needed 0.5 whatever the truth; otherwise one step 0.5.
  const MATRIX: Record<VulnSchedule, Record<VulnSchedule, [number, string]>> = {
    emergency: { emergency: [1, 'exact'], 'next-window': [0.5, 'one-step'], 'standard-cycle': [0, 'wrong'], none: [0, 'wrong'] },
    'next-window': { emergency: [0.5, 'emergency-unjustified'], 'next-window': [1, 'exact'], 'standard-cycle': [0.5, 'one-step'], none: [0, 'wrong'] },
    'standard-cycle': { emergency: [0.5, 'emergency-unjustified'], 'next-window': [0.5, 'one-step'], 'standard-cycle': [1, 'exact'], none: [0.5, 'one-step'] },
    none: { emergency: [0.5, 'emergency-unjustified'], 'next-window': [0, 'wrong'], 'standard-cycle': [0.5, 'one-step'], none: [1, 'exact'] },
  };
  const pairs = VULN_SCHEDULES.flatMap((truth) => VULN_SCHEDULES.map((given): [VulnSchedule, VulnSchedule, number, string] => [truth, given, ...MATRIX[truth][given]]));

  it.each(pairs)('truth %s, given %s: credit %s (%s)', (truth, given, credit, verdict) => {
    expect(grade(truth, given)).toEqual({ given, truth, credit, verdict });
  });

  it('rule a: not set is 0', () => {
    expect(grade('next-window', null)).toEqual({ given: null, truth: 'next-window', credit: 0, verdict: 'missing' });
  });

  it('rule b: later than the SLA allows is 0 whatever the distance', () => {
    // One step late: half credit within the SLA, nothing past it.
    expect(grade('next-window', 'standard-cycle', 'standard-cycle')).toMatchObject({ credit: 0.5, verdict: 'one-step' });
    expect(grade('next-window', 'standard-cycle', 'next-window')).toMatchObject({ credit: 0, verdict: 'sla-breach' });
    expect(grade('standard-cycle', 'none', 'standard-cycle')).toMatchObject({ credit: 0, verdict: 'sla-breach' });
    // Two and three steps late.
    expect(grade('emergency', 'standard-cycle', 'next-window')).toMatchObject({ credit: 0, verdict: 'sla-breach' });
    expect(grade('emergency', 'none', 'emergency')).toMatchObject({ credit: 0, verdict: 'sla-breach' });
    // On the limit is fine; earlier than the limit is not a breach.
    expect(grade('next-window', 'next-window', 'next-window')).toMatchObject({ credit: 1, verdict: 'exact' });
    expect(grade('standard-cycle', 'emergency', 'standard-cycle')).toMatchObject({ credit: 0.5, verdict: 'emergency-unjustified' });
    // Without a limit the same late choice is only a step off.
    expect(grade('next-window', 'standard-cycle')).toMatchObject({ credit: 0.5, verdict: 'one-step' });
    // The SLA check comes before an exact match: a truth later than its own limit cannot score.
    expect(grade('standard-cycle', 'standard-cycle', 'next-window')).toMatchObject({ credit: 0, verdict: 'sla-breach' });
  });

  it('rule b: a null limit is not set, like an absent one', () => {
    // A stored case can hold null where the type says "absent"; that must not read as a limit earlier than every choice.
    const gradeNull = (truth: VulnSchedule, given: VulnSchedule) => gradeOne({ schedule: truth, slaLatest: null } as unknown as Partial<FindingTruth>, { schedule: given }).f.schedule;
    expect(gradeNull('next-window', 'standard-cycle')).toEqual({ given: 'standard-cycle', truth: 'next-window', credit: 0.5, verdict: 'one-step' });
    expect(gradeNull('next-window', 'next-window')).toMatchObject({ credit: 1, verdict: 'exact' });
    expect(gradeNull('emergency', 'none')).toMatchObject({ credit: 0, verdict: 'wrong' }); // not a breach
    for (const truth of VULN_SCHEDULES) for (const given of VULN_SCHEDULES) expect(gradeNull(truth, given), `${truth} / ${given}`).toEqual(grade(truth, given));
  });

  it('rule d: an emergency change nobody needed is half credit, two and three steps early included', () => {
    expect(grade('standard-cycle', 'emergency')).toMatchObject({ credit: 0.5, verdict: 'emergency-unjustified' });
    expect(grade('none', 'emergency')).toMatchObject({ credit: 0.5, verdict: 'emergency-unjustified' });
  });

  it('rule e: anything but an emergency is graded by distance; next-window on a false positive is 0', () => {
    const { f } = gradeOne({ decision: 'false-positive', schedule: 'none' }, { decision: 'false-positive', schedule: 'next-window' });
    expect(f.schedule).toEqual({ given: 'next-window', truth: 'none', credit: 0, verdict: 'wrong' });
    expect(grade('none', 'standard-cycle')).toMatchObject({ credit: 0.5, verdict: 'one-step' });
  });

  it('is an unweighted mean over all findings', () => {
    const c = vcase([finding('A', {}, { weight: 3 }), finding('B', {}, { weight: 1 }), finding('C'), finding('D')]);
    // A exact, the others not set: 10 x 1/4 whatever A's weight.
    expect(earned(gradeVulnCase(c, submit({ A: { schedule: 'next-window' } })), 'schedule')).toBe(2.5);
    expect(earned(gradeVulnCase(c, submit({ B: { schedule: 'next-window' } })), 'schedule')).toBe(2.5);
  });
});

describe('schedule capacity', () => {
  const four = (tiers: string[][], capacity: number) =>
    vcase(['A', 'B', 'C', 'D'].map((id) => finding(id)), { tiers, constraints: calendar(capacity) });
  const allNextWindow = Object.fromEntries(['A', 'B', 'C', 'D'].map((id) => [id, { decision: 'patch' as const, schedule: 'next-window' as const }]));

  it('zeroes the lowest-relevance assignments first, even when their schedule was right', () => {
    const c = four([['A'], ['B'], ['C']], 2); // D is in no tier
    const g = gradeVulnCase(c, submit(allNextWindow, { order: ['A', 'B', 'C', 'D'] }));
    expect(g.overflow).toEqual(['D', 'C']);
    expect(g.findings.map((f) => f.schedule.verdict)).toEqual(['exact', 'exact', 'overflow', 'overflow']);
    expect(g.findings.map((f) => f.schedule.credit)).toEqual([1, 1, 0, 0]);
    expect(earned(g, 'schedule')).toBe(5);
  });

  it('breaks a tie in relevance by the learner\'s order: the lower-ranked one overflows', () => {
    const c = four([['A', 'B', 'C', 'D']], 2);
    const g = gradeVulnCase(c, submit(allNextWindow, { order: ['B', 'D', 'A', 'C'] }));
    expect(g.overflow).toEqual(['C', 'A']); // positions 3 and 2
    expect(g.findings.map((f) => f.schedule.verdict)).toEqual(['overflow', 'exact', 'overflow', 'exact']);
  });

  it('counts an unranked finding as lower than every ranked one, then the later finding in case order', () => {
    const c = four([['A', 'B', 'C', 'D']], 2);
    const g = gradeVulnCase(c, submit(allNextWindow, { order: ['A', 'B'] }));
    expect(g.overflow).toEqual(['D', 'C']); // C and D are unranked; D is later in the case
    expect(gradeVulnCase(four([['A', 'B', 'C', 'D']], 3), submit(allNextWindow, { order: ['A', 'B'] })).overflow).toEqual(['D']);
    // All three levels at once: capacity 1 leaves the best-ranked finding only.
    const mixed = gradeVulnCase(four([['A', 'B', 'C', 'D']], 1), submit(allNextWindow, { order: ['A', 'C'] }));
    expect(mixed.overflow).toEqual(['D', 'B', 'C']); // unranked D, B (later first), then ranked C; A survives
  });

  it('does not count a full window, or any schedule but emergency and next window', () => {
    const c = four([['A', 'B', 'C', 'D']], 2);
    const atCapacity = gradeVulnCase(c, submit({ A: { schedule: 'emergency' }, B: { schedule: 'next-window' }, C: { schedule: 'standard-cycle' }, D: { schedule: 'none' } }));
    expect(atCapacity.overflow).toEqual([]);
    const over = gradeVulnCase(c, submit({ A: { schedule: 'emergency' }, B: { schedule: 'next-window' }, C: { schedule: 'emergency' }, D: { schedule: 'none' } }, { order: ['A', 'B', 'C'] }));
    expect(over.overflow).toEqual(['C']); // emergency and next-window share the capacity
  });

  it('keeps the verdict of a finding that already scored 0, a breach or a wrong answer, and still lists it as overflow', () => {
    const c = vcase([finding('A'), finding('B', { schedule: 'emergency', slaLatest: 'emergency' }), finding('C', { schedule: 'none' })], { constraints: calendar(1), tiers: [['A'], ['B'], ['C']] });
    const submission = submit({ A: { schedule: 'next-window' }, B: { schedule: 'next-window' }, C: { schedule: 'next-window' } }, { order: ['A', 'B', 'C'] });
    // Before capacity: A exact, B a breach of its SLA, C wrong.
    const before = gradeVulnCase({ ...c, constraints: calendar(3) }, submission);
    expect(before.findings.map((f) => f.schedule.verdict)).toEqual(['exact', 'sla-breach', 'wrong']);
    expect(before.overflow).toEqual([]);
    // Capacity 1 sends B and C over; they had no credit to lose, so "overflow" would only hide why.
    const g = gradeVulnCase(c, submission);
    expect(g.overflow).toEqual(['C', 'B']);
    expect(g.findings.map((f) => f.schedule.verdict)).toEqual(['exact', 'sla-breach', 'wrong']);
    expect(g.findings.map((f) => f.schedule.credit)).toEqual([1, 0, 0]);
    expect(earned(g, 'schedule')).toBe(3.3);
    expect(part(g, 'schedule').detail).toBe('1 of 3 scheduled right; 1 later than the SLA allows; 1 wrong.');
  });

  it('says "overflow" for a finding whose credit capacity took away, half credit included', () => {
    // A is exact, B one step off (half credit), C an emergency change nobody needed (half credit); capacity 1 keeps A only.
    const c = vcase([finding('A'), finding('B', { schedule: 'standard-cycle' }), finding('C')], { constraints: calendar(1), tiers: [['A'], ['B'], ['C']] });
    const submission = submit({ A: { schedule: 'next-window' }, B: { schedule: 'next-window' }, C: { schedule: 'emergency' } }, { order: ['A', 'B', 'C'] });
    expect(gradeVulnCase({ ...c, constraints: calendar(3) }, submission).findings.map((f) => [f.schedule.verdict, f.schedule.credit])).toEqual([['exact', 1], ['one-step', 0.5], ['emergency-unjustified', 0.5]]);
    const g = gradeVulnCase(c, submission);
    expect(g.overflow).toEqual(['C', 'B']);
    expect(g.findings.map((f) => [f.schedule.verdict, f.schedule.credit])).toEqual([['exact', 1], ['overflow', 0], ['overflow', 0]]);
    expect(earned(g, 'schedule')).toBe(3.3);
    expect(part(g, 'schedule').detail).toBe('1 of 3 scheduled right; 2 over the capacity of 1 per window.');
  });

  it('puts relevance before the learner\'s order: the less urgent finding overflows even when it was ranked first', () => {
    // A is tier 1, B tier 2, but B was put first. Rank only breaks a tie in relevance.
    const c = vcase([finding('A'), finding('B')], { tiers: [['A'], ['B']], constraints: calendar(1) });
    const g = gradeVulnCase(c, submit({ A: { schedule: 'next-window' }, B: { schedule: 'next-window' } }, { order: ['B', 'A'] }));
    expect(g.findings.map((f) => f.position)).toEqual([1, 0]);
    expect(g.overflow).toEqual(['B']);
    expect(g.findings.map((f) => f.schedule.verdict)).toEqual(['exact', 'overflow']);
    expect(earned(g, 'schedule')).toBe(5);
  });
});

// ---- ordering (DESIGN 5.2) ------------------------------------------------------------

describe('ordering', () => {
  // A and B are tier 1, C tier 2, D tier 3, E is in no tier.
  const c = vcase(['A', 'B', 'C', 'D', 'E'].map((id) => finding(id)), { tiers: [['A', 'B'], ['C'], ['D']], idealOrder: ['A', 'B', 'C', 'D', 'E'] });
  const ordering = (order: string[]) => gradeVulnCase(c, submit({}, { order }));

  it('scores 20 x nDCG, and ties inside a tier are free', () => {
    expect(earned(ordering(['A', 'B', 'C', 'D']), 'ordering')).toBe(20);
    expect(earned(ordering(['B', 'A', 'C', 'D']), 'ordering')).toBe(20);
    const reversed = ordering(['D', 'C', 'B', 'A']);
    const ndcg = ndcgOf([[3, 3], [3, 2], [2, 1], [1, 0], [0, null]]);
    expect(reversed.ndcg).toBeCloseTo(ndcg, 12);
    expect(earned(reversed, 'ordering')).toBe(round1(20 * ndcg));
    expect(ndcg).toBeLessThan(1);
  });

  it('costs nothing to leave a false positive or noise finding unranked, but ranking it first does', () => {
    expect(earned(ordering(['A', 'B', 'C', 'D']), 'ordering')).toBe(20);
    expect(earned(ordering(['A', 'B', 'C', 'D', 'E']), 'ordering')).toBe(20);
    expect(earned(ordering(['E', 'A', 'B', 'C', 'D']), 'ordering')).toBeLessThan(20);
  });

  it('reads relevance from the first three tiers only, and the most urgent one for a finding listed twice', () => {
    // The builder rejects both shapes, but the grader must still answer for a hand-made case.
    const odd = vcase(['A', 'B', 'C', 'D'].map((id) => finding(id)), { tiers: [['A'], ['B', 'A'], ['C'], ['D']] });
    expect(gradeVulnCase(odd, emptyVulnSubmission()).findings.map((f) => f.relevance)).toEqual([3, 2, 1, 0]);
  });

  it('gives no gain to a tiered finding left out', () => {
    const g = ordering(['A', 'B', 'C']);
    expect(g.ndcg).toBeCloseTo(ndcgOf([[3, 0], [3, 1], [2, 2], [1, null], [0, null]]), 12);
    expect(g.findings.map((f) => f.position)).toEqual([0, 1, 2, null, null]);
  });

  it('ignores unknown and repeated ids: a finding\'s place is its first mention among the known ones', () => {
    const g = ordering(['ZZ', 'A', 'A', 'B', 'YY', 'C', 'A', 'D', 'ZZ']);
    expect(g.findings.map((f) => f.position)).toEqual([0, 1, 2, 3, null]);
    expect(earned(g, 'ordering')).toBe(20);
  });

  describe('must-not-miss findings', () => {
    // M1 and M2 must not be missed, so both are due in the first three places (k = 3).
    const m = vcase(['M1', 'M2', 'X', 'Y', 'Z'].map((id) => finding(id, {}, { mustNotMiss: id.startsWith('M') })), { tiers: [['M1', 'M2'], ['X', 'Y'], ['Z']] });
    const rank = (order: string[]) => gradeVulnCase(m, submit({}, { order }));
    const relevance = [3, 3, 2, 2, 1];
    const ndcgFor = (order: string[]) => ndcgOf(['M1', 'M2', 'X', 'Y', 'Z'].map((id, i): [number, number | null] => [relevance[i], order.includes(id) ? order.indexOf(id) : null]));

    it('takes 4 points for each one outside the top k, and none inside it', () => {
      expect(rank(['M1', 'M2', 'X', 'Y', 'Z']).mustNotMiss).toEqual({ dismissed: [], outsideTopK: [], decisionPenalty: 0, orderingPenalty: 0 });
      const third = rank(['M1', 'X', 'M2', 'Y', 'Z']); // M2 in place 3 of 3: inside
      expect(third.mustNotMiss.outsideTopK).toEqual([]);
      expect(earned(third, 'ordering')).toBe(round1(20 * ndcgFor(['M1', 'X', 'M2', 'Y', 'Z'])));
      const fourth = rank(['M1', 'X', 'Y', 'M2', 'Z']); // place 4: outside
      expect(fourth.mustNotMiss).toMatchObject({ outsideTopK: ['M2'], orderingPenalty: 4 });
      expect(earned(fourth, 'ordering')).toBe(round1(20 * ndcgFor(['M1', 'X', 'Y', 'M2', 'Z']) - 4));
    });

    it('counts a must-not-miss finding left out as outside the top k', () => {
      const g = rank(['M1', 'X', 'Y', 'Z']);
      expect(g.mustNotMiss).toMatchObject({ outsideTopK: ['M2'], orderingPenalty: 4 });
      expect(earned(g, 'ordering')).toBe(round1(20 * ndcgFor(['M1', 'X', 'Y', 'Z']) - 4));
      expect(rank(['X', 'Y', 'Z']).mustNotMiss).toMatchObject({ outsideTopK: ['M1', 'M2'], orderingPenalty: 8 });
    });

    it('cannot take the component below 0', () => {
      const g = rank([]);
      expect(g.ndcg).toBe(0);
      expect(g.mustNotMiss.orderingPenalty).toBe(8);
      expect(earned(g, 'ordering')).toBe(0);
      // A little gain and a bigger penalty.
      const small = rank(['Z']);
      expect(20 * (small.ndcg ?? 0)).toBeLessThan(8);
      expect(earned(small, 'ordering')).toBe(0);
    });

    it('sets k from the number of must-not-miss findings', () => {
      // One must-not-miss finding: k = 2, so place 2 is outside.
      const one = vcase(['M', 'X', 'Y'].map((id) => finding(id, {}, { mustNotMiss: id === 'M' })), { tiers: [['M'], ['X', 'Y']] });
      expect(gradeVulnCase(one, submit({}, { order: ['X', 'M', 'Y'] })).mustNotMiss.outsideTopK).toEqual([]);
      expect(gradeVulnCase(one, submit({}, { order: ['X', 'Y', 'M'] })).mustNotMiss.outsideTopK).toEqual(['M']);
    });

    it('counts the must-not-miss findings for k, not the findings in the top tier', () => {
      // M, X and Y are all tier 1 but only M must not be missed: k = 2, so M in place 3 is outside.
      const tied = vcase(['M', 'X', 'Y'].map((id) => finding(id, {}, { mustNotMiss: id === 'M' })), { tiers: [['M', 'X', 'Y']] });
      const g = gradeVulnCase(tied, submit({}, { order: ['X', 'Y', 'M'] }));
      expect(g.mustNotMiss).toEqual({ dismissed: [], outsideTopK: ['M'], decisionPenalty: 0, orderingPenalty: 4 });
      expect(g.ndcg).toBeCloseTo(1, 12); // a tie inside a tier is free: the penalty is the whole loss
      expect(earned(g, 'ordering')).toBe(16);
      expect(part(g, 'ordering').detail).toBe('Your order earned 100% of the ideal urgency score; 1 must-not-miss finding outside the top 2 (−4).');
      // Place 2 is still inside.
      expect(gradeVulnCase(tied, submit({}, { order: ['X', 'M', 'Y'] })).mustNotMiss.outsideTopK).toEqual([]);
    });
  });

  describe('a case with no tiered finding', () => {
    const none = vcase([finding('A', { decision: 'false-positive', schedule: 'none' }, { mustNotMiss: true }), finding('B', { decision: 'accept', schedule: 'none' })]);

    it('scores the full 20 once any decision is given, and 0 otherwise', () => {
      expect(earned(gradeVulnCase(none, submit({ B: { decision: 'accept' } })), 'ordering')).toBe(20);
      expect(earned(gradeVulnCase(none, submit({ A: { decision: 'patch' } })), 'ordering')).toBe(20); // even a wrong one
      expect(earned(gradeVulnCase(none, emptyVulnSubmission()), 'ordering')).toBe(0);
      expect(earned(gradeVulnCase(none, submit({ A: { schedule: 'none' } }, { order: ['A', 'B'] })), 'ordering')).toBe(0); // schedules and order are not a verdict
      expect(earned(gradeVulnCase(none, submit({ ZZ: { decision: 'patch' } })), 'ordering')).toBe(0); // an answer to no finding of the case
    });

    it('applies nothing else: no nDCG and no must-not-miss penalty', () => {
      const g = gradeVulnCase(none, submit({ A: { decision: 'false-positive' } }));
      expect(g.ndcg).toBeNull();
      expect(g.mustNotMiss).toEqual({ dismissed: [], outsideTopK: [], decisionPenalty: 0, orderingPenalty: 0 });
      expect(part(g, 'ordering').ok).toBe(true);
    });

    it('reads a list of empty tiers as no tiered finding', () => {
      // `tiers` is not empty, but nothing is in it: the same restraint rule applies.
      const hollow = { ...none, tiers: [[]] };
      expect(hollow.tiers).toHaveLength(1);
      const untouched = gradeVulnCase(hollow, emptyVulnSubmission());
      expect(untouched.ndcg).toBeNull();
      expect(earned(untouched, 'ordering')).toBe(0);
      expect(untouched.score).toBe(0);
      const decided = gradeVulnCase(hollow, submit({ B: { decision: 'accept' } }));
      expect(decided.ndcg).toBeNull();
      expect(earned(decided, 'ordering')).toBe(20);
      expect(part(decided, 'ordering').detail).toBe('Nothing here needed urgent handling, so any order is fine.');
    });
  });

  describe('the sentence under the score', () => {
    // A and B are tier 1, C, D and E tier 2, F tier 3.
    const ids = ['A', 'B', 'C', 'D', 'E', 'F'];
    const six = vcase(ids.map((id) => finding(id)), { tiers: [['A', 'B'], ['C', 'D', 'E'], ['F']] });
    const rank = (order: string[]) => gradeVulnCase(six, submit({}, { order }));

    it('rounds down: an order 0.4% short of perfect does not read as 100%', () => {
      // E and F swapped. nDCG 0.9961 is 19.9 of 20 points, and rounding to the nearest percent would say 100%.
      const g = rank(['A', 'B', 'C', 'D', 'F', 'E']);
      expect(g.ndcg).toBeCloseTo(ndcgOf([[3, 0], [3, 1], [2, 2], [2, 3], [2, 5], [1, 4]]), 12);
      expect(g.ndcg).toBeGreaterThanOrEqual(0.995);
      expect(earned(g, 'ordering')).toBe(19.9);
      expect(part(g, 'ordering').ok).toBe(false);
      expect(part(g, 'ordering').detail).toBe('Your order earned 99% of the ideal urgency score.');
    });

    it('never says 100% below full marks, in any of the 720 orders of six findings', () => {
      let nearFull = 0;
      for (const order of permutations(ids)) {
        const g = rank(order);
        const x = part(g, 'ordering');
        if (x.ok) {
          expect(x.detail, order.join('')).toMatch(/^Correct — /);
        } else {
          expect(x.detail, order.join('')).not.toContain('100%');
          if ((g.ndcg ?? 0) >= 0.995) nearFull += 1;
        }
      }
      expect(nearFull).toBeGreaterThan(0); // the loop does reach the band where the nearest percent was 100%
    });

    it('still says 100% for a perfect ranking that is only charged a must-not-miss penalty', () => {
      // Five findings tied in tier 1 and M must not be missed (k = 2): every order has an nDCG of 1,
      // though the sum of a tie can come out a last bit short of it. Only where M is placed decides the penalty.
      const tie = ['M', 'X', 'Y', 'Z', 'W'];
      const tied = vcase(tie.map((id) => finding(id, {}, { mustNotMiss: id === 'M' })), { tiers: [tie] });
      for (const order of permutations(tie)) {
        const g = gradeVulnCase(tied, submit({}, { order }));
        const expected = order.indexOf('M') < 2 ? 'Correct — the most urgent findings came first.' : 'Your order earned 100% of the ideal urgency score; 1 must-not-miss finding outside the top 2 (−4).';
        expect(part(g, 'ordering').detail, order.join('')).toBe(expected);
      }
    });
  });
});

// ---- justification (DESIGN 5.4) ----------------------------------------------------------

describe('justification', () => {
  const grade = (truth: Partial<FindingTruth>, reasons: string[], over: Partial<VulnFindingAnswer> = {}) =>
    gradeOne({ decision: 'patch', ...truth }, { decision: 'patch', reasons: reasons as ReasonCode[], ...over });

  it('is |given and required| / |required|, and codes outside the list are free', () => {
    const t = { reasons: ['known-exploited', 'public-exploit'] as ReasonCode[] };
    expect(grade(t, ['known-exploited', 'public-exploit']).f.reasons.credit).toBe(1);
    expect(grade(t, ['known-exploited']).f.reasons.credit).toBe(0.5);
    expect(grade(t, ['known-exploited', 'banner-only']).f.reasons.credit).toBe(0.5);
    expect(grade(t, ['banner-only']).f.reasons.credit).toBe(0);
    expect(grade(t, []).f.reasons.credit).toBe(0);
    expect(earned(grade(t, ['known-exploited']).g, 'justification')).toBe(7.5);
    expect(grade(t, ['public-exploit', 'banner-only']).f.reasons).toEqual({ given: ['public-exploit', 'banner-only'], matched: ['public-exploit'], missed: ['known-exploited'], contradicting: [], credit: 0.5 });
  });

  it('takes a quarter off for each contradicting code and clamps at 0', () => {
    const t = { reasons: ['known-exploited', 'public-exploit'] as ReasonCode[], contradicting: ['stale-scan', 'banner-only'] as ReasonCode[] };
    expect(grade(t, ['known-exploited', 'public-exploit', 'stale-scan']).f.reasons.credit).toBe(0.75);
    expect(grade(t, ['known-exploited', 'stale-scan', 'banner-only']).f.reasons.credit).toBe(0); // 0.5 - 0.5
    expect(grade(t, ['known-exploited', 'stale-scan']).f.reasons.credit).toBe(0.25);
    expect(grade(t, ['stale-scan', 'banner-only']).f.reasons.credit).toBe(0); // 0 - 0.5, clamped: never negative
    const g = grade(t, ['stale-scan']);
    expect(g.f.reasons).toMatchObject({ contradicting: ['stale-scan'], credit: 0 });
    expect(earned(g.g, 'justification')).toBe(0);
  });

  it('never exceeds 1, and counts a required code listed twice once', () => {
    const t = { reasons: ['known-exploited', 'known-exploited'] as ReasonCode[] };
    expect(grade(t, ['known-exploited']).f.reasons).toMatchObject({ matched: ['known-exploited'], missed: [], credit: 1 });
  });

  it('counts only the first three distinct valid codes', () => {
    const t = { reasons: ['known-exploited', 'public-exploit'] as ReasonCode[], contradicting: ['stale-scan'] as ReasonCode[] };
    // The fourth code is ignored, whether it would help or hurt.
    const fourth = grade(t, ['banner-only', 'internet-exposed', 'critical-asset', 'known-exploited', 'public-exploit']);
    expect(fourth.f.reasons).toMatchObject({ given: ['banner-only', 'internet-exposed', 'critical-asset'], matched: [], credit: 0 });
    expect(grade(t, ['known-exploited', 'banner-only', 'internet-exposed', 'stale-scan']).f.reasons).toMatchObject({ contradicting: [], credit: 0.5 });
    // Repeats and unknown codes take no slot.
    const spread = grade(t, ['known-exploited', 'known-exploited', 'nonsense', 'known-exploited', 'public-exploit', 'banner-only']);
    expect(spread.f.reasons).toMatchObject({ given: ['known-exploited', 'public-exploit', 'banner-only'], credit: 1 });
    expect(REASON_CODES).not.toContain('nonsense');
  });

  it('gives a finding that needs no reason full marks for deciding it, and nothing for not deciding', () => {
    expect(grade({ reasons: [] }, []).f.reasons.credit).toBe(1);
    expect(grade({ reasons: [] }, [], { decision: null }).f.reasons.credit).toBe(0);
    expect(grade({ reasons: [] }, ['banner-only'], { decision: null }).f.reasons.credit).toBe(0);
    // A reason nobody asked for is free, a contradicting one still costs a quarter.
    expect(grade({ reasons: [] }, ['banner-only']).f.reasons.credit).toBe(1);
    expect(grade({ reasons: [], contradicting: ['banner-only'] }, ['banner-only']).f.reasons.credit).toBe(0.75);
    // Required reasons without a decision still score their share: the decision is only the restraint rule.
    expect(grade({ reasons: ['known-exploited'] }, ['known-exploited'], { decision: null }).f.reasons.credit).toBe(1);
  });

  it('weights findings like decisions: 15 x sum(w x score) / sum(w)', () => {
    const c = vcase([finding('A', { reasons: ['known-exploited', 'public-exploit'] }, { weight: 3 }), finding('B', { reasons: ['banner-only'] })]);
    const g = gradeVulnCase(c, submit({ A: { reasons: ['known-exploited'] }, B: { reasons: ['banner-only'] } }));
    expect(earned(g, 'justification')).toBe(round1((15 * (3 * 0.5 + 1)) / 4));
  });
});

// ---- evidence (DESIGN 5.5) ---------------------------------------------------------------

describe('evidence', () => {
  it('lets any row of a point satisfy it, and two findings share a pinned row', () => {
    const c = vcase([
      finding('A', {}, { evidence: [point('a', 'R1', 'R2'), point('shared-a', 'S1')] }),
      finding('B', {}, { evidence: [point('shared-b', 'S1', 'S2')] }),
      finding('C', {}, { evidence: [point('c', 'R9')] }),
    ]);
    const g = gradeVulnCase(c, submit({}, { pins: ['R2', 'S1'] }));
    expect(g.evidence.map((e) => [e.findingId, e.id, e.found, e.pinned])).toEqual([
      ['A', 'a', true, 'R2'],
      ['A', 'shared-a', true, 'S1'],
      ['B', 'shared-b', true, 'S1'],
      ['C', 'c', false, null],
    ]);
    expect(earned(g, 'evidence')).toBe(11); // 3 of 4 points x 15, rounded to whole points as in the SOC grader
    expect(g.irrelevantPins).toBe(0);
    expect(g.evidence[0].recordIds).toEqual(['R1', 'R2']);
    expect(part(g, 'evidence').detail).toBe('3 of 4 evidence points pinned.');
  });

  it('costs 20% per hint used, never counting more hints than the case has', () => {
    const c = vcase([finding('A', {}, { evidence: [point('a', 'R1')] })], { hints: ['h1', 'h2'] });
    const grade = (hintsUsed: number) => gradeVulnCase(c, submit({}, { pins: ['R1'], hintsUsed }));
    expect(earned(grade(0), 'evidence')).toBe(15);
    expect(earned(grade(1), 'evidence')).toBe(12);
    expect(earned(grade(2), 'evidence')).toBe(9);
    expect(earned(grade(5), 'evidence')).toBe(9); // the case has two hints
    expect(part(grade(2), 'evidence').detail).toBe('1 of 1 evidence points pinned. 2 hints used (−40%).');
    // A stored draft with a nonsense count cannot score more than the component.
    expect(earned(grade(-3), 'evidence')).toBe(15);
    expect(earned(grade(Number.NaN), 'evidence')).toBe(15);
  });

  it('allows four irrelevant pins, then costs a point each up to 5', () => {
    const c = vcase([finding('A', {}, { evidence: [point('a', 'R1')] })]);
    const grade = (extra: number) => gradeVulnCase(c, submit({}, { pins: ['R1', ...Array.from({ length: extra }, (_, i) => `X${i}`)] }));
    expect([0, 4, 5, 6, 9, 10, 20].map((n) => earned(grade(n), 'evidence'))).toEqual([15, 15, 14, 13, 10, 10, 10]);
    expect(grade(9).irrelevantPins).toBe(9);
    expect(part(grade(9), 'evidence').detail).toBe('1 of 1 evidence points pinned. 9 pins were not relevant (−5).');
    // The same pin twice is one pin; a pin that satisfies a point is never irrelevant.
    expect(gradeVulnCase(c, submit({}, { pins: ['R1', 'R1', 'X', 'X'] })).irrelevantPins).toBe(1);
    // The penalty comes off the earned points, and cannot go below 0.
    expect(earned(gradeVulnCase(c, submit({}, { pins: Array.from({ length: 9 }, (_, i) => `X${i}`) })), 'evidence')).toBe(0);
  });

  it('scores 0 when the case has no evidence points', () => {
    const g = gradeVulnCase(vcase([finding('A')]), submit({}, { pins: ['X'] }));
    expect(earned(g, 'evidence')).toBe(0);
    expect(g.evidence).toEqual([]);
  });
});

// ---- totals, XP, purity -----------------------------------------------------------------------

describe('totals', () => {
  it('rounds each component to one decimal and sums the rounded components', () => {
    // Decisions 40/3 = 13.33 and schedule 10/3 = 3.33 round down to 13.3 and 3.3;
    // the raw components sum to 51.67, the rounded ones to 51.6.
    const c = vcase([finding('A', { reasons: [] }), finding('B', { reasons: [] }), finding('C', { reasons: [] })]);
    const g = gradeVulnCase(
      c,
      submit({ A: { decision: 'patch', schedule: 'next-window' }, B: { decision: 'accept', schedule: 'none' }, C: { decision: 'transfer', schedule: 'none' } }),
    );
    expect(g.components.map((x) => x.earned)).toEqual([13.3, 20, 3.3, 15, 0]);
    expect(g.score).toBe(51.6);
    expect(g.percent).toBe(52);
  });

  it('reports the components in order, with labels, possible points and a sentence each', () => {
    const g = gradeVulnCase(example(), emptyVulnSubmission());
    expect(g.components.map((x) => x.id)).toEqual(['decisions', 'ordering', 'schedule', 'justification', 'evidence']);
    expect(g.components.map((x) => x.label)).toEqual(['Decisions', 'Ordering', 'Schedule', 'Justification', 'Evidence']);
    expect(g.components.map((x) => x.possible)).toEqual([40, 20, 10, 15, 15]);
    expect(Object.values(VULN_POINTS).reduce((a, b) => a + b, 0)).toBe(100);
    expect(VULN_MAX_SCORE).toBe(100);
    for (const x of g.components) {
      expect(x.detail, x.id).toMatch(/^\S.*\.$/); // one sentence
      expect(x.ok).toBe(false);
    }
  });

  it('reports one grade per finding in case order, and the evidence with its finding', () => {
    const c = example();
    const g = gradeVulnCase(c, perfectVulnSubmission(c));
    expect(g.findings.map((f) => f.findingId)).toEqual(['F1', 'F2', 'F3', 'F4']);
    expect(g.findings.map((f) => [f.weight, f.mustNotMiss])).toEqual([[3, true], [1, false], [1, false], [1, false]]);
    expect(g.findings[0].reasons).toEqual({ given: ['known-exploited', 'public-exploit'], matched: ['known-exploited', 'public-exploit'], missed: [], contradicting: [], credit: 1 });
    expect(g.evidence.map((e) => e.findingId)).toEqual(['F1', 'F3', 'F4']);
    expect(g.irrelevantPins).toBe(0);
  });

  it('adds up the XP as score x difficulty multiplier + 3 per rubric hit, rounded', () => {
    const rubric = [
      { id: 'first', text: 'Names the exploited one', keywords: ['known exploited', 'kev'] },
      { id: 'second', text: 'Says when', keywords: ['emergency'] },
      { id: 'third', text: 'Never met', keywords: ['zzzz'] },
    ];
    for (const difficulty of ['tier1', 'tier2', 'tier3'] as const) {
      const c = vcase([finding('A', {}, { evidence: [point('a', 'R1')] })], { difficulty, rubric, idealOrder: ['A'], tiers: [['A']], hints: [] });
      const p = perfectVulnSubmission(c);
      const plain = gradeVulnCase(c, p);
      expect(plain.rubricHits).toEqual([]);
      expect(plain.xp).toBe(Math.round(100 * DIFFICULTY_MULTIPLIER[difficulty]));
      const noted = gradeVulnCase(c, { ...p, notes: 'The Known   Exploited flaw needs an EMERGENCY change.' });
      expect(noted.rubricHits).toEqual(['first', 'second']);
      expect(noted.xp).toBe(Math.round(100 * DIFFICULTY_MULTIPLIER[difficulty] + 6));
      expect(noted.score).toBe(plain.score); // notes are coaching and XP, never points
    }
    // A fractional score is rounded once, in the XP: 51.6 x 2 = 103.2, and 57.3 x 1.5 = 85.95 rounds up.
    const c = vcase([finding('A', { reasons: [] }), finding('B', { reasons: [] }), finding('C', { reasons: [] })], { difficulty: 'tier3' });
    const g = gradeVulnCase(c, submit({ A: { decision: 'patch', schedule: 'next-window' }, B: { decision: 'accept', schedule: 'none' }, C: { decision: 'transfer', schedule: 'none' } }));
    expect(g.score).toBe(51.6);
    expect(g.xp).toBe(103);
    expect(gradeVulnCase({ ...example(), difficulty: 'tier2' }, sortByCvss()).xp).toBe(86);
    expect(gradeVulnCase(example(), sortByCvss()).xp).toBe(57);
    expect(gradeVulnCase(example(), emptyVulnSubmission()).xp).toBe(0);
  });

  it('never scores above 100, whatever a stored draft says about hints', () => {
    const c = example();
    const p = perfectVulnSubmission(c);
    expect(gradeVulnCase(c, { ...p, hintsUsed: -5 }).score).toBe(100);
    expect(gradeVulnCase(c, { ...p, hintsUsed: Number.NaN }).score).toBe(100);
  });
});

describe('robustness', () => {
  it('does not mutate the case or the submission, and is deterministic', () => {
    const c = deepFreeze(example());
    const s = deepFreeze(
      submit(
        { F1: { decision: 'false-positive', schedule: 'next-window', reasons: ['banner-only', 'stale-scan'] }, F2: { decision: 'patch', schedule: 'next-window' }, F3: { decision: 'mitigate', control: 'CTL' }, F4: { schedule: 'emergency' } },
        { order: ['F4', 'F4', 'ZZ', 'F2', 'F1'], pins: ['REC-KEV', 'X1', 'X2'], notes: 'known exploited', hintsUsed: 1 },
      ),
    );
    const before = JSON.stringify([c, s]);
    const a = gradeVulnCase(c, s);
    expect(JSON.stringify([c, s])).toBe(before);
    expect(JSON.stringify(gradeVulnCase(c, s))).toBe(JSON.stringify(a));
    // Nor the perfect and empty submissions' own inputs.
    expect(() => perfectVulnSubmission(c)).not.toThrow();
    expect(() => gradeVulnCase(c, deepFreeze(perfectVulnSubmission(c)))).not.toThrow();
  });

  it('grades the same whatever order the answers were written in', () => {
    const c = example();
    const forward = submit({ F1: { decision: 'patch' }, F2: { decision: 'accept' }, F3: { decision: 'false-positive' }, F4: { decision: 'patch' } });
    const backward = submit({ F4: { decision: 'patch' }, F3: { decision: 'false-positive' }, F2: { decision: 'accept' }, F1: { decision: 'patch' } });
    expect(JSON.stringify(gradeVulnCase(c, forward))).toBe(JSON.stringify(gradeVulnCase(c, backward)));
  });

  it('treats a finding with no answer as all null, and inherited object keys as no answer', () => {
    const c = vcase([finding('constructor'), finding('toString')]);
    const g = gradeVulnCase(c, emptyVulnSubmission());
    expect(g.findings.map((f) => [f.decision.given, f.schedule.given, f.reasons.given])).toEqual([[null, null, []], [null, null, []]]);
    expect(g.score).toBe(0);
  });

  it('counts a value it does not know as not answered', () => {
    // What a stale stored draft could hold; the types forbid it, so go around them.
    const stale = { ...emptyVulnSubmission(), answers: { F: { decision: 'obliterate', control: null, schedule: 'yesterday', reasons: [] } } } as unknown as VulnSubmission;
    const f = gradeVulnCase(vcase([finding('F', { schedule: 'emergency' })]), stale).findings[0];
    expect(f.decision).toMatchObject({ given: null, credit: 0, verdict: 'missing' });
    expect(f.schedule).toMatchObject({ given: null, credit: 0, verdict: 'missing' }); // not the half credit a nonsense "one step off" would give
    // An answer stored with only some of its fields is graded on what it has.
    const partial = { ...emptyVulnSubmission(), answers: { F: { decision: 'patch' } } } as unknown as VulnSubmission;
    const g = gradeVulnCase(vcase([finding('F', { reasons: ['known-exploited'] })]), partial).findings[0];
    expect(g.decision.verdict).toBe('exact');
    expect(g.schedule.verdict).toBe('missing');
    expect(g.reasons).toMatchObject({ given: [], credit: 0 });
  });
});
