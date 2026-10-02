import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { STATS_OBJECTIVES, mixUpSentence, vulnStats, type VulnStatsAttempt } from '../src/state/vuln-stats.ts';
import { VULN_DECISIONS, type VulnDecision } from '../src/core/vuln/model.ts';
import { CYSA_OBJECTIVES, objectiveLabel } from '../src/core/taxonomy/cysa.ts';

type D = NonNullable<VulnStatsAttempt['vuln']>['decisions'][number];
const d = (truth: VulnDecision, given: VulnDecision | null, verdict?: D['verdict']): D => ({ findingId: `VF-${Math.random()}`, truth, given, mustNotMiss: false, ...(verdict ? { verdict } : {}) });
const vuln = (percent: number, objectives: string[], decisions: D[] = []): VulnStatsAttempt => ({ mode: 'vuln', percent, dispositionCorrect: percent >= 70, vuln: { objectives, evidenceFound: 0, evidenceTotal: 0, decisions } });
const soc = (percent: number): VulnStatsAttempt => ({ mode: 'practice', percent, dispositionCorrect: percent >= 50 });

describe('vulnStats', () => {
  it('has no data without vuln attempts, and ignores SOC attempts', () => {
    const s = vulnStats([soc(90), soc(10)]);
    expect(s.hasData).toBe(false);
    expect(s.summary).toEqual({ cases: 0, passed: 0, passRate: null, avgScore: null });
    expect(s.objectives.every((o) => o.cases === 0 && o.passRate === null && o.avgScore === null)).toBe(true);
    expect(s.matrix.findings).toBe(0);
    expect(s.mixUp).toBeNull();
    expect(vulnStats([]).hasData).toBe(false);
  });

  it('summarises domain 2.0 over vuln attempts only', () => {
    const s = vulnStats([soc(100), vuln(90, ['2.3']), vuln(50, ['2.3']), vuln(70, ['2.1'])]);
    expect(s.hasData).toBe(true);
    expect(s.summary).toMatchObject({ cases: 3, passed: 2 });
    expect(s.summary.passRate).toBeCloseTo(2 / 3, 10);
    expect(s.summary.avgScore).toBeCloseTo(70, 10);
  });

  it('has one row per objective 2.1 to 2.5 (4.1 is not a row), with the official title', () => {
    const s = vulnStats([vuln(90, ['2.3', '2.5', '4.1']), vuln(50, ['2.3', '4.1'])]);
    expect(s.objectives.map((o) => o.id)).toEqual(['2.1', '2.2', '2.3', '2.4', '2.5']);
    expect(STATS_OBJECTIVES.map((o) => o.id)).toEqual(['2.1', '2.2', '2.3', '2.4', '2.5']);
    expect(s.objectives.map((o) => o.label)).toEqual(['2.1 Vulnerability scanning methods', '2.2 Assessment tool output', '2.3 Prioritizing vulnerabilities', '2.4 Mitigating controls', '2.5 Vulnerability response and management']);
    const o23 = s.objectives.find((o) => o.id === '2.3')!;
    expect(o23).toMatchObject({ cases: 2, passed: 1, passRate: 0.5, avgScore: 70 });
    expect(o23.title).toBe('Given a scenario, analyze data to prioritize vulnerabilities.');
    expect(s.objectives.find((o) => o.id === '2.5')).toMatchObject({ cases: 1, passed: 1, passRate: 1, avgScore: 90 });
  });

  it('rows without cases say so (null, not 0 %)', () => {
    const s = vulnStats([vuln(90, ['2.3'])]);
    for (const id of ['2.1', '2.2', '2.4', '2.5']) {
      expect(s.objectives.find((o) => o.id === id)).toMatchObject({ cases: 0, passed: 0, passRate: null, avgScore: null });
    }
    // a vuln record without details (old or odd) still counts for the summary, not for any objective
    const odd = vulnStats([{ mode: 'vuln', percent: 80, dispositionCorrect: true }]);
    expect(odd.summary.cases).toBe(1);
    expect(odd.objectives.every((o) => o.cases === 0)).toBe(true);
  });

  it('counts findings in the confusion matrix by the right decision and the one given', () => {
    const s = vulnStats([
      vuln(80, [], [d('patch', 'patch', 'exact'), d('patch', 'accept', 'wrong'), d('false-positive', 'patch', 'wrong')]),
      vuln(60, [], [d('false-positive', 'patch', 'wrong'), d('false-positive', null, 'missing'), d('mitigate', 'mitigate', 'wrong-control')]),
    ]);
    const { truths, givens, counts, findings } = s.matrix;
    expect(truths).toEqual(VULN_DECISIONS);
    expect(givens).toEqual([...VULN_DECISIONS, null]);
    expect(findings).toBe(6);
    const at = (t: VulnDecision, g: VulnDecision | null) => counts[truths.indexOf(t)][givens.indexOf(g)];
    expect(at('patch', 'patch')).toBe(1);
    expect(at('patch', 'accept')).toBe(1);
    expect(at('false-positive', 'patch')).toBe(2);
    expect(at('false-positive', null)).toBe(1);
    expect(at('mitigate', 'mitigate')).toBe(1);
    expect(counts.flat().reduce((a, b) => a + b, 0)).toBe(6);
  });

  it('names the most frequent mix-up and counts only decisions that did not earn full credit', () => {
    const s = vulnStats([
      vuln(40, [], [
        d('false-positive', 'patch', 'wrong'),
        d('false-positive', 'patch', 'wrong'),
        d('false-positive', 'patch', 'wrong'),
        d('patch', 'mitigate', 'also-accepted'), // off the diagonal but full credit: not a mix-up
        d('patch', 'mitigate', 'also-accepted'),
        d('patch', 'mitigate', 'also-accepted'),
        d('patch', 'mitigate', 'also-accepted'),
        d('avoid', 'accept', 'near-miss'),
        d('mitigate', 'mitigate', 'wrong-control'), // right decision, wrong control: on the diagonal, not a mix-up
        d('mitigate', null, 'missing'), // undecided is not a mix-up
      ]),
    ]);
    expect(s.mixUp).toEqual({ truth: 'false-positive', given: 'patch', count: 3 });
    expect(mixUpSentence(s.mixUp, s.matrix.findings)).toBe('Most common mix-up: you chose Patch when the answer was False positive (3 findings).');
  });

  it('says "1 finding" in the singular, breaks ties by the earlier pair, and reads old records without a verdict', () => {
    const one = vulnStats([vuln(50, [], [d('accept', 'transfer', 'wrong')])]);
    expect(mixUpSentence(one.mixUp, one.matrix.findings)).toBe('Most common mix-up: you chose Transfer when the answer was Accept (1 finding).');
    // old records carry no verdict: any off-diagonal pair counts
    const old = vulnStats([vuln(50, [], [d('patch', 'accept'), d('patch', 'accept'), d('accept', 'patch'), d('patch', 'patch')])]);
    expect(old.mixUp).toEqual({ truth: 'patch', given: 'accept', count: 2 });
    // a tie keeps the pair that comes first in decision order (rows, then columns)
    const tie = vulnStats([vuln(50, [], [d('accept', 'patch'), d('patch', 'accept')])]);
    expect(tie.mixUp).toEqual({ truth: 'patch', given: 'accept', count: 1 });
  });

  it('gives a short positive sentence when there is no mix-up, and a neutral one without findings', () => {
    const clean = vulnStats([vuln(100, ['2.3'], [d('patch', 'patch', 'exact'), d('patch', 'mitigate', 'also-accepted')])]);
    expect(clean.mixUp).toBeNull();
    expect(mixUpSentence(clean.mixUp, clean.matrix.findings)).toBe('No mix-ups so far: every decision you made earned full credit.');
    const none = vulnStats([vuln(100, ['2.3'])]);
    expect(mixUpSentence(none.mixUp, none.matrix.findings)).toBe('No decisions recorded yet.');
  });
});

describe('which findings count as a mix-up', () => {
  const mix = (...ds: D[]) => vulnStats([vuln(50, [], ds)]).mixUp;
  it('does not count an off-diagonal also-accepted finding', () => {
    expect(mix(d('patch', 'mitigate', 'also-accepted'))).toBeNull();
  });
  it('counts an off-diagonal wrong-control finding (an accepted alternative with a non-covering control) as a control problem, not a mix-up', () => {
    expect(mix(d('patch', 'mitigate', 'wrong-control'))).toBeNull();
    expect(vulnStats([vuln(50, [], [d('patch', 'mitigate', 'wrong-control'), d('mitigate', 'mitigate', 'wrong-control')])]).matrix).toMatchObject({ alternatives: 0, wrongControl: 2 });
  });

  it('does not count a diagonal wrong-control finding as a mix-up pair', () => {
    expect(mix(d('mitigate', 'mitigate', 'wrong-control'), d('mitigate', 'mitigate', 'wrong-control'))).toBeNull();
    // and it never wins against a real off-diagonal pair
    expect(mix(d('mitigate', 'mitigate', 'wrong-control'), d('mitigate', 'mitigate', 'wrong-control'), d('accept', 'avoid', 'wrong'))).toEqual({ truth: 'accept', given: 'avoid', count: 1 });
  });
  it('counts an off-diagonal pair on an old record without a verdict, but not a diagonal one', () => {
    expect(mix(d('accept', 'avoid'))).toEqual({ truth: 'accept', given: 'avoid', count: 1 });
    expect(mix(d('accept', 'accept'))).toBeNull();
  });
  it('ignores an unanswered finding, with or without a verdict', () => {
    expect(mix(d('accept', null, 'missing'))).toBeNull();
    expect(mix(d('accept', null))).toBeNull();
    expect(mix(d('accept', null), d('accept', null), d('patch', 'avoid', 'wrong'))).toEqual({ truth: 'patch', given: 'avoid', count: 1 });
  });
  it('counts near-miss and wrong off-diagonal findings', () => {
    expect(mix(d('avoid', 'accept', 'near-miss'))).toEqual({ truth: 'avoid', given: 'accept', count: 1 });
    expect(mix(d('patch', 'accept', 'wrong'))).toEqual({ truth: 'patch', given: 'accept', count: 1 });
    expect(mix(d('patch', 'accept', 'wrong'), d('patch', 'accept', 'near-miss'))).toEqual({ truth: 'patch', given: 'accept', count: 2 });
  });
});

describe('alternatives and wrong-control counts', () => {
  it('counts off-diagonal answers that earned full credit, and mitigate answers with the wrong control', () => {
    const s = vulnStats([
      vuln(70, [], [
        d('patch', 'mitigate', 'also-accepted'),
        d('patch', 'mitigate', 'also-accepted'),
        d('patch', 'patch', 'exact'),
        d('accept', 'avoid', 'wrong'),
        d('accept', 'avoid'), // old record: no verdict, never an alternative
        d('mitigate', 'mitigate', 'wrong-control'),
        d('mitigate', null, 'missing'),
      ]),
    ]);
    expect(s.matrix.alternatives).toBe(2);
    expect(s.matrix.wrongControl).toBe(1);
    expect(vulnStats([vuln(50, [], [d('patch', 'patch', 'exact')])]).matrix).toMatchObject({ alternatives: 0, wrongControl: 0 });
    expect(vulnStats([]).matrix).toMatchObject({ alternatives: 0, wrongControl: 0 });
  });

  it('uses the full-credit sentence only when every decided finding earned full credit', () => {
    const half = vulnStats([vuln(80, [], [d('patch', 'patch', 'exact'), d('mitigate', 'mitigate', 'wrong-control')])]);
    expect(half.mixUp).toBeNull();
    const text = mixUpSentence(half.mixUp, half.matrix.findings, half.matrix.wrongControl);
    expect(text).toBe('No decision mix-ups; 1 mitigate decision named a control that does not cover the path.');
    expect(text).not.toContain('full credit');
    const two = vulnStats([vuln(80, [], [d('mitigate', 'mitigate', 'wrong-control'), d('mitigate', 'mitigate', 'wrong-control')])]);
    expect(mixUpSentence(two.mixUp, two.matrix.findings, two.matrix.wrongControl)).toBe('No decision mix-ups; 2 mitigate decisions named a control that does not cover the path.');
    // full credit everywhere (an undecided finding is not a decision): the positive sentence
    const full = vulnStats([vuln(90, [], [d('patch', 'patch', 'exact'), d('patch', 'mitigate', 'also-accepted'), d('accept', null, 'missing')])]);
    expect(mixUpSentence(full.mixUp, full.matrix.findings, full.matrix.wrongControl)).toBe('No mix-ups so far: every decision you made earned full credit.');
  });
});

describe('objective labels', () => {
  it('keep the official titles verbatim (DESIGN section 1) and the short labels', () => {
    expect(CYSA_OBJECTIVES.map((o) => o.id)).toEqual(['2.1', '2.2', '2.3', '2.4', '2.5', '4.1']);
    expect(CYSA_OBJECTIVES.map((o) => o.title)).toEqual([
      'Given a scenario, implement vulnerability scanning methods and concepts.',
      'Given a scenario, analyze output from vulnerability assessment tools.',
      'Given a scenario, analyze data to prioritize vulnerabilities.',
      'Given a scenario, recommend controls to mitigate attacks and software vulnerabilities.',
      'Explain concepts related to vulnerability response, handling, and management.',
      'Explain the importance of vulnerability management reporting and communication.',
    ]);
    expect(CYSA_OBJECTIVES.map((o) => o.domain)).toEqual(['2.0', '2.0', '2.0', '2.0', '2.0', '4.0']);
    // and they match the design document's table, word for word
    const design = readFileSync(new URL('../docs/vuln-mgmt/DESIGN.md', import.meta.url), 'utf8');
    for (const o of CYSA_OBJECTIVES) expect(design).toContain(`| ${o.id}${o.id === '4.1' ? ' (secondary)' : ''} | ${o.title} |`);
    expect(objectiveLabel('4.1')).toBe('4.1 Vulnerability management reporting');
    expect(objectiveLabel('9.9')).toBe('9.9');
  });
});
