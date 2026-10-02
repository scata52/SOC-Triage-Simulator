// Vulnerability-management statistics: pure aggregation over the profile's
// attempt records (no Preact, no storage, no clock). Stats.tsx renders it.
//
// Domain 2.0 summary, one row per objective 2.1-2.5, and a decision confusion
// matrix (the right decision against the one the analyst chose, over every
// finding of every vuln attempt). 4.1 is not a row: every vuln case carries it,
// so it would only repeat the domain summary.

import { CYSA_OBJECTIVES, objectiveLabel } from '../core/taxonomy/cysa.ts';
import { VULN_DECISIONS, type VulnDecision } from '../core/vuln/model.ts';
import { DECISION_LABELS } from '../core/vuln/worklist.ts';
import type { AttemptRecord } from './profile.ts';

export type VulnStatsAttempt = Pick<AttemptRecord, 'mode' | 'percent' | 'dispositionCorrect' | 'vuln'>;

// The objectives shown as table rows.
export const STATS_OBJECTIVES = CYSA_OBJECTIVES.filter((o) => o.domain === '2.0');

export interface VulnSummary {
  cases: number;
  passed: number;
  passRate: number | null; // 0-1, null without cases
  avgScore: number | null; // mean percent, null without cases
}

export interface ObjectiveRow extends VulnSummary {
  id: string;
  label: string; // "2.3 Prioritizing vulnerabilities"
  title: string; // the official wording
}

export interface DecisionMatrix {
  truths: readonly VulnDecision[]; // rows
  givens: readonly (VulnDecision | null)[]; // columns; null = no decision
  counts: number[][]; // counts[row][column]
  findings: number;
  alternatives: number; // off-diagonal decisions the case also accepted (full credit)
  wrongControl: number; // mitigate decisions (right or an accepted alternative) that named a control not covering the path (half credit)
}

export interface MixUp {
  truth: VulnDecision;
  given: VulnDecision;
  count: number;
}

export interface VulnStats {
  hasData: boolean;
  summary: VulnSummary;
  objectives: ObjectiveRow[];
  matrix: DecisionMatrix;
  mixUp: MixUp | null;
}

function summarise(list: readonly VulnStatsAttempt[]): VulnSummary {
  const cases = list.length;
  const passed = list.filter((a) => a.dispositionCorrect).length;
  return {
    cases,
    passed,
    passRate: cases ? passed / cases : null,
    avgScore: cases ? list.reduce((s, a) => s + a.percent, 0) / cases : null,
  };
}

// Did this decision earn full credit? Records from before the verdict was stored
// have no `verdict`: for them, only a matching decision counts as right.
function fullCredit(d: { truth: VulnDecision; given: VulnDecision | null; verdict?: string }): boolean {
  if (d.verdict !== undefined) return d.verdict === 'exact' || d.verdict === 'also-accepted';
  return d.given === d.truth;
}

export function vulnStats(attempts: readonly VulnStatsAttempt[]): VulnStats {
  const vuln = attempts.filter((a) => a.mode === 'vuln');
  const objectives: ObjectiveRow[] = STATS_OBJECTIVES.map((o) => ({
    id: o.id,
    label: objectiveLabel(o.id),
    title: o.title,
    ...summarise(vuln.filter((a) => a.vuln?.objectives.includes(o.id))),
  }));

  const truths = VULN_DECISIONS;
  const givens: readonly (VulnDecision | null)[] = [...VULN_DECISIONS, null];
  const counts = truths.map(() => givens.map(() => 0));
  const mix = new Map<string, number>();
  let findings = 0;
  let alternatives = 0;
  let wrongControl = 0;
  for (const a of vuln) {
    for (const d of a.vuln?.decisions ?? []) {
      const r = truths.indexOf(d.truth);
      if (r < 0) continue;
      const c = d.given === null ? givens.length - 1 : givens.indexOf(d.given);
      if (c < 0) continue;
      counts[r][c]++;
      findings++;
      if (d.given !== null && d.given !== d.truth && fullCredit(d)) alternatives++;
      // Mitigate with a control that does not cover the path: the decision was right (or an accepted
      // alternative), the control was not, so it is counted here and never as a decision mix-up.
      if (d.given !== null && d.verdict === 'wrong-control') wrongControl++;
      // A mix-up is a decision that was made and did not earn full credit; leaving a finding
      // undecided is a separate matter (the submit gate asks for every decision).
      else if (d.given !== null && d.given !== d.truth && !fullCredit(d)) mix.set(`${r}:${c}`, (mix.get(`${r}:${c}`) ?? 0) + 1);
    }
  }
  let mixUp: MixUp | null = null;
  let best = 0;
  for (const [key, count] of [...mix].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
    if (count <= best) continue; // ties keep the earlier (row, column) pair
    const [r, c] = key.split(':').map(Number);
    best = count;
    mixUp = { truth: truths[r], given: givens[c] as VulnDecision, count };
  }
  return { hasData: vuln.length > 0, summary: summarise(vuln), objectives, matrix: { truths, givens, counts, findings, alternatives, wrongControl }, mixUp };
}

export function mixUpSentence(m: MixUp | null, findings: number, wrongControl = 0): string {
  if (m) {
    return `Most common mix-up: you chose ${DECISION_LABELS[m.given]} when the answer was ${DECISION_LABELS[m.truth]} (${m.count} ${m.count === 1 ? 'finding' : 'findings'}).`;
  }
  if (wrongControl > 0) {
    return `No decision mix-ups; ${wrongControl} mitigate ${wrongControl === 1 ? 'decision' : 'decisions'} named a control that does not cover the path.`;
  }
  return findings > 0 ? 'No mix-ups so far: every decision you made earned full credit.' : 'No decisions recorded yet.';
}
