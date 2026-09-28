// Shift scoring. 80% is the severity-weighted quality of the verdicts, 20% is
// prioritisation: did the real incidents get worked first? Alerts left in the
// queue at handover score zero — the clock is part of the job.

import type { ResolvedCase } from '../cases/scenario.ts';
import { emptyVerdict, gradeCase, type CaseGrade, type Verdict } from '../grading/grade.ts';
import type { Severity } from '../types.ts';

export const CASE_SHARE = 80;
export const PRIORITY_SHARE = 20;
export const CLEAN_SHIFT_BONUS = 25;

const SEVERITY_WEIGHT: Record<Severity, number> = { informational: 1, low: 1.5, medium: 2, high: 3, critical: 4 };

export interface Submission {
  alertId: string;
  verdict: Verdict;
  atSec: number; // seconds into the shift when submitted
}

export interface ShiftCaseResult {
  alertId: string;
  case: ResolvedCase;
  handled: boolean;
  order: number | null; // 0-based position in the analyst's handling order
  atSec: number | null;
  verdict: Verdict;
  grade: CaseGrade;
  weight: number;
  priority: number; // how urgently the truth needed handling
}

export interface ShiftResult {
  score: number; // 0–100
  caseScore: number; // 0–100, severity-weighted
  prioritisation: number; // 0–1 (nDCG of the handling order)
  handled: number;
  total: number;
  missedIncidents: string[]; // alert ids: real incidents not called true positive
  falseEscalations: string[]; // alert ids: non-incidents escalated
  unhandled: string[];
  idealOrder: string[];
  cases: ShiftCaseResult[];
  xp: number;
  clean: boolean;
}

// Urgency of the truth: real, escalation-worthy incidents by severity first,
// then real-but-contained ones; benign alerts carry no urgency.
export function priorityOf(c: ResolvedCase): number {
  const t = c.truth;
  if (t.disposition !== 'true-positive') return 0;
  return SEVERITY_WEIGHT[t.severity] * (t.action === 'escalate' ? 2 : t.action === 'monitor' ? 1 : 0.5);
}

export function caseWeight(c: ResolvedCase): number {
  return SEVERITY_WEIGHT[c.truth.severity] * (c.truth.disposition === 'true-positive' ? 1.5 : 1);
}

// Normalised discounted cumulative gain of the handling order. Unhandled
// alerts earn no gain. 1 when there is nothing urgent to prioritise.
export function prioritisation(cases: { priority: number; order: number | null }[]): number {
  const gain = (p: number, pos: number) => p / Math.log2(pos + 2);
  const ideal = [...cases].map((c) => c.priority).sort((a, b) => b - a).reduce((s, p, i) => s + gain(p, i), 0);
  if (ideal === 0) return 1;
  const actual = cases.reduce((s, c) => s + (c.order === null ? 0 : gain(c.priority, c.order)), 0);
  return Math.max(0, Math.min(1, actual / ideal));
}

export function scoreShift(cases: readonly ResolvedCase[], submissions: readonly Submission[]): ShiftResult {
  // Last submission per alert wins; order is by first submission time.
  const byAlert = new Map<string, Submission>();
  const firstAt = new Map<string, number>();
  for (const s of submissions) {
    byAlert.set(s.alertId, s);
    if (!firstAt.has(s.alertId)) firstAt.set(s.alertId, s.atSec);
  }
  const handledOrder = [...firstAt.entries()]
    .filter(([id]) => cases.some((c) => c.alertId === id))
    .sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1))
    .map(([id]) => id);

  const results: ShiftCaseResult[] = cases.map((c) => {
    const sub = byAlert.get(c.alertId);
    const verdict = sub?.verdict ?? emptyVerdict();
    const order = handledOrder.indexOf(c.alertId);
    return {
      alertId: c.alertId,
      case: c,
      handled: !!sub,
      order: order >= 0 ? order : null,
      atSec: sub ? firstAt.get(c.alertId)! : null,
      verdict,
      grade: gradeCase(c, verdict),
      weight: caseWeight(c),
      priority: priorityOf(c),
    };
  });

  const totalWeight = results.reduce((s, r) => s + r.weight, 0);
  const caseScore = totalWeight ? results.reduce((s, r) => s + r.weight * r.grade.percent, 0) / totalWeight : 0;
  const prio = prioritisation(results);
  const score = Math.round((caseScore * CASE_SHARE) / 100 + prio * PRIORITY_SHARE);

  const missedIncidents = results.filter((r) => r.case.truth.disposition === 'true-positive' && r.case.truth.action !== 'close' && r.verdict.disposition !== 'true-positive').map((r) => r.alertId);
  const falseEscalations = results.filter((r) => r.case.truth.disposition !== 'true-positive' && r.verdict.action === 'escalate').map((r) => r.alertId);
  const unhandled = results.filter((r) => !r.handled).map((r) => r.alertId);
  const clean = missedIncidents.length === 0 && falseEscalations.length === 0 && unhandled.length === 0;
  const idealOrder = [...results].sort((a, b) => b.priority - a.priority || (a.case.alert.time < b.case.alert.time ? -1 : 1)).map((r) => r.alertId);

  return {
    score,
    caseScore: Math.round(caseScore),
    prioritisation: Math.round(prio * 100) / 100,
    handled: results.length - unhandled.length,
    total: results.length,
    missedIncidents,
    falseEscalations,
    unhandled,
    idealOrder,
    cases: results,
    xp: results.reduce((s, r) => s + r.grade.xp, 0) + (clean ? CLEAN_SHIFT_BONUS : 0),
    clean,
  };
}
