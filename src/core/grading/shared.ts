// Grading helpers both graders share: the SOC verdict grader (grade.ts) and the
// vulnerability-management grader (vuln/grade.ts). Moved out of grade.ts
// unchanged, so the SOC numbers stay exactly what they were.

import type { ResolvedEvidence } from '../cases/scenario.ts';

export const HINT_PENALTY = 0.2; // share of the evidence component per hint used
export const FREE_EXTRA_PINS = 4;

export interface EvidenceResult {
  id: string;
  label: string;
  why: string;
  found: boolean;
  pinned: string | null;
  recordIds: string[];
}

// Ordinal partial credit: full at the right step of an ordered scale, half one
// step off, nothing further away.
export function ordinalCredit<T>(order: readonly T[], given: T, truth: T): 1 | 0.5 | 0 {
  const d = Math.abs(order.indexOf(given) - order.indexOf(truth));
  return d === 0 ? 1 : d === 1 ? 0.5 : 0;
}

export interface EvidenceScore {
  results: EvidenceResult[];
  found: number;
  irrelevantPins: number;
  hintFactor: number;
  pinPenalty: number;
  earned: number;
}

// The evidence component. A point counts once any one of its rows is pinned;
// each hint used costs a share of the points (never more than the case has
// hints); irrelevant pins beyond the free ones cost a point each, at most 5.
// The pin rule is opt-in: the SOC grader passes nothing and keeps 4 free pins and
// the 5-point cap; the vuln grader frees one pin per evidence point, has no cap
// and never counts a finding's own scan row as irrelevant (DESIGN section 5.5).
export interface PinRule {
  free: number; // irrelevant pins that cost nothing
  cap: number; // most the penalty can take (Infinity: none; the component still floors at 0)
  neutral?: ReadonlySet<string>; // rows that are never irrelevant (they satisfy no point unless an evidence point lists them)
}
export const SOC_PIN_RULE: PinRule = { free: FREE_EXTRA_PINS, cap: 5 };
export function scoreEvidence(points: readonly ResolvedEvidence[], pins: readonly string[], hintsUsed: number, hintCount: number, possible: number, pinRule: PinRule = SOC_PIN_RULE): EvidenceScore {
  const pinned = new Set(pins);
  const results: EvidenceResult[] = points.map((e) => {
    const hit = e.recordIds.find((id) => pinned.has(id)) ?? null;
    return { id: e.id, label: e.label, why: e.why, found: hit !== null, pinned: hit, recordIds: e.recordIds };
  });
  const relevant = new Set(points.flatMap((e) => e.recordIds));
  const irrelevantPins = [...pinned].filter((p) => !relevant.has(p) && !pinRule.neutral?.has(p)).length;
  const found = results.filter((e) => e.found).length;
  const hintFactor = Math.max(0, 1 - HINT_PENALTY * Math.min(hintsUsed, hintCount));
  const pinPenalty = Math.min(pinRule.cap, Math.max(0, irrelevantPins - pinRule.free));
  const earned = Math.max(0, Math.round((found / Math.max(1, points.length)) * possible * hintFactor) - pinPenalty);
  return { results, found, irrelevantPins, hintFactor, pinPenalty, earned };
}
