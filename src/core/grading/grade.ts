// Grading v2. 100 points:
//   disposition 30 · severity 10 · action 10 · ATT&CK 15 · evidence 20 · indicators 15
// The first four judge the conclusion; evidence and indicators judge the
// investigation — what the analyst actually found in the SIEM.

import type { ResolvedCase } from '../cases/scenario.ts';
import type { IndicatorSpec } from '../cases/model.ts';
import { ACTION_ORDER, SEVERITY_ORDER, type Difficulty, type Disposition, type RubricItem, type Severity, type TriageAction } from '../types.ts';
import { bestMatch, findMatch, normalise, type GivenIndicator } from './indicators.ts';
import { ordinalCredit, scoreEvidence, type EvidenceResult } from './shared.ts';

// Shared with the vulnerability grader, so they live in shared.ts; re-exported
// here so every existing import keeps working.
export { FREE_EXTRA_PINS, HINT_PENALTY } from './shared.ts';
export type { EvidenceResult } from './shared.ts';

export const POINTS = { disposition: 30, severity: 10, action: 10, attack: 15, evidence: 20, indicators: 15 } as const;
export const MAX_SCORE = Object.values(POINTS).reduce((a, b) => a + b, 0);

export const DISPOSITION_LABELS: Record<Disposition, string> = {
  'true-positive': 'True positive',
  'false-positive': 'False positive',
  benign: 'Benign / expected',
};
export const SEVERITY_LABELS: Record<Severity, string> = { informational: 'Informational', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
export const ACTION_LABELS: Record<TriageAction, string> = { close: 'Close', monitor: 'Monitor', escalate: 'Escalate to IR' };

export interface Verdict {
  disposition: Disposition | null;
  severity: Severity | null;
  action: TriageAction | null;
  techniques: string[];
  notes: string;
  pins: string[]; // RecordIds
  indicators: GivenIndicator[];
  hintsUsed: number;
}

export function emptyVerdict(): Verdict {
  return { disposition: null, severity: null, action: null, techniques: [], notes: '', pins: [], indicators: [], hintsUsed: 0 };
}

export type ComponentId = keyof typeof POINTS;

export interface Component {
  id: ComponentId;
  label: string;
  earned: number;
  possible: number;
  ok: boolean;
  detail: string;
}

export interface IndicatorResult {
  given: GivenIndicator;
  verdict: 'correct' | 'must-not' | 'unsupported';
  spec?: IndicatorSpec;
}

export interface CaseGrade {
  score: number;
  max: number;
  percent: number;
  dispositionCorrect: boolean;
  components: Component[];
  techniques: { matched: string[]; partial: string[]; missed: string[]; extra: string[]; accepted: string[] };
  evidence: EvidenceResult[];
  indicators: { results: IndicatorResult[]; missedBlock: IndicatorSpec[]; missedScope: IndicatorSpec[] };
  irrelevantPins: number;
  rubricHits: string[];
  xp: number;
}

const parentOf = (id: string) => id.split('.')[0];

export const DIFFICULTY_MULTIPLIER: Record<Difficulty, number> = { tier1: 1, tier2: 1.5, tier3: 2 };

// Takes anything with a rubric, so the vulnerability grader can use it too.
export function detectRubricHits(c: { rubric: readonly RubricItem[] }, notes: string): string[] {
  const text = notes.toLowerCase().replace(/\s+/g, ' ');
  if (!text.trim()) return [];
  return c.rubric.filter((r) => r.keywords.some((k) => text.includes(k.toLowerCase()))).map((r) => r.id);
}

export function gradeCase(c: ResolvedCase, v: Verdict): CaseGrade {
  const t = c.truth;
  const components: Component[] = [];

  // ---- disposition ------------------------------------------------------
  const dispositionCorrect = v.disposition === t.disposition;
  const bothBenign = v.disposition !== null && v.disposition !== 'true-positive' && t.disposition !== 'true-positive';
  const dEarned = dispositionCorrect ? POINTS.disposition : bothBenign ? POINTS.disposition / 2 : 0;
  components.push({
    id: 'disposition',
    label: 'Disposition',
    earned: dEarned,
    possible: POINTS.disposition,
    ok: dispositionCorrect,
    detail: dispositionCorrect
      ? `Correct — ${DISPOSITION_LABELS[t.disposition]}.`
      : v.disposition === null
        ? `No disposition given. Answer: ${DISPOSITION_LABELS[t.disposition]}.`
        : bothBenign
          ? `Near miss — ${DISPOSITION_LABELS[v.disposition]} vs ${DISPOSITION_LABELS[t.disposition]}. Both non-malicious, so half credit.`
          : `You said ${DISPOSITION_LABELS[v.disposition]}; the answer is ${DISPOSITION_LABELS[t.disposition]}.`,
  });

  // ---- severity / action --------------------------------------------------
  const ordinal = <T extends string>(order: T[], given: T | null, truth: T, points: number, labels: Record<T, string>, id: ComponentId, label: string) => {
    if (given === null) return components.push({ id, label, earned: 0, possible: points, ok: false, detail: `Not set. Answer: ${labels[truth]}.` });
    const share = ordinalCredit(order, given, truth);
    const earned = points * share;
    components.push({ id, label, earned, possible: points, ok: share === 1, detail: share === 1 ? `Correct — ${labels[truth]}.` : `${labels[given]} vs ${labels[truth]}${share === 0.5 ? ' — one step off, half credit' : ''}.` });
  };
  ordinal(SEVERITY_ORDER, v.severity, t.severity, POINTS.severity, SEVERITY_LABELS, 'severity', 'Severity');
  ordinal(ACTION_ORDER, v.action, t.action, POINTS.action, ACTION_LABELS, 'action', 'Action');

  // ---- ATT&CK -------------------------------------------------------------
  const chosen = [...new Set(v.techniques)];
  const required = t.techniques;
  const accept = new Set(t.alsoAccept ?? []);
  const matched: string[] = [];
  const partial: string[] = [];
  const extra: string[] = [];
  const accepted: string[] = [];
  let credit = 0;
  const covered = new Set<string>();
  // Exact matches first, so a sibling tag can't claim a technique that is
  // also tagged exactly (which would count it one and a half times).
  for (const id of chosen) {
    if (required.includes(id)) {
      matched.push(id);
      covered.add(id);
    }
  }
  // Then related tags: a sibling or parent of an uncovered required technique
  // earns half credit even when it is also on the accepted list (otherwise
  // "also defensible" would score worse than a wrong sub-technique).
  for (const id of chosen) {
    if (required.includes(id)) continue;
    const sibling = required.find((r) => parentOf(r) === parentOf(id) && !covered.has(r));
    if (sibling) {
      partial.push(id);
      covered.add(sibling);
    } else if (accept.has(id)) accepted.push(id);
    else extra.push(id);
  }
  credit = matched.length + partial.length * 0.5;
  const missed = required.filter((r) => !covered.has(r));
  let aEarned: number;
  let aDetail: string;
  if (required.length === 0) {
    // Restraint only earns credit as part of an actual verdict: an alert left
    // untouched at the end of a shift scores nothing.
    const tagged = chosen.length - accepted.length;
    aEarned = v.disposition === null ? 0 : Math.max(0, POINTS.attack - 5 * tagged);
    aDetail = v.disposition === null ? 'No verdict given.' : tagged === 0 ? 'Correct — no adversary technique applies.' : `Nothing malicious happened, but ${tagged} technique${tagged === 1 ? ' was' : 's were'} tagged.`;
  } else {
    aEarned = Math.max(0, Math.round((credit / required.length) * POINTS.attack - 2 * extra.length));
    const parts = [
      matched.length && `matched ${matched.join(', ')}`,
      partial.length && `related ${partial.join(', ')} (half credit)`,
      missed.length && `missed ${missed.join(', ')}`,
      accepted.length && `also defensible ${accepted.join(', ')}`,
      extra.length && `unsupported ${extra.join(', ')}`,
    ].filter(Boolean);
    aDetail = parts.length ? `${parts.join('; ')}.` : 'No techniques tagged.';
  }
  components.push({ id: 'attack', label: 'MITRE ATT&CK', earned: aEarned, possible: POINTS.attack, ok: aEarned === POINTS.attack, detail: aDetail });

  // ---- evidence -----------------------------------------------------------
  const { results: evidence, found, irrelevantPins, hintFactor, pinPenalty, earned: eEarned } = scoreEvidence(c.evidence, v.pins, v.hintsUsed, c.hints.length, POINTS.evidence);
  components.push({
    id: 'evidence',
    label: 'Evidence',
    earned: eEarned,
    possible: POINTS.evidence,
    ok: eEarned === POINTS.evidence,
    detail: [
      `${found} of ${evidence.length} key findings pinned.`,
      v.hintsUsed > 0 ? `${v.hintsUsed} hint${v.hintsUsed === 1 ? '' : 's'} used (−${Math.round((1 - hintFactor) * 100)}%).` : '',
      pinPenalty > 0 ? `${irrelevantPins} pins were not relevant (−${pinPenalty}).` : '',
    ]
      .filter(Boolean)
      .join(' '),
  });

  // ---- indicators ---------------------------------------------------------
  const ind = c.indicators;
  const wanted = [...ind.block, ...ind.scope];
  const results: IndicatorResult[] = [];
  const hitBlock = new Set<IndicatorSpec>();
  const hitScope = new Set<IndicatorSpec>();
  const seen = new Set<string>();
  for (const g of v.indicators) {
    const key = normalise(g.value);
    if (seen.has(key)) continue;
    seen.add(key);
    const bad = findMatch(g, ind.mustNot);
    if (bad) {
      results.push({ given: g, verdict: 'must-not', spec: bad });
      continue;
    }
    const good = bestMatch(g, wanted, new Set([...hitBlock, ...hitScope]));
    if (good) {
      results.push({ given: g, verdict: 'correct', spec: good });
      (ind.block.includes(good) ? hitBlock : hitScope).add(good);
    } else {
      results.push({ given: g, verdict: 'unsupported' });
    }
  }
  const mustNotCount = results.filter((r) => r.verdict === 'must-not').length;
  const unsupported = results.filter((r) => r.verdict === 'unsupported').length;
  const blockWeight = ind.block.length ? (ind.scope.length ? 10 : 15) : 0;
  const scopeWeight = ind.scope.length ? (ind.block.length ? 5 : 15) : 0;
  let iEarned: number;
  if (blockWeight + scopeWeight === 0) {
    // Nothing to report: full marks for restraint (again, only with a verdict).
    iEarned = v.disposition === null ? 0 : POINTS.indicators;
  } else {
    iEarned = (ind.block.length ? (hitBlock.size / ind.block.length) * blockWeight : 0) + (ind.scope.length ? (hitScope.size / ind.scope.length) * scopeWeight : 0);
  }
  iEarned = Math.max(0, Math.round(iEarned - 5 * mustNotCount - Math.min(6, 2 * unsupported)));
  const missedBlock = ind.block.filter((s) => !hitBlock.has(s));
  const missedScope = ind.scope.filter((s) => !hitScope.has(s));
  components.push({
    id: 'indicators',
    label: 'Indicators',
    earned: iEarned,
    possible: POINTS.indicators,
    ok: iEarned === POINTS.indicators,
    detail: [
      ind.block.length ? `${hitBlock.size}/${ind.block.length} indicators to block.` : '',
      ind.scope.length ? `${hitScope.size}/${ind.scope.length} affected users/hosts.` : '',
      blockWeight + scopeWeight === 0 && results.length === 0 && v.disposition !== null ? 'Correct — nothing here needed blocking.' : '',
      mustNotCount ? `${mustNotCount} flagged indicator${mustNotCount === 1 ? ' is' : 's are'} your own or legitimate infrastructure (−${5 * mustNotCount}).` : '',
      unsupported ? `${unsupported} not supported by the evidence (−${Math.min(6, 2 * unsupported)}).` : '',
    ]
      .filter(Boolean)
      .join(' '),
  });

  const score = components.reduce((s, x) => s + x.earned, 0);
  const rubricHits = detectRubricHits(c, v.notes);
  return {
    score,
    max: MAX_SCORE,
    percent: Math.round((score / MAX_SCORE) * 100),
    dispositionCorrect,
    components,
    techniques: { matched, partial, missed, extra, accepted },
    evidence,
    indicators: { results, missedBlock, missedScope },
    irrelevantPins,
    rubricHits,
    xp: Math.round(score * DIFFICULTY_MULTIPLIER[c.difficulty] + 3 * rubricHits.length),
  };
}

// The verdict a perfect analyst would submit (used by tests and the debrief).
export function perfectVerdict(c: ResolvedCase): Verdict {
  return {
    disposition: c.truth.disposition,
    severity: c.truth.severity,
    action: c.truth.action,
    techniques: [...c.truth.techniques],
    notes: '',
    pins: c.evidence.map((e) => e.recordIds[0]),
    indicators: [...c.indicators.block, ...c.indicators.scope].map((s) => ({ kind: s.kind, value: s.value })),
    hintsUsed: 0,
  };
}
