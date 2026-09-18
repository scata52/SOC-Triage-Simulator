import type {
  GradeBreakdown,
  GradeResult,
  Severity,
  TriageAction,
  TriageCase,
  TriageResponse,
} from '../types.ts';
import { techniqueName } from '../data/mitre.ts';
import { DIFFICULTY_MULTIPLIER } from './generator.ts';

export const SEVERITY_ORDER: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
export const ACTION_ORDER: TriageAction[] = ['close', 'monitor', 'escalate'];

export const POINTS = {
  disposition: 40,
  severity: 20,
  action: 15,
  techniques: 25,
} as const;

export const MAX_SCORE =
  POINTS.disposition + POINTS.severity + POINTS.action + POINTS.techniques;

export const SEVERITY_LABELS: Record<Severity, string> = {
  informational: 'Informational',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export const ACTION_LABELS: Record<TriageAction, string> = {
  close: 'Close',
  monitor: 'Monitor',
  escalate: 'Escalate to IR',
};

export const DISPOSITION_LABELS = {
  'true-positive': 'True Positive',
  'false-positive': 'False Positive',
  benign: 'Benign / Expected',
} as const;

// Parent technique id: "T1078.004" -> "T1078"; "T1046" -> "T1046".
function parentOf(id: string): string {
  return id.split('.')[0];
}

function normaliseNotes(notes: string): string {
  return notes.toLowerCase().replace(/\s+/g, ' ');
}

export function detectRubricHits(c: TriageCase, notes: string): string[] {
  const text = normaliseNotes(notes);
  if (!text.trim()) return [];
  const hits: string[] = [];
  for (const item of c.rubric) {
    if (item.keywords.some((k) => text.includes(k.toLowerCase()))) hits.push(item.id);
  }
  return hits;
}

export function gradeResponse(c: TriageCase, r: TriageResponse): GradeResult {
  const truth = c.groundTruth;
  const breakdown: GradeBreakdown[] = [];

  // --- Disposition -------------------------------------------------------
  // "false-positive" and "benign" are both non-malicious; treat picking the
  // sibling as a near-miss worth half credit, since the operational outcome
  // (no incident) is the same.
  let dispEarned = 0;
  let dispDetail: string;
  const dispositionCorrect = r.disposition === truth.disposition;
  const bothNonMalicious =
    r.disposition !== null &&
    r.disposition !== 'true-positive' &&
    truth.disposition !== 'true-positive';
  if (dispositionCorrect) {
    dispEarned = POINTS.disposition;
    dispDetail = `Correct — ${DISPOSITION_LABELS[truth.disposition]}.`;
  } else if (bothNonMalicious) {
    dispEarned = Math.round(POINTS.disposition / 2);
    dispDetail = `Near miss — you said ${DISPOSITION_LABELS[r.disposition!]}, answer key says ${DISPOSITION_LABELS[truth.disposition]}. Both are non-malicious, so half credit.`;
  } else if (r.disposition === null) {
    dispDetail = `No disposition given. Answer: ${DISPOSITION_LABELS[truth.disposition]}.`;
  } else {
    dispDetail = `Incorrect — you said ${DISPOSITION_LABELS[r.disposition]}, answer is ${DISPOSITION_LABELS[truth.disposition]}.`;
  }
  breakdown.push({
    label: 'Disposition',
    earned: dispEarned,
    possible: POINTS.disposition,
    detail: dispDetail,
    ok: dispositionCorrect,
  });

  // --- Severity ----------------------------------------------------------
  let sevEarned = 0;
  let sevDetail: string;
  if (r.severity === null) {
    sevDetail = `No severity given. Answer: ${SEVERITY_LABELS[truth.severity]}.`;
  } else {
    const delta = Math.abs(
      SEVERITY_ORDER.indexOf(r.severity) - SEVERITY_ORDER.indexOf(truth.severity),
    );
    if (delta === 0) {
      sevEarned = POINTS.severity;
      sevDetail = `Exact — ${SEVERITY_LABELS[truth.severity]}.`;
    } else if (delta === 1) {
      sevEarned = Math.round(POINTS.severity / 2);
      sevDetail = `One level off — you said ${SEVERITY_LABELS[r.severity]}, answer is ${SEVERITY_LABELS[truth.severity]}.`;
    } else {
      sevDetail = `Off by ${delta} levels — you said ${SEVERITY_LABELS[r.severity]}, answer is ${SEVERITY_LABELS[truth.severity]}.`;
    }
  }
  breakdown.push({
    label: 'Severity',
    earned: sevEarned,
    possible: POINTS.severity,
    detail: sevDetail,
    ok: sevEarned === POINTS.severity,
  });

  // --- Action ------------------------------------------------------------
  let actEarned = 0;
  let actDetail: string;
  if (r.action === null) {
    actDetail = `No action given. Answer: ${ACTION_LABELS[truth.action]}.`;
  } else {
    const delta = Math.abs(ACTION_ORDER.indexOf(r.action) - ACTION_ORDER.indexOf(truth.action));
    if (delta === 0) {
      actEarned = POINTS.action;
      actDetail = `Correct — ${ACTION_LABELS[truth.action]}.`;
    } else if (delta === 1) {
      actEarned = Math.round(POINTS.action / 2);
      actDetail = `Adjacent — you chose ${ACTION_LABELS[r.action]}, answer is ${ACTION_LABELS[truth.action]}.`;
    } else {
      actDetail = `Wrong direction — you chose ${ACTION_LABELS[r.action]}, answer is ${ACTION_LABELS[truth.action]}.`;
    }
  }
  breakdown.push({
    label: 'Action',
    earned: actEarned,
    possible: POINTS.action,
    detail: actDetail,
    ok: actEarned === POINTS.action,
  });

  // --- MITRE ATT&CK techniques ------------------------------------------
  const chosen = Array.from(new Set(r.techniques));
  const truthSet = new Set(truth.techniques);
  const matched: string[] = [];
  const extra: string[] = [];
  let credit = 0; // in "technique units"

  for (const id of chosen) {
    if (truthSet.has(id)) {
      matched.push(id);
      credit += 1;
    } else if (truth.techniques.some((t) => parentOf(t) === parentOf(id))) {
      // Parent/sibling of a correct technique: half credit, not an "extra".
      matched.push(id);
      credit += 0.5;
    } else {
      extra.push(id);
    }
  }
  const missed = truth.techniques.filter(
    (t) => !chosen.some((c2) => c2 === t || parentOf(c2) === parentOf(t)),
  );

  let techEarned = 0;
  let techDetail: string;
  if (truth.techniques.length === 0) {
    // Non-malicious case: the right answer is "no adversary technique".
    techEarned = Math.max(0, POINTS.techniques - 10 * chosen.length);
    techDetail =
      chosen.length === 0
        ? 'Correct — no adversary technique applies to a benign/false-positive case.'
        : `Benign case: no technique should be tagged (you tagged ${chosen.length}).`;
  } else {
    const raw = (credit / truth.techniques.length) * POINTS.techniques;
    techEarned = Math.max(0, Math.round(raw - 3 * extra.length));
    const parts: string[] = [];
    if (matched.length) parts.push(`matched ${matched.map(techniqueName).join(', ')}`);
    if (missed.length) parts.push(`missed ${missed.map(techniqueName).join(', ')}`);
    if (extra.length) parts.push(`extra ${extra.map(techniqueName).join(', ')}`);
    techDetail = parts.length ? parts.join('; ') + '.' : 'No techniques selected.';
  }
  breakdown.push({
    label: 'MITRE ATT&CK',
    earned: techEarned,
    possible: POINTS.techniques,
    detail: techDetail,
    ok: techEarned === POINTS.techniques,
  });

  // --- Notes rubric (coaching, XP bonus) ---------------------------------
  const rubricAutoHits = detectRubricHits(c, r.notes);

  const score = dispEarned + sevEarned + actEarned + techEarned;
  const percent = Math.round((score / MAX_SCORE) * 100);
  const xpAwarded = Math.round(
    score * DIFFICULTY_MULTIPLIER[c.difficulty] + rubricAutoHits.length * 5,
  );

  return {
    score,
    maxScore: MAX_SCORE,
    percent,
    dispositionCorrect,
    breakdown,
    matchedTechniques: matched,
    missedTechniques: missed,
    extraTechniques: extra,
    rubricAutoHits,
    xpAwarded,
  };
}
