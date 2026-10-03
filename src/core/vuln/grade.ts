// Grading for vulnerability-management cases (DESIGN section 5). 100 points:
//   decisions 40 · ordering 20 · schedule 10 · justification 15 · evidence 15
// Decisions, schedule and justification judge the choices made per finding,
// ordering judges the worklist, evidence judges what was found in the SIEM.
// Like the SOC grader it is pure, deterministic, never mutates its inputs and
// scores an untouched worklist at 0. It reuses the SOC helpers: ordinal partial
// credit, evidence pin scoring with the hint penalty, the nDCG of the shift
// score, the rubric keyword check and the difficulty multiplier.

import { DIFFICULTY_MULTIPLIER } from '../grading/grade.ts';
import { ordinalCredit, scoreEvidence, type EvidenceResult, type PinRule } from '../grading/shared.ts';
import { prioritisation } from '../shift/score.ts';
import { REASON_CODES, VULN_DECISIONS, VULN_SCHEDULES, type ControlId, type FindingTruth, type ReasonCode, type VulnDecision, type VulnSchedule } from './model.ts';
import type { ResolvedVulnCase, ResolvedVulnFinding } from './scenario.ts';
import type { RubricItem } from '../types.ts';

export const VULN_POINTS = { decisions: 40, ordering: 20, schedule: 10, justification: 15, evidence: 15 } as const;
export const VULN_MAX_SCORE = Object.values(VULN_POINTS).reduce((a, b) => a + b, 0);

// Leaving a real must-not-miss finding open (dismissed as a false positive,
// unscheduled, or scheduled later than its SLA) costs this much of the
// decisions component each, at most the cap (DESIGN section 5.1).
const LEFT_OPEN_PENALTY = 5;
const LEFT_OPEN_PENALTY_CAP = 10;
// Each must-not-miss finding outside the top k costs this much ordering (5.2).
const OUTSIDE_TOP_K_PENALTY = 4;
// At most three reason codes count per finding; a counted code the finding does
// not require takes a quarter off its score, a contradicting one half (5.4).
const MAX_REASONS = 3;
const UNNEEDED_REASON_PENALTY = 0.25;
const CONTRADICTING_REASON_PENALTY = 0.5;
// Tier 1, 2 and 3 of `tiers` are worth this much relevance; no tier is 0.
const TIER_RELEVANCE = [3, 2, 1];
// The lesson gate (5.8): a missed key finding caps the total here, below the
// 70 pass mark (5.7).
export const KEY_MISS_CAP = 60;

export interface VulnFindingAnswer {
  decision: VulnDecision | null;
  control: ControlId | null; // the control put in front of the finding, for `mitigate`
  schedule: VulnSchedule | null;
  reasons: ReasonCode[]; // only the first three distinct valid codes count
}

export interface VulnSubmission {
  answers: Record<string, VulnFindingAnswer>; // by findingId; a finding with no entry is unanswered
  order: string[]; // findingIds, most urgent first; findings may be left out
  pins: string[]; // RecordIds
  notes: string; // stakeholder note: coaching and XP only, never points
  hintsUsed: number;
}

export type VulnComponentId = keyof typeof VULN_POINTS;

export interface VulnComponent {
  id: VulnComponentId;
  label: string;
  earned: number;
  possible: number;
  ok: boolean;
  detail: string;
}

export type VulnDecisionVerdict = 'exact' | 'also-accepted' | 'wrong-control' | 'near-miss' | 'wrong' | 'missing';
export type VulnScheduleVerdict = 'exact' | 'one-step' | 'emergency-unjustified' | 'sla-breach' | 'overflow' | 'no-decision' | 'wrong' | 'missing';
// Why a key finding counts as missed (5.8), first match in this order.
export type KeyMissWhy = 'undecided' | 'wrong-decision' | 'near-miss' | 'wrong-control' | 'unscheduled' | 'late' | 'two-steps';

export interface VulnFindingGrade {
  findingId: string;
  weight: number;
  mustNotMiss: boolean;
  lesson: boolean;
  key: boolean; // lesson or must-not-miss: the findings the gate watches
  keyMiss: KeyMissWhy | null; // null when the finding is not key or was handled
  relevance: number; // 3, 2, 1 by tier, 0 for a finding in no tier
  position: number | null; // 0-based place in the submitted order; null when left out
  decision: { given: VulnDecision | null; truth: VulnDecision; credit: number; verdict: VulnDecisionVerdict };
  schedule: { given: VulnSchedule | null; truth: VulnSchedule; credit: number; verdict: VulnScheduleVerdict };
  // given: the codes that counted (first three distinct valid ones); matched,
  // contradicting and unneeded (counted, neither required nor contradicting) in
  // the learner's order, missed in the case's order.
  // zeroed: the reasons would have earned credit, but the decision earned none (5.4).
  reasons: { given: ReasonCode[]; matched: ReasonCode[]; missed: ReasonCode[]; contradicting: ReasonCode[]; unneeded: ReasonCode[]; credit: number; zeroed: boolean };
}

export interface VulnGrade {
  score: number; // sum of the components, one decimal, then the lesson-gate cap
  max: number;
  percent: number;
  components: VulnComponent[]; // decisions, ordering, schedule, justification, evidence
  findings: VulnFindingGrade[]; // one per finding, in case order
  evidence: (EvidenceResult & { findingId: string })[];
  irrelevantPins: number;
  ndcg: number | null; // null for a case with no tiered finding
  // The costly mistakes a debrief leads with. The penalties are what the
  // rules charge; a component that is already at zero cannot go lower.
  // dismissed: a real must-not-miss finding given false-positive; late: one left
  // unscheduled or scheduled later than its SLA. Each costs LEFT_OPEN_PENALTY.
  mustNotMiss: { dismissed: string[]; late: string[]; outsideTopK: string[]; decisionPenalty: number; orderingPenalty: number };
  // The lesson gate (5.8): the key findings missed (case order), the cap they
  // set (null when none) and the component sum before the cap.
  gate: { missed: { findingId: string; lesson: boolean; mustNotMiss: boolean; why: KeyMissWhy }[]; cap: number | null; uncapped: number };
  // Findings whose schedule went over capacity, first to overflow first. All of
  // them score 0 for the schedule; only those that had credit read "overflow".
  overflow: string[];
  rubricHits: string[];
  xp: number;
}

export function emptyVulnSubmission(): VulnSubmission {
  return { answers: {}, order: [], pins: [], notes: '', hintsUsed: 0 };
}

// The submission a perfect analyst would make (used by tests and the debrief).
export function perfectVulnSubmission(c: ResolvedVulnCase): VulnSubmission {
  const answers: Record<string, VulnFindingAnswer> = {};
  for (const f of c.findings) {
    const t = f.truth;
    answers[f.findingId] = {
      decision: t.decision,
      control: t.decision === 'mitigate' ? (t.mitigation?.[0] ?? null) : null,
      schedule: t.schedule,
      reasons: [...new Set(t.reasons)].slice(0, MAX_REASONS), // the grader counts a required code once
    };
  }
  // The first row of every evidence point that has one, repeats dropped.
  const pins = [...new Set(c.findings.flatMap((f) => f.evidence.filter((e) => e.recordIds.length > 0).map((e) => e.recordIds[0])))];
  return { answers, order: [...c.idealOrder], pins, notes: '', hintsUsed: 0 };
}

// ---- per-finding rules ------------------------------------------------------

interface Call<V> {
  credit: number;
  verdict: V;
}

// truth -> given pairs worth half credit whatever the control. The patch ->
// mitigate near miss is not here: it needs a control that covers the path.
const NEAR_MISSES: readonly (readonly [VulnDecision, VulnDecision])[] = [
  ['mitigate', 'patch'],
  ['accept', 'mitigate'],
  ['mitigate', 'accept'],
  ['transfer', 'accept'],
  ['accept', 'transfer'],
  ['avoid', 'patch'], // fixes this finding but keeps the attack surface; patch -> avoid stays 0
];

function decisionCall(t: FindingTruth, given: VulnDecision | null, control: ControlId | null): Call<VulnDecisionVerdict> {
  if (given === null) return { credit: 0, verdict: 'missing' };
  const covers = control !== null && (t.mitigation ?? []).includes(control);
  if (given === t.decision || (t.alsoAccept ?? []).includes(given)) {
    // Mitigate is only right with a control that covers the path; a missing control is a wrong one.
    if (given === 'mitigate' && !covers) return { credit: 0.5, verdict: 'wrong-control' };
    return { credit: 1, verdict: given === t.decision ? 'exact' : 'also-accepted' };
  }
  const near = t.decision === 'patch' && given === 'mitigate' ? covers : NEAR_MISSES.some(([truth, got]) => truth === t.decision && got === given);
  return near ? { credit: 0.5, verdict: 'near-miss' } : { credit: 0, verdict: 'wrong' };
}

// Lateness order is VULN_SCHEDULES: emergency, next window, standard cycle, none.
// A stored case can carry null for "no limit"; it is not set, like undefined.
const pastSla = (t: FindingTruth, given: VulnSchedule) => t.slaLatest != null && VULN_SCHEDULES.indexOf(given) > VULN_SCHEDULES.indexOf(t.slaLatest);
function scheduleCall(t: FindingTruth, given: VulnSchedule | null): Call<VulnScheduleVerdict> {
  if (given === null) return { credit: 0, verdict: 'missing' };
  if (pastSla(t, given)) return { credit: 0, verdict: 'sla-breach' };
  if (given === t.schedule) return { credit: 1, verdict: 'exact' };
  // Change fatigue is real: on a real finding (the truth is not a false positive, the test the must-not-miss
  // penalty uses) an emergency change nobody needed is half right, however late the truth is, `none`
  // (accept, transfer) included. A false positive needs no change at all, so an emergency change for one gets
  // no such credit: it falls through to the ordinal below, which is 0 against its usual truth `none`.
  if (given === 'emergency' && t.decision !== 'false-positive') return { credit: 0.5, verdict: 'emergency-unjustified' };
  return ordinalCredit(VULN_SCHEDULES, given, t.schedule) === 0.5 ? { credit: 0.5, verdict: 'one-step' } : { credit: 0, verdict: 'wrong' };
}

function justificationCall(t: FindingTruth, given: ReasonCode[], decided: boolean, noCredit: boolean) {
  const required = [...new Set(t.reasons)];
  const contradicting = new Set(t.contradicting ?? []);
  const matched = given.filter((r) => required.includes(r));
  const missed = required.filter((r) => !given.includes(r));
  const against = given.filter((r) => contradicting.has(r));
  // Unneeded: counted, neither required nor contradicting. A code the finding
  // does not require never raises its score (5.4).
  const unneeded = given.filter((r) => !required.includes(r) && !contradicting.has(r));
  // Restraint: a finding that needs no reason is justified by deciding it.
  const base = required.length > 0 ? matched.length / Math.min(required.length, MAX_REASONS) : decided ? 1 : 0;
  const raw = base - UNNEEDED_REASON_PENALTY * unneeded.length - CONTRADICTING_REASON_PENALTY * against.length;
  // A reason qualifies a decision: when the decision earns nothing, so do they (5.4).
  const credit = noCredit ? 0 : Math.min(1, Math.max(0, raw));
  return { given, matched, missed, contradicting: against, unneeded, credit, zeroed: noCredit && raw > 0 };
}

// The lesson gate (5.8). A key finding is missed when its decision fails the
// bar (a lesson finding needs full credit, any other must-not-miss finding only
// more than 0) or, when the truth schedule is not `none`, its schedule is unset,
// later than its SLA or two or more steps from the truth (an emergency change
// for a standard-cycle finding is two steps). A must-not-miss finding that is
// not a lesson finding is never gated for an emergency change: it keeps the half
// credit of 5.3, the rule guards against delay, not over-reaction. One step off
// inside the SLA is a slip: half credit, nothing more. Only the learner's own
// answer to the key finding counts: capacity overflow and ordering never gate.
function keyMiss(t: FindingTruth, lesson: boolean, d: Call<VulnDecisionVerdict>, given: VulnSchedule | null): KeyMissWhy | null {
  if (d.verdict === 'missing') return 'undecided';
  if (d.verdict === 'wrong') return 'wrong-decision';
  if (lesson && d.verdict === 'near-miss') return 'near-miss';
  if (lesson && d.verdict === 'wrong-control') return 'wrong-control';
  if (t.schedule === 'none') return null;
  if (given === null) return 'unscheduled';
  if (pastSla(t, given)) return 'late';
  if (!lesson && given === 'emergency') return null; // keeps half credit (5.3); not a distance miss
  if (Math.abs(VULN_SCHEDULES.indexOf(given) - VULN_SCHEDULES.indexOf(t.schedule)) >= 2) return 'two-steps';
  return null;
}

// ---- submission reading -----------------------------------------------------

// Everything the grader needs to know about one finding and the answer to it.
interface Row {
  f: ResolvedVulnFinding;
  index: number; // place in c.findings
  decision: VulnDecision | null;
  control: ControlId | null;
  schedule: VulnSchedule | null;
  reasons: ReasonCode[];
  relevance: number;
  position: number | null;
}

const NO_ANSWER: VulnFindingAnswer = { decision: null, control: null, schedule: null, reasons: [] };

// A stored draft can hold values the rules do not know; those count as not answered.
function oneOf<T extends string>(list: readonly T[], value: unknown): T | null {
  return list.includes(value as T) ? (value as T) : null;
}

// The first three distinct valid codes: repeats and unknown codes take no slot.
function countedReasons(reasons: readonly ReasonCode[]): ReasonCode[] {
  const out: ReasonCode[] = [];
  for (const r of reasons) {
    if (out.length === MAX_REASONS) break;
    if ((REASON_CODES as readonly string[]).includes(r) && !out.includes(r)) out.push(r);
  }
  return out;
}

function readRows(c: ResolvedVulnCase, s: VulnSubmission): Row[] {
  const relevance = new Map<string, number>();
  c.tiers.slice(0, TIER_RELEVANCE.length).forEach((tier, i) => {
    for (const id of tier) if (!relevance.has(id)) relevance.set(id, TIER_RELEVANCE[i]);
  });
  // Unknown ids and repeats are ignored; the first mention of a finding is its place.
  const known = new Set(c.findings.map((f) => f.findingId));
  const position = new Map<string, number>();
  for (const id of s.order) if (known.has(id) && !position.has(id)) position.set(id, position.size);
  return c.findings.map((f, index) => {
    const a = (Object.hasOwn(s.answers, f.findingId) ? s.answers[f.findingId] : undefined) ?? NO_ANSWER;
    return {
      f,
      index,
      decision: oneOf(VULN_DECISIONS, a.decision),
      control: a.control ?? null,
      schedule: oneOf(VULN_SCHEDULES, a.schedule),
      reasons: countedReasons(a.reasons ?? []),
      relevance: relevance.get(f.findingId) ?? 0,
      position: position.get(f.findingId) ?? null,
    };
  });
}

// ---- components ---------------------------------------------------------------

const round1 = (x: number) => Math.round(x * 10) / 10;
// A percent to one decimal, rounded down so that 100% is only claimed for a
// perfect ranking (one decimal agrees with the points beside it to within
// rounding); the nudge keeps the last bit of the nDCG sum (0.9999999999999999)
// from turning a perfect ranking into 99.9%.
export const percentDown = (x: number) => Math.floor(x * 1000 + 1e-6) / 10;
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
const listed = (parts: (string | false)[]) => `${parts.filter(Boolean).join('; ')}.`;

// The order findings lose their schedule when a window is over capacity:
// lowest relevance first, then the one the learner ranked lowest (unranked
// counts as lowest), then the later finding in case order.
function overflowOrder(a: Row, b: Row): number {
  if (a.relevance !== b.relevance) return a.relevance - b.relevance;
  const pa = a.position ?? Number.POSITIVE_INFINITY;
  const pb = b.position ?? Number.POSITIVE_INFINITY;
  if (pa !== pb) return pb > pa ? 1 : -1;
  return b.index - a.index;
}

// Keyword check for the vulnerability notes, with word boundaries (the SOC
// detectRubricHits stays a plain substring test). Both sides are normalised the
// same way: lowercase, every run of characters outside a-z0-9 becomes one space.
// The note is also trimmed and padded with one space at each end. A keyword keeps
// its leading and trailing space, so ' oct 3 ' demands a word boundary on both
// sides: it matches "Oct 3." and "by Oct 3" but not "Oct 31". A keyword without
// a letter or digit never matches; an empty note hits nothing. Before that, a
// possessive ('s or ’s after a letter or digit, at a word end) is dropped on both
// sides, so 'app01 console' matches "APP01's console". "it's" becomes "it"; "its" is untouched.
const normaliseRubric = (t: string): string => t.toLowerCase().replace(/(?<=[a-z0-9])['’]s(?![a-z0-9])/g, '').replace(/[^a-z0-9]+/g, ' ');
export function vulnRubricHits(rubric: readonly RubricItem[], notes: string): string[] {
  const body = normaliseRubric(notes).trim();
  if (!body) return [];
  const text = ` ${body} `;
  return rubric.filter((r) => r.keywords.some((k) => /[a-z0-9]/i.test(k) && text.includes(normaliseRubric(k)))).map((r) => r.id);
}

export function gradeVulnCase(c: ResolvedVulnCase, s: VulnSubmission): VulnGrade {
  const rows = readRows(c, s);
  const n = rows.length;
  const hintsUsed = s.hintsUsed > 0 ? s.hintsUsed : 0; // a stored draft can hold a negative or missing count
  const idOf = (r: Row) => r.f.findingId;
  const weightSum = rows.reduce((sum, r) => sum + r.f.weight, 0);
  const isFull = (earned: number, id: VulnComponentId) => round1(earned) === VULN_POINTS[id];

  // ---- decisions ----------------------------------------------------------
  const decisions = rows.map((r) => decisionCall(r.f.truth, r.decision, r.control));
  // A real must-not-miss finding is left open when it is dismissed as a false
  // positive, or not fixed in time: unscheduled (when its truth schedule is not
  // `none`, so there is something to schedule) or later than its SLA (5.1).
  const realMnm = (r: Row) => r.f.mustNotMiss && r.f.truth.decision !== 'false-positive';
  const dismissed = rows.filter((r) => realMnm(r) && r.decision === 'false-positive').map(idOf);
  const late = rows.filter((r) => realMnm(r) && r.decision !== 'false-positive' && r.f.truth.schedule !== 'none' && (r.schedule === null || pastSla(r.f.truth, r.schedule))).map(idOf);
  const leftOpen = dismissed.length + late.length;
  const decisionPenalty = Math.min(LEFT_OPEN_PENALTY_CAP, LEFT_OPEN_PENALTY * leftOpen);
  const weightedCredit = rows.reduce((sum, r, i) => sum + r.f.weight * decisions[i].credit, 0);
  const dEarned = weightSum > 0 ? Math.max(0, (VULN_POINTS.decisions * weightedCredit) / weightSum - decisionPenalty) : 0;
  const dCount = (v: VulnDecisionVerdict) => decisions.filter((x) => x.verdict === v).length;
  const dRight = dCount('exact') + dCount('also-accepted');
  const dDetail =
    n === 0
      ? 'No findings to decide.'
      : dRight === n && decisionPenalty === 0
        ? `Correct — all ${n} findings decided right.`
        : listed([
            `${dRight} of ${n} decided right`,
            dCount('wrong-control') > 0 && `${dCount('wrong-control')} with the wrong control (half credit)`,
            dCount('near-miss') > 0 && `${dCount('near-miss')} near ${plural(dCount('near-miss'), 'miss', 'misses')} (half credit)`,
            dCount('wrong') > 0 && `${dCount('wrong')} wrong`,
            dCount('missing') > 0 && `${dCount('missing')} not decided`,
            decisionPenalty > 0 && `${leftOpen} real must-not-miss ${plural(leftOpen, 'finding', 'findings')} left open: dismissed as false positive or not fixed within the SLA (−${decisionPenalty})`,
          ]);

  // ---- ordering -----------------------------------------------------------
  const tiered = rows.some((r) => r.relevance > 0);
  const topK = rows.filter((r) => r.f.mustNotMiss).length + 1; // each must-not-miss finding is due in the first k places
  let ndcg: number | null = null;
  let outsideTopK: string[] = [];
  let oEarned: number;
  if (tiered) {
    ndcg = prioritisation(rows.map((r) => ({ priority: r.relevance, order: r.position })));
    outsideTopK = rows.filter((r) => r.f.mustNotMiss && (r.position === null || r.position >= topK)).map(idOf);
    oEarned = Math.max(0, VULN_POINTS.ordering * ndcg - OUTSIDE_TOP_K_PENALTY * outsideTopK.length);
  } else {
    // Nothing needs ranking: restraint earns the points, but only as part of an actual answer.
    oEarned = rows.some((r) => r.decision !== null) ? VULN_POINTS.ordering : 0;
  }
  const orderingPenalty = OUTSIDE_TOP_K_PENALTY * outsideTopK.length;
  const oDetail = !tiered
    ? oEarned > 0
      ? 'Nothing here needed urgent handling, so any order is fine.'
      : 'No verdict given.'
    : isFull(oEarned, 'ordering')
      ? 'Correct — the most urgent findings came first.'
      : listed([
          `Your order earned ${percentDown(ndcg ?? 0)}% of the ideal urgency score${outsideTopK.length > 0 ? ' before the must-not-miss charge' : ''}`,
          outsideTopK.length > 0 && `${outsideTopK.length} must-not-miss ${plural(outsideTopK.length, 'finding', 'findings')} outside the top ${topK} (−${orderingPenalty})`,
        ]);

  // ---- schedule -----------------------------------------------------------
  const schedules = rows.map((r) => scheduleCall(r.f.truth, r.schedule));
  const capacity = c.constraints.capacityPerWindow;
  const assigned = rows.filter((r) => r.schedule === 'emergency' || r.schedule === 'next-window');
  const overflowing = assigned.length > capacity ? [...assigned].sort(overflowOrder).slice(0, assigned.length - capacity) : [];
  // Capacity takes away whatever credit the rules gave. A finding that had none
  // keeps its own verdict (a breach or a wrong answer says more than "overflow").
  for (const r of overflowing) if (schedules[r.index].credit > 0) schedules[r.index] = { credit: 0, verdict: 'overflow' };
  // A window only means something for the right kind of action: a finding whose
  // decision earns 0 earns 0 for its schedule (5.3). It still takes its place
  // in a window, so capacity above is unaffected.
  decisions.forEach((d, i) => {
    if (d.credit === 0 && schedules[i].credit > 0) schedules[i] = { credit: 0, verdict: 'no-decision' };
  });
  const sEarned = n > 0 ? (VULN_POINTS.schedule * schedules.reduce((sum, x) => sum + x.credit, 0)) / n : 0;
  const sCount = (v: VulnScheduleVerdict) => schedules.filter((x) => x.verdict === v).length;
  const sDetail =
    n === 0
      ? 'No findings to schedule.'
      : sCount('exact') === n
        ? `Correct — all ${n} findings scheduled right.`
        : listed([
            `${sCount('exact')} of ${n} scheduled right`,
            sCount('one-step') > 0 && `${sCount('one-step')} one step off (half credit)`,
            sCount('emergency-unjustified') > 0 && `${sCount('emergency-unjustified')} emergency ${plural(sCount('emergency-unjustified'), 'change', 'changes')} not justified (half credit)`,
            sCount('sla-breach') > 0 && `${sCount('sla-breach')} later than the SLA allows`,
            sCount('overflow') > 0 && `${sCount('overflow')} over the capacity of ${capacity} per window`,
            sCount('no-decision') > 0 && `${sCount('no-decision')} with a decision that earned nothing (no schedule credit)`,
            sCount('wrong') > 0 && `${sCount('wrong')} wrong`,
            sCount('missing') > 0 && `${sCount('missing')} not scheduled`,
          ]);

  // ---- justification ------------------------------------------------------
  const reasons = rows.map((r, i) => justificationCall(r.f.truth, r.reasons, r.decision !== null, decisions[i].credit === 0));
  const weightedReasons = rows.reduce((sum, r, i) => sum + r.f.weight * reasons[i].credit, 0);
  const jEarned = weightSum > 0 ? (VULN_POINTS.justification * weightedReasons) / weightSum : 0;
  const jFull = reasons.filter((x) => x.credit === 1).length;
  const jAgainst = reasons.reduce((sum, x) => sum + x.contradicting.length, 0);
  const jUnneeded = reasons.reduce((sum, x) => sum + x.unneeded.length, 0);
  const jZeroed = reasons.filter((x) => x.zeroed).length;
  const floorNote = "a finding's reason credit runs from 0% to 100% and stops at 0%"; // said once, on the last deduction named
  const jDetail =
    n === 0
      ? 'No findings to justify.'
      : jFull === n
        ? 'Correct — every finding justified.'
        : listed([
            `${jFull} of ${n} findings fully justified`,
            jAgainst > 0 && `${jAgainst} ${plural(jAgainst, 'reason', 'reasons')} contradicted the evidence (−50% credit each${jUnneeded > 0 ? '' : `; ${floorNote}`})`,
            jUnneeded > 0 && `${jUnneeded} ${plural(jUnneeded, 'reason', 'reasons')} not needed for ${plural(jUnneeded, 'its finding', 'their findings')} (−25% credit each; ${floorNote})`,
            jZeroed > 0 && `${jZeroed} with a decision that earned nothing (no reason credit)`,
          ]);

  // ---- evidence -----------------------------------------------------------
  const points = rows.flatMap((r) => r.f.evidence.map((e) => ({ findingId: r.f.findingId, e })));
  // One free extra pin per evidence point, then −1 each with no cap (the
  // component floors at 0); a finding's own scan row is never counted against you (5.5).
  const pinRule: PinRule = { free: points.length, cap: Number.POSITIVE_INFINITY, neutral: new Set(rows.map((r) => r.f.recordId)) };
  const scored = scoreEvidence(points.map((p) => p.e), s.pins, hintsUsed, c.hints.length, VULN_POINTS.evidence, pinRule);
  const eDetail = [
    `${scored.found} of ${points.length} evidence points pinned.`,
    hintsUsed > 0 ? `${hintsUsed} ${plural(hintsUsed, 'hint', 'hints')} used (−${Math.round((1 - scored.hintFactor) * 100)}%).` : '',
    scored.pinPenalty > 0 ? `${scored.irrelevantPins} pins were not relevant, ${pinRule.free} of them free (−${scored.pinPenalty}).` : '',
  ]
    .filter(Boolean)
    .join(' ');

  // ---- components, totals -------------------------------------------------
  const done = (id: VulnComponentId, label: string, earned: number, detail: string): VulnComponent => {
    const e = round1(earned);
    return { id, label, earned: e, possible: VULN_POINTS[id], ok: e === VULN_POINTS[id], detail };
  };
  const components: VulnComponent[] = [
    done('decisions', 'Decisions', dEarned, dDetail),
    done('ordering', 'Ordering', oEarned, oDetail),
    done('schedule', 'Schedule', sEarned, sDetail),
    done('justification', 'Justification', jEarned, jDetail),
    done('evidence', 'Evidence', scored.earned, eDetail),
  ];

  // The lesson gate (5.8): any missed key finding caps the score.
  const isLesson = (r: Row) => r.f.lesson === true;
  const isKey = (r: Row) => isLesson(r) || r.f.mustNotMiss;
  const misses = rows.map((r, i) => (isKey(r) ? keyMiss(r.f.truth, isLesson(r), decisions[i], r.schedule) : null));
  const missed = rows.filter((r) => misses[r.index] !== null).map((r) => ({ findingId: idOf(r), lesson: isLesson(r), mustNotMiss: r.f.mustNotMiss, why: misses[r.index]! }));
  const uncapped = round1(components.reduce((sum, x) => sum + x.earned, 0));
  const cap = missed.length > 0 ? KEY_MISS_CAP : null;
  const score = cap !== null ? Math.min(uncapped, cap) : uncapped;
  const rubricHits = vulnRubricHits(c.rubric, s.notes);
  const findings: VulnFindingGrade[] = rows.map((r, i) => ({
    findingId: r.f.findingId,
    weight: r.f.weight,
    mustNotMiss: r.f.mustNotMiss,
    lesson: isLesson(r),
    key: isKey(r),
    keyMiss: misses[i],
    relevance: r.relevance,
    position: r.position,
    decision: { given: r.decision, truth: r.f.truth.decision, credit: decisions[i].credit, verdict: decisions[i].verdict },
    schedule: { given: r.schedule, truth: r.f.truth.schedule, credit: schedules[i].credit, verdict: schedules[i].verdict },
    reasons: reasons[i],
  }));
  return {
    score,
    max: VULN_MAX_SCORE,
    percent: Math.round(score),
    components,
    findings,
    evidence: scored.results.map((e, i) => ({ findingId: points[i].findingId, ...e })),
    irrelevantPins: scored.irrelevantPins,
    ndcg,
    mustNotMiss: { dismissed, late, outsideTopK, decisionPenalty, orderingPenalty },
    gate: { missed, cap, uncapped },
    overflow: overflowing.map(idOf),
    rubricHits,
    xp: Math.round(score * DIFFICULTY_MULTIPLIER[c.difficulty] + 3 * rubricHits.length),
  };
}
