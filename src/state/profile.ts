// Analyst profile v2: pure data and pure transitions (no storage, no DOM), so
// everything here is unit-testable. `storage.ts` persists it; the UI store
// wraps it in signals.
//
// The world (the fictional organisation) is regenerated from `worldSeed`, and
// every case and shift from its seed, so the profile stores decisions and
// results — never logs.

import type { Category, Difficulty, Tactic } from '../core/types.ts';
import type { CaseGrade, ComponentId, Verdict } from '../core/grading/grade.ts';
import type { ResolvedCase } from '../core/cases/scenario.ts';
import type { Budget } from '../core/shift/plan.ts';
import { CLEAN_SHIFT_BONUS, type ShiftResult, type Submission } from '../core/shift/score.ts';
import type { CampaignState, StageOutcome } from '../core/campaign/campaign.ts';
import { review, type Card } from '../core/study/srs.ts';
import type { Attempt, AttemptMode } from '../core/study/scheduler.ts';
import { templateById } from '../core/cases/templates/index.ts';
import type { VulnComponentId, VulnGrade, VulnSubmission } from '../core/vuln/grade.ts';
import type { VulnDecision } from '../core/vuln/model.ts';
import type { VulnDecisionVerdict } from '../core/vuln/grade.ts';
import type { ResolvedVulnCase } from '../core/vuln/scenario.ts';
import { VULN_PASS_PERCENT } from '../core/vuln/worklist.ts';

export const PROFILE_VERSION = 2;
export const MAX_ATTEMPTS = 1500;
export const MAX_SHIFTS = 200;
export const MAX_QUERY_HISTORY = 50;
export const RECENT_WINDOW = 8;
const DAY_MS = 86_400_000;

export type ThemePref = 'system' | 'dark' | 'light';
export type MotionPref = 'system' | 'reduce' | 'full';

export interface Settings {
  sound: boolean; // ambient/feedback sound — off by default
  volume: number; // 0–1
  theme: ThemePref;
  motion: MotionPref;
  timerEnabled: boolean; // practice-case timer
  showRubricLive: boolean;
  defaultBudget: Budget;
  editorFontSize: number;
}

// A vulnerability case stores its components under these keys, so SOC stats that
// read ComponentId keys never see them.
export type VulnComponentKey = `vuln-${VulnComponentId}`;

export interface AttemptRecord {
  id: string; // `${templateId}~${seed}` or `${shiftId}/${alertId}`
  templateId: string;
  seed: string;
  mode: AttemptMode;
  completedAt: number; // epoch ms
  day: number; // local day number
  percent: number;
  score: number;
  dispositionCorrect: boolean;
  xp: number;
  hintsUsed: number;
  durationSec: number | null;
  components: Partial<Record<ComponentId | VulnComponentKey, number>>;
  matchedTechniques: string[];
  missedTechniques: string[];
  evidenceFound: number;
  evidenceTotal: number;
  category: Category;
  difficulty: Difficulty;
  tactics: Tactic[];
  cysaDomains: string[];
  legacy?: boolean; // migrated from v1 (graded by the v1 rubric)
  // Only on vulnerability cases (mode 'vuln'): the real evidence counts and the per-finding
  // decisions (the objective stats and the decision confusion matrix read them).
  // `verdict` is the grade's verdict for the decision; records from before it was stored lack it.
  vuln?: {
    objectives: string[];
    evidenceFound: number;
    evidenceTotal: number;
    decisions: { findingId: string; truth: VulnDecision; given: VulnDecision | null; mustNotMiss: boolean; verdict?: VulnDecisionVerdict }[];
  };
}

export interface ActiveShift {
  number: number;
  budget: Budget;
  startedAt: number; // epoch ms
  elapsedSec: number; // clock only runs while the app is open
  campaignAlertId?: string;
  drafts: Record<string, Verdict>;
  submissions: Submission[];
}

export interface ShiftRecord {
  number: number;
  completedAt: number;
  budget: Budget;
  elapsedSec: number;
  score: number;
  caseScore: number;
  prioritisation: number;
  handled: number;
  total: number;
  missedIncidents: number;
  falseEscalations: number;
  xp: number;
  clean: boolean;
  campaignOutcome?: StageOutcome;
}

export interface SavedQuery {
  id: string;
  name: string;
  text: string;
  lang: 'kql' | 'sql';
}

export interface Profile {
  version: 2;
  analystName: string;
  createdAt: number;
  worldSeed: string;
  xp: number;
  streak: number; // consecutive correct dispositions
  bestStreak: number;
  attempts: AttemptRecord[];
  cards: Record<string, Card>;
  shifts: ShiftRecord[];
  activeShift: ActiveShift | null;
  campaign: CampaignState | null;
  campaignsFinished: { actorId: string; status: string; shifts: number }[];
  savedQueries: SavedQuery[];
  queryHistory: string[];
  recentTemplateIds: string[];
  dailyDone: string[];
  settings: Settings;
  migratedFromV1?: { records: number; at: number };
}

export function defaultSettings(): Settings {
  return { sound: false, volume: 0.5, theme: 'system', motion: 'system', timerEnabled: false, showRubricLive: false, defaultBudget: 30, editorFontSize: 14 };
}

export function defaultProfile(now: number, worldSeed: string): Profile {
  return {
    version: 2,
    analystName: 'Analyst',
    createdAt: now,
    worldSeed,
    xp: 0,
    streak: 0,
    bestStreak: 0,
    attempts: [],
    cards: {},
    shifts: [],
    activeShift: null,
    campaign: null,
    campaignsFinished: [],
    savedQueries: [],
    queryHistory: [],
    recentTemplateIds: [],
    dailyDone: [],
    settings: defaultSettings(),
  };
}

// Local calendar day number (days since the epoch in local time).
export function dayNumber(ms: number, tzOffsetMinutes: number): number {
  return Math.floor((ms - tzOffsetMinutes * 60_000) / DAY_MS);
}

export function asStudyAttempts(p: Profile): Attempt[] {
  // Vulnerability attempts count too: `correct` is the recorded pass flag.
  return p.attempts.map((a) => ({ templateId: a.templateId, percent: a.percent, day: a.day, mode: a.mode, correct: a.dispositionCorrect }));
}

// ---------------------------------------------------------------- transitions

export interface AttemptInput {
  c: ResolvedCase;
  grade: CaseGrade;
  verdict: Verdict;
  mode: AttemptMode;
  now: number;
  day: number;
  durationSec: number | null;
  id?: string;
  dailySeed?: string;
}

export function recordAttempt(p: Profile, input: AttemptInput): { profile: Profile; record: AttemptRecord } {
  const { c, grade: g } = input;
  const record: AttemptRecord = {
    id: input.id ?? c.id,
    templateId: c.templateId,
    seed: c.seed,
    mode: input.mode,
    completedAt: input.now,
    day: input.day,
    percent: g.percent,
    score: g.score,
    dispositionCorrect: g.dispositionCorrect,
    xp: g.xp,
    hintsUsed: input.verdict.hintsUsed,
    durationSec: input.durationSec,
    components: Object.fromEntries(g.components.map((x) => [x.id, x.earned])),
    matchedTechniques: [...g.techniques.matched, ...g.techniques.partial],
    missedTechniques: g.techniques.missed,
    evidenceFound: g.evidence.filter((e) => e.found).length,
    evidenceTotal: g.evidence.length,
    category: c.category,
    difficulty: c.difficulty,
    tactics: c.truth.tactics,
    cysaDomains: c.cysaDomains,
  };
  const streak = g.dispositionCorrect ? p.streak + 1 : 0;
  const profile: Profile = {
    ...p,
    xp: p.xp + g.xp,
    streak,
    bestStreak: Math.max(p.bestStreak, streak),
    attempts: [...p.attempts, record].slice(-MAX_ATTEMPTS),
    // Every graded case counts as a review of its card, whatever the mode.
    cards: { ...p.cards, [c.templateId]: review(p.cards[c.templateId], c.templateId, g.percent, input.day) },
    recentTemplateIds: [...p.recentTemplateIds.filter((id) => id !== c.templateId), c.templateId].slice(-RECENT_WINDOW),
    dailyDone: input.dailySeed && !p.dailyDone.includes(input.dailySeed) ? [...p.dailyDone, input.dailySeed] : p.dailyDone,
  };
  return { profile, record };
}

export interface VulnAttemptInput {
  c: ResolvedVulnCase;
  grade: VulnGrade;
  submission: VulnSubmission;
  now: number;
  day: number;
  durationSec: number | null;
  id?: string;
}

// A graded vulnerability case: XP joins the shared total, the attempt is
// recorded and its study card is reviewed (one card per template id, so each twin
// has its own, as SOC twins do). The SOC disposition streak, recents and daily
// flags stay as they are: a vuln pass is not a disposition.
export function recordVulnAttempt(p: Profile, input: VulnAttemptInput): { profile: Profile; record: AttemptRecord } {
  const { c, grade: g } = input;
  const record: AttemptRecord = {
    id: input.id ?? c.id,
    templateId: c.templateId,
    seed: c.seed,
    mode: 'vuln',
    completedAt: input.now,
    day: input.day,
    percent: g.percent,
    score: g.score,
    dispositionCorrect: g.percent >= VULN_PASS_PERCENT,
    xp: g.xp,
    hintsUsed: input.submission.hintsUsed,
    durationSec: input.durationSec,
    components: Object.fromEntries(g.components.map((x) => [`vuln-${x.id}`, x.earned])),
    matchedTechniques: [],
    missedTechniques: [],
    evidenceFound: 0,
    evidenceTotal: 0,
    category: 'vulnmgmt',
    difficulty: c.difficulty,
    tactics: [],
    cysaDomains: c.cysaDomains,
    vuln: {
      objectives: c.objectives,
      evidenceFound: g.evidence.filter((e) => e.found).length,
      evidenceTotal: g.evidence.length,
      decisions: g.findings.map((f) => ({ findingId: f.findingId, truth: f.decision.truth, given: f.decision.given, mustNotMiss: f.mustNotMiss, verdict: f.decision.verdict })),
    },
  };
  const cards = { ...p.cards, [c.templateId]: review(p.cards[c.templateId], c.templateId, g.percent, input.day) };
  return { profile: { ...p, xp: p.xp + g.xp, attempts: [...p.attempts, record].slice(-MAX_ATTEMPTS), cards }, record };
}

export function startShift(p: Profile, number: number, budget: Budget, now: number, campaignAlertId?: string): Profile {
  return { ...p, activeShift: { number, budget, startedAt: now, elapsedSec: 0, campaignAlertId, drafts: {}, submissions: [] } };
}

export function updateShift(p: Profile, patch: Partial<Pick<ActiveShift, 'elapsedSec' | 'drafts' | 'submissions'>>): Profile {
  if (!p.activeShift) return p;
  return { ...p, activeShift: { ...p.activeShift, ...patch } };
}

export function finishShift(p: Profile, result: ShiftResult, opts: { now: number; campaign: CampaignState | null; campaignOutcome?: StageOutcome }): Profile {
  const s = p.activeShift;
  if (!s) return p;
  const record: ShiftRecord = {
    number: s.number,
    completedAt: opts.now,
    budget: s.budget,
    elapsedSec: s.elapsedSec,
    score: result.score,
    caseScore: result.caseScore,
    prioritisation: result.prioritisation,
    handled: result.handled,
    total: result.total,
    missedIncidents: result.missedIncidents.length,
    falseEscalations: result.falseEscalations.length,
    xp: result.xp,
    clean: result.clean,
    campaignOutcome: opts.campaignOutcome,
  };
  const finished = opts.campaign && opts.campaign.status !== 'active' && p.campaign?.status === 'active';
  return {
    ...p,
    // Case XP is added per case by recordAttempt; only the clean-shift bonus here.
    xp: p.xp + (result.clean ? CLEAN_SHIFT_BONUS : 0),
    activeShift: null,
    shifts: [...p.shifts, record].slice(-MAX_SHIFTS),
    campaign: opts.campaign,
    campaignsFinished: finished ? [...p.campaignsFinished, { actorId: opts.campaign!.actorId, status: opts.campaign!.status, shifts: opts.campaign!.log.length }] : p.campaignsFinished,
  };
}

export function nextShiftNumber(p: Profile): number {
  return p.shifts.length ? Math.max(...p.shifts.map((s) => s.number)) + 1 : 0;
}

export function recentShiftTemplates(p: Profile, n = 12): string[] {
  return p.attempts.filter((a) => a.mode === 'shift' || a.mode === 'campaign').slice(-n).map((a) => a.templateId);
}

export function addQueryHistory(p: Profile, text: string): Profile {
  const t = text.trim();
  if (!t) return p;
  return { ...p, queryHistory: [t, ...p.queryHistory.filter((q) => q !== t)].slice(0, MAX_QUERY_HISTORY) };
}

// ---------------------------------------------------------------- ranks

export interface Rank {
  name: string;
  minXp: number;
}

export const RANKS: Rank[] = [
  { name: 'Trainee', minXp: 0 },
  { name: 'Tier 1 Analyst', minXp: 300 },
  { name: 'Tier 2 Analyst', minXp: 900 },
  { name: 'Tier 3 Analyst', minXp: 2000 },
  { name: 'Incident Responder', minXp: 3800 },
  { name: 'Threat Hunter', minXp: 6500 },
  { name: 'SOC Lead', minXp: 10000 },
];

export function rankFor(xp: number): { current: Rank; next: Rank | null; progress: number } {
  let i = 0;
  while (i + 1 < RANKS.length && xp >= RANKS[i + 1].minXp) i++;
  const current = RANKS[i];
  const next = RANKS[i + 1] ?? null;
  return { current, next, progress: next ? Math.min(1, (xp - current.minXp) / (next.minXp - current.minXp)) : 1 };
}

// ---------------------------------------------------------------- v1 → v2

interface V1Record {
  caseId?: unknown;
  templateId?: unknown;
  category?: unknown;
  difficulty?: unknown;
  completedAt?: unknown;
  score?: unknown;
  percent?: unknown;
  dispositionCorrect?: unknown;
  xp?: unknown;
  matchedTechniques?: unknown;
  missedTechniques?: unknown;
  tactics?: unknown;
  cysaDomains?: unknown;
  durationSec?: unknown;
}

const num = (v: unknown, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d);
const strs = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export function isV1Profile(raw: unknown): boolean {
  return !!raw && typeof raw === 'object' && (raw as { version?: unknown }).version === 1 && Array.isArray((raw as { records?: unknown }).records);
}

export function migrateV1(raw: unknown, now: number, worldSeed: string, tzOffsetMinutes: number): Profile {
  const v1 = raw as Record<string, unknown>;
  const p = defaultProfile(now, worldSeed);
  p.analystName = str(v1.analystName, 'Analyst').trim() || 'Analyst';
  p.xp = Math.max(0, Math.round(num(v1.xp)));
  p.streak = Math.max(0, Math.round(num(v1.streak)));
  p.bestStreak = Math.max(p.streak, Math.round(num(v1.bestStreak)));
  p.dailyDone = strs(v1.dailyDone);
  p.recentTemplateIds = strs(v1.recentTemplateIds).filter((id) => templateById(id)).slice(-RECENT_WINDOW);
  const s = (v1.settings ?? {}) as Record<string, unknown>;
  p.settings.timerEnabled = s.timerEnabled === true;
  p.settings.showRubricLive = s.showRubricLive === true;

  const records = (Array.isArray(v1.records) ? v1.records : []) as V1Record[];
  const migrated: AttemptRecord[] = [];
  for (const r of records) {
    if (!r || typeof r !== 'object') continue;
    const templateId = str(r.templateId);
    const t = templateById(templateId);
    if (!t) continue;
    const completedAt = num(r.completedAt, now);
    const caseId = str(r.caseId, templateId);
    migrated.push({
      id: `v1:${caseId}`,
      templateId,
      seed: caseId.includes('#') ? caseId.split('#').pop()! : caseId,
      mode: 'practice',
      completedAt,
      day: dayNumber(completedAt, tzOffsetMinutes),
      percent: Math.max(0, Math.min(100, Math.round(num(r.percent)))),
      score: num(r.score),
      dispositionCorrect: r.dispositionCorrect === true,
      xp: Math.max(0, Math.round(num(r.xp))),
      hintsUsed: 0,
      durationSec: typeof r.durationSec === 'number' ? r.durationSec : null,
      components: {},
      matchedTechniques: strs(r.matchedTechniques),
      missedTechniques: strs(r.missedTechniques),
      evidenceFound: 0,
      evidenceTotal: 0,
      category: t.category,
      difficulty: t.difficulty,
      tactics: t.tactics,
      cysaDomains: t.cysaDomains,
      legacy: true,
    });
  }
  migrated.sort((a, b) => a.completedAt - b.completedAt);
  p.attempts = migrated.slice(-MAX_ATTEMPTS);
  // Replay history into spaced-repetition cards.
  for (const a of p.attempts) p.cards[a.templateId] = review(p.cards[a.templateId], a.templateId, a.percent, a.day);
  p.migratedFromV1 = { records: migrated.length, at: now };
  return p;
}

// ---------------------------------------------------------------- validation

// Accept a stored or imported blob: v2 as-is (with defaults for fields added
// later), v1 via migration. Anything else is rejected.
export function coerceProfile(raw: unknown, ctx: { now: number; newWorldSeed: string; tzOffsetMinutes: number }): Profile | null {
  if (!raw || typeof raw !== 'object') return null;
  if (isV1Profile(raw)) return migrateV1(raw, ctx.now, ctx.newWorldSeed, ctx.tzOffsetMinutes);
  const r = raw as Partial<Profile>;
  if (r.version !== 2 || !Array.isArray(r.attempts) || typeof r.worldSeed !== 'string' || !r.worldSeed) return null;
  const base = defaultProfile(ctx.now, r.worldSeed);
  return {
    ...base,
    ...r,
    version: 2,
    cards: r.cards && typeof r.cards === 'object' ? r.cards : {},
    shifts: Array.isArray(r.shifts) ? r.shifts : [],
    savedQueries: Array.isArray(r.savedQueries) ? r.savedQueries : [],
    queryHistory: Array.isArray(r.queryHistory) ? r.queryHistory : [],
    campaignsFinished: Array.isArray(r.campaignsFinished) ? r.campaignsFinished : [],
    settings: { ...base.settings, ...(r.settings ?? {}) },
  };
}
