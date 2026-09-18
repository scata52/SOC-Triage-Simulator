// Persistent analyst profile. Lives in localStorage; every read/write is
// wrapped so the app still works (session-only) when storage is unavailable.

import type { Category, Difficulty, GradeResult, TriageCase } from '../types.ts';

export interface CaseRecord {
  caseId: string;
  templateId: string;
  title: string;
  category: Category;
  difficulty: Difficulty;
  completedAt: number; // epoch ms
  score: number;
  maxScore: number;
  percent: number;
  dispositionCorrect: boolean;
  xp: number;
  truthTechniques: string[];
  matchedTechniques: string[];
  missedTechniques: string[];
  tactics: string[];
  rubricHits: number;
  rubricTotal: number;
  cysaDomains: string[];
  durationSec: number | null;
}

export interface Settings {
  timerEnabled: boolean;
  showRubricLive: boolean; // show rubric checklist while typing notes
}

export interface Profile {
  version: 1;
  analystName: string;
  xp: number;
  streak: number;
  bestStreak: number;
  records: CaseRecord[];
  recentTemplateIds: string[];
  dailyDone: string[]; // daily seeds completed
  settings: Settings;
}

const KEY = 'soc-triage-sim:v1';
const MAX_RECORDS = 1000;
const RECENT_WINDOW = 6;

function defaultProfile(): Profile {
  return {
    version: 1,
    analystName: 'Analyst',
    xp: 0,
    streak: 0,
    bestStreak: 0,
    records: [],
    recentTemplateIds: [],
    dailyDone: [],
    settings: { timerEnabled: false, showRubricLive: false },
  };
}

let profile: Profile = load();
const listeners = new Set<() => void>();

function load(): Profile {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return defaultProfile();
    const parsed = JSON.parse(raw) as Partial<Profile>;
    if (parsed.version !== 1) return defaultProfile();
    return { ...defaultProfile(), ...parsed, settings: { ...defaultProfile().settings, ...(parsed.settings ?? {}) } };
  } catch {
    return defaultProfile();
  }
}

function save(): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(profile));
  } catch {
    // storage unavailable — keep in-memory state only
  }
  for (const l of listeners) l();
}

export function getProfile(): Profile {
  return profile;
}

export function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function updateSettings(patch: Partial<Settings>): void {
  profile.settings = { ...profile.settings, ...patch };
  save();
}

export function setAnalystName(name: string): void {
  profile.analystName = name.trim() || 'Analyst';
  save();
}

export function recordResult(
  c: TriageCase,
  g: GradeResult,
  durationSec: number | null,
  dailySeed?: string,
): CaseRecord {
  const rec: CaseRecord = {
    caseId: c.id,
    templateId: c.templateId,
    title: c.title,
    category: c.category,
    difficulty: c.difficulty,
    completedAt: Date.now(),
    score: g.score,
    maxScore: g.maxScore,
    percent: g.percent,
    dispositionCorrect: g.dispositionCorrect,
    xp: g.xpAwarded,
    truthTechniques: c.groundTruth.techniques,
    matchedTechniques: g.matchedTechniques,
    missedTechniques: g.missedTechniques,
    tactics: c.groundTruth.tactics,
    rubricHits: g.rubricAutoHits.length,
    rubricTotal: c.rubric.length,
    cysaDomains: c.cysaDomains,
    durationSec,
  };

  profile.records.push(rec);
  if (profile.records.length > MAX_RECORDS) {
    profile.records = profile.records.slice(-MAX_RECORDS);
  }
  profile.xp += g.xpAwarded;

  if (g.dispositionCorrect) {
    profile.streak += 1;
    profile.bestStreak = Math.max(profile.bestStreak, profile.streak);
  } else {
    profile.streak = 0;
  }

  profile.recentTemplateIds = [...profile.recentTemplateIds, c.templateId].slice(-RECENT_WINDOW);
  if (dailySeed && !profile.dailyDone.includes(dailySeed)) {
    profile.dailyDone.push(dailySeed);
  }
  save();
  return rec;
}

export function resetProfile(): void {
  profile = defaultProfile();
  save();
}

export function exportProfileJson(): string {
  return JSON.stringify(profile, null, 2);
}

export function importProfileJson(json: string): boolean {
  try {
    const parsed = JSON.parse(json) as Partial<Profile>;
    if (parsed.version !== 1 || !Array.isArray(parsed.records)) return false;
    profile = { ...defaultProfile(), ...parsed };
    save();
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Ranks
// ---------------------------------------------------------------------------
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
  let current = RANKS[0];
  let next: Rank | null = null;
  for (let i = 0; i < RANKS.length; i++) {
    if (xp >= RANKS[i].minXp) {
      current = RANKS[i];
      next = RANKS[i + 1] ?? null;
    }
  }
  const progress = next
    ? Math.min(1, (xp - current.minXp) / (next.minXp - current.minXp))
    : 1;
  return { current, next, progress };
}
