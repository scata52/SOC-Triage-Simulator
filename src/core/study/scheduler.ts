// What to study next. Due reviews come first; otherwise new or not-yet-due
// cases are drawn with weights that favour the analyst's weakest CySA+
// domains, ATT&CK tactics and alert categories.

import type { Rng } from '../rng.ts';
import type { Category, Difficulty, Tactic } from '../types.ts';
import type { CaseTemplate } from '../cases/model.ts';
import { ALL_TEMPLATES, CATEGORY_LABELS, templateById } from '../cases/templates/index.ts';
import { TACTIC_LABELS, TACTIC_ORDER } from '../taxonomy/mitre.ts';
import { CYSA_DOMAINS, cysaLabel } from '../taxonomy/cysa.ts';
import { isDue, type Card } from './srs.ts';

export type AttemptMode = 'practice' | 'study' | 'shift' | 'campaign';

export interface Attempt {
  templateId: string;
  percent: number;
  day: number;
  mode: AttemptMode;
  correct: boolean; // disposition right
}

export type SkillKind = 'domain' | 'tactic' | 'category';

export interface Skill {
  kind: SkillKind;
  key: string;
  label: string;
  mastery: number; // 0–1, recency-weighted; a prior of PRIOR for unseen skills
  attempts: number;
}

const PRIOR = 0.4;
const PRIOR_WEIGHT = 1;
const RECENCY = 0.85; // each older attempt counts 85% of the next newer one

// Benign twins and ops cases train the same judgement as the attacks they
// resemble, so they count toward their twin's tactics — or, without a twin,
// the tactic their alert category is about.
const CATEGORY_TACTIC: Record<Category, Tactic> = {
  phishing: 'initial-access',
  identity: 'credential-access',
  malware: 'execution',
  recon: 'discovery',
  privesc: 'privilege-escalation',
  exfil: 'exfiltration',
  lateral: 'lateral-movement',
  persistence: 'persistence',
  c2: 'command-and-control',
  ransomware: 'impact',
};

export function skillTactics(t: CaseTemplate): Tactic[] {
  if (t.tactics.length) return t.tactics;
  const twin = t.twin ? templateById(t.twin) : ALL_TEMPLATES.find((x) => x.twin === t.id);
  return twin?.tactics.length ? twin.tactics : [CATEGORY_TACTIC[t.category]];
}

function skillKeys(t: CaseTemplate): { kind: SkillKind; key: string }[] {
  return [
    ...t.cysaDomains.map((key) => ({ kind: 'domain' as const, key })),
    ...skillTactics(t).map((key) => ({ kind: 'tactic' as const, key })),
    { kind: 'category' as const, key: t.category },
  ];
}

function label(kind: SkillKind, key: string): string {
  if (kind === 'domain') return cysaLabel(key);
  if (kind === 'tactic') return TACTIC_LABELS[key as Tactic] ?? key;
  return CATEGORY_LABELS[key as Category] ?? key;
}

export function skills(attempts: readonly Attempt[]): Skill[] {
  const acc = new Map<string, { kind: SkillKind; key: string; sum: number; weight: number; n: number }>();
  const touch = (kind: SkillKind, key: string) => {
    const id = `${kind}:${key}`;
    let a = acc.get(id);
    if (!a) acc.set(id, (a = { kind, key, sum: PRIOR * PRIOR_WEIGHT, weight: PRIOR_WEIGHT, n: 0 }));
    return a;
  };
  for (const d of CYSA_DOMAINS) touch('domain', d.id);
  const tactics = new Set(ALL_TEMPLATES.flatMap(skillTactics));
  for (const t of TACTIC_ORDER) if (tactics.has(t)) touch('tactic', t);
  for (const c of new Set(ALL_TEMPLATES.map((t) => t.category))) touch('category', c);

  // Newest attempts weigh most.
  const ordered = [...attempts].sort((a, b) => b.day - a.day);
  const seenPerSkill = new Map<string, number>();
  for (const at of ordered) {
    const t = templateById(at.templateId);
    if (!t) continue;
    for (const { kind, key } of skillKeys(t)) {
      const a = touch(kind, key);
      const id = `${kind}:${key}`;
      const k = seenPerSkill.get(id) ?? 0;
      seenPerSkill.set(id, k + 1);
      const w = RECENCY ** k;
      a.sum += w * Math.max(0, Math.min(100, at.percent)) / 100;
      a.weight += w;
      a.n += 1;
    }
  }
  return [...acc.values()].map((a) => ({ kind: a.kind, key: a.key, label: label(a.kind, a.key), mastery: a.sum / a.weight, attempts: a.n }));
}

export function weakest(all: readonly Skill[], kind: SkillKind, n = 3): Skill[] {
  return all
    .filter((s) => s.kind === kind)
    .sort((a, b) => a.mastery - b.mastery || a.attempts - b.attempts || (a.key < b.key ? -1 : 1))
    .slice(0, n);
}

export interface Suggestion {
  templateId: string;
  reason: 'due' | 'new' | 'weak' | 'review';
  detail: string;
}

export interface StudyOptions {
  exclude?: readonly string[];
  // Don't serve tier-3 cases to a brand-new analyst.
  gateDifficulty?: boolean;
}

const DIFFICULTY_GATE: Record<Difficulty, number> = { tier1: 0, tier2: 3, tier3: 8 };

export function nextStudyCase(cards: Readonly<Record<string, Card>>, attempts: readonly Attempt[], today: number, rng: Rng, opts: StudyOptions = {}): Suggestion {
  const exclude = new Set(opts.exclude ?? []);
  const due = Object.values(cards)
    .filter((c) => isDue(c, today) && !exclude.has(c.templateId) && templateById(c.templateId))
    .sort((a, b) => a.due - b.due || a.lastPercent - b.lastPercent || (a.templateId < b.templateId ? -1 : 1));
  if (due.length) {
    const c = due[0];
    const overdue = today - c.due;
    return { templateId: c.templateId, reason: 'due', detail: overdue > 0 ? `Review overdue by ${overdue} day${overdue === 1 ? '' : 's'} (last score ${c.lastPercent}%).` : `Review due today (last score ${c.lastPercent}%).` };
  }

  const all = skills(attempts);
  const byId = new Map(all.map((s) => [`${s.kind}:${s.key}`, s]));
  const gate = opts.gateDifficulty ?? true;
  const pool = ALL_TEMPLATES.filter((t) => !exclude.has(t.id) && (!gate || attempts.length >= DIFFICULTY_GATE[t.difficulty]));
  const candidates = (pool.length ? pool : ALL_TEMPLATES.filter((t) => !exclude.has(t.id))).map((t) => {
    const keys = skillKeys(t).map(({ kind, key }) => byId.get(`${kind}:${key}`)!);
    // Half the average gap, half the single weakest skill the case trains:
    // one glaring gap should pull a case forward even if the rest is solid.
    const minMastery = Math.min(...keys.map((k) => k.mastery));
    const weakness = 0.5 * (1 - keys.reduce((s, k) => s + k.mastery, 0) / keys.length) + 0.5 * (1 - minMastery);
    const card = cards[t.id];
    let weight = Math.exp(4 * weakness);
    if (!card) weight *= 2;
    else if (card.last === today) weight *= 0.05;
    else weight *= 0.3;
    const weakestKey = [...keys].sort((a, b) => a.mastery - b.mastery)[0];
    return { t, weight, card, weakestKey };
  });
  if (!candidates.length) throw new Error('No study candidates');
  const pick = rng.pickWeighted(candidates.map((c) => ({ value: c, weight: c.weight })));
  const pct = Math.round(pick.weakestKey.mastery * 100);
  if (!pick.card) {
    return { templateId: pick.t.id, reason: pick.weakestKey.attempts ? 'weak' : 'new', detail: pick.weakestKey.attempts ? `New case in a weak area: ${pick.weakestKey.label} (${pct}%).` : `New ground: ${pick.weakestKey.label}.` };
  }
  return { templateId: pick.t.id, reason: 'review', detail: `Early review — strengthens ${pick.weakestKey.label} (${pct}%).` };
}

export interface StudyPlan {
  dueToday: string[];
  overdue: number;
  upcoming: { day: number; count: number }[];
  weakest: { domain: Skill[]; tactic: Skill[]; category: Skill[] };
  skills: Skill[];
  seen: number;
  total: number;
  streak: number;
}

export function streak(attempts: readonly Attempt[], today: number): number {
  const days = new Set(attempts.map((a) => a.day));
  let d = days.has(today) ? today : today - 1;
  let n = 0;
  while (days.has(d)) {
    n++;
    d--;
  }
  return n;
}

export function studyPlan(cards: Readonly<Record<string, Card>>, attempts: readonly Attempt[], today: number): StudyPlan {
  const list = Object.values(cards).filter((c) => templateById(c.templateId));
  const due = list.filter((c) => isDue(c, today)).sort((a, b) => a.due - b.due || (a.templateId < b.templateId ? -1 : 1));
  const upcoming = new Map<number, number>();
  for (const c of list) if (c.due > today && c.due <= today + 14) upcoming.set(c.due, (upcoming.get(c.due) ?? 0) + 1);
  const all = skills(attempts);
  return {
    dueToday: due.map((c) => c.templateId),
    overdue: due.filter((c) => c.due < today).length,
    upcoming: [...upcoming].sort((a, b) => a[0] - b[0]).map(([day, count]) => ({ day, count })),
    weakest: { domain: weakest(all, 'domain', 2), tactic: weakest(all, 'tactic'), category: weakest(all, 'category') },
    skills: all,
    seen: new Set(attempts.map((a) => a.templateId).filter((id) => templateById(id))).size,
    total: ALL_TEMPLATES.length,
    streak: streak(attempts, today),
  };
}
