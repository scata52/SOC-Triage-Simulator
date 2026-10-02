import { describe, expect, it } from 'vitest';
import { addQueryHistory, asStudyAttempts, coerceProfile, dayNumber, defaultProfile, finishShift, migrateV1, nextShiftNumber, rankFor, recordAttempt, moveToNewOrganisation, recordVulnAttempt, recentShiftTemplates, startShift, MAX_ATTEMPTS, type Profile } from '../src/state/profile.ts';
import { exportProfile, importProfile, loadProfile, saveProfile, V1_KEY, V2_KEY, type KeyValueStore } from '../src/state/storage.ts';
import { buildPracticeCase } from '../src/core/cases/scenario.ts';
import { emptyVerdict, gradeCase, perfectVerdict } from '../src/core/grading/grade.ts';
import { scoreShift, CLEAN_SHIFT_BONUS } from '../src/core/shift/score.ts';
import { startCampaign } from '../src/core/campaign/campaign.ts';
import { buildVulnScenario } from '../src/core/vuln/scenario.ts';
import { VULN_POINTS, gradeVulnCase, perfectVulnSubmission } from '../src/core/vuln/grade.ts';
import { DIFFICULTY_MULTIPLIER } from '../src/core/grading/grade.ts';
import { studyPlan, nextStudyCase, FULL_STUDY_POOL } from '../src/core/study/scheduler.ts';
import { review } from '../src/core/study/srs.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { createRng } from '../src/core/rng.ts';
import { world } from './helpers/scenario-check.ts';

import { VULN_LINK_TEMPLATE_ID } from '../src/core/shift/vuln-hook.ts';
const NOW = Date.UTC(2026, 9, 1, 12);
const ctx = { now: NOW, tzOffsetMinutes: -120, newWorldSeed: () => 'seed-new' };

class MemoryKV implements KeyValueStore {
  data = new Map<string, string>();
  getItem(k: string) {
    return this.data.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.data.set(k, v);
  }
}

// Shaped like a real v1 export (src/state/store.ts).
const V1 = {
  version: 1,
  analystName: 'Riley',
  xp: 845,
  streak: 3,
  bestStreak: 7,
  records: [
    { caseId: 'identity-password-spray#abc', templateId: 'identity-password-spray', title: 'x', category: 'identity', difficulty: 'tier2', completedAt: NOW - 3 * 86_400_000, score: 80, maxScore: 100, percent: 80, dispositionCorrect: true, xp: 120, truthTechniques: [], matchedTechniques: ['T1110.003'], missedTechniques: [], tactics: ['credential-access'], rubricHits: 1, rubricTotal: 3, cysaDomains: ['1.0'], durationSec: 300 },
    { caseId: 'identity-password-spray#def', templateId: 'identity-password-spray', completedAt: NOW - 86_400_000, percent: 95, dispositionCorrect: true, xp: 140 },
    { caseId: 'retired#1', templateId: 'a-template-that-no-longer-exists', completedAt: NOW, percent: 50 },
    { caseId: 'email-phish-credential#q', templateId: 'email-phish-credential', completedAt: NOW - 2 * 86_400_000, percent: 40, dispositionCorrect: false, xp: 20 },
  ],
  recentTemplateIds: ['identity-password-spray', 'email-phish-credential'],
  dailyDone: ['2026-09-29'],
  settings: { timerEnabled: true, showRubricLive: true },
};

describe('v1 migration', () => {
  it('carries progress over and replays history into study cards', () => {
    const p = migrateV1(V1, NOW, 'w1', -120);
    expect(p).toMatchObject({ version: 2, analystName: 'Riley', xp: 845, streak: 3, bestStreak: 7, worldSeed: 'w1', dailyDone: ['2026-09-29'] });
    expect(p.attempts.map((a) => a.templateId)).toEqual(['identity-password-spray', 'email-phish-credential', 'identity-password-spray']);
    expect(p.attempts.every((a) => a.legacy && a.mode === 'practice')).toBe(true);
    expect(p.attempts[0]).toMatchObject({ id: 'v1:identity-password-spray#abc', seed: 'abc', percent: 80, durationSec: 300, category: 'identity' });
    expect(p.cards['identity-password-spray'].reps).toBe(2);
    expect(p.cards['email-phish-credential'].reps).toBe(0);
    expect(p.migratedFromV1).toEqual({ records: 3, at: NOW });
    expect(p.settings).toMatchObject({ timerEnabled: true, showRubricLive: true, sound: false });
  });

  it('computes local day numbers', () => {
    // 23:30 UTC is already tomorrow at UTC+2 (offset −120 minutes).
    const t = Date.UTC(2026, 9, 1, 23, 30);
    expect(dayNumber(t, -120)).toBe(dayNumber(t, 0) + 1);
  });
});

describe('storage', () => {
  it('prefers v2, migrates v1 without touching it, and starts fresh otherwise', () => {
    const kv = new MemoryKV();
    expect(loadProfile(kv, ctx).source).toBe('new');
    kv.setItem(V1_KEY, JSON.stringify(V1));
    const migrated = loadProfile(kv, ctx);
    expect(migrated.source).toBe('v1-migrated');
    expect(migrated.profile.analystName).toBe('Riley');
    expect(saveProfile(kv, migrated.profile)).toBe(true);
    expect(JSON.parse(kv.getItem(V1_KEY)!)).toEqual(V1);
    const again = loadProfile(kv, ctx);
    expect(again.source).toBe('v2');
    expect(again.profile).toEqual(migrated.profile);
  });

  it('survives a malformed v1 profile', () => {
    const kv = new MemoryKV();
    kv.setItem(V1_KEY, JSON.stringify({ version: 1, records: [null, 5, 'x', { templateId: 'identity-password-spray', percent: 70 }] }));
    const r = loadProfile(kv, ctx);
    expect(r.source).toBe('v1-migrated');
    expect(r.profile.attempts).toHaveLength(1);
  });

  it('backs up an unreadable v2 blob instead of overwriting it', () => {
    const kv = new MemoryKV();
    kv.setItem(V2_KEY, '{not json');
    const r = loadProfile(kv, ctx);
    expect(r.source).toBe('recovered');
    expect(kv.getItem(`${V2_KEY}:unreadable:${NOW}`)).toBe('{not json');
  });

  it('runs in memory when storage is unavailable or throws', () => {
    expect(loadProfile(null, ctx).source).toBe('memory');
    const throwing: KeyValueStore = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
    };
    expect(loadProfile(throwing, ctx).profile.version).toBe(2);
    expect(saveProfile(throwing, defaultProfile(NOW, 'x'))).toBe(false);
  });

  it('round-trips export/import and accepts v1 exports', () => {
    const p = { ...defaultProfile(NOW, 'w'), analystName: 'Sam' };
    expect(importProfile(exportProfile(p), ctx)).toEqual(p);
    expect(importProfile(JSON.stringify(V1), ctx)?.analystName).toBe('Riley');
    expect(importProfile('{"version":3}', ctx)).toBeNull();
    expect(importProfile('nope', ctx)).toBeNull();
  });

  it('fills settings added after a profile was saved', () => {
    const old = defaultProfile(NOW, 'w') as unknown as Record<string, unknown>;
    old.settings = { theme: 'dark' };
    const p = coerceProfile(old, { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!;
    expect(p.settings).toMatchObject({ theme: 'dark', sound: false, defaultBudget: 30 });
  });
});

describe('profile transitions', () => {
  const w = world('profile');
  const s = buildPracticeCase(w, 'identity-password-spray', 'p1');
  const c = s.cases[0];

  it('records attempts: XP, streak, card, recents', () => {
    let p = defaultProfile(NOW, w.seed);
    const good = gradeCase(c, perfectVerdict(c));
    p = recordAttempt(p, { c, grade: good, verdict: perfectVerdict(c), mode: 'practice', now: NOW, day: 100, durationSec: 240, dailySeed: 'd1' }).profile;
    expect(p.xp).toBe(good.xp);
    expect(p.streak).toBe(1);
    expect(p.cards[c.templateId]).toMatchObject({ reps: 1, due: 101 });
    expect(p.dailyDone).toEqual(['d1']);
    const bad = gradeCase(c, emptyVerdict());
    const r = recordAttempt(p, { c, grade: bad, verdict: emptyVerdict(), mode: 'study', now: NOW, day: 101, durationSec: null });
    expect(r.profile.streak).toBe(0);
    expect(r.profile.bestStreak).toBe(1);
    expect(r.record).toMatchObject({ mode: 'study', percent: 0, evidenceFound: 0, evidenceTotal: c.evidence.length, tactics: c.truth.tactics });
    expect(r.profile.recentTemplateIds).toEqual([c.templateId]);
  });

  it('caps stored attempts', () => {
    let p = defaultProfile(NOW, w.seed);
    const g = gradeCase(c, perfectVerdict(c));
    p = { ...p, attempts: Array.from({ length: MAX_ATTEMPTS }, () => recordAttempt(p, { c, grade: g, verdict: perfectVerdict(c), mode: 'practice', now: NOW, day: 1, durationSec: null }).record) };
    p = recordAttempt(p, { c, grade: g, verdict: perfectVerdict(c), mode: 'practice', now: NOW, day: 2, durationSec: null }).profile;
    expect(p.attempts).toHaveLength(MAX_ATTEMPTS);
    expect(p.attempts.at(-1)!.day).toBe(2);
  });

  it('runs a shift from start to handover', () => {
    let p = defaultProfile(NOW, w.seed);
    expect(nextShiftNumber(p)).toBe(0);
    p = startShift(p, 0, 30, NOW);
    expect(p.activeShift).toMatchObject({ number: 0, budget: 30, elapsedSec: 0 });
    const result = scoreShift([c], [{ alertId: c.alertId, verdict: perfectVerdict(c), atSec: 30 }]);
    const campaign = startCampaign(w, 'c1');
    const finished = finishShift(p, result, { now: NOW + 1, campaign: { ...campaign, status: 'evicted' } });
    expect(finished.activeShift).toBeNull();
    expect(finished.xp).toBe(CLEAN_SHIFT_BONUS);
    expect(finished.shifts[0]).toMatchObject({ number: 0, score: 100, clean: true });
    expect(nextShiftNumber(finished)).toBe(1);
    // Only an active → ended transition counts as a finished campaign.
    expect(finished.campaignsFinished).toEqual([]);
    const withActive = { ...startShift(p, 0, 30, NOW), campaign };
    const ended = finishShift(withActive, result, { now: NOW, campaign: { ...campaign, status: 'breached' } });
    expect(ended.campaignsFinished).toEqual([{ actorId: campaign.actorId, status: 'breached', shifts: 0 }]);
  });

  it('keeps a de-duplicated query history', () => {
    let p = defaultProfile(NOW, 'w');
    p = addQueryHistory(p, 'SigninLogs | take 5');
    p = addQueryHistory(p, 'DnsEvents');
    p = addQueryHistory(p, 'SigninLogs | take 5');
    p = addQueryHistory(p, '   ');
    expect(p.queryHistory).toEqual(['SigninLogs | take 5', 'DnsEvents']);
  });

  it('ranks by XP', () => {
    expect(rankFor(0).current.name).toBe('Trainee');
    expect(rankFor(300).current.name).toBe('Tier 1 Analyst');
    expect(rankFor(600).progress).toBeCloseTo(0.5, 5);
    expect(rankFor(99999)).toMatchObject({ next: null, progress: 1 });
  });
});

describe('vulnerability attempts', () => {
  const w = world('profile');
  const cases = ['vm-kev-internal', 'vm-backport-fp'].map((templateId) => {
    const c = buildVulnScenario({ worldSeed: w.seed, templateId, seed: 'p1', world: w }).case;
    // a note that hits every rubric item's first keyword
    const submission = { ...perfectVulnSubmission(c), notes: c.rubric.map((r) => r.keywords[0]).join(' ') };
    return { c, submission, grade: gradeVulnCase(c, submission) };
  });
  const input = (i: number, extra: { day?: number } = {}) => ({ c: cases[i].c, grade: cases[i].grade, submission: cases[i].submission, now: NOW, day: extra.day ?? 100, durationSec: 321 });

  // a profile that already has SOC history, so "untouched" means something
  const soc = buildPracticeCase(w, 'identity-password-spray', 'p1').cases[0];
  function withSocHistory(): Profile {
    const g = gradeCase(soc, perfectVerdict(soc));
    return recordAttempt(defaultProfile(NOW, w.seed), { c: soc, grade: g, verdict: perfectVerdict(soc), mode: 'practice', now: NOW, day: 99, durationSec: 60, dailySeed: 'd1' }).profile;
  }

  it('records mode vuln and category vulnmgmt', () => {
    for (const [i, x] of cases.entries()) {
      expect(x.grade.rubricHits.length).toBeGreaterThan(0);
      const r = recordVulnAttempt(defaultProfile(NOW, w.seed), input(i)).record;
      expect(r).toMatchObject({
        id: x.c.id,
        templateId: x.c.templateId,
        seed: 'p1',
        mode: 'vuln',
        completedAt: NOW,
        day: 100,
        percent: x.grade.percent,
        score: x.grade.score,
        dispositionCorrect: x.grade.percent >= 70,
        xp: x.grade.xp,
        hintsUsed: 0,
        durationSec: 321,
        matchedTechniques: [],
        missedTechniques: [],
        evidenceFound: 0,
        evidenceTotal: 0,
        category: 'vulnmgmt',
        difficulty: x.c.difficulty,
        tactics: [],
        cysaDomains: x.c.cysaDomains,
      });
      expect(Object.keys(r.components).sort()).toEqual(Object.keys(VULN_POINTS).map((k) => 'vuln-' + k).sort());
      for (const comp of x.grade.components) expect(r.components[('vuln-' + comp.id) as 'vuln-decisions']).toBe(comp.earned);
      expect(r.vuln).toEqual({
        objectives: x.c.objectives,
        evidenceFound: x.grade.evidence.filter((e) => e.found).length,
        evidenceTotal: x.grade.evidence.length,
        decisions: x.c.findings.map((f) => ({ findingId: f.findingId, truth: f.truth.decision, given: f.truth.decision, mustNotMiss: f.mustNotMiss, verdict: x.grade.findings.find((g) => g.findingId === f.findingId)!.decision.verdict })),
      });
      expect(r.vuln!.evidenceTotal).toBeGreaterThan(0);
      expect(r.vuln!.decisions).toHaveLength(x.c.findings.length);
    }
    expect(cases[0].c.difficulty).toBe('tier1');
    expect(cases[1].c.difficulty).toBe('tier2');
  });

  it('adds the case XP to the shared total', () => {
    for (const [i, x] of cases.entries()) {
      expect(x.grade.xp).toBe(Math.round(x.grade.score * DIFFICULTY_MULTIPLIER[x.c.difficulty] + 3 * x.grade.rubricHits.length));
      const p0 = { ...defaultProfile(NOW, w.seed), xp: 290 };
      const p1 = recordVulnAttempt(p0, input(i)).profile;
      expect(p1.xp).toBe(290 + x.grade.xp);
      expect(rankFor(p0.xp).current.name).toBe('Trainee');
      expect(rankFor(p1.xp).current.name).toBe('Tier 1 Analyst');
    }
  });

  it('leaves streaks, recent templates and daily flags untouched, and reviews its own card', () => {
    const p0 = withSocHistory();
    const p1 = recordVulnAttempt(p0, input(0)).profile;
    // the SOC cards are as they were; the vuln template gains a card of its own (keyed by template id)
    const { [cases[0].c.templateId]: vulnCard, ...otherCards } = p1.cards;
    expect(otherCards).toEqual(p0.cards);
    expect(vulnCard).toEqual(review(undefined, cases[0].c.templateId, cases[0].grade.percent, 100));
    expect(p1.streak).toBe(p0.streak);
    expect(p1.bestStreak).toBe(p0.bestStreak);
    expect(p1.recentTemplateIds).toEqual(p0.recentTemplateIds);
    expect(p1.dailyDone).toEqual(p0.dailyDone);
    expect(p1.attempts).toHaveLength(p0.attempts.length + 1);
    expect(p1.attempts.slice(0, -1)).toEqual(p0.attempts);
    // a failed vuln attempt does not break the SOC streak either
    const bad = { ...cases[0].grade, percent: 10 };
    expect(recordVulnAttempt(p0, { ...input(0), grade: bad }).profile.streak).toBe(p0.streak);
  });

  it('vuln attempts join the study attempts; the default SOC pool ignores their cards', () => {
    const p0 = withSocHistory();
    const p1 = recordVulnAttempt(recordVulnAttempt(p0, input(0, { day: 100 })).profile, input(1, { day: 101 })).profile;
    expect(asStudyAttempts(p1)).toEqual([
      ...asStudyAttempts(p0),
      ...cases.map((x, i) => ({ templateId: x.c.templateId, percent: x.grade.percent, day: 100 + i, mode: 'vuln', correct: x.grade.percent >= 70 })),
    ]);
    // without the full pool the SOC plan (due list, counts, upcoming) is as it was
    const a = studyPlan(p0.cards, asStudyAttempts(p0), 102);
    const b = studyPlan(p1.cards, asStudyAttempts(p1), 102);
    // (the day streak and the skills do move: vuln days count as study days)
    expect({ ...b, skills: undefined, weakest: undefined, streak: undefined }).toEqual({ ...a, skills: undefined, weakest: undefined, streak: undefined });
    expect(b.streak).toBeGreaterThan(a.streak);
    expect(nextStudyCase(p1.cards, asStudyAttempts(p1), 102, createRng('vuln-study')).templateId.startsWith('vm-')).toBe(false);
    // with the full pool the vuln cards and attempts count
    const full = studyPlan(p1.cards, asStudyAttempts(p1), 102, { pool: FULL_STUDY_POOL });
    expect(full.seen).toBe(a.seen + 2);
    expect(full.total).toBe(a.total + VULN_TEMPLATES.length);
  });

  it('a vuln attempt creates its card, a repeat updates it, and each twin has its own', () => {
    const p1 = recordVulnAttempt(defaultProfile(NOW, w.seed), input(0, { day: 100 })).profile;
    const id0 = cases[0].c.templateId;
    expect(Object.keys(p1.cards)).toEqual([id0]);
    expect(p1.cards[id0]).toMatchObject({ templateId: id0, lastPercent: cases[0].grade.percent, last: 100, reps: 1 });
    const p2 = recordVulnAttempt(p1, input(0, { day: 101 })).profile;
    expect(Object.keys(p2.cards)).toEqual([id0]);
    expect(p2.cards[id0]).toEqual(review(p1.cards[id0], id0, cases[0].grade.percent, 101));
    expect(p2.cards[id0].last).toBe(101);
    const p3 = recordVulnAttempt(p2, input(1, { day: 101 })).profile;
    expect(Object.keys(p3.cards).sort()).toEqual([id0, cases[1].c.templateId].sort());
    expect(p3.cards[id0]).toEqual(p2.cards[id0]);
    // a failed attempt lapses the card
    const bad = recordVulnAttempt(p3, { ...input(0, { day: 105 }), grade: { ...cases[0].grade, percent: 10 } }).profile;
    expect(bad.cards[id0]).toMatchObject({ lapses: 1, lastPercent: 10 });
  });

  it('stores the grade verdict of every decision, and coerces old records without it', () => {
    const r = recordVulnAttempt(defaultProfile(NOW, w.seed), input(0)).record;
    expect(r.vuln!.decisions.every((d) => d.verdict === 'exact')).toBe(true);
    // a wrong decision is recorded with its verdict
    const wrong = { ...cases[0].grade, findings: cases[0].grade.findings.map((f, i) => (i === 0 ? { ...f, decision: { ...f.decision, given: 'accept' as const, verdict: 'wrong' as const } } : f)) };
    expect(recordVulnAttempt(defaultProfile(NOW, w.seed), { ...input(0), grade: wrong }).record.vuln!.decisions[0]).toMatchObject({ given: 'accept', verdict: 'wrong' });
    // an old record (before WP4) has no verdict and no card: it loads as it is
    const p = recordVulnAttempt(withSocHistory(), input(0)).profile;
    const old = JSON.parse(JSON.stringify(p)) as Profile;
    for (const a of old.attempts) for (const d of a.vuln?.decisions ?? []) delete d.verdict;
    old.cards = Object.fromEntries(Object.entries(old.cards).filter(([id]) => !id.startsWith('vm-')));
    const back = coerceProfile(JSON.parse(JSON.stringify(old)), { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!;
    expect(back).toEqual(old);
    expect(back.version).toBe(2);
    const vuln = back.attempts.find((a) => a.mode === 'vuln')!;
    expect(vuln.vuln!.decisions.every((d) => d.verdict === undefined)).toBe(true);
    // a profile with no cards field at all (an older v2) still loads with an empty card set
    const noCards = JSON.parse(JSON.stringify(old)) as Record<string, unknown>;
    delete noCards.cards;
    expect(coerceProfile(noCards, { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!.cards).toEqual({});
  });

  it('SOC component stats ignore vuln records', () => {
    const p1 = recordVulnAttempt(withSocHistory(), input(0)).profile;
    const r = p1.attempts.at(-1)!;
    const socIds = new Set<string>(gradeCase(soc, perfectVerdict(soc)).components.map((x) => x.id));
    for (const k of Object.keys(r.components)) {
      expect(socIds.has(k)).toBe(false);
      expect(k.startsWith('vuln-')).toBe(true);
    }
    expect(r.evidenceFound).toBe(0);
    expect(r.evidenceTotal).toBe(0);
  });

  it('coerces an old v2 profile unchanged', () => {
    const old = withSocHistory();
    const back = coerceProfile(JSON.parse(JSON.stringify(old)), { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!;
    expect(back).toEqual(old);
    expect(back.attempts.every((a) => a.vuln === undefined)).toBe(true);
    // the v1 migration still produces practice attempts only
    expect(migrateV1(V1, NOW, 'w1', -120).attempts.every((a) => a.mode === 'practice' && a.vuln === undefined)).toBe(true);
  });

  it('a profile with vuln attempts survives export and import', () => {
    const p = recordVulnAttempt(recordVulnAttempt(withSocHistory(), input(0)).profile, input(1, { day: 101 })).profile;
    const back = importProfile(exportProfile(p), ctx)!;
    expect(back).toEqual(p);
    expect(back.attempts.filter((a) => a.mode === 'vuln')).toHaveLength(2);
    const kv = new MemoryKV();
    expect(saveProfile(kv, p)).toBe(true);
    expect(loadProfile(kv, ctx).profile).toEqual(p);
  });

  it('caps stored attempts like SOC attempts', () => {
    let p = defaultProfile(NOW, w.seed);
    const r = recordVulnAttempt(p, input(0)).record;
    p = { ...p, attempts: Array.from({ length: MAX_ATTEMPTS }, () => r) };
    p = recordVulnAttempt(p, input(0, { day: 7 })).profile;
    expect(p.attempts).toHaveLength(MAX_ATTEMPTS);
    expect(p.attempts.at(-1)!.day).toBe(7);
  });
});

// ---------------------------------------------------------------------------
// The continuity ledger (DESIGN section 8): written by recordVulnAttempt, consumed by startShift.

describe('vulnerability continuity ledger', () => {
  const w = world('profile');
  const base = defaultProfile(NOW, w.seed);
  const caseFor = (seed: string, templateId = 'vm-kev-internal') => buildVulnScenario({ worldSeed: w.seed, templateId, seed, world: w }).case;
  // the answer of an analyst who dismisses one real must-not-miss finding on a shared-world host, everything else right
  const dismissing = (c: ReturnType<typeof caseFor>) => {
    const target = c.findings.find((f) => f.mustNotMiss && f.truth.decision !== 'false-positive' && f.sharedHost)!;
    const s = perfectVulnSubmission(c);
    const submission = { ...s, answers: { ...s.answers, [target.findingId]: { ...s.answers[target.findingId], decision: 'false-positive' as const, schedule: 'none' as const } } };
    return { target, submission };
  };
  const attempt = (p: Profile, c: ReturnType<typeof caseFor>, sub = perfectVulnSubmission(c), at = NOW, day = 100) =>
    recordVulnAttempt(p, { c, grade: gradeVulnCase(c, sub), submission: sub, now: at, day, durationSec: 60 });

  it('writes no ledger for an attempt that leaves nothing open', () => {
    const c = caseFor('l1');
    const { profile } = attempt(base, c);
    expect('vulnLedger' in profile).toBe(false);
  });

  it('records an entry for a dismissed real must-not-miss finding', () => {
    const c = caseFor('l2');
    const { target, submission } = dismissing(c);
    const { profile, record } = attempt(base, c, submission, NOW + 5, 123);
    expect(profile.vulnLedger).toEqual([
      {
        id: `${c.id}/${target.findingId}@${NOW + 5}`,
        vulnId: target.vulnId,
        host: target.host,
        decision: 'false-positive',
        schedule: 'none',
        decidedDay: 123,
        caseRef: c.id,
      },
    ]);
    expect(record.id).toBe(c.id);
    // the attempt itself is recorded as any other
    expect(profile.attempts).toHaveLength(1);
    expect(profile.xp).toBe(record.xp);
  });

  it('adds no second unconsumed entry for the same finding, and adds one again once it is consumed', () => {
    const c = caseFor('l3');
    const { submission } = dismissing(c);
    const once = attempt(base, c, submission, NOW, 100).profile;
    const twice = attempt(once, c, submission, NOW + 1000, 101).profile;
    expect(twice.vulnLedger).toHaveLength(1);
    const consumed = { ...once, vulnLedger: once.vulnLedger!.map((e) => ({ ...e, consumed: true })) };
    const again = attempt(consumed, c, submission, NOW + 2000, 102).profile;
    expect(again.vulnLedger).toHaveLength(2);
    expect(again.vulnLedger!.map((e) => !!e.consumed)).toEqual([true, false]);
  });

  it('keeps at most 50 entries across many attempts, dropping consumed ones first', () => {
    let p: Profile = base;
    for (let i = 0; i < 60; i++) {
      const c = caseFor(`cap-${i}`);
      p = attempt(p, c, dismissing(c).submission, NOW + i, 100 + i).profile;
      if (i === 9) p = { ...p, vulnLedger: p.vulnLedger!.map((e, k) => (k < 3 ? { ...e, consumed: true } : e)) };
    }
    expect(p.vulnLedger!.length).toBeLessThanOrEqual(50);
    expect(p.vulnLedger!.length).toBeGreaterThan(30);
    expect(p.vulnLedger!.filter((e) => e.consumed)).toHaveLength(0); // the three consumed ones went first
  });

  describe('startShift', () => {
    const entry = { id: 'e1', vulnId: 'SIMVULN-2026-00007', host: 'APP01', decision: 'accept' as const, schedule: 'none' as const, decidedDay: 90, caseRef: 'vm-kev-internal~z' };
    const hook = { ledgerId: 'e1', host: 'APP01', vulnId: entry.vulnId, decidedDay: 90, caseRef: entry.caseRef, decision: entry.decision, schedule: entry.schedule, seed: 's:vuln:e1' };
    const withLedger: Profile = { ...base, vulnLedger: [entry, { ...entry, id: 'e2', vulnId: 'SIMVULN-2026-00008' }] };

    it('behaves as before without a hook (string or options argument)', () => {
      const old = { number: 2, budget: 30 as const, startedAt: NOW, elapsedSec: 0, campaignAlertId: undefined, drafts: {}, submissions: [] };
      expect(startShift(base, 2, 30, NOW).activeShift).toEqual(old);
      expect(startShift(base, 2, 30, NOW, 'A4').activeShift).toEqual({ ...old, campaignAlertId: 'A4' });
      expect(startShift(base, 2, 30, NOW, { campaignAlertId: 'A4' }).activeShift).toEqual({ ...old, campaignAlertId: 'A4' });
      expect(startShift(base, 2, 30, NOW, { vulnHook: null }).activeShift).toEqual(old);
      expect('vulnHook' in startShift(withLedger, 2, 30, NOW, { vulnHook: null }).activeShift!).toBe(false);
      expect(startShift(withLedger, 2, 30, NOW, { vulnHook: null }).vulnLedger).toEqual(withLedger.vulnLedger);
    });

    it('stores the hook and consumes exactly its entry, purely', () => {
      const frozen = JSON.stringify(withLedger);
      const p = startShift(withLedger, 2, 30, NOW, { campaignAlertId: 'A1', vulnHook: hook });
      expect(p.activeShift).toMatchObject({ number: 2, campaignAlertId: 'A1', vulnHook: hook });
      expect(p.vulnLedger).toEqual([{ ...entry, consumed: true }, { ...entry, id: 'e2', vulnId: 'SIMVULN-2026-00008' }]);
      expect(JSON.stringify(withLedger)).toBe(frozen);
    });

    it('consumes the entry named by hook.ledgerId even when it is not the first unconsumed one', () => {
      const three: Profile = { ...base, vulnLedger: [entry, { ...entry, id: 'e2', vulnId: 'SIMVULN-2026-00008' }, { ...entry, id: 'e3', vulnId: 'SIMVULN-2026-00009' }] };
      const p = startShift(three, 2, 30, NOW, { vulnHook: { ...hook, ledgerId: 'e2' } });
      expect(p.vulnLedger!.map((e) => [e.id, !!e.consumed])).toEqual([['e1', false], ['e2', true], ['e3', false]]);
    });

    it('does not hand the entry back when the shift ends or is dropped', () => {
      const p = startShift(withLedger, 2, 30, NOW, { vulnHook: hook });
      const dropped = { ...p, activeShift: null };
      expect(dropped.vulnLedger![0].consumed).toBe(true);
      const finished = finishShift(p, scoreShift([], []), { now: NOW + 1, campaign: null });
      expect(finished.vulnLedger![0].consumed).toBe(true);
      expect(finished.activeShift).toBeNull();
    });

    it('moving to a new organisation clears the ledger and the shift', () => {
      const p = startShift(withLedger, 2, 30, NOW, { vulnHook: hook });
      const moved = moveToNewOrganisation(p, 'seed-new');
      expect('vulnLedger' in moved).toBe(false);
      expect(moved).toMatchObject({ worldSeed: 'seed-new', campaign: null, activeShift: null });
      expect(moved.attempts).toBe(p.attempts);
    });
  });

  describe('coerceProfile', () => {
    const goodEntry = { id: 'e1', vulnId: 'SIMVULN-2026-00007', host: 'APP01', decision: 'accept', schedule: 'none', decidedDay: 90, caseRef: 'vm-kev-internal~z' };
    const goodHook = { ledgerId: 'e1', host: 'APP01', vulnId: goodEntry.vulnId, decidedDay: 90, caseRef: goodEntry.caseRef, decision: 'accept', schedule: 'none', seed: 's:vuln:e1' };
    const run = (extra: object) => coerceProfile({ ...JSON.parse(JSON.stringify(base)), ...extra }, { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!;

    it('an old profile has no ledger and keeps working', () => {
      const p = run({});
      expect('vulnLedger' in p).toBe(false);
      expect(p.activeShift).toBeNull();
    });

    it('keeps valid entries, drops malformed ones, and caps the ledger', () => {
      const p = run({ vulnLedger: [goodEntry, { ...goodEntry, id: 'bad', vulnId: 'CVE-2021-44228' }, 'x', null, { ...goodEntry, id: 'e2', consumed: true }] });
      expect(p.vulnLedger!.map((e) => e.id)).toEqual(['e1', 'e2']);
      expect(run({ vulnLedger: 'not a list' }).vulnLedger).toBeUndefined();
      expect(run({ vulnLedger: Array.from({ length: 80 }, (_, i) => ({ ...goodEntry, id: `e${i}` })) }).vulnLedger).toHaveLength(50);
    });

    it('keeps a valid hook on the active shift and drops a malformed one so the shift still runs', () => {
      const shift = { number: 1, budget: 30, startedAt: NOW, elapsedSec: 0, drafts: {}, submissions: [] };
      expect(run({ activeShift: { ...shift, vulnHook: goodHook } }).activeShift).toEqual({ ...shift, vulnHook: goodHook });
      for (const bad of [{ ...goodHook, vulnId: 'nope' }, { ...goodHook, seed: '' }, { ...goodHook, decision: 'x' }, 'hook', 3, null, { ledgerId: 'e1' }]) {
        const p = run({ activeShift: { ...shift, vulnHook: bad } });
        expect(p.activeShift).toEqual(shift);
        expect('vulnHook' in p.activeShift!).toBe(false);
      }
      expect(run({ activeShift: shift }).activeShift).toEqual(shift);
    });

    it('dropping a malformed hook also resets the alert-keyed state of the shift', () => {
      const shift = { number: 1, budget: 30, startedAt: NOW, elapsedSec: 40, campaignAlertId: 'A7', drafts: { A1: {} }, submissions: [{ alertId: 'A1' }] };
      const p = run({ activeShift: { ...shift, vulnHook: { ledgerId: 'e1' } } });
      expect(p.activeShift).toEqual({ number: 1, budget: 30, startedAt: NOW, elapsedSec: 40, drafts: {}, submissions: [] });
      expect('campaignAlertId' in p.activeShift!).toBe(false);
      // a valid hook (or none) leaves the state alone
      expect(run({ activeShift: { ...shift, vulnHook: goodHook } }).activeShift).toEqual({ ...shift, vulnHook: goodHook });
      expect(run({ activeShift: shift }).activeShift).toEqual(shift);
    });

    it('survives a JSON round trip of a profile with a ledger and a hook', () => {
      const p = startShift({ ...base, vulnLedger: [goodEntry as never] }, 1, 30, NOW, { vulnHook: goodHook as never });
      const back = coerceProfile(JSON.parse(JSON.stringify(p)), { now: NOW, tzOffsetMinutes: 0, newWorldSeed: 'x' })!;
      expect(back.vulnLedger).toEqual(p.vulnLedger);
      expect(back.activeShift).toEqual(p.activeShift);
    });
  });
});

describe('recentShiftTemplates and the continuity hook', () => {
  const at = (templateId: string, mode: 'shift' | 'campaign' | 'practice') => ({ templateId, percent: 80, day: 1, mode, correct: true, id: templateId, at: NOW }) as never;
  const withAttempts = (list: unknown[]): Profile => ({ ...defaultProfile(NOW, 'seed'), attempts: list as never });

  it('leaves the hook attempt out before slicing, so a real template keeps its place', () => {
    const soc = Array.from({ length: 12 }, (_, i) => at(`soc-${i}`, 'shift'));
    const list = [...soc.slice(0, 6), at(VULN_LINK_TEMPLATE_ID, 'shift'), ...soc.slice(6), at(VULN_LINK_TEMPLATE_ID, 'shift')];
    expect(recentShiftTemplates(withAttempts(list))).toEqual(soc.map((a) => (a as { templateId: string }).templateId));
  });

  it('is unchanged for a profile without a hook attempt', () => {
    const list = [...Array.from({ length: 15 }, (_, i) => at(`soc-${i}`, 'shift')), at('p-1', 'practice'), at('c-1', 'campaign')];
    const out = recentShiftTemplates(withAttempts(list));
    expect(out).toHaveLength(12);
    expect(out[11]).toBe('c-1');
    expect(out[0]).toBe('soc-4');
    expect(recentShiftTemplates(withAttempts([]))).toEqual([]);
  });
});
