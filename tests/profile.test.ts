import { describe, expect, it } from 'vitest';
import { addQueryHistory, asStudyAttempts, coerceProfile, dayNumber, defaultProfile, finishShift, migrateV1, nextShiftNumber, rankFor, recordAttempt, recordVulnAttempt, startShift, MAX_ATTEMPTS, type Profile } from '../src/state/profile.ts';
import { exportProfile, importProfile, loadProfile, saveProfile, V1_KEY, V2_KEY, type KeyValueStore } from '../src/state/storage.ts';
import { buildPracticeCase } from '../src/core/cases/scenario.ts';
import { emptyVerdict, gradeCase, perfectVerdict } from '../src/core/grading/grade.ts';
import { scoreShift, CLEAN_SHIFT_BONUS } from '../src/core/shift/score.ts';
import { startCampaign } from '../src/core/campaign/campaign.ts';
import { buildVulnScenario } from '../src/core/vuln/scenario.ts';
import { VULN_POINTS, gradeVulnCase, perfectVulnSubmission } from '../src/core/vuln/grade.ts';
import { DIFFICULTY_MULTIPLIER } from '../src/core/grading/grade.ts';
import { studyPlan, nextStudyCase } from '../src/core/study/scheduler.ts';
import { createRng } from '../src/core/rng.ts';
import { world } from './helpers/scenario-check.ts';

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
        decisions: x.c.findings.map((f) => ({ findingId: f.findingId, truth: f.truth.decision, given: f.truth.decision, mustNotMiss: f.mustNotMiss })),
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

  it('leaves cards, streaks, recent templates and daily flags untouched', () => {
    const p0 = withSocHistory();
    const p1 = recordVulnAttempt(p0, input(0)).profile;
    expect(p1.cards).toEqual(p0.cards);
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

  it('study plan and suggestion are unchanged by vuln attempts', () => {
    const p0 = withSocHistory();
    const p1 = recordVulnAttempt(recordVulnAttempt(p0, input(0, { day: 100 })).profile, input(1, { day: 101 })).profile;
    expect(asStudyAttempts(p1)).toEqual(asStudyAttempts(p0));
    expect(studyPlan(p1.cards, asStudyAttempts(p1), 102)).toEqual(studyPlan(p0.cards, asStudyAttempts(p0), 102));
    expect(nextStudyCase(p1.cards, asStudyAttempts(p1), 102, createRng('vuln-study'))).toEqual(nextStudyCase(p0.cards, asStudyAttempts(p0), 102, createRng('vuln-study')));
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
