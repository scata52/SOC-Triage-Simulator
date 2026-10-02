import { describe, expect, it } from 'vitest';
import { createRng } from '../src/core/rng.ts';
import { quality, review, type Card } from '../src/core/study/srs.ts';
import { nextStudyCase, skills, skillTactics, streak, studyPlan, weakest, type Attempt } from '../src/core/study/scheduler.ts';
import { ALL_TEMPLATES, templateById } from '../src/core/cases/templates/index.ts';

const attempt = (templateId: string, percent: number, day: number): Attempt => ({ templateId, percent, day, mode: 'study', correct: percent >= 50 });

describe('SM-2', () => {
  it('maps scores to quality with a 70% pass mark', () => {
    expect([100, 95, 90, 85, 72, 70, 69, 50, 30, 0].map(quality)).toEqual([5, 5, 4, 4, 3, 3, 2, 2, 1, 0]);
  });

  it('grows intervals 1 → 6 → ×EF on passes', () => {
    let c = review(undefined, 't', 100, 0);
    expect([c.interval, c.due, c.reps]).toEqual([1, 1, 1]);
    c = review(c, 't', 100, 1);
    expect([c.interval, c.due]).toEqual([6, 7]);
    const ef = c.ef;
    c = review(c, 't', 100, 7);
    expect(c.interval).toBe(Math.round(6 * ef));
    expect(c.ef).toBeGreaterThan(2.5);
  });

  it('does not stretch the interval for a pass before the card is due', () => {
    let c = review(undefined, 't', 100, 10);
    c = review(c, 't', 100, 10);
    c = review(c, 't', 100, 10);
    expect([c.reps, c.interval, c.due]).toEqual([1, 1, 11]);
    expect(c.lastPercent).toBe(100);
    // An early fail still counts.
    c = review(c, 't', 10, 10);
    expect([c.reps, c.lapses, c.due]).toEqual([0, 1, 11]);
  });

  it('lapses on a fail and never drops EF below 1.3', () => {
    let c: Card = review(undefined, 't', 100, 0);
    c = review(c, 't', 100, 1);
    c = review(c, 't', 10, 7);
    expect([c.interval, c.reps, c.lapses, c.due]).toEqual([1, 0, 1, 8]);
    for (let i = 0; i < 20; i++) c = review(c, 't', 0, 8 + i);
    expect(c.ef).toBe(1.3);
  });
});

describe('skills and weakness', () => {
  it('every template trains at least one tactic (benign ones through their twin or category)', () => {
    const orphans = ALL_TEMPLATES.filter((t) => skillTactics(t).length === 0).map((t) => t.id);
    expect(orphans).toEqual([]);
  });

  it('starts every skill at the prior and moves with recent results', () => {
    const fresh = skills([]);
    expect(new Set(fresh.map((s) => s.mastery))).toEqual(new Set([0.4]));
    const t = templateById('identity-password-spray')!;
    const after = skills([attempt(t.id, 20, 1), attempt(t.id, 100, 2)]);
    const cred = after.find((s) => s.kind === 'tactic' && s.key === 'credential-access')!;
    expect(cred.attempts).toBe(2);
    // The newer 100% counts more than the older 20%.
    expect(cred.mastery).toBeGreaterThan((0.4 + 0.2 + 1) / 3);
    expect(weakest(after, 'tactic', 1)[0].key).not.toBe('credential-access');
  });

  it('weighs the newest of several same-day attempts most', () => {
    const t = 'identity-password-spray';
    const sameDay = skills([attempt(t, 0, 5), attempt(t, 100, 5)]).find((s) => s.key === 'identity')!;
    const nextDay = skills([attempt(t, 0, 5), attempt(t, 100, 6)]).find((s) => s.key === 'identity')!;
    expect(sameDay.mastery).toBeCloseTo(nextDay.mastery, 10);
  });

  it('counts a streak of consecutive days', () => {
    const a = [attempt('identity-password-spray', 80, 10), attempt('identity-password-spray', 80, 9), attempt('identity-password-spray', 80, 7)];
    expect(streak(a, 10)).toBe(2);
    expect(streak(a, 11)).toBe(2);
    expect(streak(a, 12)).toBe(0);
  });
});

describe('nextStudyCase', () => {
  it('serves the most overdue card first', () => {
    const cards: Record<string, Card> = {
      a: { ...review(undefined, 'identity-password-spray', 40, 0) },
      b: { ...review(undefined, 'email-phish-credential', 90, 3) },
    };
    cards.a = { ...cards.a, templateId: 'identity-password-spray' };
    cards.b = { ...cards.b, templateId: 'email-phish-credential' };
    const s = nextStudyCase({ [cards.a.templateId]: cards.a, [cards.b.templateId]: cards.b }, [], 10, createRng('x'));
    expect(s).toMatchObject({ templateId: 'identity-password-spray', reason: 'due' });
    expect(s.detail).toMatch(/overdue by 9 days/);
  });

  it('gates hard cases for a new analyst and is deterministic per rng', () => {
    for (let i = 0; i < 40; i++) {
      const s = nextStudyCase({}, [], 0, createRng(`gate-${i}`));
      expect(templateById(s.templateId)!.difficulty).toBe('tier1');
      expect(s.reason).toBe('new');
      expect(nextStudyCase({}, [], 0, createRng(`gate-${i}`))).toEqual(s);
    }
  });

  it('favours weak areas over strong ones', () => {
    // Strong at identity, weak at everything touching exfiltration.
    const attempts: Attempt[] = [];
    const cards: Record<string, Card> = {};
    let day = 0;
    for (const t of ALL_TEMPLATES) {
      const pct = t.category === 'identity' ? 100 : t.category === 'exfil' ? 10 : 60;
      attempts.push(attempt(t.id, pct, day));
      cards[t.id] = review(undefined, t.id, pct, day);
      cards[t.id] = { ...cards[t.id], due: 1000 };
      day++;
    }
    const counts = { identity: 0, exfil: 0 };
    for (let i = 0; i < 400; i++) {
      const s = nextStudyCase(cards, attempts, day, createRng(`weak-${i}`));
      const cat = templateById(s.templateId)!.category;
      if (cat === 'identity' || cat === 'exfil') counts[cat]++;
    }
    const perTemplate = (cat: string) => ALL_TEMPLATES.filter((t) => t.category === cat).length;
    expect(counts.exfil / perTemplate('exfil')).toBeGreaterThan((2 * counts.identity) / perTemplate('identity'));
  });

  it('builds a study plan', () => {
    const cards = { 'identity-password-spray': review(undefined, 'identity-password-spray', 90, 5) };
    const plan = studyPlan(cards, [attempt('identity-password-spray', 90, 5)], 5);
    expect(plan.dueToday).toEqual([]);
    expect(plan.upcoming).toEqual([{ day: 6, count: 1 }]);
    expect(plan.seen).toBe(1);
    expect(plan.total).toBe(ALL_TEMPLATES.length);
    expect(plan.streak).toBe(1);
    expect(plan.weakest.tactic.map((s) => s.key)).not.toContain('credential-access');
  });
});

import { FULL_STUDY_POOL, SOC_STUDY_POOL, skillIndex, studyTemplateById, studyWeight, type Skill, type StudyTemplate } from '../src/core/study/scheduler.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { resolveVulnTemplate, vulnCaseTypes, vulnSeedFor } from '../src/core/vuln/worklist.ts';

// ---------------------------------------------------------------- WP4: vulnerability integration

describe('objective skills and the study pool', () => {
  const vulnT = (id: string) => studyTemplateById(id)!;
  const withObjective = (key: string) => FULL_STUDY_POOL.filter((t) => t.objectives.includes(key));
  const v = (id: string, percent: number, day: number): Attempt => ({ templateId: id, percent, day, mode: 'vuln', correct: percent >= 70 });

  it('objective skills start at the prior and move with vuln attempts', () => {
    const fresh = skills([]);
    expect(fresh.filter((s) => s.kind === 'objective').map((s) => s.key)).toEqual(['2.1', '2.2', '2.3', '2.4', '2.5', '4.1']);
    expect(new Set(fresh.filter((s) => s.kind === 'objective').map((s) => s.mastery))).toEqual(new Set([0.4]));
    expect(fresh.find((s) => s.kind === 'objective' && s.key === '2.3')!.label).toBe('2.3 Prioritizing vulnerabilities');
    const t = vulnT('vm-kev-internal');
    expect(t.objectives).toContain('2.3');
    const after = skills([v(t.id, 20, 1), v(t.id, 100, 2)]);
    const o = after.find((s) => s.kind === 'objective' && s.key === '2.3')!;
    expect(o.attempts).toBe(2);
    expect(o.mastery).toBeGreaterThan((0.4 + 0.2 + 1) / 3); // newest counts more
    expect(after.find((s) => s.kind === 'domain' && s.key === '2.0')!.attempts).toBe(2);
    expect(after.find((s) => s.kind === 'category' && s.key === 'vulnmgmt')!.attempts).toBe(2);
    // an objective the case does not train is untouched
    const untouched = ['2.1', '2.2', '2.3', '2.4', '2.5', '4.1'].filter((k) => !t.objectives.includes(k));
    for (const k of untouched) expect(after.find((s) => s.kind === 'objective' && s.key === k)!.attempts).toBe(0);
    // SOC attempts never touch an objective
    const soc = skills([attempt('identity-password-spray', 100, 1)]);
    expect(soc.filter((s) => s.kind === 'objective').every((s) => s.attempts === 0)).toBe(true);
  });

  it('the weight of a case rises when an objective it trains is weak, the rest fixed', () => {
    const target = FULL_STUDY_POOL.find((t) => t.kind === 'vuln' && t.objectives.includes('2.4'))!;
    const objectiveOnly = (mastery: number) => skills([]).map((s) => (s.kind === 'objective' && s.key === '2.4' ? { ...s, mastery } : s));
    const weight = (all: Skill[]) => studyWeight(target, skillIndex(all), undefined, 10).weight;
    const strong = weight(objectiveOnly(0.95));
    const prior = weight(objectiveOnly(0.4));
    const weak = weight(objectiveOnly(0.05));
    expect(weak).toBeGreaterThan(prior);
    expect(prior).toBeGreaterThan(strong);
    // a template without that objective is unaffected by it
    const other = FULL_STUDY_POOL.find((t) => t.kind === 'vuln' && !t.objectives.includes('2.4'))!;
    expect(studyWeight(other, skillIndex(objectiveOnly(0.05)), undefined, 10).weight).toBe(studyWeight(other, skillIndex(objectiveOnly(0.95)), undefined, 10).weight);
    // and the weakest key the case reports is the weak objective
    expect(studyWeight(target, skillIndex(objectiveOnly(0.05)), undefined, 10).weakestKey).toMatchObject({ kind: 'objective', key: '2.4' });
    expect(withObjective('2.4').length).toBeGreaterThan(1);
  });

  it('favours a template that trains a weak objective over one that trains a strong one (full pool)', () => {
    // 2.4 is weak, 2.2 strong: attempts on the cases that train them. Every case has a card, not yet due.
    const vulnTemplates = FULL_STUDY_POOL.filter((t) => t.kind === 'vuln');
    const trains = (t: StudyTemplate, k: string) => t.objectives.includes(k);
    const weakSet = vulnTemplates.filter((t) => trains(t, '2.4') && !trains(t, '2.2'));
    const strongSet = vulnTemplates.filter((t) => trains(t, '2.2') && !trains(t, '2.4'));
    expect(weakSet.length).toBeGreaterThan(0);
    expect(strongSet.length).toBeGreaterThan(0);
    const attempts: Attempt[] = [];
    const cards: Record<string, Card> = {};
    let day = 0;
    for (const t of FULL_STUDY_POOL) {
      const pct = t.kind === 'soc' ? 60 : trains(t, '2.4') ? 10 : trains(t, '2.2') ? 100 : 60;
      attempts.push({ templateId: t.id, percent: pct, day, mode: t.kind === 'vuln' ? 'vuln' : 'study', correct: pct >= 70 });
      cards[t.id] = { ...review(undefined, t.id, pct, day), due: 1000 };
      day++;
    }
    let weak = 0;
    let strong = 0;
    for (let i = 0; i < 600; i++) {
      const s = nextStudyCase(cards, attempts, day, createRng(`obj-${i}`), { pool: FULL_STUDY_POOL });
      if (weakSet.some((t) => t.id === s.templateId)) weak++;
      if (strongSet.some((t) => t.id === s.templateId)) strong++;
    }
    expect(weak / weakSet.length).toBeGreaterThan((1.5 * strong) / strongSet.length);
  });

  it('defaults to the SOC pool: a vuln id never comes back without the full pool', () => {
    expect(SOC_STUDY_POOL.map((t) => t.id)).toEqual(ALL_TEMPLATES.map((t) => t.id));
    expect(SOC_STUDY_POOL.every((t) => t.kind === 'soc' && t.objectives.length === 0 && t.tactics.length > 0)).toBe(true);
    expect(FULL_STUDY_POOL.length).toBe(ALL_TEMPLATES.length + VULN_TEMPLATES.length);
    expect(FULL_STUDY_POOL.filter((t) => t.kind === 'vuln').every((t) => t.id.startsWith('vm-') && t.tactics.length === 0 && t.category === 'vulnmgmt')).toBe(true);
    // a due vuln card is ignored without the full pool, even when it is the only card
    const card = { ...review(undefined, 'vm-kev-internal', 10, 0), templateId: 'vm-kev-internal' };
    for (let i = 0; i < 60; i++) {
      const s = nextStudyCase({ 'vm-kev-internal': card }, [v('vm-kev-internal', 10, 0)], 10, createRng(`soc-${i}`));
      expect(s.templateId.startsWith('vm-')).toBe(false);
      expect(templateById(s.templateId)).toBeDefined();
    }
    expect(studyPlan({ 'vm-kev-internal': card }, [v('vm-kev-internal', 10, 0)], 10)).toMatchObject({ dueToday: [], seen: 0, total: ALL_TEMPLATES.length });
    // both registries resolve through studyTemplateById
    expect(studyTemplateById('identity-password-spray')!.kind).toBe('soc');
    expect(studyTemplateById('vm-kev-internal')!.kind).toBe('vuln');
    expect(studyTemplateById('nope')).toBeUndefined();
  });

  it('with the full pool, a due vuln card is served first and the plan counts vuln cards', () => {
    const vc = review(undefined, 'vm-stale-scan', 30, 0);
    const sc = review(undefined, 'identity-password-spray', 90, 3);
    const cards = { 'vm-stale-scan': vc, 'identity-password-spray': sc };
    const s = nextStudyCase(cards, [], 10, createRng('x'), { pool: FULL_STUDY_POOL });
    expect(s).toMatchObject({ templateId: 'vm-stale-scan', reason: 'due' });
    expect(nextStudyCase(cards, [], 10, createRng('x'), { pool: FULL_STUDY_POOL, exclude: ['vm-stale-scan'] }).templateId).toBe('identity-password-spray');
    const plan = studyPlan(cards, [v('vm-stale-scan', 30, 0), attempt('identity-password-spray', 90, 3)], 10, { pool: FULL_STUDY_POOL });
    expect(plan.dueToday).toEqual(['vm-stale-scan', 'identity-password-spray']);
    expect(plan.seen).toBe(2);
    expect(plan.total).toBe(FULL_STUDY_POOL.length);
    expect(plan.weakest.objective).toHaveLength(3);
    expect(plan.weakest.category.map((s) => s.key)).not.toContain('vulnmgmt');
    // gated suggestions never serve vuln tier 2 or 3 to a brand-new analyst
    for (let i = 0; i < 80; i++) {
      const t = studyTemplateById(nextStudyCase({}, [], 0, createRng(`g-${i}`), { pool: FULL_STUDY_POOL }).templateId)!;
      expect(t.difficulty).toBe('tier1');
    }
  });

  it('vulnSeedFor finds a seed that resolves to the requested twin', () => {
    const types = vulnCaseTypes(VULN_TEMPLATES);
    const twinned = types.filter((t) => t.templates.length > 1);
    expect(twinned.length).toBeGreaterThan(0);
    for (const type of twinned) {
      for (const t of type.templates) {
        const r = vulnSeedFor(types, t.id, 'base-1')!;
        expect(r.slug).toBe(type.slug);
        expect(resolveVulnTemplate(type, r.seed).id).toBe(t.id);
        expect(r.seed.startsWith('base-1')).toBe(true);
        expect(vulnSeedFor(types, t.id, 'base-1')).toEqual(r); // deterministic
      }
    }
    expect(vulnSeedFor(types, 'identity-password-spray', 'b')).toBeNull();
  });
});
