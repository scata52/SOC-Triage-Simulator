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
