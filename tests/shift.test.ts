import { describe, expect, it } from 'vitest';
import { buildShift, planShift, shiftDay, SHIFT_END_LOCAL_HOUR } from '../src/core/shift/plan.ts';
import { prioritisation, scoreShift, type Submission } from '../src/core/shift/score.ts';
import { emptyVerdict, perfectVerdict } from '../src/core/grading/grade.ts';
import { templateById } from '../src/core/cases/templates/index.ts';
import { localHour, localWeekday } from '../src/core/logs/time.ts';
import { SiemDatabase } from '../src/core/query/engine.ts';
import { checkGrading, checkSolvable, checkStructure, world } from './helpers/scenario-check.ts';
import { syntheticViolations } from './helpers/guardrails.ts';
import { sqljs } from './helpers/sql.ts';
import type { ResolvedCase } from '../src/core/cases/scenario.ts';

describe('shift planning', () => {
  it('schedules shifts on consecutive working days, ending late afternoon', () => {
    const w = world('shift-plan');
    const days = Array.from({ length: 10 }, (_, i) => shiftDay(i, w.org.utcOffset));
    for (const d of days) expect([0, 6]).not.toContain(localWeekday(d + 12 * 3600_000, w.org.utcOffset));
    expect(new Set(days).size).toBe(10);
    const plan = planShift({ world: w, seed: 'p', number: 3 });
    expect(localHour(plan.end, w.org.utcOffset)).toBeCloseTo(SHIFT_END_LOCAL_HOUR, 5);
  });

  it('composes 6–9 distinct alerts with at least one and at most three real incidents', () => {
    const w = world('shift-plan');
    for (let i = 0; i < 60; i++) {
      const plan = planShift({ world: w, seed: `compose-${i}`, number: i % 20 });
      const ids = plan.items.map((x) => x.templateId);
      expect(ids.length).toBeGreaterThanOrEqual(6);
      expect(ids.length).toBeLessThanOrEqual(9);
      expect(new Set(ids).size).toBe(ids.length);
      expect(ids).not.toContain('ops-hunt-repo-exfil');
      const tps = ids.filter((id) => templateById(id)!.kind === 'incident' && id !== 'ops-already-contained');
      expect(tps.length).toBeGreaterThanOrEqual(1);
      expect(tps.length).toBeLessThanOrEqual(3);
      expect(plan.items.map((x) => x.alertId)).toEqual(ids.map((_, k) => `A${k + 1}`));
      for (let k = 1; k < plan.items.length; k++) expect(plan.items[k].at).toBeGreaterThanOrEqual(plan.items[k - 1].at);
      for (const it of plan.items) expect(it.at).toBeLessThan(plan.end);
    }
  });

  it('is deterministic and avoids recently seen templates where it can', () => {
    const w = world('shift-plan');
    const a = planShift({ world: w, seed: 'det', number: 2 });
    expect(planShift({ world: w, seed: 'det', number: 2 })).toEqual(a);
    const recent = a.items.map((x) => x.templateId);
    const b = planShift({ world: w, seed: 'det', number: 2, recent });
    const overlap = b.items.filter((x) => recent.includes(x.templateId)).length;
    expect(overlap).toBeLessThan(recent.length);
  });
});

describe('shift corpora', () => {
  // Several cases in one corpus: each must still be internally consistent,
  // gradeable and solvable with the others' activity as background noise.
  for (let i = 0; i < 8; i++) {
    it(`shift ${i} builds and every case is solvable in the shared corpus`, async () => {
      const w = world(`shift-world-${i % 3}`);
      const plan = planShift({ world: w, seed: `suite-${i}`, number: i });
      const s = buildShift(w, plan);
      expect(s.cases.map((c) => c.alertId)).toEqual(plan.items.map((x) => x.alertId));
      expect(syntheticViolations(s.corpus, w)).toEqual([]);
      const db = new SiemDatabase(await sqljs(), s.corpus);
      try {
        for (const c of s.cases) {
          checkStructure(c);
          checkGrading(c);
          await checkSolvable(s, c, db);
        }
      } finally {
        db.close();
      }
    });
  }
});

describe('shift scoring', () => {
  const w = world('shift-score');
  const plan = planShift({ world: w, seed: 'score', number: 1, size: 8 });
  const s = buildShift(w, plan);
  const cases = s.cases;
  const byPriority = (list: ResolvedCase[]) => [...list].sort((a, b) => Number(b.truth.disposition === 'true-positive') - Number(a.truth.disposition === 'true-positive'));
  const submitAll = (order: ResolvedCase[], verdict = perfectVerdict): Submission[] => order.map((c, i) => ({ alertId: c.alertId, verdict: verdict(c), atSec: 60 * (i + 1) }));

  it('scores a perfect, well-prioritised shift at 100', () => {
    // Ideal order straight from the result itself.
    const first = scoreShift(cases, submitAll(cases));
    const ideal = first.idealOrder.map((id) => cases.find((c) => c.alertId === id)!);
    const r = scoreShift(cases, submitAll(ideal));
    expect(r.prioritisation).toBe(1);
    expect(r.score).toBe(100);
    expect(r.clean).toBe(true);
    expect(r.handled).toBe(cases.length);
  });

  it('costs prioritisation points to work the incidents last', () => {
    const good = scoreShift(cases, submitAll(byPriority(cases)));
    const bad = scoreShift(cases, submitAll(byPriority(cases).reverse()));
    expect(bad.prioritisation).toBeLessThan(good.prioritisation);
    expect(bad.score).toBeLessThan(good.score);
    expect(bad.caseScore).toBe(good.caseScore);
  });

  it('reports missed incidents, false escalations and unhandled alerts', () => {
    const tp = cases.filter((c) => c.truth.disposition === 'true-positive' && c.truth.action !== 'close');
    const benign = cases.filter((c) => c.truth.disposition !== 'true-positive');
    expect(tp.length).toBeGreaterThan(0);
    const subs: Submission[] = [
      { alertId: tp[0].alertId, verdict: { ...emptyVerdict(), disposition: 'benign', severity: 'low', action: 'close' }, atSec: 10 },
      ...(benign.length ? [{ alertId: benign[0].alertId, verdict: { ...perfectVerdict(benign[0]), action: 'escalate' as const }, atSec: 20 }] : []),
    ];
    const r = scoreShift(cases, subs);
    expect(r.missedIncidents).toContain(tp[0].alertId);
    if (benign.length) expect(r.falseEscalations).toEqual([benign[0].alertId]);
    expect(r.unhandled.length).toBe(cases.length - subs.length);
    expect(r.clean).toBe(false);
    expect(r.score).toBeLessThan(50);
  });

  it('uses the last submission per alert but the first for ordering', () => {
    const c = cases[0];
    const r = scoreShift(cases, [
      { alertId: c.alertId, verdict: emptyVerdict(), atSec: 5 },
      { alertId: c.alertId, verdict: perfectVerdict(c), atSec: 500 },
    ]);
    const cr = r.cases.find((x) => x.alertId === c.alertId)!;
    expect(cr.grade.percent).toBe(100);
    expect(cr.atSec).toBe(5);
    expect(cr.order).toBe(0);
  });

  it('computes nDCG prioritisation', () => {
    expect(prioritisation([{ priority: 0, order: 0 }])).toBe(1);
    expect(prioritisation([{ priority: 8, order: 0 }, { priority: 0, order: 1 }])).toBe(1);
    expect(prioritisation([{ priority: 8, order: 1 }, { priority: 0, order: 0 }])).toBeCloseTo(1 / Math.log2(3), 5);
    expect(prioritisation([{ priority: 8, order: null }, { priority: 0, order: 0 }])).toBe(0);
  });
});
