import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { alertTime, buildShift, planShift, shiftDay, shiftSeedFor, SHIFT_END_LOCAL_HOUR } from '../src/core/shift/plan.ts';
import { selectVulnFollowUp, VULN_LINK_TEMPLATE_ID, type VulnHook, type VulnLedgerEntry } from '../src/core/shift/vuln-hook.ts';
import { campaignContext, campaignSlot, startCampaign } from '../src/core/campaign/campaign.ts';
import { buildScenario, type Scenario } from '../src/core/cases/scenario.ts';
import { createRng } from '../src/core/rng.ts';
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
      expect(syntheticViolations(s.corpus, w, s.cases)).toEqual([]);
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

// ---------------------------------------------------------------------------
// Vulnerability continuity (DESIGN section 8): one extra alert from the hook.

const digest = (x: unknown) => createHash('sha256').update(JSON.stringify(x)).digest('hex');

// What a case's evidence says, independent of RecordIds (they are positions in the
// whole corpus, so an extra alert's rows shift them).
function evidenceContent(s: Scenario, c: ResolvedCase): { id: string; rows: string[] }[] {
  const byId = new Map<string, string>();
  for (const [table, t] of Object.entries(s.corpus.tables)) {
    const at = t.columns.indexOf('RecordId');
    if (at < 0) continue;
    for (const r of t.rows) byId.set(String(r[at]), `${table}|${JSON.stringify(r.filter((_, i) => i !== at))}`);
  }
  return c.evidence.map((e) => ({ id: e.id, rows: e.recordIds.map((id) => byId.get(id) ?? `missing:${id}`).sort() }));
}

const ENTRY: VulnLedgerEntry = {
  id: 'vm-kev-internal~hk1/F2@1700000000000',
  vulnId: 'SIMVULN-2026-00421',
  host: 'WEB01',
  decision: 'false-positive',
  schedule: 'none',
  decidedDay: 20000,
  caseRef: 'vm-kev-internal~hk1',
};
const hookFor = (seed: string, n: number, host = 'WEB01'): VulnHook => selectVulnFollowUp([{ ...ENTRY, host }], shiftSeedFor(seed, n))!;

describe('continuity: no hook means the same shift', () => {
  it('shiftSeedFor is the seed planShift uses', () => {
    const w = world('shift-plan');
    expect(planShift({ world: w, seed: 'p', number: 3 }).seed).toBe(shiftSeedFor('p', 3));
  });

  it('an absent, undefined, empty-ledger or all-consumed hook plans and builds a byte-identical shift', () => {
    for (const [i, ws] of ['shift-plan', 'shift-world-1'].entries()) {
      const w = world(ws);
      for (let n = 0; n < 4; n++) {
        const seed = `nohook-${i}-${n}`;
        const plain = planShift({ world: w, seed, number: n });
        const base = { plan: digest(plain), built: digest(buildShift(w, plain)) };
        const noHooks = [
          undefined,
          selectVulnFollowUp(undefined, shiftSeedFor(seed, n)) ?? undefined,
          selectVulnFollowUp([], shiftSeedFor(seed, n)) ?? undefined,
          selectVulnFollowUp([{ ...ENTRY, consumed: true }], shiftSeedFor(seed, n)) ?? undefined,
        ];
        for (const vulnHook of noHooks) {
          expect(vulnHook).toBeUndefined();
          const p = planShift({ world: w, seed, number: n, vulnHook });
          expect(p).toEqual(plain);
          expect(p.items.every((x) => !('vulnHook' in x))).toBe(true);
          expect({ plan: digest(p), built: digest(buildShift(w, p)) }).toEqual(base);
        }
      }
    }
  });

  it('with no hook no case carries a vulnerability link', () => {
    const w = world('shift-plan');
    const s = buildShift(w, planShift({ world: w, seed: 'nolink', number: 2 }));
    expect(s.cases.some((c) => 'vulnLink' in c)).toBe(false);
  });
});

describe('continuity: a hooked item is built after the others', () => {
  // Template-independent: any template can carry the hook on its item, and the
  // others must come out exactly as if it were not there.
  const w = world('shift-plan');
  const day = shiftDay(2, w.org.utcOffset);
  const now = day + 20 * 3600_000;
  const at = (h: number) => day + h * 3600_000;
  const hook = hookFor('hk', 2);
  const mk = (templateId: string, alertId: string, h: number, extra: object = {}) => ({ alertId, templateId, seed: `${templateId}-s`, at: at(h), ...extra });
  const run = (items: ReturnType<typeof mk>[]) => buildScenario({ world: w, seed: 'order-probe', now, windowHours: 22, items, historyFiller: true });
  const A = mk('identity-password-spray', 'A1', 8);
  const C = mk('endpoint-certutil-download', 'A3', 12);
  const B = mk('email-phish-credential', 'A2', 10, { vulnHook: hook });

  it('keeps cases in alert order and marks only the hooked one', () => {
    const s = run([A, B, C]);
    expect(s.cases.map((c) => c.alertId)).toEqual(['A1', 'A2', 'A3']);
    expect(s.cases.map((c) => c.templateId)).toEqual([A.templateId, B.templateId, C.templateId]);
    expect(Object.keys(s.infra)).toEqual(['A1', 'A2', 'A3']);
    expect(s.cases[1].vulnLink).toEqual({ caseRef: hook.caseRef, vulnId: hook.vulnId, host: hook.host, decision: hook.decision, schedule: hook.schedule });
    expect(s.cases[0].vulnLink).toBeUndefined();
    expect(s.cases[2].vulnLink).toBeUndefined();
  });

  it('leaves every other case, its infrastructure and its evidence rows as they are without the hooked item', () => {
    const withHook = run([A, B, C]);
    const without = run([A, C]);
    for (const alertId of ['A1', 'A3']) {
      const a = withHook.cases.find((c) => c.alertId === alertId)!;
      const b = without.cases.find((c) => c.alertId === alertId)!;
      expect(withHook.infra[alertId], alertId).toEqual(without.infra[alertId]);
      expect(a.alert).toEqual(b.alert);
      expect(a.truth).toEqual(b.truth);
      expect(a.indicators).toEqual(b.indicators);
      expect(evidenceContent(withHook, a)).toEqual(evidenceContent(without, b));
    }
  });

  it('builds the same result wherever the hooked item sits in the list', () => {
    const last = run([A, C, { ...B, alertId: 'A9' }]);
    const first = run([{ ...B, alertId: 'A9' }, A, C]);
    for (const alertId of ['A1', 'A3']) {
      expect(last.infra[alertId]).toEqual(first.infra[alertId]);
      expect(evidenceContent(last, last.cases.find((c) => c.alertId === alertId)!)).toEqual(evidenceContent(first, first.cases.find((c) => c.alertId === alertId)!));
    }
    expect(first.cases[0].alertId).toBe('A9');
    expect(last.cases.at(-1)!.alertId).toBe('A9');
  });
});

// These need the SOC template `endpoint-known-vuln-exploit` (src/core/cases/templates/vuln-link.ts):
// planShift reads its `when`, buildScenario builds it.
describe('continuity: a shift with the hook (needs endpoint-known-vuln-exploit)', () => {
  const worlds = ['shift-plan', 'shift-world-1'];
  const plans = (ws: string, seed: string, n: number, campaign = false) => {
    const w = world(ws);
    const state = campaign ? startCampaign(w, `c-${seed}`) : null;
    const slot = state ? campaignSlot(state, w, n) : undefined;
    const hook = hookFor(`${ws}:${seed}`, n);
    const base = { world: w, seed: `${ws}:${seed}`, number: n, campaign: slot };
    return { w, state, hook, base, without: planShift(base), with: planShift({ ...base, vulnHook: hook }) };
  };

  it('plans the same shift plus exactly one hook item with its own seed and time', () => {
    for (const ws of worlds) {
      for (let n = 0; n < 6; n++) {
        for (const campaign of [false, true]) {
          const p = plans(ws, `plan-${n}`, n, campaign);
          const key = (it: { templateId: string; seed: string; at: number }) => `${it.templateId}|${it.seed}|${it.at}`;
          const hooked = p.with.items.filter((x) => x.vulnHook);
          expect(hooked).toHaveLength(1);
          expect(hooked[0]).toMatchObject({ templateId: VULN_LINK_TEMPLATE_ID, seed: p.hook.seed, vulnHook: p.hook });
          expect(hooked[0].campaign).toBeUndefined();
          const t = templateById(VULN_LINK_TEMPLATE_ID)!;
          expect(hooked[0].at).toBe(alertTime(createRng(`${p.with.seed}:vuln-hook`), p.with.day, t.when, p.w.org.utcOffset));
          expect(hooked[0].at).toBeLessThan(p.with.end);
          expect(p.with.items.filter((x) => !x.vulnHook).map(key).sort()).toEqual(p.without.items.map(key).sort());
          // natural arrival order and numbering
          expect(p.with.items.map((x) => x.alertId)).toEqual(p.with.items.map((_, k) => `A${k + 1}`));
          for (let k = 1; k < p.with.items.length; k++) expect(p.with.items[k].at).toBeGreaterThanOrEqual(p.with.items[k - 1].at);
          expect(p.with.items).toHaveLength(p.without.items.length + 1);
          // the campaign alert is still the campaign alert
          if (campaign) expect(p.with.items.find((x) => x.alertId === p.with.campaignAlertId)!.campaign).toBeDefined();
          expect(p.with.start).toBeLessThanOrEqual(p.without.start);
          // deterministic
          expect(planShift({ ...p.base, vulnHook: p.hook })).toEqual(p.with);
        }
      }
    }
  });

  it('builds every other case exactly as without the hook, and one case carries the link', () => {
    for (const ws of worlds) {
      for (let n = 0; n < 3; n++) {
        for (const campaign of [false, true]) {
          const p = plans(ws, `build-${n}`, n, campaign);
          const ctx = p.state ? campaignContext(p.state, p.w, n) : undefined;
          const a = buildShift(p.w, p.without, ctx);
          const b = buildShift(p.w, p.with, ctx);
          expect(b.cases.map((c) => c.alertId)).toEqual(p.with.items.map((x) => x.alertId));
          const linked = b.cases.filter((c) => c.vulnLink);
          expect(linked).toHaveLength(1);
          expect(linked[0].templateId).toBe(VULN_LINK_TEMPLATE_ID);
          expect(linked[0].vulnLink).toMatchObject({ host: p.hook.host, vulnId: p.hook.vulnId, caseRef: p.hook.caseRef });
          const others = b.cases.filter((c) => !c.vulnLink);
          expect(others.map((c) => c.templateId).sort()).toEqual(a.cases.map((c) => c.templateId).sort());
          for (const c of others) {
            const mate = a.cases.find((x) => x.templateId === c.templateId)!;
            expect(b.infra[c.alertId], c.templateId).toEqual(a.infra[mate.alertId]);
            expect(c.alert, c.templateId).toEqual(mate.alert);
            expect(c.truth, c.templateId).toEqual(mate.truth);
            expect(evidenceContent(b, c), c.templateId).toEqual(evidenceContent(a, mate));
          }
          expect(digest(buildShift(p.w, p.with, ctx))).toBe(digest(b));
        }
      }
    }
  });

  it('is solvable and gradeable with the other alerts as background', async () => {
    const p = plans('shift-plan', 'solve', 1);
    const s = buildShift(p.w, p.with);
    expect(syntheticViolations(s.corpus, p.w, s.cases)).toEqual([]);
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
});
