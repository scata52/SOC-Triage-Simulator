import { describe, expect, it } from 'vitest';
import { ACTORS, actorById, VENDOR_NAMING } from '../src/core/campaign/actors.ts';
import { campaignContext, campaignSlot, campaignSummary, nextCampaign, recordShift, startCampaign, type CampaignState } from '../src/core/campaign/campaign.ts';
import { shiftDay } from '../src/core/shift/plan.ts';
import { buildShift, planShift } from '../src/core/shift/plan.ts';
import { scoreShift, type Submission } from '../src/core/shift/score.ts';
import { perfectVerdict, type Verdict } from '../src/core/grading/grade.ts';
import { templateById } from '../src/core/cases/templates/index.ts';
import { WorldIndex } from '../src/core/world/index.ts';
import type { ResolvedCase, Scenario } from '../src/core/cases/scenario.ts';
import { SiemDatabase } from '../src/core/query/engine.ts';
import { checkGrading, checkSolvable, checkStructure, world } from './helpers/scenario-check.ts';
import { syntheticViolations } from './helpers/guardrails.ts';
import { sqljs } from './helpers/sql.ts';

// Domains the engine generated in earlier shifts: they come back through the campaign state (reported intel,
// incident history, the actor's infrastructure), though this shift's own DomainIntel does not list them.
function carriedDomains(state: CampaignState): string[] {
  return [...JSON.stringify({ intel: state.intel, history: state.history, infra: state.infra }).matchAll(/[a-z0-9-]+(?:\.[a-z0-9-]+)+/gi)].map((m) => m[0]);
}

type Policy = (c: ResolvedCase) => Verdict;
const miss: Policy = (c) => ({ ...perfectVerdict(c), disposition: 'benign', action: 'close', techniques: [], indicators: [] });
const catchAll: Policy = perfectVerdict;

interface Turn {
  shift: number;
  scenario: Scenario;
  campaignCase?: ResolvedCase;
  before: CampaignState;
  after: CampaignState;
}

async function play(worldSeed: string, actorId: string, policy: Policy, maxShifts = 10, verify = true): Promise<Turn[]> {
  const w = world(worldSeed);
  let state = startCampaign(w, `test-${worldSeed}-${actorId}`, actorId);
  const turns: Turn[] = [];
  for (let shift = 0; shift < maxShifts && state.status === 'active'; shift++) {
    const slot = campaignSlot(state, w, shift)!;
    const plan = planShift({ world: w, seed: `camp-${worldSeed}`, number: shift, campaign: slot });
    const scenario = buildShift(w, plan, campaignContext(state, w, shift));
    const campaignCase = scenario.cases.find((c) => c.alertId === plan.campaignAlertId);
    expect(campaignCase?.templateId).toBe(slot.templateId);
    if (verify) {
      expect(syntheticViolations(scenario.corpus, w, scenario.cases, carriedDomains(state))).toEqual([]);
      const db = new SiemDatabase(await sqljs(), scenario.corpus);
      try {
        for (const c of scenario.cases) {
          checkStructure(c);
          checkGrading(c);
          await checkSolvable(scenario, c, db);
        }
      } finally {
        db.close();
      }
    }
    const subs: Submission[] = scenario.cases.map((c, i) => ({ alertId: c.alertId, verdict: c.alertId === plan.campaignAlertId ? policy(c) : perfectVerdict(c), atSec: 60 * (i + 1) }));
    const result = scoreShift(scenario.cases, subs);
    const after = recordShift(state, w, shift, scenario.infra, result, plan.campaignAlertId);
    turns.push({ shift, scenario, campaignCase, before: state, after });
    state = after;
  }
  return turns;
}

function scopeHas(c: ResolvedCase, upn: string, host: string): boolean {
  return c.indicators.scope.some((s) => s.value.toLowerCase() === upn.toLowerCase() || s.value === host || (s.aliases ?? []).includes(upn));
}

describe('actors', () => {
  it('have invented names that follow no vendor naming scheme', () => {
    for (const a of ACTORS) {
      expect(a.name, a.name).not.toMatch(VENDOR_NAMING);
      expect(a.name.split(/\s+/), `${a.name}: one coined word`).toHaveLength(1);
    }
    for (const real of ['LINEN MARLIN', 'Linen Typhoon', 'Cozy Bear', 'APT29', 'Scattered Spider', 'GOLD SOUTHFIELD', 'Paper Werewolf', 'Storm-0558']) expect(real).toMatch(VENDOR_NAMING);
  });


  it('only reference incident templates that exist and fit their stage', () => {
    for (const a of ACTORS) {
      for (const step of a.playbook) {
        for (const id of step.templates) {
          const t = templateById(id);
          expect(t, id).toBeDefined();
          expect(t!.kind).toBe('incident');
          expect(t!.stages ?? [], `${id} at ${step.stage}`).toContain(step.stage);
        }
      }
      expect(a.playbook.at(-1)!.stage).toBe('objective');
    }
  });
});

describe('campaign playthroughs', () => {
  for (const actor of ACTORS) {
    it(`${actor.id}: an analyst who misses everything ends in a breach, on one foothold`, async () => {
      const turns = await play('camp-miss', actor.id, miss);
      const last = turns.at(-1)!.after;
      expect(last.status).toBe('breached');
      expect(turns).toHaveLength(actor.playbook.length);
      expect(last.log.map((e) => e.stage)).toEqual(actor.playbook.map((s) => s.stage));
      expect(last.log.every((e) => e.outcome === 'missed')).toBe(true);
      expect(last.intrusions).toBe(1);
      const idx = new WorldIndex(world('camp-miss'));
      const victim = idx.person(turns[0].before.victimId);
      // Same victim throughout, and every stage names them or their laptop.
      for (const t of turns) {
        expect(t.before.victimId).toBe(victim.id);
        expect(scopeHas(t.campaignCase!, victim.upn, t.before.host), `${t.campaignCase!.templateId} scope`).toBe(true);
      }
      // Infrastructure persists: some attacker value recurs across stages.
      const values = turns.map((t) => new Set([...Object.values(t.scenario.infra[t.campaignCase!.alertId].domains), ...Object.values(t.scenario.infra[t.campaignCase!.alertId].ips)]));
      const recurring = values.some((v, i) => i > 0 && values.slice(0, i).some((prev) => [...v].some((x) => prev.has(x))));
      expect(recurring).toBe(true);
      expect(campaignSummary(last)).toMatchObject({ status: 'breached', progress: 1, actor: 'Unattributed activity' });
      expect(last.log.at(-1)!.narrative).toMatch(/Campaign over/);
      for (const e of last.log) expect(e.narrative).not.toMatch(/[a-z,] The intruder/);
      expect(last.log.some((e) => /(^|\. )The intruder/.test(e.narrative) || /the intruder/.test(e.narrative))).toBe(true);
    });

    it(`${actor.id}: an analyst who contains every stage evicts the actor`, async () => {
      const turns = await play('camp-catch', actor.id, catchAll);
      const last = turns.at(-1)!.after;
      expect(last.status).toBe('evicted');
      expect(turns).toHaveLength(actor.tenacity);
      expect(last.contained).toBe(actor.tenacity);
      expect(last.identified).toBe(true);
      // Each containment forces a pivot to a new victim at initial access.
      expect(new Set(turns.map((t) => t.before.victimId)).size).toBe(actor.tenacity);
      for (const t of turns) expect(actorById(actor.id)!.playbook[t.before.stage].stage).toBe('initial-access');
      expect(last.intel.length).toBeGreaterThan(0);
      expect(campaignSummary(last).actor).toBe(actor.name);
    });
  }
});

describe('campaign consequences', () => {
  it('turns reported indicators into attributed ThreatIntel and verdicts into IncidentHistory', async () => {
    const turns = await play('camp-intel', 'orrax', catchAll, 1, false);
    const state = turns[0].after;
    expect(state.status).toBe('active');
    expect(state.history).toHaveLength(turns[0].scenario.cases.length);
    const w = world('camp-intel');
    const slot = campaignSlot(state, w, 1)!;
    const plan = planShift({ world: w, seed: 'camp-intel', number: 1, campaign: slot });
    const s = buildShift(w, plan, campaignContext(state, w, 1));
    const ti = s.corpus.tables.ThreatIntel;
    const col = (name: string) => ti.columns.indexOf(name);
    const ours = ti.rows.filter((r) => r[col('Source')] === 'SOC — analyst report');
    expect(ours.map((r) => r[col('Indicator')]).sort()).toEqual(state.intel.map((i) => i.indicator).sort());
    for (const r of ours) expect(r[col('Actor')]).toBe('Orrax');
    const ih = s.corpus.tables.IncidentHistory;
    const mine = ih.rows.filter((r) => r[ih.columns.indexOf('Analyst')] === 'You');
    expect(mine).toHaveLength(state.history.length);
    expect(new Set(mine.map((r) => r[ih.columns.indexOf('IncidentId')])).size).toBe(mine.length);
    expect(syntheticViolations(s.corpus, w, s.cases, carriedDomains(state))).toEqual([]);
  });

  it('keeps the infrastructure you did not block and rotates what you did', async () => {
    // Contain the stage but report only the affected user/host: nothing blocked.
    const scopeOnly: Policy = (c) => ({ ...perfectVerdict(c), indicators: c.indicators.scope.map((s) => ({ kind: s.kind, value: s.value })) });
    const kept = (await play('camp-rotate', 'velmyr', scopeOnly, 1, false))[0];
    const usedKept = kept.scenario.infra[kept.campaignCase!.alertId];
    expect(kept.after.infra.ips).toEqual(usedKept.ips);
    expect(kept.after.intel).toEqual([]);

    const blocked = (await play('camp-rotate', 'velmyr', catchAll, 1, false))[0];
    const usedBlocked = blocked.scenario.infra[blocked.campaignCase!.alertId];
    const blockedValues = new Set(blocked.campaignCase!.indicators.block.map((b) => b.value));
    for (const v of Object.values(usedBlocked.ips)) {
      if (blockedValues.has(v!)) expect(Object.values(blocked.after.infra.ips)).not.toContain(v);
    }
    expect(blocked.after.intel.length).toBeGreaterThan(0);
  });

  it('keeps ageing domains the actor carries between stages', async () => {
    const turns = await play('camp-age', 'orrax', miss, 6, false);
    const w = world('camp-age');
    let checked = 0;
    for (const t of turns.slice(1)) {
      const before = t.before;
      if (before.lastShift === null) continue;
      const days = Math.round((shiftDay(t.shift, w.org.utcOffset) - shiftDay(before.lastShift, w.org.utcOffset)) / 86_400_000);
      for (const [role, d] of Object.entries(before.infra.domains)) {
        if (t.after.infra.domains[role as keyof typeof before.infra.domains] !== d) continue;
        const a0 = before.infra.domainAgeDays![role as keyof typeof before.infra.domains]!;
        const a1 = t.after.infra.domainAgeDays![role as keyof typeof before.infra.domains]!;
        expect(a1, `${role} ${d}`).toBe(a0 + days);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(0);
  });

  it('carries incident history and intel into the next campaign, keeping attribution', async () => {
    const turns = await play('camp-next', 'orrax', catchAll, 10, false);
    const ended = turns.at(-1)!.after;
    expect(ended.status).toBe('evicted');
    const w = world('camp-next');
    const next = nextCampaign(ended, w, 'camp-next:c1', 'velmyr');
    expect(next.status).toBe('active');
    expect(next.history).toEqual(ended.history);
    expect(next.intel.map((i) => i.indicator)).toEqual(ended.intel.map((i) => i.indicator));
    expect(next.intel.every((i) => i.actor === 'Orrax')).toBe(true);
    expect(next.log).toEqual([]);
    const s = buildShift(w, planShift({ world: w, seed: 'camp-next', number: turns.length, campaign: campaignSlot(next, w, turns.length) }), campaignContext(next, w, turns.length));
    const ti = s.corpus.tables.ThreatIntel;
    const ours = ti.rows.filter((r) => r[ti.columns.indexOf('Source')] === 'SOC — analyst report');
    expect(ours.length).toBe(ended.intel.length);
    for (const r of ours) expect(r[ti.columns.indexOf('Actor')]).toBe('Orrax');
    expect(nextCampaign(null, w, 'fresh').history).toEqual([]);
  });

  it('treats a flagged-but-not-escalated stage as uncontained', async () => {
    const flag: Policy = (c) => ({ ...perfectVerdict(c), action: 'monitor' });
    const t = (await play('camp-flag', 'orrax', flag, 1, false))[0];
    expect(t.after.log[0].outcome).toBe('flagged');
    expect(t.after.stage).toBe(1);
    expect(t.after.victimId).toBe(t.before.victimId);
    expect(t.after.log[0].narrative).toMatch(/did not escalate/);
  });

  it('is deterministic', async () => {
    const a = await play('camp-det', 'velmyr', miss, 2, false);
    const b = await play('camp-det', 'velmyr', miss, 2, false);
    expect(JSON.stringify(a.map((t) => t.after))).toBe(JSON.stringify(b.map((t) => t.after)));
  });
});

// ---------------------------------------------------------------------------
// The vulnerability hook's alert is not part of the campaign (DESIGN section 8).

describe('campaign state ignores the vulnerability hook alert', () => {
  const HOOK = { ledgerId: 'vm-kev-internal~c1/F2@1', host: 'WEB01', vulnId: 'SIMVULN-2026-00421', decidedDay: 20000, caseRef: 'vm-kev-internal~c1', decision: 'false-positive' as const, schedule: 'none' as const, seed: 'seed:vuln:x' };

  // Alert ids are positions in a shift's queue, so a hooked shift can number the campaign alert
  // differently. Reading the state through the template behind each alert id compares the rest.
  const normalise = (state: CampaignState, scenarios: Record<number, Scenario>): string => {
    const named = (e: { shift: number }) => {
      const tpl = new Map(scenarios[e.shift].cases.map((c) => [c.alertId, c.templateId]));
      return JSON.stringify(e).replace(/\bA\d+\b/g, (id) => `<${tpl.get(id) ?? id}>`);
    };
    return JSON.stringify({ ...state, log: state.log.map(named), intel: state.intel.map(named) });
  };

  for (const actor of ACTORS.slice(0, 2)) {
    for (const [name, policy] of [['missed', miss], ['contained', catchAll]] as const) {
      it(`${actor.id}, ${name}: recordShift gives the same campaign with and without the hook alert`, () => {
        const w = world('camp-hook');
        let a = startCampaign(w, `hook-${actor.id}-${name}`, actor.id);
        let b = a;
        const seenA: Record<number, Scenario> = {};
        const seenB: Record<number, Scenario> = {};
        for (let shift = 0; shift < 3 && a.status === 'active'; shift++) {
          const slot = campaignSlot(a, w, shift)!;
          const base = { world: w, seed: 'camp-hook', number: shift, campaign: slot };
          const planA = planShift(base);
          const planB = planShift({ ...base, vulnHook: HOOK });
          const ctx = campaignContext(a, w, shift);
          const sa = buildShift(w, planA, ctx);
          const sb = buildShift(w, planB, ctx);
          expect(sb.cases.filter((c) => c.vulnLink)).toHaveLength(1);
          // the same verdicts on the other alerts, matched by template; a wrong-way verdict on the hook alert
          const verdictFor = (c: ResolvedCase, campaignAlertId?: string) => (c.vulnLink ? miss(c) : c.alertId === campaignAlertId ? policy(c) : perfectVerdict(c));
          const subs = (s: Scenario, campaignAlertId?: string): Submission[] => s.cases.map((c, i) => ({ alertId: c.alertId, verdict: verdictFor(c, campaignAlertId), atSec: 60 * (i + 1) }));
          const ra = scoreShift(sa.cases, subs(sa, planA.campaignAlertId));
          const rb = scoreShift(sb.cases, subs(sb, planB.campaignAlertId));
          expect(planB.campaignAlertId).toBeDefined();
          const nextA = recordShift(a, w, shift, sa.infra, ra, planA.campaignAlertId);
          const nextB = recordShift(b, w, shift, sb.infra, rb, planB.campaignAlertId);
          seenA[shift] = sa;
          seenB[shift] = sb;
          expect(normalise(nextB, seenB)).toBe(normalise(nextA, seenA));
          // no history entry for the hook alert, and the INC ids are those of the shift without it
          expect(nextB.history.map((h) => h.id)).toEqual(nextA.history.map((h) => h.id));
          expect(nextB.history.every((h) => h.title !== sb.cases.find((c) => c.vulnLink)!.alert.rule)).toBe(true);
          a = nextA;
          b = nextB;
        }
        expect(b.log.length).toBeGreaterThan(0);
      });
    }
  }

  it('skips a case that carries a vulnerability link, whatever template it is (template-independent)', () => {
    const w = world('camp-hook-2');
    const state = startCampaign(w, 'hook-synth');
    const plan = planShift({ world: w, seed: 'synth', number: 0, campaign: campaignSlot(state, w, 0)! });
    const s = buildShift(w, plan, campaignContext(state, w, 0));
    const plain = scoreShift(s.cases, s.cases.map((c, i) => ({ alertId: c.alertId, verdict: perfectVerdict(c), atSec: 60 * (i + 1) })));
    const extra = { ...s.cases.find((c) => c.truth.disposition !== 'true-positive')!, alertId: 'A99', vulnLink: { caseRef: HOOK.caseRef, vulnId: HOOK.vulnId, host: HOOK.host, decision: HOOK.decision, schedule: HOOK.schedule } };
    const cases = [...s.cases, extra];
    const withExtra = scoreShift(cases, cases.map((c, i) => ({ alertId: c.alertId, verdict: perfectVerdict(c), atSec: 60 * (i + 1) })));
    const a = recordShift(state, w, 0, s.infra, plain, plan.campaignAlertId);
    const b = recordShift(state, w, 0, { ...s.infra, A99: s.infra[s.cases[0].alertId] }, withExtra, plan.campaignAlertId);
    expect(b).toEqual(a);
    expect(b.history).toHaveLength(s.cases.length);
  });
});
