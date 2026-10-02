// A shift: the late-shift analyst inherits the day's queue plus whatever
// fired overnight. Six to nine alerts share one corpus — the noise of one is
// the background of another — typically one or two real incidents, the
// benign look-alikes that make them hard, and routine ops tickets.

import { createRng, type Rng } from '../rng.ts';
import type { World } from '../world/world.ts';
import type { CaseTemplate, TimePreference } from '../cases/model.ts';
import { ALL_TEMPLATES, templateById } from '../cases/templates/index.ts';
import { buildScenario, type Scenario, type ScenarioItem } from '../cases/scenario.ts';
import type { CorpusBuilder } from '../logs/corpus.ts';
import { atLocalHour, DAY, HOUR, localWeekday } from '../logs/time.ts';
import { VULN_LINK_TEMPLATE_ID, type VulnHook } from './vuln-hook.ts';

export const SEASON_START = Date.UTC(2026, 8, 1);
export const SHIFT_END_LOCAL_HOUR = 17.5;
export const SHIFT_WINDOW_HOURS = 22;
export const BUDGETS = [0, 20, 30, 45] as const; // minutes; 0 = untimed
export type Budget = (typeof BUDGETS)[number];

// Hunts start from a hypothesis rather than an alert, so they stay out of
// the queue; the ops "already contained" case plays the routine-ticket role.
const NOT_IN_QUEUE = new Set(['ops-hunt-repo-exfil']);
const OPS = new Set(['ops-already-contained', 'ops-phishing-simulation', 'ops-authorized-pentest']);

export interface CampaignSlot {
  templateId: string;
  seed: string;
  campaign: NonNullable<ScenarioItem['campaign']>;
}

// The seed a shift is planned and built from.
export function shiftSeedFor(worldSeed: string, number: number): string {
  return `${worldSeed}:shift:${number}`;
}

export interface ShiftOptions {
  world: World;
  seed: string; // profile-level seed
  number: number; // 0-based shift counter
  size?: number;
  budget?: Budget;
  campaign?: CampaignSlot;
  // Vulnerability continuity (DESIGN section 8): one extra alert, planned after
  // everything else so that the rest of the shift is exactly what it would be
  // without it.
  vulnHook?: VulnHook;
  // Templates seen in the last shifts, avoided where possible.
  recent?: readonly string[];
}

export interface ShiftPlan {
  id: string;
  seed: string;
  number: number;
  day: number; // UTC ms of the shift's local day
  start: number; // earliest alert time
  end: number; // "now": when the analyst sits down
  budget: Budget;
  items: ScenarioItem[];
  campaignAlertId?: string;
}

// The number-th working day of the season.
export function shiftDay(number: number, utcOffset: number): number {
  let day = SEASON_START;
  let n = 0;
  for (;;) {
    if (![0, 6].includes(localWeekday(day + 12 * HOUR, utcOffset))) {
      if (n === number) return day;
      n++;
    }
    day += DAY;
  }
}

export function alertTime(rng: Rng, day: number, when: TimePreference | undefined, utcOffset: number): number {
  let hour: number;
  if (when === 'off-hours') hour = rng.float(0.8, 5.2);
  else if (when === 'any') hour = rng.bool(0.3) ? rng.float(0.8, 6.5) : rng.float(7.5, 16.9);
  else hour = rng.float(9.2, 16.9);
  return Math.floor(atLocalHour(day + 12 * HOUR, hour, utcOffset) / 1000) * 1000;
}

function eligible(t: CaseTemplate): boolean {
  return !NOT_IN_QUEUE.has(t.id);
}

export function planShift(opts: ShiftOptions): ShiftPlan {
  const { world } = opts;
  const seed = shiftSeedFor(opts.seed, opts.number);
  const rng = createRng(seed);
  const size = opts.size ?? rng.int(6, 9);
  const recent = new Set(opts.recent ?? []);
  const utcOffset = world.org.utcOffset;
  const day = shiftDay(opts.number, utcOffset);
  const end = atLocalHour(day + 12 * HOUR, SHIFT_END_LOCAL_HOUR, utcOffset);

  const chosen: string[] = [];
  const add = (id: string) => {
    if (!chosen.includes(id) && chosen.length < size) chosen.push(id);
  };
  const freshFirst = (ids: string[]) => {
    const shuffled = rng.shuffle(ids);
    return [...shuffled.filter((id) => !recent.has(id)), ...shuffled.filter((id) => recent.has(id))];
  };
  const incidents = ALL_TEMPLATES.filter((t) => eligible(t) && t.kind === 'incident' && !OPS.has(t.id)).map((t) => t.id);
  const benign = ALL_TEMPLATES.filter((t) => eligible(t) && t.kind === 'benign' && !OPS.has(t.id)).map((t) => t.id);

  // 1. The headline incident: the campaign's next move, or a fresh one.
  const primary = opts.campaign?.templateId ?? freshFirst(incidents)[0];
  add(primary);
  // 2. Sometimes a second, unrelated incident.
  if (rng.bool(0.55)) {
    const cat = templateById(primary)!.category;
    const other = freshFirst(incidents).find((id) => id !== primary && templateById(id)!.category !== cat);
    if (other) add(other);
  }
  // 3. Look-alikes: the benign twin of each incident, most of the time.
  for (const id of [...chosen]) {
    const twin = templateById(id)!.twin;
    if (twin && rng.bool(0.7)) add(twin);
  }
  // 4. Routine ops tickets.
  const ops = freshFirst([...OPS]);
  add(ops[0]);
  if (rng.bool(0.35)) add(ops[1]);
  // 5. Fill: mostly benign, some ops, and — up to three real incidents in
  // total — the occasional extra true positive, so no queue is predictable.
  const isIncident = (id: string) => templateById(id)!.kind === 'incident' && !OPS.has(id);
  let pool = [...benign, ...ops, ...incidents].filter((id) => !chosen.includes(id));
  while (chosen.length < size && pool.length) {
    const tps = chosen.filter(isIncident).length;
    const weighted = pool
      .filter((id) => !isIncident(id) || tps < 3)
      .map((id) => ({ value: id, weight: (isIncident(id) ? 0.9 : OPS.has(id) ? 1.2 : 3) * (recent.has(id) ? 0.35 : 1) }));
    if (!weighted.length) break;
    const id = rng.pickWeighted(weighted);
    add(id);
    pool = pool.filter((x) => x !== id);
  }

  const items: ScenarioItem[] = [];
  const irng = rng.fork('items');
  for (const id of chosen) {
    const t = templateById(id)!;
    const isCampaign = opts.campaign && id === opts.campaign.templateId;
    const caseSeed = isCampaign ? opts.campaign!.seed : `${seed}:${id}`;
    items.push({ alertId: '', templateId: id, seed: caseSeed, at: alertTime(irng.fork(id), day, t.when, utcOffset), campaign: isCampaign ? opts.campaign!.campaign : undefined });
  }
  // The continuity alert: one extra item with its own seed and its own time
  // stream, so the main rng and every other item are untouched.
  if (opts.vulnHook) {
    const t = templateById(VULN_LINK_TEMPLATE_ID);
    if (!t) throw new Error(`Unknown template ${VULN_LINK_TEMPLATE_ID}`);
    items.push({ alertId: '', templateId: t.id, seed: opts.vulnHook.seed, at: alertTime(createRng(`${seed}:vuln-hook`), day, t.when, utcOffset), vulnHook: opts.vulnHook });
  }
  // Queue order is arrival order; alert ids follow it.
  items.sort((a, b) => a.at - b.at || (a.templateId < b.templateId ? -1 : 1));
  items.forEach((it, i) => (it.alertId = `A${i + 1}`));
  const campaignAlertId = opts.campaign ? items.find((i) => i.campaign)?.alertId : undefined;

  return {
    id: `shift-${opts.number + 1}`,
    seed,
    number: opts.number,
    day,
    start: Math.min(...items.map((i) => i.at)),
    end,
    budget: opts.budget ?? 30,
    items,
    campaignAlertId,
  };
}

export function buildShift(world: World, plan: ShiftPlan, context?: (b: CorpusBuilder) => void): Scenario {
  return buildScenario({
    world,
    seed: plan.seed,
    now: plan.end,
    windowHours: SHIFT_WINDOW_HOURS,
    items: plan.items,
    historyFiller: true,
    context,
  });
}
