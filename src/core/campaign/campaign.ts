// The campaign: a fictional actor works through its playbook against the
// organisation, one stage per shift, on the same victim and infrastructure.
// The analyst's verdicts have consequences:
//   - escalate a stage as a true positive → IR contains it: the foothold is
//     burned, the actor pivots to a new victim and starts again; after
//     `tenacity` containments it gives up (evicted).
//   - miss it (or flag it without escalating) → the actor moves to the next
//     stage on the same foothold; missing the objective ends in a breach.
//   - reported indicators land in ThreatIntel and are blocked: the actor
//     rotates that infrastructure, but keeps whatever you didn't report.
// Every verdict you give in a shift appears in IncidentHistory afterwards.

import { createRng } from '../rng.ts';
import type { World } from '../world/world.ts';
import { WorldIndex } from '../world/index.ts';
import type { CampaignStage, IndicatorSpec } from '../cases/model.ts';
import type { InfraRecord } from '../cases/infra.ts';
import type { ResolvedCase, Scenario } from '../cases/scenario.ts';
import type { CorpusBuilder } from '../logs/corpus.ts';
import { DAY, HOUR, MIN } from '../logs/time.ts';
import { ACTION_LABELS, DISPOSITION_LABELS, SEVERITY_LABELS } from '../grading/grade.ts';
import { shiftDay, type CampaignSlot } from '../shift/plan.ts';
import type { ShiftResult } from '../shift/score.ts';
import { ACTORS, actorById, compatible, type Actor } from './actors.ts';

export type CampaignStatus = 'active' | 'evicted' | 'breached';
export type StageOutcome = 'contained' | 'flagged' | 'missed';

export interface CampaignEntry {
  shift: number;
  alertId: string;
  templateId: string;
  stage: CampaignStage;
  outcome: StageOutcome;
  victim: string; // UPN
  host: string;
  blocked: string[];
  narrative: string;
}

export interface IntelRecord {
  indicator: string;
  type: 'ipv4' | 'domain' | 'sha256' | 'email' | 'url';
  threat: string;
  shift: number;
  note: string;
  // Set when the record outlives its campaign: the attribution IR had made
  // by then ('' if the actor was never identified).
  actor?: string;
}

export interface HistoryRecord {
  id: string;
  shift: number;
  time: string; // ISO — when the alert fired
  title: string;
  severity: string;
  disposition: string;
  status: string;
  entities: string;
  summary: string;
}

export interface CampaignState {
  version: 1;
  seed: string;
  actorId: string;
  status: CampaignStatus;
  stage: number; // index into the actor's playbook
  intrusions: number; // 1 + number of pivots
  contained: number;
  identified: boolean; // IR attributes the activity once a stage is contained
  victimId: string;
  host: string;
  usedVictims: string[];
  infra: InfraRecord;
  lastShift: number | null;
  log: CampaignEntry[];
  intel: IntelRecord[];
  history: HistoryRecord[];
}

const MAX_HISTORY = 60;

function emptyInfra(): InfraRecord {
  return { domains: {}, ips: {}, hashes: {}, ipCities: {}, domainAgeDays: {} };
}

export function actorOf(state: CampaignState): Actor {
  // A stored campaign from an older build may name an actor that no longer
  // exists; carry on with the first one rather than failing to load.
  return actorById(state.actorId) ?? ACTORS[0];
}

// People the actor could plausibly target: Windows laptop users in the
// actor's preferred departments, not IT admins, and — where the playbook
// needs it — on push-notification MFA.
function candidates(world: World, actor: Actor, exclude: readonly string[]): string[] {
  const idx = new WorldIndex(world);
  const templates = actor.playbook.flatMap((s) => s.templates);
  const fits = (p: World['people'][number], all: boolean) => {
    const os = idx.deviceOf(p).os;
    return all ? templates.every((t) => compatible(t, p, os)) : actor.playbook.every((s) => s.templates.some((t) => compatible(t, p, os)));
  };
  const base = world.people.filter((p) => !p.adminAccount && !exclude.includes(p.id) && actor.victimDepartments.includes(p.department));
  for (const all of [true, false]) {
    const ok = base.filter((p) => fits(p, all));
    if (ok.length) return ok.map((p) => p.id);
  }
  const any = world.people.filter((p) => !p.adminAccount && !exclude.includes(p.id) && idx.deviceOf(p).os.startsWith('Windows'));
  return (any.length ? any : world.people).map((p) => p.id);
}

function pickVictim(world: World, actor: Actor, seed: string, exclude: readonly string[]): { victimId: string; host: string } {
  const rng = createRng(seed);
  const victimId = rng.pick(candidates(world, actor, exclude));
  return { victimId, host: new WorldIndex(world).deviceOf(new WorldIndex(world).person(victimId)).name };
}

export function startCampaign(world: World, seed: string, actorId?: string): CampaignState {
  const rng = createRng(`campaign:${seed}`);
  const actor = (actorId && actorById(actorId)) || rng.pick(ACTORS);
  const v = pickVictim(world, actor, `campaign:${seed}:victim:1`, []);
  return {
    version: 1,
    seed,
    actorId: actor.id,
    status: 'active',
    stage: 0,
    intrusions: 1,
    contained: 0,
    identified: false,
    victimId: v.victimId,
    host: v.host,
    usedVictims: [v.victimId],
    infra: emptyInfra(),
    lastShift: null,
    log: [],
    intel: [],
    history: [],
  };
}

// The actor's infrastructure as of a shift: domains age by the calendar
// days since the stage that last used them.
function agedInfra(state: CampaignState, world: World, shift: number): InfraRecord {
  const infra: InfraRecord = JSON.parse(JSON.stringify(state.infra)) as InfraRecord;
  if (state.lastShift !== null) {
    const days = Math.round((shiftDay(shift, world.org.utcOffset) - shiftDay(state.lastShift, world.org.utcOffset)) / DAY);
    for (const k of Object.keys(infra.domainAgeDays ?? {}) as (keyof NonNullable<InfraRecord['domainAgeDays']>)[]) {
      infra.domainAgeDays![k] = (infra.domainAgeDays![k] ?? 0) + days;
    }
  }
  return infra;
}

// The campaign's move for the given shift, or nothing once it has ended.
export function campaignSlot(state: CampaignState, world: World, shift: number): CampaignSlot | undefined {
  if (state.status !== 'active') return undefined;
  const actor = actorOf(state);
  const step = actor.playbook[state.stage];
  const idx = new WorldIndex(world);
  const victim = idx.person(state.victimId);
  const os = idx.deviceOf(victim).os;
  const options = step.templates.filter((t) => compatible(t, victim, os));
  const rng = createRng(`campaign:${state.seed}:slot:${shift}`);
  const templateId = rng.pick(options.length ? options : step.templates);

  const infra = agedInfra(state, world, shift);
  return {
    templateId,
    seed: `campaign:${state.seed}:${state.intrusions}:${state.stage}:${shift}`,
    campaign: { infra, foothold: { personId: state.victimId, host: state.host } },
  };
}

// ThreatIntel rows for what you reported, IncidentHistory rows for what you
// decided — dated relative to the shift being built.
export function campaignContext(state: CampaignState, world: World, shift: number): (b: CorpusBuilder) => void {
  const actor = actorOf(state);
  const today = shiftDay(shift, world.org.utcOffset);
  const ago = (s: number) => Math.max(1, Math.round((today - shiftDay(s, world.org.utcOffset)) / DAY)) * DAY;
  return (b) => {
    for (const r of state.intel) {
      b.intel({
        Indicator: r.indicator,
        IndicatorType: r.type,
        ThreatType: r.threat,
        Confidence: 90,
        Source: 'SOC — analyst report',
        FirstSeen: b.now - ago(r.shift) - 3 * HOUR,
        LastSeen: b.now - ago(r.shift) - 2 * HOUR,
        Description: r.note,
        Actor: r.actor ?? (state.identified ? actor.name : ''),
      });
    }
    for (const h of state.history) {
      if (h.shift >= shift) continue;
      b.incident({
        IncidentId: h.id,
        Opened: b.now - ago(h.shift) - 30 * MIN,
        Title: h.title,
        Severity: h.severity,
        Disposition: h.disposition,
        Status: h.status,
        Analyst: 'You',
        Entities: h.entities,
        Summary: h.summary,
      });
    }
  };
}

const INTEL_TYPE: Partial<Record<IndicatorSpec['kind'], IntelRecord['type']>> = { ip: 'ipv4', domain: 'domain', sha256: 'sha256', email: 'email', url: 'url' };

function fill(text: string, vars: Record<string, string>): string {
  return text.replace(/\{(\w+)\}/g, (_, k: string) => vars[k] ?? `{${k}}`).replace(/(^|[.!?]\s+)([a-z])/g, (_, pre: string, ch: string) => pre + ch.toUpperCase());
}

function historyOf(c: ResolvedCase, r: ShiftResult['cases'][number], shift: number, n: number): HistoryRecord {
  const v = r.verdict;
  const status = !r.handled ? 'Unworked at handover' : v.action === 'escalate' ? 'Escalated' : v.action === 'monitor' ? 'Monitoring' : 'Closed';
  const entities = v.indicators.map((i) => i.value).slice(0, 6).join(', ');
  return {
    id: `INC-${60000 + ((shift * 20 + n) % 9900)}`,
    shift,
    time: c.alert.time,
    title: c.alert.rule,
    severity: v.severity ? SEVERITY_LABELS[v.severity] : SEVERITY_LABELS[c.alert.severity],
    disposition: v.disposition ? DISPOSITION_LABELS[v.disposition] : 'Not triaged',
    status,
    entities,
    summary: (v.notes.trim() || (r.handled ? `${v.action ? ACTION_LABELS[v.action] : 'No action'} — no handover note.` : 'Left in the queue at shift end.')).slice(0, 280),
  };
}

// Apply a finished shift to the campaign.
export function recordShift(state: CampaignState, world: World, shift: number, infra: Scenario['infra'], result: ShiftResult, campaignAlertId?: string): CampaignState {
  const next: CampaignState = JSON.parse(JSON.stringify(state)) as CampaignState;
  // Every verdict of the shift becomes history.
  // The one alert a shift gets from a vulnerability case is not part of the
  // campaign's story: no history entry, and the INC numbers count only the rest.
  result.cases.filter((r) => !r.case.vulnLink).forEach((r, i) => next.history.push(historyOf(r.case, r, shift, i)));
  next.history = next.history.slice(-MAX_HISTORY);

  if (state.status !== 'active' || !campaignAlertId) return next;
  const r = result.cases.find((x) => x.alertId === campaignAlertId);
  if (!r) return next;
  const actor = actorOf(state);
  const step = actor.playbook[state.stage];
  const used = infra[campaignAlertId] ?? emptyInfra();
  const idx = new WorldIndex(world);
  const victim = idx.person(state.victimId);

  // Reported block indicators: into ThreatIntel, and burned for the actor.
  const reported = r.grade.indicators.results.filter((x) => x.verdict === 'correct' && x.spec && r.case.indicators.block.includes(x.spec)).map((x) => x.spec!);
  const burned = new Set(reported.map((s) => s.value.toLowerCase()));
  for (const s of reported) {
    const type = INTEL_TYPE[s.kind];
    if (!type || next.intel.some((x) => x.indicator.toLowerCase() === s.value.toLowerCase())) continue;
    next.intel.push({ indicator: s.value, type, threat: s.kind === 'sha256' ? 'Malware' : s.note?.toLowerCase().includes('phish') || s.note?.toLowerCase().includes('sender') ? 'Phishing' : 'C2', shift, note: `${s.note ?? 'Indicator'} — reported from ${r.alertId} (${r.case.alert.rule}).` });
  }
  // Infrastructure: keep what the actor used and you didn't block.
  // Start from the infrastructure as aged to this shift, so domains the actor
  // carries but did not use keep getting older.
  const merged: InfraRecord = agedInfra(state, world, shift);
  const keep = <K extends string>(into: Partial<Record<K, string>>, from: Partial<Record<K, string>>) => {
    for (const [k, v] of Object.entries(from) as [K, string][]) if (v) into[k] = v;
    for (const [k, v] of Object.entries(into) as [K, string][]) if (v && burned.has(v.toLowerCase())) delete into[k];
  };
  keep(merged.domains, used.domains);
  keep(merged.ips, used.ips);
  keep(merged.hashes, used.hashes);
  merged.ipCities = { ...merged.ipCities, ...used.ipCities };
  merged.domainAgeDays = { ...merged.domainAgeDays, ...used.domainAgeDays };
  for (const k of Object.keys(merged.domainAgeDays) as (keyof typeof merged.domainAgeDays)[]) if (!merged.domains[k]) delete merged.domainAgeDays[k];
  for (const k of Object.keys(merged.ipCities) as (keyof typeof merged.ipCities)[]) if (!merged.ips[k]) delete merged.ipCities[k];
  next.infra = merged;
  next.lastShift = shift;

  const v = r.verdict;
  const outcome: StageOutcome = v.disposition === 'true-positive' && v.action === 'escalate' ? 'contained' : v.disposition === 'true-positive' ? 'flagged' : 'missed';
  const vars = { actor: state.identified || outcome === 'contained' ? actor.name : 'the intruder', victim: victim.display, host: state.host };
  let narrative: string;
  if (outcome === 'contained') {
    next.contained += 1;
    next.identified = true;
    narrative = fill(step.contained, vars);
    if (next.contained >= actor.tenacity) {
      next.status = 'evicted';
      narrative += ` After ${next.contained} failed attempts, ${actor.name} has given up on ${world.org.name}. Campaign over — you won.`;
    } else {
      const v2 = pickVictim(world, actor, `campaign:${state.seed}:victim:${state.intrusions + 1}`, next.usedVictims);
      next.victimId = v2.victimId;
      next.host = v2.host;
      next.usedVictims.push(v2.victimId);
      next.stage = 0;
      next.intrusions += 1;
      narrative += ` ${actor.name} is regrouping${burned.size ? ' on fresh infrastructure' : ' — and you left some of its infrastructure unblocked'}.`;
    }
  } else {
    narrative = (outcome === 'flagged' ? 'You flagged it but did not escalate, so nobody contained it. ' : '') + fill(step.missed, vars);
    if (state.stage + 1 >= actor.playbook.length) {
      next.status = 'breached';
      narrative += ` Campaign over: ${actor.name} ${actor.objective}.`;
    } else {
      next.stage = state.stage + 1;
    }
  }
  next.log.push({ shift, alertId: campaignAlertId, templateId: r.case.templateId, stage: step.stage, outcome, victim: victim.upn, host: state.host, blocked: reported.map((s) => s.value), narrative });
  return next;
}

// A new campaign after the last one ended. The organisation's memory — your
// incident history and the intel you reported — carries over, with each
// indicator keeping the attribution IR had made for it.
export function nextCampaign(prev: CampaignState | null, world: World, seed: string, actorId?: string): CampaignState {
  const fresh = startCampaign(world, seed, actorId);
  if (!prev) return fresh;
  const name = prev.identified ? actorOf(prev).name : '';
  return {
    ...fresh,
    history: [...prev.history],
    intel: prev.intel.map((r) => ({ ...r, actor: r.actor ?? name })),
  };
}

// Short situational summary for the intel board.
export function campaignSummary(state: CampaignState): { actor: string; status: CampaignStatus; stage: CampaignStage | null; progress: number; contained: number; tenacity: number; lastNarrative: string | null } {
  const actor = actorOf(state);
  return {
    actor: state.identified ? actor.name : 'Unattributed activity',
    status: state.status,
    stage: state.status === 'active' ? actor.playbook[state.stage].stage : null,
    progress: state.status === 'breached' ? 1 : state.stage / actor.playbook.length,
    contained: state.contained,
    tenacity: actor.tenacity,
    lastNarrative: state.log.at(-1)?.narrative ?? null,
  };
}

