// buildVulnScenario: one vulnerability-management case as a corpus plus a
// resolved spec, deterministic in (worldSeed, templateId, seed). It reuses the
// world, the RNG, the corpus builder and the presence planner of the SOC path,
// but not the log noise: a vuln case is about joining context (findings,
// intel, inventory, controls, tickets), so its corpus is hundreds of rows, not
// thousands (DESIGN section 6.3).

import { createRng } from '../rng.ts';
import { generateWorld, type World } from '../world/world.ts';
import { CorpusBuilder, recordIdOf, type Corpus } from '../logs/corpus.ts';
import { planSessions } from '../logs/noise/presence.ts';
import { DAY, iso, utcDayStart } from '../logs/time.ts';
import { Infra } from '../cases/infra.ts';
import { Picker } from '../cases/picker.ts';
import { practiceTiming, type ResolvedEvidence } from '../cases/scenario.ts';
import type { Attachment, SolutionStep } from '../cases/model.ts';
import type { CaseReference, Difficulty, RubricItem } from '../types.ts';
import { generateCatalogue } from './catalogue.ts';
import type { FindingTruth, VulnConstraints, VulnTemplate } from './model.ts';
import { vulnTemplateById } from './registry.ts';
import { ScanWriter } from './scan-writer.ts';

// The log window of a vuln case. Only the (few) log tables a template writes,
// such as firewall sessions that prove exposure, live inside it.
export const VULN_WINDOW_DAYS = 14;

export interface VulnScenarioOptions {
  worldSeed: string;
  templateId: string;
  seed: string;
  // A world already generated for worldSeed (the worker and tests cache one).
  world?: World;
  // Build from this template instead of looking it up in the registry
  // (fixtures and tests).
  template?: VulnTemplate;
}

export interface ResolvedVulnFinding {
  findingId: string;
  recordId: string; // the finding's VulnFindings row
  // Read from that row; answer-key data for the continuity ledger (DESIGN section 8),
  // used only after submit. sharedHost: the host is a device of the shared world
  // (not one a case added to its own scope), so a shift corpus can show it.
  host: string;
  vulnId: string;
  sharedHost: boolean;
  truth: FindingTruth;
  weight: number;
  mustNotMiss: boolean;
  lesson: boolean; // the lesson text is about this finding (DESIGN section 5.8)
  evidence: ResolvedEvidence[];
}

export interface ResolvedVulnCase {
  id: string;
  templateId: string;
  seed: string;
  difficulty: Difficulty;
  title: string;
  lesson: string;
  cysaDomains: string[];
  objectives: string[];
  twin?: string;
  kind: 'vuln';
  now: string;
  briefing: string;
  attachments: Attachment[];
  findings: ResolvedVulnFinding[];
  constraints: VulnConstraints;
  idealOrder: string[];
  tiers: string[][];
  hints: string[];
  solution: SolutionStep[];
  rubric: RubricItem[];
  explanation: string[];
  pitfalls: string[];
  references: CaseReference[];
}

export interface VulnScenario {
  worldSeed: string;
  now: string;
  corpus: Corpus;
  case: ResolvedVulnCase;
}

export function buildVulnScenario(opts: VulnScenarioOptions): VulnScenario {
  const template = opts.template ?? vulnTemplateById(opts.templateId);
  if (!template) throw new Error(`Unknown vuln template ${opts.templateId}`);
  if (opts.template && opts.template.id !== opts.templateId) throw new Error(`Template object is ${opts.template.id}, not ${opts.templateId}`);
  const world = opts.world ?? generateWorld(opts.worldSeed);
  if (world.seed !== opts.worldSeed) throw new Error(`World ${world.seed} does not match worldSeed ${opts.worldSeed}`);

  // The case date: a weekday in business hours, as for a practice case. It
  // depends on the seed and not on the template, so twin templates built with
  // the same seed share the date and (below) the catalogue.
  const { now } = practiceTiming('vuln-case', opts.seed, 'business', world.org.utcOffset);
  const rng = createRng(`vuln-scenario:${opts.worldSeed}:${template.id}:${opts.seed}`);
  const b = new CorpusBuilder({ world, rng: rng.fork('corpus'), windowStart: now - VULN_WINDOW_DAYS * DAY, windowEnd: now, now });
  const sessions = planSessions(b, rng.fork('presence'));

  // One catalogue per (world, seed): twin templates with the same seed see the
  // same fictional vulnerabilities and can pair their deciders.
  const catalogue = generateCatalogue(`${opts.worldSeed}/${opts.seed}`, utcDayStart(now));
  const scan = new ScanWriter(b, rng.fork('scan'), catalogue);

  const crng = createRng(`${template.id}:${opts.seed}:${world.seed}`);
  const spec = template.build({
    rng: crng.fork('build'),
    world,
    idx: b.idx,
    log: b,
    at: now,
    now,
    sessions,
    pick: new Picker(crng.fork('pick'), b.idx, sessions, b, now),
    infra: new Infra(b, crng.fork('infra'), world.org.short),
    vuln: { catalogue, scan },
  });

  // Catch template mistakes at build time, with the template's name on them.
  const ids = spec.findings.map((f) => f.findingId);
  if (new Set(ids).size !== ids.length) throw new Error(`${template.id}: duplicate findingId`);
  for (const f of spec.findings) {
    if (f.row.table !== 'VulnFindings') throw new Error(`${template.id}: finding ${f.findingId} must point at a VulnFindings row, not ${f.row.table}`);
    if (f.row.row.FindingId !== f.findingId) throw new Error(`${template.id}: finding ${f.findingId} does not match its row (${String(f.row.row.FindingId)})`);
  }
  const known = new Set(ids);
  const order = [...spec.idealOrder, ...spec.tiers.flat()];
  for (const id of order) if (!known.has(id)) throw new Error(`${template.id}: idealOrder/tiers name unknown finding ${id}`);
  if (new Set(spec.idealOrder).size !== spec.idealOrder.length) throw new Error(`${template.id}: idealOrder repeats a finding`);

  // The ordering grade rests on the tiers (DESIGN section 5.2): relevance 3, 2, 1
  // for the three tiers and 0 for everything else, so they must be well formed.
  if (spec.tiers.length > 3) throw new Error(`${template.id}: at most three tiers (relevance 3, 2, 1), found ${spec.tiers.length}`);
  const tierOf = new Map<string, number>();
  spec.tiers.forEach((tier, i) => {
    for (const id of tier) {
      if (tierOf.has(id)) throw new Error(`${template.id}: tiers list finding ${id} more than once`);
      tierOf.set(id, i);
    }
  });
  for (const f of spec.findings) {
    const tiered = tierOf.has(f.findingId);
    if (tiered && (f.truth.decision === 'false-positive' || f.truth.decision === 'accept')) throw new Error(`${template.id}: finding ${f.findingId} is ${f.truth.decision} and must not be in a tier`);
    if (f.mustNotMiss && !tiered) throw new Error(`${template.id}: must-not-miss finding ${f.findingId} must be in a tier`);
  }
  // The lesson gate (DESIGN section 5.8) needs a lesson finding, an SLA to hold
  // every real key finding to, and something to pin.
  if (!spec.findings.some((f) => f.lesson === true)) throw new Error(`${template.id}: no finding is marked as the lesson finding`);
  for (const f of spec.findings) {
    const real = f.truth.decision !== 'false-positive';
    if (real && (f.lesson === true || f.mustNotMiss === true) && f.truth.slaLatest == null) throw new Error(`${template.id}: key finding ${f.findingId} needs truth.slaLatest`);
  }
  if (!spec.findings.some((f) => f.evidence.length > 0)) throw new Error(`${template.id}: the case has no evidence point`);
  for (const id of tierOf.keys()) if (!spec.idealOrder.includes(id)) throw new Error(`${template.id}: tiered finding ${id} is missing from idealOrder`);
  // Along idealOrder the tier index never falls, so relevance never rises;
  // untiered findings, if listed, come after every tiered one.
  let tierSoFar = 0;
  for (const id of spec.idealOrder) {
    const rank = tierOf.get(id) ?? spec.tiers.length;
    if (rank < tierSoFar) throw new Error(`${template.id}: idealOrder puts ${id} after a less urgent finding`);
    tierSoFar = rank;
  }

  const corpus = b.finalize();

  const resolved: ResolvedVulnCase = {
    id: `${template.id}~${opts.seed}`,
    templateId: template.id,
    seed: opts.seed,
    difficulty: template.difficulty,
    title: template.title,
    lesson: template.lesson,
    cysaDomains: template.cysaDomains,
    objectives: template.objectives,
    twin: template.twin,
    kind: 'vuln',
    now: iso(now),
    briefing: spec.briefing,
    attachments: spec.attachments ?? [],
    findings: spec.findings.map((f) => ({
      findingId: f.findingId,
      recordId: recordIdOf(f.row),
      host: String(f.row.row.DeviceName ?? ''),
      vulnId: String(f.row.row.VulnId ?? ''),
      sharedHost: world.hosts.some((h) => h.name === f.row.row.DeviceName),
      truth: f.truth,
      weight: f.weight,
      mustNotMiss: f.mustNotMiss ?? false,
      lesson: f.lesson ?? false,
      evidence: f.evidence.map((e) => ({
        id: e.id,
        label: e.label,
        why: e.why,
        recordIds: [...new Set(e.rows.map((r) => recordIdOf(r)))],
      })),
    })),
    constraints: spec.constraints,
    idealOrder: spec.idealOrder,
    tiers: spec.tiers,
    hints: spec.hints,
    solution: spec.solution,
    rubric: spec.rubric,
    explanation: spec.explanation,
    pitfalls: spec.pitfalls,
    references: spec.references,
  };

  return { worldSeed: world.seed, now: iso(now), corpus, case: resolved };
}
