// A scenario is one corpus holding one or more cases: a practice case, or a
// whole shift where the noise of one alert is the background of another.

import { createRng } from '../rng.ts';
import type { World } from '../world/world.ts';
import { CorpusBuilder, recordIdOf, type Corpus } from '../logs/corpus.ts';
import { generateNoise } from '../logs/noise/index.ts';
import { atLocalHour, DAY, HOUR, iso, MIN, localWeekday } from '../logs/time.ts';
import type { AlertEntity, Attachment, CaseKind, CaseSpec, CaseTemplate, Indicators, SolutionStep, TimePreference } from './model.ts';
import type { Category, CaseReference, Difficulty, GroundTruth, RubricItem, Severity } from '../types.ts';
import { Picker } from './picker.ts';
import { Infra, type InfraRecord } from './infra.ts';
import { templateById } from './templates/index.ts';
import type { VulnHook } from '../shift/vuln-hook.ts';
import type { VulnDecision, VulnSchedule } from '../vuln/model.ts';

export interface ScenarioItem {
  alertId: string;
  templateId: string;
  seed: string;
  at: number;
  campaign?: { infra: InfraRecord; foothold?: { personId?: string; host?: string } };
  vulnHook?: VulnHook;
}

export interface ScenarioOptions {
  world: World;
  seed: string;
  now: number;
  windowHours?: number;
  items: ScenarioItem[];
  historyFiller?: boolean;
  // Extra context rows (e.g. campaign threat intel and incident history).
  context?: (b: CorpusBuilder) => void;
}

export interface ResolvedEvidence {
  id: string;
  label: string;
  why: string;
  recordIds: string[];
}

export interface ResolvedCase {
  id: string;
  alertId: string;
  templateId: string;
  seed: string;
  category: Category;
  difficulty: Difficulty;
  title: string;
  lesson: string;
  cysaDomains: string[];
  kind: CaseKind;
  twin?: string;
  alert: {
    rule: string;
    product: string;
    severity: Severity;
    time: string;
    summary: string;
    entities: AlertEntity[];
    fields: [string, string][];
  };
  briefing: string;
  attachments: Attachment[];
  truth: GroundTruth;
  evidence: ResolvedEvidence[];
  indicators: Indicators;
  hints: string[];
  solution: SolutionStep[];
  rubric: RubricItem[];
  explanation: string[];
  pitfalls: string[];
  references: CaseReference[];
  // Set on the one alert a shift gets from a vulnerability case (DESIGN section 8):
  // answer-key data for the debrief, shown only after the alert is submitted.
  vulnLink?: VulnLink;
}

export interface VulnLink {
  caseRef: string;
  vulnId: string;
  host: string;
  decision: VulnDecision;
  schedule: VulnSchedule;
}

export interface Scenario {
  worldSeed: string;
  now: string;
  corpus: Corpus;
  cases: ResolvedCase[];
  infra: Record<string, InfraRecord>;
}

export function buildScenario(opts: ScenarioOptions): Scenario {
  const { world, now } = opts;
  const rng = createRng(`scenario:${opts.seed}`);
  const b = new CorpusBuilder({
    world,
    rng: rng.fork('corpus'),
    windowStart: now - (opts.windowHours ?? 20) * HOUR,
    windowEnd: now,
    now,
    reservedExternal: opts.items.flatMap((i) => Object.values(i.campaign?.infra.ips ?? {}).filter((x): x is string => !!x)),
  });
  const sessions = generateNoise(b, { historyFiller: opts.historyFiller ?? false });
  opts.context?.(b);

  // Items that carry a vulnerability hook are built after all the others: the
  // builder's shared state (external addresses, ticket numbers, the corpus rng)
  // then reaches every other item exactly as it would without them. The result
  // stays in the order of `opts.items`.
  const buildOrder = [...opts.items.keys()].sort((i, j) => Number(!!opts.items[i].vulnHook) - Number(!!opts.items[j].vulnHook) || i - j);
  const builtByIndex = new Map<number, { item: ScenarioItem; template: CaseTemplate; spec: CaseSpec; infra: Infra }>();
  for (const index of buildOrder) {
    const item = opts.items[index];
    const template = templateById(item.templateId);
    if (!template) throw new Error(`Unknown template ${item.templateId}`);
    const crng = createRng(`${item.templateId}:${item.seed}:${world.seed}`);
    const infra = new Infra(b, crng.fork('infra'), world.org.short, item.campaign?.infra);
    const spec = template.build({
      rng: crng.fork('build'),
      world,
      idx: b.idx,
      log: b,
      at: item.at,
      now,
      sessions,
      pick: new Picker(crng.fork('pick'), b.idx, sessions, b, item.at),
      infra,
      foothold: item.campaign?.foothold,
      vulnHook: item.vulnHook,
    });
    builtByIndex.set(index, { item, template, spec, infra });
  }
  const built = opts.items.map((_, i) => builtByIndex.get(i)!);

  const corpus = b.finalize();

  const cases: ResolvedCase[] = built.map(({ item, template, spec }) => ({
    id: `${template.id}~${item.seed}`,
    alertId: item.alertId,
    templateId: template.id,
    seed: item.seed,
    category: template.category,
    difficulty: template.difficulty,
    title: template.title,
    lesson: template.lesson,
    cysaDomains: template.cysaDomains,
    kind: template.kind,
    twin: template.twin,
    alert: {
      rule: spec.alert.rule,
      product: spec.alert.product,
      severity: spec.alert.severity,
      time: iso(spec.alert.time),
      summary: spec.alert.summary,
      entities: spec.alert.entities,
      fields: spec.alert.fields ?? [],
    },
    briefing: spec.briefing,
    attachments: spec.attachments ?? [],
    truth: spec.truth,
    evidence: spec.evidence.map((e) => ({
      id: e.id,
      label: e.label,
      why: e.why,
      recordIds: [...new Set(e.rows.map((r) => {
        try {
          return recordIdOf(r);
        } catch {
          throw new Error(`${template.id}: evidence "${e.id}" row in ${r.table} fell outside the corpus window`);
        }
      }))],
    })),
    indicators: spec.indicators,
    hints: spec.hints,
    solution: spec.solution,
    rubric: spec.rubric,
    explanation: spec.explanation,
    pitfalls: spec.pitfalls,
    references: spec.references,
    ...(item.vulnHook ? { vulnLink: { caseRef: item.vulnHook.caseRef, vulnId: item.vulnHook.vulnId, host: item.vulnHook.host, decision: item.vulnHook.decision, schedule: item.vulnHook.schedule } } : {}),
  }));

  return {
    worldSeed: world.seed,
    now: iso(now),
    corpus,
    cases,
    infra: Object.fromEntries(built.map(({ item, infra }) => [item.alertId, infra.record()])),
  };
}

// Deterministic timing for a standalone practice case: a weekday in the
// simulated season, at a local time that suits the template.
export function practiceTiming(templateId: string, seed: string, when: TimePreference = 'business', utcOffset = 2): { at: number; now: number } {
  const rng = createRng(`timing:${templateId}:${seed}`);
  let day = Date.UTC(2026, 8, 1) + rng.int(0, 58) * DAY;
  while ([0, 6].includes(localWeekday(day + 12 * HOUR, utcOffset))) day += DAY;
  let hour: number;
  if (when === 'off-hours') hour = rng.bool(0.6) ? rng.float(0.8, 5.2) : rng.float(20.5, 23.2);
  else if (when === 'any') hour = rng.float(7.5, 21.5);
  else hour = rng.float(9.2, 16.6);
  const at = Math.floor(atLocalHour(day, hour, utcOffset) / 1000) * 1000;
  return { at, now: at + rng.int(6, 22) * MIN + rng.int(0, 59) * 1000 };
}

export function buildPracticeCase(world: World, templateId: string, seed: string): Scenario {
  const template = templateById(templateId);
  if (!template) throw new Error(`Unknown template ${templateId}`);
  const { at, now } = practiceTiming(templateId, seed, template.when, world.org.utcOffset);
  return buildScenario({
    world,
    seed: `practice:${templateId}:${seed}`,
    now,
    items: [{ alertId: 'A1', templateId, seed, at }],
    historyFiller: true,
  });
}
