import type { CaseTemplate, Category, Difficulty, TriageCase } from '../types.ts';
import { ALL_TEMPLATES } from '../data/templates/index.ts';
import { createRng, dailySeed, randomSeed } from './rng.ts';
import { createFaker } from './fakes.ts';

export interface GenerateOptions {
  seed?: string;
  category?: Category | 'any';
  difficulty?: Difficulty | 'any';
  // Template ids to avoid (e.g. the last few played) so cases don't repeat back-to-back.
  avoidTemplateIds?: string[];
  // Force a specific template (used by Case of the Day and deep-links).
  templateId?: string;
}

function filterTemplates(opts: GenerateOptions): CaseTemplate[] {
  let pool = ALL_TEMPLATES;
  if (opts.templateId) {
    const t = pool.find((x) => x.id === opts.templateId);
    return t ? [t] : pool;
  }
  if (opts.category && opts.category !== 'any') {
    pool = pool.filter((t) => t.category === opts.category);
  }
  if (opts.difficulty && opts.difficulty !== 'any') {
    pool = pool.filter((t) => t.difficulty === opts.difficulty);
  }
  if (opts.avoidTemplateIds?.length) {
    const avoid = new Set(opts.avoidTemplateIds);
    const narrowed = pool.filter((t) => !avoid.has(t.id));
    // Only apply the avoid-list if it leaves us something to pick from.
    if (narrowed.length > 0) pool = narrowed;
  }
  return pool.length > 0 ? pool : ALL_TEMPLATES;
}

export function generateCase(opts: GenerateOptions = {}): TriageCase {
  const seed = opts.seed ?? randomSeed();
  const pool = filterTemplates(opts);

  // One RNG stream picks the template; a second, template-scoped stream builds
  // it — so the same seed + same template always yields the same case, even if
  // the pool composition changes later.
  const picker = createRng(`pick:${seed}`);
  const template = picker.pick(pool);
  const rng = createRng(`${template.id}:${seed}`);
  const faker = createFaker(rng);
  const body = template.build({ rng, faker });

  return {
    id: `${template.id}#${seed}`,
    templateId: template.id,
    category: template.category,
    difficulty: template.difficulty,
    title: template.title,
    cysaDomains: template.cysaDomains,
    ...body,
  };
}

// Deterministic "Case of the Day".
export function generateDailyCase(date = new Date()): TriageCase {
  return generateCase({ seed: dailySeed(date) });
}

// Re-materialise a case from its id (templateId#seed) — for history/replay.
export function regenerateFromId(caseId: string): TriageCase | null {
  const idx = caseId.indexOf('#');
  if (idx < 0) return null;
  const templateId = caseId.slice(0, idx);
  const seed = caseId.slice(idx + 1);
  if (!ALL_TEMPLATES.some((t) => t.id === templateId)) return null;
  return generateCase({ seed, templateId });
}

export const DIFFICULTY_LABELS: Record<Difficulty, string> = {
  tier1: 'Tier 1',
  tier2: 'Tier 2',
  tier3: 'Tier 3',
};

export const DIFFICULTY_MULTIPLIER: Record<Difficulty, number> = {
  tier1: 1,
  tier2: 1.5,
  tier3: 2,
};
