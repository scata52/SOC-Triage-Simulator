// Alert types for the practice library. Twins share a title on purpose (the
// same detection with opposite answers), so the library offers alert types,
// not templates, and the seed decides which variant you get. Neither the
// card nor the URL gives the answer away.

import { createRng } from '../../core/rng.ts';
import type { CaseTemplate } from '../../core/cases/model.ts';
import { ALL_TEMPLATES, templateById } from '../../core/cases/templates/index.ts';
import type { Category, Difficulty } from '../../core/types.ts';

export interface AlertType {
  slug: string;
  title: string;
  templates: CaseTemplate[];
  category: Category;
  difficulty: Difficulty;
  cysaDomains: string[];
  hunt: boolean;
}

export function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

export const ALERT_TYPES: AlertType[] = (() => {
  const by = new Map<string, CaseTemplate[]>();
  for (const t of ALL_TEMPLATES) by.set(t.title, [...(by.get(t.title) ?? []), t]);
  return [...by.entries()].map(([title, templates]) => ({
    slug: slugify(title),
    title,
    templates,
    category: templates[0].category,
    difficulty: templates[0].difficulty,
    cysaDomains: [...new Set(templates.flatMap((t) => t.cysaDomains))].sort(),
    hunt: title.startsWith('Threat hunt'),
  }));
})();

const BY_SLUG = new Map(ALERT_TYPES.map((a) => [a.slug, a]));

export function alertType(slug: string): AlertType | undefined {
  return BY_SLUG.get(slug);
}

export function slugOf(templateId: string): string {
  const t = templateById(templateId);
  return t ? slugify(t.title) : templateId;
}

export function resolveCase(slug: string, seed: string): CaseTemplate | undefined {
  const a = BY_SLUG.get(slug);
  if (!a) return undefined;
  if (a.templates.length === 1) return a.templates[0];
  return a.templates[createRng(`variant:${slug}:${seed}`).int(0, a.templates.length - 1)];
}

// A seed (derived from `base`) whose variant is the given template.
export function seedFor(templateId: string, base: string): string {
  const slug = slugOf(templateId);
  for (let i = 0; i < 200; i++) {
    const s = i === 0 ? base : `${base}${i.toString(36)}`;
    if (resolveCase(slug, s)?.id === templateId) return s;
  }
  return base;
}

export const DAILY_WORLD = 'daily-world-v2';

export function dailyCase(seed: string): { slug: string; seed: string } {
  const pool = ALERT_TYPES.filter((a) => !a.hunt);
  return { slug: createRng(`daily:${seed}`).pick(pool).slug, seed };
}
