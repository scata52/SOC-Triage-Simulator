// Shared scenario checks: every template must build deterministically, stay
// synthetic, be internally consistent, and — the important one — be solvable
// through the query console: its reference investigation, run against a real
// sql.js database, must surface a row for every evidence point and every
// indicator it expects the analyst to report.

import { expect } from 'vitest';
import { generateWorld, type World } from '../../src/core/world/world.ts';
import { buildPracticeCase, type ResolvedCase, type Scenario } from '../../src/core/cases/scenario.ts';
import { templateById } from '../../src/core/cases/templates/index.ts';
import { technique } from '../../src/core/taxonomy/mitre.ts';
import { cysaDomain } from '../../src/core/taxonomy/cysa.ts';
import { SiemDatabase } from '../../src/core/query/engine.ts';
import { syntheticViolations } from './guardrails.ts';
import { sqljs } from './sql.ts';

const SWEEP = 30;
const worlds = new Map<string, World>();
export function world(seed: string): World {
  let w = worlds.get(seed);
  if (!w) {
    w = generateWorld(seed);
    worlds.set(seed, w);
  }
  return w;
}

export function checkStructure(c: ResolvedCase): void {
  const t = templateById(c.templateId)!;
  expect(c.alert.rule.trim()).not.toBe('');
  expect(c.alert.summary.trim()).not.toBe('');
  // Hunts start from a hypothesis, not an alert, so they carry no entities.
  if (c.alert.product !== 'Threat hunt') expect(c.alert.entities.length).toBeGreaterThan(0);
  expect(c.briefing.trim()).not.toBe('');
  expect(c.explanation.length).toBeGreaterThan(0);
  expect(c.pitfalls.length).toBeGreaterThan(0);
  expect(c.hints.length).toBeGreaterThanOrEqual(2);
  expect(c.solution.length).toBeGreaterThanOrEqual(1);
  expect(c.evidence.length).toBeGreaterThanOrEqual(2);
  expect(new Set(c.evidence.map((e) => e.id)).size).toBe(c.evidence.length);
  for (const e of c.evidence) expect(e.recordIds.length, `evidence ${e.id} has rows`).toBeGreaterThan(0);
  expect(new Set(c.rubric.map((r) => r.id)).size).toBe(c.rubric.length);
  for (const r of c.rubric) expect(r.keywords.length).toBeGreaterThan(0);
  for (const id of [...c.truth.techniques, ...(c.truth.alsoAccept ?? [])]) expect(technique(id), `technique ${id}`).toBeDefined();
  for (const id of c.truth.techniques) expect(c.truth.alsoAccept ?? []).not.toContain(id);
  for (const d of c.cysaDomains) expect(cysaDomain(d), `domain ${d}`).toBeDefined();
  const ind = c.indicators;
  if (c.truth.disposition === 'true-positive') {
    expect(c.truth.techniques.length).toBeGreaterThan(0);
    expect(ind.block.length + ind.scope.length).toBeGreaterThan(0);
  } else {
    expect(c.truth.techniques).toEqual([]);
    expect(ind.block).toEqual([]);
  }
  const blocked = new Set(ind.block.map((i) => i.value.toLowerCase()));
  for (const m of ind.mustNot) expect(blocked.has(m.value.toLowerCase()), `mustNot ${m.value} is also in block`).toBe(false);
  for (const i of [...ind.block, ...ind.scope, ...ind.mustNot]) expect(i.value.trim()).not.toBe('');
  expect(t.kind === 'incident').toBe(c.truth.disposition === 'true-positive' && c.truth.action === 'escalate' ? true : t.kind === 'incident');
}

export async function checkSolvable(s: Scenario, c: ResolvedCase): Promise<void> {
  const db = new SiemDatabase(await sqljs(), s.corpus);
  try {
    const found = new Set<string>();
    const texts: string[] = [c.alert.summary, ...c.alert.entities.map((e) => e.value)];
    for (const step of c.solution) {
      let r;
      try {
        r = db.run(step.kql, 'kql', { maxRows: 5000 });
      } catch (e) {
        throw new Error(`${c.templateId}: solution "${step.title}" failed: ${(e as Error).message}\n${step.kql}`);
      }
      if (step.expectEmpty) {
        expect(r.rows.length, `${c.templateId}: solution "${step.title}" should prove an absence but returned rows`).toBe(0);
        continue;
      }
      expect(r.rows.length, `${c.templateId}: solution "${step.title}" returned no rows`).toBeGreaterThan(0);
      if (r.recordIdColumn >= 0) for (const row of r.rows) found.add(String(row[r.recordIdColumn]));
      for (const row of r.rows) texts.push(row.map((v) => String(v ?? '')).join(' '));
    }
    for (const e of c.evidence) {
      expect(e.recordIds.some((id) => found.has(id)), `${c.templateId}: evidence "${e.id}" not surfaced by the reference investigation`).toBe(true);
    }
    const hay = texts.join('\n').toLowerCase();
    for (const i of [...c.indicators.block, ...c.indicators.scope]) {
      const variants = [i.value, ...(i.aliases ?? [])].map((v) => v.toLowerCase());
      expect(variants.some((v) => hay.includes(v)), `${c.templateId}: indicator ${i.value} never visible in the investigation`).toBe(true);
    }
  } finally {
    db.close();
  }
}

export async function checkTemplate(templateId: string, runs: { world: string; seed: string; db: boolean }[]): Promise<void> {
  for (const run of runs) {
    const w = world(run.world);
    const s = buildPracticeCase(w, templateId, run.seed);
    expect(s.cases).toHaveLength(1);
    const c = s.cases[0];
    checkStructure(c);
    expect(syntheticViolations(s.corpus, w), `${templateId} ${run.world}/${run.seed}`).toEqual([]);
    if (run.db) await checkSolvable(s, c);
  }
  // Crash sweep: many more seeds and worlds, structure only. Catches signal
  // rows that fall outside the window on unlucky timings.
  for (let i = 0; i < SWEEP; i++) {
    const s = buildPracticeCase(world(`sweep-${i % 5}`), templateId, `sweep-${i}`);
    checkStructure(s.cases[0]);
  }
  // Determinism: same inputs, same scenario.
  const first = runs[0];
  const a = buildPracticeCase(world(first.world), templateId, first.seed);
  const b = buildPracticeCase(world(first.world), templateId, first.seed);
  expect(JSON.stringify(a)).toBe(JSON.stringify(b));
}

export function standardRuns(n = 8, dbRuns = 4): { world: string; seed: string; db: boolean }[] {
  return Array.from({ length: n }, (_, i) => ({ world: `scn-world-${i % 3}`, seed: `s${i}`, db: i < dbRuns }));
}
