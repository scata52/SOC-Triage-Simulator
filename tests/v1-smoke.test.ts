// v1 smoke test, ported to Vitest unchanged in substance: every v1 template x
// many seeds must build, reference only catalogued techniques, grade a perfect
// answer at 100%, and regenerate deterministically from its id. Removed when
// the v1 engine is retired in favour of the v2 scenario suite.
import { describe, expect, it } from 'vitest';
import { ALL_TEMPLATES } from '../src/data/templates/index.ts';
import { generateCase, regenerateFromId } from '../src/engine/generator.ts';
import { gradeResponse, MAX_SCORE } from '../src/engine/grading.ts';
import { technique } from '../src/data/mitre.ts';
import { cysaDomain } from '../src/data/cysa.ts';

const SEEDS_PER_TEMPLATE = 40;

describe('v1 templates', () => {
  for (const t of ALL_TEMPLATES) {
    it(`${t.id} builds, grades and regenerates across ${SEEDS_PER_TEMPLATE} seeds`, () => {
      for (let i = 0; i < SEEDS_PER_TEMPLATE; i++) {
        const c = generateCase({ seed: `smoke-${t.id}-${i}`, templateId: t.id });

        expect(c.templateId).toBe(t.id);
        expect(c.alert.trim()).not.toBe('');
        expect(c.artifacts.length).toBeGreaterThan(0);
        for (const a of c.artifacts) expect(a.lines.length).toBeGreaterThan(0);
        expect(c.explanation.length).toBeGreaterThan(0);
        expect(c.rubric.length).toBeGreaterThan(0);
        expect(new Set(c.rubric.map((r) => r.id)).size).toBe(c.rubric.length);
        for (const r of c.rubric) expect(r.keywords.length).toBeGreaterThan(0);

        for (const id of c.groundTruth.techniques) expect(technique(id), id).toBeDefined();
        for (const d of c.cysaDomains) expect(cysaDomain(d), d).toBeDefined();

        if (c.groundTruth.disposition === 'true-positive') {
          expect(c.groundTruth.techniques.length).toBeGreaterThan(0);
        } else {
          expect(c.groundTruth.techniques).toEqual([]);
        }

        const perfect = gradeResponse(c, {
          disposition: c.groundTruth.disposition,
          severity: c.groundTruth.severity,
          action: c.groundTruth.action,
          techniques: c.groundTruth.techniques,
          notes: '',
        });
        expect(perfect.score).toBe(MAX_SCORE);

        const empty = gradeResponse(c, { disposition: null, severity: null, action: null, techniques: [], notes: '' });
        expect(empty.score).toBe(c.groundTruth.techniques.length === 0 ? 25 : 0);

        expect(JSON.stringify(regenerateFromId(c.id))).toBe(JSON.stringify(c));
      }
    });
  }

  it('random generation rotates across templates', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 300; i++) seen.add(generateCase({ seed: `rot-${i}` }).templateId);
    expect(seen.size).toBeGreaterThanOrEqual(ALL_TEMPLATES.length * 0.8);
  });
});
