import { describe, expect, it } from 'vitest';
import { resolveCase, studyRoute } from '../src/ui/lib/cases.ts';
import { ALL_TEMPLATES } from '../src/core/cases/templates/index.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { resolveVulnTemplate, vulnCaseTypes } from '../src/core/vuln/worklist.ts';

const BASES = ['2026-01-01', 'a', 'seed-7', 'x9z', 'study-0'];
const TYPES = vulnCaseTypes(VULN_TEMPLATES);

describe('studyRoute resolves to exactly the suggested template', () => {
  it('every vuln template, over several bases: a vuln-case route whose slug and seed give that template', () => {
    for (const t of VULN_TEMPLATES) {
      for (const base of BASES) {
        const r = studyRoute(t.id, base);
        expect(r.name, `${t.id} ${base}`).toBe('vuln-case');
        if (r.name !== 'vuln-case') continue;
        const type = TYPES.find((x) => x.slug === r.slug);
        expect(type, `${t.id}: slug ${r.slug}`).toBeDefined();
        expect(resolveVulnTemplate(type!, r.seed).id, `${t.id} ${base}`).toBe(t.id);
        expect('study' in r, 'no study flag on a vuln route').toBe(false);
      }
    }
  });

  it('every SOC template, over several bases: a study case route whose slug and seed give that template', () => {
    for (const t of ALL_TEMPLATES) {
      for (const base of BASES) {
        const r = studyRoute(t.id, base);
        expect(r.name, `${t.id} ${base}`).toBe('case');
        if (r.name !== 'case') continue;
        expect(r.study).toBe(true);
        expect(resolveCase(r.slug, r.seed)?.id, `${t.id} ${base}`).toBe(t.id);
      }
    }
  });
});
