// DESIGN section 9, rules 2 and 4: scenario data is fully fictional. No string
// shaped like a real CVE identifier may appear in it, and there is no
// allowlist. "Scenario data" is everything under src/core/vuln/** (templates
// included) plus everything a vuln case generates: corpus rows, briefing,
// hints, solution, explanation and debrief text.
//
// generatedCaseSources() serialises the output of every registered template
// and of the engine fixture for several seeds; every source is scanned by the
// same helper as the source files.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { generateCatalogue } from '../src/core/vuln/catalogue.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { buildVulnScenario } from '../src/core/vuln/scenario.ts';
import { cveViolations, type Source } from './helpers/cve-guard.ts';
import { fixtureTier3 } from './helpers/vuln-fixture.ts';
import { world } from './helpers/scenario-check.ts';

const VULN_DIR = 'src/core/vuln';

function allFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? allFiles(p) : [p];
  });
}

// Every file under src/core/vuln/**, whatever its extension.
function sourceFiles(): Source[] {
  return allFiles(VULN_DIR).map((p) => ({ label: p.split('\\').join('/'), text: readFileSync(p, 'utf8') }));
}

const REFERENCE_DATE = Date.UTC(2026, 8, 28);

// Serialised catalogues for several seeds (every field, as the corpus will see it).
function catalogueSources(): Source[] {
  return ['guardrail-a', 'guardrail-b', 'guardrail-c', 'guardrail-d', 'guardrail-e', 'guardrail-f', 'guardrail-g', 'guardrail-h'].map((seed) => ({
    label: `catalogue(${seed})`,
    text: JSON.stringify(generateCatalogue(seed, REFERENCE_DATE), null, 1),
  }));
}

const GUARDRAIL_SEEDS = ['g0', 'g1', 'g2', 'g3', 'g4', 'g5'];

// Text of generated vuln cases for a spread of seeds: the resolved case
// (briefing, hints, solution KQL, explanation, pitfalls, rubric, attachments,
// evidence labels, references) and the whole corpus, serialised one item per line.
function generatedCaseSources(): Source[] {
  const out: Source[] = [];
  for (const template of [...VULN_TEMPLATES, fixtureTier3]) {
    GUARDRAIL_SEEDS.forEach((seed, i) => {
      const w = world(`guardrail-world-${i % 3}`);
      const s = buildVulnScenario({ worldSeed: w.seed, templateId: template.id, seed, world: w, template });
      out.push({ label: `case(${template.id}/${seed}).spec`, text: JSON.stringify(s.case, null, 1) });
      out.push({ label: `case(${template.id}/${seed}).corpus`, text: JSON.stringify(s.corpus, null, 1) });
    });
  }
  return out;
}

describe('no real CVE identifiers in scenario data (DESIGN section 9)', () => {
  it('the checker flags CVE-shaped ids and ignores fictional ones', () => {
    // Built by concatenation so this file carries no CVE-shaped literal itself.
    const cve = (year: string, serial: string) => 'CVE' + '-' + year + '-' + serial;
    for (const flagged of [cve('2020', '1234'), cve('1999', '0001'), cve('2026', '123456'), 'see ' + cve('2021', '90001').toLowerCase() + ' for details']) {
      expect(cveViolations({ label: 't', text: flagged }), flagged).toHaveLength(1);
    }
    for (const fine of ['SIMVULN-2026-10421', cve('20', '1234'), cve('2020', '123'), 'CVE', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']) {
      expect(cveViolations({ label: 't', text: fine }), fine).toEqual([]);
    }
    expect(cveViolations({ label: 'f', text: 'ok\nbad ' + cve('2019', '0007') + '\nok' })).toEqual(['f:2: ' + cve('2019', '0007')]);
  });

  it('scans every file under src/core/vuln/**', () => {
    const files = sourceFiles();
    const labels = files.map((f) => f.label);
    for (const expected of ['model.ts', 'cvss31.ts', 'catalogue.ts', 'ids.ts', 'scan-writer.ts', 'scenario.ts', 'registry.ts']) expect(labels).toContain(`${VULN_DIR}/${expected}`);
    expect(files.flatMap(cveViolations)).toEqual([]);
  });

  it('finds none in serialised catalogues for several seeds', () => {
    const sources = catalogueSources();
    expect(sources.length).toBeGreaterThanOrEqual(5);
    for (const s of sources) expect(s.text.length).toBeGreaterThan(1000);
    expect(sources.flatMap(cveViolations)).toEqual([]);
  });

  it('finds none in generated case output (spec text and corpus rows)', () => {
    const sources = generatedCaseSources();
    // The fixture alone contributes a spec and a corpus per seed.
    expect(sources.length).toBeGreaterThanOrEqual(GUARDRAIL_SEEDS.length * 2);
    for (const s of sources) expect(s.text.length, s.label).toBeGreaterThan(1000);
    expect(sources.some((s) => s.text.includes('SIMVULN-'))).toBe(true);
    expect(sources.flatMap(cveViolations)).toEqual([]);
  });
});
