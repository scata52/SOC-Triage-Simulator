// DESIGN section 9, rules 2 and 4: scenario data is fully fictional. No string
// shaped like a real CVE identifier may appear in it, and there is no
// allowlist. "Scenario data" is everything under src/core/vuln/** (templates
// included) plus everything a vuln case generates.
//
// To extend (WP1b onward): return generated case output (briefing, hints,
// solution, explanation, debrief text and corpus rows, serialised) from
// generatedCaseSources(); every source is scanned by the same helper.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { generateCatalogue } from '../src/core/vuln/catalogue.ts';

// The pattern from DESIGN section 9 rule 4, verbatim.
export const REAL_CVE_ID = /CVE-\d{4}-\d{4,}/i;

interface Source {
  label: string;
  text: string;
}

// Lines of a source that match the pattern, as "label:line: excerpt".
export function cveViolations(source: Source): string[] {
  const out: string[] = [];
  source.text.split('\n').forEach((line, i) => {
    const m = REAL_CVE_ID.exec(line);
    if (m) out.push(`${source.label}:${i + 1}: ${m[0]}`);
  });
  return out;
}

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

// WP1b+: text of generated vuln cases (briefing, hints, solution KQL, explanation,
// pitfalls, rubric, attachments, corpus rows) for a spread of templates and seeds.
function generatedCaseSources(): Source[] {
  return [];
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
    for (const expected of ['model.ts', 'cvss31.ts', 'catalogue.ts', 'ids.ts']) expect(labels).toContain(`${VULN_DIR}/${expected}`);
    expect(files.flatMap(cveViolations)).toEqual([]);
  });

  it('finds none in serialised catalogues for several seeds', () => {
    const sources = catalogueSources();
    expect(sources.length).toBeGreaterThanOrEqual(5);
    for (const s of sources) expect(s.text.length).toBeGreaterThan(1000);
    expect(sources.flatMap(cveViolations)).toEqual([]);
  });

  it('finds none in generated case output', () => {
    expect(generatedCaseSources().flatMap(cveViolations)).toEqual([]);
  });
});
