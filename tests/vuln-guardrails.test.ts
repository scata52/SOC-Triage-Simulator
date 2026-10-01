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
import { buildFor, vulnRuns } from './helpers/vuln-scenario-check.ts';

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

// WP1f acceptance 6: every domain-like token in vuln-authored generated data is a reserved name.
//
// Reserved: RFC 2606 / 6761 names (.example, .test, .invalid, .localhost, and example.com / .net / .org).
// EXEMPT (explicit, pending NEEDS-HUMAN-CHECK 4 in docs/vuln-mgmt/PLAN.md): the shared world's organisation
// domain and its subdomains (e.g. corp.<org domain>, mail addresses of its staff). The world is shared with the
// SOC modes, so changing it would change SOC output, which stays unchanged.
// EXEMPT, listed below: the hosts of the real documentation citations a case links (its `references`). Nothing
// else is: a case reference to any other host fails this test.
// A bare token (not the host of a URL or of an e-mail address) is also allowed when it is a known file name or
// extension ("report.pdf") or a world account name ("nina.quinn"), because those look like hosts.
describe('reserved domains in generated vuln data (WP1f)', () => {
  const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost']);
  const RESERVED_NAMES = ['example.com', 'example.net', 'example.org'];
  const CITATION_HOSTS = new Set(['www.first.org', 'www.cisa.gov', 'www.comptia.org']);
  // File names and code-like tokens ("report.pdf", "Table.Column") are not domains. Bare tokens only.
  const FILE_EXTENSIONS = new Set(['pdf', 'csv', 'txt', 'exe', 'dll', 'log', 'json', 'xml', 'zip', 'msi', 'ps1', 'sh', 'conf', 'cfg', 'yml', 'yaml', 'html', 'htm', 'js', 'py', 'docx', 'xlsx', 'bak', 'sql', 'tar', 'gz', 'ini', 'bat', 'so', 'dat', 'tmp', 'md', 'png', 'jpg', 'pem', 'key', 'crt', 'tsv']);
  const TOKEN = /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w-])/gi;
  const URL_HOST = /[a-z][a-z0-9+.-]*:\/\/(?:[^/@\s"'<>]*@)?([^/:?#\s"'<>]+)/gi;
  const MAIL_HOST = /[\w.+-]+@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)/gi;

  const strings = (value: unknown, out: string[] = []): string[] => {
    if (typeof value === 'string') out.push(value);
    else if (Array.isArray(value)) for (const v of value) strings(v, out);
    else if (value && typeof value === 'object') for (const v of Object.values(value)) strings(v, out);
    return out;
  };

  // First.last account names look like hosts; the world's people and service accounts are the known ones.
  function accountNames(w: ReturnType<typeof world>): Set<string> {
    const names = new Set<string>();
    for (const p of w.people) {
      for (const n of [p.sam, p.upn.split('@')[0], p.adminAccount, `${p.first}.${p.last}`]) if (n) names.add(n.toLowerCase());
    }
    for (const a of w.serviceAccounts) names.add(a.name.toLowerCase());
    return names;
  }

  function violations(text: string, orgDomain: string, accounts: ReadonlySet<string> = new Set()): string[] {
    const org = orgDomain.toLowerCase();
    const allowedHost = (host: string): boolean => {
      const tld = host.slice(host.lastIndexOf('.') + 1);
      return RESERVED_TLDS.has(tld) || RESERVED_NAMES.some((r) => host === r || host.endsWith('.' + r)) || host === org || host.endsWith('.' + org) || CITATION_HOSTS.has(host);
    };
    const bad = new Set<string>();
    // Hosts of URLs and e-mail addresses: no file-extension or account-name exception.
    for (const m of [...text.matchAll(URL_HOST), ...text.matchAll(MAIL_HOST)]) {
      const host = m[1].toLowerCase();
      if (!allowedHost(host)) bad.add(host);
    }
    // Bare tokens: any multi-label token whose last label is not reserved, unless it is a file name or an account.
    for (const m of text.match(TOKEN) ?? []) {
      const token = m.toLowerCase();
      if (allowedHost(token) || accounts.has(token) || FILE_EXTENSIONS.has(token.slice(token.lastIndexOf('.') + 1))) continue;
      bad.add(token);
    }
    return [...bad].sort();
  }

  it('the scanner flags real-looking domains and accepts reserved ones', () => {
    const org = 'acme-corp.example';
    expect(violations('see https://evil.com/x and bob@mail.contoso.net', org)).toEqual(['evil.com', 'mail.contoso.net']);
    for (const ok of ['https://a.example/x', 'host.corp.test', 'x@y.invalid', 'svc.localhost', 'www.example.com', 'mail.example.org', 'corp.' + org, 'u@' + org, 'report.pdf', 'v1.2.3']) expect(violations(ok, org), ok).toEqual([]);
  });

  it('the file-extension exception is for bare tokens only; account names and citation hosts are explicit', () => {
    const org = 'acme-corp.example';
    // A URL or e-mail host is never excused by its last label, even when that label is a file extension.
    expect(violations('fetch https://evil.sh/x and https://files.pdf/a and bob@mail.py', org)).toEqual(['evil.sh', 'files.pdf', 'mail.py']);
    // A bare token with any non-reserved last label is flagged, a real top-level domain or not.
    expect(violations('connect to payments.zzz or pay.vendor', org)).toEqual(['pay.vendor', 'payments.zzz']);
    expect(violations('run installer.exe, read notes.txt', org)).toEqual([]);
    // World account names are bare tokens that look like hosts.
    expect(violations('owner nina.quinn', org)).toEqual(['nina.quinn']);
    expect(violations('owner nina.quinn', org, new Set(['nina.quinn']))).toEqual([]);
    // Citation hosts are exact: a look-alike is a violation.
    expect(violations('https://www.first.org/epss/ https://www.cisa.gov/x https://www.comptia.org/en-us/', org)).toEqual([]);
    expect(violations('https://www.first.org.evil.com/epss/ https://cisa.gov/x', org)).toEqual(['cisa.gov', 'www.first.org.evil.com']);
  });

  it('every string of every vuln corpus table and built spec, references included, uses reserved names, the world org domain or a listed citation host', async () => {
    const found: string[] = [];
    let scanned = 0;
    let withOrg = 0;
    let citations = 0;
    for (const template of VULN_TEMPLATES)
      for (const run of vulnRuns()) {
        const w = world(run.world);
        const accounts = accountNames(w);
        const s = buildFor(template, w, run.seed);
        const label = `${template.id} ${run.world}/${run.seed}`;
        const cells = Object.values(s.corpus.tables).flatMap((tb) => tb.rows.flatMap((row) => row.filter((c): c is string => typeof c === 'string')));
        const texts = [...cells, ...strings(s.case)];
        scanned += texts.length;
        citations += s.case.references.length;
        if (texts.some((x) => x.toLowerCase().includes(w.org.domain.toLowerCase()))) withOrg++;
        for (const text of texts) for (const d of violations(text, w.org.domain, accounts)) found.push(`${label}: ${d}`);
      }
    expect(scanned).toBeGreaterThan(1000);
    expect(citations, 'the citation hosts are exercised').toBeGreaterThan(0);
    expect(withOrg, 'the org-domain exemption is exercised').toBeGreaterThan(0);
    expect([...new Set(found)].slice(0, 40)).toEqual([]);
  }, 60_000);
});
