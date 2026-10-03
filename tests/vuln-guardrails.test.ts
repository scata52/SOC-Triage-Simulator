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
import { specViolations, syntheticViolations } from './helpers/guardrails.ts';
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

  it('also flags space, underscore and Unicode-dash variants of a CVE id', () => {
    const v = (sep1: string, sep2: string) => 'CVE' + sep1 + '2021' + sep2 + '90001';
    for (const flagged of [v(' ', '-'), v('_', '_'), v('-', ' '), v('', '-'), v('\u2010', '\u2011'), v('\u2012', '\u2013'), v('\u2014', '\u2015'), v('\u2212', '\u2212'), 'x ' + v(' ', ' ') + ' y']) {
      expect(cveViolations({ label: 't', text: flagged }), flagged).toHaveLength(1);
    }
    for (const fine of ['CVE 20 1234', 'CVE 2021 123', 'CVSS 3.1 2021 90001', 'SIMVULN-2026-10421', 'the CVE list']) {
      expect(cveViolations({ label: 't', text: fine }), fine).toEqual([]);
    }
  });

  it('scans every source file under src/** (UI copy, schema and reference text included)', () => {
    const files = allFiles('src').map((p) => ({ label: p.split('\\').join('/'), text: readFileSync(p, 'utf8') }));
    expect(files.length).toBeGreaterThan(50);
    expect(files.flatMap(cveViolations)).toEqual([]);
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

// Human decision 2026-10-02 on domain names. A real registered domain (the shared world's Microsoft sample
// namespace, e.g. contoso.com, included) may appear only in a benign, legitimate role. Any domain in an attacker
// or malicious role must be a reserved name (.example, .test, .invalid, .localhost, example.com / .net / .org).
//
// Enforced as follows. A non-reserved domain is allowed only
//   (a) in the explicit allowlist BENIGN_ORG_COLUMNS of (table, column) pairs, where the world's org domain
//       legitimately appears in vuln data as asset or identity context (an owner, an account, a manager, a
//       requester), or
//   (b) in the `url` of a case reference, for a host in CITATION_HOSTS (documentation citations).
// Every other string is reserved-only: every other column of every table, and every built-spec text (briefing,
// attachments, hints, explanation, pitfalls, solution text, evidence label and why, rubric, reference titles).
// So a domain in an attacker or malicious role can only be a reserved name, and the UI never links data text.
// A bare token (not the host of a URL or of an e-mail address) is also allowed when it is a known file name or
// extension ("report.pdf") or a world account name ("nina.quinn"), because those look like hosts.
describe('reserved domains in generated vuln data (human decision 2026-10-02)', () => {
  const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost']);
  const RESERVED_NAMES = ['example.com', 'example.net', 'example.org'];
  const CITATION_HOSTS = new Set(['www.first.org', 'www.cisa.gov', 'www.comptia.org']);
  // The benign columns, taken from the generated corpus (every cell mentioning the org domain across all vuln
  // templates and worlds): the org domain is the company's own mail/identity namespace, never an attacker's.
  //   IdentityInfo.AccountUpn  the user principal name of a world account (svc-monitor@<org domain>)
  //   IdentityInfo.Manager     the manager of an account, as a UPN
  //   DeviceInfo.Owner         the asset owner, as a UPN
  //   Tickets.Requester        who raised a ticket, as a UPN
  const BENIGN_ORG_COLUMNS = new Set(['IdentityInfo.AccountUpn', 'IdentityInfo.Manager', 'DeviceInfo.Owner', 'Tickets.Requester']);
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

  // What a string may carry besides reserved names: the world org domain (benign column) and/or citation hosts.
  interface Allow {
    org?: string;
    citations?: boolean;
  }

  function violations(text: string, allow: Allow = {}, accounts: ReadonlySet<string> = new Set()): string[] {
    const org = allow.org?.toLowerCase();
    const allowedHost = (host: string): boolean => {
      const tld = host.slice(host.lastIndexOf('.') + 1);
      return (
        RESERVED_TLDS.has(tld) ||
        RESERVED_NAMES.some((r) => host === r || host.endsWith('.' + r)) ||
        (org !== undefined && (host === org || host.endsWith('.' + org))) ||
        (allow.citations === true && CITATION_HOSTS.has(host))
      );
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

  // The checker for a built scenario. Corpus cells: reserved names only, except the org domain in a benign column.
  // Spec text: reserved names only, except the citation hosts in a reference url.
  type Tables = Record<string, { columns: string[]; rows: unknown[][] }>;

  function corpusViolations(tables: Tables, orgDomain: string, accounts: ReadonlySet<string>): { found: string[]; cells: number; orgCells: number } {
    const found: string[] = [];
    let cells = 0;
    let orgCells = 0;
    for (const [table, tb] of Object.entries(tables))
      tb.columns.forEach((column, ci) => {
        const key = `${table}.${column}`;
        const benign = BENIGN_ORG_COLUMNS.has(key);
        for (const row of tb.rows) {
          const cell = row[ci];
          if (typeof cell !== 'string') continue;
          cells++;
          if (benign && cell.toLowerCase().includes(orgDomain.toLowerCase())) orgCells++;
          for (const d of violations(cell, benign ? { org: orgDomain } : {}, accounts)) found.push(`${key}: ${d}`);
        }
      });
    return { found, cells, orgCells };
  }

  function specViolations(c: { references: { label: string; url: string }[] }, accounts: ReadonlySet<string>): { found: string[]; strings: number } {
    const found: string[] = [];
    const { references, ...rest } = c as { references: { label: string; url: string }[] } & Record<string, unknown>;
    const texts = strings(rest);
    for (const text of texts) for (const d of violations(text, {}, accounts)) found.push(`spec: ${d}`);
    for (const r of references) {
      for (const d of violations(r.label, {}, accounts)) found.push(`reference label: ${d}`);
      for (const d of violations(r.url, { citations: true }, accounts)) found.push(`reference url: ${d}`);
    }
    return { found, strings: texts.length + references.length * 2 };
  }

  it('the scanner flags real-looking domains and accepts reserved ones', () => {
    const org = 'acme-corp.example';
    expect(violations('see https://evil.com/x and bob@mail.contoso.net')).toEqual(['evil.com', 'mail.contoso.net']);
    for (const ok of ['https://a.example/x', 'host.corp.test', 'x@y.invalid', 'svc.localhost', 'www.example.com', 'mail.example.org', 'report.pdf', 'v1.2.3']) expect(violations(ok), ok).toEqual([]);
    // The org domain is allowed only when the caller grants it (a benign column).
    for (const ok of ['corp.' + org, 'u@' + org]) expect(violations(ok, { org }), ok).toEqual([]);
    expect(violations('u@wideworldimporters.com')).toEqual(['wideworldimporters.com']);
    expect(violations('u@wideworldimporters.com', { org: 'wideworldimporters.com' })).toEqual([]);
    expect(violations('u@wideworldimporters.com', { org: 'other-corp.zz' })).toEqual(['wideworldimporters.com']);
  });

  it('the file-extension exception is for bare tokens only; account names and citation hosts are explicit', () => {
    // A URL or e-mail host is never excused by its last label, even when that label is a file extension.
    expect(violations('fetch https://evil.sh/x and https://files.pdf/a and bob@mail.py')).toEqual(['evil.sh', 'files.pdf', 'mail.py']);
    // A bare token with any non-reserved last label is flagged, a real top-level domain or not.
    expect(violations('connect to payments.zzz or pay.vendor')).toEqual(['pay.vendor', 'payments.zzz']);
    expect(violations('run installer.exe, read notes.txt')).toEqual([]);
    // World account names are bare tokens that look like hosts.
    expect(violations('owner nina.quinn')).toEqual(['nina.quinn']);
    expect(violations('owner nina.quinn', {}, new Set(['nina.quinn']))).toEqual([]);
    // Citation hosts are exact and only where granted: a look-alike is a violation.
    const cites = 'https://www.first.org/epss/ https://www.cisa.gov/x https://www.comptia.org/en-us/';
    expect(violations(cites, { citations: true })).toEqual([]);
    expect(violations(cites)).toEqual(['www.cisa.gov', 'www.comptia.org', 'www.first.org']);
    expect(violations('https://www.first.org.evil.com/epss/ https://cisa.gov/x', { citations: true })).toEqual(['cisa.gov', 'www.first.org.evil.com']);
  });

  it('the checker reports a non-reserved domain in a non-benign column and in spec text, and accepts the benign ones', () => {
    const org = 'wideworldimporters.com';
    const none = new Set<string>(['lena.haas']);
    const tables: Tables = {
      DeviceInfo: { columns: ['DeviceName', 'Owner', 'Notes'], rows: [['ws-01', 'lena.haas@' + org, 'ok'], ['ws-02', 'x@y.test', 'beacon to c2.' + org]] },
      DnsEvents: { columns: ['QueryName'], rows: [['update.' + org], ['lure.example']] },
      IdentityInfo: { columns: ['AccountUpn', 'Manager', 'Department'], rows: [['a@' + org, 'b@' + org, 'mail.' + org]] },
    };
    // The same org domain is fine in DeviceInfo.Owner and IdentityInfo.AccountUpn / Manager, and nowhere else.
    const c = corpusViolations(tables, org, none);
    expect(c.found).toEqual(['DeviceInfo.Notes: c2.' + org, 'DnsEvents.QueryName: update.' + org, 'IdentityInfo.Department: mail.' + org]);
    expect(c.orgCells).toBe(3);
    // A real registered domain in a benign column is still only allowed if it is the world's org domain.
    expect(corpusViolations({ DeviceInfo: { columns: ['Owner'], rows: [['a@evil.com']] } }, org, none).found).toEqual(['DeviceInfo.Owner: evil.com']);
    // Spec text: the org domain is reported too, as is a reference label or a look-alike citation host.
    const spec = {
      briefing: 'Beacons to https://c2.' + org + '/a and to https://c2.bad.test/b.',
      hints: ['See portal.contoso.com'],
      references: [
        { label: 'FIRST EPSS', url: 'https://www.first.org/epss/' },
        { label: 'portal.' + org, url: 'https://www.first.org.evil.com/' },
      ],
    };
    expect(specViolations(spec, none).found).toEqual([
      'spec: c2.' + org,
      'spec: portal.contoso.com',
      'reference label: portal.' + org,
      'reference url: www.first.org.evil.com',
    ]);
    const clean = { ...spec, briefing: 'ok', hints: [], references: [spec.references[0]] };
    expect(specViolations(clean, none).found).toEqual([]);
  });

  it('every vuln template, over the standard runs: corpus cells are reserved except the benign org columns, spec text is reserved except citation urls', () => {
    const found: string[] = [];
    let cells = 0;
    let specStrings = 0;
    let orgCells = 0;
    let citations = 0;
    for (const template of VULN_TEMPLATES)
      for (const run of vulnRuns()) {
        const w = world(run.world);
        const accounts = accountNames(w);
        const s = buildFor(template, w, run.seed);
        const label = `${template.id} ${run.world}/${run.seed}`;
        const c = corpusViolations(s.corpus.tables, w.org.domain, accounts);
        const sp = specViolations(s.case, accounts);
        cells += c.cells;
        orgCells += c.orgCells;
        specStrings += sp.strings;
        citations += s.case.references.length;
        for (const d of [...c.found, ...sp.found]) found.push(`${label}: ${d}`);
      }
    expect(cells + specStrings).toBeGreaterThan(1000);
    expect(citations, 'the citation hosts are exercised').toBeGreaterThan(0);
    expect(orgCells, 'the benign org-domain columns are exercised').toBeGreaterThan(0);
    expect([...new Set(found)].slice(0, 40)).toEqual([]);
  }, 60_000);
});

// The SOC and vuln corpus guard (tests/helpers/guardrails.ts) must actually catch what it claims to.
describe('the synthetic-data checker catches violations (self-test)', () => {
  const w = world('guardrail-self-test');
  const built = buildVulnScenario({ worldSeed: w.seed, templateId: fixtureTier3.id, seed: 'self', world: w, template: fixtureTier3 });

  // A copy of the corpus whose first free-text cell (not an id or hash column) holds `text`.
  function withCell(text: string) {
    const corpus = structuredClone(built.corpus);
    for (const table of Object.values(corpus.tables)) {
      const ci = table.columns.findIndex((c) => ['Evidence', 'Description', 'Title', 'Message', 'Details'].includes(c));
      if (ci >= 0 && table.rows.length > 0) {
        table.rows[0][ci] = text;
        return corpus;
      }
    }
    throw new Error('no free-text column in the fixture corpus');
  }

  it('is quiet on the untouched fixture, case text included', () => {
    expect(syntheticViolations(built.corpus, w, built.case)).toEqual([]);
  });

  it('flags a non-synthetic IPv4 in any cell and in the case text', () => {
    expect(syntheticViolations(withCell('beacon to 8.8.8.8 seen'), w).join('\n')).toContain('8.8.8.8');
    expect(syntheticViolations(built.corpus, w, { briefing: 'call 8.8.8.8 now' }).join('\n')).toContain('8.8.8.8');
    expect(syntheticViolations(built.corpus, w, { a: ['x', { b: 'host 203.0.113.9 and 10.1.2.3 and Chrome/131.0.0.0' }] })).toEqual([]);
  });

  it('flags a non-documentation IPv6 in the case text, not a MAC address or a time', () => {
    expect(specViolations({ t: 'peer 2606:4700::1111 replied' }).join('\n')).toContain('2606:4700::1111');
    expect(specViolations({ t: 'peer 2001:db8::5 replied' })).toEqual([]);
    expect(specViolations({ t: 'mac aa:bb:cc:dd:ee:ff at 10:30:45' })).toEqual([]);
  });

  it('flags a CVE id in the case text', () => {
    expect(specViolations({ t: 'see ' + 'CVE' + '-' + '2020' + '-' + '1234' })).toHaveLength(1);
    expect(specViolations({ t: 'see ' + 'CVE' + ' ' + '2020' + '_' + '1234' })).toHaveLength(1);
  });

  it('flags a real domain inside a URL or an e-mail address in any cell, and accepts reserved names', () => {
    expect(syntheticViolations(withCell('download from https://payload.realsite.io/x.bin'), w).join('\n')).toContain('realsite.io');
    expect(syntheticViolations(withCell('contact ops@mail.realsite.io today'), w).join('\n')).toContain('realsite.io');
    expect(syntheticViolations(withCell('see https://c2.attacker.example/x and ops@corp.invalid'), w)).toEqual([]);
  });

  it('applies a dot boundary to the organisation domain', () => {
    expect(syntheticViolations(withCell('https://x' + w.org.domain + '/a'), w).join('\n')).toContain('x' + w.org.domain);
    expect(syntheticViolations(withCell('https://portal.' + w.org.domain + '/a'), w)).toEqual([]);
    expect(syntheticViolations(withCell('https://' + w.org.domain + '/a'), w)).toEqual([]);
  });
});
