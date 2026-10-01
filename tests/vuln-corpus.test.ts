// WP1b: the vulnerability corpus tables, the scan writer and buildVulnScenario.
import { beforeAll, describe, expect, it } from 'vitest';
import { createRng } from '../src/core/rng.ts';
import { CorpusBuilder } from '../src/core/logs/corpus.ts';
import { DAY } from '../src/core/logs/time.ts';
import { SCHEMA, TABLE_NAMES, hasTimeColumn, tableInfo, type TableName } from '../src/core/logs/schema.ts';
import { SiemDatabase } from '../src/core/query/engine.ts';
import { KQL_REFERENCE } from '../src/core/query/kql/reference.ts';
import { buildPracticeCase } from '../src/core/cases/scenario.ts';
import { generateCatalogue, type CatalogueEntry } from '../src/core/vuln/catalogue.ts';
import { isSimVulnId } from '../src/core/vuln/ids.ts';
import { buildVulnScenario, VULN_WINDOW_DAYS, type VulnScenario } from '../src/core/vuln/scenario.ts';
import { compareVersions, ScanWriter, SIM_INTEL_SOURCE, upstreamVersion, versionBasis, versionBelow } from '../src/core/vuln/scan-writer.ts';
import { VULN_TEMPLATES, isVulnTemplateId, vulnTemplateById } from '../src/core/vuln/registry.ts';
import type { VulnCaseSpec, VulnTemplate } from '../src/core/vuln/model.ts';
import { sessionKey } from '../src/ui/lib/protocol.ts';
import { syntheticViolations } from './helpers/guardrails.ts';
import { world } from './helpers/scenario-check.ts';
import { sqljs } from './helpers/sql.ts';
import { checkVulnTemplate, vulnRuns } from './helpers/vuln-scenario-check.ts';
import { fixtureTier3, FIXTURE_TEMPLATE_ID } from './helpers/vuln-fixture.ts';

const VULN_TABLES = ['VulnFindings', 'ScanRuns', 'VulnIntel', 'SoftwareInventory', 'PatchHistory', 'ControlInventory'] as const;
const SOC_TABLES = ['SigninLogs', 'AuditLogs', 'SecurityEvent', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents', 'EmailEvents', 'WebProxy', 'DnsEvents', 'FirewallLogs', 'SecurityAlert', 'IdentityInfo', 'DeviceInfo', 'NamedLocations', 'Tickets', 'ThreatIntel', 'DomainIntel', 'IncidentHistory'];

const WORLD = 'vuln-corpus-world';

function build(seed: string, worldSeed = WORLD): VulnScenario {
  return buildVulnScenario({ worldSeed, templateId: FIXTURE_TEMPLATE_ID, seed, world: world(worldSeed), template: fixtureTier3 });
}

function col(s: VulnScenario, table: TableName, name: string): unknown[] {
  const t = s.corpus.tables[table];
  const i = t.columns.indexOf(name);
  return t.rows.map((r) => r[i]);
}

describe('vulnerability tables in the schema (DESIGN section 6.1)', () => {
  const columns: Record<(typeof VULN_TABLES)[number], string[]> = {
    VulnFindings: ['FindingId', 'DeviceName', 'VulnId', 'Title', 'Severity', 'CvssBase', 'Port', 'Service', 'DetectedVersion', 'Evidence', 'ScanRunId', 'FirstSeen', 'LastSeen', 'Status', 'PluginFamily', 'RecordId'],
    ScanRuns: ['ScanRunId', 'Tool', 'Method', 'Vantage', 'Started', 'Finished', 'TargetsPlanned', 'TargetsScanned', 'AuthFailures', 'RecordId'],
    VulnIntel: ['VulnId', 'CvssVector', 'CvssBase', 'KnownExploited', 'KnownExploitedAdded', 'ExploitProbability', 'ExploitPercentile', 'PublicExploit', 'VendorFix', 'FixedVersion', 'Published', 'Source', 'RecordId'],
    SoftwareInventory: ['DeviceName', 'Product', 'Vendor', 'Version', 'PackageSource', 'InstalledOn', 'RecordId'],
    PatchHistory: ['DeviceName', 'PatchId', 'Description', 'InstalledOn', 'RebootPending', 'Result', 'RecordId'],
    ControlInventory: ['ControlId', 'Kind', 'Target', 'Mode', 'CoversVulnId', 'Evidence', 'RecordId'],
  };

  it('adds the six context tables with the documented columns', () => {
    for (const t of VULN_TABLES) {
      const info = tableInfo(t);
      expect(info.kind, t).toBe('context');
      expect(info.columns.map((c) => c.name), t).toEqual(columns[t]);
      expect(hasTimeColumn(t), t).toBe(false);
      expect(info.doc.length, t).toBeGreaterThan(20);
      for (const c of info.columns) expect(c.doc.length, `${t}.${c.name}`).toBeGreaterThan(5);
    }
  });

  it('keeps every existing table first and in order, so existing RecordIds cannot shift', () => {
    expect(TABLE_NAMES.slice(0, SOC_TABLES.length)).toEqual(SOC_TABLES);
    expect(TABLE_NAMES.slice(SOC_TABLES.length)).toEqual([...VULN_TABLES]);
    expect(Object.keys(SCHEMA)).toEqual(TABLE_NAMES);
  });

  it('leaves the vuln tables empty in a SOC case', () => {
    const s = buildPracticeCase(world('vuln-soc'), 'endpoint-encoded-powershell', 'v1');
    for (const t of VULN_TABLES) expect(s.corpus.tables[t].rows, t).toEqual([]);
    expect(s.corpus.tables.DeviceInfo.rows.length).toBeGreaterThan(50);
  });
});

describe('buildVulnScenario', () => {
  it('is deterministic: same seed, identical rows and spec', () => {
    const a = build('det');
    const b = build('det');
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    const c = build('other');
    expect(JSON.stringify(c.corpus.tables.VulnFindings)).not.toBe(JSON.stringify(a.corpus.tables.VulnFindings));
    expect(build('det', 'vuln-corpus-world-2').case.id).toBe(a.case.id); // same case id, different world
  });

  it('gives twin templates built with the same seed the same date and the same catalogue', () => {
    const twin: VulnTemplate = { ...fixtureTier3, id: 'vm-fixture-twin' };
    const a = build('twins');
    const b = buildVulnScenario({ worldSeed: WORLD, templateId: twin.id, seed: 'twins', world: world(WORLD), template: twin });
    expect(b.now).toBe(a.now);
    // The fixture picks its deciders from the catalogue by rule, so the same
    // catalogue gives the same decider intel.
    const kevOf = (s: VulnScenario) => (col(s, 'VulnIntel', 'VulnId') as string[]).filter((_, i) => col(s, 'VulnIntel', 'KnownExploited')[i] === 1).sort();
    expect(kevOf(b)).toEqual(kevOf(a));
    expect(b.case.id).not.toBe(a.case.id);
    // A different seed moves the date.
    expect(new Set(['t1', 't2', 't3', 't4', 't5', 't6'].map((s) => build(s).now)).size).toBeGreaterThan(1);
  });

  it('gives each case a stable id and resolves findings to rows', () => {
    const s = build('ids');
    expect(s.case.id).toBe(`${FIXTURE_TEMPLATE_ID}~ids`);
    expect(s.case.kind).toBe('vuln');
    const recordIds = new Set(col(s, 'VulnFindings', 'RecordId') as string[]);
    for (const f of s.case.findings) expect(recordIds.has(f.recordId)).toBe(true);
  });

  it('is sized like tier 3: about 20 findings, 2 scan runs, hundreds of rows', () => {
    const s = build('size');
    expect(s.corpus.tables.VulnFindings.rows.length).toBeGreaterThanOrEqual(15);
    expect(s.corpus.tables.VulnFindings.rows.length).toBeLessThanOrEqual(25);
    expect(s.corpus.tables.ScanRuns.rows.length).toBe(2);
    expect(s.corpus.rowCount).toBeGreaterThan(150);
    expect(s.corpus.rowCount).toBeLessThan(2000);
    expect(Date.parse(s.corpus.windowEnd) - Date.parse(s.corpus.windowStart)).toBe(VULN_WINDOW_DAYS * DAY);
  });

  it('builds a tier-3 case in well under a second (Node)', () => {
    build('warm');
    const t0 = performance.now();
    for (let i = 0; i < 5; i++) build(`time-${i}`);
    const each = (performance.now() - t0) / 5;
    expect(each).toBeLessThan(1000);
    // Including generating the world from scratch, as the worker does on a cold start.
    const t1 = performance.now();
    buildVulnScenario({ worldSeed: 'vuln-cold-world', templateId: FIXTURE_TEMPLATE_ID, seed: 'cold', template: fixtureTier3 });
    expect(performance.now() - t1).toBeLessThan(1000);
  });

  it('keeps every address synthetic', () => {
    for (let i = 0; i < 6; i++) {
      const w = world(`vuln-syn-${i % 3}`);
      const s = buildVulnScenario({ worldSeed: w.seed, templateId: FIXTURE_TEMPLATE_ID, seed: `syn-${i}`, world: w, template: fixtureTier3 });
      expect(syntheticViolations(s.corpus, w), `seed ${i}`).toEqual([]);
    }
  });

  it('resolves templates from the registry, or from a template object, and refuses unknown ones', () => {
    expect(() => buildVulnScenario({ worldSeed: WORLD, templateId: 'vm-nope', seed: 'x', world: world(WORLD) })).toThrow(/Unknown vuln template/);
    expect(() => buildVulnScenario({ worldSeed: WORLD, templateId: 'vm-other', seed: 'x', world: world(WORLD), template: fixtureTier3 })).toThrow(/not vm-other/);
    expect(() => buildVulnScenario({ worldSeed: 'a-different-world', templateId: FIXTURE_TEMPLATE_ID, seed: 'x', world: world(WORLD), template: fixtureTier3 })).toThrow(/does not match/);
    for (const t of VULN_TEMPLATES) {
      expect(isVulnTemplateId(t.id)).toBe(true);
      expect(vulnTemplateById(t.id)).toBe(t);
    }
    expect(isVulnTemplateId(FIXTURE_TEMPLATE_ID)).toBe(true);
    expect(isVulnTemplateId('endpoint-encoded-powershell')).toBe(false);
  });

  it('rejects a template whose findings do not match their rows', () => {
    const broken = (patch: (spec: VulnCaseSpec) => void): VulnTemplate => ({
      ...fixtureTier3,
      id: 'vm-broken',
      build: (ctx) => {
        const spec = fixtureTier3.build(ctx);
        patch(spec);
        return spec;
      },
    });
    const run = (t: VulnTemplate) => buildVulnScenario({ worldSeed: WORLD, templateId: t.id, seed: 'b', world: world(WORLD), template: t });
    expect(() => run(broken((s) => void (s.findings[1].findingId = s.findings[0].findingId)))).toThrow(/duplicate findingId/);
    expect(() => run(broken((s) => void (s.findings[0].findingId = 'VF-00000')))).toThrow(/does not match its row/);
    expect(() => run(broken((s) => void s.idealOrder.push('VF-nope')))).toThrow(/unknown finding/);
  });

  it('rejects tiers the ordering grade cannot use (ADR-19)', () => {
    const broken = (patch: (spec: VulnCaseSpec) => void): VulnTemplate => ({
      ...fixtureTier3,
      id: 'vm-broken-tiers',
      build: (ctx) => {
        const spec = fixtureTier3.build(ctx);
        patch(spec);
        return spec;
      },
    });
    const run = (t: VulnTemplate) => buildVulnScenario({ worldSeed: WORLD, templateId: t.id, seed: 'b', world: world(WORLD), template: t });
    // The fixture's findings: 0 exploited (must-not-miss), 1 false positive, 2 low probability,
    // 3 false positive, 4 mitigated, 5 accepted. Tiers [[0], [4], [2]], idealOrder [0, 4, 2].
    const id = (s: VulnCaseSpec, i: number) => s.findings[i].findingId;
    expect(() => run(broken((s) => void s.tiers.push([])))).toThrow(/at most three tiers/);
    expect(() => run(broken((s) => void s.tiers[1].push(id(s, 0))))).toThrow(/tiers list finding .* more than once/); // in two tiers
    expect(() => run(broken((s) => void s.tiers[0].push(id(s, 0))))).toThrow(/tiers list finding .* more than once/); // twice in one tier
    expect(() => run(broken((s) => void s.tiers[2].push(id(s, 1))))).toThrow(/finding .* is false-positive and must not be in a tier/);
    expect(() => run(broken((s) => void s.tiers[2].push(id(s, 5))))).toThrow(/finding .* is accept and must not be in a tier/);
    expect(() =>
      run(
        broken((s) => {
          s.tiers[0] = [];
          s.idealOrder = s.idealOrder.filter((x) => x !== id(s, 0));
        }),
      ),
    ).toThrow(/must-not-miss finding .* must be in a tier/);
    expect(() => run(broken((s) => void (s.idealOrder = s.idealOrder.filter((x) => x !== id(s, 2)))))).toThrow(/tiered finding .* is missing from idealOrder/);
    expect(() => run(broken((s) => void s.idealOrder.reverse()))).toThrow(/idealOrder puts .* after a less urgent finding/);
    expect(() => run(broken((s) => void s.idealOrder.unshift(id(s, 1))))).toThrow(/idealOrder puts .* after a less urgent finding/); // an untiered finding listed first

    // Well-formed variants still build: untiered findings listed last, several findings in one tier.
    expect(() => run(broken((s) => void s.idealOrder.push(id(s, 1))))).not.toThrow();
    expect(() => run(broken((s) => void (s.tiers = [[id(s, 0)], [id(s, 4), id(s, 2)]])))).not.toThrow();
    expect(run(fixtureTier3).case.tiers).toHaveLength(3);
  });

  it('rejects a case the lesson gate cannot use (ADR-22)', () => {
    const broken = (patch: (spec: VulnCaseSpec) => void): VulnTemplate => ({
      ...fixtureTier3,
      id: 'vm-broken-gate',
      build: (ctx) => {
        const spec = fixtureTier3.build(ctx);
        patch(spec);
        return spec;
      },
    });
    const run = (t: VulnTemplate) => buildVulnScenario({ worldSeed: WORLD, templateId: t.id, seed: 'b', world: world(WORLD), template: t });
    // The fixture: finding 0 is the lesson and must-not-miss finding (emergency, slaLatest emergency).
    const built = run(fixtureTier3).case;
    expect(built.findings.map((f) => f.lesson)).toEqual([true, false, false, false, false, false]);
    // No lesson finding.
    expect(() => run(broken((s) => void (s.findings[0].lesson = false)))).toThrow(/no finding is marked as the lesson finding/);
    expect(() => run(broken((s) => void s.findings.forEach((f) => void (f.lesson = undefined))))).toThrow(/no finding is marked as the lesson finding/);
    // A real key finding without slaLatest: the must-not-miss lesson finding, a lesson finding, a must-not-miss finding.
    expect(() => run(broken((s) => void delete s.findings[0].truth.slaLatest))).toThrow(/key finding VF-\d+ needs truth\.slaLatest/);
    expect(() => run(broken((s) => void (s.findings[4].lesson = true)))).toThrow(/key finding .* needs truth\.slaLatest/); // a real lesson finding
    expect(() =>
      run(
        broken((s) => {
          s.findings[2].mustNotMiss = true; // tiered in the fixture
        }),
      ),
    ).toThrow(/key finding .* needs truth\.slaLatest/);
    // A key finding that is a false positive needs no SLA, and a limit on any real key finding is enough.
    expect(() => run(broken((s) => void (s.findings[1].lesson = true)))).not.toThrow();
    expect(() => run(broken((s) => void ((s.findings[4].lesson = true), (s.findings[4].truth.slaLatest = 'next-window'))))).not.toThrow();
    // No evidence point anywhere.
    expect(() => run(broken((s) => void s.findings.forEach((f) => void (f.evidence = []))))).toThrow(/no evidence point/);
    expect(() => run(broken((s) => void s.findings.slice(1).forEach((f) => void (f.evidence = []))))).not.toThrow(); // one point is enough
  });

  it('has consistent, sound corpus and case checks for the fixture', async () => {
    await checkVulnTemplate(fixtureTier3, vulnRuns(6, 3), 12);
  });

  it('does not put the scenario-only host at the end of the CMDB every time', () => {
    const positions = new Set<boolean>();
    for (let i = 0; i < 12; i++) {
      const names = col(build(`pos-${i}`), 'DeviceInfo', 'DeviceName') as string[];
      positions.add(names.indexOf('OLDFILE01') === names.length - 1);
      expect(names).toContain('OLDFILE01');
    }
    expect(positions.has(false)).toBe(true);
  });
});

describe('KQL over a vuln case', () => {
  let db: SiemDatabase;
  let s: VulnScenario;

  beforeAll(async () => {
    s = build('kql');
    db = new SiemDatabase(await sqljs(), s.corpus);
  });

  it('joins findings to intel and filters to known-exploited (bare table or subquery on the right)', () => {
    const bare = db.run('VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited', 'kql', { maxRows: 500 });
    const sub = db.run('VulnFindings\n| join kind=inner (VulnIntel) on VulnId\n| where KnownExploited', 'kql', { maxRows: 500 });
    expect(bare.rows).toEqual(sub.rows);
    expect(bare.columns).toEqual(sub.columns);
    const r = bare;
    expect(r.rows.length).toBeGreaterThanOrEqual(1);
    const names = r.columns.map((c) => c.name);
    expect(names).toContain('DeviceName');
    expect(names).toContain('VulnId1');
    // Every returned finding is on a Sim-KEV entry.
    const kevIds = new Set(
      s.corpus.tables.VulnIntel.rows.filter((row) => row[s.corpus.tables.VulnIntel.columns.indexOf('KnownExploited')] === 1).map((row) => row[0]),
    );
    const vi = names.indexOf('VulnId');
    for (const row of r.rows) expect(kevIds.has(row[vi] as string)).toBe(true);
  });

  it('runs every reference example that touches the vuln tables and gets rows', () => {
    const touching = KQL_REFERENCE.filter((e) => VULN_TABLES.some((t) => e.example.includes(t)));
    expect(touching.length).toBeGreaterThanOrEqual(2);
    expect(touching.map((e) => e.name)).toContain('join (findings + intel)');
    for (const e of touching) {
      const r = db.run(e.example, 'kql', { maxRows: 50 });
      expect(r.rows.length, `${e.name}: example returns rows on a vuln case`).toBeGreaterThanOrEqual(1);
    }
  });

  it('looks up vuln rows by RecordId', () => {
    const f = s.case.findings[0];
    const rows = db.lookup([f.recordId]);
    expect(rows).toHaveLength(1);
    expect(rows[0].table).toBe('VulnFindings');
    expect(rows[0].row[rows[0].columns.indexOf('FindingId')]).toBe(f.findingId);
  });

  it('answers SQL as well', () => {
    const r = db.run('SELECT f.FindingId, i.KnownExploited FROM VulnFindings f JOIN VulnIntel i ON i.VulnId = f.VulnId WHERE i.KnownExploited = 1', 'sql');
    expect(r.rows.length).toBeGreaterThanOrEqual(1);
  });
});

describe('protocol', () => {
  it('keys a vuln session apart from practice and shift sessions', () => {
    const vuln = sessionKey({ kind: 'vuln', worldSeed: 'w', templateId: 'vm-x', seed: 's' });
    const practice = sessionKey({ kind: 'practice', worldSeed: 'w', templateId: 'vm-x', seed: 's' });
    expect(vuln).toBe('vuln:w:vm-x:s');
    expect(vuln).not.toBe(practice);
    expect(sessionKey({ kind: 'practice', worldSeed: 'w', templateId: 't', seed: 's' })).toBe('practice:w:t:s');
    expect(sessionKey({ kind: 'shift', worldSeed: 'w', number: 3, budget: 30, campaign: null, recent: [] })).toBe('shift:w:3');
  });
});

// ---------------------------------------------------------------------------
// Scan writer method semantics (DESIGN section 6.2)

function harness(seed = 'sw') {
  const w = world('vuln-scan-writer');
  const now = Date.parse('2026-09-23T13:20:00Z');
  const b = new CorpusBuilder({ world: w, rng: createRng(seed), windowStart: now - 14 * DAY, windowEnd: now, now });
  const catalogue = generateCatalogue(seed, now);
  const scan = new ScanWriter(b, createRng(`${seed}/scan`), catalogue);
  return { w, now, b, catalogue, scan };
}

function entryWhere(entries: readonly CatalogueEntry[], pred: (e: CatalogueEntry) => boolean): CatalogueEntry {
  const e = entries.find(pred);
  if (!e) throw new Error('no entry');
  return e;
}

describe('scan writer: method semantics', () => {
  it('unauthenticated scans see the banner version, never the package version', () => {
    const { scan, catalogue, now } = harness();
    const run = scan.run({ method: 'Unauthenticated', started: now - DAY, targetsPlanned: 3 });
    const entry = entryWhere(catalogue.entries, (e) => e.vendorFix);
    const f = scan.finding(run, { host: 'WEB01', entry, port: 443, installedVersion: '4.1.2-3+esm2', packageSource: 'distro' });
    const row = f.row.row;
    expect(f.basis).toBe('banner');
    expect(row.DetectedVersion).toBe('4.1.2');
    expect(JSON.stringify(row)).not.toContain('esm2');
    expect(String(row.Evidence)).toMatch(/banner/i);
    expect(String(row.Evidence)).not.toMatch(/package database/);
    expect(row.Port).toBe(443);
    expect(row.Service).toBe('https');
    // The inventory, which no scan produced, still tells the truth.
    const inv = scan.software({ host: 'WEB01', product: entry.product, vendor: entry.vendor, version: '4.1.2-3+esm2', source: 'distro' });
    expect(inv.row.Version).toBe('4.1.2-3+esm2');
  });

  it('an explicit banner version overrides the derived one', () => {
    const { scan, catalogue, now } = harness();
    const run = scan.run({ method: 'Unauthenticated', started: now - DAY, targetsPlanned: 3 });
    const f = scan.finding(run, { host: 'WEB01', entry: catalogue.entries[0], port: 8443, installedVersion: '9.9.9', bannerVersion: '2.0.1' });
    expect(f.row.row.DetectedVersion).toBe('2.0.1');
  });

  it('credentialed and agent scans see the installed package version', () => {
    const { scan, catalogue, now } = harness();
    const entry = entryWhere(catalogue.entries, (e) => e.vendorFix);
    for (const method of ['Credentialed', 'Agent'] as const) {
      const run = scan.run({ method, started: now - DAY, targetsPlanned: 3 });
      const f = scan.finding(run, { host: 'APP01', entry, installedVersion: '4.1.2-3+esm2', packageSource: 'distro' });
      expect(f.basis).toBe('package');
      expect(f.row.row.DetectedVersion).toBe('4.1.2-3+esm2');
      expect(String(f.row.row.Evidence)).toMatch(method === 'Agent' ? /Agent local check/ : /Credentialed local check/);
      expect(String(f.row.row.Evidence)).toContain('package source: distro');
      expect(f.row.row.Port).toBeNull();
      expect(f.row.row.PluginFamily).toBe('Local Security Checks');
    }
  });

  it('a failed login falls back to the banner and is counted in the run', () => {
    const { scan, catalogue, now } = harness();
    const run = scan.run({ method: 'Credentialed', started: now - DAY, targetsPlanned: 5, targetsScanned: 4 });
    expect(run.row.row.AuthFailures).toBe(0);
    const [a, b] = catalogue.entries.filter((e) => e.vendorFix);
    const f = scan.finding(run, { host: 'FS01', entry: a, port: 445, installedVersion: '2.3.4-1+dfsg', authFailed: true });
    expect(f.basis).toBe('banner');
    expect(f.row.row.DetectedVersion).toBe('2.3.4');
    expect(String(f.row.row.Evidence)).toMatch(/login failed/i);
    expect(run.row.row.AuthFailures).toBe(1);
    scan.finding(run, { host: 'FS01', entry: b, port: 445, authFailed: true }); // same device: still one failure
    expect(run.row.row.AuthFailures).toBe(1);
    scan.finding(run, { host: 'SQL01', entry: catalogue.entries[3], port: 443, authFailed: true });
    expect(run.row.row.AuthFailures).toBe(2);
  });

  it('keeps coverage honest: a device logs in or fails for the whole run, and a run only reaches as many devices as it says', () => {
    const { scan, catalogue, now } = harness('cov');
    const [a, b, c] = catalogue.entries.filter((e) => e.vendorFix);
    const run = scan.run({ method: 'Credentialed', started: now - DAY, targetsPlanned: 4, targetsScanned: 2 });
    scan.finding(run, { host: 'APP01', entry: a });
    expect(() => scan.finding(run, { host: 'APP01', entry: b, port: 443, authFailed: true })).toThrow(/worked for other findings/);
    scan.finding(run, { host: 'FS01', entry: b, port: 445, authFailed: true });
    expect(() => scan.finding(run, { host: 'FS01', entry: c })).toThrow(/failed for other findings/);
    expect(() => scan.finding(run, { host: 'SQL01', entry: c })).toThrow(/more devices than the 2 the run reached/);
    // Background findings on a device whose login failed are banner-level too.
    const run2 = scan.run({ method: 'Credentialed', started: now - 2 * DAY, targetsPlanned: 3 });
    scan.finding(run2, { host: 'PRINT01', entry: a, port: 443, authFailed: true });
    const bg = scan.background(run2, { hosts: ['PRINT01'], count: 3 });
    for (const f of bg) {
      expect(f.basis).toBe('banner');
      expect(f.row.row.Port).not.toBeNull();
    }
    expect(run2.row.row.AuthFailures).toBe(1);
  });

  it('versionBasis is the whole rule', () => {
    expect(versionBasis('Unauthenticated')).toBe('banner');
    expect(versionBasis('Unauthenticated', true)).toBe('banner');
    expect(versionBasis('Credentialed')).toBe('package');
    expect(versionBasis('Credentialed', true)).toBe('banner');
    expect(versionBasis('Agent')).toBe('package');
  });

  it('refuses combinations no real scanner could produce', () => {
    const { scan, catalogue, now } = harness();
    const entry = catalogue.entries[0];
    const unauth = scan.run({ method: 'Unauthenticated', started: now - DAY, targetsPlanned: 3 });
    const cred = scan.run({ method: 'Credentialed', started: now - DAY, targetsPlanned: 3 });
    const ext = scan.run({ method: 'Unauthenticated', vantage: 'External', started: now - DAY, targetsPlanned: 3 });
    expect(() => scan.finding(unauth, { host: 'WEB01', entry })).toThrow(/needs the port/);
    expect(() => scan.finding(unauth, { host: 'WEB01', entry, port: 70000 })).toThrow(/Bad port/);
    expect(() => scan.finding(unauth, { host: 'WEB01', entry, port: 443, authFailed: true })).toThrow(/credentialed run/);
    expect(() => scan.finding(cred, { host: 'NOPE99', entry })).toThrow(/No DeviceInfo row/);
    expect(() => scan.finding(ext, { host: 'APP01', entry, port: 443 })).toThrow(/not exposed/); // internal-only host
    expect(scan.finding(ext, { host: 'WEB01', entry, port: 443 }).findingId).toMatch(/^VF-\d{5}$/); // exposed host is visible
    expect(() => scan.run({ method: 'Credentialed', vantage: 'External', started: now, targetsPlanned: 1 })).toThrow(/external scan can only be unauthenticated/);
    expect(() => scan.run({ method: 'Agent', vantage: 'External', started: now, targetsPlanned: 1 })).toThrow();
    expect(() => scan.run({ method: 'Unauthenticated', started: now, targetsPlanned: 3, authFailures: 1 })).toThrow(/login failures/);
    expect(() => scan.run({ method: 'Credentialed', started: now, targetsPlanned: 3, targetsScanned: 4 })).toThrow(/targetsScanned/);
    expect(() => scan.run({ method: 'Credentialed', started: now, targetsPlanned: 3, targetsScanned: 2, authFailures: 3 })).toThrow(/authFailures/);
    expect(() => scan.run({ id: unauth.id, method: 'Agent', started: now, targetsPlanned: 1 })).toThrow(/already exists/);
  });

  it('writes a VulnIntel row per vulnerability from the simulated feeds, once', () => {
    const { scan, catalogue, now, b } = harness();
    const run = scan.run({ method: 'Credentialed', started: now - DAY, targetsPlanned: 2 });
    const kev = entryWhere(catalogue.entries, (e) => e.knownExploited);
    scan.finding(run, { host: 'APP01', entry: kev });
    scan.finding(run, { host: 'SQL01', entry: kev });
    expect(b.count('VulnIntel')).toBe(1);
    const row = b.rowsOf('VulnIntel')[0];
    expect(row).toMatchObject({ VulnId: kev.id, CvssVector: kev.vector, CvssBase: kev.base, KnownExploited: true, ExploitProbability: kev.epss, ExploitPercentile: kev.epssPercentile, Source: SIM_INTEL_SOURCE });
    expect(isSimVulnId(String(row.VulnId))).toBe(true);
    // A modified copy of the entry patches the row (a template overriding a decider).
    scan.intel({ ...kev, epss: 0.004, epssPercentile: 0.31 });
    expect(b.count('VulnIntel')).toBe(1);
    expect(b.rowsOf('VulnIntel')[0]).toMatchObject({ ExploitProbability: 0.004, ExploitPercentile: 0.31 });
  });

  it('keeps the installed version consistent per device and product', () => {
    const { scan, catalogue, now, b } = harness();
    const run = scan.run({ method: 'Credentialed', started: now - DAY, targetsPlanned: 2 });
    const [first, second] = [catalogue.entries[0], ...catalogue.entries.filter((e) => e.product === catalogue.entries[0].product && e.id !== catalogue.entries[0].id)];
    const a = scan.finding(run, { host: 'APP01', entry: first, installedVersion: '1.2.3' });
    if (second) {
      const c = scan.finding(run, { host: 'APP01', entry: second });
      expect(c.row.row.DetectedVersion).toBe(a.row.row.DetectedVersion);
    }
    expect(b.rowsOf('SoftwareInventory').filter((r) => r.DeviceName === 'APP01' && r.Product === first.product)).toHaveLength(1);
    // recordInventory: false leaves the inventory alone.
    const before = b.count('SoftwareInventory');
    scan.finding(run, { host: 'SQL01', entry: catalogue.entries[10], recordInventory: false });
    expect(b.count('SoftwareInventory')).toBe(before);
  });

  it('adds a scenario-only device with a free private address', () => {
    const { scan, b, w } = harness();
    const name = scan.scopeHost({ name: 'OLDBOX01', role: 'Legacy box', os: 'Windows Server 2008 R2', owner: 'IT Infrastructure', criticality: 'Low' });
    const ref = b.deviceRef(name);
    const ip = String(ref.row.IPAddress);
    expect(ip).toMatch(/^10\.\d+\.10\.\d+$/);
    expect(w.hosts.some((h) => h.ip === ip)).toBe(false);
    expect(ref.row.ExposedToInternet).toBe(false);
    const dmz = scan.scopeHost({ name: 'OLDBOX02', role: 'Old portal', os: 'Ubuntu 16.04', owner: 'Marketing', criticality: 'Medium', exposed: true });
    expect(String(b.deviceRef(dmz).row.IPAddress)).toMatch(/^10\.\d+\.100\.\d+$/);
    expect(() => scan.scopeHost({ name: 'oldbox01', role: 'x', os: 'x', owner: 'x', criticality: 'Low' })).toThrow(/already exists/);
    expect(() => scan.scopeHost({ name: 'OLDBOX03', role: 'x', os: 'x', owner: 'x', criticality: 'Low', ip })).toThrow(/already in use/);
  });

  it('background findings are never Sim-KEV, never repeat a vulnerability, and add hygiene checks', () => {
    const { scan, catalogue, now, b } = harness('bg');
    const run = scan.run({ method: 'Unauthenticated', started: now - DAY, targetsPlanned: 6 });
    const decider = entryWhere(catalogue.entries, (e) => e.knownExploited);
    scan.finding(run, { host: 'WEB01', entry: decider, port: 443 });
    const out = scan.background(run, { hosts: ['WEB01', 'APP01', 'SQL01', 'FS01', 'BUILD01', 'PRINT01'], count: 12, hygiene: 3 });
    expect(out).toHaveLength(15);
    const rows = b.rowsOf('VulnFindings');
    expect(rows).toHaveLength(16);
    const kev = new Set(catalogue.entries.filter((e) => e.knownExploited).map((e) => e.id));
    const backgroundIds = out.map((f) => String(f.row.row.VulnId)).filter((id) => id !== '');
    expect(backgroundIds).toHaveLength(12);
    expect(new Set(backgroundIds).size).toBe(12);
    for (const id of backgroundIds) {
      expect(kev.has(id)).toBe(false);
      expect(id).not.toBe(decider.id);
    }
    const hygiene = out.filter((f) => f.row.row.VulnId === '');
    expect(hygiene).toHaveLength(3);
    for (const h of hygiene) expect(h.row.row.DetectedVersion).toBe('');
    expect(b.count('VulnIntel')).toBe(13); // hygiene checks have no intel
    expect(() => scan.background(run, { hosts: [], count: 1 })).toThrow(/at least one host/);
    expect(() => scan.background(run, { hosts: ['WEB01'], count: 500 })).toThrow(/only \d+ catalogue entries are free/);
  });

  it('background respects an external run: only exposed hosts', () => {
    const { scan, now } = harness('bg-ext');
    const ext = scan.run({ method: 'Unauthenticated', vantage: 'External', started: now - DAY, targetsPlanned: 2 });
    expect(scan.background(ext, { hosts: ['WEB01', 'VPN01'], count: 4 })).toHaveLength(4);
    expect(() => scan.background(ext, { hosts: ['APP01'], count: 1 })).toThrow(/not exposed/);
  });

  it('is deterministic for a seed', () => {
    const one = () => {
      const { scan, catalogue, now, b } = harness('det-sw');
      const run = scan.run({ method: 'Unauthenticated', started: now - DAY, targetsPlanned: 4 });
      scan.finding(run, { host: 'WEB01', entry: catalogue.entries[2], port: 443 });
      scan.background(run, { hosts: ['WEB01', 'APP01'], count: 6, hygiene: 2 });
      return JSON.stringify([b.rowsOf('VulnFindings'), b.rowsOf('ScanRuns'), b.rowsOf('VulnIntel'), b.rowsOf('SoftwareInventory')]);
    };
    expect(one()).toBe(one());
  });
});

describe('version helpers', () => {
  it('upstreamVersion strips a distribution suffix', () => {
    expect(upstreamVersion('4.1.2-3+esm2')).toBe('4.1.2');
    expect(upstreamVersion('4.1.2+dfsg')).toBe('4.1.2');
    expect(upstreamVersion('4.1.2~rc1')).toBe('4.1.2');
    expect(upstreamVersion('4.1.2')).toBe('4.1.2');
  });

  it('compareVersions compares numerically, ignoring the suffix', () => {
    expect(compareVersions('4.1.2', '4.1.10')).toBe(-1);
    expect(compareVersions('4.2.0', '4.1.10')).toBe(1);
    expect(compareVersions('4.1.2-3+esm2', '4.1.2')).toBe(0);
    expect(compareVersions('4.1', '4.1.0')).toBe(0);
  });

  it('versionBelow is strictly below the fixed version and stays three-part', () => {
    const rng = createRng('vb');
    for (const fixed of ['4.1.7', '4.3.0', '2.0.0', '1.0.0', '9.12.9', '1.0.3']) {
      for (let i = 0; i < 40; i++) {
        const v = versionBelow(rng, fixed);
        expect(v, `${v} < ${fixed}`).toMatch(/^\d+\.\d+\.\d+$/);
        expect(compareVersions(v, fixed), `${v} < ${fixed}`).toBe(-1);
      }
    }
    expect(() => versionBelow(rng, '4.1')).toThrow();
  });
});
