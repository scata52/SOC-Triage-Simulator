// Shared checks for vulnerability-management scenarios, the counterpart of
// scenario-check.ts. A vuln case must build deterministically, stay synthetic,
// be referentially sound (findings point at real devices, scan runs and
// intel), be internally consistent, and be solvable through the query
// console: the reference investigation, run against a real sql.js database,
// must surface a row for every evidence point. The grader must agree with the
// template: the reference answer scores 100 and an untouched worklist 0.

import { expect } from 'vitest';
import type { World } from '../../src/core/world/world.ts';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { SiemDatabase } from '../../src/core/query/engine.ts';
import { cysaDomain } from '../../src/core/taxonomy/cysa.ts';
import { buildVulnScenario, type ResolvedVulnCase, type VulnScenario } from '../../src/core/vuln/scenario.ts';
import type { VulnTemplate } from '../../src/core/vuln/model.ts';
import { emptyVulnSubmission, gradeVulnCase, perfectVulnSubmission } from '../../src/core/vuln/grade.ts';
import { isSimVulnId } from '../../src/core/vuln/ids.ts';
import { syntheticViolations } from './guardrails.ts';
import { sqljs } from './sql.ts';
import { world } from './scenario-check.ts';

function column(corpus: Corpus, table: keyof Corpus['tables'], name: string): string[] {
  const t = corpus.tables[table];
  const i = t.columns.indexOf(name);
  return t.rows.map((r) => String(r[i]));
}

// Everything findings, runs, intel, devices and inventory promise each other.
export function checkVulnCorpus(corpus: Corpus, label: string): void {
  const devices = new Set(column(corpus, 'DeviceInfo', 'DeviceName'));
  const runs = new Set(column(corpus, 'ScanRuns', 'ScanRunId'));
  const intel = new Set(column(corpus, 'VulnIntel', 'VulnId'));
  expect(intel.size, `${label}: VulnIntel ids unique`).toBe(corpus.tables.VulnIntel.rows.length);
  for (const id of intel) expect(isSimVulnId(id), `${label}: intel id ${id}`).toBe(true);

  const findingIds = column(corpus, 'VulnFindings', 'FindingId');
  expect(new Set(findingIds).size, `${label}: FindingIds unique`).toBe(findingIds.length);
  expect(new Set(column(corpus, 'ScanRuns', 'ScanRunId')).size, `${label}: ScanRunIds unique`).toBe(corpus.tables.ScanRuns.rows.length);

  const f = corpus.tables.VulnFindings;
  const at = (n: string) => f.columns.indexOf(n);
  for (const row of f.rows) {
    const id = String(row[at('FindingId')]);
    expect(devices.has(String(row[at('DeviceName')])), `${label}: ${id} device`).toBe(true);
    expect(runs.has(String(row[at('ScanRunId')])), `${label}: ${id} scan run`).toBe(true);
    const vuln = String(row[at('VulnId')]);
    if (vuln !== '') expect(intel.has(vuln), `${label}: ${id} has intel for ${vuln}`).toBe(true);
    expect(String(row[at('FirstSeen')]) <= String(row[at('LastSeen')]), `${label}: ${id} first/last seen`).toBe(true);
  }

  // Coverage sanity: scanned <= planned, failures <= scanned, finished after started.
  const r = corpus.tables.ScanRuns;
  const ra = (n: string) => r.columns.indexOf(n);
  for (const row of r.rows) {
    const id = String(row[ra('ScanRunId')]);
    expect(Number(row[ra('TargetsScanned')]) <= Number(row[ra('TargetsPlanned')]), `${id} scanned <= planned`).toBe(true);
    expect(Number(row[ra('AuthFailures')]) <= Number(row[ra('TargetsScanned')]), `${id} failures <= scanned`).toBe(true);
    expect(String(row[ra('Finished')]) > String(row[ra('Started')]), `${id} finished after started`).toBe(true);
  }
  // A host's address is its own: unique among the non-empty DeviceInfo values, and never one of the organisation's egress addresses (NamedLocations).
  const deviceIps = column(corpus, 'DeviceInfo', 'IPAddress').filter((ip) => ip !== '');
  expect(new Set(deviceIps).size, `${label}: DeviceInfo addresses unique`).toBe(deviceIps.length);
  const egress = new Set(column(corpus, 'NamedLocations', 'IPAddress'));
  for (const ip of deviceIps) expect(egress.has(ip), `${label}: DeviceInfo address ${ip} is a NamedLocations egress address`).toBe(false);
  for (const d of column(corpus, 'SoftwareInventory', 'DeviceName')) expect(devices.has(d), `${label}: inventory device ${d}`).toBe(true);
  for (const d of column(corpus, 'PatchHistory', 'DeviceName')) expect(devices.has(d), `${label}: patch device ${d}`).toBe(true);
  for (const id of column(corpus, 'ControlInventory', 'CoversVulnId')) if (id !== '') expect(isSimVulnId(id), `${label}: control covers ${id}`).toBe(true);
}

export function checkVulnStructure(c: ResolvedVulnCase, corpus: Corpus): void {
  const label = c.id;
  expect(c.briefing.trim(), `${label}: briefing`).not.toBe('');
  expect(c.findings.length, `${label}: findings`).toBeGreaterThanOrEqual(1);
  expect(c.explanation.length).toBeGreaterThan(0);
  expect(c.pitfalls.length).toBeGreaterThan(0);
  expect(c.hints.length).toBeGreaterThanOrEqual(2);
  expect(c.solution.length).toBeGreaterThanOrEqual(1);
  expect(new Set(c.rubric.map((r) => r.id)).size).toBe(c.rubric.length);
  for (const r of c.rubric) expect(r.keywords.length).toBeGreaterThan(0);
  for (const d of c.cysaDomains) expect(cysaDomain(d), `${label}: domain ${d}`).toBeDefined();

  const idsOf = (name: keyof Corpus['tables']) => new Set(column(corpus, name, 'RecordId'));
  const findingRecordIds = idsOf('VulnFindings');
  const allRecordIds = new Set((Object.keys(corpus.tables) as (keyof Corpus['tables'])[]).flatMap((t) => [...idsOf(t)]));
  const findingRows = new Map(corpus.tables.VulnFindings.rows.map((r) => [String(r[corpus.tables.VulnFindings.columns.indexOf('RecordId')]), r]));
  const fidCol = corpus.tables.VulnFindings.columns.indexOf('FindingId');
  expect(new Set(c.findings.map((f) => f.findingId)).size, `${label}: finding ids unique`).toBe(c.findings.length);
  for (const f of c.findings) {
    expect(findingRecordIds.has(f.recordId), `${label}: ${f.findingId} row exists`).toBe(true);
    expect(String(findingRows.get(f.recordId)![fidCol]), `${label}: ${f.findingId} matches its row`).toBe(f.findingId);
    expect(f.weight, `${label}: ${f.findingId} weight`).toBeGreaterThan(0);
    // Evidence is per case (DESIGN 5.5, 5.6: F2 has no point), but the costly
    // mistake must be provable: every must-not-miss finding has a point.
    if (f.mustNotMiss) expect(f.evidence.length, `${label}: must-not-miss ${f.findingId} has an evidence point`).toBeGreaterThanOrEqual(1);
    if (f.truth.decision === 'false-positive') expect(f.truth.schedule, `${label}: false positive ${f.findingId} is not scheduled`).toBe('none');
    // The lesson gate (DESIGN 5.8) holds every real key finding to an SLA.
    if ((f.lesson || f.mustNotMiss) && f.truth.decision !== 'false-positive') expect(f.truth.slaLatest, `${label}: key finding ${f.findingId} has slaLatest`).toBeDefined();
    for (const e of f.evidence) {
      expect(e.recordIds.length, `${label}: evidence ${e.id} has rows`).toBeGreaterThan(0);
      for (const id of e.recordIds) expect(allRecordIds.has(id), `${label}: evidence ${e.id} row ${id} exists`).toBe(true);
    }
  }
  expect(c.findings.some((f) => f.lesson), `${label}: a lesson finding`).toBe(true);
  const evidenceIds = c.findings.flatMap((f) => f.evidence.map((e) => e.id));
  expect(evidenceIds.length, `${label}: evidence points`).toBeGreaterThanOrEqual(1);
  expect(new Set(evidenceIds).size, `${label}: evidence ids unique`).toBe(evidenceIds.length);

  const known = new Set(c.findings.map((f) => f.findingId));
  for (const id of [...c.idealOrder, ...(c.tiers ?? []).flat()]) expect(known.has(id), `${label}: order names ${id}`).toBe(true);
  const k = c.constraints;
  expect(k.windows.length, `${label}: change windows`).toBeGreaterThanOrEqual(1);
  for (const w of [...k.windows, ...(k.freezes ?? [])]) expect(w.end, `${label}: window ${w.id}`).toBeGreaterThan(w.start);
  expect(k.capacityPerWindow).toBeGreaterThanOrEqual(1);
  for (const days of Object.values(k.slaDays)) expect(days).toBeGreaterThan(0);
}

// The grader must agree with the template: the reference answer scores 100
// and an untouched worklist scores 0 (the counterpart of checkGrading).
export function checkVulnGrading(c: ResolvedVulnCase): void {
  const perfect = gradeVulnCase(c, perfectVulnSubmission(c));
  expect(perfect.score, `${c.id}: perfect submission ${JSON.stringify(perfect.components.filter((x) => !x.ok))}`).toBe(100);
  expect(gradeVulnCase(c, emptyVulnSubmission()).score, `${c.id}: empty submission`).toBe(0);
}

// The reference investigation, run for real: every step returns rows (or proves
// an absence) and together the steps surface a row of every evidence point.
// With `everyRow` they must return every row of every point (PLAN WP1d
// acceptance 1, used for the shipped templates).
export async function checkVulnSolvable(s: VulnScenario, shared?: SiemDatabase, everyRow = false): Promise<void> {
  const c = s.case;
  const db = shared ?? new SiemDatabase(await sqljs(), s.corpus);
  try {
    const found = new Set<string>();
    for (const step of c.solution) {
      let r;
      try {
        r = db.run(step.kql, 'kql', { maxRows: 5000 });
      } catch (e) {
        throw new Error(`${c.templateId}: solution "${step.title}" failed: ${(e as Error).message}\n${step.kql}`);
      }
      if (step.expectEmpty) {
        expect(r.rows.length, `${c.templateId}: solution "${step.title}" should prove an absence`).toBe(0);
        continue;
      }
      expect(r.rows.length, `${c.templateId}: solution "${step.title}" returned no rows`).toBeGreaterThan(0);
      if (r.recordIdColumn >= 0) for (const row of r.rows) found.add(String(row[r.recordIdColumn]));
    }
    for (const f of c.findings) {
      for (const e of f.evidence) {
        if (everyRow) {
          for (const id of e.recordIds) expect(found.has(id), `${c.templateId}: evidence "${e.id}" row ${id} not returned by the reference investigation`).toBe(true);
        } else {
          expect(e.recordIds.some((id) => found.has(id)), `${c.templateId}: evidence "${e.id}" not surfaced by the reference investigation`).toBe(true);
        }
      }
    }
  } finally {
    if (!shared) db.close();
  }
}

export interface VulnRun {
  world: string;
  seed: string;
  db: boolean;
}

export function vulnRuns(n = 6, dbRuns = 3): VulnRun[] {
  return Array.from({ length: n }, (_, i) => ({ world: `vuln-world-${i % 3}`, seed: `v${i}`, db: i < dbRuns }));
}

export function buildFor(template: VulnTemplate, w: World, seed: string): VulnScenario {
  return buildVulnScenario({ worldSeed: w.seed, templateId: template.id, seed, world: w, template });
}

// Build, determinism, structure, corpus integrity, grading, synthetic
// guardrails and solvability for one template over several runs, plus a wider
// crash sweep.
export async function checkVulnTemplate(template: VulnTemplate, runs: VulnRun[], sweep = 20, opts: { everyEvidenceRow?: boolean } = {}): Promise<void> {
  for (const run of runs) {
    const w = world(run.world);
    const s = buildFor(template, w, run.seed);
    const label = `${template.id} ${run.world}/${run.seed}`;
    expect(JSON.stringify(buildFor(template, w, run.seed)) === JSON.stringify(s), `${label}: deterministic`).toBe(true);
    checkVulnStructure(s.case, s.corpus);
    checkVulnCorpus(s.corpus, label);
    checkVulnGrading(s.case);
    expect(syntheticViolations(s.corpus, w, s.case), label).toEqual([]);
    if (run.db) await checkVulnSolvable(s, undefined, opts.everyEvidenceRow ?? false);
  }
  for (let i = 0; i < sweep; i++) {
    const s = buildFor(template, world(`vuln-sweep-${i % 5}`), `sweep-${i}`);
    checkVulnStructure(s.case, s.corpus);
    checkVulnCorpus(s.corpus, `${template.id} sweep-${i}`);
    checkVulnGrading(s.case);
  }
}
