// vm-backport-fp: the headline came from a banner-only run; its package is the
// distro build at the fixed release; the decoy host shows the same banner and
// an older release.
import { expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { generateCatalogue } from '../../src/core/vuln/catalogue.ts';
import { backportFp } from '../../src/core/vuln/templates/backport-fp.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const release = (v: unknown): number => Number(/-(\d+)\./.exec(String(v))![1]);

it('the headline is a backported fix, the decoy is not', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(backportFp, world(run.world), run.seed);
    const c = b.corpus as Corpus;
    const [head, decoy] = b.case.findings;
    const f = rows(c, 'VulnFindings');
    const hf = f.find((r) => r.FindingId === head.findingId)!;
    const df = f.find((r) => r.FindingId === decoy.findingId)!;
    expect(rows(c, 'ScanRuns').find((r) => r.ScanRunId === hf.ScanRunId)!.Method).toBe('Unauthenticated');
    expect(df.DetectedVersion).toBe(hf.DetectedVersion);
    const soft = (h: Row) => rows(c, 'SoftwareInventory').find((r) => r.DeviceName === h.DeviceName && r.Product === 'Quorvane httpd')!;
    expect(soft(hf).PackageSource).toBe('distro');
    expect(release(soft(hf).Version)).toBeGreaterThan(release(soft(df).Version));
    const patch = rows(c, 'PatchHistory').find((r) => r.DeviceName === hf.DeviceName && String(r.Description).includes(String(hf.VulnId)))!;
    expect(patch, `${run.seed}: advisory row`).toBeDefined();
    expect(rows(c, 'PatchHistory').some((r) => r.DeviceName === df.DeviceName && String(r.Description).includes(String(df.VulnId)))).toBe(false);
    expect(b.case.findings.length).toBeGreaterThanOrEqual(8);
  }
}, 600_000);

it('the Sim-KEV decoy is stale and was never re-tested, the must-not-miss is not', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(backportFp, world(run.world), run.seed);
    const c = b.corpus as Corpus;
    const f = rows(c, 'VulnFindings');
    const intel = rows(c, 'VulnIntel');
    const listed = b.case.findings.filter((x) => intel.find((i) => i.VulnId === f.find((r) => r.FindingId === x.findingId)!.VulnId)?.KnownExploited);
    expect(listed).toHaveLength(2);
    const [must, decoy] = listed.sort((x, y) => Number(y.mustNotMiss) - Number(x.mustNotMiss));
    expect(must.truth.schedule).toBe('emergency');
    expect(decoy.truth.decision).toBe('false-positive');
    expect(decoy.truth.contradicting).toContain('pending-reboot');
    const row = f.find((r) => r.FindingId === decoy.findingId)!;
    const patch = rows(c, 'PatchHistory').find((r) => r.DeviceName === row.DeviceName && String(r.Description).includes(String(row.VulnId)))!;
    expect(patch, `${run.seed}: patch names the id`).toBeDefined();
    expect(Date.parse(String(patch.InstalledOn))).toBeGreaterThan(Date.parse(String(row.FirstSeen)));
    expect(Number(patch.RebootPending)).toBe(0);
    expect(f.some((r) => r.DeviceName === row.DeviceName && String(r.Title).startsWith('Authentication failure'))).toBe(true);
    // listing at the start of a day, and the rubric names the public website's actual owner
    const owner = String(rows(c, 'DeviceInfo').find((d) => d.DeviceName === 'WEB01')!.Owner).toLowerCase();
    expect(b.case.rubric.find((r) => r.id === 'owner')!.keywords).toContain(owner);
    const added = Date.parse(String(intel.find((i) => i.VulnId === f.find((r) => r.FindingId === must.findingId)!.VulnId)!.KnownExploitedAdded));
    expect(added % 86_400_000).toBe(0);
  }
}, 600_000);

it('the accepted item is network-reachable, its exception fits and is not expired, and the owner rubric has no repeats', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(backportFp, world(run.world), run.seed);
    const c = b.corpus as Corpus;
    const label = `${run.world}/${run.seed}`;
    const ex = b.case.findings[b.case.findings.length - 1];
    const row = rows(c, 'VulnFindings').find((r) => r.FindingId === ex.findingId)!;
    const intel = rows(c, 'VulnIntel').find((r) => r.VulnId === row.VulnId)!;
    expect(ex.truth.decision, label).toBe('accept');
    expect(intel.CvssVector, `${label}: accepted item is network-reachable`).toMatch(/AV:N/);
    const ticket = rows(c, 'Tickets').find((r) => String(r.Title).startsWith('Risk exception'))!;
    expect(String(ticket.Details), label).toContain(String(row.VulnId));
    expect(Date.parse(String(ticket.Created)), `${label}: ticket after publication`).toBeGreaterThanOrEqual(Date.parse(String(intel.Published)));
    expect(Date.parse(String(ticket.WindowEnd)), `${label}: not expired`).toBeGreaterThan(Date.parse(String(b.now)));
    const keywords = b.case.rubric.find((r) => r.id === 'owner')!.keywords;
    expect(new Set(keywords).size, `${label}: owner keywords`).toBe(keywords.length);
    const text = JSON.stringify(b.case.rubric) + JSON.stringify(b.case.explanation) + JSON.stringify(b.case.pitfalls);
    expect(text, `${label}: it is the vulnerability, not the website, that is on the list`).not.toMatch(/website (?:is|was) (?:known|on|listed)|website finding/i);
  }
}, 600_000);

it('the web server product shares no word with a catalogue product; the banner-only evidence accepts the headline row (P6, P7)', () => {
  const words = (name: string) => name.toLowerCase().split(/\W+/).filter(Boolean);
  const run = vulnRuns(1, 1)[0];
  const b = buildFor(backportFp, world(run.world), run.seed);
  const c = b.corpus as Corpus;
  const web = words('Quorvane httpd');
  const others = new Set(generateCatalogue('p6', Date.parse(String(b.now))).entries.flatMap((e) => words(e.product)));
  expect(web.filter((w) => others.has(w))).toEqual([]);
  const head = b.case.findings[0];
  const banner = head.evidence.find((e) => e.id === 'banner-only-scan')!;
  const headRow = rows(c, 'VulnFindings').find((r) => r.FindingId === head.findingId)!;
  expect(banner.recordIds).toContain(String(headRow.RecordId));
}, 600_000);
