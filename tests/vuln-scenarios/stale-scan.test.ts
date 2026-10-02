// vm-stale-scan: the headline's update was installed after the old scan run
// started, no reboot is pending and the newer run could not log in to the host
// (a visible login-failure row is the only thing it wrote there). The decoy
// host's later patch is an unrelated operating system rollup.
// vm-fresh-scan (the B side): the headline's update predates the scan but a reboot is pending and the credentialed
// evidence shows the old library still loaded; the sibling file server is the stale one.
import { expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { AUTH_FAILURE_TITLE } from '../../src/core/vuln/templates/common.ts';
import { freshScan, staleScan } from '../../src/core/vuln/templates/stale-scan.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const ms = (v: unknown): number => new Date(String(v)).getTime();

it('the headline is stale on every seed', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(staleScan, world(run.world), run.seed);
    const corpus = b.corpus as Corpus;
    const [head, decoy] = b.case.findings;
    const finding = rows(corpus, 'VulnFindings').find((r) => r.FindingId === head.findingId)!;
    const oldRun = rows(corpus, 'ScanRuns').find((r) => r.ScanRunId === finding.ScanRunId)!;
    const patch = rows(corpus, 'PatchHistory').find((r) => r.DeviceName === finding.DeviceName && String(r.Description).includes(String(finding.VulnId)))!;
    expect(patch, `${run.seed}: patch row`).toBeDefined();
    expect(ms(patch.InstalledOn)).toBeGreaterThan(ms(oldRun.Started));
    expect(Number(patch.RebootPending)).toBe(0);
    // Package-level: no banner port for a fallback to re-detect it.
    expect(finding.Port, `${run.seed}: package-level finding`).toBeNull();
    // The newer run never re-tested the host: its only row there is the visible login failure.
    const newer = rows(corpus, 'VulnFindings').filter((r) => r.DeviceName === finding.DeviceName && r.ScanRunId !== finding.ScanRunId);
    expect(newer.map((r) => r.Title), `${run.seed}: only the login failure`).toEqual([AUTH_FAILURE_TITLE]);
    expect(newer[0].VulnId).toBe('');
    const newRun = rows(corpus, 'ScanRuns').find((r) => r.ScanRunId === newer[0].ScanRunId)!;
    expect(Number(newRun.AuthFailures)).toBe(1);
    expect(ms(newRun.Started)).toBeGreaterThan(ms(oldRun.Started));
    // The decoy host's later patch is dated after the old run started but is an unrelated rollup.
    const decoyRow = rows(corpus, 'VulnFindings').find((r) => r.FindingId === decoy.findingId)!;
    const rollup = rows(corpus, 'PatchHistory').find((r) => r.DeviceName === decoyRow.DeviceName)!;
    expect(ms(rollup.InstalledOn), `${run.seed}: decoy patch dated after the old run`).toBeGreaterThan(ms(oldRun.Started));
    expect(String(rollup.Description)).not.toMatch(/SIMVULN/);
  }
}, 600_000);

it('the Critical was published after the complete old run started; the accepted item fits its exception', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(staleScan, world(run.world), run.seed);
    const corpus = b.corpus as Corpus;
    const label = `${run.world}/${run.seed}`;
    const vf = rows(corpus, 'VulnFindings');
    const intel = (id: unknown) => rows(corpus, 'VulnIntel').find((r) => r.VulnId === id)!;
    const rowOf = (i: number) => vf.find((r) => r.FindingId === b.case.findings[i].findingId)!;
    const oldRun = rows(corpus, 'ScanRuns').find((r) => r.ScanRunId === rowOf(0).ScanRunId)!;
    const crit = rowOf(3);
    expect(crit.Severity, label).toBe('Critical');
    expect(ms(intel(crit.VulnId).Published), `${label}: published after the old run started`).toBeGreaterThan(ms(oldRun.Started));
    expect(ms(intel(crit.VulnId).Published), `${label}: published before it was first seen`).toBeLessThanOrEqual(ms(crit.FirstSeen));
    const ex = rowOf(4);
    const exIntel = intel(ex.VulnId);
    expect(exIntel.CvssVector, `${label}: accepted item is network-reachable`).toMatch(/AV:N/);
    expect(exIntel.VendorFix, label).toBeFalsy();
    const ticket = rows(corpus, 'Tickets').find((r) => String(r.Title).startsWith('Risk exception'))!;
    expect(String(ticket.Details), label).toContain(String(ex.VulnId));
    expect(ms(ticket.Created), `${label}: ticket after publication`).toBeGreaterThanOrEqual(ms(exIntel.Published));
    expect(ms(ticket.WindowEnd), `${label}: not expired`).toBeGreaterThan(ms(b.now));
  }
}, 600_000);

it('the stale host and the decoy host run different products, and the decoy shows a version below the fix (S2, S4)', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(staleScan, world(run.world), run.seed);
    const corpus = b.corpus as Corpus;
    const vf = rows(corpus, 'VulnFindings');
    const [head, decoy] = b.case.findings;
    const of = (id: string) => vf.find((r) => r.FindingId === id)!;
    const [h, d] = [of(head.findingId), of(decoy.findingId)];
    const productsOn = (host: unknown) => new Set(rows(corpus, 'SoftwareInventory').filter((s) => s.DeviceName === host).map((s) => String(s.Product)));
    const [ph, pd] = [productsOn(h.DeviceName), productsOn(d.DeviceName)];
    expect([...ph].filter((p) => pd.has(p)), `${run.seed}: no shared product`).toEqual([]);
    // the SoftwareInventory rows are alternative evidence for the two points
    const soft = new Set(rows(corpus, 'SoftwareInventory').map((s) => String(s.RecordId)));
    for (const f of [head, decoy]) expect(f.evidence[0].recordIds.some((id) => soft.has(id)), `${run.seed}: inventory row among the evidence alternatives`).toBe(true);
  }
}, 600_000);

it('vm-fresh-scan: the update predates the old run, the reboot is pending and the service still loads the old library', () => {
  for (const run of vulnRuns(20, 20)) {
    const b = buildFor(freshScan, world(run.world), run.seed);
    const corpus = b.corpus as Corpus;
    const [head, sib] = b.case.findings;
    const finding = rows(corpus, 'VulnFindings').find((r) => r.FindingId === head.findingId)!;
    const oldRun = rows(corpus, 'ScanRuns').find((r) => r.ScanRunId === finding.ScanRunId)!;
    const patch = rows(corpus, 'PatchHistory').find((r) => r.DeviceName === finding.DeviceName && String(r.Description).includes(String(finding.VulnId)))!;
    expect(patch, `${run.seed}: patch row`).toBeDefined();
    expect(ms(patch.InstalledOn), `${run.seed}: installed before the old run`).toBeLessThan(ms(oldRun.Started));
    expect(Number(patch.RebootPending), `${run.seed}: reboot pending`).toBe(1);
    expect(finding.Port, `${run.seed}: package-level finding`).toBeNull();
    // the finding's DetectedVersion is the running (old) version; the inventory shows the fixed package on disk
    const intel = rows(corpus, 'VulnIntel').find((r) => r.VulnId === finding.VulnId)!;
    const soft = rows(corpus, 'SoftwareInventory').find((s) => s.DeviceName === finding.DeviceName && s.Version === intel.FixedVersion)!;
    expect(soft, `${run.seed}: the fixed package is on disk`).toBeDefined();
    expect(String(finding.Evidence)).toContain(String(finding.DetectedVersion));
    expect(finding.DetectedVersion).not.toBe(intel.FixedVersion);
    // the newer run did not touch the host (a visible gap is not the clue here: the reboot is)
    expect(rows(corpus, 'VulnFindings').filter((r) => r.DeviceName === finding.DeviceName && r.ScanRunId !== finding.ScanRunId), `${run.seed}: not in the newer run`).toEqual([]);
    // the sibling is the stale one: updated after the old run started, no reboot pending, login failed in the newer run
    const sf = rows(corpus, 'VulnFindings').find((r) => r.FindingId === sib.findingId)!;
    const sp = rows(corpus, 'PatchHistory').find((r) => r.DeviceName === sf.DeviceName && String(r.Description).includes(String(sf.VulnId)))!;
    expect(ms(sp.InstalledOn)).toBeGreaterThan(ms(oldRun.Started));
    expect(Number(sp.RebootPending)).toBe(0);
    const newer = rows(corpus, 'VulnFindings').filter((r) => r.DeviceName === sf.DeviceName && r.ScanRunId !== sf.ScanRunId);
    expect(newer.map((r) => r.Title)).toEqual([AUTH_FAILURE_TITLE]);
    expect(b.case.findings[0].truth.contradicting).toContain('stale-scan');
  }
}, 600_000);

it('the real Critical is a key finding in both twins (dismissing it as a false positive must trip the lesson gate)', () => {
  for (const run of vulnRuns(20, 20)) {
    for (const t of [staleScan, freshScan]) {
      const s = buildFor(t, world(run.world), run.seed);
      const crit = s.case.findings.find((f) => f.truth.schedule === 'emergency')!;
      expect(crit.mustNotMiss, `${t.id} ${run.seed}`).toBe(true);
      expect(crit.weight, `${t.id} ${run.seed}`).toBe(3);
      expect(crit.evidence.length, `${t.id} ${run.seed}: evidence point`).toBeGreaterThanOrEqual(1);
    }
  }
}, 600_000);
