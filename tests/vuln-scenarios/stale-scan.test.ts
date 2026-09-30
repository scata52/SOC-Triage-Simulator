// vm-stale-scan: the headline's update was installed after the old scan run
// started, no reboot is pending and the newer run could not log in to the host
// (a visible login-failure row is the only thing it wrote there). The decoy
// host's later patch is an unrelated operating system rollup.
import { expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { AUTH_FAILURE_TITLE } from '../../src/core/vuln/templates/common.ts';
import { staleScan } from '../../src/core/vuln/templates/stale-scan.ts';
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
