// Content batch B (WP3): the twin pairs of the batch as a table keyed by pair (T6, T7, T8, T11, T10), checked by the generic
// suite shared with batch A (pair-helpers.ts: registration, same title/difficulty/headline, rule 3, the lesson names the
// clue, the clue is in the data on every run, an identical pre-submit surface). All five pairs of WP3 are rows of PAIRS (T10, the tier-3 pair with
// T9's ordering pattern inside, carries the tier-3 checks in its row: size, two runs, stale versus fresh, T9 order, capacity).
import { describe, expect, it } from 'vitest';
import { VULN_SCHEDULES, type VulnSchedule } from '../../src/core/vuln/model.ts';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import { byId, findingRow, flag, headIntel, headRow, type PairRow, registerPairSuite, rows } from './pair-helpers.ts';
import type { VulnScenario } from '../../src/core/vuln/scenario.ts';
import { compareVersions } from '../../src/core/vuln/scan-writer.ts';
import { AUTH_FAILURE_TITLE, endOfDay, slaClassOf } from '../../src/core/vuln/templates/common.ts';

const DAY_MS = 86_400_000;

// ---- T6: vm-legacy-accept / vm-legacy-isolate ----------------------------------------------------------

// The controller (headline host), its control-interface sessions, the ACL rows on that interface and the exception tickets.
function legacyFacts(s: VulnScenario) {
  const head = headRow(s);
  const device = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!;
  const sessions = rows(s.corpus, 'FirewallLogs').filter((f) => f.DestinationIP === device.IPAddress && Number(f.DestinationPort) === Number(head.Port));
  const headAcls = rows(s.corpus, 'ControlInventory').filter((c) => c.Kind === 'ACL' && c.CoversVulnId === head.VulnId);
  const exceptions = rows(s.corpus, 'Tickets').filter((t) => String(t.Title).startsWith('Risk exception'));
  const named = exceptions.filter((t) => String(t.Details).includes(String(head.VulnId)));
  const intel = rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === head.VulnId)!;
  return { head, device, sessions, headAcls, exceptions, named, intel };
}

const T6: PairRow = {
  pair: 'T6',
  a: 'vm-legacy-accept',
  b: 'vm-legacy-isolate',
  lesson: { a: ['Tickets', 'approved', 'exception', 'ControlInventory', 'block', 'FirewallLogs', 'accept'], b: ['Tickets', 'no approved exception', 'ControlInventory', 'FirewallLogs', 'corporate', 'mitigate'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [legacyFacts(a), legacyFacts(b)];
    const now = Date.parse(a.now);
    // Both: the same controller, no vendor fix (VulnIntel), the one ACL id that covers the headline, seven sessions to the control port (six plus the scanner).
    for (const [name, f] of [['A', fa], ['B', fb]] as const) {
      expect(flag(f.intel.VendorFix), `${label}: ${name} no vendor fix`).toBe(false);
      expect(flag(f.device.ExposedToInternet), `${label}: ${name} not exposed`).toBe(false);
      expect(f.headAcls.length, `${label}: ${name} one ACL names the headline`).toBe(1);
      expect(f.headAcls[0].Mode, `${label}: ${name} the ACL blocks`).toBe('block');
      expect(f.sessions.length, `${label}: ${name} sessions to the control port`).toBe(7);
    }
    expect(fa.headAcls[0].ControlId, `${label}: same ACL id`).toBe(fb.headAcls[0].ControlId);
    // The allowed sources are OT engineering workstations of the lab team in the management range (not corporate IT servers), and the controller
    // sits in the management range too (round-1 review: a corporate software-deployment server was the "OT management host").
    for (const s of [a, b]) {
      const f = legacyFacts(s);
      const devices = rows(s.corpus, 'DeviceInfo');
      const scannerIp = String(devices.find((x) => x.DeviceName === 'SCAN01')!.IPAddress);
      const sources = [...new Set(f.sessions.filter((x) => /\.250\./.test(String(x.SourceIP)) && x.SourceIP !== scannerIp).map((x) => String(x.SourceIP)))];
      expect(sources.length, `${label}: ${s.case.templateId} the allowed sources`).toBeGreaterThanOrEqual(1);
      for (const ip of sources) {
        const d = devices.find((x) => x.IPAddress === ip)!;
        expect([String(d.Role).startsWith('OT engineering workstation'), d.Owner], `${label}: ${s.case.templateId} ${ip} is an OT engineering workstation of Lab Engineering`).toEqual([true, 'Lab Engineering']);
      }
      expect(String(f.device.IPAddress), `${label}: ${s.case.templateId} the controller is in the management range`).toMatch(/\.250\./);
      expect(String(f.device.Role), `${label}: ${s.case.templateId} the controller's role says the laboratory segment`).toContain('laboratory segment');
      // The no-vendor-fix row decides accept against mitigate (the Compensating control row's mitigate is for a control still to be applied).
      const noFix = (s.case.attachments.find((x) => x.title.includes('remediation standard'))!.body as [string, string][]).find(([k]) => k === 'No vendor fix')![1];
      for (const phrase of ['record the finding as accept and note the expiry', 'this row, not the Compensating control row, decides', 'mitigate is for a control that is still to be applied']) expect(noFix, `${label}: ${s.case.templateId} the row says "${phrase}"`).toContain(phrase);
    }
    expect(a.case.pitfalls.some((p) => p.startsWith('Recording mitigate')), `${label}: A names the mitigate misconception`).toBe(true);
    // The allowed sources are the OT management hosts and the authorised scanner SCAN01 (also in the management range): the ACL Evidence
    // and the exception name both, and the newer sweep that read the banner left one allowed session (during that run) from it.
    const scannerOf = (s: VulnScenario) => String(rows(s.corpus, 'DeviceInfo').find((x) => x.DeviceName === 'SCAN01')!.IPAddress);
    const scan = (s: VulnScenario) => legacyFacts(s).sessions.filter((x) => x.SourceIP === scannerOf(s));
    const mgmt = (f: ReturnType<typeof legacyFacts>, s: VulnScenario) => f.sessions.filter((x) => /\.250\./.test(String(x.SourceIP)) && x.SourceIP !== scannerOf(s));
    const corp = (f: ReturnType<typeof legacyFacts>) => f.sessions.filter((s) => !/\.250\./.test(String(s.SourceIP)));
    for (const [f, s] of [[fa, a], [fb, b]] as const) {
      expect(mgmt(f, s).length, `${label}: three OT management sessions`).toBe(3);
      expect(mgmt(f, s).every((x) => x.Action === 'Allow'), `${label}: the OT management hosts are allowed`).toBe(true);
      expect(corp(f).length, `${label}: three corporate sessions`).toBe(3);
      const sc = scan(s);
      expect(sc.length, `${label}: ${s.case.templateId} one scanner session`).toBe(1);
      expect(sc[0].Action, `${label}: the scanner is allowed`).toBe('Allow');
      const run = rows(s.corpus, 'ScanRuns').filter((r) => r.Method === 'Unauthenticated').sort((x, y) => Date.parse(String(y.Started)) - Date.parse(String(x.Started)))[0];
      const t = Date.parse(String(sc[0].TimeGenerated));
      expect(t >= Date.parse(String(run.Started)) && t <= Date.parse(String(run.Finished)), `${label}: ${s.case.templateId} the scanner session is during the newer sweep, which is after the ACL was verified`).toBe(true);
      const acl = f.headAcls[0];
      expect(String(acl.Evidence), `${label}: ${s.case.templateId} the ACL Evidence names the authorised scanner`).toContain('SCAN01');
      if (s === a) expect(String(f.named[0].Details), `${label}: A the exception names the scanner`).toContain('SCAN01');
    }
    expect(JSON.stringify(scan(a).map((x) => [x.TimeGenerated, x.SourcePort])), `${label}: the scanner session is the same in both twins`).toBe(JSON.stringify(scan(b).map((x) => [x.TimeGenerated, x.SourcePort])));
    // A: an approved, unexpired exception for the host; the ACL names the host; the corporate sessions are denied.
    expect(fa.named.length, `${label}: A one exception names the headline`).toBe(1);
    const ex = fa.named[0];
    expect([ex.Status, ex.Scope], `${label}: A exception is approved and scoped to the host`).toEqual(['Approved', String(fa.head.DeviceName)]);
    expect(Date.parse(String(ex.WindowEnd)), `${label}: A exception has not expired`).toBeGreaterThan(now);
    expect(Date.parse(String(ex.WindowEnd)) - now, `${label}: A exception is time-boxed (under a year)`).toBeLessThan(365 * DAY_MS);
    expect(String(fa.headAcls[0].Target), `${label}: A ACL names the host`).toContain(String(fa.head.DeviceName));
    expect(corp(fa).every((s) => s.Action === 'Deny' && Number(s.BytesSent) === 0), `${label}: A corporate sources are denied`).toBe(true);
    expect(a.case.findings[0].truth, `${label}: A accepts`).toMatchObject({ decision: 'accept', schedule: 'none' });
    expect(a.case.findings[0].truth.reasons, `${label}: A reasons`).toEqual(expect.arrayContaining(['approved-exception', 'no-vendor-fix']));
    expect(a.case.findings[0].truth.mitigation, `${label}: A names no control to apply`).toBeUndefined();
    // B: no approved exception names the host (one open request does); the ACL is for the segment and its Evidence says the host is not in scope;
    // corporate workstations are allowed; the truth is mitigate naming that ACL.
    expect(fb.named.length, `${label}: B one request names the headline`).toBe(1);
    expect(fb.named[0].Status, `${label}: B request is only open`).toBe('Open');
    expect(fb.named.filter((t) => t.Status === 'Approved').length, `${label}: B has no approved exception for the host`).toBe(0);
    expect(String(fb.headAcls[0].Target), `${label}: B ACL is the segment's, not the host's`).not.toContain(String(fb.head.DeviceName));
    expect(String(fb.headAcls[0].Evidence), `${label}: B ACL says the host is not in scope`).toContain(`${String(fb.head.DeviceName)} is not in scope`);
    expect(corp(fb).every((s) => s.Action === 'Allow' && Number(s.BytesReceived) > 0), `${label}: B corporate sources are allowed through`).toBe(true);
    expect(b.case.findings[0].truth, `${label}: B mitigates in the next window`).toMatchObject({ decision: 'mitigate', schedule: 'next-window', slaLatest: 'next-window', mitigation: [String(fb.headAcls[0].ControlId)] });
    expect(b.case.findings[0].truth.reasons, `${label}: B reasons`).toEqual(expect.arrayContaining(['no-vendor-fix', 'control-not-covering']));
    expect(b.case.findings[0].truth.alsoAccept ?? [], `${label}: B does not accept an accept`).not.toContain('accept');
    expect(a.case.findings[0].truth.alsoAccept ?? [], `${label}: A does not accept a mitigate`).not.toContain('mitigate');
    // Both: the same corporate sources and times, the same decoys (an expired exception on another host whose flaw has a fix now,
    // a detect-mode ACL naming another finding, an enforcing control that is not on the path).
    const key = (f: ReturnType<typeof legacyFacts>) => corp(f).map((s) => `${String(s.SourceIP)}|${String(s.TimeGenerated)}|${String(s.SourcePort)}`).sort();
    expect(key(fa), `${label}: same corporate sources and times`).toEqual(key(fb));
    for (const s of [a, b]) {
      const expired = legacyFacts(s).exceptions.filter((t) => Date.parse(String(t.WindowEnd)) < now);
      expect(expired.length, `${label}: ${s.case.templateId} one expired exception`).toBe(1);
      expect(expired[0].Status, `${label}: the expired exception is still marked Approved`).toBe('Approved');
      expect(String(expired[0].Scope), `${label}: on another host`).not.toBe(String(fa.head.DeviceName));
      const other = rows(s.corpus, 'VulnIntel').find((r) => String(expired[0].Details).includes(String(r.VulnId)))!;
      expect(flag(other.VendorFix), `${label}: its flaw has a vendor fix now`).toBe(true);
      expect(rows(s.corpus, 'ControlInventory').some((c) => c.Kind === 'ACL' && c.Mode === 'detect' && c.CoversVulnId !== '' && c.CoversVulnId !== fa.head.VulnId), `${label}: a detect-mode ACL names another finding`).toBe(true);
      expect(rows(s.corpus, 'ControlInventory').some((c) => c.Kind === 'Config' && c.Mode === 'block' && c.CoversVulnId === ''), `${label}: an enforcing control that is not on the path`).toBe(true);
    }
    const decoyTruths = (s: VulnScenario) => JSON.stringify(s.case.findings.slice(1).map((f) => f.truth));
    expect(decoyTruths(a), `${label}: same truths below the headline`).toBe(decoyTruths(b));
    expect(legacyFacts(a).exceptions.length, `${label}: same number of exception tickets`).toBe(legacyFacts(b).exceptions.length);
  },
  extra: ({ a, b, label }) => {
    // The headline is a High, not on Sim-KEV, with identical intel; the case is tier 1; the policy states the no-vendor-fix rule in both twins.
    for (const s of [a, b]) {
      const h = headRow(s);
      expect(Number(h.CvssBase), `${label}: High`).toBeGreaterThanOrEqual(7);
      expect(Number(h.CvssBase), `${label}: High`).toBeLessThan(9);
      expect(flag(rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === h.VulnId)!.KnownExploited), `${label}: not on Sim-KEV`).toBe(false);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeGreaterThanOrEqual(4);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeLessThanOrEqual(6);
      expect(JSON.stringify(s.case.attachments.find((x) => x.title.includes('remediation standard'))!.body), `${label}: the policy has the no-vendor-fix row`).toContain('No vendor fix');
    }
    expect(headIntel(a), `${label}: same intel`).toBe(headIntel(b));
    // The High deadline (30 days from first detection) falls after the next window and before the standard cycle: B's change is next-window and the
    // window ends a day or more before the deadline (nothing else meets it); the case fits the window's capacity in either twin.
    const k = b.case.constraints;
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(k));
    const [next, cycle] = [...k.windows].sort((x, y) => x.start - y.start);
    const deadline = Date.parse(String(headRow(b).FirstSeen)) + k.slaDays.high * DAY_MS;
    expect(deadline - next.end, `${label}: the deadline is a day or more after the next window`).toBeGreaterThanOrEqual(DAY_MS);
    expect(cycle.start - deadline, `${label}: the deadline is before the standard cycle`).toBeGreaterThan(0);
    for (const s of [a, b]) {
      const scheduled = s.case.findings.filter((f) => f.truth.schedule === 'emergency' || f.truth.schedule === 'next-window').length;
      expect(scheduled, `${label}: ${s.case.templateId} emergency and next-window changes fit the capacity`).toBeLessThanOrEqual(k.capacityPerWindow);
    }
    // The twins differ in the headline's truth only by decision (accept vs mitigate); the ordering follows: B tiers the headline, A leaves it out.
    expect(b.case.tiers.flat(), `${label}: B tiers the headline`).toContain(b.case.findings[0].findingId);
    expect(a.case.tiers.flat(), `${label}: A leaves the accepted headline out`).not.toContain(a.case.findings[0].findingId);
    expect(VULN_SCHEDULES.indexOf(b.case.findings[0].truth.schedule), `${label}: B schedule is a real window`).toBeLessThan(VULN_SCHEDULES.indexOf('standard-cycle'));
  },
};

// ---- T7: vm-noncred-low / vm-cred-high -----------------------------------------------------------------
// Two look-alike application servers carry the same Critical from an unauthenticated sweep (banner only). The older credentialed run
// reached one (a local check row) and failed to log in to the other (the "Authentication failure" row); the inventory of the first shows
// a release above the fix, the other's the vulnerable one. A: the headline is the first (false positive); B: the headline is the other (real).

function scanMethodFacts(s: VulnScenario) {
  const runs = rows(s.corpus, 'ScanRuns');
  const all = rows(s.corpus, 'VulnFindings');
  const [r0, r1] = [findingRow(s, 0), findingRow(s, 1)];
  const sweep = runs.find((r) => r.ScanRunId === r0.ScanRunId)!;
  const cred = runs.find((r) => r.Method === 'Credentialed')!;
  const intel = rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === r0.VulnId)!;
  const host = (row: Record<string, unknown>) => {
    const name = String(row.DeviceName);
    const inCred = all.filter((r) => r.ScanRunId === cred.ScanRunId && r.DeviceName === name);
    const failed = inCred.filter((r) => String(r.Title) === AUTH_FAILURE_TITLE);
    const reached = inCred.filter((r) => String(r.Title) !== AUTH_FAILURE_TITLE);
    const inv = rows(s.corpus, 'SoftwareInventory').filter((x) => x.DeviceName === name && String(row.Title).includes(` in ${String(x.Product)} `));
    return { row, name, failed, reached, inv, above: inv.length === 1 && compareVersions(String(inv[0].Version), String(intel.FixedVersion)) >= 0 };
  };
  const head = host(r0);
  const sib = host(r1);
  const patched = rows(s.corpus, 'PatchHistory').some((p) => [head.name, sib.name].includes(String(p.DeviceName)));
  return { sweep, cred, intel, head, sib, patched };
}

const T7: PairRow = {
  pair: 'T7',
  a: 'vm-noncred-low',
  b: 'vm-cred-high',
  lesson: { a: ['ScanRuns', 'unauthenticated', 'banner', 'credentialed', 'VulnFindings', 'SoftwareInventory', 'false positive'], b: ['ScanRuns', 'VulnFindings', 'credentialed', 'could not log in', 'authentication failure', 'SoftwareInventory', 'real', 'emergency'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [scanMethodFacts(a), scanMethodFacts(b)];
    for (const [name, f] of [['A', fa], ['B', fb]] as const) {
      // The flaw was published before the credentialed run started, so that run could have tested for it (its silence means something).
      expect(Date.parse(String(f.intel.Published)), `${label}: ${name} the headline flaw is older than the credentialed run`).toBeLessThan(Date.parse(String(f.cred.Started)));
      // Both: one credentialed run, older than the unauthenticated sweep that reports the headline, with one authentication failure in it.
      expect(f.cred.Method, `${label}: ${name} credentialed run`).toBe('Credentialed');
      expect(f.sweep.Method, `${label}: ${name} the sweep is unauthenticated`).toBe('Unauthenticated');
      expect(Date.parse(String(f.cred.Started)), `${label}: ${name} the credentialed run is older than the sweep`).toBeLessThan(Date.parse(String(f.sweep.Started)));
      expect(Number(f.cred.AuthFailures), `${label}: ${name} one login failed`).toBe(1);
      expect(Number(f.cred.TargetsScanned), `${label}: ${name} the credentialed run is partial`).toBeLessThan(Number(f.cred.TargetsPlanned));
      // Both worklist rows come from the sweep with the same banner, Open, banner-only evidence.
      for (const r of [f.head.row, f.sib.row]) {
        expect(r.ScanRunId, `${label}: ${name} sweep row`).toBe(f.sweep.ScanRunId);
        expect(r.Status, `${label}: ${name} open`).toBe('Open');
        expect(String(r.Evidence), `${label}: ${name} banner only`).toContain('banner only');
      }
      expect(f.head.row.DetectedVersion, `${label}: ${name} the same banner on both`).toBe(f.sib.row.DetectedVersion);
      expect(f.head.row.VulnId, `${label}: ${name} the same vulnerability on both`).toBe(f.sib.row.VulnId);
      expect(flag(f.intel.KnownExploited) || flag(f.intel.PublicExploit), `${label}: ${name} no exploitation signal`).toBe(false);
      expect(f.head.inv.length + f.sib.inv.length, `${label}: ${name} one inventory row each`).toBe(2);
      // No update record on either server: the false positive is not a backport (T1's lesson), its release is above the fix by its own number.
      expect(f.patched, `${label}: ${name} no update record`).toBe(false);
    }
    // A: the headline host was reached by the credentialed run (a row, no failure) and its inventory is above the fix: false positive.
    // The sibling failed to log in and its inventory shows the banner's (vulnerable) release: real.
    expect([fa.head.reached.length, fa.head.failed.length, fa.head.above], `${label}: A headline coverage`).toEqual([1, 0, true]);
    expect([fa.sib.reached.length, fa.sib.failed.length, fa.sib.above], `${label}: A sibling coverage`).toEqual([0, 1, false]);
    expect(String(fa.sib.inv[0].Version), `${label}: A sibling runs the banner's release`).toBe(String(fa.sib.row.DetectedVersion));
    expect(a.case.findings[0].truth, `${label}: A headline is a false positive`).toMatchObject({ decision: 'false-positive', schedule: 'none' });
    expect(a.case.findings[0].truth.reasons, `${label}: A reasons`).toEqual(['banner-only']);
    expect(a.case.findings[1].truth, `${label}: A sibling is real`).toMatchObject({ decision: 'patch', schedule: 'emergency', slaLatest: 'emergency' });
    // B: the roles swap.
    expect([fb.head.reached.length, fb.head.failed.length, fb.head.above], `${label}: B headline coverage`).toEqual([0, 1, false]);
    expect([fb.sib.reached.length, fb.sib.failed.length, fb.sib.above], `${label}: B sibling coverage`).toEqual([1, 0, true]);
    expect(String(fb.head.inv[0].Version), `${label}: B headline runs the banner's release`).toBe(String(fb.head.row.DetectedVersion));
    expect(b.case.findings[0].truth, `${label}: B headline is real`).toMatchObject({ decision: 'patch', schedule: 'emergency', slaLatest: 'emergency' });
    expect(b.case.findings[0].truth.reasons, `${label}: B reasons`).toEqual(['sla-deadline']);
    expect(b.case.findings[1].truth, `${label}: B sibling is a false positive`).toMatchObject({ decision: 'false-positive', schedule: 'none' });
    // 'backported-fix' is wrong on both servers (distinct from T1); the findings are banner rows, so 'credentialed-confirmed' is no reason.
    for (const f of [...a.case.findings.slice(0, 2), ...b.case.findings.slice(0, 2)]) {
      expect(f.truth.contradicting, `${label}: ${f.findingId} backported-fix is wrong`).toContain('backported-fix');
      expect(f.truth.reasons, `${label}: ${f.findingId} no credentialed-confirmed`).not.toContain('credentialed-confirmed');
    }
  },
  extra: ({ a, b, label }) => {
    // Critical, tier 1, one emergency and one next-window change (capacity two), the real Critical first, the false positive untiered.
    for (const s of [a, b]) {
      expect(Number(headRow(s).CvssBase), `${label}: Critical`).toBeGreaterThanOrEqual(9);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeGreaterThanOrEqual(4);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeLessThanOrEqual(6);
      const scheduled = s.case.findings.filter((f) => f.truth.schedule === 'emergency' || f.truth.schedule === 'next-window');
      expect(scheduled.length, `${label}: ${s.case.templateId} emergency and next-window changes`).toBe(2);
      expect(scheduled.length, `${label}: fits the capacity`).toBeLessThanOrEqual(s.case.constraints.capacityPerWindow);
      const real = s.case.findings.find((f) => f.lesson && f.truth.decision === 'patch')!;
      const fp = s.case.findings.find((f) => f.lesson && f.truth.decision === 'false-positive')!;
      expect(s.case.tiers[0], `${label}: the real Critical is tier 1`).toEqual([real.findingId]);
      expect(s.case.tiers.flat(), `${label}: the false positive is untiered`).not.toContain(fp.findingId);
    }
    expect(headIntel(a), `${label}: same intel`).toBe(headIntel(b));
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
    const below = (s: VulnScenario) => JSON.stringify(s.case.findings.slice(2).map((f) => f.truth));
    expect(below(a), `${label}: same truths below the two servers`).toBe(below(b));
  },
};

// ---- T8: vm-saas-transfer / vm-self-hosted -----------------------------------------------------------------
// The same Critical in a third-party ticketing product, read by the external run as a version string of the organisation's own public
// hostname. A: DeviceInfo shows a vendor-hosted service IT does not manage and Tickets holds the subscription agreement (transfer). B: an
// IT-managed server and the installation record (patch, emergency). The vendor's advisory is the same text in both; a vendor support contract
// for an IT-run product and a second vendor-hosted service are the same decoys in both.

function saasFacts(s: VulnScenario) {
  const head = headRow(s);
  const device = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!;
  const tickets = rows(s.corpus, 'Tickets');
  const about = (host: unknown) => tickets.filter((t) => t.Scope === host);
  const advisory = about(head.DeviceName).find((t) => String(t.Title).startsWith('Vendor advisory'))!;
  const subscription = about(head.DeviceName).filter((t) => String(t.Title).startsWith('Vendor subscription'));
  const installation = about(head.DeviceName).filter((t) => String(t.Title).startsWith('Installation record'));
  const run = rows(s.corpus, 'ScanRuns').find((r) => r.ScanRunId === head.ScanRunId)!;
  const second = findingRow(s, 2);
  const secondDevice = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === second.DeviceName)!;
  const decoy = findingRow(s, 1);
  const decoyDevice = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === decoy.DeviceName)!;
  const contract = tickets.filter((t) => String(t.Title).startsWith('Vendor support contract'));
  const intel = rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === head.VulnId)!;
  return { head, device, advisory, subscription, installation, run, second, secondDevice, decoy, decoyDevice, contract, intel };
}

const T8: PairRow = {
  pair: 'T8',
  a: 'vm-saas-transfer',
  b: 'vm-self-hosted',
  lesson: { a: ['DeviceInfo', 'vendor-hosted', 'Tickets', 'subscription agreement', 'advisory', 'transfer'], b: ['DeviceInfo', 'installed', 'Tickets', 'installation record', 'hosted tenants', 'patch', 'emergency'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [saasFacts(a), saasFacts(b)];
    const reserved = (text: unknown) => /\.example\b/.test(String(text));
    for (const [name, f] of [['A', fa], ['B', fb]] as const) {
      // Both: the finding comes from an external, unauthenticated run (a version read of our own public hostname), never a test of the vendor.
      expect([f.run.Method, f.run.Vantage], `${label}: ${name} external unauthenticated run`).toEqual(['Unauthenticated', 'External']);
      expect(flag(f.device.ExposedToInternet), `${label}: ${name} the headline host is a public hostname`).toBe(true);
      expect(String(f.head.Evidence), `${label}: ${name} the finding is a version read, not an intrusive test`).toMatch(/own public hostname; no exploit and no intrusive test was sent/);
      expect(String(f.head.Evidence), `${label}: ${name} banner only`).toContain('banner only');
      expect(flag(f.intel.VendorFix), `${label}: ${name} a vendor fix exists`).toBe(true);
      expect(flag(f.intel.KnownExploited) || flag(f.intel.PublicExploit), `${label}: ${name} no exploitation signal`).toBe(false);
      // The vendor's advisory is the same in both twins: a hosted-tenant sentence with a committed date, and a self-managed sentence.
      const text = String(f.advisory.Details);
      expect(text, `${label}: ${name} advisory names the vulnerability`).toContain(String(f.head.VulnId));
      expect(text, `${label}: ${name} advisory has the hosted-tenant commitment`).toMatch(/Hosted service: the vendor is updating every hosted tenant and commits to finish the rollout by \d{4}-\d\d-\d\d/);
      expect(text, `${label}: ${name} advisory has the self-managed sentence`).toContain('Self-managed edition: the vendor does not update customer-run servers');
      const committed = /rollout by (\d{4}-\d\d-\d\d)/.exec(text)![1];
      const deadline = new Date(Date.parse(String(f.head.FirstSeen)) + 7 * DAY_MS).toISOString().slice(0, 10);
      expect(committed > a.now.slice(0, 10) && committed < deadline, `${label}: ${name} the vendor's date is after the case date and before our Critical deadline`).toBe(true);
      // Decoys, identical in both twins: a support contract for a product IT installed and runs (the finding is a patch), and a second hosted service (a transfer).
      expect(f.contract.length, `${label}: ${name} one vendor support contract`).toBe(1);
      expect(f.contract[0].Scope, `${label}: ${name} the contract is for the decoy host`).toBe(f.decoy.DeviceName);
      expect(flag(f.decoyDevice.IsManaged), `${label}: ${name} the contract's host is IT-managed`).toBe(true);
      expect(String(f.contract[0].Details), `${label}: ${name} IT runs the contract's product`).toContain('IT installed');
      expect(flag(f.secondDevice.IsManaged), `${label}: ${name} the second hosted service is not managed by IT`).toBe(false);
      expect(String(f.secondDevice.Role), `${label}: ${name} the second hosted service's tenant host is reserved`).toMatch(/vendor-hosted at tenant-\d+\.[a-z-]+\.example/);
    }
    expect(fa.advisory.Details, `${label}: the advisory is the same text in both twins`).toBe(fb.advisory.Details);
    // One recent story: the flaw was disclosed 2 to 10 days (plus the day start) before the first read, the advisory is 3 days old (round-2 review: a Published date
    // years back made a vendor that left a public Critical unpatched for years).
    for (const [name, f, s] of [['A', fa, a], ['B', fb, b]] as const) {
      for (const [row, intel] of [[f.head, f.intel], [f.second, rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === f.second.VulnId)!]] as const) {
        const gap = (Date.parse(String(row.FirstSeen)) - Date.parse(String(intel.Published))) / DAY_MS;
        expect(gap, `${label}: ${name} ${String(row.DeviceName)} the flaw was disclosed shortly before its first detection`).toBeGreaterThan(1);
        expect(gap, `${label}: ${name} ${String(row.DeviceName)} the flaw was disclosed shortly before its first detection`).toBeLessThanOrEqual(11);
      }
      // The finding is read from an organisation-owned public hostname, named in the data: the alias for the vendor's tenant (A) or the server's own name (B).
      const alias = /public hostname (helpdesk\.[a-z0-9.-]+[a-z])/.exec(String(f.device.Role))?.[1];
      expect(alias, `${label}: ${name} DeviceInfo names the organisation's public hostname`).toBeDefined();
      expect(String(f.head.Evidence), `${label}: ${name} the finding Evidence names that hostname`).toContain(`served at ${alias}, the organisation's own public hostname`);
      expect(String(f.secondDevice.Role), `${label}: ${name} the second hosted service has an alias of ours`).toMatch(/our public hostname dashboards\.[a-z0-9.-]+[a-z] is an alias/);
      expect(String(f.second.Evidence), `${label}: ${name} its finding Evidence names it`).toMatch(/served at dashboards\.[a-z0-9.-]+[a-z], the organisation's own public hostname/);
    }
    expect(String(fa.subscription[0].Details), `${label}: A the subscription ticket names the alias`).toMatch(/our public hostname helpdesk\.[a-z0-9.-]+[a-z] is an alias/);
    // The vendor-cloud addresses are never one of the world's reserved external addresses (office egress, VPN gateways).
    for (const [name, s, f] of [['A', a, fa], ['B', b, fb]] as const) {
      const named = new Set(rows(s.corpus, 'NamedLocations').map((r) => String(r.IPAddress)));
      for (const d of [f.device, f.secondDevice]) expect(named.has(String(d.IPAddress)), `${label}: ${name} ${String(d.DeviceName)} does not take a NamedLocations address`).toBe(false);
    }
    // A vendor-hosted service is not on our network: a vendor-cloud site and a documentation-range address (A's headline, and the second service in both
    // twins); the self-managed server in B is on our DMZ. (Round-1 review: hosted services had a DMZ address and our site.)
    for (const [name, d] of [['A headline', fa.device], ['A second service', fa.secondDevice], ['B second service', fb.secondDevice]] as const) {
      expect(String(d.IPAddress), `${label}: ${name} has a documentation-range address`).toMatch(/^203\.0\.113\.\d+$/);
      expect(String(d.Site), `${label}: ${name} is on the vendor's cloud`).toMatch(/^Vendor cloud [(]/);
    }
    expect(String(fb.device.IPAddress), `${label}: B the self-managed server is on our DMZ`).toMatch(/^\d+\.\d+\.100\.\d+$/);
    expect(String(fb.device.Site), `${label}: B the server is on our site`).not.toMatch(/^Vendor cloud/);
    expect(fa.device.IPAddress, `${label}: the two hosted services have different addresses`).not.toBe(fa.secondDevice.IPAddress);
    // A: vendor-hosted. DeviceInfo says so (not managed, reserved tenant host) and Tickets holds the subscription agreement, no installation record.
    expect(flag(fa.device.IsManaged), `${label}: A not managed by IT`).toBe(false);
    expect(String(fa.device.Role), `${label}: A role says vendor-hosted with a reserved tenant host`).toMatch(/vendor-hosted at tenant-\d+\.[a-z-]+\.example/);
    expect(reserved(fa.device.Role), `${label}: A tenant host is a reserved name`).toBe(true);
    expect([fa.subscription.length, fa.installation.length], `${label}: A subscription, no installation record`).toEqual([1, 0]);
    expect(String(fa.subscription[0].Details), `${label}: A the vendor installs the fixes`).toContain('installs all updates and security fixes on its own platform');
    expect(fa.subscription[0].Status, `${label}: A subscription is in force`).toBe('Approved');
    expect(a.case.findings[0].truth, `${label}: A transfers`).toMatchObject({ decision: 'transfer', schedule: 'none', slaLatest: 'none', reasons: ['vendor-responsibility'] });
    expect(a.case.findings[0].truth.alsoAccept ?? [], `${label}: A accepts only transfer`).toEqual([]);
    expect(a.case.findings[0].truth.mitigation, `${label}: A names no control`).toBeUndefined();
    // B: installed and run by IT. DeviceInfo says so (managed, an operating system), Tickets holds the installation record, no subscription.
    expect(flag(fb.device.IsManaged), `${label}: B managed by IT`).toBe(true);
    expect(String(fb.device.Role), `${label}: B role says installed and operated by IT`).toContain('installed and operated by IT');
    expect(reserved(fb.device.Role), `${label}: B has no vendor tenant host`).toBe(false);
    expect([fb.subscription.length, fb.installation.length], `${label}: B installation record, no subscription`).toEqual([0, 1]);
    expect(String(fb.installation[0].Details), `${label}: B IT runs it and applies the updates`).toContain('runs it and applies its updates');
    expect(b.case.findings[0].truth, `${label}: B patches by emergency change`).toMatchObject({ decision: 'patch', schedule: 'emergency', slaLatest: 'emergency' });
    expect(b.case.findings[0].truth.reasons, `${label}: B reasons`).toEqual(['sla-deadline', 'internet-exposed']);
    expect(b.case.findings[0].truth.contradicting, `${label}: B vendor-responsibility is wrong`).toContain('vendor-responsibility');
    expect(b.case.findings[0].truth.alsoAccept ?? [], `${label}: B accepts only patch`).toEqual([]);
    // Below the headline both twins are the same: a patch on the contract host (next window), a transfer of the second hosted service.
    expect(a.case.findings[1].truth, `${label}: the contract decoy is a patch in the next window`).toMatchObject({ decision: 'patch', schedule: 'next-window', slaLatest: 'next-window' });
    expect(a.case.findings[2].truth, `${label}: the second hosted service is a transfer`).toMatchObject({ decision: 'transfer', schedule: 'none', reasons: ['vendor-responsibility'] });
    const below = (s: VulnScenario) => JSON.stringify(s.case.findings.slice(1).map((f) => f.truth));
    expect(below(a), `${label}: same truths below the headline`).toBe(below(b));
  },
  extra: ({ a, b, label }) => {
    for (const s of [a, b]) {
      expect(Number(headRow(s).CvssBase), `${label}: Critical`).toBeGreaterThanOrEqual(9);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeGreaterThanOrEqual(4);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeLessThanOrEqual(6);
      const scheduled = s.case.findings.filter((f) => f.truth.schedule === 'emergency' || f.truth.schedule === 'next-window').length;
      expect(scheduled, `${label}: ${s.case.templateId} emergency and next-window changes fit the capacity`).toBeLessThanOrEqual(s.case.constraints.capacityPerWindow);
      // The policy states the vendor-operated rule, with the written-permission limit, in both twins.
      const row = (s.case.attachments.find((x) => x.title.includes('remediation standard'))!.body as [string, string][]).find(([k]) => k === 'Vendor-operated service')!;
      expect(row, `${label}: the policy has the vendor-operated service row`).toBeDefined();
      expect(row[1], `${label}: the row forbids testing the vendor's systems without written permission`).toContain("Do not scan or test the vendor's systems without the vendor's written permission");
      // Nothing in the scan store is an active scan of a vendor system: the external run has rows only on the organisation's own public hostnames.
      const ext = rows(s.corpus, 'ScanRuns').find((r) => r.Vantage === 'External')!;
      const devices = new Map(rows(s.corpus, 'DeviceInfo').map((d) => [String(d.DeviceName), d]));
      for (const r of rows(s.corpus, 'VulnFindings').filter((x) => x.ScanRunId === ext.ScanRunId)) expect(flag(devices.get(String(r.DeviceName))!.ExposedToInternet), `${label}: ${String(r.DeviceName)} is a public hostname`).toBe(true);
      expect(Number(ext.TargetsScanned), `${label}: the external run is partial`).toBeLessThan(Number(ext.TargetsPlanned));
    }
    expect(headIntel(a), `${label}: same intel`).toBe(headIntel(b));
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
    expect(b.case.tiers[0], `${label}: B tiers the headline first`).toContain(b.case.findings[0].findingId);
    expect(a.case.tiers.flat(), `${label}: A leaves the transferred headline out`).not.toContain(a.case.findings[0].findingId);
    expect(a.case.tiers.flat(), `${label}: A leaves the transferred second service out`).not.toContain(a.case.findings[2].findingId);
  },
};

// ---- T11: vm-unused-service / vm-needed-service ----------------------------------------------------------
// The same High remote code execution flaw in the optional scripting console of the application on APP01. A: the owner confirms in Tickets that
// nothing uses it and FirewallLogs show only the scanner on its port (the export job goes to the API port): avoid, with patch not accepted.
// B: the same job reaches the console port at the same times and Tickets holds the process record: patch. The installation record, SoftwareInventory,
// the scanner's connections and the other two consoles (an unused one: avoid; a used one: patch) are identical in both twins.

function unusedFacts(s: VulnScenario) {
  const head = headRow(s);
  const device = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!;
  const consolePort = Number(head.Port);
  const fw = rows(s.corpus, 'FirewallLogs');
  const toHost = fw.filter((f) => f.DestinationIP === device.IPAddress);
  const scanner = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'SCAN01')!;
  const job = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'BUILD01')!;
  const scannerRows = toHost.filter((f) => f.SourceIP === scanner.IPAddress);
  const jobRows = toHost.filter((f) => f.SourceIP === job.IPAddress);
  const tickets = rows(s.corpus, 'Tickets').filter((t) => t.Scope === head.DeviceName);
  const ownerConfirmation = tickets.filter((t) => String(t.Title).startsWith('Owner confirmation'));
  const processRecord = tickets.filter((t) => String(t.Title).startsWith('Process record'));
  const installRecord = tickets.filter((t) => String(t.Title).startsWith('Installation record'));
  const components = rows(s.corpus, 'SoftwareInventory').filter((x) => x.DeviceName === head.DeviceName && String(x.Product).endsWith('(optional component)'));
  const earliest = Math.min(...fw.map((f) => Date.parse(String(f.TimeGenerated))));
  return { head, device, consolePort, toHost, scannerRows, jobRows, ownerConfirmation, processRecord, installRecord, components, earliest };
}

const T11: PairRow = {
  pair: 'T11',
  a: 'vm-unused-service',
  b: 'vm-needed-service',
  lesson: { a: ['FirewallLogs', 'no session', 'Tickets', 'owner', 'SoftwareInventory', 'optional', 'avoid', 'patch'], b: ['FirewallLogs', 'regular sessions', 'Tickets', 'process record', 'installed by default', 'patch'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [unusedFacts(a), unusedFacts(b)];
    const now = Date.parse(a.now);
    for (const [name, f] of [['A', fa], ['B', fb]] as const) {
      // Both: a banner finding on the console port; the console is an optional component in SoftwareInventory; the installation record says default options;
      // the scanner's own connections to the console port; four sessions from the export job a few days apart; the firewall log reaches back 13 days or more.
      expect(f.consolePort, `${label}: ${name} console port`).toBe(8443);
      expect(String(f.head.Evidence), `${label}: ${name} banner`).toContain('banner only');
      expect(f.components.length, `${label}: ${name} the console is its own optional component in SoftwareInventory`).toBe(1);
      expect([f.installRecord.length, String(f.installRecord[0]?.Details).includes('default options')], `${label}: ${name} installation record`).toEqual([1, true]);
      expect(f.scannerRows.length, `${label}: ${name} two connections from the scanner`).toBe(2);
      expect(f.scannerRows.every((r) => Number(r.DestinationPort) === f.consolePort && r.RuleName === 'allow-scanner' && Number(r.BytesSent) < 400), `${label}: ${name} short scanner connections to the console port`).toBe(true);
      expect(f.jobRows.length, `${label}: ${name} four job sessions`).toBe(4);
      const days = f.jobRows.map((r) => (now - Date.parse(String(r.TimeGenerated))) / DAY_MS).sort((x, y) => y - x);
      expect(days[0], `${label}: ${name} the first job session is 13 days back`).toBeGreaterThanOrEqual(13);
      expect(days[0] - days[3], `${label}: ${name} the sessions span over 9 days`).toBeGreaterThan(9);
      for (let i = 1; i < 4; i++) expect(days[i - 1] - days[i], `${label}: ${name} sessions 3 to 4 days apart`).toBeGreaterThanOrEqual(2.9);
      expect(now - f.earliest, `${label}: ${name} the firewall log reaches back 13 days or more (over twice the 3 to 4 day cycle)`).toBeGreaterThanOrEqual(13 * DAY_MS);
      expect(String((f.ownerConfirmation[0] ?? f.processRecord[0]).Details), `${label}: ${name} the owner documents the cycle`).toContain('3 to 4 days');
    }
    // The banner-only Medium on the build server: the flaw was published before the credentialed run that reached the host and did not report it,
    // and the console hosts' ports saw only the scanner's own short connections from that older run (the log covers it).
    for (const s of [a, b]) {
      const old = rows(s.corpus, 'ScanRuns').find((r) => r.Method === 'Credentialed')!;
      const f4 = findingRow(s, 3);
      const pub = Date.parse(String(rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === f4.VulnId)!.Published));
      expect(pub, `${label}: ${s.case.templateId} the banner-only Medium was published before the credentialed run`).toBeLessThan(Date.parse(String(old.Started)));
      const scanIp = String(rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'SCAN01')!.IPAddress);
      for (const host of [findingRow(s, 1).DeviceName, findingRow(s, 2).DeviceName]) {
        const ip = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === host)!.IPAddress;
        const toConsole = rows(s.corpus, 'FirewallLogs').filter((x) => x.DestinationIP === ip && Number(x.DestinationPort) === 8443 && x.SourceIP === scanIp && x.RuleName === 'allow-scanner');
        expect(toConsole.length, `${label}: ${s.case.templateId} the older run's own connection to ${String(host)}`).toBe(1);
      }
    }
    const keyOf = (f: ReturnType<typeof unusedFacts>) => f.jobRows.map((r) => `${String(r.TimeGenerated)}|${String(r.SourceIP)}|${String(r.SourcePort)}|${Number(r.BytesSent)}`).sort();
    expect(keyOf(fa), `${label}: the job's sessions are the same in both twins but for the port`).toEqual(keyOf(fb));
    expect(fa.installRecord[0].Details, `${label}: same installation record`).toBe(fb.installRecord[0].Details);
    // A: only the owner confirmation; nothing but the scanner on the console port; the job goes to the API port; avoid, patch not accepted.
    expect([fa.ownerConfirmation.length, fa.processRecord.length], `${label}: A owner confirmation, no process record`).toEqual([1, 0]);
    expect(String(fa.ownerConfirmation[0].Details), `${label}: A nobody uses the console`).toContain('no business process uses');
    expect(fa.toHost.filter((f) => Number(f.DestinationPort) === fa.consolePort && !fa.scannerRows.includes(f)).length, `${label}: A no session to the console port but the scanner's`).toBe(0);
    expect(fa.jobRows.every((r) => Number(r.DestinationPort) === 443 && r.RuleName === 'allow-app-api'), `${label}: A the job goes to the API port`).toBe(true);
    expect(a.case.findings[0].truth, `${label}: A avoids in the next window`).toMatchObject({ decision: 'avoid', schedule: 'next-window', slaLatest: 'next-window', reasons: ['unused-component'] });
    expect(a.case.findings[0].truth.alsoAccept ?? [], `${label}: A patch is not accepted (avoid -> patch is a near miss and a lesson finding needs full credit)`).toEqual([]);
    expect(a.case.findings[0].truth.contradicting, `${label}: A`).not.toContain('unused-component');
    // B: the process record; the job on the console port; patch, avoid not accepted.
    expect([fb.ownerConfirmation.length, fb.processRecord.length], `${label}: B process record, no owner confirmation`).toEqual([0, 1]);
    expect(String(fb.processRecord[0].Details), `${label}: B a named business process depends on the console`).toContain('the finance team relies on the export');
    expect(fb.jobRows.every((r) => Number(r.DestinationPort) === fb.consolePort && r.RuleName === 'allow-app-admin'), `${label}: B the job goes to the console port`).toBe(true);
    expect(b.case.findings[0].truth, `${label}: B patches in the next window`).toMatchObject({ decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'] });
    expect(b.case.findings[0].truth.alsoAccept ?? [], `${label}: B avoid is not accepted`).toEqual([]);
    expect(b.case.findings[0].truth.contradicting, `${label}: B unused-component is wrong`).toContain('unused-component');
    // Below the headline both twins are the same: a second unused console (avoid, standard cycle) and a used one (patch, next window).
    expect(a.case.findings[1].truth, `${label}: the second unused console is an avoid`).toMatchObject({ decision: 'avoid', schedule: 'standard-cycle', slaLatest: 'standard-cycle' });
    expect(a.case.findings[2].truth, `${label}: the used console is a patch`).toMatchObject({ decision: 'patch', schedule: 'next-window' });
    expect(a.case.findings[3].truth, `${label}: the banner-only Medium on the build server is a false positive (the same in both twins)`).toMatchObject({ decision: 'false-positive', schedule: 'none', reasons: ['banner-only'] });
    const below = (s: VulnScenario) => JSON.stringify(s.case.findings.slice(1).map((f) => f.truth));
    expect(below(a), `${label}: same truths below the headline`).toBe(below(b));
  },
  extra: ({ a, b, label }) => {
    for (const s of [a, b]) {
      expect(Number(headRow(s).CvssBase), `${label}: High`).toBeGreaterThanOrEqual(7);
      expect(Number(headRow(s).CvssBase), `${label}: High`).toBeLessThan(9);
      expect(String(headRow(s).Title), `${label}: remote code execution in the console`).toMatch(/^Remote code execution in .* scripting console$/);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeGreaterThanOrEqual(4);
      expect(s.case.findings.length, `${label}: tier 1 size`).toBeLessThanOrEqual(6);
      const scheduled = s.case.findings.filter((f) => f.truth.schedule === 'emergency' || f.truth.schedule === 'next-window').length;
      expect(scheduled, `${label}: ${s.case.templateId} emergency and next-window changes fit the capacity`).toBeLessThanOrEqual(s.case.constraints.capacityPerWindow);
      // The policy states what unused means (owner confirmation, the scanner's own connections, a log period of twice the cycle) and that default is not unused.
      const row = (s.case.attachments.find((x) => x.title.includes('remediation standard'))!.body as [string, string][]).find(([k]) => k === 'Unused component')!;
      expect(row, `${label}: the policy has the unused component row`).toBeDefined();
      for (const phrase of ['avoid', 'confirms in Tickets', 'other than connections from the vulnerability scanner itself', 'at least twice as long as the longest cycle', 'installed by default']) expect(row[1], `${label}: the row says "${phrase}"`).toContain(phrase);
      expect(s.case.tiers.flat(), `${label}: the avoid findings are ranked (a change is scheduled)`).toContain(s.case.findings[0].findingId);
    }
    expect(headIntel(a), `${label}: same intel`).toBe(headIntel(b));
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
  },
};

// ---- T10 with T9 inside: vm-dup-plugins / vm-distinct (tier 3) -------------------------------------------------
// One application server reports the same flaw in a shared transport library six times: the package-level finding (credentialed run) and one
// detection per service (the unauthenticated sweep, banner only). The headline is the portal's detection on 443/tcp. A: SoftwareInventory says
// the portal links the system package (duplicate, closed with duplicate-root-cause); B: it bundles its own copy (patch). Two more services link
// the system package (duplicates in both twins) and two bundle their own copies (patches in both twins). T9 inside both: a Medium on the
// payments database against a Critical on an isolated developer test server; the template-local Asset tier row moves each deadline one class.

const LIB = 'Skerrimoor Secure Transport Library';
const LIB_PORTS = [443, 8443, 636, 465, 8883]; // the services, in worklist order after the package-level finding

function tier3Facts(s: VulnScenario) {
  const head = headRow(s);
  const lib = rows(s.corpus, 'VulnFindings').filter((r) => r.VulnId === head.VulnId && r.DeviceName === head.DeviceName);
  const runs = rows(s.corpus, 'ScanRuns');
  const inv = rows(s.corpus, 'SoftwareInventory').filter((x) => x.DeviceName === head.DeviceName && String(x.Product).startsWith(LIB));
  const system = inv.filter((x) => String(x.Product).endsWith('(system package)'));
  const usage = (port: number) => inv.filter((x) => String(x.Product).includes(', ') && String(x.Product).includes(` ${port}/tcp)`));
  const policy = s.case.attachments.find((x) => x.title.includes('remediation standard'))!.body as [string, string][];
  const intel = rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === head.VulnId)!;
  return { head, lib, runs, inv, system, usage, policy, intel };
}

// The worklist findings (case entry, place in the worklist and scan row) on a host.
function onHost(s: VulnScenario, host: string) {
  const all = rows(s.corpus, 'VulnFindings');
  return s.case.findings.map((f, i) => ({ f, i, row: all.find((r) => r.RecordId === f.recordId)! })).filter((x) => x.row.DeviceName === host);
}
const deviceOf = (s: VulnScenario, name: string) => rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === name)!;

const T10: PairRow = {
  pair: 'T10',
  a: 'vm-dup-plugins',
  b: 'vm-distinct',
  lesson: { a: ['SoftwareInventory', 'system package', 'package-level finding', 'duplicate-root-cause', 'restart', 'DeviceInfo', 'payments database'], b: ['SoftwareInventory', 'bundled copy', 'not a duplicate', 'own update', 'DeviceInfo', 'payments database'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [tier3Facts(a), tier3Facts(b)];
    for (const [name, f] of [['A', fa], ['B', fb]] as const) {
      // Both: six rows of one vulnerability on the headline host: the package-level one from the credentialed run, five per-service banner rows from the sweep.
      expect(f.lib.length, `${label}: ${name} six detections of the flaw on the host`).toBe(6);
      const pkg = f.lib.filter((r) => r.Port === null || r.Port === '');
      const svc = f.lib.filter((r) => r.Port !== null && r.Port !== '');
      expect(pkg.length, `${label}: ${name} one package-level finding`).toBe(1);
      expect(svc.map((r) => Number(r.Port)).sort((x, y) => x - y), `${label}: ${name} one detection per service port`).toEqual([...LIB_PORTS].sort((x, y) => x - y));
      const cred = f.runs.find((r) => r.Method === 'Credentialed')!;
      const sweep = f.runs.find((r) => r.Method === 'Unauthenticated')!;
      expect(pkg[0].ScanRunId, `${label}: ${name} the package-level finding is from the credentialed run`).toBe(cred.ScanRunId);
      expect([...new Set(svc.map((r) => r.ScanRunId))], `${label}: ${name} the service rows are from the sweep`).toEqual([sweep.ScanRunId]);
      expect(String(pkg[0].Evidence), `${label}: ${name} the package-level row is a credentialed local check`).toMatch(/^Credentialed local check/);
      for (const r of svc) expect(String(r.Evidence), `${label}: ${name} a service row is a remote check, which cannot show where the copy comes from`).toContain('origin of the service');
      expect(new Set(f.lib.map((r) => r.DetectedVersion)).size, `${label}: ${name} the same version on every row`).toBe(1);
      expect(Number(f.head.Port), `${label}: ${name} the headline is the portal on 443`).toBe(443);
      expect(flag(f.intel.VendorFix) && !flag(f.intel.KnownExploited) && !flag(f.intel.PublicExploit), `${label}: ${name} fixable, no exploitation signal`).toBe(true);
      expect(Number(f.head.CvssBase), `${label}: ${name} a Medium`).toBeLessThan(7);
      // Both: SoftwareInventory has the system package and one usage row per service; the version is the one the scanner read everywhere.
      expect(f.system.length, `${label}: ${name} one system package row`).toBe(1);
      expect([f.system[0].PackageSource, f.system[0].Vendor, f.system[0].Version], `${label}: ${name} system package`).toEqual(['distro', 'Skerrimoor Labs', f.head.DetectedVersion]);
      for (const port of LIB_PORTS) expect(f.usage(port).length, `${label}: ${name} one usage row for ${port}/tcp`).toBe(1);
      for (const port of [8443, 636]) {
        const u = f.usage(port)[0];
        expect([String(u.Product).includes('linked by'), u.PackageSource, u.Vendor], `${label}: ${name} ${port}/tcp links the system package`).toEqual([true, 'distro', 'Skerrimoor Labs']);
      }
      for (const port of [465, 8883]) {
        const u = f.usage(port)[0];
        expect([String(u.Product).includes('bundled with'), u.PackageSource], `${label}: ${name} ${port}/tcp bundles its own copy`).toEqual([true, 'vendor']);
        expect(String(u.Vendor), `${label}: ${name} the bundled copy has its own vendor`).not.toBe('Skerrimoor Labs');
      }
      // Below the headline the twins agree: the package-level finding is a patch, two linked services are duplicates, two bundled ones are patches.
      const [pkgT, l1, l2, b1, b2] = (name === 'A' ? a : b).case.findings.map((x) => x.truth).slice(1, 6);
      expect(pkgT, `${label}: ${name} the package-level finding is a patch in the standard cycle`).toMatchObject({ decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle' });
      expect(pkgT.reasons, `${label}: ${name} package-level reasons`).toEqual(['credentialed-confirmed', 'low-exploitability']);
      for (const x of [l1, l2]) expect(x, `${label}: ${name} a linked service is a duplicate`).toMatchObject({ decision: 'false-positive', schedule: 'none', reasons: ['duplicate-root-cause'] });
      for (const x of [b1, b2]) {
        expect(x, `${label}: ${name} a bundled copy is a patch`).toMatchObject({ decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle' });
        expect(x.contradicting, `${label}: ${name} duplicate-root-cause is wrong on a bundled copy`).toContain('duplicate-root-cause');
      }
      // The policy states the duplicate rule (honest wording, bundled copies first, restart) and the asset tier row (deadline, not class), in both twins.
      const dupRow = f.policy.find(([k]) => k === 'Duplicate detections')?.[1] ?? '';
      for (const phrase of ['SoftwareInventory', 'bundles with itself', 'separate component with its own fix', 'false-positive with the reason duplicate-root-cause', 'it is not a claim that the vulnerability is absent', 'is real and is fixed once, on the package-level finding', 'restart every service', 'keeps the old library in memory'])
        expect(dupRow, `${label}: ${name} the duplicate row says "${phrase}"`).toContain(phrase);
      const tier = f.policy.find(([k]) => k === 'Asset tier')?.[1] ?? '';
      for (const phrase of ['never changes the severity class', 'holds payment or customer data', 'a Medium in 30 days', 'a Critical in 30 days', 'isolated non-production host', 'Every other host follows the table'])
        expect(tier, `${label}: ${name} the asset tier row says "${phrase}"`).toContain(phrase);
      expect(f.policy.map(([k]) => k), `${label}: ${name} the severity class row stands`).toContain('Severity class');
    }
    // The twins differ in the portal's usage row and the headline's truth only.
    const portal = (f: ReturnType<typeof tier3Facts>) => f.usage(443)[0];
    expect(String(portal(fa).Product), `${label}: A the portal links the system package`).toContain('linked by');
    expect([portal(fa).PackageSource, portal(fa).Vendor], `${label}: A the portal has no copy of its own`).toEqual(['distro', 'Skerrimoor Labs']);
    // Every other library row of the host (the system package and the four other usage rows, all columns) is identical in the twins.
    const others = (f: ReturnType<typeof tier3Facts>) => f.inv.filter((x) => x !== portal(f)).map(({ RecordId: _r, ...rest }) => JSON.stringify(rest)).sort();
    expect(others(fa).length, `${label}: five library rows besides the portal's`).toBe(5);
    expect(others(fa), `${label}: the library rows besides the portal's are identical in the twins`).toEqual(others(fb));
    expect(String(portal(fb).Product), `${label}: B the portal bundles its own copy`).toContain('bundled with');
    expect(portal(fb).PackageSource, `${label}: B the portal's copy is the vendor's`).toBe('vendor');
    expect(String(portal(fb).Vendor), `${label}: B the portal's copy has its own vendor`).not.toBe('Skerrimoor Labs');
    expect(a.case.findings[0].truth, `${label}: A closes the portal detection as a duplicate`).toMatchObject({ decision: 'false-positive', schedule: 'none', reasons: ['duplicate-root-cause'] });
    expect(a.case.findings[0].truth.alsoAccept ?? [], `${label}: A accepts only the duplicate closure`).toEqual([]);
    expect(b.case.findings[0].truth, `${label}: B patches the portal`).toMatchObject({ decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'] });
    expect(b.case.findings[0].truth.contradicting, `${label}: B duplicate-root-cause is wrong`).toContain('duplicate-root-cause');
    expect(b.case.findings[0].truth.alsoAccept ?? [], `${label}: B accepts only patch`).toEqual([]);
    const below = (s: VulnScenario) => JSON.stringify(s.case.findings.slice(1).map((x) => x.truth));
    expect(below(a), `${label}: same truths below the headline`).toBe(below(b));
    // The lesson findings are every finding the lesson names (tier 3 lifts the 1-3 guidance of DESIGN 5.8; tier3.test.ts probes each): the portal detection,
    // the package-level finding, the mail relay's and the chat service's bundled copies (closing every per-service detection as a duplicate fails them), the
    // payments finding, the developer test server's Critical and the old-run High that only a rollup touched.
    for (const s of [a, b]) {
      expect(s.case.findings.filter((x) => x.lesson).length, `${label}: ${s.case.templateId} seven lesson findings`).toBe(7);
      expect(s.case.findings.filter((x) => x.lesson).map((x) => s.case.findings.indexOf(x)), `${label}: ${s.case.templateId} the lesson findings`).toEqual([0, 1, 4, 5, 6, 7, 10]);
    }
  },
  extra: ({ a, b, label }) => {
    const sorted = (s: VulnScenario) => [...s.case.constraints.windows].sort((x, y) => x.start - y.start);
    for (const s of [a, b]) {
      const id = s.case.templateId;
      const k = s.case.constraints;
      const [next, cycle] = sorted(s);
      // Tier 3 (DESIGN 2.3): 15 to 25 findings across two runs, one partial; the case difficulty is tier3.
      expect(byId(id).difficulty, `${label}: ${id} tier 3`).toBe('tier3');
      expect(s.case.findings.length, `${label}: ${id} 15 to 25 findings`).toBeGreaterThanOrEqual(15);
      expect(s.case.findings.length, `${label}: ${id} 15 to 25 findings`).toBeLessThanOrEqual(25);
      const runs = rows(s.corpus, 'ScanRuns');
      expect(runs.length, `${label}: ${id} two scan runs`).toBe(2);
      const [older, newer] = [...runs].sort((x, y) => Date.parse(String(x.Started)) - Date.parse(String(y.Started)));
      expect([older.Method, newer.Method], `${label}: ${id} an older credentialed run and a newer unauthenticated sweep`).toEqual(['Credentialed', 'Unauthenticated']);
      expect(runs.some((r) => Number(r.TargetsScanned) < Number(r.TargetsPlanned) || Number(r.AuthFailures) > 0), `${label}: ${id} one run is partial or has login failures`).toBe(true);
      expect(Number(newer.TargetsScanned), `${label}: ${id} the sweep did not reach every target`).toBeLessThan(Number(newer.TargetsPlanned));
      const all = rows(s.corpus, 'VulnFindings');
      const wl = s.case.findings.map((f) => ({ f, row: all.find((r) => r.RecordId === f.recordId)! }));
      expect(new Set(wl.map((x) => x.row.ScanRunId)), `${label}: ${id} worklist rows from both runs`).toEqual(new Set([older.ScanRunId, newer.ScanRunId]));

      // Stale versus fresh: the finding whose truth is stale-scan is from the older run, its host was updated after that run started, and the sweep has no row for it;
      // the host's other finding is a different product that the update did not touch (still real); the other old-run host's update is only a rollup (still real).
      const stale = wl.filter((x) => x.f.truth.reasons.includes('stale-scan'));
      expect(stale.length, `${label}: ${id} one stale finding`).toBe(1);
      const host = String(stale[0].row.DeviceName);
      expect(stale[0].f.truth.decision, `${label}: ${id} the stale finding is closed`).toBe('false-positive');
      expect(stale[0].row.ScanRunId, `${label}: ${id} the stale finding is from the older run`).toBe(older.ScanRunId);
      expect(all.filter((r) => r.DeviceName === host && r.ScanRunId === newer.ScanRunId).length, `${label}: ${id} the sweep did not re-test ${host}`).toBe(0);
      const patches = rows(s.corpus, 'PatchHistory').filter((p) => p.DeviceName === host && String(p.Description).includes(String(stale[0].row.VulnId)));
      expect(patches.length, `${label}: ${id} one update names the stale finding's vulnerability`).toBe(1);
      expect(Date.parse(String(patches[0].InstalledOn)), `${label}: ${id} the update is after the older run started`).toBeGreaterThan(Date.parse(String(older.Started)));
      expect(flag(patches[0].RebootPending), `${label}: ${id} no reboot pending`).toBe(false);
      const sameHost = wl.filter((x) => x.row.DeviceName === host && x !== stale[0]);
      expect(sameHost.length, `${label}: ${id} the stale host has another real finding`).toBeGreaterThanOrEqual(1);
      for (const x of sameHost) expect(x.f.truth.decision, `${label}: ${id} still real`).toBe('patch');
      const rollupHost = wl.find((x) => x.f.evidence.some((e) => e.id === 'unrelated-rollup'))!;
      expect(rollupHost.f.truth.decision, `${label}: ${id} the rollup host is still vulnerable`).toBe('patch');
      expect(rows(s.corpus, 'PatchHistory').filter((p) => p.DeviceName === rollupHost.row.DeviceName).some((p) => /rollup/i.test(String(p.Description)) && Date.parse(String(p.InstalledOn)) > Date.parse(String(older.Started))), `${label}: ${id} a later rollup`).toBe(true);

      // T9 inside: the Medium on the payments database against the Critical on the isolated developer test server.
      const devices = rows(s.corpus, 'DeviceInfo');
      const payHost = String(devices.find((d) => /payment/i.test(String(d.Role)) && /production/.test(String(d.Role)))!.DeviceName);
      const devHost = String(devices.find((d) => /non-production/.test(String(d.Role)))!.DeviceName);
      const [pay, dev] = [onHost(s, payHost)[0], onHost(s, devHost)[0]];
      expect([deviceOf(s, payHost).Criticality, flag(deviceOf(s, payHost).ExposedToInternet)], `${label}: ${id} the payments database is High criticality`).toEqual(['High', false]);
      expect(String(deviceOf(s, payHost).Role), `${label}: ${id} the Role says payment data`).toMatch(/holds payment data/);
      expect([deviceOf(s, devHost).Criticality, flag(deviceOf(s, devHost).ExposedToInternet)], `${label}: ${id} the developer test server is Low and not exposed`).toEqual(['Low', false]);
      expect(String(deviceOf(s, devHost).Role), `${label}: ${id} the Role says isolated, no production data`).toMatch(/isolated, no production data/);
      expect(slaClassOf(Number(pay.row.CvssBase)), `${label}: ${id} the payments finding is a Medium (the class does not change)`).toBe('medium');
      expect(slaClassOf(Number(dev.row.CvssBase)), `${label}: ${id} the developer finding is a Critical (the class does not change)`).toBe('critical');
      expect(Number(pay.row.CvssBase), `${label}: ${id} the Critical outranks the Medium by score`).toBeLessThan(Number(dev.row.CvssBase));
      // Deadlines, derived here from the Asset tier row (Medium on payments as a High, Critical on the isolated host as a High), with a day or more of margin.
      const due = (first: unknown, days: number) => endOfDay(Date.parse(String(first)) + days * DAY_MS);
      const payDue = due(pay.row.FirstSeen, k.slaDays.high);
      const devDue = due(dev.row.FirstSeen, k.slaDays.high);
      expect(payDue - next.end, `${label}: ${id} the payments deadline is a day or more after the next window`).toBeGreaterThanOrEqual(DAY_MS);
      expect(cycle.end - payDue, `${label}: ${id} and a day or more before the standard cycle ends`).toBeGreaterThanOrEqual(DAY_MS);
      expect(devDue - cycle.end, `${label}: ${id} the developer deadline is a day or more after the standard cycle`).toBeGreaterThanOrEqual(DAY_MS);
      expect(devDue - payDue, `${label}: ${id} payments is due a day or more before the developer test server`).toBeGreaterThanOrEqual(DAY_MS);
      // ...and by the table alone the Critical would be due first (7 days against 90).
      expect(due(dev.row.FirstSeen, k.slaDays.critical), `${label}: ${id} by the table alone the Critical is due first`).toBeLessThan(due(pay.row.FirstSeen, k.slaDays.medium));
      expect(pay.f.truth, `${label}: ${id} payments: next window`).toMatchObject({ decision: 'patch', schedule: 'next-window', slaLatest: 'next-window' });
      expect(pay.f.truth.reasons, `${label}: ${id} payments reasons`).toEqual(expect.arrayContaining(['critical-asset', 'sensitive-data']));
      expect(pay.f.lesson, `${label}: ${id} the payments finding is a lesson finding`).toBe(true);
      expect(dev.f.truth, `${label}: ${id} developer test server: standard cycle`).toMatchObject({ decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle' });
      expect(dev.f.truth.contradicting, `${label}: ${id} critical-asset and sensitive-data are wrong on the developer test server`).toEqual(expect.arrayContaining(['critical-asset', 'sensitive-data']));
      // The order: payments first, in the tiers and in the ideal order.
      const tierOf = (fid: string) => s.case.tiers.findIndex((t) => t.includes(fid));
      expect(tierOf(pay.f.findingId), `${label}: ${id} payments is tiered`).toBeGreaterThanOrEqual(0);
      expect(tierOf(pay.f.findingId), `${label}: ${id} payments before the developer test server in the tiers`).toBeLessThan(tierOf(dev.f.findingId));
      expect(s.case.idealOrder.indexOf(pay.f.findingId), `${label}: ${id} payments before the developer test server in the ideal order`).toBeLessThan(s.case.idealOrder.indexOf(dev.f.findingId));
      // Sorting by the severity column gets the order wrong: the Critical comes first by score.
      const bySeverity = [...wl].sort((x, y) => Number(y.row.CvssBase) - Number(x.row.CvssBase)).map((x) => x.f.findingId);
      expect(bySeverity.indexOf(dev.f.findingId), `${label}: ${id} by severity the Critical is ahead of the Medium`).toBeLessThan(bySeverity.indexOf(pay.f.findingId));
      // The tiers follow the deadlines written in the policy (Sim-KEV override, asset tier row, SLA table) and nothing else: every deadline in a tier is
      // on or before every deadline in a later tier (round-1 review finding: a Medium due later was ranked ahead of Mediums due earlier).
      const deadlineOf = (x: (typeof wl)[number]): number => {
        const intel = rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === x.row.VulnId)!;
        if (flag(intel.KnownExploited)) return endOfDay(Math.max(Date.parse(String(x.row.FirstSeen)), Date.parse(String(intel.KnownExploitedAdded))) + 3 * DAY_MS);
        if (x.f.findingId === pay.f.findingId || x.f.findingId === dev.f.findingId) return due(x.row.FirstSeen, k.slaDays.high);
        return due(x.row.FirstSeen, k.slaDays[slaClassOf(Number(x.row.CvssBase))]);
      };
      const tiered = s.case.tiers.map((t) => t.map((fid) => deadlineOf(wl.find((x) => x.f.findingId === fid)!)));
      for (let i = 0; i + 1 < tiered.length; i++) expect(Math.max(...tiered[i]), `${label}: ${id} tier ${i + 1} is due on or before everything in tier ${i + 2}`).toBeLessThanOrEqual(Math.min(...tiered[i + 1]));

      // Capacity squeeze: the ideal answer fits the window, and patching everything at its SLA-table schedule does not.
      const scheduled = (x: VulnSchedule) => x === 'emergency' || x === 'next-window';
      expect(s.case.findings.filter((f) => scheduled(f.truth.schedule)).length, `${label}: ${id} the ideal answer uses the whole capacity and no more`).toBe(k.capacityPerWindow);
      const tableSchedule = (row: Record<string, unknown>): VulnSchedule => {
        const deadline = due(row.FirstSeen, k.slaDays[slaClassOf(Number(row.CvssBase))]);
        return deadline < next.end ? 'emergency' : deadline < cycle.end ? 'next-window' : 'standard-cycle';
      };
      const wanting = wl.filter((x) => scheduled(tableSchedule(x.row)));
      expect(wanting.length, `${label}: ${id} by the SLA table alone more findings want a change before the standard cycle than the window takes`).toBeGreaterThan(k.capacityPerWindow);
      const perfect = perfectVulnSubmission(s.case);
      expect(gradeVulnCase(s.case, perfect).overflow, `${label}: ${id} the ideal answer overflows nothing`).toEqual([]);
      const everything: VulnSubmission = {
        ...perfect,
        answers: Object.fromEntries(wl.map((x) => [x.f.findingId, { decision: 'patch', control: null, schedule: tableSchedule(x.row), reasons: [] }])) as VulnSubmission['answers'],
      };
      expect(gradeVulnCase(s.case, everything).overflow.length, `${label}: ${id} patching every finding at its SLA-table schedule overflows the window`).toBeGreaterThan(0);
      // The Sim-KEV Critical is the emergency (the one must-not-miss, in the first tier), the payments Medium the one next-window change.
      const mnm = s.case.findings.filter((f) => f.mustNotMiss);
      expect(mnm.length, `${label}: ${id} one must-not-miss`).toBe(1);
      expect(mnm[0].truth, `${label}: ${id} an emergency`).toMatchObject({ decision: 'patch', schedule: 'emergency', slaLatest: 'emergency' });
      expect(s.case.tiers[0], `${label}: ${id} tier 1 is the emergency and the payments finding`).toEqual([mnm[0].findingId, pay.f.findingId]);
      // Decoys and padding: one accepted risk with an approved exception, routine findings without an evidence point.
      expect(s.case.findings.filter((f) => f.truth.decision === 'accept').length, `${label}: ${id} one accepted risk`).toBe(1);
      expect(s.case.findings.filter((f) => f.evidence.length === 0).length, `${label}: ${id} routine findings without evidence`).toBeGreaterThanOrEqual(3);
    }
    expect(headIntel(a), `${label}: same intel`).toBe(headIntel(b));
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
    // The twins' ideal orders differ only by the portal's place (a standard-cycle Medium: tier 3 in B, untiered in A).
    expect(a.case.tiers.flat(), `${label}: A leaves the closed duplicate out`).not.toContain(a.case.findings[0].findingId);
    expect(b.case.tiers[2], `${label}: B ranks the portal's own update in tier 3`).toContain(b.case.findings[0].findingId);
    expect(byId('vm-dup-plugins').objectives, `${label}: objectives`).toEqual(['2.2', '2.3', '2.5', '4.1']);
  },
};

// ---- the batch -----------------------------------------------------------------------------------------

const PAIRS: readonly PairRow[] = [T6, T7, T8, T11, T10];

describe('batch B is registered', () => {
  it('lists every twin of the batch, both ways', () => {
    for (const r of PAIRS) {
      expect(byId(r.a).twin, `${r.pair}: A names B`).toBe(r.b);
      expect(byId(r.b).twin, `${r.pair}: B names A`).toBe(r.a);
    }
    expect(new Set(PAIRS.flatMap((r) => [r.a, r.b])).size, 'no template twice').toBe(PAIRS.length * 2);
    // All five pairs of WP3: T6, T7, T8, T11 and the tier-3 pair T10 (with T9's ordering pattern inside both).
    expect(PAIRS.map((r) => r.pair)).toEqual(['T6', 'T7', 'T8', 'T11', 'T10']);
    for (const id of ['vm-legacy-accept', 'vm-legacy-isolate', 'vm-noncred-low', 'vm-cred-high', 'vm-saas-transfer', 'vm-self-hosted', 'vm-unused-service', 'vm-needed-service', 'vm-dup-plugins', 'vm-distinct']) expect(PAIRS.flatMap((r) => [r.a, r.b]), `${id} is in the batch table`).toContain(id);
  });
});

it('registers tier-3 templates: the T10 pair, the only ones in the registry (human decision 2026-10-02: no separate T9 templates)', () => {
  const tier3 = VULN_CASE_TEMPLATES.filter((t) => t.difficulty === 'tier3').map((t) => t.id).sort();
  expect(tier3).toEqual(['vm-distinct', 'vm-dup-plugins']);
});

registerPairSuite('batch B', PAIRS);

