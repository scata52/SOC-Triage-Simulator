// Content batch A (WP2): the generic checks every twin pair of the batch must pass, written as a table keyed by
// twin pair. A later author adds a row to PAIRS (and the ids to the registered list, which it already derives from
// the rows); nothing else here changes. The checks, per pair, on the standard seeds:
//   - both twins are registered and name each other (tests/vuln-scenarios/slice.test.ts checks this for every pair too);
//   - same title, difficulty and headline row (VulnId, host, CVSS base, FirstSeen, DetectedVersion);
//   - the lesson findings differ by decision, by two or more schedule steps, or across the SLA (DESIGN 5.8);
//   - each twin's lesson text names its deciding clue (the table and the fact);
//   - the deciding clue is in the data on every run, A vs B;
//   - the pre-submit surface does not give the twin away: same briefing, attachments and hint 1, and the same
//     number of rows in every table (the T3 test in kev-internal.test.ts does the same for its pair).
import { describe, expect, it } from 'vitest';
import { environmentalScore, severityOf } from '../../src/core/vuln/cvss31.ts';
import type { FindingTruth } from '../../src/core/vuln/model.ts';
import type { VulnScenario } from '../../src/core/vuln/scenario.ts';
import { AUTH_FAILURE_TITLE } from '../../src/core/vuln/templates/common.ts';
import { byId, differsByRule3, flag, headRow, type PairRow, registerPairSuite, type Row, rows } from './pair-helpers.ts';

// ---- T4: vm-exposed-edge / vm-segmented ---------------------------------------------------------------

// The management-port sessions of the headline host, and the ACL rows that name its management interface.
function edgeFacts(s: VulnScenario) {
  const head = headRow(s);
  const device = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!;
  const sessions = rows(s.corpus, 'FirewallLogs').filter((f) => f.DestinationIP === device.IPAddress && Number(f.DestinationPort) === Number(head.Port));
  const acls = rows(s.corpus, 'ControlInventory').filter((c) => c.Kind === 'ACL' && String(c.Target).startsWith(`${String(head.DeviceName)} management interface`));
  return { head, device, sessions, acls };
}

const T4: PairRow = {
  pair: 'T4',
  a: 'vm-exposed-edge',
  b: 'vm-segmented',
  lesson: { a: ['DeviceInfo', 'ExposedToInternet', 'FirewallLogs', 'ControlInventory', 'detect'], b: ['ControlInventory', 'block', 'FirewallLogs', 'DeviceInfo', 'ExposedToInternet'] },
  clue: ({ a, b, label }) => {
    const ea = edgeFacts(a);
    const eb = edgeFacts(b);
    // A: exposed, internet sources allowed to the management port, the only ACL on the interface only detects and covers nothing.
    expect(flag(ea.device.ExposedToInternet), `${label}: A is exposed`).toBe(true);
    const inboundA = ea.sessions.filter((f) => f.Direction === 'Inbound');
    expect(inboundA.length, `${label}: A internet sessions`).toBeGreaterThanOrEqual(3);
    expect(inboundA.every((f) => f.Action === 'Allow'), `${label}: A internet sources are allowed`).toBe(true);
    expect(ea.acls.length, `${label}: A has an ACL row on the interface`).toBe(1);
    expect(ea.acls[0].Mode, `${label}: A ACL only detects`).toBe('detect');
    expect(String(ea.acls[0].CoversVulnId), `${label}: A ACL covers nothing`).toBe('');
    // B: not exposed, a block-mode ACL names the headline, internet sources denied, only the management VLAN allowed.
    expect(flag(eb.device.ExposedToInternet), `${label}: B is not exposed`).toBe(false);
    const inboundB = eb.sessions.filter((f) => f.Direction === 'Inbound');
    expect(inboundB.length, `${label}: B internet sessions`).toBe(inboundA.length);
    expect(inboundB.every((f) => f.Action === 'Deny'), `${label}: B internet sources are denied`).toBe(true);
    const allowedB = eb.sessions.filter((f) => f.Action === 'Allow');
    expect(allowedB.length, `${label}: B has management sessions`).toBeGreaterThanOrEqual(1);
    expect(allowedB.every((f) => /\.250\./.test(String(f.SourceIP))), `${label}: B only the management VLAN is allowed`).toBe(true);
    expect(eb.acls.length, `${label}: B has an ACL row on the interface`).toBe(1);
    expect(eb.acls[0].Mode, `${label}: B ACL blocks`).toBe('block');
    expect(String(eb.acls[0].CoversVulnId), `${label}: B ACL covers the headline`).toBe(String(eb.head.VulnId));
    expect(b.case.findings[0].truth.mitigation, `${label}: B mitigation names the ACL`).toEqual([String(eb.acls[0].ControlId)]);
    // Both: the same decoy controls (a detect-mode ACL naming another finding, an enforcing ACL on another port).
    const decoys = (s: VulnScenario) => rows(s.corpus, 'ControlInventory').filter((c) => !String(c.Target).includes('management interface')).map(({ RecordId: _r, ...rest }) => JSON.stringify(rest)).sort();
    expect(decoys(a), `${label}: same decoy controls`).toEqual(decoys(b));
    expect(decoys(a).length, `${label}: two decoys`).toBe(2);
    expect(rows(a.corpus, 'ControlInventory').some((c) => c.Mode === 'detect' && c.CoversVulnId !== '' && c.CoversVulnId !== ea.head.VulnId), `${label}: a detect-mode ACL names another finding`).toBe(true);
  },
  extra: ({ a, b, label }) => {
    // Base is not environmental: the 9.8 with a modified attack vector of Adjacent (MAV:A) scores 8.8, and the policy class stays Critical.
    const intel = rows(b.corpus, 'VulnIntel').find((r) => r.VulnId === headRow(b).VulnId)!;
    expect(Number(headRow(b).CvssBase), `${label}: base`).toBe(9.8);
    expect(environmentalScore(`${String(intel.CvssVector)}/MAV:A`), `${label}: environmental with MAV:A`).toBe(8.8);
    expect(severityOf(9.8), label).toBe('critical');
    expect(b.case.explanation.join(' '), `${label}: B explains the environmental score`).toContain('8.8');
    // The headline is not on Sim-KEV in either twin (a listing would put the twin on the 3-day clock) and the intel is identical.
    for (const s of [a, b]) expect(flag(rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === headRow(s).VulnId)!.KnownExploited), `${label}: not on Sim-KEV`).toBe(false);
    const norm = (s: VulnScenario) => JSON.stringify(rows(s.corpus, 'VulnIntel').filter((r) => r.VulnId === headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => rest));
    expect(norm(a), `${label}: same intel`).toBe(norm(b));
  },
};

// ---- T5: vm-waf-covers / vm-waf-bypass ----------------------------------------------------------------

// The headline's WAF rule, the WAF's own sessions to the headline host, and the headline host.
function wafFacts(s: VulnScenario) {
  const head = headRow(s);
  const device = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!;
  const rules = rows(s.corpus, 'ControlInventory').filter((c) => c.Kind === 'WAF' && c.CoversVulnId === head.VulnId);
  const sessions = rows(s.corpus, 'FirewallLogs').filter((f) => f.DestinationIP === device.IPAddress && Number(f.DestinationPort) === Number(head.Port));
  const attacks = sessions.filter((f) => rules.length === 1 && String(f.RuleName).startsWith(String(rules[0].ControlId)));
  return { head, device, rules, sessions, attacks };
}

const T5: PairRow = {
  pair: 'T5',
  a: 'vm-waf-covers',
  b: 'vm-waf-bypass',
  lesson: { a: ['ControlInventory', 'WAF', 'block', 'FirewallLogs'], b: ['ControlInventory', 'WAF', 'detect', 'FirewallLogs'] },
  clue: ({ a, b, label }) => {
    const [fa, fb] = [wafFacts(a), wafFacts(b)];
    // Both: the headline host is public, and one WAF rule names the headline (the same id, target and vulnerability).
    expect(flag(fa.device.ExposedToInternet) && flag(fb.device.ExposedToInternet), `${label}: the portal is exposed in both twins`).toBe(true);
    expect(fa.rules.length, `${label}: A has one WAF rule naming the headline`).toBe(1);
    expect(fb.rules.length, `${label}: B has one WAF rule naming the headline`).toBe(1);
    const same = ({ RecordId: _r, Mode: _m, Evidence: _e, ...rest }: Row) => JSON.stringify(rest);
    expect(same(fa.rules[0]), `${label}: the same rule id, target and vulnerability`).toBe(same(fb.rules[0]));
    // A: block mode, the WAF denied the four attack requests, the truth is mitigate with that rule.
    expect(fa.rules[0].Mode, `${label}: A rule blocks`).toBe('block');
    expect(fa.attacks.length, `${label}: A attack sessions`).toBe(4);
    expect(fa.attacks.every((f) => f.Action === 'Deny'), `${label}: A attack requests are denied`).toBe(true);
    expect(a.case.findings[0].truth.mitigation, `${label}: A mitigation names the rule`).toEqual([String(fa.rules[0].ControlId)]);
    // B: detect mode, the same requests allowed through, the truth is patch by emergency change with no covering control.
    expect(fb.rules[0].Mode, `${label}: B rule only detects`).toBe('detect');
    expect(fb.attacks.length, `${label}: B attack sessions`).toBe(4);
    expect(fb.attacks.every((f) => f.Action === 'Allow'), `${label}: B attack requests are allowed`).toBe(true);
    expect(b.case.findings[0].truth.mitigation, `${label}: B names no covering control`).toBeUndefined();
    expect(b.case.findings[0].truth.alsoAccept ?? [], `${label}: B does not accept avoid (the vulnerable page is a business process)`).not.toContain('avoid');
    // Both: the same decoys: a detect-mode WAF rule on another application naming another finding, and an enforcing MFA control.
    const decoys = (s: VulnScenario) => rows(s.corpus, 'ControlInventory').filter((c) => c.CoversVulnId !== headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => JSON.stringify(rest)).sort();
    expect(decoys(a), `${label}: same decoy controls`).toEqual(decoys(b));
    expect(rows(a.corpus, 'ControlInventory').some((c) => c.Kind === 'WAF' && c.Mode === 'detect' && c.CoversVulnId !== '' && c.CoversVulnId !== fa.head.VulnId), `${label}: a detect-mode WAF rule names another finding`).toBe(true);
    expect(rows(a.corpus, 'ControlInventory').some((c) => c.Kind === 'MFA' && c.Mode === 'block'), `${label}: an enforcing control that is not on the path`).toBe(true);
  },
  extra: ({ a, b, label }) => {
    // The calendar of both twins: a freeze in effect from the case date, the next window the first after it, the Critical
    // deadline before that window (one calendar for the pair).
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
    const k = a.case.constraints;
    const freeze = k.freezes![0];
    const next = [...k.windows].sort((x, y) => x.start - y.start)[0];
    expect(freeze.start, `${label}: the freeze is in effect from the case date`).toBeLessThanOrEqual(Date.parse(a.now));
    expect(freeze.end, `${label}: the freeze ends before the next window`).toBeLessThanOrEqual(next.start);
    expect(k.windows.every((w) => w.start >= freeze.end), `${label}: no window falls inside the freeze`).toBe(true);
    const deadline = Date.parse(String(headRow(a).FirstSeen)) + k.slaDays.critical * 86_400_000;
    expect(deadline, `${label}: the Critical deadline falls before the next window`).toBeLessThan(next.start);
    expect(a.case.findings[0].truth.schedule, `${label}: A permanent fix in the next window`).toBe('next-window');
    expect(b.case.findings[0].truth.schedule, `${label}: B emergency`).toBe('emergency');
    // Same intel (no Sim-KEV listing) in both twins.
    const norm = (s: VulnScenario) => JSON.stringify(rows(s.corpus, 'VulnIntel').filter((r) => r.VulnId === headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => rest));
    expect(norm(a), `${label}: same intel`).toBe(norm(b));
    expect(flag(rows(a.corpus, 'VulnIntel').find((r) => r.VulnId === headRow(a).VulnId)!.KnownExploited), `${label}: not on Sim-KEV`).toBe(false);
  },
};

// ---- T1: vm-backport-fp / vm-backport-real ------------------------------------------------------------

// The two web servers' rows: the web server in SoftwareInventory, the PatchHistory rows of the host, and those that name the headline.
// The headline host is findings[0]; its sibling is the host of findings[1] (the twins swap the two hosts' roles).
function backportFacts(s: VulnScenario, index: 0 | 1) {
  const head = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[index].recordId)!;
  const soft = rows(s.corpus, 'SoftwareInventory').filter((r) => r.DeviceName === head.DeviceName && r.Product === 'Dunmarrow httpd');
  const patches = rows(s.corpus, 'PatchHistory').filter((r) => r.DeviceName === head.DeviceName);
  const naming = patches.filter((r) => String(r.Description).includes(String(headRow(s).VulnId)));
  const run = rows(s.corpus, 'ScanRuns').find((r) => r.ScanRunId === head.ScanRunId)!;
  return { head, soft, patches, naming, run, truth: s.case.findings[index].truth };
}

const T1: PairRow = {
  pair: 'T1',
  a: 'vm-backport-fp',
  b: 'vm-backport-real',
  lesson: { a: ['SoftwareInventory', 'distro', 'PatchHistory', 'advisory'], b: ['SoftwareInventory', 'source-built', 'PatchHistory', 'advisory'] },
  clue: ({ a, b, label }) => {
    const [ah, as, bh, bs] = [backportFacts(a, 0), backportFacts(a, 1), backportFacts(b, 0), backportFacts(b, 1)];
    // Both: banner-only runs, the same two hosts, one web server row on each, the same banner version on the headline.
    for (const [name, f] of [['A head', ah], ['A sibling', as], ['B head', bh], ['B sibling', bs]] as const) {
      expect(f.run.Method, `${label}: ${name} banner-only`).toBe('Unauthenticated');
      expect(f.soft.length, `${label}: ${name} one web server row`).toBe(1);
    }
    expect([as.head.DeviceName, bs.head.DeviceName], `${label}: same sibling host`).toEqual([bs.head.DeviceName, as.head.DeviceName]);
    // A: the headline is the distro package at a release that carries the fix, with an advisory that names it (a false positive).
    expect(ah.soft[0].PackageSource, `${label}: A head distro package`).toBe('distro');
    expect(String(ah.soft[0].Version), `${label}: A head release suffix`).toMatch(/-[0-9]+\.dx54$/);
    expect(ah.naming.length, `${label}: A advisory names the headline`).toBe(1);
    expect(ah.truth.decision, `${label}: A dismisses`).toBe('false-positive');
    // A: the sibling is a distro package at an older release, no advisory (real).
    expect(as.soft[0].PackageSource, `${label}: A sibling distro`).toBe('distro');
    expect(as.naming.length, `${label}: no advisory names the headline on the A sibling`).toBe(0);
    expect(as.truth, `${label}: A sibling is a real emergency`).toMatchObject({ decision: 'patch', schedule: 'emergency' });
    // B: the headline is built from source at the banner version, no update names it (only an unrelated OS update), banner accurate.
    expect(bh.soft[0].PackageSource, `${label}: B head built from source`).toBe('source-built');
    expect(bh.soft[0].Version, `${label}: B installed version is the banner version`).toBe(bh.head.DetectedVersion);
    expect(bh.naming.length, `${label}: no advisory names the headline in B`).toBe(0);
    expect(bh.patches.length, `${label}: B head has the same number of update rows`).toBe(ah.patches.length);
    expect(bh.patches.every((r) => !/Dunmarrow/.test(String(r.Description))), `${label}: B head updates do not touch the web server`).toBe(true);
    expect(Date.parse(String(bh.soft[0].InstalledOn)), `${label}: B head built before first detection`).toBeLessThan(Date.parse(String(bh.head.FirstSeen)));
    expect(bh.truth.decision, `${label}: B patches`).toBe('patch');
    expect(bh.truth.contradicting, `${label}: backported-fix contradicts in B`).toContain('backported-fix');
    expect(bh.truth.reasons, `${label}: backported-fix is not a B reason`).not.toContain('backported-fix');
    const ev = b.case.findings[0].evidence.flatMap((e) => e.recordIds);
    expect(ev, `${label}: B evidence cites the inventory row`).toContain(String(bh.soft[0].RecordId));
    // B: the sibling is the distro package at the fixed release with the advisory (the false positive of A's headline).
    expect(bs.soft[0].PackageSource, `${label}: B sibling distro`).toBe('distro');
    expect(bs.naming.length, `${label}: advisory names the headline on the B sibling`).toBe(1);
    expect(bs.truth.decision, `${label}: B sibling dismissed`).toBe('false-positive');
    // Capacity: one false positive and one real emergency on the web servers in either twin, so the case fits two changes.
    for (const [s, f] of [[a, [ah, as]], [b, [bh, bs]]] as const) expect(f.filter((x) => x.truth.decision === 'patch').length, `${label}: ${s.case.templateId} real web servers`).toBe(1);
  },
  extra: ({ a, b, label }) => {
    // The headline is Critical on both and not on Sim-KEV in either twin; the intel is identical.
    for (const s of [a, b]) {
      expect(Number(headRow(s).CvssBase), `${label}: Critical`).toBeGreaterThanOrEqual(9);
      expect(flag(rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === headRow(s).VulnId)!.KnownExploited), `${label}: not on Sim-KEV`).toBe(false);
    }
    const norm = (s: VulnScenario) => JSON.stringify(rows(s.corpus, 'VulnIntel').filter((r) => r.VulnId === headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => rest));
    expect(norm(a), `${label}: same intel`).toBe(norm(b));
    expect(b.case.findings[0].truth.schedule, `${label}: B emergency`).toBe('emergency');
    expect(b.case.findings[0].truth.slaLatest, `${label}: B slaLatest`).toBe('emergency');
    // The same worklist (host and vulnerability of every row), and the same truths below the two web servers.
    const key = (s: VulnScenario) => s.case.findings.map((f) => { const r = rows(s.corpus, 'VulnFindings').find((x) => x.RecordId === f.recordId)!; return `${String(r.DeviceName)}|${String(r.VulnId)}`; });
    expect(key(b), `${label}: same worklist`).toEqual(key(a));
    expect(JSON.stringify(b.case.findings.slice(2).map((f) => f.truth)), `${label}: same truths below the web servers`).toBe(JSON.stringify(a.case.findings.slice(2).map((f) => f.truth)));
  },
};

// ---- T2: vm-stale-scan / vm-fresh-scan ----------------------------------------------------------------

// The two file servers: findings[0] is the headline host (FS01), findings[1] its sibling (FS02); the twins swap their roles.
// A host's update rows (the ones that name its vulnerability), the rows the newer run wrote there, and its old-run finding.
function fileServerFacts(s: VulnScenario, index: 0 | 1) {
  const finding = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[index].recordId)!;
  const host = finding.DeviceName;
  const oldRun = rows(s.corpus, 'ScanRuns').find((r) => r.ScanRunId === finding.ScanRunId)!;
  const patches = rows(s.corpus, 'PatchHistory').filter((r) => r.DeviceName === host);
  const naming = patches.filter((r) => String(r.Description).includes(String(finding.VulnId)));
  const newer = rows(s.corpus, 'VulnFindings').filter((r) => r.DeviceName === host && r.ScanRunId !== finding.ScanRunId);
  return { finding, host, oldRun, patches, naming, newer, truth: s.case.findings[index].truth };
}

const T2: PairRow = {
  pair: 'T2',
  a: 'vm-stale-scan',
  b: 'vm-fresh-scan',
  lesson: { a: ['PatchHistory', 'ScanRuns', 'Authentication failure', 'rollup'], b: ['PatchHistory', 'RebootPending', 'VulnFindings', 'Evidence', 'library'] },
  clue: ({ a, b, label }) => {
    const [ah, as, bh, bs] = [fileServerFacts(a, 0), fileServerFacts(a, 1), fileServerFacts(b, 0), fileServerFacts(b, 1)];
    expect([ah.host, as.host], `${label}: the two file servers`).toEqual([bh.host, bs.host]);
    const stale = (f: ReturnType<typeof fileServerFacts>, name: string) => {
      // updated after the old run started, no reboot pending, and the newer run's only row there is the visible login failure
      expect(f.naming.length, `${label}: ${name} one update names the vulnerability`).toBe(1);
      expect(Date.parse(String(f.naming[0].InstalledOn)), `${label}: ${name} updated after the old run started`).toBeGreaterThan(Date.parse(String(f.oldRun.Started)));
      expect(flag(f.naming[0].RebootPending), `${label}: ${name} no reboot pending`).toBe(false);
      expect(f.newer.map((r) => r.Title), `${label}: ${name} only the login failure`).toEqual([AUTH_FAILURE_TITLE]);
      expect(f.truth, `${label}: ${name} dismissed`).toMatchObject({ decision: 'false-positive', schedule: 'none' });
    };
    // A: the headline is stale; the sibling's later update is an unrelated rollup (no update names its vulnerability), a real finding.
    stale(ah, 'A head');
    expect(as.naming.length, `${label}: no update names the vulnerability on the A sibling`).toBe(0);
    expect(as.patches.some((r) => Date.parse(String(r.InstalledOn)) > Date.parse(String(as.oldRun.Started))), `${label}: the A sibling has a later update (the decoy)`).toBe(true);
    expect(as.newer, `${label}: the newer run wrote nothing on the A sibling`).toEqual([]);
    expect(as.truth, `${label}: A sibling is real`).toMatchObject({ decision: 'patch', schedule: 'next-window', slaLatest: 'next-window' });
    expect(String(ah.finding.Evidence), `${label}: A head evidence names no running library`).not.toMatch(/still has the old library/);
    // B: the headline's update went in BEFORE the old run but a reboot is pending, and the credentialed check's Evidence shows
    // the service still loading the old library; the newer run never touched the host. The sibling is the stale one.
    expect(bh.naming.length, `${label}: one update names the B headline vulnerability`).toBe(1);
    expect(Date.parse(String(bh.naming[0].InstalledOn)), `${label}: B head updated before the old run started`).toBeLessThan(Date.parse(String(bh.oldRun.Started)));
    expect(flag(bh.naming[0].RebootPending), `${label}: B head reboot pending`).toBe(true);
    expect(bh.naming[0].Result, `${label}: B head update installed`).toBe('Installed');
    expect(String(bh.finding.Evidence), `${label}: B head evidence shows the service still loading the old library`).toMatch(/still has the old library .* loaded/);
    expect(bh.finding.Port, `${label}: B head package-level`).toBeNull();
    expect(bh.newer, `${label}: the newer run did not test the B headline host`).toEqual([]);
    expect(bh.truth, `${label}: B head is real`).toMatchObject({ decision: 'patch', schedule: 'next-window', slaLatest: 'next-window' });
    expect(bh.truth.reasons, `${label}: pending-reboot is a B reason`).toContain('pending-reboot');
    expect(bh.truth.contradicting, `${label}: stale-scan contradicts in B`).toContain('stale-scan');
    expect(bh.truth.contradicting, `${label}: pending-reboot is not contradicting in B`).not.toContain('pending-reboot');
    const evB = b.case.findings[0].evidence.flatMap((e) => e.recordIds);
    expect(evB, `${label}: B evidence cites the update row and the finding row`).toEqual(expect.arrayContaining([String(bh.naming[0].RecordId), String(bh.finding.RecordId)]));
    stale(bs, 'B sibling');
    // Capacity: one false positive and one real next-window file-server finding in either twin.
    for (const [s, f] of [[a, [ah, as]], [b, [bh, bs]]] as const) expect(f.filter((x) => x.truth.decision === 'patch').length, `${label}: ${s.case.templateId} real file servers`).toBe(1);
  },
  extra: ({ a, b, label }) => {
    // The headline is a High on a file server, first seen 21 days ago, not on Sim-KEV; the intel is identical.
    for (const s of [a, b]) {
      const h = headRow(s);
      expect(Number(h.CvssBase), `${label}: High`).toBeGreaterThanOrEqual(7);
      expect(Number(h.CvssBase), `${label}: High`).toBeLessThan(9);
      expect(Math.round((Date.parse(s.now) - Date.parse(String(h.FirstSeen))) / 86_400_000), `${label}: first seen 21 days ago`).toBe(21);
      expect(flag(rows(s.corpus, 'VulnIntel').find((r) => r.VulnId === h.VulnId)!.KnownExploited), `${label}: not on Sim-KEV`).toBe(false);
    }
    const norm = (s: VulnScenario) => JSON.stringify(rows(s.corpus, 'VulnIntel').filter((r) => r.VulnId === headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => rest));
    expect(norm(a), `${label}: same intel`).toBe(norm(b));
    // The High deadline (30 days from first detection) is after the next window and before the standard cycle, so both real file-server truths are next-window.
    const k = b.case.constraints;
    const [next, cycle] = [...k.windows].sort((x, y) => x.start - y.start);
    const deadline = Date.parse(String(headRow(b).FirstSeen)) + k.slaDays.high * 86_400_000;
    expect(deadline, `${label}: the High deadline is after the next window`).toBeGreaterThan(next.end);
    expect(deadline, `${label}: the High deadline is before the standard cycle`).toBeLessThan(cycle.start);
    // The same calendar and the same worklist (host and vulnerability of every row), with the same truths below the file servers.
    expect(JSON.stringify(a.case.constraints), `${label}: one calendar`).toBe(JSON.stringify(b.case.constraints));
    const key = (s: VulnScenario) => s.case.findings.map((f) => { const r = rows(s.corpus, 'VulnFindings').find((x) => x.RecordId === f.recordId)!; return `${String(r.DeviceName)}|${String(r.VulnId)}`; });
    expect(key(b), `${label}: same worklist`).toEqual(key(a));
    expect(JSON.stringify(b.case.findings.slice(2).map((f) => f.truth)), `${label}: same truths below the file servers`).toBe(JSON.stringify(a.case.findings.slice(2).map((f) => f.truth)));
  },
};

// All four pairs of batch A.
const PAIRS: readonly PairRow[] = [T1, T2, T4, T5];

// ---- generic checks (shared with batch B: pair-helpers.ts) ----------------------------------------------

describe('rule 3 helper', () => {
  const t = (decision: FindingTruth['decision'], schedule: FindingTruth['schedule'], slaLatest?: FindingTruth['schedule']): FindingTruth => ({ decision, schedule, slaLatest, reasons: [] });
  it('accepts a different decision, a two-step gap and a gap across the SLA, and refuses a one-step slip inside it', () => {
    expect(differsByRule3(t('patch', 'emergency'), t('mitigate', 'emergency'))).toBe(true);
    expect(differsByRule3(t('patch', 'emergency', 'emergency'), t('patch', 'standard-cycle', 'standard-cycle'))).toBe(true);
    expect(differsByRule3(t('patch', 'emergency', 'emergency'), t('patch', 'next-window', 'next-window'))).toBe(true); // next-window is later than the emergency SLA
    expect(differsByRule3(t('patch', 'emergency', 'next-window'), t('patch', 'next-window', 'next-window'))).toBe(false);
  });
});

describe('batch A is registered', () => {
  it('lists every twin of the batch, both ways', () => {
    for (const r of PAIRS) {
      expect(byId(r.a).twin, `${r.pair}: A names B`).toBe(r.b);
      expect(byId(r.b).twin, `${r.pair}: B names A`).toBe(r.a);
    }
    expect(new Set(PAIRS.flatMap((r) => [r.a, r.b])).size, 'no template twice').toBe(PAIRS.length * 2);
    // The four pairs and the six templates this batch adds (T1-B and T2-B beside their existing A sides, T4 and T5 whole).
    expect(PAIRS.map((r) => r.pair)).toEqual(['T1', 'T2', 'T4', 'T5']);
    for (const id of ['vm-backport-real', 'vm-fresh-scan', 'vm-exposed-edge', 'vm-segmented', 'vm-waf-covers', 'vm-waf-bypass']) expect(PAIRS.flatMap((r) => [r.a, r.b]), `${id} is in the batch table`).toContain(id);
  });
});

registerPairSuite('batch A', PAIRS);
