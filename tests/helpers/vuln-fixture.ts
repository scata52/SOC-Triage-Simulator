// A tier-3 sized vulnerability-management fixture template for the engine
// tests (WP1b onward). It is not content: real templates live in
// src/core/vuln/templates. It exercises everything the corpus layer offers:
// two scan runs (one credentialed and stale with a login failure, one fresh
// and unauthenticated), banner versus package versions, a distribution
// backport, a stale finding fixed since the scan, a verified control and a
// detect-only decoy, a legacy scenario-only host, change windows, a freeze,
// a risk exception, and about twenty findings in all.

import type { CatalogueEntry } from '../../src/core/vuln/catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../../src/core/vuln/model.ts';
import type { WrittenFinding } from '../../src/core/vuln/scan-writer.ts';
import { versionBelow } from '../../src/core/vuln/scan-writer.ts';
import { DAY, HOUR, iso } from '../../src/core/logs/time.ts';

export const FIXTURE_TEMPLATE_ID = 'vm-fixture-tier3';

function take(entries: readonly CatalogueEntry[], used: Set<string>, preferred: (e: CatalogueEntry) => boolean, what: string): CatalogueEntry {
  const free = entries.filter((e) => !used.has(e.id));
  const entry = free.find(preferred) ?? free[0];
  if (!entry) throw new Error(`fixture: no catalogue entry for ${what}`);
  used.add(entry.id);
  return entry;
}

function fixtureBuild(ctx: VulnContext): VulnCaseSpec {
  const { log, now, rng } = ctx;
  const { catalogue, scan } = ctx.vuln;
  const used = new Set<string>();
  const entries = catalogue.entries;

  // ---- scope: world servers plus one forgotten scenario-only host
  const legacy = scan.scopeHost({ name: 'OLDFILE01', role: 'Legacy file transfer server (decommission pending)', os: 'Windows Server 2012 R2', owner: 'IT Infrastructure', criticality: 'Low' });
  const hosts = ['WEB01', 'APP01', 'FS01', 'SQL01', 'BUILD01', 'PRINT01'];
  const scanned = [...hosts, legacy];

  // ---- two scan runs: an old credentialed one (partial coverage) and a fresh banner scan
  const oldRun = scan.run({ method: 'Credentialed', started: now - 21 * DAY, targetsPlanned: 8, targetsScanned: 7 });
  const newRun = scan.run({ method: 'Unauthenticated', started: now - 2 * DAY, targetsPlanned: 8 });

  // ---- deciders
  const kev = take(entries, used, (e) => e.knownExploited && e.vendorFix && (e.severity === 'critical' || e.severity === 'high'), 'exploited finding');
  const f1 = scan.finding(newRun, { host: 'APP01', entry: kev, port: 8443, firstSeen: now - 30 * DAY });
  const dep = take(entries, used, (e) => !e.knownExploited && e.vendorFix && e.severity === 'high', 'fixed-since-scan finding');
  const f2 = scan.finding(oldRun, { host: 'FS01', entry: dep });
  const fixedAt = now - 10 * DAY;
  scan.software({ host: 'FS01', product: dep.product, vendor: dep.vendor, version: dep.fixedVersion, installedOn: fixedAt });
  const patch = log.patch({ DeviceName: 'FS01', PatchId: `PKG-${rng.int(1000, 9999)}`, Description: `${dep.product} updated to ${dep.fixedVersion}`, InstalledOn: fixedAt, RebootPending: false, Result: 'Installed' });

  const lowEpss = take(entries, used, (e) => !e.knownExploited && e.severity === 'high' && e.epss < 0.02, 'low-probability finding');
  const f3 = scan.finding(newRun, { host: 'BUILD01', entry: lowEpss, port: 8080 });

  const bp = take(entries, used, (e) => !e.knownExploited && e.vendorFix && e.severity !== 'critical', 'backported finding');
  const banner = versionBelow(rng, bp.fixedVersion);
  const f4 = scan.finding(newRun, { host: 'WEB01', entry: bp, port: 443, installedVersion: `${banner}-2+esm1`, packageSource: 'distro' });
  const backport = log.patch({ DeviceName: 'WEB01', PatchId: `USN-${rng.int(1000, 9999)}`, Description: `Distribution security update: fix for ${bp.id} backported into ${banner}`, InstalledOn: now - 40 * DAY, RebootPending: false, Result: 'Installed' });

  const ctl = take(entries, used, (e) => !e.knownExploited && (e.vulnClass === 'sqli' || e.vulnClass === 'auth-bypass') && e.severity === 'high', 'controlled finding');
  const f5 = scan.finding(oldRun, { host: 'SQL01', entry: ctl });
  const control = log.control({ ControlId: 'CTL-ACL-0412', Kind: 'ACL', Target: 'SQL01', Mode: 'block', CoversVulnId: ctl.id, Evidence: 'Segment ACL verified 6 days ago: only APP01 may reach the database port.' });
  const decoyEntry = take(entries, used, (e) => !e.knownExploited && e.vulnClass === 'rce', 'decoy control target');
  log.control({ ControlId: 'CTL-WAF-0230', Kind: 'WAF', Target: 'WEB01', Mode: 'detect', CoversVulnId: decoyEntry.id, Evidence: 'Rule logs only and does not block; never moved to enforcing.' });

  const old = take(entries, used, (e) => e.knownExploited && e.year <= 2019, 'legacy exploited finding');
  const f6 = scan.finding(oldRun, { host: legacy, entry: old, port: 445, authFailed: true });

  // ---- background: most of a scan is noise
  scan.background(newRun, { hosts, count: 8, hygiene: 3, exclude: used });
  scan.background(oldRun, { hosts: scanned, count: 3, exclude: used });

  // ---- context: exposure proof, tickets, windows, a freeze and an exception
  const outside = ctx.pick.ip('hosting');
  const web = ctx.idx.host('WEB01');
  const exposure = [1, 3, 5, 8].map((d) =>
    log.fw({ TimeGenerated: now - d * DAY - rng.int(0, 600) * 1000, Direction: 'Inbound', Action: 'Allow', Protocol: 'TCP', SourceIP: outside, SourcePort: rng.int(49152, 65000), DestinationIP: web.ip, DestinationPort: 443, RuleName: 'allow-web-inbound', BytesSent: rng.int(400, 4000), BytesReceived: rng.int(2000, 90000), SessionDurationSec: rng.int(1, 60) }),
  );
  const admin = ctx.pick.person({ dept: 'IT', working: false });
  const change = (title: string, scope: string, start: number, hours: number, details: string) =>
    log.ticket({ TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: title, Requester: admin.upn, AssignedTo: 'IT Infrastructure', Status: 'Approved', Created: now - rng.int(3, 20) * DAY, WindowStart: start, WindowEnd: start + hours * HOUR, Scope: scope, Details: details });
  const w1 = now + 3 * DAY;
  const w2 = now + 10 * DAY;
  const fz = now + 6 * DAY;
  change('Monthly patch window: application servers', 'APP01, FS01, SQL01', w1, 4, 'Standard monthly maintenance window for application servers.');
  change('Monthly patch window: second cycle', 'APP01, FS01, SQL01, BUILD01', w2, 4, 'Second monthly maintenance window.');
  change('Change freeze: quarter-end close', 'All production', fz, 72, 'No production changes during the finance close.');
  change('Replace UPS batteries in the server room', 'Server room', now + 5 * DAY, 2, 'Facilities work; no server impact expected.');
  change('Rotate the wireless guest password', 'Guest wireless', now + 1 * DAY, 1, 'Routine rotation.');
  const exception = log.ticket({ TicketId: log.nextTicketId('REQ'), Type: 'Service request', Title: `Risk exception: ${legacy}`, Requester: admin.upn, AssignedTo: 'Security — Vulnerability Management', Status: 'Approved', Created: now - 45 * DAY, WindowStart: now - 45 * DAY, WindowEnd: now + 60 * DAY, Scope: legacy, Details: `Risk accepted until decommissioning: host isolated on its own VLAN, no internet access. Exception expires ${iso(now + 60 * DAY).slice(0, 10)}.` });

  const spec = (w: WrittenFinding, decision: FindingSpec['truth']['decision'], schedule: FindingSpec['truth']['schedule'], reasons: FindingSpec['truth']['reasons'], weight: number, evidence: FindingSpec['evidence'], extra: Partial<FindingSpec> = {}): FindingSpec => ({
    findingId: w.findingId,
    row: w.row,
    truth: { decision, schedule, reasons },
    weight,
    evidence,
    ...extra,
  });

  const findings: FindingSpec[] = [
    spec(f1, 'patch', 'emergency', ['known-exploited'], 3, [{ id: 'kev-listing', label: 'The vulnerability is on the Sim-KEV list', why: 'Confirmed exploitation outranks a modest probability score.', rows: [scan.intel(kev)] }], { mustNotMiss: true, lesson: true, truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['known-exploited'] } }),
    spec(f2, 'false-positive', 'none', ['stale-scan'], 1, [{ id: 'patched-since', label: 'The device was patched after the scan', why: 'The finding comes from a scan that predates the fix.', rows: [patch] }]),
    spec(f3, 'patch', 'standard-cycle', ['low-exploitability'], 1, [{ id: 'low-probability', label: 'Sim-EPSS probability is low', why: 'High CVSS, but little sign of exploitation.', rows: [scan.intel(lowEpss)] }]),
    spec(f4, 'false-positive', 'none', ['backported-fix', 'banner-only'], 1, [{ id: 'backport', label: 'The distribution backported the fix', why: 'A banner shows the upstream version, not the patched package.', rows: [backport, f4.row] }, { id: 'web-exposed', label: 'The web server is reachable from the internet', why: 'Exposure would raise the priority of a real finding here.', rows: exposure }]),
    spec(f5, 'mitigate', 'next-window', ['compensating-control-verified'], 1, [{ id: 'acl', label: 'A blocking ACL covers the finding', why: 'The control was verified, so the patch can wait for the window.', rows: [control] }], { truth: { decision: 'mitigate', schedule: 'next-window', reasons: ['compensating-control-verified'], mitigation: ['CTL-ACL-0412'] } }),
    spec(f6, 'accept', 'none', ['approved-exception'], 1, [{ id: 'exception', label: 'A risk exception covers the legacy host', why: 'Isolated and due for decommissioning; the exception has an expiry.', rows: [exception] }]),
  ];

  return {
    briefing: `Weekly review of the latest scan results for the servers in scope (${scanned.length} devices, two scan runs). Decide what to patch, mitigate, accept or dismiss, in what order, and when.`,
    findings,
    constraints: {
      windows: [
        { id: 'w1', label: 'Monthly patch window', start: w1, end: w1 + 4 * HOUR },
        { id: 'w2', label: 'Second monthly window', start: w2, end: w2 + 4 * HOUR },
      ],
      freezes: [{ id: 'fz', label: 'Quarter-end freeze', start: fz, end: fz + 72 * HOUR }],
      slaDays: { critical: 3, high: 14, medium: 30, low: 90 },
      capacityPerWindow: 4,
    },
    idealOrder: [f1.findingId, f5.findingId, f3.findingId],
    tiers: [[f1.findingId], [f5.findingId], [f3.findingId]],
    hints: ['Start with the vulnerabilities that are known to be exploited.', 'Compare when each scan ran with when the device was last patched.', 'A banner shows the upstream version; check the installed package.'],
    solution: [
      { title: 'Which vulnerabilities are known to be exploited?', kql: 'VulnIntel\n| where KnownExploited\n| project VulnId, KnownExploitedAdded, ExploitProbability, RecordId', why: 'Sim-KEV listing is the strongest signal.' },
      { title: 'Which findings are those, and how sure is the scanner?', kql: 'VulnFindings\n| join kind=inner (VulnIntel) on VulnId\n| where KnownExploited\n| project DeviceName, VulnId, Title, DetectedVersion, Evidence, RecordId', why: 'Join findings to intel, then read the raw evidence.' },
      { title: 'How likely is exploitation for the high-scoring ones?', kql: 'VulnIntel\n| where CvssBase >= 7 and not(KnownExploited)\n| project VulnId, CvssBase, ExploitProbability, ExploitPercentile, PublicExploit, RecordId\n| sort by ExploitProbability asc', why: 'A high CVSS score with a low Sim-EPSS probability can wait for the standard cycle.' },
      { title: 'When did each scan run, and how complete was it?', kql: 'ScanRuns\n| sort by Started desc', why: 'A stale or partial scan cannot be trusted for what changed since.' },
      { title: 'What was patched, and when?', kql: 'PatchHistory\n| sort by InstalledOn desc', why: 'Patches after a scan make its findings stale; backports explain banner mismatches.' },
      { title: 'Which controls block, and which only detect?', kql: 'ControlInventory\n| project ControlId, Kind, Target, Mode, CoversVulnId, Evidence, RecordId', why: 'Only an enforcing, verified control counts as mitigation.' },
      { title: 'Who has an exception?', kql: 'Tickets\n| where Title startswith "Risk exception"\n| project TicketId, Title, WindowEnd, Details, RecordId', why: 'Exceptions carry an expiry.' },
      { title: 'Is the web server reachable from outside?', kql: `FirewallLogs\n| where DestinationIP == "${web.ip}" and Direction == "Inbound"\n| take 5`, why: 'Exposure proof from firewall sessions.' },
    ],
    rubric: [{ id: 'note', text: 'States what to fix first and why.', keywords: ['known exploited', 'emergency'] }],
    explanation: ['Known exploitation beats a modest probability.', 'Stale scans and backported fixes produce findings that are not real.'],
    pitfalls: ['Sorting by CVSS alone.', 'Trusting an unauthenticated banner version.'],
    references: [{ label: 'FIRST CVSS v3.1 specification', url: 'https://www.first.org/cvss/v3.1/specification-document' }],
  };
}

export const fixtureTier3: VulnTemplate = {
  id: FIXTURE_TEMPLATE_ID,
  difficulty: 'tier3',
  title: 'Fixture: weekly scan review',
  lesson: 'Engine test fixture; not shown to learners.',
  cysaDomains: ['2.0'],
  objectives: ['2.3'],
  kind: 'vuln',
  build: fixtureBuild,
};

