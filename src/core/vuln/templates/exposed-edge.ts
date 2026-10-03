// Twin T4 (DESIGN section 4): the same CVSS 9.8 remote code execution in the
// management interface of an edge appliance, in the same scan, with the same
// worklist. In `vm-exposed-edge` the appliance is reachable from the internet
// (DeviceInfo ExposedToInternet, FirewallLogs show internet sources allowed to
// the management port) and the only ACL on that interface logs without blocking:
// the Critical deadline ends before the next window, so it is an emergency
// patch. In `vm-segmented` the appliance is not exposed, an ACL in block mode
// covers the vulnerability, and FirewallLogs show every non-management source
// denied: the written compensating-control rule lets the control meet the
// deadline while the permanent fix goes in the next window. One builder, the
// clue bundle is a parameter. Everything else (the headline entry, the host,
// versions and dates, the other four findings, the noise) is chosen from the
// catalogue seed, not from the template id.

import { DAY, HOUR } from '../../logs/time.ts';
import { environmentalScore } from '../cvss31.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  AGENT_PRODUCTS,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  FICTIONAL_OS,
  hostFacts,
  installedBefore,
  LOW_EPSS,
  lowerHalfEpss,
  ownersOf,
  placedOn,
  policyAttachments,
  REF_CVSS,
  REF_EPSS,
  REF_EXAM,
  REF_KEV,
  scopeSharedHost,
  type ShapeWant,
  shaped,
  shapedOn,
  sharedRng,
  sizeRunToHosts,
  slaDeadline,
  withEpss,
  withFix,
  writeAuthFailure,
  writeChangeTickets,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  lowered,
  KW_EMERGENCY,
  KW_MITIGATE,
} from './common.ts';

type Variant = 'exposed' | 'segmented';

const EDGE_HOST = 'EDGE01';
const APP_HOST = 'APP01';
const FILE_HOST = 'FS01';
const DB_HOST = 'SQL01';
const MGMT_PORT = 8443;
const EDGE_PRODUCTS = ['Sablecrest Gateway', 'Marrowgate Proxy', 'Wrenwick Relay', 'Gallowglass Firewall Manager'] as const;

const TITLE = 'Scan review: edge and internal servers';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const isExposed = variant === 'exposed';
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'exposed-edge');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const version = (label: string, e: CatalogueEntry) => versionBelow(sharedRng(ctx, `version/${label}`), e.fixedVersion);

  // ---- two credentialed runs: an older complete one, a newer partial one whose login failed on the file server.
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 10 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 4 * DAY, targetsPlanned: 8, targetsScanned: 8 }); // sized to the devices that have a row once all rows are written
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / 60_000))) * 60_000;

  // ---- entries (twins share every choice)
  // Worklist flaws on different hosts sit on different products (version realism): a host never runs a product below the
  // fix of another worklist vulnerability on that product unless it carries that finding too.
  const taken = new Set<string>();
  const choose = (want: ShapeWant, bound: number, host: string, avoid: ReadonlySet<string> = new Set()): CatalogueEntry => {
    const known = free().filter((x) => quiet(x) && x.published <= bound);
    const e = shapedOn(withFix(rng.pick(known), rng), host, rng, want, new Set([...avoid, ...taken]));
    used.add(e.id);
    taken.add(e.product);
    return e;
  };
  // The headline: a quiet entry, published well before the host's software was installed, placed on an edge appliance product
  // and shaped as the 9.8 unauthenticated remote code execution. Not on Sim-KEV (a listing would put the twin on the 3-day clock).
  const headPick = rng.pick(free().filter((x) => quiet(x) && x.published <= now - 45 * DAY));
  used.add(headPick.id);
  const headPlaced = placedOn(withFix(headPick, rng), EDGE_HOST, rng, new Set(AGENT_PRODUCTS), EDGE_PRODUCTS) ?? headPick;
  const f1Entry = withEpss(shaped(headPlaced, rng, { classes: ['rce'], min: 9.8, max: 9.8, component: /^request parser$/ }), LOW_EPSS);
  const avoid = new Set([f1Entry.product]);
  const f2Entry = withEpss(choose({ min: 7.6, max: 8.9 }, now - 45 * DAY, APP_HOST, avoid), LOW_EPSS);
  const f3Entry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, FILE_HOST, avoid), LOW_EPSS);
  const f4Entry = withEpss(choose({ min: 4, max: 6.9 }, now - 60 * DAY, DB_HOST, avoid), lowerHalfEpss(rng.fork('f4-epss'), 0.45));

  // ---- the headline host: authored for this case, identical in the twins except for the exposure clue.
  const edge = scopeSharedHost(ctx, { name: EDGE_HOST, role: `Edge gateway (management interface on ${MGMT_PORT}/tcp)`, os: FICTIONAL_OS, owner: 'IT Infrastructure', criticality: 'High', deviceType: 'Appliance' }, 'edge', 'mgmt'); // appliances sit in the management range, exposed or not
  if (isExposed) ctx.log.deviceRef(edge).row.ExposedToInternet = true;
  const edgeIp = String(ctx.log.deviceRef(edge).row.IPAddress);
  const edgeRow = log.deviceRef(edge);

  // ---- F1 headline: first detected by the newer run (the version was installed after the older run started).
  const f1FirstSeen = newRun.started;
  const f1Version = version('f1', f1Entry);
  const f1 = scan.finding(newRun, { host: edge, entry: f1Entry, port: MGMT_PORT, firstSeen: f1FirstSeen, lastSeen: lastSeen(newRun, 'f1'), installedVersion: f1Version, title: f1Entry.title });
  scan.software({ host: edge, product: f1Entry.product, vendor: f1Entry.vendor, version: f1Version, installedOn: now - 6 * DAY });
  scan.intel(f1Entry);

  // ---- F2 the decoy: a High on the application server whose ACL only detects
  const f2FirstSeen = now - 21 * DAY;
  const f2 = scan.finding(newRun, { host: APP_HOST, entry: f2Entry, firstSeen: f2FirstSeen, lastSeen: lastSeen(newRun, 'f2'), installedVersion: version('f2', f2Entry), title: f2Entry.title });
  scan.software({ host: APP_HOST, product: f2Entry.product, vendor: f2Entry.vendor, version: version('f2', f2Entry), installedOn: installedBefore(ctx, 'f2', f2FirstSeen) });

  // ---- F3 the stale result: High on the file server, patched after the older run started, never re-tested (the newer run's login failed)
  const f3FirstSeen = oldRun.started;
  const f3 = scan.finding(oldRun, { host: FILE_HOST, entry: f3Entry, firstSeen: f3FirstSeen, lastSeen: lastSeen(oldRun, 'f3'), installedVersion: version('f3', f3Entry), title: f3Entry.title });
  const patchedAt = oldRun.started + 3 * DAY;
  scan.software({ host: FILE_HOST, product: f3Entry.product, vendor: f3Entry.vendor, version: f3Entry.fixedVersion, installedOn: patchedAt });
  const patch = log.patch({
    DeviceName: FILE_HOST,
    PatchId: `PKG-${sharedRng(ctx, 'f3-patch').int(1000, 9999)}`,
    Description: `${f3Entry.product} update to ${f3Entry.fixedVersion} (addresses ${f3Entry.id})`,
    InstalledOn: patchedAt,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- F4 a Medium on the database server: standard cycle
  const f4FirstSeen = now - 40 * DAY;
  const f4 = scan.finding(newRun, { host: DB_HOST, entry: f4Entry, firstSeen: f4FirstSeen, lastSeen: lastSeen(newRun, 'f4'), installedVersion: version('f4', f4Entry), title: f4Entry.title });
  scan.software({ host: DB_HOST, product: f4Entry.product, vendor: f4Entry.vendor, version: version('f4', f4Entry), installedOn: installedBefore(ctx, 'f4', f4FirstSeen) });

  // ---- controls: three rows in both twins. The first is the clue: the ACL on the management interface either blocks and
  // covers the headline (segmented) or only logs and covers nothing (exposed).
  const crng = sharedRng(ctx, 'controls');
  const verified = now - crng.int(2, 4) * DAY;
  const aclId = (): string => `CTL-ACL-${crng.int(1000, 9999)}`;
  const edgeAclId = aclId();
  let decoyAclId = aclId();
  while (decoyAclId === edgeAclId) decoyAclId = aclId();
  let sshAclId = aclId();
  while (sshAclId === edgeAclId || sshAclId === decoyAclId) sshAclId = aclId();
  const edgeAcl = log.control(
    isExposed
      ? { ControlId: edgeAclId, Kind: 'ACL', Target: `${edge} management interface (${MGMT_PORT}/tcp)`, Mode: 'detect', CoversVulnId: '', Evidence: 'Rule created in log-only mode; never moved to enforcing, so it blocks nothing. No change request to enforce it has been approved.' }
      : { ControlId: edgeAclId, Kind: 'ACL', Target: `${edge} management interface (${MGMT_PORT}/tcp)`, Mode: 'block', CoversVulnId: f1Entry.id, Evidence: `Verified ${ymd(verified)}: only the management VLAN may reach ${MGMT_PORT}/tcp on ${edge}; every other source is denied (see FirewallLogs).` },
  );
  const decoyAcl = log.control({ ControlId: decoyAclId, Kind: 'ACL', Target: `${APP_HOST} application port (${MGMT_PORT}/tcp)`, Mode: 'detect', CoversVulnId: f2Entry.id, Evidence: 'Rule logs matches and blocks nothing; it has not been verified as enforcing.' });
  log.control({ ControlId: sshAclId, Kind: 'ACL', Target: `${edge} SSH (22/tcp)`, Mode: 'block', CoversVulnId: '', Evidence: `Verified ${ymd(verified)}: SSH to ${edge} is limited to the management VLAN. It does not apply to the management web interface.` });

  // ---- firewall sessions to the management port: the same six sessions (sources, times, ports) in both twins; the action
  // and rule differ: internet sources are allowed in the exposed twin and denied in the segmented one.
  const frng = sharedRng(ctx, 'edge-firewall');
  const w = world.internet;
  const outside = frng.sample(w.scanners, 4); // internet scanners: short connection probes, not data transfers
  const adminIps = ['SCCM01', 'SCAN01'].map((h) => String(log.deviceRef(h).row.IPAddress));
  const internetRows = outside.map((src) => {
    const t = now - frng.int(1, 6) * DAY - frng.int(0, 20) * HOUR - frng.int(0, 3599) * 1000;
    const sent = frng.int(300, 1200);
    const received = frng.int(200, 1900);
    const duration = frng.int(1, 4);
    const port = frng.int(49152, 65000);
    return log.fw({
      TimeGenerated: t,
      Direction: 'Inbound',
      Action: isExposed ? 'Allow' : 'Deny',
      SourceIP: src,
      SourcePort: port,
      DestinationIP: edgeIp,
      DestinationPort: MGMT_PORT,
      RuleName: isExposed ? 'allow-edge-mgmt-any' : 'deny-edge-mgmt-nonadmin',
      BytesSent: isExposed ? sent : 0,
      BytesReceived: isExposed ? received : 0,
      SessionDurationSec: isExposed ? duration : 0,
    });
  });
  const adminRows = adminIps.map((src) =>
    log.fw({
      TimeGenerated: now - frng.int(1, 6) * DAY - frng.int(0, 20) * HOUR,
      Direction: 'Internal',
      Action: 'Allow',
      SourceIP: src,
      SourcePort: frng.int(49152, 65000),
      DestinationIP: edgeIp,
      DestinationPort: MGMT_PORT,
      RuleName: 'allow-edge-mgmt-vlan',
      BytesSent: frng.int(1200, 9000),
      BytesReceived: frng.int(8000, 400_000),
      SessionDurationSec: frng.int(5, 600),
    }),
  );

  // ---- background scanner noise, tickets, calendar, unrelated updates.
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['FS02', 'DC01', 'SCCM01'] },
      { run: newRun, hosts: ['BKP01', 'BUILD01'] },
    ],
    [f1Entry, f2Entry, f3Entry, f4Entry],
    { extraNonWorklist: 1 }, // the login-failure row
  );
  writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'SCCM01', 'BKP01', 'BUILD01'], 2, sharedRng(ctx, 'unrelated-patches'));
  const authFailure = writeAuthFailure(ctx, newRun, FILE_HOST); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  // ---- the truth (derived from the policy, the calendar, the dates and the control rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const f1Deadline = slaDeadline('critical', f1FirstSeen);
  const f2Deadline = slaDeadline('high', f2FirstSeen);
  const envScore = environmentalScore(`${f1Entry.vector}/MAV:A`);
  const f1Reasons = isExposed ? (['internet-exposed', 'control-not-covering', 'sla-deadline'] as const) : (['compensating-control-verified'] as const);
  const f1Spec: FindingSpec = isExposed
    ? spec(f1, {
        truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(edge), f1Reasons) },
        weight: 3,
        mustNotMiss: true,
        lesson: true,
        evidence: [
          {
            id: 'exposed-and-reachable',
            label: `${edge} is exposed to the internet and the firewall allows internet sources to its management port`,
            why: `DeviceInfo shows ${edge} reachable from the internet (ExposedToInternet true), and FirewallLogs show ${internetRows.length} internet sources allowed to ${MGMT_PORT}/tcp (Action Allow, rule allow-edge-mgmt-any), alongside the management hosts. The path to the vulnerable interface is open. The 9.8 is Critical by its base score: 7 days from first detection, due ${ymd(f1Deadline)} (end of day), before the next window (${ymd(cal.next.start)}), so only an emergency change meets it. Sim-EPSS ${LOW_EPSS} and no Sim-KEV listing do not move the deadline.`,
            rows: [edgeRow, ...internetRows],
          },
          {
            id: 'acl-log-only',
            label: `The ACL on the management interface is in detect mode and covers no vulnerability`,
            why: `ControlInventory has an ACL on ${edge} ${MGMT_PORT}/tcp, but its Mode is detect (it logs and blocks nothing) and CoversVulnId is empty, so it is not a compensating control under the policy: that needs block mode, coverage of this vulnerability and confirmation in the logs.`,
            rows: [edgeAcl],
          },
        ],
      })
    : spec(f1, {
        truth: { decision: 'mitigate', schedule: 'next-window', slaLatest: 'next-window', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(edge, { control: true }), f1Reasons), mitigation: [edgeAclId] },
        weight: 3,
        mustNotMiss: true,
        lesson: true,
        evidence: [
          {
            id: 'verified-block-acl',
            label: `An ACL in block mode covers this vulnerability on ${edge}, and the firewall denies every non-management source`,
            why: `ControlInventory has ${edgeAclId}: an ACL on ${edge} ${MGMT_PORT}/tcp, Mode block, CoversVulnId ${f1Entry.id}, verified ${ymd(verified)}. FirewallLogs confirm it: ${internetRows.length} internet sources were denied (rule deny-edge-mgmt-nonadmin) and only the management VLAN hosts were allowed. The policy lets a control that blocks the path meet the deadline while it stays in effect, so the Critical deadline (${ymd(f1Deadline)}, end of day) is met by the control; it ends when the permanent fix is deployed, so schedule that in the next window (${ymd(cal.next.start)}).`,
            rows: [edgeAcl, ...internetRows, ...adminRows],
          },
          {
            id: 'not-exposed',
            label: `${edge} is not exposed to the internet`,
            why: `DeviceInfo shows ${edge} with ExposedToInternet false: the interface is reachable only from the management VLAN, which is why the environmental score (${f1Entry.vector}/MAV:A = ${envScore.toFixed(1)}) is below the base score of ${f1Entry.base.toFixed(1)}. The policy still classes the finding from the base score shown in VulnFindings (Critical).`,
            rows: [edgeRow],
          },
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['control-not-covering', 'sla-deadline'], contradicting: contradictionsFor(f2Entry, facts(APP_HOST), ['control-not-covering', 'sla-deadline']) },
      weight: 1,
      evidence: [
        {
          id: 'detect-only-acl',
          label: `The ACL that names this vulnerability is in detect mode on ${APP_HOST}`,
          why: `ControlInventory lists ${decoyAclId} for ${f2Entry.id}, but its Mode is detect: it logs matches and blocks nothing, so it is not a compensating control and does not change the decision. The High deadline (${ymd(f2Deadline)}, end of day) is after the next window and before the standard cycle: patch it in the next window.`,
          rows: [decoyAcl],
        },
      ],
    }),
    spec(f3, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(f3Entry, facts(FILE_HOST, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      evidence: [
        {
          id: 'patched-since-scan',
          label: `${FILE_HOST} received the update after the older scan run started, with no reboot pending, and the newer run's login failed there`,
          why: `The finding comes from the older run (last seen ${ymd(f3.row.row.LastSeen as number)}); the update that fixes it was installed after that run started (Result Installed, no reboot pending). The newer run tried ${FILE_HOST} but its login failed (an "Authentication failure: local checks not run" row), so nothing re-tested the host and the old result is still shown. It is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
          rows: [patch, authFailure],
        },
      ],
    }),
    spec(f4, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f4Entry, facts(DB_HOST), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
  ];

  const ids = { f1: f1.findingId, f2: f2.findingId, f3: f3.findingId, f4: f4.findingId };
  const owners = ownersOf(ctx, [EDGE_HOST, APP_HOST, FILE_HOST, DB_HOST]);
  const ownerNames = [...new Set([...owners, 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const f1Age = Math.round((now - f1FirstSeen) / DAY);

  const briefing = `${world.org.name}: review of the latest scan results for an edge appliance and the internal servers in scope (two scan runs, the newer one partial). Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch, ticket, firewall and control data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'A CVSS score describes the flaw, not the place it sits. For the headline, which tables show who can actually reach the vulnerable interface, and what stands in front of it?';
  const second = 'DeviceInfo and FirewallLogs describe the path to the management port; ControlInventory lists what is in front of it. Read Mode (block or detect) and CoversVulnId, then check the policy on compensating controls and the dates of the deadline and the next window.';

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.f1, ids.f2, ids.f4],
    tiers: isExposed ? [[ids.f1], [ids.f2], [ids.f4]] : [[ids.f1, ids.f2], [ids.f4]],
    hints: [
      lead,
      second,
      isExposed
        ? `The ACL on ${edge}'s management interface is in detect mode and covers no vulnerability, and FirewallLogs show internet sources allowed to the port: nothing is in front of the flaw. A Critical's deadline is 7 days from first detection; compare it with the next window.`
        : `The ACL on ${edge}'s management interface is in block mode and names this vulnerability, FirewallLogs show non-management sources denied, and the host is not exposed. The policy lets that control meet the deadline until the permanent fix is deployed.`,
    ],
    solution: [
      {
        title: 'What did the scanner find on the edge appliance?',
        kql: `VulnFindings\n| where DeviceName == "${edge}"\n| project FindingId, VulnId, Title, Severity, CvssBase, Port, Service, FirstSeen, ScanRunId, RecordId`,
        why: 'A Critical remote code execution in the management interface (port 8443), first detected by the newer run.',
      },
      {
        title: 'What does the intel say about it?',
        kql: `VulnIntel\n| where VulnId == "${f1Entry.id}"\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, RecordId`,
        why: 'No Sim-KEV listing, a low Sim-EPSS and no public exploit in both twins: the intel does not decide this case. The deciding clue is where the appliance sits.',
      },
      {
        title: 'Is the appliance reachable from the internet?',
        kql: `DeviceInfo\n| where DeviceName == "${edge}"\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, IPAddress, RecordId`,
        why: isExposed ? 'ExposedToInternet is true.' : 'ExposedToInternet is false.',
      },
      {
        title: 'Who reached the management port, and what did the firewall do?',
        kql: `FirewallLogs\n| where DestinationIP == "${edgeIp}" and DestinationPort == ${MGMT_PORT}\n| project TimeGenerated, Direction, Action, SourceIP, DestinationPort, RuleName, RecordId\n| sort by TimeGenerated desc`,
        why: isExposed ? 'Internet sources are allowed to the management port (rule allow-edge-mgmt-any), next to the management hosts.' : 'Internet sources are denied (rule deny-edge-mgmt-nonadmin); only the management VLAN hosts are allowed.',
      },
      {
        title: 'Which controls exist, and do they block or only detect?',
        kql: 'ControlInventory\n| project ControlId, Kind, Target, Mode, CoversVulnId, Evidence, RecordId',
        why: isExposed ? 'The ACL on the management interface is in detect mode and names no vulnerability; the SSH ACL is on another port; the ACL for the application server finding is in detect mode.' : 'The ACL on the management interface is in block mode and names the headline; the SSH ACL is on another port; the ACL for the application server finding is in detect mode, so it counts for nothing.',
      },
      {
        title: 'Was the file server patched after its scan?',
        kql: `PatchHistory\n| where DeviceName == "${FILE_HOST}"\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: 'An update that names the vulnerability, installed after the older run started, with Result Installed and no pending reboot, makes that scan result stale.',
      },
      {
        title: 'Did the newer run re-test the file server?',
        kql: `VulnFindings\n| where DeviceName == "${FILE_HOST}"\n| project FindingId, VulnId, Title, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId\n| sort by LastSeen desc`,
        why: 'The vulnerability row belongs to the older run; the newer run only logged an authentication failure for the host, so its local checks did not run.',
      },
      {
        title: 'When are the change windows and the freeze?',
        kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, RecordId\n| sort by WindowStart asc',
        why: 'The next window and the standard cycle are the dates each deadline is compared with.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: lowered(ownerNames) },
      {
        id: 'risk',
        text: isExposed ? 'States the risk in plain words: an internet-reachable management interface with an unauthenticated remote code execution flaw and nothing blocking it.' : 'States that the management interface is reachable only from the management VLAN and that a verified blocking ACL is compensating for the missing patch for now.',
        keywords: isExposed
          ? lowered(['internet-facing', 'internet facing', 'internet-reachable', 'internet reachable', 'reachable from the internet', 'open to the internet', 'public internet', 'is exposed to the internet', 'are exposed to the internet', 'exposed to the internet with', 'exposed to the internet and', 'exposed on the internet', 'internet-exposed', 'internet exposed', 'nothing blocks', 'nothing is blocking', 'nothing in front', 'no control in front', 'no acl'])
          : lowered(['management vlan', 'management network', 'blocking acl', 'verified acl', 'acl in block', 'acl blocks', 'compensating for', 'acts as a compensating', 'reachable only from', 'only reachable from', 'is segmented', 'segmented from']),
      },
      {
        id: 'action',
        text: isExposed ? 'Recommends an emergency patch of the edge appliance, a compromise check on it (the internet sources that reached its management port), the next window for the application server, the standard cycle for the Medium, and a rescan of the file server.' : 'Recommends the blocking ACL as the mitigation now, the permanent fix in the next window, a check that the control stays in effect until then, and a rescan of the file server.',
        keywords: isExposed
          ? lowered(KW_EMERGENCY, ['compromise check', 'check for compromise', 'check it for compromise', 'for compromise', 'signs of compromise'])
          : lowered(KW_MITIGATE, ['keep the acl', 'acl stays', 'acl has to stay in effect', 'acl must stay in effect', 'acl is kept in effect', 'acl remains in effect', 'control stays in effect', 'control remains in effect', 'acl is the mitigation', 'acl as the mitigation', `mitigate ${EDGE_HOST} with`, 'keep it in effect', 'keep the control in effect', 'in effect until the permanent', 'in effect until the patch', 'in effect until the fix', 'permanent fix in the next', 'permanent fix goes in the next']),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy.',
        keywords: dateRubricKeywords(cal, [f1Deadline, f2Deadline], [7, 30]),
      },
    ],
    explanation: isExposed
      ? [
          `The headline scores 9.8: Critical, a 7-day deadline counted from first detection ${f1Age} days ago and due ${ymd(f1Deadline)} (end of day), before the next window (${ymd(cal.next.start)}). The deciding clue is the path to the interface: DeviceInfo shows ${edge} exposed to the internet (ExposedToInternet true) and FirewallLogs show internet sources allowed to the management port. The only ACL on that interface (ControlInventory) is in detect mode and names no vulnerability, so it blocks nothing and is not a compensating control. Only an emergency change meets the deadline: patch, emergency.`,
          `The intel shows no known exploitation (not on Sim-KEV, Sim-EPSS ${LOW_EPSS}, no public exploit), but the deadline does not depend on it: the policy sets it from the severity class (the base score), and an internet-reachable unauthenticated remote code execution is the finding the class is for. The internet sources that reached the management port are handed to the SOC for a compromise check on the appliance as well; that is separate from the remediation decision and does not change it. The twin has the same score, the same intel and the same ACL row, but the ACL blocks and the host is not reachable from outside.`,
          `The decoys are in ControlInventory: an ACL on the same host's SSH port (it does not cover the management interface) and a detect-mode ACL for the application server finding (it blocks nothing). The application server's High finding is real: 30 days from first detection ends after the next window and before the standard cycle (${ymd(cal.cycle.start)}), so it goes in the next window. The Medium on the database server has a 90-day deadline: standard cycle.`,
          `The file server's High finding is no longer valid: PatchHistory shows the update installed after the older run started, Result Installed and no reboot pending, and the newer (partial) run only logged an authentication failure for the host ("local checks not run"), so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm. The older, complete run did not report the headline because the vulnerable version was installed after it started (SoftwareInventory InstalledOn).`,
        ]
      : [
          `The headline scores 9.8: Critical, a 7-day deadline counted from first detection ${f1Age} days ago and due ${ymd(f1Deadline)} (end of day), before the next window (${ymd(cal.next.start)}). The deciding clue is what stands in front of the interface: ControlInventory has an ACL on ${edge} ${MGMT_PORT}/tcp in block mode that names this vulnerability (CoversVulnId), FirewallLogs show every non-management source denied and only the management VLAN allowed, and DeviceInfo shows ExposedToInternet false. The policy lets a control that blocks the path meet the deadline while it stays in effect and ends when the permanent fix is deployed, so the answer is mitigate with that ACL, and the permanent fix goes in the next window.`,
          `The score shown in the scan store stays 9.8 and the policy classes the finding from it (Critical). Scoring the environment is a different question: with the network path limited to the adjacent network (modified attack vector A, ${f1Entry.vector}/MAV:A) the environmental score is ${envScore.toFixed(1)}. Base is not environmental: that is why a reasonable analyst reads the path, not only the number. It is also why this is not an emergency patch (the twin, with an open path, is) and not a standard-cycle patch: the control is temporary and the permanent fix has a date.`,
          `The decoys are in ControlInventory: an ACL on the same host's SSH port (it does not cover the management interface) and a detect-mode ACL for the application server finding (it blocks nothing, so that High finding is a normal next-window patch). The Medium on the database server has a 90-day deadline: standard cycle.`,
          `The file server's High finding is no longer valid: PatchHistory shows the update installed after the older run started, Result Installed and no reboot pending, and the newer (partial) run only logged an authentication failure for the host ("local checks not run"), so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm. The older, complete run did not report the headline because the vulnerable version was installed after it started (SoftwareInventory InstalledOn).`,
        ],
    pitfalls: isExposed
      ? [
          'Treating a low Sim-EPSS and no Sim-KEV listing as a reason to wait: the Critical deadline ends before the next window whatever the feeds say.',
          'Taking the ACL row for a control without reading its Mode: a detect-mode rule logs and blocks nothing.',
          'Using the SSH ACL on the same host as cover for the management interface: it protects another port.',
          'Choosing mitigate with no verified control: only an enforcing control that covers the vulnerability counts.',
          'Treating the internet sessions to the management port as only a scheduling question: patch on the emergency clock and also have the SOC check the appliance for compromise.',
          'Believing the scanner over the patch record for the file server.',
        ]
      : [
          'Chasing the base score: 9.8 is the same in both twins; what differs is the path to the interface, and the environmental score (8.8 with MAV:A) neither replaces reading it nor changes the policy class.',
          'Taking the ACL on trust: Mode block, CoversVulnId and the denies in FirewallLogs together prove it; the detect-mode ACL for the application server proves nothing.',
          'Stopping at the mitigation: the control ends when the permanent fix is deployed, so the permanent fix still needs a window.',
          'Ordering and scheduling the headline as an emergency because it is a 9.8: that spends scarce change capacity where a verified control already meets the deadline.',
          'Believing the scanner over the patch record for the file server.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier1',
  title: TITLE,
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.3', '2.5', '4.1'],
  kind: 'vuln',
};

export const exposedEdge: VulnTemplate = {
  ...COMMON,
  id: 'vm-exposed-edge',
  twin: 'vm-segmented',
  lesson:
    'DeviceInfo shows the edge appliance exposed to the internet (ExposedToInternet true) and FirewallLogs show internet sources allowed to its management port, with the only ACL in ControlInventory in detect mode: nothing is in front of the 9.8, its 7-day deadline ends before the next window, so it is an emergency patch. The twin has the same score and a verified block-mode ACL.',
  build: (ctx) => build('exposed', ctx),
};

export const segmented: VulnTemplate = {
  ...COMMON,
  id: 'vm-segmented',
  twin: 'vm-exposed-edge',
  lesson:
    'ControlInventory shows an ACL in block mode covering the headline on the edge appliance, FirewallLogs show every non-management source denied and DeviceInfo shows ExposedToInternet false: a verified compensating control meets the deadline until the permanent fix, so mitigate now and patch in the next window (environmental 8.8 with MAV:A, but the policy class stays Critical). The twin is exposed with an ACL that only detects.',
  build: (ctx) => build('segmented', ctx),
};
