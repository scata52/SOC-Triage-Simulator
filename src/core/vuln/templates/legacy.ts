// Twin T6 (DESIGN section 4): the same High remote flaw in the firmware of a laboratory
// process controller whose vendor has ended support, so no fix will ever exist
// (VulnIntel VendorFix false). The headline, the host, the versions, the dates and the
// other four findings are shared. In `vm-legacy-accept` an approved, unexpired risk
// exception for the host is in Tickets and the isolation it relies on is in effect (an
// ACL in block mode names the host, and FirewallLogs show the corporate sources
// denied): accept, and note the expiry. In `vm-legacy-isolate` the only request for an
// exception is still open, the ACL exists for the OT controller VLAN but does not
// cover this host, and FirewallLogs show corporate workstations reaching it: put the
// host behind that ACL by the deadline (mitigate, naming it) and raise the exception.
// The decoy is the same in both: an exception on the print server that expired weeks
// ago, for a flaw the vendor has fixed since (accept no longer applies: patch).
// One builder, the clue bundle is a parameter. Everything else is chosen from the
// catalogue seed, not from the template id.

import { DAY, HOUR, MIN } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  dayStart,
  hostFacts,
  installedBefore,
  LOW_EPSS,
  lowerHalfEpss,
  ownersOf,
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
  withPublished,
  writeChangeTickets,
  writeRiskException,
  writeUnrelatedPatches,
  ymd,
} from './common.ts';

type Variant = 'accept' | 'isolate';

const HOST = 'LABCTL01';
const PRINT = 'PRINT01'; // the decoy: an exception that has expired
const DB = 'SQL01';
const APP = 'APP01';
const BUILD = 'BUILD01';
const PORT = 7410;
const SERVICE = 'ctl-api';
const PRODUCT = 'Halbrenn Bench Controller';
const VENDOR = 'Halbrenn Instruments';
const CONTROLLER_OS = 'Halbrenn RTOS 2.8';
const MGMT_HOSTS = ['OTMGMT01', 'OTMGMT02'] as const; // the OT management hosts: engineering workstations of Lab Engineering (management range), authored for this case
const SCANNER = 'SCAN01'; // the authorised scanner: its sweep read the controller's banner, so it is an allowed source too
const SEGMENT = `OT management hosts and the authorised scanner (${SCANNER})`;

const TITLE = 'Scan review: laboratory controller and internal servers';

// The template-local policy row (identical in both twins): what the rules say when the vendor has published no fix.
const NO_FIX_ROW: [string, string] = [
  'No vendor fix',
  'When the vendor has published no fix (VendorFix false in VulnIntel), accept is allowed only under an approved, unexpired risk exception for that system; an expired exception no longer allows it. The exception rests on a compensating measure that limits who can reach the system, and it counts only while that control is in effect for that system (ControlInventory shows it in block mode naming the system; FirewallLogs confirm it). With no valid exception, put the system behind a control that blocks the vulnerable path (ControlInventory, block mode, covering this vulnerability) by the deadline: record the finding as mitigate naming that control, schedule it in the window in which the system is moved behind the control (that window must end before the deadline), and raise a risk exception once the control is in effect. When an approved, unexpired exception exists and its control is already in effect for the system, record the finding as accept and note the expiry: the exception is the standing decision and the control is its condition, so this row, not the Compensating control row, decides (mitigate is for a control that is still to be applied, when no valid exception exists).',
];

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const isAccept = variant === 'accept';
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'legacy');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const allIds = catalogue.entries.map((e) => e.id);
  const versionOf = (label: string, e: CatalogueEntry): string => {
    const r = sharedRng(ctx, `version/${label}`);
    return e.vendorFix ? versionBelow(r, e.fixedVersion) : `${r.int(1, 9)}.${r.int(0, 12)}.${r.int(0, 9)}`;
  };

  // ---- two runs: an older complete credentialed run of the servers, a newer unauthenticated sweep of the lab range that did
  // not reach every target. The controller has no login a scanner can use, so its version is the banner's.
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 9 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Unauthenticated', started: now - 2 * DAY, targetsPlanned: 6, targetsScanned: 5 }); // sized to the devices that have a row once all rows are written
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // ---- dates (all relative to the case date, shared by the twins)
  const f1First = now - 22 * DAY; // High: due 30 days on, after the next window and before the standard cycle
  const approvedAt = now - 15 * DAY;
  const expires = now + 165 * DAY;
  const f2First = now - 81 * DAY; // Medium: due 90 days on, after the next window and before the standard cycle
  const f2Approved = now - 79 * DAY;
  const f2Expired = now - 19 * DAY;
  const f3First = now - 40 * DAY;
  const f4First = oldRun.started; // first detected by the older run
  const f5First = now - 20 * DAY;

  // ---- entries (twins share every choice)
  const choose = (want: ShapeWant, firstSeen: number, epss: number, host: string, brand?: { product: string; vendor: string }): CatalogueEntry => {
    const pool = free().filter(quiet);
    const known = pool.filter((x) => x.published <= firstSeen);
    const base = rng.pick(known.length > 0 ? known : pool);
    const dated = withPublished(base, Math.min(base.published, dayStart(firstSeen - DAY)), allIds);
    const e = brand ? shaped({ ...dated, ...brand }, rng, want) : shapedOn(dated, host, rng, want);
    used.add(base.id);
    used.add(e.id);
    return withEpss(withFix(e, rng), epss);
  };
  const lower = (label: string) => lowerHalfEpss(rng.fork(label), 0.45);
  // The headline: a network flaw (High) in the controller firmware, no vendor fix, no Sim-KEV listing.
  const f1Entry: CatalogueEntry = { ...choose({ classes: ['rce'], min: 7.6, max: 8.9, network: true }, f1First, LOW_EPSS, HOST, { product: PRODUCT, vendor: VENDOR }), vendorFix: false, fixedVersion: '' };
  // The decoy: a Medium on the print server whose exception expired; the vendor has published a fix since.
  const f2Entry = choose({ min: 4, max: 6.9, network: true }, f2First, LOW_EPSS, PRINT);
  const f3Entry = choose({ min: 4, max: 6.9 }, f3First, lower('f3'), DB);
  const f4Entry = choose({ min: 7, max: 8.9 }, f4First, lower('f4'), APP);
  const f5Entry = choose({ max: 3.9 }, f5First, lower('f5'), BUILD);

  // ---- the controller: authored for this case, identical in both twins
  scopeSharedHost(ctx, { name: HOST, role: `Laboratory process controller on the laboratory segment (vendor support ended; control interface ${PORT}/tcp)`, os: CONTROLLER_OS, owner: 'Lab Engineering', criticality: 'Medium', deviceType: 'Appliance' }, 'labctl', 'mgmt'); // appliances sit in the management range
  MGMT_HOSTS.forEach((name, i) => scopeSharedHost(ctx, { name, role: 'OT engineering workstation (manages the laboratory controllers)', os: 'Windows 11 Enterprise', owner: 'Lab Engineering', criticality: 'Low', deviceType: 'Workstation' }, `otmgmt${i}`, 'mgmt'));
  const hostRow = log.deviceRef(HOST);
  const hostIp = String(hostRow.row.IPAddress);

  // ---- F1 headline
  const f1Version = versionOf('f1', f1Entry);
  const f1Last = lastSeen(newRun, 'f1');
  const f1 = scan.finding(newRun, { host: HOST, entry: f1Entry, port: PORT, service: SERVICE, firstSeen: f1First, lastSeen: f1Last, installedVersion: f1Version, title: f1Entry.title });
  scan.software({ host: HOST, product: PRODUCT, vendor: VENDOR, version: f1Version, installedOn: installedBefore(ctx, 'f1', f1First, approvedAt) });
  const f1Intel = scan.intel(f1Entry);

  // ---- the exception ticket (the clue): approved and valid in A; in B only a request, still open.
  const exTicket = isAccept
    ? writeRiskException(ctx, f1Entry, HOST, SEGMENT, approvedAt, expires)
    : log.ticket({
        TicketId: log.nextTicketId('REQ'),
        Type: 'Service request',
        Title: `Risk exception request: ${PRODUCT} on ${HOST} (not yet approved)`,
        Requester: ctx.pick.person({ dept: 'IT', working: false }).upn,
        AssignedTo: 'Security - Vulnerability Management',
        Status: 'Open',
        Created: now - 5 * DAY,
        Scope: HOST,
        Details: `Request for a risk exception for ${f1Entry.id} on ${HOST}: the vendor has ended support and published no fix. The board has not approved it: no control limits who can reach the controller yet. Until it is approved, no exception exists for this host.`,
      });

  // ---- F2 the decoy: an approved exception that expired, on a flaw the vendor has since fixed
  const f2 = scan.finding(oldRun, { host: PRINT, entry: f2Entry, firstSeen: f2First, lastSeen: lastSeen(oldRun, 'f2'), installedVersion: versionOf('f2', f2Entry), title: f2Entry.title });
  scan.software({ host: PRINT, product: f2Entry.product, vendor: f2Entry.vendor, version: versionOf('f2', f2Entry), installedOn: installedBefore(ctx, 'f2', f2First, f2Approved) });
  const f2Ticket = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Risk exception: ${f2Entry.product} on ${PRINT} (no vendor fix at the time)`,
    Requester: ctx.pick.person({ dept: 'IT', working: false }).upn,
    AssignedTo: 'Security - Vulnerability Management',
    Status: 'Approved',
    Created: f2Approved,
    WindowStart: f2Approved,
    WindowEnd: f2Expired,
    Scope: PRINT,
    Details: `Approved risk exception for ${f2Entry.id} on ${PRINT}: at the time the vendor had published no fix. Compensating measure: the service is reachable over the network only from the print VLAN. Time-boxed: valid until ${ymd(f2Expired)}, then it must be reviewed.`,
  });
  const f2Intel = scan.intel(f2Entry);

  // ---- F3 Medium, F4 High (standard cycle), F5 Low: clear-cut, from the credentialed run
  const f3 = scan.finding(oldRun, { host: DB, entry: f3Entry, firstSeen: f3First, lastSeen: lastSeen(oldRun, 'f3'), installedVersion: versionOf('f3', f3Entry), title: f3Entry.title });
  const f4 = scan.finding(oldRun, { host: APP, entry: f4Entry, firstSeen: f4First, lastSeen: lastSeen(oldRun, 'f4'), installedVersion: versionOf('f4', f4Entry), title: f4Entry.title });
  const f5 = scan.finding(oldRun, { host: BUILD, entry: f5Entry, firstSeen: f5First, lastSeen: lastSeen(oldRun, 'f5'), installedVersion: versionOf('f5', f5Entry), title: f5Entry.title });
  for (const [label, host, e, first] of [['f3', DB, f3Entry, f3First], ['f4', APP, f4Entry, f4First], ['f5', BUILD, f5Entry, f5First]] as const)
    scan.software({ host, product: e.product, vendor: e.vendor, version: versionOf(label, e), installedOn: installedBefore(ctx, label, first) });

  // ---- controls: three rows in both twins. The first is the clue: the same ACL id either names the controller (A: in effect)
  // or belongs to the OT controller VLAN and is not applied to it (B).
  const crng = sharedRng(ctx, 'controls');
  const verified = now - crng.int(2, 4) * DAY;
  const ids = new Set<string>();
  const nextId = (kind: 'ACL' | 'CFG'): string => {
    let id: string;
    do id = `CTL-${kind}-${crng.int(1000, 9999)}`;
    while (ids.has(id));
    ids.add(id);
    return id;
  };
  const aclId = nextId('ACL');
  const decoyAclId = nextId('ACL');
  const cfgId = nextId('CFG');
  const acl = log.control(
    isAccept
      ? { ControlId: aclId, Kind: 'ACL', Target: `${HOST} control interface (${PORT}/tcp)`, Mode: 'block', CoversVulnId: f1Entry.id, Evidence: `Verified ${ymd(verified)}: only the OT management hosts and the authorised scanner (${SCANNER}) may reach ${PORT}/tcp on ${HOST}; every other source is denied (see FirewallLogs).` }
      : { ControlId: aclId, Kind: 'ACL', Target: `OT controller VLAN ACL (${PORT}/tcp)`, Mode: 'block', CoversVulnId: f1Entry.id, Evidence: `Verified ${ymd(verified)} for the controllers in the OT controller VLAN: only the OT management hosts and the authorised scanner (${SCANNER}) may reach ${PORT}/tcp; every other source is denied. ${HOST} is not in scope of this rule: it is not a member of that VLAN and the rule is not applied to it.` },
  );
  const decoyAcl = log.control({ ControlId: decoyAclId, Kind: 'ACL', Target: `${APP} application port`, Mode: 'detect', CoversVulnId: f4Entry.id, Evidence: 'Rule logs matches and blocks nothing; it has not been verified as enforcing.' });
  log.control({ ControlId: cfgId, Kind: 'Config', Target: `${HOST} web console`, Mode: 'block', CoversVulnId: '', Evidence: `Verified ${ymd(verified)}: the web console requires a changed default password. It does not limit who can reach the ${PORT}/tcp control interface.` });

  // ---- firewall sessions to the control interface: the same six sessions (sources, times, ports) in both twins; only the
  // corporate ones differ (denied in A, allowed in B).
  const frng = sharedRng(ctx, 'ctl-firewall');
  const mgmtIps = MGMT_HOSTS.map((h) => String(log.deviceRef(h).row.IPAddress));
  const scannerIp = String(log.deviceRef(SCANNER).row.IPAddress);
  const srng = sharedRng(ctx, 'ctl-scanner'); // its own stream: the other sessions are drawn exactly as before
  log.fw({
    TimeGenerated: Math.max(newRun.started, f1Last - srng.int(0, 2) * MIN), // the sweep's connection that read the banner: at the finding's LastSeen (up to 2 minutes before), inside the run
    Direction: 'Internal',
    Action: 'Allow',
    SourceIP: scannerIp,
    SourcePort: srng.int(30000, 60000),
    DestinationIP: hostIp,
    DestinationPort: PORT,
    RuleName: 'allow-scanner',
    BytesSent: srng.int(60, 300),
    BytesReceived: srng.int(0, 400),
    SessionDurationSec: srng.int(0, 2),
  });
  // The corporate sources are Engineering staff laptops outside the OT management range (a plausible reason to try a lab controller), not random departments.
  const workstationIps = (depts?: readonly string[]): string[] => world.people.filter((p) => depts === undefined || depts.includes(p.department)).map((p) => ctx.idx.deviceOf(p).ip).filter((ip) => /^\d+\.\d+\.(2\d|3\d)\.\d+$/.test(ip));
  const engineering = workstationIps(['Engineering']);
  const corp = frng.sample(engineering.length >= 3 ? engineering : workstationIps(), 3);
  const mgmtRows = [0, 1, 2].map((i) =>
    log.fw({
      TimeGenerated: now - frng.int(1, 6) * DAY - frng.int(0, 20) * HOUR - frng.int(0, 3599) * 1000,
      Direction: 'Internal',
      Action: 'Allow',
      SourceIP: mgmtIps[i % mgmtIps.length],
      SourcePort: frng.int(49152, 65000),
      DestinationIP: hostIp,
      DestinationPort: PORT,
      RuleName: 'allow-lab-ot-mgmt',
      BytesSent: frng.int(1200, 9000),
      BytesReceived: frng.int(8000, 400_000),
      SessionDurationSec: frng.int(5, 600),
    }),
  );
  const corpRows = corp.map((src) => {
    const t = now - frng.int(1, 6) * DAY - frng.int(0, 20) * HOUR - frng.int(0, 3599) * 1000;
    const port = frng.int(49152, 65000);
    const sent = frng.int(600, 4000);
    const received = frng.int(2000, 90_000);
    const duration = frng.int(10, 900);
    return log.fw({
      TimeGenerated: t,
      Direction: 'Internal',
      Action: isAccept ? 'Deny' : 'Allow',
      SourceIP: src,
      SourcePort: port,
      DestinationIP: hostIp,
      DestinationPort: PORT,
      RuleName: isAccept ? 'deny-lab-controller-nonadmin' : 'allow-lab-corp-any',
      BytesSent: isAccept ? 0 : sent,
      BytesReceived: isAccept ? 0 : received,
      SessionDurationSec: isAccept ? 0 : duration,
    });
  });

  // ---- noise, tickets, calendar, unrelated updates
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['FS02', 'DC01', 'DC02'] },
      { run: newRun, hosts: ['SCCM01', 'BKP01', 'ADCONNECT01'] },
    ],
    [f1Entry, f2Entry, f3Entry, f4Entry, f5Entry],
  );
  writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'DC02', 'SCCM01', 'BKP01', 'ADCONNECT01'], 2, sharedRng(ctx, 'unrelated-patches'));
  sizeRunToHosts(ctx, oldRun);
  sizeRunToHosts(ctx, newRun);
  oldRun.row.row.TargetsPlanned = Number(oldRun.row.row.TargetsScanned); // the older run reached everything it planned; only the sweep missed targets

  // ---- the truth (derived from the policy, the calendar, the dates and the rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const f1Deadline = slaDeadline('high', f1First);
  const f2Deadline = slaDeadline('medium', f2First);
  const f1Reasons = isAccept ? (['approved-exception', 'no-vendor-fix', 'compensating-control-verified'] as const) : (['no-vendor-fix', 'control-not-covering'] as const);

  const f1Spec: FindingSpec = isAccept
    ? spec(f1, {
        truth: { decision: 'accept', schedule: 'none', slaLatest: 'none', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(HOST, { packageBasis: false, exception: true, control: true }), f1Reasons) },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'approved-exception',
            label: `An approved risk exception for ${HOST} is in Tickets and has not expired`,
            why: `Tickets has an approved risk exception for ${f1Entry.id} on ${HOST} (Status Approved, approved ${ymd(approvedAt)}, valid until ${ymd(expires)}): the vendor has ended support and published no fix (VulnIntel VendorFix false), and the compensating measure is that only the ${SEGMENT} can reach the controller. The policy lets an approved, unexpired exception allow accept; note the expiry date and re-assess then.`,
            rows: [exTicket],
          },
          {
            id: 'no-vendor-fix',
            label: 'The vendor has ended support and published no fix for the controller flaw',
            why: `VulnIntel shows VendorFix false for ${f1Entry.id}: there is nothing to patch, in this case and in its twin. That makes the exception, the control and the firewall data the whole decision.`,
            rows: [f1Intel],
          },
          {
            id: 'isolation-in-effect',
            label: `The isolation the exception relies on is in effect: a block-mode ACL names ${HOST} and FirewallLogs show only the OT management hosts and the scanner reaching it`,
            why: `The exception counts only while its control is in effect (the policy row on no vendor fix). ControlInventory has ${aclId}: an ACL on ${HOST} ${PORT}/tcp, Mode block, CoversVulnId ${f1Entry.id}, verified ${ymd(verified)}. FirewallLogs confirm it: the ${mgmtRows.length} sessions from the OT management hosts are allowed, and so is the one short session from ${SCANNER}, the authorised scanner, during the newer sweep (a few hundred bytes, rule allow-scanner: the sweep that read the banner), and the ${corpRows.length} from corporate workstations (Engineering staff laptops outside the OT management range) are denied (rule deny-lab-controller-nonadmin). So accept is right, and no schedule applies: there is no fix to deploy.`,
            rows: [acl, ...corpRows], // only rows that differ between the twins: the management and scanner sessions are the same in B, so pinning them would prove nothing
          },
        ],
      })
    : spec(f1, {
        truth: { decision: 'mitigate', schedule: 'next-window', slaLatest: 'next-window', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(HOST, { packageBasis: false, exception: false, control: false }), f1Reasons), mitigation: [aclId] },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'no-approved-exception',
            label: `No approved exception exists for ${HOST}: the only request is still open`,
            why: `Tickets shows only a request for a risk exception for ${f1Entry.id} on ${HOST}, Status Open: the board has not approved it because nothing limits who can reach the controller yet, and VulnIntel shows VendorFix false, so there is no patch either. With no valid exception, accept is not allowed: the policy says to put the system behind a control that blocks the path by the deadline (High: 30 days from first detection, due ${ymd(f1Deadline)}, end of day).`,
            rows: [exTicket],
          },
          {
            id: 'no-vendor-fix',
            label: 'The vendor has ended support and published no fix for the controller flaw',
            why: `VulnIntel shows VendorFix false for ${f1Entry.id}: there is nothing to patch, in this case and in its twin. That makes the exception, the control and the firewall data the whole decision.`,
            rows: [f1Intel],
          },
          {
            id: 'acl-not-covering',
            label: `The ACL exists for the OT controller VLAN but is not applied to ${HOST}`,
            why: `ControlInventory has ${aclId}: an ACL for the OT controller VLAN (Mode block, CoversVulnId ${f1Entry.id}), but its Evidence says ${HOST} is not in scope of the rule. It is the control that would block the path once the host is moved behind it, so it is the control to name; today it protects this host not at all.`,
            rows: [acl],
          },
          {
            id: 'corporate-reach',
            label: `Corporate workstations are allowed to the control interface`,
            why: `FirewallLogs show ${corpRows.length} sessions from corporate workstations (Engineering staff laptops outside the OT management range) allowed to ${HOST} ${PORT}/tcp (rule allow-lab-corp-any), next to the ${mgmtRows.length} from the OT management hosts and the one from ${SCANNER}, the scanner: the vulnerable path is open to a whole corporate VLAN. Put the host behind the ACL in the next maintenance window (${ymd(cal.next.start)}), which ends before the deadline (${ymd(f1Deadline)}), then raise the risk exception.`,
            rows: [...corpRows], // the allowed corporate sessions differ from A's denied ones; the management and scanner sessions are the same in A
          },
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'], contradicting: contradictionsFor(f2Entry, facts(PRINT), ['sla-deadline']) },
      weight: 1,
      evidence: [
        {
          id: 'expired-exception',
          label: `The exception on ${PRINT} expired ${ymd(f2Expired)} and the vendor has since published a fix`,
          why: `Tickets has an approved exception for ${f2Entry.id} on ${PRINT}, but it was valid only until ${ymd(f2Expired)} and the case date is later: an expired exception no longer allows accept. It was granted while the vendor had no fix; VulnIntel now shows VendorFix true (fixed in ${f2Entry.fixedVersion}), so patch it. Its Medium deadline (90 days from first detection, due ${ymd(f2Deadline)}, end of day) is after the next window and before the standard cycle: the next window.`,
          rows: [f2Ticket, f2Intel],
        },
      ],
    }),
    spec(f3, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f3Entry, facts(DB), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f4, {
      truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['control-not-covering', 'sla-deadline'], contradicting: contradictionsFor(f4Entry, facts(APP), ['control-not-covering', 'sla-deadline']) },
      weight: 1,
      evidence: [
        {
          id: 'detect-only-acl',
          label: `The ACL that names this vulnerability is in detect mode on ${APP}`,
          why: `ControlInventory lists ${decoyAclId} for ${f4Entry.id}, but its Mode is detect: it logs matches and blocks nothing, so it is not a compensating control. The High finding was first detected ${Math.round((now - f4First) / DAY)} days ago: its 30-day deadline (${ymd(slaDeadline('high', f4First))}, end of day) is after the standard cycle (${ymd(cal.cycle.start)}), so it goes in the standard cycle.`,
          rows: [decoyAcl],
        },
      ],
    }),
    spec(f5, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f5Entry, facts(BUILD), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
  ];

  const ids6 = { f1: f1.findingId, f2: f2.findingId, f3: f3.findingId, f4: f4.findingId, f5: f5.findingId };
  const owners = ownersOf(ctx, [HOST, PRINT, DB, APP, BUILD]);
  const ownerNames = [...new Set([...owners, 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const f1Age = Math.round((now - f1First) / DAY);

  const briefing = `${world.org.name}: review of the latest scan results for a laboratory process controller and the internal servers in scope (two scan runs, the newer one an unauthenticated sweep that did not reach every target). Decide for each worklist finding whether to patch, mitigate, accept or dismiss it, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch, ticket, firewall and control data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'A vendor that has ended support publishes no fix, so patch is not on the table for the headline. Which tables show whether someone has formally accepted the risk, and what actually limits who can reach the controller?';
  const second = 'Tickets holds exception tickets (read Status and the expiry date) and ControlInventory lists the controls (read Mode, CoversVulnId and what the Evidence says the rule applies to). FirewallLogs shows who really reached the control interface. Then check the policy rule on a vendor with no fix.';

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal, [NO_FIX_ROW]),
    findings,
    constraints: cal.constraints,
    idealOrder: isAccept ? [ids6.f2, ids6.f4, ids6.f3, ids6.f5] : [ids6.f1, ids6.f2, ids6.f4, ids6.f3, ids6.f5],
    tiers: isAccept ? [[ids6.f2], [ids6.f4], [ids6.f3, ids6.f5]] : [[ids6.f1, ids6.f2], [ids6.f4], [ids6.f3, ids6.f5]],
    hints: [
      lead,
      second,
      isAccept
        ? `The exception ticket for ${HOST} is approved and not expired, the ACL in ControlInventory names the host in block mode, and FirewallLogs show the corporate sources denied: the exception's own condition is met, so accept it and note when it expires. Check the exception on the print server too.`
        : `The only exception ticket for ${HOST} is an open request, the ACL in ControlInventory belongs to the OT controller VLAN and is not applied to the host, and FirewallLogs show corporate workstations allowed to its control port: no exception is valid, so put the host behind that ACL before the deadline.`,
    ],
    solution: [
      {
        title: 'What did the scanner find on the controller and the servers?',
        kql: `VulnFindings\n| where DeviceName in ("${HOST}", "${PRINT}", "${DB}", "${APP}", "${BUILD}")\n| project FindingId, DeviceName, VulnId, Title, Severity, CvssBase, Port, DetectedVersion, FirstSeen, ScanRunId, Evidence, RecordId`,
        why: 'A High remote flaw on the controller, found by the newer unauthenticated sweep from the service banner; its Evidence says no vendor fix is available. The other findings come from the older credentialed run.',
      },
      {
        title: 'What does the intel say: is there a vendor fix?',
        kql: `VulnIntel\n| where VulnId in ("${f1Entry.id}", "${f2Entry.id}")\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, RecordId`,
        why: `The controller flaw has VendorFix false in both twins (no Sim-KEV listing, a low Sim-EPSS): the intel does not decide this case. The print server flaw has VendorFix true now.`,
      },
      {
        title: 'Which risk exceptions exist, for what, and until when?',
        kql: 'Tickets\n| where Title has "Risk exception"\n| project TicketId, Title, Status, Created, WindowStart, WindowEnd, Scope, Details, RecordId',
        why: isAccept ? `One approved exception for ${HOST}, valid until ${ymd(expires)}, and one approved exception for ${PRINT} that expired ${ymd(f2Expired)}.` : `Only an open request for ${HOST} (no approved exception) and the approved exception for ${PRINT} that expired ${ymd(f2Expired)}.`,
      },
      {
        title: 'Which controls exist, and what do they cover?',
        kql: 'ControlInventory\n| project ControlId, Kind, Target, Mode, CoversVulnId, Evidence, RecordId',
        why: isAccept ? `The ACL names ${HOST} in block mode and covers the headline; the detect-mode ACL names the application server finding and counts for nothing; the console hardening is on another path.` : `The ACL is in block mode for the OT controller VLAN and its Evidence says ${HOST} is not in scope; the detect-mode ACL names the application server finding and counts for nothing; the console hardening is on another path.`,
      },
      {
        title: 'Who reached the control interface, and what did the firewall do?',
        kql: `FirewallLogs\n| where DestinationIP == "${hostIp}" and DestinationPort == ${PORT}\n| project TimeGenerated, Direction, Action, SourceIP, DestinationPort, RuleName, RecordId\n| sort by TimeGenerated desc`,
        why: isAccept ? 'The OT management hosts and the authorised scanner (one short session during the newer sweep) are allowed; the corporate workstations are denied (rule deny-lab-controller-nonadmin).' : 'The OT management hosts and the scanner are allowed, and so are corporate workstations (rule allow-lab-corp-any): the isolation does not cover this host.',
      },
      {
        title: 'What is the controller and who owns it?',
        kql: `DeviceInfo\n| where DeviceName == "${HOST}"\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, IPAddress, RecordId`,
        why: 'A laboratory process controller whose vendor ended support; not reachable from the internet; owned by Lab Engineering.',
      },
      {
        title: 'When are the change windows and the freeze?',
        kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, RecordId\n| sort by WindowStart asc',
        why: 'The next window and the standard cycle are the dates each deadline is compared with.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: ['owner', ...ownerNames.map((o) => o.toLowerCase())] },
      {
        id: 'risk',
        text: isAccept ? 'States the risk in plain words: the vendor has ended support, no fix will come, and the controller is reachable only from the OT management hosts and the authorised scanner, which is the condition of the approved exception.' : 'States the risk in plain words: the vendor has ended support, no fix will come, and corporate workstations can reach the controller, with no approved exception.',
        keywords: isAccept ? ['end of support', 'no fix', 'exception', 'isolat', 'management'] : ['end of support', 'no fix', 'corporate', 'reach', 'exposed'],
      },
      {
        id: 'action',
        text: isAccept ? `Recommends accepting the controller finding under the approved exception, with its expiry date (${ymd(expires)}) to re-assess, patching the print server (its exception expired) and the standard cycle for the rest.` : 'Recommends moving the controller behind the OT controller VLAN ACL in the next window, raising a risk exception once it is in effect, patching the print server (its exception expired) and the standard cycle for the rest.',
        keywords: isAccept ? ['accept', 'expiry', 're-assess', 'review', 'print server'] : ['mitigate', 'acl', 'isolate', 'next window', 'print server'],
      },
      { id: 'date', text: 'Gives dates or deadlines and ties them to the policy.', keywords: ['30 days', 'deadline', 'sla', 'window', 'expir'] },
    ],
    explanation: isAccept
      ? [
          `The headline is a High (30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day) in the firmware of a laboratory controller whose vendor has ended support: VulnIntel shows VendorFix false, so there is nothing to patch and nothing to schedule. The deciding clue is the pair of rows the policy asks for. Tickets has an approved risk exception for ${HOST}, not yet expired (valid until ${ymd(expires)}); and the control it rests on is in effect: ControlInventory shows ${aclId} in block mode naming ${HOST}, and FirewallLogs show only the OT management hosts and the scanner allowed, the corporate workstations denied. Accept, and note the expiry date for re-assessment.`,
          `The twin has the same flaw, the same intel and the same host, but its only exception ticket is an open request and its ACL belongs to the OT controller VLAN without covering the host (corporate workstations are allowed through). "Can't patch" is not "nothing to do": it means accept (under a valid exception and a control in effect) or isolate.`,
          `The decoys are in Tickets and ControlInventory: an approved exception on the print server that expired ${ymd(f2Expired)}, for a flaw the vendor has since fixed (VulnIntel VendorFix true): accept no longer applies, and the Medium deadline (90 days from first detection, due ${ymd(f2Deadline)}) is after the next window and before the standard cycle: patch in the next window. A detect-mode ACL names the application server finding but blocks nothing, and a console-hardening control is on another path. The remaining findings follow the SLA table (standard cycle). Scanning an OT controller needs care: schedule the sweep with the lab owner and keep it non-intrusive (version and banner checks, no exploit tests), because a fragile controller can fail under an aggressive scan.`,
        ]
      : [
          `The headline is a High (30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day) in the firmware of a laboratory controller whose vendor has ended support: VulnIntel shows VendorFix false, so patch is not possible. The deciding clue is that no exception is valid and no isolation is in effect. Tickets shows only an open request for an exception; ControlInventory has ${aclId} in block mode, but for the OT controller VLAN, and its Evidence says ${HOST} is not in scope; FirewallLogs show corporate workstations allowed to the control interface. The policy row on no vendor fix says what to do: put the host behind a control that blocks the path before the deadline, record mitigate naming that control, schedule the window of the change (the next window, ${ymd(cal.next.start)}, which ends before the deadline), and raise a risk exception once it is in effect.`,
          `The twin has the same flaw, the same intel and the same host, but an approved, unexpired exception and an ACL in effect for the host: there the answer is accept. Accept here would leave the controller open to the corporate network under no valid exception; patch is impossible; and an emergency change is not needed because the High deadline falls after the next window.`,
          `The decoys are in Tickets and ControlInventory: an approved exception on the print server that expired ${ymd(f2Expired)}, for a flaw the vendor has since fixed: accept no longer applies, patch it in the next window (Medium: due ${ymd(f2Deadline)}). A detect-mode ACL names the application server finding but blocks nothing, and a console-hardening control is on another path. The remaining findings follow the SLA table (standard cycle). Two changes (the controller and the print server) fill the next window's capacity. Scanning an OT controller needs care: schedule the sweep with the lab owner and keep it non-intrusive (version and banner checks, no exploit tests), because a fragile controller can fail under an aggressive scan.`,
        ],
    pitfalls: isAccept
      ? [
          'Reading "no vendor fix" as "nothing to do" or as a reason to patch: with a valid exception and a control in effect the answer is accept, with the expiry noted.',
          'Taking an exception ticket as valid without reading its Status and its expiry date: the print server\'s approved exception expired and the flaw is fixed now, so it must be patched.',
          `Accepting on the ticket alone: this exception's approval names the isolation it relies on (only ${SEGMENT} may reach the controller), so it counts only while that isolation is in effect for ${HOST}: ControlInventory block mode naming the host, and FirewallLogs.`,
          'Recording mitigate: the exception is in force and its control is in effect, so the finding is accepted, with the control as the exception\'s condition. Mitigate is for a control that is still to be applied, when no valid exception exists.',
          'Scheduling a change for an accepted finding: there is no fix to deploy.',
          'Treating the detect-mode ACL on the application server as cover for that finding.',
        ]
      : [
          'Reading "no vendor fix" as "nothing to do" or as an automatic accept: without an approved exception the policy says to isolate.',
          'Believing an ACL exists for the host because ControlInventory has a block-mode row naming the vulnerability: read what the Evidence says it applies to, and check FirewallLogs for who is actually allowed through.',
          'Treating the open exception request as an approved exception.',
          'Choosing mitigate with no control, or the wrong one: name the OT controller VLAN ACL, the control that blocks the path once the host is behind it.',
          'Taking an exception ticket on the print server at face value: it expired and the flaw is fixed, so patch it.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier1',
  title: TITLE,
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.4', '2.5', '4.1'],
  kind: 'vuln',
};

export const legacyAccept: VulnTemplate = {
  ...COMMON,
  id: 'vm-legacy-accept',
  twin: 'vm-legacy-isolate',
  lesson:
    'Tickets shows an approved, unexpired risk exception for the lab controller whose vendor has ended support (VulnIntel: no fix), and the isolation it relies on is in effect: ControlInventory has an ACL in block mode naming the host and FirewallLogs show the corporate workstations denied. Accept it and note the expiry. The twin has the same flaw but only an open exception request, and an ACL that does not cover the host.',
  build: (ctx) => build('accept', ctx),
};

export const legacyIsolate: VulnTemplate = {
  ...COMMON,
  id: 'vm-legacy-isolate',
  twin: 'vm-legacy-accept',
  lesson:
    'Tickets shows no approved exception for the lab controller whose vendor has ended support (VulnIntel: no fix; only an open request), ControlInventory has an ACL for the OT controller VLAN that does not cover the host, and FirewallLogs show corporate workstations allowed to it: nothing is in effect, so put the host behind that ACL in the next window (mitigate, naming it) and raise the exception. The twin has an approved exception and the isolation in effect.',
  build: (ctx) => build('isolate', ctx),
};
