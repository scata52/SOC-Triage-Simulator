// Twin T11 (DESIGN section 4): a High remote code execution flaw in the optional scripting console of a
// line-of-business application on APP01. The headline, the host, the versions, the dates, the installation
// record ("installed with the default options") and SoftwareInventory are identical in both twins. What
// differs is whether anything uses the console.
//
// vm-unused-service (A): Tickets holds the application owner's confirmation that no business process uses the
// console, and FirewallLogs show no session to its port in two weeks except the vulnerability scanner's own
// connections (a scanner connecting is not use). The one job that talks to the application, a twice-weekly
// export from BUILD01, calls the API on 443/tcp. The policy row on unused components says what to do: remove
// or disable the component (avoid), do not patch the product. Patch is not in alsoAccept: DESIGN 5.1 makes
// avoid -> patch a near miss (the flaw is fixed, the attack surface stays) and a lesson finding needs full credit.
//
// vm-needed-service (B): the same sessions from the same job at the same times, but to the console's port, and
// Tickets holds the process record that names the stock export that depends on the console. Avoid would stop
// the export (DESIGN 5.1: truth patch, given avoid is 0): patch it in the next window.
//
// Decoys, identical in both twins: the scanner's own connections to the console port (they look like use), the
// installation record (an optional, default-installed component is not unused by that fact alone), a second
// unused console on DEVBOX01 (avoid in both twins, so neither "avoid every console" nor "patch every console"
// is right in either twin) and a console on SQL01 that the database team uses (patch in both twins).
// The firewall log reaches back 13 days, more than twice the longest cycle the owners document.
// One builder, the clue is a parameter. Everything else is chosen from the catalogue seed, not from the template id.

import { DAY, MIN } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, ReasonCode, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  dayStart,
  FICTIONAL_OS,
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
  shapedOn,
  sharedRng,
  sizeRunToHosts,
  slaDeadline,
  withEpss,
  withFix,
  withPublished,
  writeChangeTickets,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  lowered,
  verbsOn,
  VERBS_AVOID,
  VERBS_PATCH,
} from './common.ts';

type Variant = 'unused' | 'needed';

const APP = 'APP01'; // findings[0] in both twins: the clue
const DEV = 'DEVBOX01'; // findings[1]: a second unused console (avoid in both twins)
const DB = 'SQL01'; // findings[2]: a console the database team uses (patch in both twins)

const JUMP = 'JUMP01';
const JOB = 'BUILD01'; // the host the twice-weekly export job runs on
const SCANNER = 'SCAN01';
const PORT = 8443; // the console's port on every host that has one
const API_PORT = 443; // the application's API, where the export job goes in A
const COMPONENT = 'scripting console';
const SERVICE = 'https-admin';

const TITLE = 'Scan review: optional admin consoles and internal servers';

// The template-local policy row (identical in both twins): what "unused" means, and what to do with an unused component.
const UNUSED_ROW: [string, string] = [
  'Unused component',
  'When the vulnerable part of a product is an optional component that is not used, remove or disable the component instead of patching the product: record the finding as avoid, schedule the change in the window in which it is made (that window must end before the deadline), and rescan to close the finding. Patching the product would fix this flaw but leave the unused component, and its attack surface, in place. A component is unused only when both hold: the owner of the system confirms in Tickets that no business process uses it, and FirewallLogs show no session to its port, other than connections from the vulnerability scanner itself, across a period at least twice as long as the longest cycle of any process the owner documents for the product (read the earliest and the latest TimeGenerated of FirewallLogs to see what period it covers). That a component was installed by default (SoftwareInventory, Tickets) does not make it unused. A component that a business process uses is not removed: patch it by the standard rules.',
];

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const unused = variant === 'unused'; // A: nothing uses the headline's console
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'unused-service');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const allIds = catalogue.entries.map((e) => e.id);
  const versionOf = (label: string, e: CatalogueEntry): string => versionBelow(sharedRng(ctx, `version/${label}`), e.fixedVersion);

  // ---- two runs: an older complete credentialed run of the servers, a newer unauthenticated sweep that reads banners and did
  // not reach every target (the console on APP01 is found by its banner).
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 9 * DAY, targetsPlanned: 9, targetsScanned: 9 }); // sized to the devices that have a row
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Unauthenticated', started: now - 2 * DAY, targetsPlanned: 6, targetsScanned: 5 });
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // ---- dates (all relative to the case date, shared by the twins)
  const f1First = now - 22 * DAY; // High: due 30 days on, after the next window and before the standard cycle
  const f2First = oldRun.started; // High: due 30 days after the older run, after the standard cycle
  const f3First = now - 22 * DAY;
  const f4First = newRun.started; // the sweep is the first run to report the Medium on BUILD01
  const f5First = now - 20 * DAY;

  // ---- entries (twins share every choice)
  // `by` is the date the flaw must have been published by (default: the first detection); the banner-only Medium is published before the credentialed run, so that run's silence about it means something.
  const choose = (want: ShapeWant, first: number, epss: number, host: string, avoid: ReadonlySet<string> = new Set(), by: number = first): CatalogueEntry => {
    const candidates = free().filter(quiet);
    const known = candidates.filter((x) => x.published <= by);
    const base = rng.pick(known.length > 0 ? known : candidates);
    const dated = withPublished(base, Math.min(base.published, dayStart(by - DAY)), allIds);
    const e = shapedOn(dated, host, rng, want, avoid);
    used.add(base.id);
    used.add(e.id);
    return withEpss(withFix(e, rng), epss);
  };
  const consoleWant: ShapeWant = { classes: ['rce'], component: /^scripting console$/, min: 7, max: 8.9, network: true };
  const lower = (label: string) => lowerHalfEpss(rng.fork(label), 0.45);
  const f1Entry = choose(consoleWant, f1First, LOW_EPSS, APP);
  const avoid = new Set([f1Entry.product, 'Brackenridge DB Console']); // no "console console" in a title, no product twice
  const f2Entry = choose(consoleWant, f2First, lower('f2'), DEV, avoid);
  const f3Entry = choose(consoleWant, f3First, lower('f3'), DB, new Set([...avoid, f2Entry.product]));
  const rest = new Set([f1Entry.product, f2Entry.product, f3Entry.product]);
  let f4Entry = choose({ min: 4, max: 6.9, network: true }, f4First, lower('f4'), JOB, rest, oldRun.started);
  if (!/^\d+\.\d+\.\d+$/.test(f4Entry.fixedVersion)) f4Entry = { ...f4Entry, fixedVersion: `${rng.int(2, 9)}.${rng.int(2, 9)}.${rng.int(2, 9)}` };
  const f4Banner = versionBelow(rng, f4Entry.fixedVersion);
  const [fa, fb] = f4Entry.fixedVersion.split('.').map(Number);
  const f4Newer = `${fa}.${fb + rng.int(1, 2)}.${rng.int(0, 5)}`; // above the fix by its own version number (no backport)
  const f5Entry = choose({ max: 3.9 }, f5First, lower('f5'), JUMP, rest);

  // ---- the hosts: APP01, SQL01, BUILD01, JUMP01 are the shared world's; DEVBOX01 is authored for the case (identical in both twins)
  scopeSharedHost(ctx, { name: DEV, role: 'Developer test server (no production data)', os: FICTIONAL_OS, owner: 'Engineering', criticality: 'Low' }, 'devbox');
  const appIp = String(log.deviceRef(APP).row.IPAddress);
  const devIp = String(log.deviceRef(DEV).row.IPAddress);
  const dbIp = String(log.deviceRef(DB).row.IPAddress);
  const appOwner = String(log.deviceRef(APP).row.Owner);
  const devOwner = String(log.deviceRef(DEV).row.Owner);

  // ---- the findings. The console on APP01 is read from its banner (newer sweep); the others come from the credentialed run.
  const f1Version = versionOf('f1', f1Entry);
  const f4Intel = scan.intel(f4Entry);
  const banner = `Remote check: the https service on ${PORT}/tcp announces "${f1Entry.product.replace(/\s+/g, '-')}-Console/${f1Version}". Version taken from the banner only; installed packages were not inspected. Fixed in ${f1Entry.fixedVersion}.`;
  const f1Last = Math.max(lastSeen(newRun, 'f1'), newRun.started + 14 * MIN); // the banner is read by the scanner's connections at +3 and +14 minutes: LastSeen is not before them
  const f1 = scan.finding(newRun, { host: APP, entry: f1Entry, port: PORT, service: SERVICE, firstSeen: f1First, lastSeen: f1Last, installedVersion: f1Version, bannerVersion: f1Version, title: f1Entry.title, evidence: banner });
  const f2 = scan.finding(oldRun, { host: DEV, entry: f2Entry, firstSeen: f2First, lastSeen: lastSeen(oldRun, 'f2'), installedVersion: versionOf('f2', f2Entry), title: f2Entry.title });
  const f3 = scan.finding(oldRun, { host: DB, entry: f3Entry, firstSeen: f3First, lastSeen: lastSeen(oldRun, 'f3'), installedVersion: versionOf('f3', f3Entry), title: f3Entry.title });
  const f4 = scan.finding(newRun, { host: JOB, entry: f4Entry, port: 443, firstSeen: f4First, lastSeen: lastSeen(newRun, 'f4'), installedVersion: f4Newer, bannerVersion: f4Banner });
  const f5 = scan.finding(oldRun, { host: JUMP, entry: f5Entry, firstSeen: f5First, lastSeen: lastSeen(oldRun, 'f5'), installedVersion: versionOf('f5', f5Entry), title: f5Entry.title });

  // ---- SoftwareInventory: the product, and for the three console findings the optional component that came with it (the same rows in both twins)
  const installs = new Map<string, number>();
  const install = (label: string, host: string, e: CatalogueEntry, first: number, withComponent: boolean) => {
    const at = installedBefore(ctx, label, first);
    installs.set(label, at);
    const version = versionOf(label, e);
    scan.software({ host, product: e.product, vendor: e.vendor, version, installedOn: at });
    return withComponent ? scan.software({ host, product: `${e.product} ${COMPONENT} (optional component)`, vendor: e.vendor, version, installedOn: at }) : null;
  };
  const f1Comp = install('f1', APP, f1Entry, f1First, true)!;
  const f2Comp = install('f2', DEV, f2Entry, f2First, true)!;
  const f3Comp = install('f3', DB, f3Entry, f3First, true)!;
  const f4Soft = scan.software({ host: JOB, product: f4Entry.product, vendor: f4Entry.vendor, version: f4Newer, installedOn: installedBefore(ctx, 'f4', oldRun.started) }); // the release in use is above the fix, installed before the credentialed run
  install('f5', JUMP, f5Entry, f5First, false);

  // ---- tickets: the installation record (the same in both twins), the one record that differs, the two shared records of the other consoles
  const requester = () => ctx.pick.person({ dept: 'IT', working: false }).upn;
  const installRecord = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Installation record: ${f1Entry.product} on ${APP}`,
    Requester: requester(),
    AssignedTo: 'IT Infrastructure',
    Status: 'Closed',
    Created: installs.get('f1')!,
    Scope: APP,
    Details: `IT installed ${f1Entry.product} on ${APP} with the vendor's default options. The default install includes the optional ${COMPONENT} component (${PORT}/tcp); nobody selected it and it was not customised.`,
  });
  const clue = unused
    ? log.ticket({
        TicketId: log.nextTicketId('REQ'),
        Type: 'Service request',
        Title: `Owner confirmation: ${COMPONENT} of ${f1Entry.product} on ${APP} is not used`,
        Requester: requester(),
        AssignedTo: 'IT Service Management',
        Status: 'Approved',
        Created: now - 4 * DAY,
        Scope: APP,
        Details: `${appOwner}, the owner of ${APP}, confirms that no business process uses the ${COMPONENT} of ${f1Entry.product} on ${APP} (${PORT}/tcp): it came with the default install and nobody signs in to it. The one job that uses the product, the stock export (twice a week) from ${JOB}, calls the application's API on ${API_PORT}/tcp, not the console. The longest cycle of any process that uses the product is therefore 3 to 4 days.`,
      })
    : log.ticket({
        TicketId: log.nextTicketId('REQ'),
        Type: 'Service request',
        Title: `Process record: stock export from ${JOB} uses the ${COMPONENT} of ${f1Entry.product} on ${APP}`,
        Requester: requester(),
        AssignedTo: 'IT Service Management',
        Status: 'Approved',
        Created: now - 4 * DAY,
        Scope: APP,
        Details: `${appOwner}, the owner of ${APP}, records that the stock export (twice a week, every 3 to 4 days) runs from ${JOB} and calls the ${COMPONENT} of ${f1Entry.product} on ${APP} (${PORT}/tcp) to run its export script; the finance team relies on the export. Switching the console off stops the export. The longest cycle of any process that uses the product is therefore 3 to 4 days.`,
      });
  const f2Owner = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Owner confirmation: ${COMPONENT} of ${f2Entry.product} on ${DEV} is not used`,
    Requester: requester(),
    AssignedTo: 'IT Service Management',
    Status: 'Approved',
    Created: now - 6 * DAY,
    Scope: DEV,
    Details: `${devOwner}, the owner of ${DEV}, confirms that no process uses the ${COMPONENT} of ${f2Entry.product} on ${DEV} (${PORT}/tcp): it came with the default install. The only scheduled task of the product is its nightly cleanup, which runs on the host itself, so the longest cycle of any process that uses it is one day.`,
  });
  const f3Process = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Process record: database maintenance uses the ${COMPONENT} of ${f3Entry.product} on ${DB}`,
    Requester: requester(),
    AssignedTo: 'IT Service Management',
    Status: 'Approved',
    Created: now - 30 * DAY,
    Scope: DB,
    Details: `The database administration team runs its maintenance scripts through the ${COMPONENT} of ${f3Entry.product} on ${DB} (${PORT}/tcp) from their workstations, about twice a week; the monthly ledger close depends on them. Switching the console off stops the maintenance.`,
  });

  // ---- firewall sessions (the same times and sources in both twins). The export job reaches APP01 on the API port in A and on the
  // console port in B; the scanner's own connections to the console port and the database team's sessions are the same in both.
  const frng = sharedRng(ctx, 'sessions');
  const at = (days: number): number => now - days * DAY - frng.int(0, 30) * MIN;
  const jobIp = String(log.deviceRef(JOB).row.IPAddress);
  const scannerIp = String(log.deviceRef(SCANNER).row.IPAddress);
  const jobRows = [13, 10, 6, 3].map((d) => {
    const when = at(d);
    const [sent, received, duration, srcPort] = [frng.int(900, 6000), frng.int(20_000, 600_000), frng.int(20, 300), frng.int(49152, 65000)];
    return log.fw({ TimeGenerated: when, Direction: 'Internal', Action: 'Allow', SourceIP: jobIp, SourcePort: srcPort, DestinationIP: appIp, DestinationPort: unused ? API_PORT : PORT, RuleName: unused ? 'allow-app-api' : 'allow-app-admin', BytesSent: sent, BytesReceived: received, SessionDurationSec: duration });
  });
  const scannerRows = [0, 1].map((i) => {
    const when = newRun.started + (3 + i * 11) * MIN;
    const [sent, received, srcPort] = [frng.int(60, 300), frng.int(0, 400), frng.int(30000, 60000)];
    return log.fw({ TimeGenerated: when, Direction: 'Internal', Action: 'Allow', SourceIP: scannerIp, SourcePort: srcPort, DestinationIP: appIp, DestinationPort: PORT, RuleName: 'allow-scanner', BytesSent: sent, BytesReceived: received, SessionDurationSec: i });
  });
  // the older credentialed run also touched the console ports of the two other consoles (its own short connections, the same in both twins)
  const oldScan = (ip: string, i: number) => {
    const [sent, received, srcPort] = [frng.int(60, 300), frng.int(0, 400), frng.int(30000, 60000)];
    return log.fw({ TimeGenerated: oldRun.started + (4 + i * 9) * MIN, Direction: 'Internal', Action: 'Allow', SourceIP: scannerIp, SourcePort: srcPort, DestinationIP: ip, DestinationPort: PORT, RuleName: 'allow-scanner', BytesSent: sent, BytesReceived: received, SessionDurationSec: 0 });
  };
  const devScanRow = oldScan(devIp, 0);
  oldScan(dbIp, 1);
  // the database administration team: IT staff workstations
  const workstationIps = (dept?: string): string[] => world.people.filter((p) => dept === undefined || p.department === dept).map((p) => ctx.idx.deviceOf(p).ip).filter((ip) => /^\d+\.\d+\.(2\d|3\d)\.\d+$/.test(ip));
  const itIps = workstationIps('IT');
  const dbaIps = frng.sample(itIps.length >= 2 ? itIps : workstationIps(), 2);
  const dbaRows = [12.5, 9, 5.5, 2].map((d, i) => {
    const when = at(d);
    const [sent, received, duration, srcPort] = [frng.int(8000, 60_000), frng.int(30_000, 900_000), frng.int(600, 2400), frng.int(49152, 65000)];
    return log.fw({ TimeGenerated: when, Direction: 'Internal', Action: 'Allow', SourceIP: dbaIps[i % dbaIps.length], SourcePort: srcPort, DestinationIP: dbIp, DestinationPort: PORT, RuleName: 'allow-dba-console', BytesSent: sent, BytesReceived: received, SessionDurationSec: duration });
  });
  const earliest = [...jobRows, ...dbaRows].reduce((a, b) => (Number(a.row.TimeGenerated) <= Number(b.row.TimeGenerated) ? a : b));
  const latest = [...jobRows, ...dbaRows].reduce((a, b) => (Number(a.row.TimeGenerated) >= Number(b.row.TimeGenerated) ? a : b));

  // ---- noise, tickets, calendar, unrelated updates
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['FS02', 'DC01', 'DC02'] },
      { run: newRun, hosts: ['SCCM01', 'BKP01', 'ADCONNECT01'] },
    ],
    [f1Entry, f2Entry, f3Entry, f4Entry, f5Entry],
    { worklistSize: 5, extraNonWorklist: 1 }, // the credentialed run's "login worked" row on BUILD01
  );
  writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'DC02', 'SCCM01', 'BKP01', 'ADCONNECT01'], 2, sharedRng(ctx, 'unrelated-patches'));
  // the credentialed run reached BUILD01 (a local check row, no login failure): it did not report the Medium that the later sweep read from a banner
  const covered = scan.hygieneFinding(oldRun, JOB, 2);
  covered.row.row.Evidence = `Credentialed login to ${JOB} succeeded; local configuration check on 22/tcp (ssh): deprecated key exchange algorithms are enabled.`;
  sizeRunToHosts(ctx, oldRun);
  sizeRunToHosts(ctx, newRun);
  oldRun.row.row.TargetsPlanned = Number(oldRun.row.row.TargetsScanned); // the older run reached everything it planned; only the sweep missed targets

  // ---- the truth (derived from the policy, the calendar, the dates and the rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const notUnused: ReasonCode[] = ['unused-component'];
  const f1Deadline = slaDeadline('high', f1First);
  const f2Deadline = slaDeadline('high', f2First);
  const f3Deadline = slaDeadline('high', f3First);
  const f1Age = Math.round((now - f1First) / DAY);
  const reach = Math.floor((now - Number(earliest.row.TimeGenerated)) / DAY); // how far back the sessions written here go (the log reaches at least that far)
  const jobTimes = jobRows.map((r) => Number(r.row.TimeGenerated));
  const jobSpan = Math.round((Math.max(...jobTimes) - Math.min(...jobTimes)) / DAY);

  const f1Spec: FindingSpec = unused
    ? spec(f1, {
        truth: { decision: 'avoid', schedule: 'next-window', slaLatest: 'next-window', reasons: ['unused-component'], contradicting: contradictionsFor(f1Entry, facts(APP, { packageBasis: false }), ['unused-component']) },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'owner-says-unused',
            label: `The owner of ${APP} confirms in Tickets that nothing uses the ${COMPONENT}, and SoftwareInventory shows it is an optional component`,
            why: `Tickets has the owner's confirmation: no business process uses the ${COMPONENT} of ${f1Entry.product} on ${APP}, nobody signs in to it, and the longest cycle of any process that uses the product is 3 to 4 days. SoftwareInventory lists it as its own optional component (${f1Entry.product} ${COMPONENT}), and the installation record says it came with the default options. Installed by default does not by itself make it unused: the confirmation and the firewall log do.`,
            rows: [clue],
          },
          {
            id: 'installed-by-default',
            label: `SoftwareInventory and the installation record show the ${COMPONENT} is an optional component installed with the default options`,
            why: `SoftwareInventory lists the ${COMPONENT} as its own optional component of ${f1Entry.product} and the installation record in Tickets says it came with the vendor's default options: nobody chose it. That is the same in the twin and proves nothing either way: neither "optional, so unused" nor "installed, so needed" follows from it.`,
            rows: [f1Comp, installRecord],
          },
          {
            id: 'no-console-sessions',
            label: `FirewallLogs show no session to ${PORT}/tcp on ${APP} except two connections from the vulnerability scanner`,
            why: `FirewallLogs reach back ${reach} days or more, over twice the longest cycle the owner documents (3 to 4 days), and the only sessions to ${APP} on the console port ${PORT}/tcp are ${scannerRows.length} short connections from ${SCANNER}, the scanner itself (rule allow-scanner, a few hundred bytes): a scanner connecting is not use. The ${jobRows.length} sessions from ${JOB} every 3 to 4 days go to ${API_PORT}/tcp, the application's API (rule allow-app-api), not to the console. The policy row on unused components applies: avoid, not patch. Disable the component in the next maintenance window (${ymd(cal.next.start)}), which ends before the deadline (High: 30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day), and rescan to close the finding.`,
            rows: jobRows,
          },
        ],
      })
    : spec(f1, {
        truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'], contradicting: [...new Set([...contradictionsFor(f1Entry, facts(APP, { packageBasis: false }), ['sla-deadline']), ...notUnused])] },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'process-needs-console',
            label: `Tickets has the process record: the stock export depends on the ${COMPONENT}, though SoftwareInventory shows it was installed by default`,
            why: `Tickets has the owner's process record: the stock export (twice a week) from ${JOB} calls the ${COMPONENT} of ${f1Entry.product} on ${APP} (${PORT}/tcp), the finance team relies on it, and switching the console off stops it. SoftwareInventory lists the console as an optional component and the installation record says it came with the default options, but optional and default-installed do not mean unused: a business process uses it.`,
            rows: [clue],
          },
          {
            id: 'installed-by-default',
            label: `SoftwareInventory and the installation record show the ${COMPONENT} is an optional component installed with the default options`,
            why: `SoftwareInventory lists the ${COMPONENT} as its own optional component of ${f1Entry.product} and the installation record in Tickets says it came with the vendor's default options: nobody chose it. That is the same in the twin and proves nothing either way: neither "optional, so unused" nor "installed, so needed" follows from it.`,
            rows: [f1Comp, installRecord],
          },
          {
            id: 'regular-console-sessions',
            label: `FirewallLogs show regular sessions from ${JOB} to ${PORT}/tcp on ${APP}`,
            why: `FirewallLogs show ${jobRows.length} sessions from ${JOB} to ${APP} on ${PORT}/tcp, one every 3 to 4 days over ${jobSpan} days (rule allow-app-admin): the cycle in the process record. The two short connections from ${SCANNER} are the scanner, not use, but these are. The component is needed, so avoid would stop the export: patch it. The High deadline (30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day) is after the next window (${ymd(cal.next.start)}) and before the standard cycle: next window.`,
            rows: jobRows,
          },
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, {
      truth: { decision: 'avoid', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['unused-component'], contradicting: contradictionsFor(f2Entry, facts(DEV), ['unused-component']) },
      weight: 1,
      evidence: [
        {
          id: 'second-unused-console',
          label: `The owner of ${DEV} confirms its ${COMPONENT} is not used, and no session to it appears in FirewallLogs`,
          why: `Tickets has the owner's confirmation for ${f2Entry.product} on ${DEV} (the only scheduled task is a nightly cleanup, so the longest cycle is a day), and FirewallLogs, which reach back ${reach} days or more (from ${ymd(Number(earliest.row.TimeGenerated))} to ${ymd(Number(latest.row.TimeGenerated))} in the sessions below), hold no session to ${DEV} on ${PORT}/tcp except one short connection from ${SCANNER}, the scanner, during the older run. The policy row on unused components applies: avoid. Its High deadline (30 days from first detection, due ${ymd(f2Deadline)}, end of day) is after the standard cycle (${ymd(cal.cycle.start)}): disable it in the standard cycle.`,
          rows: [f2Owner, f2Comp, devScanRow, earliest, latest],
        },
      ],
    }),
    spec(f3, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'], contradicting: [...new Set([...contradictionsFor(f3Entry, facts(DB), ['sla-deadline']), ...notUnused])] },
      weight: 1,
      evidence: [
        {
          id: 'console-in-use',
          label: `The database team uses the ${COMPONENT} on ${DB}: a process record in Tickets and regular sessions in FirewallLogs`,
          why: `Tickets has the process record: the database administration team runs its maintenance scripts through the ${COMPONENT} of ${f3Entry.product} on ${DB} about twice a week, and the monthly ledger close depends on them. FirewallLogs show ${dbaRows.length} sessions from their workstations to ${DB} on ${PORT}/tcp (rule allow-dba-console), a few days apart. It is used, so patch it, not avoid it: the High deadline (30 days from first detection ${Math.round((now - f3First) / DAY)} days ago, due ${ymd(f3Deadline)}, end of day) is after the next window and before the standard cycle: next window.`,
          rows: [f3Process, f3Comp, ...dbaRows],
        },
      ],
    }),
    // the banner guess that the data disproves (the T7 pattern): a false positive in both twins
    spec(f4, {
      truth: {
        decision: 'false-positive',
        schedule: 'none',
        reasons: ['banner-only'],
        contradicting: [...new Set([...contradictionsFor(f4Entry, facts(JOB, { real: false, packageBasis: false, fixedBeforeScan: true }), ['banner-only']), 'backported-fix' as const])],
      },
      weight: 1,
      evidence: [
        {
          id: 'inventory-above-fix',
          label: `SoftwareInventory shows ${f4Entry.product} on ${JOB} above the fixed version, and the credentialed run reached the host`,
          why: `The sweep (${newRun.id}, Method Unauthenticated) read ${f4Banner} from a banner on ${JOB}, below the fix in ${f4Entry.fixedVersion}; its Evidence says the version was taken from the banner only. SoftwareInventory has ${f4Entry.product} ${f4Newer} on ${JOB}, installed ${ymd(Number(f4Soft.row.InstalledOn))}, before the older credentialed run (${oldRun.id}), which logged in to ${JOB} (a local check row, no authentication failure). The installed release is itself above the fix (VulnIntel), so this is no backport: the banner was a guess. Dismiss it and ask for a credentialed rescan.`,
          rows: [f4Soft, f4Intel, covered.row],
        },
      ],
    }),
    spec(f5, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f5Entry, facts(JUMP), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
  ];

  const ids = { f1: f1.findingId, f2: f2.findingId, f3: f3.findingId, f4: f4.findingId, f5: f5.findingId };
  const ownerNames = [...new Set([...ownersOf(ctx, [APP, DEV, DB, JOB, JUMP]), 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure

  const briefing = `${world.org.name}: review of the latest scan results for the application server, the developer test server, the database server and the other internal servers in scope (an older credentialed run and a newer unauthenticated sweep that did not reach every target). Three of the findings are in the optional admin console that comes with a product. Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, software inventory, ticket and firewall data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'Fixing a flaw in an optional component is not the only answer: sometimes the better one is to remove the component. What shows whether anything really uses it, and how long a period of records is enough to say so? Which tables show that?';
  const second = "FirewallLogs shows who connected to a port and for how long the log reaches back; a connection from the vulnerability scanner is not use. Tickets holds the installation record and what the owners say about use. SoftwareInventory shows what was installed. Then read the policy row on unused components.";

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal, [UNUSED_ROW]),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.f1, ids.f3, ids.f2, ids.f5],
    tiers: [[ids.f1, ids.f3], [ids.f2], [ids.f5]],
    hints: [
      lead,
      second,
      unused
        ? `The owner of ${APP} says nothing uses the console, and FirewallLogs show only the scanner on its port over two weeks; the export job goes to the application's API instead. Remove or disable the component (avoid), do not patch the product. The console on ${DB} is a different case: it is in use.`
        : `A job on ${JOB} calls the console on ${APP} every few days (FirewallLogs, and the process record in Tickets): the business needs it, so removing it would break the export. Patch it. The console on ${DEV} is the unused one.`,
    ],
    solution: [
      {
        title: 'What did the scanner find, and which run found it?',
        kql: `VulnFindings\n| where DeviceName in ("${APP}", "${DEV}", "${DB}", "${JOB}", "${JUMP}")\n| project FindingId, DeviceName, VulnId, Title, Severity, CvssBase, Port, DetectedVersion, FirstSeen, ScanRunId, Evidence, RecordId`,
        why: `Three High findings in the ${COMPONENT} of a product (on ${APP}, ${DEV} and ${DB}), a Medium on ${JOB} and a Low on ${JUMP}. The ones on ${APP} and ${JOB} were read from banners by the newer unauthenticated sweep, the others come from the older credentialed run.`,
      },
      {
        title: 'How were the runs made, and what did each cover?',
        kql: 'ScanRuns\n| project ScanRunId, Tool, Method, Vantage, Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `${newRun.id} is the newer unauthenticated sweep and did not reach every target; ${oldRun.id} is the older credentialed run.`,
      },
      {
        title: 'What is installed: the product, and the optional console as a component of it?',
        kql: `SoftwareInventory\n| where DeviceName in ("${APP}", "${DEV}", "${DB}", "${JOB}")\n| project DeviceName, Product, Vendor, Version, PackageSource, InstalledOn, RecordId`,
        why: 'Each of the three console hosts lists the product and, as its own row, the optional scripting console that came with it; the build server shows a release above the fix. The inventory is the same whichever way the console is used: it only shows what was installed.',
      },
      {
        title: 'What do the owners say: installation records, confirmations and process records?',
        kql: 'Tickets\n| where Title has "Installation record" or Title has "Owner confirmation" or Title has "Process record"\n| project TicketId, Type, Title, Status, Created, Scope, Details, RecordId\n| sort by Created asc',
        why: unused
          ? `The installation record for ${APP} (default options), the owner's confirmation that nothing uses the console on ${APP} and on ${DEV}, and the database team's process record for ${DB}.`
          : `The installation record for ${APP} (default options), the process record that names the stock export using the console on ${APP}, the owner's confirmation that nothing uses the console on ${DEV}, and the database team's process record for ${DB}.`,
      },
      {
        title: 'Who connected to the consoles, and from when to when does the log reach?',
        kql: `FirewallLogs\n| where DestinationIP in ("${appIp}", "${dbIp}", "${devIp}")\n| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Action, RuleName, BytesSent, BytesReceived, SessionDurationSec, RecordId\n| sort by TimeGenerated asc`,
        why: unused
          ? `On ${APP} the console port ${PORT}/tcp sees only ${SCANNER} (the scanner); the job from ${JOB} goes to ${API_PORT}/tcp. On ${DB} the database team's workstations reach ${PORT}/tcp every few days. Nothing but the scanner (during the older run) connects to ${DEV}.`
          : `On ${APP} the job from ${JOB} reaches the console port ${PORT}/tcp every 3 to 4 days, next to two short connections from ${SCANNER} (the scanner). On ${DB} the database team's workstations reach ${PORT}/tcp every few days. Nothing but the scanner (during the older run) connects to ${DEV}.`,
      },
      {
        title: 'How long does the firewall log reach back?',
        kql: 'FirewallLogs\n| summarize Earliest = min(TimeGenerated), Latest = max(TimeGenerated)',
        why: 'About two weeks: more than twice the longest cycle (3 to 4 days) that the owners document, so a process that used the console would have shown up.',
      },
      {
        title: 'What does the intel say?',
        kql: `VulnIntel\n| where VulnId in ("${f1Entry.id}", "${f2Entry.id}", "${f3Entry.id}", "${f4Entry.id}")\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, FixedVersion, RecordId`,
        why: 'A vendor fix exists for each, none is on Sim-KEV, the Sim-EPSS scores are low and there is no public exploit: the High class and its 30-day SLA set the schedule, and use decides between avoid and patch. The fix for the Medium on the build server is below the release installed there.',
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
        text: unused ? `States the risk in plain words: a High remote code execution flaw in an admin console nobody uses on ${APP}; removing the console removes the attack surface.` : `States the risk in plain words: a High remote code execution flaw in an admin console that the stock export needs on ${APP}, so it cannot simply be switched off.`,
        keywords: unused
          ? lowered([`removing the console on ${APP} removes`, `removes the attack surface on ${APP}`, `removing the console on ${APP}`, `removing the ${APP} console`, `remove the console on ${APP}`, `remove the ${APP} console`, `nobody uses the ${APP}`, `no one uses the ${APP}`, `nobody uses the console on ${APP}`, `nobody uses the admin console on ${APP}`, `no one uses the console on ${APP}`, `no one uses the admin console on ${APP}`, `nobody uses it on ${APP}`, `${APP} console is unused`, `${APP} admin console is unused`, `console on ${APP} is unused`, `admin console on ${APP} is unused`, `${APP} console is not used`, `console on ${APP} is not used`, `not used by ${APP}`, `no business process uses the console on ${APP}`, `no business process uses the ${APP}`, `no business process on the ${APP}`, `unused console on ${APP}`, `unused admin console on ${APP}`, `unused ${APP} console`, `unused ${APP} admin console`, `no business process on ${APP}`, ...['nobody uses', 'no one uses', 'nobody is using', 'no one is using', 'no business process uses'].flatMap((p) => [`${p} ${APP}`, `${p} ${APP} console`, `${p} ${APP} admin console`])])
          : lowered([`stock export needs the console on ${APP}`, `stock export uses the console on ${APP}`, `stock export calls the console on ${APP}`, `stock export depends on the console on ${APP}`, `export needs the console on ${APP}`, `needs the console on ${APP}`, `depends on the console on ${APP}`, `the ${APP} console cannot be switched off`, `the ${APP} console cannot be disabled`, `console on ${APP} cannot be switched off`, `console on ${APP} cannot simply be switched off`, `console on ${APP} cannot be disabled`, `console on ${APP} cannot simply be disabled`, `${APP} console is needed`, `${APP} console is in use`, `${APP} console is used`, `console on ${APP} is needed`, `console on ${APP} is in use`, `console on ${APP} is used`]),
      },
      {
        id: 'action',
        text: unused ? `Avoids the console on ${APP} and on ${DEV} (disable it, then rescan), patches the console on ${DB}, which is used, and dismisses the banner-only Medium on ${JOB}.` : `Patches the console on ${APP} and on ${DB}, which are used, avoids the unused one on ${DEV} and dismisses the banner-only Medium on ${JOB}.`,
        keywords: unused
          ? lowered(verbsOn(VERBS_AVOID, APP), VERBS_AVOID.map((v) => `console on ${APP} ${v}`), [`disable it on ${APP}`, ...['is switched off', 'is disabled', 'is removed', 'is turned off', 'is uninstalled'].flatMap((p) => [`${APP} console ${p}`, `console on ${APP} ${p}`, `${APP} admin console ${p}`]), `${APP} console is unused`, `${APP} admin console is unused`, `console on ${APP} is unused`, `admin console on ${APP} is unused`])
          : lowered(verbsOn(VERBS_PATCH, APP), [`${APP} console is needed`, `${APP} console is in use`, `console on ${APP} is needed`, `console on ${APP} is in use`, `${APP} console is used`, `console on ${APP} is used`]),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy.',
        keywords: dateRubricKeywords(cal, [f1Deadline, f2Deadline, f3Deadline], [30]),
      },
    ],
    explanation: unused
      ? [
          `The headline is a High (30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day) in the optional ${COMPONENT} of an application on ${APP}, read from a banner by the newer sweep. The deciding clue is whether anything uses the console. Tickets holds the owner's confirmation that no business process uses it and that the longest cycle of any process that uses the product is 3 to 4 days, and FirewallLogs, which reach back ${reach} days or more, show no session to the console port except two short connections from ${SCANNER}, the scanner itself. The job from ${JOB} that talks to the application goes to the API on ${API_PORT}/tcp. SoftwareInventory shows the console as an optional component that came with the default install, which alone proves nothing. The policy row on unused components says what to do: avoid. Disable the component in the next window (${ymd(cal.next.start)}), which ends before the deadline, and rescan to close the finding.`,
          `Patching is the near miss: the update fixes this flaw (VulnIntel shows a vendor fix) but leaves the unused component and its attack surface in place, so it earns half credit on the decision and, on a lesson finding, does not pass. The twin has the same flaw and the same host, but there FirewallLogs show the job from ${JOB} using the console port and Tickets holds a process record that names the stock export that depends on it: avoid would stop the export, so the answer is patch.`,
          `The decoys: the two connections from ${SCANNER} to the console port look like use but are the scanner (a few hundred bytes, rule allow-scanner); the installation record says the console came by default, which does not make it unused; the console on ${DEV} is also unused (owner confirmation, no session but the scanner's own): avoid, due ${ymd(f2Deadline)}, so the standard cycle; the console on ${DB} is used by the database team (process record, regular sessions): patch it in the next window, which with the console on ${APP} fills its capacity of two. The Medium on ${JOB} is a false positive: the sweep read a banner, SoftwareInventory shows a release above the fix and the credentialed run reached the host (dismiss it and ask for a credentialed rescan). The Low goes in the standard cycle.`,
        ]
      : [
          `The headline is a High (30 days from first detection ${f1Age} days ago, due ${ymd(f1Deadline)}, end of day) in the optional ${COMPONENT} of an application on ${APP}, read from a banner by the newer sweep. The deciding clue is whether anything uses the console. FirewallLogs show ${jobRows.length} regular sessions, one every 3 to 4 days over ${jobSpan} days, from ${JOB} to the console port ${PORT}/tcp, and Tickets holds the owner's process record: the stock export calls the console, the finance team relies on it, and switching it off stops it. SoftwareInventory shows the console as an optional component that came with the default install, but optional and default do not mean unused. The business needs the component, so the policy row on unused components does not apply: patch by the standard rules. The deadline is after the next window and before the standard cycle: patch in the next window (${ymd(cal.next.start)}).`,
          `Avoid is wrong here and earns nothing on the decision: removing the console would stop the stock export. The twin has the same flaw and the same host, but there FirewallLogs show no session to the console port except the scanner's own two connections (the job goes to the API on ${API_PORT}/tcp) and the owner confirms in Tickets that nothing uses the console: the answer is avoid.`,
          `The decoys: the two connections from ${SCANNER} are the scanner, not use, and do not change the answer; the installation record says the console came by default, which does not make it unused; the console on ${DEV} is unused (owner confirmation, no session but the scanner's own): avoid, due ${ymd(f2Deadline)}, so the standard cycle; the console on ${DB} is used by the database team (process record, regular sessions): patch it in the next window, which with the console on ${APP} fills its capacity of two. The Medium on ${JOB} is a false positive: the sweep read a banner, SoftwareInventory shows a release above the fix and the credentialed run reached the host (dismiss it and ask for a credentialed rescan). The Low goes in the standard cycle.`,
        ],
    pitfalls: unused
      ? [
          'Patching the headline: the update fixes this flaw but keeps an unused component and its attack surface; the policy says to remove or disable an unused component (avoid).',
          'Reading the scanner\'s own two connections to the console port as use: a scanner connecting is not use; check the source of every session.',
          'Calling a component used because the application as a whole is used: the export job on the same host goes to the API port, not the console.',
          'Treating "installed by default" as proof that it is unused (or as proof that it is needed): the owner\'s confirmation and a long enough firewall log are the proof.',
          'Avoiding the console on the database server too: the database team uses it, so patch it.',
        ]
      : [
          'Avoiding the headline because the console is optional and was installed by default: the stock export depends on it, so removing it breaks a business process.',
          'Treating every optional admin console as attack surface to remove: the one on the application server is used, FirewallLogs and the process record show it.',
          'Counting the scanner\'s own connections as the use, or ignoring the job\'s regular sessions because they are few: read the source, the port and the cycle.',
          'Patching the console on the developer test server: nothing uses it, so avoid it.',
          'Scheduling the patch in the standard cycle: the High deadline falls before it, so the next window.',
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

export const unusedService: VulnTemplate = {
  ...COMMON,
  id: 'vm-unused-service',
  twin: 'vm-needed-service',
  lesson:
    "FirewallLogs show no session to the optional admin console's port in two weeks, longer than twice the longest cycle the owner documents (the scanner's own connections are not use), Tickets holds the owner's confirmation that no process needs it, and SoftwareInventory shows it is an optional component installed by default: remove or disable it (avoid) instead of patching, because a patch fixes the flaw but keeps the attack surface. The twin has the same flaw, but FirewallLogs show regular sessions from a job and Tickets a process record: the business needs the console, so patch it.",
  build: (ctx) => build('unused', ctx),
};

export const neededService: VulnTemplate = {
  ...COMMON,
  id: 'vm-needed-service',
  twin: 'vm-unused-service',
  lesson:
    "FirewallLogs show regular sessions from a scheduled job to the optional admin console's port, and Tickets holds the process record that names the stock export depending on it, although SoftwareInventory shows the console was installed by default: the business needs it, so patch it (avoid would break the export). The twin has the same flaw and no use of the console, where the answer is avoid.",
  build: (ctx) => build('needed', ctx),
};
