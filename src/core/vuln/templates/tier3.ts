// Twin pair T10 with T9's ordering pattern inside both (DESIGN section 4; human decision 2026-10-02): the
// two tier-3 cases. One application server (APP02) reports the same flaw in a shared transport library
// six times: once from the credentialed run's check of the installed package (the package-level finding)
// and once per service from the newer unauthenticated sweep, which observes each service's TLS handshake from
// outside (a true detection of that service). The headline is the per-service detection of the portal on
// 443/tcp. A remote check says nothing about where a service got its copy of the library; SoftwareInventory
// does, and that is the deciding clue.
//
// vm-dup-plugins (A): the portal links the system package. One update to the package fixes it, so its
// detection is a duplicate of the package-level finding: closed as a duplicate (decision false-positive,
// reason duplicate-root-cause; the vulnerability is real and is fixed once, on the package-level finding,
// and "closed as a duplicate" is not a claim that it is absent), schedule none.
//
// vm-distinct (B): the portal bundles its own copy (the vendor's build). The system package update does
// not touch it, so it is a separate component with its own fix: patch, standard cycle.
//
// Everything else is the same in both twins: the package-level finding (patch), two more services that
// link the system package (duplicates) and two that bundle their own copies (patches), so "close every
// per-service detection as a duplicate" and "patch every detection" are wrong in both twins. Policy rows
// (identical in both) say to check for bundled copies before closing a duplicate and to restart the
// services after the update (a running process keeps the old library in memory).
//
// T9 inside both: a Critical on an isolated developer test server and a Medium on the production payments
// database. The template-local "Asset tier" row moves the deadline one class (never the severity class): the
// Medium on the payments database is due as a High (the next window), the Critical on the developer test server
// as a High too (the standard cycle). The payments finding is ranked first although its CVSS score is lower.
//
// Tier 3 (DESIGN 2.3): 16 worklist findings across two runs (an older complete credentialed run and a newer
// unauthenticated sweep that did not reach every target), a stale-versus-fresh conflict (FS01 was patched
// after the old run and the sweep never re-tested it; JUMP01's later update is only a rollup) and a capacity
// squeeze: by the SLA table alone four findings fall due before the standard cycle (the Sim-KEV Critical, the
// Critical on the developer test server, the High that was already patched and the High that is accepted), the
// window takes two changes, and the ideal answer needs exactly two (the Sim-KEV Critical, an emergency; the
// payments Medium, the next window). One builder, the clue is a parameter. Everything else is chosen from the
// catalogue seed, not from the template id.
//
// Key findings (tier 3 lifts the 1-3 guidance of DESIGN 5.8: the rule is to flag every finding the lesson names; a case
// this size has several independent decisions, and one wrong decision on any of them must fail the case): the headline,
// the package-level finding, the two bundled copies the lesson names (the mail relay and the chat service), the payments
// Medium, the developer test server's Critical, the old-run High that only an OS rollup touched, and the Sim-KEV Critical
// (must-not-miss). Dismissing any one of them alone is gated.

import { DAY, MIN } from '../../logs/time.ts';
import { sampleSimEpss, simEpssPercentile, type CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, ReasonCode, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  coverageOf,
  dayStart,
  FICTIONAL_OS,
  hostFacts,
  installedBefore,
  kevDeadline,
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
  SLA_DAYS,
  sizeRunToHosts,
  slaDeadline,
  withEpss,
  withFix,
  withPublished,
  writeChangeTickets,
  writeRiskException,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  lowered,
} from './common.ts';

type Variant = 'dup' | 'distinct';

const LIB = 'Skerrimoor Secure Transport Library';
const LIB_VENDOR = 'Skerrimoor Labs';
const SYSTEM_ROW = `${LIB} (system package)`;

const LIB_HOST = 'APP02'; // the headline host: six findings of one flaw
const PAY = 'PAYDB01'; // T9: the payments database
const DEV = 'DEVBOX01'; // T9: the developer test server
const KEV_HOST = 'APP01'; // the Sim-KEV Critical (and a Medium)
const STALE_HOST = 'FS01'; // patched after the old run, never re-tested
const OLD_HOST = 'JUMP01'; // updated after the old run, but only by a rollup
const EXC_HOST = 'PRINT01'; // an accepted risk
const BUILD = 'BUILD01'; // a background-like worklist item

const PAY_PRODUCTS = ['Brackenridge DB Console', 'Hollowmere Reporting', 'Pinecrest Dashboards'];
// The Sim-KEV Critical and the Medium on APP01 use products that only APP01 runs (no other worklist host and no background host does), so no host sits below their fix with no finding, and the products stay out of the background's way.
const APP_ONLY_PRODUCTS = ['Wickerlow Helpdesk', 'Thistledown CMS', 'Ivorygate Payments Adapter'];

interface Service {
  product: string;
  vendor: string;
  port: number;
  service: string;
  own: boolean | null; // bundles its own copy of the library; null: the clue (A: no, B: yes)
}
// The five services of APP02 that load the library, in worklist order (the headline first).
const SERVICES: readonly Service[] = [
  { product: 'Larkspur Portal', vendor: 'Velmarrow Software', port: 443, service: 'https', own: null },
  { product: 'Velmarrow Forms', vendor: 'Velmarrow Software', port: 8443, service: 'https', own: false },
  { product: 'Harrowgate Directory Sync', vendor: 'Harrowgate Tech', port: 636, service: 'ldaps', own: false },
  { product: 'Wrenwick Relay', vendor: 'Ravenmere Systems', port: 465, service: 'smtps', own: true },
  { product: 'Elderfen Chat Server', vendor: 'Ravenmere Systems', port: 8883, service: 'mqtts', own: true },
];

const SERVICE_NAMES: ReadonlySet<string> = new Set(SERVICES.map((s) => s.product)); // no worklist finding on APP01 names a product that is also one of APP02's services

const TITLE = 'Scan review: shared services and payment systems';

// Template-local policy rows (identical in both twins).
const DUP_ROW: [string, string] = [
  'Duplicate detections',
  'Findings on one host that report the same vulnerability in the same installed component are fixed by one change. Before closing any finding as a duplicate, check SoftwareInventory for a copy of the component that the service bundles with itself: a bundled copy is a separate component with its own fix from its vendor, so it is not a duplicate; patch it by the standard rules. Record the one change on the package-level finding (the finding for the installed package) and close each remaining detection of that package as a duplicate: record it with the decision False positive and the reason Duplicate root cause, and schedule nothing for it. Closed as a duplicate means the vulnerability is real and is fixed once, on the package-level finding; it is not a claim that the vulnerability is absent. After the update, restart every service that loads the component: a running process keeps the old library in memory until it restarts, so the finding stays open until then.',
];
const TIER_ROW: [string, string] = [
  'Asset tier',
  `The asset moves the deadline by one class; it never changes the severity class (the Severity class row stands). A finding on a production system whose Role in DeviceInfo says it holds payment or customer data is due as the next more severe class would be: a Medium in ${SLA_DAYS.high} days, a High in ${SLA_DAYS.critical} days, a Critical stays at ${SLA_DAYS.critical} days. A finding on an isolated non-production host (its Role in DeviceInfo says non-production, isolated and no production data, its Criticality is Low and it is not exposed to the internet) is due as the next less severe class would be: a Critical in ${SLA_DAYS.high} days, a High in ${SLA_DAYS.medium} days, a Medium in ${SLA_DAYS.low} days. Every other host follows the table. The days are counted from first detection, and the Sim-KEV override still applies first.`,
];

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;
const XYZ = /^\d+\.\d+\.\d+$/;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const dup = variant === 'dup'; // A: the headline links the system package
  const cal = buildCalendar(now);
  const today = dayStart(now);
  const rng = sharedRng(ctx, 'tier3');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const allIds = catalogue.entries.map((e) => e.id);
  const versionOf = (label: string, e: CatalogueEntry): string => {
    const r = sharedRng(ctx, `version/${label}`);
    return e.vendorFix ? versionBelow(r, e.fixedVersion) : `${r.int(1, 9)}.${r.int(0, 12)}.${r.int(0, 9)}`;
  };

  // ---- two runs: an older complete credentialed run, a newer unauthenticated sweep that did not reach every target
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 9 * DAY, targetsPlanned: 10, targetsScanned: 10 }); // sized to the devices that have a row
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Unauthenticated', started: now - 2 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // ---- dates (all relative to the case date, shared by the twins)
  const payFirst = now - 19 * DAY; // Medium, asset tier: due as a High, after the next window and before the standard cycle
  const devFirst = newRun.started; // Critical on the isolated host: due as a High, after the standard cycle
  const staleFirst = now - 20 * DAY; // High: the SLA table alone would put it in the next window
  const oldValidFirst = now - 12 * DAY; // High: due after the standard cycle
  const excFirst = now - 120 * DAY;
  const approvedAt = now - 100 * DAY;
  const expires = now + 45 * DAY;
  const x1First = newRun.started;
  const listedAt = today - DAY; // Sim-KEV listing, a day start

  // ---- entries (twins share every choice)
  const pickBase = (first: number): CatalogueEntry => {
    const candidates = free().filter(quiet);
    const known = candidates.filter((x) => x.published <= first);
    const base = rng.pick(known.length > 0 ? known : candidates);
    used.add(base.id);
    const dated = withPublished(base, Math.min(base.published, dayStart(first - DAY)), [...allIds, ...used]);
    used.add(dated.id);
    return dated;
  };
  const place = (e: CatalogueEntry, host: string, want: ShapeWant, avoid: ReadonlySet<string> = new Set(), names?: readonly string[]): CatalogueEntry => {
    if (names) {
      const p = placedOn(e, host, rng, avoid, names);
      if (!p) throw new Error(`tier3: no product fits ${host}`);
      return shaped(p, rng, want);
    }
    return shapedOn(e, host, rng, want, avoid);
  };
  const xyz = (e: CatalogueEntry): CatalogueEntry => (!e.vendorFix || XYZ.test(e.fixedVersion) ? e : { ...e, fixedVersion: `${rng.int(2, 9)}.${rng.int(2, 9)}.${rng.int(2, 9)}` });
  const finish = (e: CatalogueEntry, epss: number): CatalogueEntry => withEpss(xyz(withFix(e, rng)), epss);
  const lower = (label: string): number => lowerHalfEpss(rng.fork(label), 0.45);

  const libEntry = finish(shaped({ ...pickBase(oldRun.started), product: LIB, vendor: LIB_VENDOR }, rng, { classes: ['info-leak'], component: /^TLS handshake handler$/ }), LOW_EPSS);
  const payEntry = finish(place(pickBase(payFirst), PAY, { classes: ['sqli', 'info-leak'], min: 4, max: 6.9, network: true }, new Set(), PAY_PRODUCTS), lower('pay'));
  // No worklist host runs a product that another worklist finding names: that product would sit below the other flaw's fix with no finding of its own.
  const devEntry = finish(place(pickBase(devFirst), DEV, { min: 9 }, new Set([payEntry.product])), LOW_EPSS);
  const kevBase = finish(place(pickBase(x1First), KEV_HOST, { min: 9 }, new Set(), APP_ONLY_PRODUCTS), LOW_EPSS);
  const kevEpss = sampleSimEpss(rng.fork('x1-epss'), { listed: true });
  const kevEntry: CatalogueEntry = { ...kevBase, knownExploited: true, knownExploitedAdded: listedAt, epss: kevEpss, epssPercentile: Math.round(simEpssPercentile(kevEpss) * 100) / 100, publicExploit: true };
  const staleEntry = finish(place(pickBase(staleFirst), STALE_HOST, { min: 7, max: 8.9 }), LOW_EPSS);
  const oldEntry = finish(place(pickBase(oldValidFirst), OLD_HOST, { min: 7, max: 8.9 }, SERVICE_NAMES), LOW_EPSS);
  const excBase = xyz(place(pickBase(excFirst - 10 * DAY), EXC_HOST, { min: 7, max: 8.9, network: true }));
  const excEntry: CatalogueEntry = { ...withEpss(excBase, lower('exc')), vendorFix: false, fixedVersion: '' };
  const n1Entry = finish(place(pickBase(oldRun.started), BUILD, { min: 4, max: 6.9, network: true }, new Set([devEntry.product])), lower('n1'));
  const n2Entry = finish(place(pickBase(oldRun.started), OLD_HOST, { max: 3.9 }, new Set([oldEntry.product, ...SERVICE_NAMES])), lower('n2'));
  const n3Entry = finish(place(pickBase(oldRun.started), STALE_HOST, { min: 4, max: 6.9, network: true }, new Set([staleEntry.product])), lower('n3'));
  const n4Entry = finish(place(pickBase(x1First), KEV_HOST, { min: 4, max: 6.9, network: true }, new Set([kevEntry.product]), APP_ONLY_PRODUCTS), lower('n4'));
  const libVersion = versionBelow(sharedRng(ctx, 'version/lib'), libEntry.fixedVersion);

  // ---- the hosts: the shared world's FS01, JUMP01, PRINT01, BUILD01, APP01; the case's own APP02, PAYDB01, DEVBOX01 (identical in both twins)
  scopeSharedHost(ctx, { name: LIB_HOST, role: 'Application and messaging server (internal services)', os: FICTIONAL_OS, owner: 'IT Infrastructure', criticality: 'Medium' }, 'lib-host');
  scopeSharedHost(ctx, { name: PAY, role: 'Payments database (production, holds payment data)', os: FICTIONAL_OS, owner: 'Finance', criticality: 'High' }, 'pay-db');
  scopeSharedHost(ctx, { name: DEV, role: 'Developer test server (non-production, isolated, no production data)', os: FICTIONAL_OS, owner: 'Engineering', criticality: 'Low' }, 'devbox');

  // ---- the findings. The library: the package-level one from the credentialed run, one per service from the sweep (a remote handshake check).
  const libFinding = (run: typeof oldRun, extra: { port?: number; service?: string; label: string }): WrittenFinding =>
    scan.finding(run, {
      host: LIB_HOST,
      entry: libEntry,
      firstSeen: run.started,
      lastSeen: lastSeen(run, extra.label),
      installedVersion: libVersion,
      ...(extra.port !== undefined
        ? { port: extra.port, service: extra.service, bannerVersion: libVersion, evidence: `Remote check: the ${extra.service} service on ${extra.port}/tcp showed the handshake behaviour of ${LIB} ${libVersion} in a TLS handshake probe (nothing exploitable was sent). Detected remotely only; installed packages and the origin of the service's copy of the library were not inspected. Fixed in ${libEntry.fixedVersion}.` }
        : { packageSource: 'distro' as const }),
      title: libEntry.title,
      recordInventory: false,
    });
  const pF = libFinding(oldRun, { label: 'lib-package' });
  const sF = SERVICES.map((svc, i) => libFinding(newRun, { port: svc.port, service: svc.service, label: `lib-${i}` }));

  const payF = scan.finding(oldRun, { host: PAY, entry: payEntry, firstSeen: payFirst, lastSeen: lastSeen(oldRun, 'pay'), installedVersion: versionOf('pay', payEntry), title: payEntry.title });
  const devF = scan.finding(newRun, { host: DEV, entry: devEntry, port: 8080, firstSeen: devFirst, lastSeen: lastSeen(newRun, 'dev'), installedVersion: versionOf('dev', devEntry), title: devEntry.title });
  const x1F = scan.finding(newRun, { host: KEV_HOST, entry: kevEntry, port: 8443, firstSeen: x1First, lastSeen: lastSeen(newRun, 'x1'), installedVersion: versionOf('x1', kevEntry), title: kevEntry.title });
  const staleF = scan.finding(oldRun, { host: STALE_HOST, entry: staleEntry, firstSeen: staleFirst, lastSeen: lastSeen(oldRun, 'stale'), installedVersion: versionOf('stale', staleEntry), title: staleEntry.title });
  const oldF = scan.finding(oldRun, { host: OLD_HOST, entry: oldEntry, firstSeen: oldValidFirst, lastSeen: lastSeen(oldRun, 'old'), installedVersion: versionOf('old', oldEntry), title: oldEntry.title });
  const excF = scan.finding(oldRun, { host: EXC_HOST, entry: excEntry, firstSeen: excFirst, lastSeen: lastSeen(oldRun, 'exc'), installedVersion: versionOf('exc', excEntry), title: excEntry.title });
  const n1F = scan.finding(oldRun, { host: BUILD, entry: n1Entry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'n1'), installedVersion: versionOf('n1', n1Entry), title: n1Entry.title });
  const n2F = scan.finding(oldRun, { host: OLD_HOST, entry: n2Entry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'n2'), installedVersion: versionOf('n2', n2Entry), title: n2Entry.title });
  const n3F = scan.finding(oldRun, { host: STALE_HOST, entry: n3Entry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'n3'), installedVersion: versionOf('n3', n3Entry), title: n3Entry.title });
  const n4F = scan.finding(newRun, { host: KEV_HOST, entry: n4Entry, port: 443, firstSeen: x1First, lastSeen: lastSeen(newRun, 'n4'), installedVersion: versionOf('n4', n4Entry), title: n4Entry.title });

  // ---- SoftwareInventory: every worklist product (installed before its first detection, identical in both twins), the system
  // library, and one row per service saying whether it links the system package or bundles a copy of its own.
  const install = (label: string, host: string, e: CatalogueEntry, first: number, notAfter: number = first) => scan.software({ host, product: e.product, vendor: e.vendor, version: versionOf(label, e), installedOn: installedBefore(ctx, label, first, notAfter) });
  install('pay', PAY, payEntry, payFirst);
  install('dev', DEV, devEntry, devFirst);
  install('x1', KEV_HOST, kevEntry, x1First);
  install('stale', STALE_HOST, staleEntry, staleFirst);
  const oldInv = install('old', OLD_HOST, oldEntry, oldValidFirst);
  install('exc', EXC_HOST, excEntry, excFirst, approvedAt);
  install('n1', BUILD, n1Entry, oldRun.started);
  install('n2', OLD_HOST, n2Entry, oldRun.started);
  install('n3', STALE_HOST, n3Entry, oldRun.started);
  install('n4', KEV_HOST, n4Entry, x1First);

  const sysAt = installedBefore(ctx, 'lib-system', oldRun.started);
  const sysRow = scan.software({ host: LIB_HOST, product: SYSTEM_ROW, vendor: LIB_VENDOR, version: libVersion, source: 'distro', installedOn: sysAt });
  const deps = SERVICES.map((svc, i) => {
    const own = svc.own ?? !dup;
    const row = scan.software({
      host: LIB_HOST,
      product: `${LIB} (${own ? 'bundled with' : 'linked by'} ${svc.product}, ${svc.service} ${svc.port}/tcp)`,
      vendor: own ? svc.vendor : LIB_VENDOR,
      version: libVersion,
      source: own ? 'vendor' : 'distro',
      installedOn: own ? installedBefore(ctx, `bundle-${i}`, oldRun.started) : sysAt,
    });
    return { svc, own, row };
  });

  // ---- PatchHistory: FS01's update after the old run (stale), JUMP01's unrelated rollup after it (still vulnerable)
  const pkgNos = [rng.int(1000, 9999), rng.int(1000, 9999)];
  const patchedAt = oldRun.started + 3 * DAY;
  const stalePatch = log.patch({ DeviceName: STALE_HOST, PatchId: `PKG-${pkgNos[0]}`, Description: `${staleEntry.product} update to ${staleEntry.fixedVersion} (addresses ${staleEntry.id})`, InstalledOn: patchedAt, RebootPending: false, Result: 'Installed' });
  const staleSoft = scan.software({ host: STALE_HOST, product: staleEntry.product, vendor: staleEntry.vendor, version: staleEntry.fixedVersion, installedOn: patchedAt });
  const rollupAt = oldRun.started + 4 * DAY;
  const rollup = log.patch({ DeviceName: OLD_HOST, PatchId: `PKG-${pkgNos[1]}`, Description: 'Monthly operating system rollup (kernel and system libraries only; fixes no application vulnerability)', InstalledOn: rollupAt, RebootPending: false, Result: 'Installed' });

  // ---- the accepted risk: an approved, time-boxed exception (the vendor has published no fix)
  const exTicket = writeRiskException(ctx, excEntry, EXC_HOST, 'print VLAN', approvedAt, expires);

  // ---- noise, tickets, calendar, unrelated updates. No background row on a worklist host.
  const oldBg = ['DC01', 'DC02', 'SCCM01'];
  const newBg = ['APP01', DEV, 'BKP01', 'ADCONNECT01', 'SQL01', 'FS02']; // APP01 and DEVBOX01 have worklist rows from the newest run only, so the sweep re-tested them: background rows are safe there
  const worklist = [libEntry, payEntry, devEntry, kevEntry, staleEntry, oldEntry, excEntry, n1Entry, n2Entry, n3Entry, n4Entry];
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: oldBg },
      { run: newRun, hosts: newBg },
    ],
    worklist,
    { worklistSize: 16 },
  );
  writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, [...oldBg, ...newBg], 2, sharedRng(ctx, 'unrelated-patches'));
  sizeRunToHosts(ctx, oldRun);
  sizeRunToHosts(ctx, newRun);
  oldRun.row.row.TargetsPlanned = Number(oldRun.row.row.TargetsScanned); // the older run reached everything it planned
  newRun.row.row.TargetsPlanned = Number(newRun.row.row.TargetsScanned) + 3; // the sweep did not reach three targets

  // ---- the truth (derived from the policy, the calendar, the dates and the rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const banner = { packageBasis: false } as const;
  const notDuplicate: ReasonCode[] = ['duplicate-root-cause'];
  const std = { schedule: 'standard-cycle', slaLatest: 'standard-cycle' } as const;
  const libIntel = scan.intel(libEntry);
  const x1Intel = scan.intel(kevEntry);
  const cov = { old: coverageOf(oldRun), fresh: coverageOf(newRun) };

  const pDeadline = slaDeadline('medium', oldRun.started);
  const payDeadline = slaDeadline('high', payFirst); // the asset tier row: a Medium due as a High
  const payTable = slaDeadline('medium', payFirst);
  const devDeadline = slaDeadline('high', devFirst); // the asset tier row: a Critical due as a High
  const devTable = slaDeadline('critical', devFirst);
  const x1Deadline = kevDeadline(x1First, listedAt);
  const staleTable = slaDeadline('high', staleFirst);
  const oldDeadline = slaDeadline('high', oldValidFirst);
  const payAge = Math.round((now - payFirst) / DAY);

  const ownerNames = [...new Set([...ownersOf(ctx, [LIB_HOST, PAY, DEV, KEV_HOST, STALE_HOST, OLD_HOST, EXC_HOST, BUILD]), 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const svcOf = (i: number) => SERVICES[i];
  const svcLabel = (i: number) => `${svcOf(i).product} on ${svcOf(i).port}/tcp`;

  // The headline: the portal's per-service detection.
  const headSpec: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec> = dup
    ? {
        truth: { decision: 'false-positive', schedule: 'none', reasons: ['duplicate-root-cause'], contradicting: contradictionsFor(libEntry, facts(LIB_HOST, { ...banner, real: false, fixedBeforeScan: true }), ['duplicate-root-cause']) },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'portal-links-system-package',
            label: `SoftwareInventory shows the portal on 443/tcp links the system package and has no copy of its own`,
            why: `SoftwareInventory lists ${LIB} ${libVersion} as a system package on ${LIB_HOST} (PackageSource distro) and a usage row for ${svcLabel(0)} that says it is linked by the portal, from the same system package (distro, no vendor of its own). The sweep's remote check of 443/tcp observed vulnerable handshake behaviour, matching release ${libVersion} by its fingerprint; it cannot show where the service got the library. The portal loads the system package, so the one update to that package fixes it: this per-service detection is a duplicate of the package-level finding (the credentialed check of ${LIB} ${libVersion}). Close it as a duplicate (decision False positive, reason Duplicate root cause): the vulnerability is real and is fixed once, on the package-level finding; this is not a claim that it is absent.`,
            rows: [deps[0].row],
          },
        ],
      }
    : {
        truth: { decision: 'patch', ...std, reasons: ['low-exploitability'], contradicting: [...new Set([...contradictionsFor(libEntry, facts(LIB_HOST, banner), ['low-exploitability']), ...notDuplicate])] },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'portal-bundles-own-copy',
            label: `SoftwareInventory shows the portal on 443/tcp bundles its own copy of the library, from its own vendor`,
            why: `SoftwareInventory has a usage row for ${svcLabel(0)} that says the portal bundles its own copy of ${LIB} ${libVersion} (vendor ${svcOf(0).vendor}, PackageSource vendor), next to the system package ${LIB} ${libVersion} (distro). The sweep's remote check of 443/tcp shows only the vulnerable behaviour; it cannot show which copy the service loaded. The portal carries a separate component with its own fix from its vendor, so updating the system package does not fix it and this detection is not a duplicate: patch it. Medium, 90 days from first detection (due ${ymd(slaDeadline('medium', newRun.started))}, end of day), after the standard cycle (${ymd(cal.cycle.start)}): standard cycle.`,
            rows: [deps[0].row],
          },
        ],
      };

  const findings: FindingSpec[] = [
    // 0: the headline
    spec(sF[0], headSpec),
    // 1: the package-level finding (the same truth in both twins)
    spec(pF, {
      truth: { decision: 'patch', ...std, reasons: ['credentialed-confirmed', 'low-exploitability'], contradicting: [...new Set([...contradictionsFor(libEntry, facts(LIB_HOST), ['credentialed-confirmed', 'low-exploitability']), ...notDuplicate])] },
      weight: 1,
      lesson: true, // the one fix: dismissing the package-level finding as a duplicate of its own detections leaves the flaw open
      evidence: [
        {
          id: 'package-level-root',
          label: `The credentialed run read ${LIB} ${libVersion} from the installed-software inventory on ${LIB_HOST}, below the fixed version`,
          why: `The package-level finding comes from the credentialed run (${oldRun.id}): ${LIB} ${libVersion} is installed as a system package on ${LIB_HOST}, below the fixed version ${libEntry.fixedVersion} (VulnIntel, vendor fix available, no Sim-KEV listing, low Sim-EPSS). It is the finding that carries the fix for every service that links the system package. Medium: 90 days from first detection (due ${ymd(pDeadline)}, end of day), after the standard cycle (${ymd(cal.cycle.start)}): patch in the standard cycle, then restart the services that load the library, because a running process keeps the old copy in memory.`,
          rows: [sysRow, libIntel],
        },
      ],
    }),
    // 2, 3: two more services that link the system package: duplicates in both twins
    ...[1, 2].map((i) =>
      spec(sF[i], {
        truth: { decision: 'false-positive', schedule: 'none', reasons: ['duplicate-root-cause'], contradicting: contradictionsFor(libEntry, facts(LIB_HOST, { ...banner, real: false, fixedBeforeScan: true }), ['duplicate-root-cause']) },
        weight: 1,
        evidence: [
          {
            id: `service-${i}-links-system-package`,
            label: `SoftwareInventory shows ${svcLabel(i)} links the system package`,
            why: `SoftwareInventory has a usage row for ${svcLabel(i)}: it is linked by ${svcOf(i).product}, the same system package ${LIB} ${libVersion} (distro). One update to that package fixes it, so this per-service detection is a duplicate of the package-level finding: close it as a duplicate (decision False positive, reason Duplicate root cause). The vulnerability is real and is fixed once, on the package-level finding.`,
            rows: [deps[i].row],
          },
        ],
      }),
    ),
    // 4, 5: two services that bundle their own copies: patches in both twins
    ...[3, 4].map((i) =>
      spec(sF[i], {
        truth: { decision: 'patch', ...std, reasons: ['low-exploitability'], contradicting: [...new Set([...contradictionsFor(libEntry, facts(LIB_HOST, banner), ['low-exploitability']), ...notDuplicate])] },
        weight: 1,
        lesson: true, // the mail relay and the chat service are the lesson's bundled-copy check: closing either as a duplicate leaves a real flaw open and fails the case
        evidence: [
          {
            id: `service-${i}-bundles-own-copy`,
            label: `SoftwareInventory shows ${svcLabel(i)} bundles its own copy of the library`,
            why: `SoftwareInventory has a usage row for ${svcLabel(i)}: ${svcOf(i).product} bundles its own copy of ${LIB} ${libVersion} (vendor ${svcOf(i).vendor}, PackageSource vendor). The system package update does not touch it: it is a separate component with its own fix from its vendor, so it is not a duplicate. Patch it in the standard cycle (Medium, 90 days from first detection, after the standard cycle), and restart the service afterwards.`,
            rows: [deps[i].row],
          },
        ],
      }),
    ),
    // 6: T9, the payments database: a Medium, ranked first because the asset tier row moves its deadline to a High's
    spec(payF, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['critical-asset', 'sensitive-data', 'sla-deadline'], contradicting: contradictionsFor(payEntry, facts(PAY), ['critical-asset', 'sensitive-data', 'sla-deadline']) },
      weight: 1,
      lesson: true,
      evidence: [
        {
          id: 'payments-asset-tier',
          label: `DeviceInfo shows ${PAY} is a production payments database holding payment data: the asset tier row makes its Medium due as a High`,
          why: `DeviceInfo says ${PAY} is a payments database, production, holding payment data, Criticality High, not exposed to the internet. The Asset tier row of the standard moves its deadline one class: the severity class stays Medium (CVSS ${String(payF.row.row.CvssBase)}), but it is due as a High, in ${SLA_DAYS.high} days from first detection ${payAge} days ago, on ${ymd(payDeadline)} (end of day), not as a Medium on ${ymd(payTable)}. That is after the next window (${ymd(cal.next.start)}) and before the standard cycle (${ymd(cal.cycle.start)}): next window. Sorting by the severity column would put it last.`,
          rows: [log.deviceRef(PAY)],
        },
      ],
    }),
    // 7: T9, the developer test server: a Critical, but due as a High
    spec(devF, {
      truth: { decision: 'patch', ...std, reasons: ['sla-deadline', 'low-exploitability'], contradicting: [...new Set([...contradictionsFor(devEntry, facts(DEV, banner), ['sla-deadline', 'low-exploitability']), 'sensitive-data' as const])] },
      weight: 1,
      lesson: true, // the T9 pattern's second half: the Critical that is not due first; dismissing it or rushing it is the severity-column misconception
      evidence: [
        {
          id: 'dev-asset-tier',
          label: `DeviceInfo shows ${DEV} is an isolated non-production host with no production data: its Critical is due as a High`,
          why: `DeviceInfo says ${DEV} is a developer test server (non-production, isolated, no production data), Criticality Low, not exposed to the internet. The Asset tier row moves the deadline one class less severe: the Critical (CVSS ${String(devF.row.row.CvssBase)}) is due as a High, ${SLA_DAYS.high} days from first detection ${ymd(devFirst)}, on ${ymd(devDeadline)} (end of day), not as a Critical on ${ymd(devTable)}. That is after the standard cycle (${ymd(cal.cycle.start)}): standard cycle. The severity class did not change; the deadline did.`,
          rows: [log.deviceRef(DEV)],
        },
      ],
    }),
    // 8: the Sim-KEV Critical: a must-not-miss emergency
    spec(x1F, {
      truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['known-exploited', 'public-exploit'], contradicting: contradictionsFor(kevEntry, facts(KEV_HOST, banner), ['known-exploited', 'public-exploit']) },
      weight: 3,
      mustNotMiss: true,
      evidence: [
        {
          id: 'sim-kev-critical',
          label: `VulnIntel shows the Critical on ${KEV_HOST} is on Sim-KEV with a public exploit: due in 3 days`,
          why: `VulnIntel lists ${kevEntry.id} on Sim-KEV (added ${ymd(listedAt)}) with a public exploit. The Sim-KEV override makes it due 3 days from the later of first detection and the listing: ${ymd(x1Deadline)} (end of day), before the next window (${ymd(cal.next.start)}): an emergency change. Together with the payments finding it fills the capacity of two changes in the next window.`,
          rows: [x1Intel, x1F.row],
        },
      ],
    }),
    // 9: the stale finding (the old run found it, the host was patched after, nothing re-tested it): a false positive
    spec(staleF, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(staleEntry, facts(STALE_HOST, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      evidence: [
        {
          id: 'patched-after-scan',
          label: `${STALE_HOST} received the update after the old run started, with no reboot pending`,
          why: `PatchHistory shows the update that addresses ${staleEntry.id} installed on ${ymd(patchedAt)}, after the credentialed run of ${ymd(oldRun.started)} started (Result Installed, no reboot pending). SoftwareInventory agrees: ${staleEntry.product} on ${STALE_HOST} is at the fixed version ${staleEntry.fixedVersion}, installed ${ymd(patchedAt)}.`,
          rows: [stalePatch, staleSoft],
        },
        {
          id: 'sweep-missed-the-host',
          label: `The newer sweep reached ${cov.fresh.scanned} of ${cov.fresh.planned} targets and has no row for ${STALE_HOST}: it was not re-tested`,
          why: `ScanRuns shows the sweep (${newRun.id}, Unauthenticated) reached ${cov.fresh.scanned} of ${cov.fresh.planned} targets, and VulnFindings has no row from it for ${STALE_HOST}: nothing re-tested the host, so the scanner still shows the result of ${oldRun.id}, which is out of date. By the SLA table alone the High (first detected ${ymd(staleFirst)}, due ${ymd(staleTable)}) would need the next window; it needs nothing: remediated after the scan. Close it and request a rescan. The other finding on ${STALE_HOST} is a different product that the update did not touch.`,
          rows: [newRun.row],
        },
      ],
    }),
    // 10: the other old-run finding: updated after the scan, but only by a rollup: still real
    spec(oldF, {
      truth: { decision: 'patch', ...std, reasons: ['sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(oldEntry, facts(OLD_HOST), ['sla-deadline', 'credentialed-confirmed']) },
      weight: 1,
      lesson: true, // the stale-versus-fresh decoy: a later update that is only an operating system rollup does not fix the finding
      evidence: [
        {
          id: 'unrelated-rollup',
          label: `${OLD_HOST}'s only update since the scan is an operating system rollup that fixes no application vulnerability`,
          why: `PatchHistory has an update on ${ymd(rollupAt)}, after the old run started, but its description shows a kernel and system library rollup that fixes no application vulnerability and names no vulnerability id. SoftwareInventory still shows ${oldEntry.product} on ${OLD_HOST} below the fixed version ${oldEntry.fixedVersion}, so the finding is real (the credentialed local check read the installed package version). It is a High, first detected ${ymd(oldValidFirst)}, due ${ymd(oldDeadline)} (end of day), after the standard cycle: standard cycle.`,
          rows: [rollup, oldInv],
        },
      ],
    }),
    // 11: the accepted risk
    spec(excF, {
      truth: { decision: 'accept', schedule: 'none', reasons: ['approved-exception', 'no-vendor-fix'], contradicting: contradictionsFor(excEntry, facts(EXC_HOST, { exception: true }), ['approved-exception', 'no-vendor-fix']) },
      weight: 0.5,
      evidence: [
        {
          id: 'exception-ticket',
          label: 'A time-boxed risk exception is approved and still valid',
          why: `The Tickets row shows an approved exception for ${excEntry.id} on ${EXC_HOST} valid until ${ymd(expires)}, with a compensating measure that limits network access to the print VLAN; the vendor has published no fix. By the SLA table alone it would be overdue and need an emergency change; the policy lets an approved, unexpired exception allow accept: accept it and note the expiry date for review.`,
          rows: [exTicket],
        },
      ],
    }),
    // 12 to 15: routine items, the same in both twins
    ...([
      [n1F, n1Entry, BUILD],
      [n2F, n2Entry, OLD_HOST],
      [n3F, n3Entry, STALE_HOST],
      [n4F, n4Entry, KEV_HOST],
    ] as const).map(([w, e, host]) => spec(w, { truth: { decision: 'patch', ...std, reasons: ['low-exploitability'], contradicting: contradictionsFor(e, facts(host, host === KEV_HOST ? banner : {}), ['low-exploitability']) }, weight: 0.5, evidence: [] })),
  ];

  const id = { head: sF[0].findingId, pkg: pF.findingId, pay: payF.findingId, dev: devF.findingId, x1: x1F.findingId, old: oldF.findingId, b1: sF[3].findingId, b2: sF[4].findingId, n1: n1F.findingId, n2: n2F.findingId, n3: n3F.findingId, n4: n4F.findingId };
  const tier1 = [id.x1, id.pay];
  const tier2 = [id.old, id.dev]; // due before every standard-cycle Medium: JUMP01's High (30 days) and the developer test server's Critical, due as a High
  const tier3 = dup ? [id.pkg, id.b1, id.b2, id.n1, id.n3, id.n4, id.n2] : [id.pkg, id.head, id.b1, id.b2, id.n1, id.n3, id.n4, id.n2]; // every standard-cycle Medium and the Low: no order between them

  const briefing = `${world.org.name}: review of the latest scan results for the application and messaging server, the payments database, the developer test server and the other internal servers in scope (an older complete credentialed run and a newer unauthenticated sweep that did not reach every target). One server reports the same flaw on several of its services. Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive (a duplicate detection is closed under that decision, with the reason Duplicate root cause, and fixed once elsewhere), put the worklist in order, choose when each change should happen (the change windows take two changes each) and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, software inventory, patch and ticket data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'Count fixes, not findings. One server reports the same flaw many times: how many separate changes would remove all of these detections, and which table shows where each service gets its copy of the library? And remember that the order of the worklist is the order in which things are due, not the order of the severity column: which rows of the standard move a deadline?';
  const second = 'SoftwareInventory lists every copy of the shared library on the server, the system package and, for each service, whether it links that package or carries a copy of its own (read the Product, Vendor and PackageSource columns). DeviceInfo shows what each host is for, its criticality and whether it is exposed: read the Asset tier row of the standard against it. ScanRuns and PatchHistory show which results are out of date, and the Sim-KEV listing in VulnIntel overrides the table.';

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal, [DUP_ROW, TIER_ROW]),
    findings,
    constraints: cal.constraints,
    idealOrder: [...tier1, ...tier2, ...tier3],
    tiers: [tier1, tier2, tier3],
    hints: [
      lead,
      second,
      dup
        ? `The portal on 443/tcp links the system package (no copy of its own in SoftwareInventory), so its detection is a duplicate of the package-level finding: close it with the decision False positive and the reason Duplicate root cause (the flaw is real and is fixed once). The mail relay and the chat service do bundle their own copies, so they are not duplicates. The Medium on the payments database is due as a High (asset tier).`
        : `The portal on 443/tcp carries a bundled copy of the library from its own vendor (SoftwareInventory), so updating the system package does not fix it and it is not a duplicate: patch it separately. The forms service and the directory sync still link the system package. The Medium on the payments database is due as a High (asset tier).`,
    ],
    solution: [
      {
        title: 'What did the scanner find on the application server, and which run found it?',
        kql: `VulnFindings\n| where DeviceName == "${LIB_HOST}"\n| project FindingId, DeviceName, VulnId, Title, Severity, CvssBase, Port, Service, DetectedVersion, FirstSeen, ScanRunId, Evidence, RecordId\n| sort by Port asc`,
        why: `One vulnerability (${libEntry.id}) appears six times on ${LIB_HOST}: once from the credentialed run (${oldRun.id}, no port: the installed package) and five times from the sweep (${newRun.id}), one per service port (443, 8443, 636, 465, 8883), each observed by a remote handshake check (not the installed package).`,
      },
      {
        title: 'Where does each service get its copy of the library?',
        kql: `SoftwareInventory\n| where DeviceName == "${LIB_HOST}"\n| project DeviceName, Product, Vendor, Version, PackageSource, InstalledOn, RecordId\n| sort by Product asc`,
        why: dup
          ? `The system package ${LIB} ${libVersion} (distro), and a usage row per service: the portal (443), the forms service (8443) and the directory sync (636) link the system package; the mail relay (465) and the chat service (8883) bundle their own copies (vendor, PackageSource vendor).`
          : `The system package ${LIB} ${libVersion} (distro), and a usage row per service: the forms service (8443) and the directory sync (636) link the system package; the portal (443), the mail relay (465) and the chat service (8883) bundle their own copies (vendor, PackageSource vendor).`,
      },
      {
        title: 'What does the intel say, and is anything on Sim-KEV?',
        kql: `VulnIntel\n| where VulnId in ("${libEntry.id}", "${kevEntry.id}", "${payEntry.id}", "${devEntry.id}")\n| project VulnId, CvssBase, KnownExploited, KnownExploitedAdded, ExploitProbability, PublicExploit, VendorFix, FixedVersion, RecordId`,
        why: `The library flaw has a vendor fix and a low Sim-EPSS; the Critical on ${KEV_HOST} (${kevEntry.id}) is on Sim-KEV with a public exploit, so the 3-day override applies.`,
      },
      {
        title: 'What is each host for, and how critical is it?',
        kql: `DeviceInfo\n| where DeviceName in ("${PAY}", "${DEV}", "${LIB_HOST}", "${KEV_HOST}")\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, IsManaged, RecordId`,
        why: `${PAY} is a production payments database holding payment data (High); ${DEV} is a non-production, isolated developer test server with no production data (Low); the Asset tier row of the standard moves their deadlines: the Medium on the payments database is due as a High, the Critical on the developer test server as a High.`,
      },
      {
        title: 'How were the runs made, and what did each cover?',
        kql: 'ScanRuns\n| project ScanRunId, Tool, Method, Vantage, Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `${oldRun.id} is the older credentialed run and reached all ${cov.old.scanned} of its targets; ${newRun.id} is the newer unauthenticated sweep and reached ${cov.fresh.scanned} of ${cov.fresh.planned}, so some hosts were not re-tested.`,
      },
      {
        title: `What did the sweep find on ${KEV_HOST}?`,
        kql: `VulnFindings\n| where DeviceName == "${KEV_HOST}" and VulnId != ""\n| project FindingId, VulnId, Title, Severity, CvssBase, Port, ScanRunId, FirstSeen, LastSeen, RecordId`,
        why: `The sweep first detected the Critical on ${KEV_HOST} ${ymd(x1First)}, by its banner; VulnIntel shows it is on Sim-KEV.`,
      },
      {
        title: `Which scan rows exist for ${STALE_HOST} and ${OLD_HOST}, and was ${STALE_HOST} in the sweep?`,
        kql: `VulnFindings\n| where DeviceName in ("${STALE_HOST}", "${OLD_HOST}")\n| project FindingId, DeviceName, VulnId, Title, Severity, DetectedVersion, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId`,
        why: `Every row for the two hosts comes from the older run (${oldRun.id}): the newer sweep (${newRun.id}) has no row for either.`,
      },
      {
        title: 'Was either host updated, when, and what did the update fix?',
        kql: `PatchHistory\n| where DeviceName in ("${STALE_HOST}", "${OLD_HOST}")\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: `${STALE_HOST} has an update naming the vulnerability, installed after the older run started, no reboot pending; ${OLD_HOST} has a later update, but it is an operating system rollup that fixes no application vulnerability.`,
      },
      {
        title: 'Which versions are installed on the two hosts?',
        kql: `SoftwareInventory\n| where DeviceName in ("${STALE_HOST}", "${OLD_HOST}")\n| project DeviceName, Product, Version, InstalledOn, RecordId`,
        why: `${STALE_HOST}'s product is at the fixed version, ${OLD_HOST}'s is still below the fix; ${STALE_HOST}'s other product is untouched.`,
      },
      {
        title: 'Is there an approved risk exception, and when are the change windows?',
        kql: 'Tickets\n| where Title has "Risk exception" or Type == "Change"\n| project TicketId, Type, Title, Status, WindowStart, WindowEnd, Scope, RecordId\n| sort by WindowStart asc',
        why: 'The print server finding has an approved, time-boxed exception because the vendor has published no fix; the next window and the standard cycle are the dates each deadline is compared with.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: lowered(ownerNames) },
      {
        id: 'risk',
        text: dup
          ? `States the risk in plain words: one flaw in a shared library, fixed once by updating the system package (and restarting the services), reported six times; the portal links that package, so one update fixes it as well; two other services bundle their own copies and need their own updates; the payments database comes before the Critical on the developer test server.`
          : `States the risk in plain words: one flaw in a shared library, but the portal and two other services bundle their own copies, so there are separate fixes to apply as well as the system package; the payments database comes before the Critical on the developer test server.`,
        keywords: dup
          ? lowered(['portal links', 'portal uses the system package', 'portal is a duplicate', 'portal as a duplicate', 'portal detection is a duplicate', 'one update fixes the portal', 'portal is covered by the package update', 'portal copy is the system package', 'no separate fix for the portal', 'no separate update for the portal', 'portal needs no separate', 'portal does not bundle', 'portal does not have its own', 'portal has no copy of its own', 'one update covers the portal', 'portal is fixed by the package update', 'portal is fixed by the system package', 'portal uses the system', 'portal, forms and directory'])
          : lowered(['portal bundles', 'portal has its own', 'portal ships its own', 'portal is not a duplicate', 'no duplicate for the portal', 'portal own bundled', 'portal bundled copy', 'portal own copy', 'portal copy needs', 'portal and two other services bundle', 'three bundled', 'portal separately']),
      },
      {
        id: 'action',
        text: dup
          ? 'Patches the system package once and closes the portal, forms and directory detections as duplicates; patches the two bundled copies, the payments database (next window) and the Sim-KEV Critical (emergency); dismisses the stale result and requests a rescan; accepts the print server finding.'
          : 'Patches the system package and each bundled copy (the portal, the mail relay and the chat service), closes the forms and directory detections as duplicates, patches the payments database (next window) and the Sim-KEV Critical (emergency); dismisses the stale result and requests a rescan; accepts the print server finding.',
        keywords: dup
          ? lowered(['close the portal', 'closes the portal', 'closed the portal', 'portal, forms and directory', 'portal, forms, and directory', 'portal as a duplicate', 'portal detection as a duplicate', 'portal is a duplicate', 'portal detection is a duplicate'])
          : lowered(['three bundled copies', 'portal, the mail relay', 'patch the portal', 'patches the portal', 'portal bundled copy', 'then the portal', 'the portal, the mail relay', 'update the portal', 'updates the portal', 'portal separately']),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy, including the asset tier row and when the print server exception expires.',
        keywords: dateRubricKeywords(cal, [pDeadline, payDeadline, devDeadline, x1Deadline, oldDeadline, expires], [3, 30, 90]),
      },
    ],
    explanation: [
      dup
        ? `${LIB_HOST} reports the same vulnerability (${libEntry.id}, a Medium, fixed in ${libEntry.fixedVersion}) six times: once from the credentialed run's check of the installed package (the package-level finding, ${oldRun.id}) and once per service from the unauthenticated sweep (${newRun.id}), which can only observe each service from outside, in a TLS handshake. That is a true detection of the service, but it shows the vulnerable behaviour, not where the service got its copy. SoftwareInventory does: it lists the system package ${LIB} ${libVersion} and, per service, whether the service links that package or bundles a copy of its own. The headline, the portal on 443/tcp, links the system package, as do the forms service on 8443/tcp and the directory sync on 636/tcp. One update to the system package fixes all three, so they are one fix together with the package-level finding. Record the change once, on the package-level finding (patch, standard cycle: Medium, 90 days from first detection, due ${ymd(pDeadline)}), and close the three per-service detections as duplicates: the decision False positive with the reason Duplicate root cause. That is how a duplicate is closed, not a claim that the vulnerability is absent: it is real and is fixed once, on the package-level finding. After the update, restart the services that load the library: a running process keeps the old copy in memory until it restarts.`
        : `${LIB_HOST} reports the same vulnerability (${libEntry.id}, a Medium, fixed in ${libEntry.fixedVersion}) six times: once from the credentialed run's check of the installed package (the package-level finding, ${oldRun.id}) and once per service from the unauthenticated sweep (${newRun.id}), which can only observe each service from outside, in a TLS handshake. That is a true detection of the service, but it shows the vulnerable behaviour, not where the service got its copy. SoftwareInventory does: it lists the system package ${LIB} ${libVersion} and, per service, whether the service links that package or bundles a copy of its own. Only the forms service on 8443/tcp and the directory sync on 636/tcp link the system package: one update to it fixes them together with the package-level finding, so those two detections are duplicates (the decision False positive with the reason Duplicate root cause: closed as a duplicate, which is not a claim that the vulnerability is absent; it is real and is fixed once, on the package-level finding). The headline, the portal on 443/tcp, bundles its own copy of the library from its own vendor, as do the mail relay and the chat service. Each bundled copy is a separate component with its own fix: patch each, in the standard cycle (Medium, 90 days from first detection), and the system package on top. After the updates, restart the services that load the library: a running process keeps the old copy in memory until it restarts.`,
      dup
        ? `The mail relay (465/tcp) and the chat service (8883/tcp) are not duplicates: SoftwareInventory shows each bundles its own copy (the vendor's build, PackageSource vendor), so the system package update does not touch them. Each is a separate component with its own fix: patch each in the standard cycle. The policy row on duplicate detections says to check for bundled copies before closing anything as a duplicate. The twin has the same detections and the same six rows, but there the portal bundles its own copy: its detection is not a duplicate and needs its own update.`
        : `The twin has the same detections and the same six rows, but there the portal links the system package: its detection is then a duplicate of the package-level finding, closed as a duplicate (decision False positive, reason Duplicate root cause), and one update to the system package fixes it. What differs is only what SoftwareInventory says about where the portal gets its library.`,
      `The Medium on the payments database and the Critical on the developer test server are the ordering lesson: the severity column puts the Critical first, the deadlines do not. The Asset tier row moves a deadline by one class and never changes the severity class. DeviceInfo says ${PAY} is a production payments database holding payment data (Criticality High), so its Medium is due as a High: ${SLA_DAYS.high} days from first detection ${payAge} days ago, on ${ymd(payDeadline)} (end of day), after the next window and before the standard cycle: next window, not the ${ymd(payTable)} of a plain Medium. DeviceInfo says ${DEV} is a non-production, isolated developer test server with no production data (Criticality Low, not exposed), so its Critical is due as a High, on ${ymd(devDeadline)} (end of day), after the standard cycle: standard cycle, not the ${ymd(devTable)} of a plain Critical. The payments finding goes ahead of it.`,
      `The Critical on ${KEV_HOST} is on Sim-KEV with a public exploit (listed ${ymd(listedAt)}): the 3-day override makes it due on ${ymd(x1Deadline)} (end of day), before the next window: an emergency change. With the payments finding it fills the capacity of two changes. By the SLA table alone four findings would be due before the standard cycle (the Sim-KEV Critical, the Critical on the developer test server, the High on ${STALE_HOST} and the accepted High on ${EXC_HOST}) and a plan that schedules all four overflows the window: only the Sim-KEV Critical really is, the developer test server's deadline moves by the asset tier row, the file server's result is stale and the print server's flaw is accepted.`,
      `${STALE_HOST} was updated after the older run started (PatchHistory, no reboot pending; SoftwareInventory shows the fixed version) and the sweep (${cov.fresh.scanned} of ${cov.fresh.planned} targets) has no row for it, so nothing re-tested the host: that High is stale, closed with a request for a rescan; its other finding is a different product and is real. ${OLD_HOST} also has an update after the run, but only an operating system rollup that fixes no application vulnerability, so its High is real and due after the standard cycle. The print server's flaw has no vendor fix and an approved, unexpired, time-boxed risk exception (valid until ${ymd(expires)}): accept it and record the expiry.`,
      'The lesson is to count fixes, not findings (check SoftwareInventory for bundled copies before closing a duplicate, and restart the services after the update), and to order by what is due first, which the asset tier row and the Sim-KEV listing set, not by the severity column.',
    ],
    pitfalls: dup
      ? [
          'Counting findings instead of fixes: patching every per-service detection one by one, or scheduling six changes where one update to the system package fixes the portal, forms and directory detections.',
          'Closing a duplicate as if the vulnerability were absent: it is real and is fixed once, on the package-level finding; the duplicates are closed as duplicates of it, not declared harmless.',
          'Closing every per-service detection as a duplicate without checking SoftwareInventory: the mail relay and the chat service bundle their own copies and need their own updates.',
          'Forgetting to restart the services after the package update: a running process keeps the old library in memory, so the finding stays open until it restarts.',
          `Sorting by the severity column: the Critical on ${DEV} looks first, but the asset tier row puts the Medium on ${PAY} ahead of it; the deadline moved, the severity class did not.`,
          'Scheduling an emergency change or the next window for everything the SLA table alone puts before the standard cycle: capacity is two changes, and only the Sim-KEV Critical and the payments Medium need one.',
        ]
      : [
          'Closing the portal detection as a duplicate because the other detections on the server are duplicates: its copy of the library is bundled, so updating the system package leaves it vulnerable.',
          'Counting findings instead of fixes in the other direction: the system package update is one fix for the forms and directory detections, which are duplicates of the package-level finding; patching each of them separately is wasted work.',
          'Treating "closed as a duplicate" as "not vulnerable": a duplicate is real and is fixed once, on the package-level finding.',
          'Forgetting to restart the services after each update: a running process keeps the old library in memory.',
          `Sorting by the severity column: the Critical on ${DEV} looks first, but the asset tier row puts the Medium on ${PAY} ahead of it; the deadline moved, the severity class did not.`,
          'Scheduling an emergency change or the next window for everything the SLA table alone puts before the standard cycle: capacity is two changes, and only the Sim-KEV Critical and the payments Medium need one.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier3',
  title: TITLE,
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.2', '2.3', '2.5', '4.1'],
  kind: 'vuln',
};

export const dupPlugins: VulnTemplate = {
  ...COMMON,
  id: 'vm-dup-plugins',
  twin: 'vm-distinct',
  lesson:
    "SoftwareInventory shows the portal service on the application server linking the system package of the shared library, with no bundled copy of its own, so its per-service detection is a duplicate of the package-level finding: patch the package once, restart the services, and close the duplicates with the decision False positive and the reason Duplicate root cause (closed as a duplicate: the vulnerability is real and is fixed once, on the package-level finding; it is not a claim that it is absent). The package-level finding is that one fix, so it is patched, not closed. Check every per-service detection: the mail relay and the chat service bundle their own copies, so they are not duplicates and need their own updates (closing every per-service detection as a duplicate leaves them open). DeviceInfo and the Asset tier row put the Medium on the payments database ahead of the Critical on the isolated developer test server, which is real and due as a High (standard cycle), not dismissed and not rushed. The jump server's High is still real: its later update is only an operating system rollup. The twin has the same detection, but the portal bundles its own copy.",
  build: (ctx) => build('dup', ctx),
};

export const distinct: VulnTemplate = {
  ...COMMON,
  id: 'vm-distinct',
  twin: 'vm-dup-plugins',
  lesson:
    "SoftwareInventory shows the portal service on the application server carrying a bundled copy of the shared library from its own vendor, so its detection is not a duplicate: updating the system package leaves it vulnerable, and it needs its own update (patch, standard cycle) next to the package-level finding (itself patched, not closed), as do the mail relay's and the chat service's bundled copies (closing every per-service detection as a duplicate leaves them open). DeviceInfo and the Asset tier row put the Medium on the payments database ahead of the Critical on the isolated developer test server, which is real and due as a High (standard cycle), not dismissed and not rushed. The jump server's High is still real: its later update is only an operating system rollup. The twin has the same detection, but the portal links the system package, so there it is a duplicate, closed as a duplicate (decision False positive, reason Duplicate root cause).",
  build: (ctx) => build('distinct', ctx),
};
