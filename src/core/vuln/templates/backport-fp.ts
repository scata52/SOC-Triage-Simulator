// Template vm-backport-fp (T1, A side; the B side comes in WP2). A non-credentialed
// (banner-only) scan reports a Critical remote code execution on a Linux web
// server from the upstream version in the banner. The distribution packages
// the component with the fix backported: SoftwareInventory shows a distro
// package at a release the advisory names, and PatchHistory names the security
// update whose advisory lists the vulnerability id. Finding: false positive.
// The decoy is a second web server with the same banner and the same package
// at a pre-fix release: real. The must-not-miss is a Sim-KEV-listed finding on
// the internet-exposed public website, confirmed by a credentialed scan. Its
// decoy is a Sim-KEV-listed finding on a file server whose fix was installed
// after the credentialed run, with a newer run whose login to that host failed
// (so nothing re-tested it): stale, not an emergency.

import { DAY, iso } from '../../logs/time.ts';
import { sampleSimEpss, simEpssPercentile, type CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  backdateInstall,
  type ShapeWant,
  shaped,
  shapedOn,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  dayStart,
  FICTIONAL_OS,
  hostFacts,
  kevDeadline,
  LOW_EPSS,
  lowerHalfEpss,
  policyAttachments,
  REF_CVSS,
  REF_EPSS,
  REF_EXAM,
  REF_KEV,
  sharedRng,
  sizeRunToHosts,
  slaDeadline,
  withEpss,
  withFix,
  withPublished,
  writeAuthFailure,
  writeChangeTickets,
  writeRiskException,
  writeUnrelatedPatches,
  ymd,
} from './common.ts';

const HEAD_HOST = 'WEBLX01';
const DECOY_HOST = 'WEBLX02';
const PUBLIC_HOST = 'WEB01';
const STALE_HOST = 'FS01'; // the Sim-KEV decoy: fixed after the credentialed run; the newer run's login failed
const DISTRO = FICTIONAL_OS;
const RELEASE_SUFFIX = 'dx54';
const ADVISORY = 'DXSA';
const BUGFIX = 'DXBA';
const WEB_PRODUCT = 'Quorvane httpd';
const WEB_SERVER_RCE = /^(request parser|chunked transfer decoder|URL rewrite module)$/;
const WEB_VENDOR = 'Dovrenix Linux (distribution package)';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'backport-fp');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));

  // ---- runs: an older banner-only run, a credentialed run, a newer partial credentialed run
  const bannerRun = scan.run({ method: 'Unauthenticated', started: now - 4 * DAY, targetsPlanned: 12, targetsScanned: 12 });
  const credRun = scan.run({ method: 'Credentialed', started: now - 3 * DAY, targetsPlanned: 12, targetsScanned: 10 });
  const newRun = scan.run({ method: 'Credentialed', started: now - 1 * DAY, targetsPlanned: 4, targetsScanned: 3 });

  // A quiet entry published before it is first seen (else dated so it was known by then), placed on the host and
  // shaped from the worklist table to what the case needs; a brand re-names its product first.
  const allIds = catalogue.entries.map((e) => e.id);
  const choose = (want: ShapeWant, firstSeen: number, epss: number, host: string, brand?: { product: string; vendor: string }): CatalogueEntry => {
    const pool = free().filter(quiet);
    const known = pool.filter((x) => x.published <= firstSeen);
    const base = rng.pick(known.length > 0 ? known : pool);
    const dated = withPublished(base, Math.min(base.published, dayStart(firstSeen - DAY)), allIds);
    const e = brand ? shaped({ ...dated, ...brand }, rng, want) : shapedOn(dated, host, rng, want);
    used.add(e.id);
    return withEpss(withFix(e, rng), epss);
  };

  // ---- the headline entry: Critical RCE in the web server component
  // (request handling only: the banner announces the httpd, so the flaw sits where it parses requests)
  const fixedAt = now - 9 * DAY;
  let head = choose({ classes: ['rce'], min: 9.8, max: 9.8, component: WEB_SERVER_RCE }, fixedAt - DAY, LOW_EPSS, HEAD_HOST, { product: WEB_PRODUCT, vendor: WEB_VENDOR });
  // a x.y.z upstream fix; the banner shows a version below it
  if (!/^\d+\.\d+\.\d+$/.test(head.fixedVersion)) head = { ...head, fixedVersion: `${rng.int(2, 9)}.${rng.int(1, 9)}.${rng.int(2, 9)}` };
  const bannerVersion = versionBelow(rng, head.fixedVersion);
  const fixedRelease = rng.int(5, 9);
  const oldRelease = rng.int(1, 3);
  const fixedPkg = `${bannerVersion}-${fixedRelease}.${RELEASE_SUFFIX}`;
  const oldPkg = `${bannerVersion}-${oldRelease}.${RELEASE_SUFFIX}`;

  // ---- the Sim-KEV entries: the must-not-miss on the public website, and its decoy on a file server
  const listed = dayStart(now) - 1 * DAY; // listed at the start of yesterday
  const kevOf = (base: CatalogueEntry, label: string, publicExploit: boolean): CatalogueEntry => {
    const eps = sampleSimEpss(rng.fork(label), { listed: true });
    return withFix(
      { ...withPublished(base, Math.min(base.published, listed - 45 * DAY), allIds), knownExploited: true, knownExploitedAdded: listed, epss: eps, epssPercentile: Math.round(simEpssPercentile(eps) * 100) / 100, publicExploit },
      rng,
    );
  };
  const kevEntry = kevOf(choose({ min: 7.6, max: 8.9, network: true }, listed - 45 * DAY, LOW_EPSS, PUBLIC_HOST), 'kev-epss', true);
  const kevDecoyEntry = kevOf(choose({ min: 7.6, max: 8.9 }, listed - 45 * DAY, LOW_EPSS, STALE_HOST), 'kev-decoy-epss', false);
  const kevFirstSeen = credRun.started;

  const lower = (label: string) => lowerHalfEpss(rng.fork(label), 0.45);
  const sqlEntry = choose({ min: 4, max: 6.9 }, now - 30 * DAY, lower('sql'), 'SQL01');
  const appEntry = choose({ min: 4, max: 6.9 }, now - 10 * DAY, lower('app'), 'APP01');
  const buildEntry = choose({ min: 7, max: 8.9 }, now - 3 * DAY, lower('build'), 'BUILD01');
  const jumpEntry = choose({ max: 3.9 }, now - 50 * DAY, lower('jump'), 'JUMP01');
  // the accepted-risk item: a network-reachable (AV:N) flaw with no vendor fix
  const exEntry: CatalogueEntry = { ...choose({ min: 4, max: 6.9, network: true }, now - 130 * DAY, lower('ex'), 'PRINT01'), vendorFix: false, fixedVersion: '' };

  // ---- scope: two Linux web servers of a fictional distribution
  scan.scopeHost({ name: HEAD_HOST, role: 'Intranet web server (customer portal backend)', os: DISTRO, owner: 'Web Platform', criticality: 'High' });
  scan.scopeHost({ name: DECOY_HOST, role: 'Intranet web server (reporting portal)', os: DISTRO, owner: 'Web Platform', criticality: 'Medium' });

  // ---- headline: banner says the upstream version, the package carries the fix
  const advisory = `${ADVISORY}-${iso(now).slice(0, 4)}:${rng.int(1000, 9999)}`;
  const headF = scan.finding(bannerRun, { host: HEAD_HOST, entry: head, port: 443, installedVersion: fixedPkg, bannerVersion, packageSource: 'distro', firstSeen: bannerRun.started });
  const headSoft = scan.software({ host: HEAD_HOST, product: WEB_PRODUCT, vendor: WEB_VENDOR, version: fixedPkg, source: 'distro', installedOn: fixedAt });
  const headPatch = log.patch({
    DeviceName: HEAD_HOST,
    PatchId: advisory,
    Description: `${DISTRO} security update ${advisory}: ${WEB_PRODUCT} ${fixedPkg}. The advisory changelog lists ${head.id} (fix backported; the upstream version string does not change).`,
    InstalledOn: fixedAt,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- decoy: same banner, same package, pre-fix release
  const decoyF = scan.finding(bannerRun, { host: DECOY_HOST, entry: head, port: 443, installedVersion: oldPkg, bannerVersion, packageSource: 'distro', firstSeen: bannerRun.started });
  const decoySoft = scan.software({ host: DECOY_HOST, product: WEB_PRODUCT, vendor: WEB_VENDOR, version: oldPkg, source: 'distro', installedOn: now - 60 * DAY });
  log.patch({
    DeviceName: DECOY_HOST,
    PatchId: `${BUGFIX}-${iso(now).slice(0, 4)}:${rng.int(1000, 9999)}`,
    Description: `${DISTRO} bugfix update: ${WEB_PRODUCT} ${oldPkg} (packaging fixes only; no security advisory)`,
    InstalledOn: now - 60 * DAY,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- must-not-miss: Sim-KEV on the internet-exposed public website, credentialed scan
  const kevF = scan.finding(credRun, { host: PUBLIC_HOST, entry: kevEntry, port: 443, firstSeen: kevFirstSeen });
  const kevIntel = scan.intel(kevEntry);
  const publicDevice = log.deviceRef(PUBLIC_HOST);
  const webOwner = String(publicDevice.row.Owner);

  // ---- decoy of the must-not-miss: Sim-KEV listed, but fixed after the run and never re-tested
  const staleF = scan.finding(credRun, { host: STALE_HOST, entry: kevDecoyEntry, firstSeen: credRun.started });
  const stalePatchedAt = credRun.started + 1 * DAY;
  scan.software({ host: STALE_HOST, product: kevDecoyEntry.product, vendor: kevDecoyEntry.vendor, version: kevDecoyEntry.fixedVersion, installedOn: stalePatchedAt });
  const stalePatch = log.patch({
    DeviceName: STALE_HOST,
    PatchId: `PKG-${rng.int(1000, 9999)}`,
    Description: `${kevDecoyEntry.product} update to ${kevDecoyEntry.fixedVersion} (addresses ${kevDecoyEntry.id})`,
    InstalledOn: stalePatchedAt,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- noise with clear truths
  const sqlF = scan.finding(credRun, { host: 'SQL01', entry: sqlEntry, firstSeen: now - 30 * DAY });
  const appF = scan.finding(credRun, { host: 'APP01', entry: appEntry, firstSeen: now - 10 * DAY });
  const buildF = scan.finding(credRun, { host: 'BUILD01', entry: buildEntry, firstSeen: now - 3 * DAY });
  const jumpF = scan.finding(credRun, { host: 'JUMP01', entry: jumpEntry, firstSeen: now - 50 * DAY });

  // the detected versions were installed on or before first detection (and before the exception ticket)
  const installs: [string, string, CatalogueEntry, number][] = [['sql', 'SQL01', sqlEntry, now - 30 * DAY], ['app', 'APP01', appEntry, now - 10 * DAY], ['build', 'BUILD01', buildEntry, now - 3 * DAY], ['jump', 'JUMP01', jumpEntry, now - 50 * DAY]];
  for (const [label, host, e, first] of installs) backdateInstall(ctx, label, host, e.product, first);

  // ---- accepted risk with a valid, time-boxed exception (a network flaw: the print VLAN limits who can reach it)
  const exF = scan.finding(credRun, { host: 'PRINT01', entry: exEntry, firstSeen: now - 120 * DAY });
  const approvedAt = now - 100 * DAY;
  const expires = now + 45 * DAY;
  const exTicket = writeRiskException(ctx, exEntry, 'PRINT01', 'print VLAN', approvedAt, expires);
  backdateInstall(ctx, 'ex', 'PRINT01', exEntry.product, now - 120 * DAY, approvedAt);

  // ---- noise: the worklist hosts get none (their runs are older than the newest), the two runs' lists are disjoint
  addBackgroundNoise(
    ctx,
    [
      { run: bannerRun, hosts: ['FS02', 'DC01'] },
      { run: credRun, hosts: ['SCCM01', 'BKP01', 'ADCONNECT01'] },
      { run: newRun, hosts: ['DC02'] },
    ],
    [head, kevEntry, kevDecoyEntry, sqlEntry, appEntry, buildEntry, jumpEntry, exEntry],
    { worklistSize: 9, extraNonWorklist: 1 }, // the login-failure row
  );
  writeUnrelatedPatches(ctx, ['SCCM01', 'BKP01', 'DC01'], 2);
  writeChangeTickets(ctx, cal);
  const authFailure = writeAuthFailure(ctx, newRun, STALE_HOST); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  const spec = (w: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: w.findingId, row: w.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const decoyDeadline = slaDeadline('critical', bannerRun.started);
  const findings: FindingSpec[] = [
    spec(headF, {
      truth: {
        decision: 'false-positive',
        schedule: 'none',
        reasons: ['backported-fix', 'banner-only'],
        contradicting: contradictionsFor(head, facts(HEAD_HOST, { real: false, packageBasis: false, fixedBeforeScan: true }), ['backported-fix', 'banner-only']),
      },
      weight: 1,
      evidence: [
        {
          id: 'distro-package-release',
          label: `${HEAD_HOST} runs the distribution package at a release that carries the fix`,
          why: `SoftwareInventory shows ${WEB_PRODUCT} ${fixedPkg} (PackageSource distro). The banner only shows the upstream ${bannerVersion}, below the upstream fix ${head.fixedVersion}, because a distribution backports fixes without changing that string.`,
          rows: [headSoft],
        },
        {
          id: 'advisory-names-the-vuln',
          label: `The installed security update's advisory lists ${head.id}`,
          why: `A release bump alone proves nothing. PatchHistory names ${advisory}, installed ${ymd(fixedAt)} with no reboot pending, and its changelog lists ${head.id}.`,
          rows: [headPatch],
        },
        {
          id: 'banner-only-scan',
          label: 'The finding came from a non-credentialed, banner-only scan',
          why: 'The scan run was non-credentialed: it read the version from the service banner and did not inspect installed packages or backports. The finding row itself says so in its Evidence: the version came from the banner.',
          rows: [bannerRun.row, headF.row],
        },
      ],
    }),
    spec(decoyF, {
      truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['sla-deadline'], contradicting: [...contradictionsFor(head, facts(DECOY_HOST, { packageBasis: false }), ['sla-deadline']), 'backported-fix'] },
      weight: 1,
      evidence: [
        {
          id: 'pre-fix-release',
          label: `${DECOY_HOST} has the same banner but the package is still at a pre-fix release`,
          why: `SoftwareInventory shows ${WEB_PRODUCT} ${oldPkg}, an older release than ${fixedPkg}, and PatchHistory has only a bugfix update with no advisory naming ${head.id}. The finding is real. First detected ${ymd(bannerRun.started)}, its 7-day Critical deadline (${ymd(decoyDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}): emergency change.`,
          rows: [decoySoft],
        },
      ],
    }),
    spec(kevF, {
      truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['known-exploited', 'internet-exposed'], contradicting: contradictionsFor(kevEntry, facts(PUBLIC_HOST), ['known-exploited', 'internet-exposed']) },
      weight: 3,
      mustNotMiss: true,
      evidence: [
        {
          id: 'kev-listing',
          label: 'The vulnerability is on the Sim-KEV list (exploitation observed in the wild)',
          why: `The 3-day rule counts from the later of first detection and the listing date (${ymd(listed)}), so the deadline (${ymd(kevDeadline(kevFirstSeen, listed))}, end of day) falls before the next window (${ymd(cal.next.start)}): only an emergency change meets it. A public exploit exists too, but it is the listing alone that sets the 3-day deadline.`,
          rows: [kevIntel],
        },
        {
          id: 'internet-exposed',
          label: `${PUBLIC_HOST} is reachable from the internet`,
          why: 'DeviceInfo shows the public website is exposed to the internet, and a credentialed scan confirmed the vulnerable package, so this is not a banner guess.',
          rows: [publicDevice],
        },
      ],
    }),
    spec(staleF, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(kevDecoyEntry, facts(STALE_HOST, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      evidence: [
        {
          id: 'patched-after-scan',
          label: `${STALE_HOST}'s Sim-KEV finding was fixed after the credentialed run started`,
          why: `PatchHistory shows the update that addresses ${kevDecoyEntry.id} installed ${ymd(stalePatchedAt)}, after the run of ${ymd(credRun.started)} started (Result Installed, no reboot pending). The newer run (${newRun.id}) wrote "Authentication failure: local checks not run" for ${STALE_HOST}, so nothing re-tested it and the old result is still shown. Being on the Sim-KEV list does not make a fixed vulnerability exploitable: dismiss it and request a rescan.`,
          rows: [stalePatch, authFailure],
        },
      ],
    }),
    spec(buildF, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(buildEntry, facts('BUILD01'), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(sqlF, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(sqlEntry, facts('SQL01'), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(appF, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(appEntry, facts('APP01'), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(jumpF, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(jumpEntry, facts('JUMP01'), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(exF, {
      truth: { decision: 'accept', schedule: 'none', reasons: ['approved-exception', 'no-vendor-fix'], contradicting: contradictionsFor(exEntry, facts('PRINT01', { exception: true }), ['approved-exception', 'no-vendor-fix']) },
      weight: 0.5,
      evidence: [
        {
          id: 'exception-ticket',
          label: 'A time-boxed risk exception is approved and still valid',
          why: `The Tickets row shows an approved exception for ${exEntry.id} on PRINT01 valid until ${ymd(expires)}, with a compensating measure that limits network access to the print VLAN; there is no vendor fix. The policy lets an approved, unexpired exception allow accept: accept it and note the expiry date for review.`,
          rows: [exTicket],
        },
      ],
    }),
  ];

  const fsOwner = String(log.deviceRef(STALE_HOST).row.Owner);
  const ownerMap = new Map<string, string[]>();
  for (const [owner, what] of [['Web Platform', 'the web servers'], [webOwner, 'the public website'], [fsOwner, 'the file server'], ['IT Infrastructure', 'the change windows']] as const) ownerMap.set(owner, [...(ownerMap.get(owner) ?? []), what]);
  const ownerText = [...ownerMap].map(([owner, what]) => `${owner} for ${what.join(' and ')}`).join('; ');
  const ids = { head: headF.findingId, decoy: decoyF.findingId, kev: kevF.findingId, build: buildF.findingId, sql: sqlF.findingId, app: appF.findingId, jump: jumpF.findingId };

  return {
    briefing: `${world.org.name}: review of the latest scan results for the web servers and internal servers (a non-credentialed run, a credentialed run and a newer credentialed run that did not cover every target). The scanner reports a Critical remote code execution on a Linux web server. Decide for each worklist finding whether to patch, mitigate, accept or dismiss it, order the worklist, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), software inventory, patch, asset and ticket data are in the SIEM tables. All data is simulated.`,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.kev, ids.decoy, ids.build, ids.sql, ids.app, ids.jump],
    tiers: [[ids.kev], [ids.decoy]],
    hints: [
      'How did the scanner learn the version of the web server component: from the service banner or from the installed packages?',
      `Compare the banner-based scan with SoftwareInventory and PatchHistory for ${HEAD_HOST} and ${DECOY_HOST}. A distribution can fix a flaw without changing the upstream version string. For every Sim-KEV finding, also check PatchHistory and whether a later run re-tested the host.`,
      `${HEAD_HOST} has the distro package at a release whose security advisory names the vulnerability id: dismiss it. ${DECOY_HOST} has the same banner but an older release with no such advisory: emergency change. The Sim-KEV finding on the public website is real and exposed. The Sim-KEV finding on ${STALE_HOST} was fixed after its run and the newer run could not log in: dismiss it and ask for a rescan.`,
    ],
    solution: [
      {
        title: 'How was each version detected, and which runs did what?',
        kql: 'ScanRuns\n| project ScanRunId, Method, Started, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: 'Both Critical findings come from a non-credentialed run that reads the version from the banner only; the newest run logged an authentication failure.',
      },
      {
        title: 'Which findings and login failures sit on these hosts?',
        kql: `VulnFindings\n| where DeviceName in ("${HEAD_HOST}", "${DECOY_HOST}", "${STALE_HOST}")\n| project DeviceName, VulnId, Title, Severity, DetectedVersion, ScanRunId, FirstSeen, LastSeen, RecordId`,
        why: `Both web servers report the same vulnerability with the same banner version. ${STALE_HOST} has a finding from the older credentialed run and a login-failure row from the newer one.`,
      },
      {
        title: 'What package release is actually installed?',
        kql: `SoftwareInventory\n| where DeviceName in ("${HEAD_HOST}", "${DECOY_HOST}", "${PUBLIC_HOST}")\n| project DeviceName, Product, Version, PackageSource, InstalledOn, RecordId`,
        why: `${HEAD_HOST} has release ${fixedRelease} of ${WEB_PRODUCT} (distro package); ${DECOY_HOST} is still at release ${oldRelease}. ${PUBLIC_HOST} runs the vulnerable version of its own product, with no fixed version installed.`,
      },
      {
        title: 'Does an update name the vulnerability, and when was it installed?',
        kql: `PatchHistory\n| where DeviceName in ("${HEAD_HOST}", "${DECOY_HOST}", "${STALE_HOST}", "${PUBLIC_HOST}")\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: `Only ${HEAD_HOST}'s security update lists ${head.id}; the other web server's update is a bugfix with no advisory. ${STALE_HOST} has an update naming its Sim-KEV vulnerability, installed after the run. ${PUBLIC_HOST} has none: nothing has been installed there.`,
      },
      {
        title: 'Which findings are on the Sim-KEV list?',
        kql: `VulnIntel\n| where KnownExploited == true`,
        why: 'Two vulnerabilities are listed: only the one on the exposed public website, still unpatched, needs an emergency change.',
      },
      {
        title: 'Are the Sim-KEV findings still open, and on which hosts?',
        kql: 'VulnFindings\n| join kind=inner VulnIntel on VulnId\n| where KnownExploited\n| project DeviceName, VulnId, ScanRunId, LastSeen, Status, RecordId',
        why: `Two findings are on the Sim-KEV list and both are still Open in the scan store. ${PUBLIC_HOST}'s has no update in PatchHistory and no newer run that re-tested it, so it is still unpatched; ${STALE_HOST}'s was fixed after its run and never re-tested.`,
      },
      {
        title: 'Is the affected host reachable from the internet?',
        kql: `DeviceInfo\n| where DeviceName == "${PUBLIC_HOST}"`,
        why: 'The public website is exposed to the internet.',
      },
      {
        title: 'Is there an approved risk exception?',
        kql: `Tickets\n| where Title has "Risk exception"`,
        why: 'The print server finding has an approved, time-boxed exception because no vendor fix exists.',
      },
      {
        title: 'When are the change windows and the freeze?',
        kql: 'Tickets\n| where Type == "Change"\n| sort by WindowStart asc',
        why: 'The next window and the standard cycle are the dates each deadline is compared with.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerText}.`, keywords: ['owner', ...ownerMap.keys()].map((k) => k.toLowerCase()) },
      { id: 'risk', text: 'Explains that the banner shows only the upstream version, that the fix was backported on one server, that the vulnerability affecting the public website appears on Sim-KEV (exploitation observed) and unpatched, and that the file server finding is stale.', keywords: ['banner', 'backport', 'known exploited', 'sim-kev', 'internet', 'stale'] },
      { id: 'action', text: `Dismisses the ${HEAD_HOST} and ${STALE_HOST} findings (and asks for rescans), patches ${DECOY_HOST} and the public website by emergency change, accepts the print server exception.`, keywords: ['dismiss', 'rescan', 'emergency', 'patch', 'accept'] },
      { id: 'date', text: 'Gives dates or deadlines, ties them to the policy and states when the exception expires.', keywords: ['3 days', '7 days', 'deadline', 'window', 'expire', 'expiry', 'review'] },
    ],
    explanation: [
      `The scanner reports a Critical ${head.base.toFixed(1)} remote code execution on ${HEAD_HOST}, but it was a non-credentialed scan: the version came from the service banner (${bannerVersion}), which shows the upstream release. The distribution packages the component and backports fixes without changing that string. SoftwareInventory shows the distro package at ${fixedPkg}, and PatchHistory names the security update ${advisory} whose changelog lists ${head.id}. A release bump alone is not proof: it is the advisory naming the vulnerability id for that release that shows the fix. This is a false positive: dismiss the finding and request a credentialed rescan.`,
      `${DECOY_HOST} shows the same banner, but its package is at ${oldPkg}, an older release, and no advisory names the vulnerability there: the finding is real. First detected ${ymd(bannerRun.started)}, its 7-day Critical deadline (${ymd(decoyDeadline)}, end of day) falls before the next window, so it needs an emergency change.`,
      `The Sim-KEV list includes the vulnerability affecting the public website, meaning exploitation has been observed in the wild, and the website is exposed to the internet. Our own 3-day rule counts from the later of first detection and the listing date, so the deadline falls before the next window: emergency change. The Sim-KEV listing and the public exploit both apply; the listing alone sets the 3-day deadline, and the public exploit adds urgency.`,
      `${STALE_HOST} also has a Sim-KEV-listed finding, but PatchHistory shows the update that addresses it installed after the credentialed run started, no reboot pending, and the newer run's "Authentication failure: local checks not run" row for ${STALE_HOST} shows nothing re-tested it (its finding still carries the credentialed run's ${credRun.id} and its LastSeen). It is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
      'The remaining items follow the standard policy: Medium and Low have long deadlines, and the High finding first seen 3 days ago has 30 days, so the standard cycle applies. The print server finding has no vendor fix and an approved, unexpired, time-boxed exception, so accept it and record its expiry.',
    ],
    pitfalls: [
      'Trusting the CVSS score and the banner version: a banner-only scan cannot see backported fixes.',
      'Treating a higher package release number as proof of the fix without checking that the advisory lists the vulnerability id.',
      'Dismissing both web servers because one is a false positive: the second host has the same banner but an older package release.',
      'Escalating every Sim-KEV finding without reading PatchHistory: one listed vulnerability was already fixed after the scan.',
      'Ordering by CVSS: the Sim-KEV-listed vulnerability on the exposed website scores below the two Critical findings, yet exploitation has been observed for it, so it goes first.',
      'Telling the two Criticals apart by the scan or the score: both come from the same banner-only run with the same banner version. The false positive is the one whose distribution package release carries the backported fix that the advisory lists; the other has an older release and no such advisory.',
    ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

export const backportFp: VulnTemplate = {
  id: 'vm-backport-fp',
  difficulty: 'tier2',
  title: 'Scan review: web servers',
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.2', '2.3', '2.5', '4.1'],
  kind: 'vuln',
  lesson: 'The banner-only scan shows the upstream version, but SoftwareInventory (distro package at the fixed release) and the PatchHistory advisory that lists the vulnerability id show the fix is already backported on one server; the sibling server has the same banner and an older release.',
  build,
};
