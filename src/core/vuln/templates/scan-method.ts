// Templates vm-noncred-low (T7, A side) and vm-cred-high (T7, B side). An unauthenticated sweep
// (banner only) reports the same Critical on two look-alike intranet application servers. A
// credentialed run, older than the sweep, tested one of them and not the other. The twins mirror
// the two hosts' roles; the worklist rows are identical.
//
// The scan store keeps one row per finding (ScanRunId and LastSeen are the latest run that saw it, and
// a finding that a later run re-tested and no longer saw is closed), so the credentialed run that shows
// the banner guess wrong has to be older than the sweep that reports it. What differs between the twins
// is what that older run did on each host and what the host's inventory says:
//
// A (vm-noncred-low): the headline host (INTRA01) was reached by the credentialed run with a working
// login (a local configuration check row, no authentication failure) and SoftwareInventory shows the
// component at a version ABOVE the fix. The sweep's banner announced an old release: a guess, wrong.
// False positive; dismiss it and ask for a credentialed rescan. The look-alike sibling (INTRA02) is the
// opposite: the credentialed run's login failed there ("Authentication failure: local checks not run"),
// so its silence proves nothing, and SoftwareInventory shows the vulnerable version: real, patch.
//
// B (vm-cred-high): the same two hosts with the roles swapped. The headline (INTRA01) is the one whose
// login failed and whose inventory shows the vulnerable version: the banner is accurate, patch by
// emergency change. The sibling is the false positive.
//
// Distinct from T1 (backport): there is no distribution backport and no advisory. The false positive's
// installed version number is itself above the fix; what the lesson teaches is the scan method and the
// coverage of each run (ScanRuns Method and AuthFailures, the host's rows in each run).

import { DAY, MIN } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
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
  LOW_EPSS,
  lowerHalfEpss,
  ownersOf,
  policyAttachments,
  productKindOf,
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
  writeAuthFailure,
  writeChangeTickets,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  dismissOn,
  lowered,
  verbsOn,
  VERBS_PATCH,
} from './common.ts';

type Variant = 'noncred' | 'cred';

const HOST_1 = 'INTRA01'; // findings[0] in both twins
const HOST_2 = 'INTRA02'; // findings[1] in both twins
const DB = 'SQL01';
const APP = 'APP01';
const JUMP = 'JUMP01';
const OWNER = 'Application Platform';
const CHECK_INDEX = 2; // the SSH configuration check: the credentialed run's "local check ran" row on the host it reached

const TITLE = 'Scan review: intranet application servers';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;
const WEB_OR_SERVER = (e: CatalogueEntry): boolean => ['web-app', 'server'].includes(productKindOf(e.product));

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const cred = variant === 'cred'; // B: the headline is the real finding
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'scan-method');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const allIds = catalogue.entries.map((e) => e.id);
  const versionOf = (label: string, e: CatalogueEntry): string => {
    const r = sharedRng(ctx, `version/${label}`);
    return e.vendorFix ? versionBelow(r, e.fixedVersion) : `${r.int(1, 9)}.${r.int(0, 12)}.${r.int(0, 9)}`;
  };

  // ---- two runs: an older credentialed run that did not log in everywhere, a newer unauthenticated sweep (banner only)
  const runRng = sharedRng(ctx, 'scan-runs');
  const credId = `SCN-${runRng.int(1000, 4999)}`;
  const sweepId = `SCN-${runRng.int(5000, 9999)}`;
  const credRun = scan.run({ id: credId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 9 * DAY, targetsPlanned: 12, targetsScanned: 12 });
  const sweepRun = scan.run({ id: sweepId, durationMin: runRng.int(45, 180), method: 'Unauthenticated', started: now - 3 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const lastSeen = (run: typeof credRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // ---- dates (shared by the twins)
  const firstSeen = sweepRun.started; // the sweep is the first run to report the headline flaw
  const f3First = now - 30 * DAY; // Medium: standard cycle
  const f4First = now - 20 * DAY; // High: due 30 days on, after the next window and before the standard cycle
  const f5First = now - 50 * DAY; // Low

  // ---- entries (twins share every choice)
  // `by` is the date the flaw must have been published by (default: the first detection). The headline is published before the credentialed run started, so that run's silence about it means something.
  // Worklist flaws on different hosts sit on different products (version realism): a host never runs a product below the
  // fix of another worklist vulnerability on that product unless it carries that finding too.
  const taken = new Set<string>();
  const choose = (want: ShapeWant, first: number, epss: number, host: string | null, pool: (e: CatalogueEntry) => boolean = () => true, by: number = first): CatalogueEntry => {
    const candidates = free().filter((e) => quiet(e) && pool(e));
    const known = candidates.filter((x) => x.published <= by);
    const base = rng.pick(known.length > 0 ? known : candidates);
    const dated = withPublished(base, Math.min(base.published, dayStart(by - DAY)), allIds);
    const e = host === null ? shaped(dated, rng, want) : shapedOn(dated, host, rng, want, taken);
    used.add(base.id);
    used.add(e.id);
    taken.add(e.product);
    return withEpss(withFix(e, rng), epss);
  };
  // The headline: a Critical network flaw in a web-facing application component, the same on both servers.
  let head = choose({ min: 9, network: true }, firstSeen, LOW_EPSS, null, WEB_OR_SERVER, credRun.started);
  if (!/^\d+\.\d+\.\d+$/.test(head.fixedVersion)) head = { ...head, fixedVersion: `${rng.int(2, 9)}.${rng.int(2, 9)}.${rng.int(2, 9)}` };
  const bannerVersion = versionBelow(rng, head.fixedVersion);
  const [fa, fb] = head.fixedVersion.split('.').map(Number);
  const newerVersion = `${fa}.${fb + rng.int(1, 2)}.${rng.int(0, 5)}`; // above the fix by its own version number (no backport)
  const port = rng.pick([443, 8443, 8080]);
  const f3Entry = choose({ min: 4, max: 6.9 }, f3First, lowerHalfEpss(rng.fork('f3'), 0.45), DB);
  const f4Entry = choose({ min: 7, max: 8.9 }, f4First, lowerHalfEpss(rng.fork('f4'), 0.45), APP);
  const f5Entry = choose({ max: 3.9 }, f5First, lowerHalfEpss(rng.fork('f5'), 0.45), JUMP);

  // ---- the two application servers: identical hosts in both twins
  const role = `Intranet application server (${head.product})`;
  scopeSharedHost(ctx, { name: HOST_1, role, os: FICTIONAL_OS, owner: OWNER, criticality: 'High' }, 'intra01');
  scopeSharedHost(ctx, { name: HOST_2, role, os: FICTIONAL_OS, owner: OWNER, criticality: 'High' }, 'intra02');
  const realHost = cred ? HOST_1 : HOST_2; // the credentialed login failed here; the inventory shows the vulnerable version
  const fpHost = cred ? HOST_2 : HOST_1; // the credentialed run reached it; the inventory shows a version above the fix

  // ---- the sweep's two rows: the same banner on both servers (rows identical in the twins)
  const f1 = scan.finding(sweepRun, { host: HOST_1, entry: head, port, firstSeen, lastSeen: lastSeen(sweepRun, 'f1'), installedVersion: HOST_1 === fpHost ? newerVersion : bannerVersion, bannerVersion });
  const f2 = scan.finding(sweepRun, { host: HOST_2, entry: head, port, firstSeen, lastSeen: lastSeen(sweepRun, 'f2'), installedVersion: HOST_2 === fpHost ? newerVersion : bannerVersion, bannerVersion });
  const realF = cred ? f1 : f2;
  const fpF = cred ? f2 : f1;
  const headIntel = scan.intel(head);
  // Inventory: the false positive's package is above the fix, installed before the credentialed run; the real one is the banner's version.
  const fpSoft = scan.software({ host: fpHost, product: head.product, vendor: head.vendor, version: newerVersion, installedOn: installedBefore(ctx, 'fp', credRun.started) });
  const realSoft = scan.software({ host: realHost, product: head.product, vendor: head.vendor, version: bannerVersion, installedOn: installedBefore(ctx, 'real', firstSeen) });

  // ---- the credentialed run's clear-cut findings (package-level)
  const f3 = scan.finding(credRun, { host: DB, entry: f3Entry, firstSeen: f3First, lastSeen: lastSeen(credRun, 'f3'), installedVersion: versionOf('f3', f3Entry) });
  const f4 = scan.finding(credRun, { host: APP, entry: f4Entry, firstSeen: f4First, lastSeen: lastSeen(credRun, 'f4'), installedVersion: versionOf('f4', f4Entry) });
  const f5 = scan.finding(credRun, { host: JUMP, entry: f5Entry, firstSeen: f5First, lastSeen: lastSeen(credRun, 'f5'), installedVersion: versionOf('f5', f5Entry) });
  for (const [label, host, e, first] of [['f3', DB, f3Entry, f3First], ['f4', APP, f4Entry, f4First], ['f5', JUMP, f5Entry, f5First]] as const)
    scan.software({ host, product: e.product, vendor: e.vendor, version: versionOf(label, e), installedOn: installedBefore(ctx, label, first) });

  // ---- noise: the credentialed run's worklist hosts get none (a row there would blur what was tested); the two runs' lists are disjoint
  addBackgroundNoise(
    ctx,
    [
      { run: credRun, hosts: ['FS02', 'DC01', 'DC02'] },
      { run: sweepRun, hosts: ['SCCM01', 'BKP01', 'ADCONNECT01'] },
    ],
    [head, f3Entry, f4Entry, f5Entry],
    { worklistSize: 5, extraNonWorklist: 2 }, // the "login worked" row and the login-failure row
  );
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'DC02', 'SCCM01', 'BKP01', 'ADCONNECT01'], 2, sharedRng(ctx, 'unrelated-patches'));
  writeChangeTickets(ctx, cal);

  // ---- the credentialed run on the two servers: a local check row where the login worked, the login-failure row where it did not
  const covered = scan.hygieneFinding(credRun, fpHost, CHECK_INDEX);
  covered.row.row.Evidence = `Credentialed login to ${fpHost} succeeded; local configuration check on 22/tcp (ssh): deprecated key exchange algorithms are enabled.`;
  const authFailure = writeAuthFailure(ctx, credRun, realHost); // after every other write to the run
  sizeRunToHosts(ctx, credRun);
  sizeRunToHosts(ctx, sweepRun);

  // ---- the truth (derived from the policy, the calendar, the dates and the rows)
  const spec = (w: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: w.findingId, row: w.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  type Part = Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>;
  const critDeadline = slaDeadline('critical', firstSeen);
  const f4Deadline = slaDeadline('high', f4First);
  const cov = coverageOf(credRun);
  const sweepAgo = Math.round((now - sweepRun.started) / DAY);

  // the banner guess that the data disproves: false positive
  // The VulnIntel row is the same for both servers: only the first (headline) finding carries it as an evidence point, so one pin earns one point.
  const withoutIntel = (part: Part, intelPoint: boolean): Part => (intelPoint ? part : { ...part, evidence: part.evidence.filter((e) => !e.id.startsWith('fixed-version-')) });
  const fpSpec = (host: string, f: WrittenFinding, intelPoint: boolean): Part => withoutIntel({
    truth: {
      decision: 'false-positive',
      schedule: 'none',
      reasons: ['banner-only'],
      contradicting: [...new Set([...contradictionsFor(head, facts(host, { real: false, packageBasis: false, fixedBeforeScan: true }), ['banner-only']), 'backported-fix' as const])],
    },
    weight: 1,
    lesson: true,
    evidence: [
      {
        id: 'credentialed-run-reached-host',
        label: `The credentialed run (older than the sweep) reached ${host} with a working login`,
        why: `${credRun.id} is a credentialed run: it reads installed packages, not banners. VulnFindings has a row from it for ${host} (a local configuration check, login succeeded) and no "Authentication failure" row, and the AuthFailures of the run are about another host. It did not report ${head.id} on ${host}. It is older than the sweep, so the sweep did not close anything: the scan store keeps the sweep's row open.`,
        rows: [covered.row], // the row that differs between the twins for this host; the run's own ScanRuns row is the same in both and proves nothing
      },
      {
        id: 'installed-version-above-fix',
        label: `SoftwareInventory shows ${head.product} on ${host} above the fixed version`,
        why: `SoftwareInventory has ${head.product} ${newerVersion} on ${host}, installed ${ymd(fpSoft.row.InstalledOn as number)}, before the credentialed run. VulnIntel says the fix is in ${head.fixedVersion}: the installed release is itself above it, so this is no backport and needs no advisory (PatchHistory has none). The banner's older release was a guess.`,
        rows: [fpSoft],
      },
      {
        id: `fixed-version-${host.toLowerCase()}`,
        label: 'VulnIntel gives the release in which the flaw is fixed',
        why: `VulnIntel has ${head.id}: fixed in ${head.fixedVersion}, no Sim-KEV listing and a low Sim-EPSS. It is the reference both servers' installed releases are compared with (the same row in the twin).`,
        rows: [headIntel],
      },
      {
        id: 'banner-only-sweep',
        label: 'The finding came from an unauthenticated sweep that read only the service banner',
        why: `${sweepRun.id} is an unauthenticated run (Method Unauthenticated, Vantage Internal): its Evidence in VulnFindings says the version was taken from the banner only and that installed packages were not inspected. A banner is a string the service announces about itself; it can be left over from an old release or set in the configuration. Dismiss the finding and ask for a credentialed rescan to confirm.`,
        rows: [f.row],
      },
    ],
  }, intelPoint);

  // the sweep's banner is accurate: the login failed on this host and the inventory shows the vulnerable version
  const realSpec = (host: string, f: WrittenFinding, intelPoint: boolean): Part => withoutIntel({
    truth: {
      decision: 'patch',
      schedule: 'emergency',
      slaLatest: 'emergency',
      reasons: ['sla-deadline'],
      contradicting: [...new Set([...contradictionsFor(head, facts(host, { packageBasis: false }), ['sla-deadline']), 'backported-fix' as const])],
    },
    weight: 1,
    lesson: true,
    evidence: [
      {
        id: 'credentialed-login-failed',
        label: `The credentialed run's login to ${host} failed: it did not test the host`,
        why: `VulnFindings has an "Authentication failure: local checks not run" row for ${host} from ${credRun.id}, and AuthFailures of that run is ${cov.failures}: no local check ran there, so the run's silence about ${head.id} is not evidence that ${host} is clean.`,
        rows: [authFailure], // the run's own ScanRuns row is the same in both twins and proves nothing
      },
      {
        id: 'installed-version-vulnerable',
        label: `SoftwareInventory shows ${head.product} on ${host} at the vulnerable version the banner announced`,
        why: `SoftwareInventory has ${head.product} ${bannerVersion} on ${host}, installed ${ymd(realSoft.row.InstalledOn as number)}, below the fix in ${head.fixedVersion} (VulnIntel): the package-level data agrees with the banner, so the finding is real.`,
        rows: [realSoft],
      },
      {
        id: `fixed-version-${host.toLowerCase()}`,
        label: 'VulnIntel gives the release in which the flaw is fixed',
        why: `VulnIntel has ${head.id}: fixed in ${head.fixedVersion}, no Sim-KEV listing and a low Sim-EPSS. It is the reference both servers' installed releases are compared with (the same row in the twin).`,
        rows: [headIntel],
      },
      {
        id: 'sweep-finding-stands',
        label: 'The sweep finding is real, and it is Critical',
        why: `First detected ${ymd(firstSeen)} (${sweepAgo} days ago), its 7-day Critical deadline (${ymd(critDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}): emergency change.`,
        rows: [f.row],
      },
    ],
  }, intelPoint);

  const findings: FindingSpec[] = [
    spec(f1, HOST_1 === fpHost ? fpSpec(HOST_1, f1, true) : realSpec(HOST_1, f1, true)),
    spec(f2, HOST_2 === fpHost ? fpSpec(HOST_2, f2, false) : realSpec(HOST_2, f2, false)),
    spec(f3, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f3Entry, facts(DB), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f4, { truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'], contradicting: contradictionsFor(f4Entry, facts(APP), ['sla-deadline']) }, weight: 0.5, evidence: [] }),
    spec(f5, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f5Entry, facts(JUMP), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
  ];

  const ids = { real: realF.findingId, fp: fpF.findingId, f3: f3.findingId, f4: f4.findingId, f5: f5.findingId };
  const ownerNames = [...new Set([...ownersOf(ctx, [HOST_1, HOST_2, DB, APP, JUMP]), 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const sweepCov = coverageOf(sweepRun);

  const briefing = `${world.org.name}: review of the latest scan results for two intranet application servers and the internal servers in scope (a credentialed run and a newer unauthenticated sweep; neither covered every target). The sweep reports the same Critical on both application servers. Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, software inventory, patch and ticket data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'How did the scanner learn the version of the application component on each server: from a service banner, or from the installed packages? Which scan runs touched these servers, and by what method?';
  const second = `Compare the runs in ScanRuns (Method, Started, AuthFailures) with the rows each run wrote for ${HOST_1} and ${HOST_2} in VulnFindings, then read SoftwareInventory for the installed release and VulnIntel for the fixed one.`;

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.real, ids.f4, ids.f3, ids.f5],
    tiers: [[ids.real], [ids.f4], [ids.f3, ids.f5]],
    hints: [
      lead,
      second,
      cred
        ? `${HOST_1}: the credentialed run's login failed, so it did not test the host, and SoftwareInventory shows the vulnerable release the banner announced: the finding is real, emergency change. ${HOST_2}: the credentialed run reached it and SoftwareInventory shows a release above the fix, so the banner was a guess: dismiss it and ask for a credentialed rescan.`
        : `${HOST_1}: the credentialed run reached the host and SoftwareInventory shows a release above the fix, so the banner was a guess: dismiss it and ask for a credentialed rescan. ${HOST_2}: the credentialed run's login failed, so it did not test the host, and SoftwareInventory shows the vulnerable release: the finding is real, emergency change.`,
    ],
    solution: [
      {
        title: 'Which runs were there, by what method, and how much did each cover?',
        kql: 'ScanRuns\n| project ScanRunId, Tool, Method, Vantage, Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `${credRun.id} is credentialed and older (${cov.scanned} of ${cov.planned} targets, ${cov.failures} authentication failure); ${sweepRun.id} is the newer unauthenticated sweep (${sweepCov.scanned} of ${sweepCov.planned} targets): it sees only what the service shows remotely (banner, responses), not the installed packages.`,
      },
      {
        title: `What did each run write for ${HOST_1} and ${HOST_2}?`,
        kql: `VulnFindings\n| where DeviceName in ("${HOST_1}", "${HOST_2}")\n| project DeviceName, VulnId, Title, Severity, CvssBase, DetectedVersion, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId\n| sort by DeviceName asc, ScanRunId asc`,
        why: `Both servers carry the same Critical from the sweep with the same banner version (Evidence: banner only). The credentialed run wrote a local check row for ${fpHost} and the "Authentication failure: local checks not run" row for ${realHost}.`,
      },
      {
        title: 'Which release of the component is actually installed on each server?',
        kql: `SoftwareInventory\n| where DeviceName in ("${HOST_1}", "${HOST_2}")\n| project DeviceName, Product, Version, PackageSource, InstalledOn, RecordId`,
        why: `${fpHost} has ${head.product} ${newerVersion}, above the fix; ${realHost} has ${bannerVersion}, the vulnerable release the banner announced.`,
      },
      {
        title: 'In which release is the flaw fixed?',
        kql: `VulnIntel\n| where VulnId == "${head.id}"\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, FixedVersion, RecordId`,
        why: `The fix is in ${head.fixedVersion}; no Sim-KEV listing, a low Sim-EPSS, no public exploit: the Critical class and the 7-day SLA set the urgency of the real server.`,
      },
      {
        title: 'Did an update change either server (is there a backport to explain)?',
        kql: `PatchHistory\n| where DeviceName in ("${HOST_1}", "${HOST_2}")\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        expectEmpty: true,
        why: 'Neither server has an update record: the false positive is not a distribution backport (that is another case); its installed release number is itself above the fix.',
      },
      {
        title: 'Who owns the two servers?',
        kql: `DeviceInfo\n| where DeviceName in ("${HOST_1}", "${HOST_2}")\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, RecordId`,
        why: 'Two internal servers of the same role, owned by Application Platform: not exposed to the internet.',
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
        text: `States that the sweep read only the service banner, that the credentialed run tested ${fpHost} (inventory above the fix: the banner was wrong) but not ${realHost} (its login failed; inventory shows the vulnerable release: the banner is right).`,
        keywords: lowered(
          [realHost, fpHost].flatMap((h) =>
            h === realHost
              ? [
                  `login failed on ${h}`, `login on ${h} failed`, `login to ${h} failed`, `authentication failed on ${h}`, `authentication failure on ${h}`, `authentication failed for ${h}`, `${h} login failed`, `${h} authentication failed`, `${h} credentialed login failed`, `${h} credentialed check failed`, `${h} credentialed scan failed`, `${h} credentialed run failed`,
                  `could not log in to ${h}`, `couldn't log in to ${h}`, `unable to log in to ${h}`, `could not log on to ${h}`, `credentialed check failed on ${h}`, `credentialed login failed on ${h}`, `credentialed scan failed on ${h}`,
                  `${h} was not tested`, `${h} was never tested`, `${h} was not reached`, `${h} could not be tested`, `not tested on ${h}`, `no credentialed check of ${h}`, `never tested ${h}`, `not tested ${h}`, `did not test ${h}`, `never reached ${h}`, `${h} was reached but`, `reached ${h} but the login failed`, `reached ${h} but login failed`, `reached ${h} but could not log in`, `reached ${h} but authentication failed`, `credentialed run never tested ${h}`, `${h} banner is right`, `${h} banner is accurate`, `${h} banner is correct`,
                ]
              : [
                  `${h} was tested`, `${h} was checked by the credentialed`, `run tested ${h}`, `scan tested ${h}`, `check tested ${h}`, `credentialed check of ${h} showed`, `credentialed check of ${h} shows`, `credentialed check of ${h} found`, `credentialed check of ${h} confirmed`, `credentialed check of ${h} confirms`, `credentialed check of ${h} read`, `credentialed check of ${h} saw`, `credentialed check of ${h} passed`, `credentialed check of ${h} succeeded`, `credentialed check of ${h} worked`, `${h} banner was wrong`, `${h} banner is wrong`,
                  `${h} is above the fix`, `${h} has the fixed version`, `${h} has the fixed release`, `${h} inventory is above`,
                ],
          ),
        ),
      },
      {
        id: 'action',
        text: `Dismisses the ${fpHost} finding and asks for a credentialed rescan; patches ${realHost} by emergency change; patches the others in the next window and the standard cycle.`,
        keywords: lowered(dismissOn(fpHost), verbsOn(VERBS_PATCH, realHost), [`${realHost} by emergency`, `emergency change for ${realHost}`, `emergency patch for ${realHost}`]),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy.',
        keywords: dateRubricKeywords(cal, [critDeadline, f4Deadline], [7, 30]),
      },
    ],
    explanation: [
      `The unauthenticated sweep (${sweepRun.id}, ${sweepAgo} days ago) reports the same Critical ${head.base.toFixed(1)} on ${HOST_1} and ${HOST_2}, from the version in the service banner (${bannerVersion}, below the fix in ${head.fixedVersion}). An unauthenticated scan sees only what the service shows remotely (its banner and its responses), not the installed packages or the local configuration; those are what a credentialed or agent check reads. So the question for each server is whether anything package-level has tested it.`,
      cred
        ? `${HOST_1} (the headline): the credentialed run's login failed (VulnFindings has "Authentication failure: local checks not run" for it; AuthFailures in ScanRuns is ${cov.failures}), so that run says nothing about the host, and SoftwareInventory shows ${head.product} ${bannerVersion}, the vulnerable release the banner announced. The banner is accurate: patch. First detected ${ymd(firstSeen)}, its 7-day Critical deadline (${ymd(critDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}): emergency change. ${HOST_2} is the look-alike: the credentialed run reached it (a local check row, no failure) and SoftwareInventory shows ${head.product} ${newerVersion}, above the fix, so the banner there was a guess.`
        : `${HOST_1} (the headline): the credentialed run reached the host with a working login (VulnFindings has its local check row and no authentication failure for it) and did not report ${head.id}, and SoftwareInventory shows ${head.product} ${newerVersion}, above the fix in ${head.fixedVersion}. The banner announced an old release (a banner is a string the service reports about itself; it can be left over or set in the configuration), so the sweep's version was a guess and the finding is a false positive: dismiss it and ask for a credentialed rescan to confirm. ${HOST_2} is the look-alike: the credentialed run's login failed there, so it tested nothing, and SoftwareInventory shows ${head.product} ${bannerVersion}, the vulnerable release: real, patch it. First detected ${ymd(firstSeen)}, its 7-day Critical deadline (${ymd(critDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}): emergency change.`,
      `Why the credentialed run is older than the sweep: the scan store keeps one row per finding and closes a finding that a later run re-tested and no longer saw. Here the credentialed run came first, so the sweep's row stays open and has to be judged on the data. This is not the backport case: no distribution package, no advisory and no update record; the false positive's installed release number is itself above the fix.`,
      `The other findings follow the SLA table: the High on ${APP} was first detected ${Math.round((now - f4First) / DAY)} days ago, so its 30-day deadline (${ymd(f4Deadline)}, end of day) is after the next window and before the standard cycle: next window, which with the emergency change fills its capacity of two. The Medium and the Low have long deadlines: standard cycle.`,
    ],
    pitfalls: cred
      ? [
          'Treating the credentialed run as proof that the server is clean: its login failed on the headline server, so it tested nothing there; read the authentication failure row and AuthFailures.',
          `Dismissing both servers as banner guesses: ${HOST_2} was tested with a working login and is the false positive, ${HOST_1} was not tested and its inventory shows the vulnerable release.`,
          'Trusting a Critical because the scanner printed it: the sweep is unauthenticated, so its version is only what the banner says.',
          'Calling this a backport: nothing was backported; the false positive\'s installed release is above the fix by its own version number.',
          'Scheduling the real Critical in the next window or later: its 7-day deadline ends before the next window.',
        ]
      : [
          'Trusting the sweep: it is unauthenticated, so its version is only what the service banner says; the credentialed run and SoftwareInventory are package-level.',
          `Dismissing both servers because one is a false positive: on ${HOST_2} the credentialed login failed, so that run proves nothing, and the inventory shows the vulnerable release.`,
          'Treating a credentialed run as covering every server in scope: read the authentication failures and which hosts have a row from it.',
          'Calling this a backport: nothing was backported; the installed release is above the fix by its own version number and PatchHistory is empty.',
          'Dismissing without asking for a credentialed rescan: the policy asks for a note and a rescan.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier1',
  title: TITLE,
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.2', '2.3', '4.1'],
  kind: 'vuln',
};

export const noncredLow: VulnTemplate = {
  ...COMMON,
  id: 'vm-noncred-low',
  twin: 'vm-cred-high',
  lesson:
    'ScanRuns shows the headline finding came from an unauthenticated sweep that read only the banner, while the older credentialed run reached the headline server (VulnFindings has its local check row and no authentication failure) and SoftwareInventory shows the component above the fix: the banner version is a guess, a false positive (dismiss, request a credentialed rescan). The other server, INTRA02, is the reverse here: the credentialed login failed on it and its inventory shows the vulnerable release, so it is real (patch it). The twin has the same banner, but on its headline server the credentialed login failed and the inventory shows the vulnerable release.',
  build: (ctx) => build('noncred', ctx),
};

export const credHigh: VulnTemplate = {
  ...COMMON,
  id: 'vm-cred-high',
  twin: 'vm-noncred-low',
  lesson:
    'ScanRuns and VulnFindings show the older credentialed run could not log in to the headline server ("Authentication failure: local checks not run"), so its silence proves nothing, and SoftwareInventory shows the component at the vulnerable release the sweep banner announced: the finding is real, patch by emergency change. The other server, INTRA02, is the reverse here: the credentialed run reached it with a working login and its inventory shows the component above the fix, so the banner there was a guess (dismiss it). The twin has the same banner, but its headline server was tested with a working login and the inventory shows the component above the fix.',
  build: (ctx) => build('cred', ctx),
};
