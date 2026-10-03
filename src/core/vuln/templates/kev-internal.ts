// Twin T3 (DESIGN sections 4 and 5.6): the same CVSS 7.5 finding on the same
// internal application server. In `vm-kev-internal` the vulnerability is on the
// Sim-KEV list with a public exploit and the organisation's 3-day rule makes it
// an emergency; in `vm-nokev-internal` it is not listed, has a Sim-EPSS of
// 0.004 and no public exploit, and waits for the standard cycle. One builder,
// the clue is a parameter. Everything the twins share (the headline entry, the
// hosts, versions and first-seen dates, the other three findings) is chosen from
// the catalogue seed, not from the template id.

import { DAY, MIN } from '../../logs/time.ts';
import type { Rng } from '../../rng.ts';
import { KEV_LAUNCH, sampleSimEpss, simEpssPercentile, type CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  buildCalendar,
  contradictionsFor,
  type ContradictionFacts,
  coverageOf,
  dayStart,
  FICTIONAL_OS,
  installedBefore,
  hostFacts,
  kevDeadline,
  LOW_EPSS,
  lowerHalfEpss,
  ownersOf,
  pickEntry,
  shapedOn,
  policyAttachments,
  REF_CVSS,
  REF_EPSS,
  REF_EXAM,
  REF_KEV,
  scopeSharedHost,
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
} from './common.ts';

type Variant = 'kev' | 'nokev';


const APP_HOST = 'APP01';
const FILE_HOST = 'FS01';
const TLS_HOST = 'PRINT01';
// The no-listing keywords name the headline (or its host). The developer server and the TLS finding are not on Sim-KEV in either twin
// and have a low Sim-EPSS, so a bare "not on Sim-KEV" or "low EPSS" fits a correct note of the listed twin too.
const NOKEV_SUBJECTS = ['headline', 'the 7.5', '7.5', 'same 7.5', `${APP_HOST}`, `${APP_HOST} finding`, `finding on ${APP_HOST}`, 'application server finding', 'application server'];
const NOKEV_PREDICATES = ['is not exploited', 'is not known exploited', 'is not being exploited', 'has not been exploited', 'is not actively exploited', 'is not on sim-kev', 'is not on the sim-kev', 'is not on kev', 'is not listed', 'is not kev listed', 'has no exploitation', 'has no sign of exploitation', 'has low epss', 'has a low epss', 'has low sim-epss', 'has a low sim-epss', 'epss is low', 'sim-epss is low', 'epss score is low', 'has no public exploit', 'has no known exploit', 'is unlikely to be exploited', 'carries little urgency', 'has little urgency', 'is not urgent', 'not on sim-kev', 'not exploited', 'not listed'];
const NOKEV_PREFIXES = ['no sign that', 'no evidence that', 'no exploitation for', 'no sign of exploitation for', 'no evidence of exploitation for', 'no exploitation observed on', 'no exploitation of', 'no exploitation on', 'no sign of exploitation on', 'no sign of exploitation of', 'no public exploit for', 'no public exploit on', 'no known exploit for', 'low epss for', 'low epss on', 'low sim-epss for', 'low sim-epss on'];
const NOKEV_RISK: string[] = [
  ...NOKEV_SUBJECTS.flatMap((subject) => NOKEV_PREDICATES.map((p) => `${subject} ${p}`)),
  ...[...NOKEV_SUBJECTS, 'the headline', 'the application server'].flatMap((subject) => NOKEV_PREFIXES.map((p) => `${p} ${subject}`)),
];

const DEV_HOST = 'DEVBOX01';

const TITLE = 'Scan review: internal servers';

// An entry listed on Sim-KEV by authoring: the listing is a day start after its publication and before the case
// (its publication is at least 36 days before the case) and never before the real KEV catalogue's launch, with the
// exploitation profile of a listed vulnerability.
function listedOnSimKev(e: CatalogueEntry, now: number, rng: Rng): CatalogueEntry {
  const epss = sampleSimEpss(rng.fork('epss'), { listed: true });
  const added = Math.min(dayStart(now) - 2 * DAY, Math.max(KEV_LAUNCH, e.published + rng.int(1, 20) * DAY));
  return { ...e, knownExploited: true, knownExploitedAdded: added, epss, epssPercentile: Math.round(simEpssPercentile(epss) * 100) / 100, publicExploit: rng.next() < 0.5 };
}

function chooseEntries(ctx: VulnContext) {
  const { catalogue } = ctx.vuln;
  const rng = sharedRng(ctx, 'kev-internal');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  // Published well before every date the finding rows carry.
  const oldEnough = (e: CatalogueEntry) => e.published <= ctx.now - 45 * DAY;

  // F1: the headline. Any unlisted entry, shaped as the 7.5 remote information disclosure (the T3 vector).
  const f1Pick = pickEntry(rng, free(), (e) => !e.knownExploited && e.vendorFix && oldEnough(e), (e) => !e.knownExploited && e.vendorFix && oldEnough(e));
  used.add(f1Pick.id);
  const f1 = shapedOn(withFix(f1Pick, rng), APP_HOST, rng, { classes: ['info-leak'], min: 7.5, max: 7.5 });

  // F3: a Sim-KEV-listed High scoring above 7.5. The last fallback never throws: any entry old enough (published
  // at least 36 days before the case, so the file server's first detection can follow it) is listed on Sim-KEV
  // here (an authored listing, a day start between its publication and the case) and shaped to a High above 7.5.
  const f3Old = (e: CatalogueEntry) => e.published <= ctx.now - 36 * DAY;
  const listedOld = free().filter((e) => e.knownExploited && f3Old(e));
  const f3Pick = listedOld.length > 0 ? pickEntry(rng, listedOld, (e) => e.vendorFix) : pickEntry(rng, free(), () => false, f3Old);
  used.add(f3Pick.id);
  const f3Listed: CatalogueEntry = f3Pick.knownExploited ? f3Pick : listedOnSimKev(f3Pick, ctx.now, rng.fork('f3-listing'));
  const f3 = shapedOn(withFix(f3Listed, rng), FILE_HOST, rng, { min: 7.6, max: 8.9 });

  // F4: a High between 7.0 and 7.4, low Sim-EPSS, no public exploit.
  const f4Pick = pickEntry(rng, free(), (e) => !e.knownExploited && e.vendorFix && oldEnough(e), (e) => !e.knownExploited && oldEnough(e));
  used.add(f4Pick.id);
  const f4 = withEpss(shapedOn(withFix(f4Pick, rng), DEV_HOST, rng, { min: 7, max: 7.4 }), LOW_EPSS);

  // F2: a Medium network TLS finding (an outdated bundled TLS component), low Sim-EPSS.
  const f2Pick = pickEntry(rng, free(), (e) => !e.knownExploited && e.vendorFix && oldEnough(e), (e) => !e.knownExploited && oldEnough(e));
  used.add(f2Pick.id);
  const f2 = withEpss(shapedOn(withFix(f2Pick, rng), TLS_HOST, rng, { component: /TLS/, min: 5, max: 6.9, network: true }), lowerHalfEpss(rng.fork('f2-epss'), 0.3));

  return { f1, f2, f3, f4, used, rng };
}

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan } = ctx.vuln;
  const isKev = variant === 'kev';
  const { f1: f1Base, f2: f2Entry, f3: f3Entry, f4: f4Entry, rng: srng } = chooseEntries(ctx);
  const cal = buildCalendar(now);
  const today = dayStart(now);

  // Versions, first-seen dates and the install date are shared by the twins.
  const version = (label: string, e: CatalogueEntry) => versionBelow(sharedRng(ctx, `version/${label}`), e.fixedVersion);

  // ---- two credentialed runs: an older complete one, and a newer partial one
  // whose login failed on the file server.
  // Ids, durations and the "last seen" times of the worklist rows come from the shared stream, so the twins'
  // ScanRuns rows and worklist scan-run columns are identical (only FindingIds are writer-generated).
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 10 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 2 * DAY, targetsPlanned: 8, targetsScanned: 8 }); // sized to the devices that have a row once all rows are written
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // F1's exploitation profile is the one clue that differs between the twins.
  let f1Entry: CatalogueEntry;
  let listed = 0;
  const f1FirstSeen = newRun.started;
  if (isKev) {
    listed = today - ctx.rng.int(1, 2) * DAY; // Sim-KEV listing 1 or 2 days before the case day
    const epss = sampleSimEpss(srng.fork('f1-epss'), { listed: true });
    f1Entry = { ...f1Base, knownExploited: true, knownExploitedAdded: listed, epss, epssPercentile: Math.round(simEpssPercentile(epss) * 100) / 100, publicExploit: true };
  } else {
    f1Entry = withEpss(f1Base, LOW_EPSS);
  }

  // ---- scope
  const dev = scopeSharedHost(ctx, { name: DEV_HOST, role: 'Developer test server (no production data)', os: FICTIONAL_OS, owner: 'Engineering', criticality: 'Low' }, 'devbox');

  // ---- F1 headline: found by the newer run. The application server is in the
  // older, complete run too (see its configuration rows below), which did not
  // report it because the vulnerable version was installed after that run.
  const f1Version = version('f1', f1Entry);
  const f1 = scan.finding(newRun, { host: APP_HOST, entry: f1Entry, port: 8443, firstSeen: f1FirstSeen, lastSeen: lastSeen(newRun, 'f1'), installedVersion: f1Version, title: f1Entry.title });
  const f1Intel = scan.intel(f1Entry);
  const f1Installed = now - 6 * DAY;
  scan.software({ host: APP_HOST, product: f1Entry.product, vendor: f1Entry.vendor, version: f1Version, installedOn: f1Installed });
  // The application server's self-signed certificate finding: first detected by
  // the older run (which therefore reached the host) and re-reported by the newer
  // run, which is the latest run that saw it (FirstSeen kept, ScanRunId/LastSeen the latest).
  const certRow = scan.hygieneFinding(newRun, APP_HOST, 0).row.row;
  certRow.FirstSeen = oldRun.started + Math.floor((oldRun.finished - oldRun.started) / 2);

  // ---- F2 outdated bundled TLS component
  const f2FirstSeen = now - 40 * DAY;
  const f2 = scan.finding(newRun, { host: TLS_HOST, entry: f2Entry, port: 443, firstSeen: f2FirstSeen, lastSeen: lastSeen(newRun, 'f2'), installedVersion: version('f2', f2Entry), title: f2Entry.title });
  scan.software({ host: TLS_HOST, product: f2Entry.product, vendor: f2Entry.vendor, version: version('f2', f2Entry), installedOn: installedBefore(ctx, 'f2', f2FirstSeen) });

  // ---- F3 the decoy: Sim-KEV listed, patched after the old run, never re-tested
  const f3 = scan.finding(oldRun, { host: FILE_HOST, entry: f3Entry, firstSeen: Math.max(now - 35 * DAY, f3Entry.published + DAY), lastSeen: lastSeen(oldRun, 'f3'), installedVersion: version('f3', f3Entry), title: f3Entry.title });
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

  // ---- F4 High on a dev box
  const f4FirstSeen = now - 22 * DAY;
  const f4 = scan.finding(newRun, { host: dev, entry: f4Entry, port: 8080, firstSeen: f4FirstSeen, lastSeen: lastSeen(newRun, 'f4'), installedVersion: version('f4', f4Entry), title: f4Entry.title });
  scan.software({ host: dev, product: f4Entry.product, vendor: f4Entry.vendor, version: version('f4', f4Entry), installedOn: installedBefore(ctx, 'f4', f4FirstSeen) });
  const devRow = log.deviceRef(dev);

  // ---- background scanner noise, tickets, calendar. The file server is on no
  // host list: the newer run's only row for it is the login failure.
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['FS02', 'SQL01', 'JUMP01'] },
      { run: newRun, hosts: ['WEB01', 'BUILD01'] },
    ],
    [f1Entry, f2Entry, f3Entry, f4Entry],
    { extraNonWorklist: 2 }, // the login-failure row and the application server's configuration row (first seen by the older run, re-reported by the newer)
  );
  writeChangeTickets(ctx, cal);
  // Unrelated update history on hosts the case does not reason about (the same rows in both twins).
  writeUnrelatedPatches(ctx, ['FS02', 'SQL01', 'JUMP01', 'WEB01', 'BUILD01'], 2, sharedRng(ctx, 'unrelated-patches'));
  const authFailure = writeAuthFailure(ctx, newRun, FILE_HOST); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  // ---- the truth (derived from the policy, the calendar and the dates)
  const spec = (w: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: w.findingId, row: w.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const f1Reasons = isKev ? (['known-exploited', 'public-exploit'] as const) : (['low-exploitability'] as const);
  const f1Spec: FindingSpec = isKev
    ? spec(f1, {
        truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(APP_HOST), f1Reasons) },
        weight: 3,
        mustNotMiss: true,
        lesson: true,
        evidence: [
          {
            id: 'kev-listing',
            label: 'The vulnerability is on the Sim-KEV list, and a public exploit also exists',
            why: `The Sim-KEV listing (${ymd(listed)}) means exploitation has been observed in the wild, and that is what triggers the 3-day rule. The public exploit is a separate signal (working code is available) that adds urgency but is not the trigger. The 3 days count from the later of first detection and the listing, so the deadline (${ymd(kevDeadline(f1FirstSeen, listed))}, end of day) falls before the next window (${ymd(cal.next.start)}): only an emergency change meets it.`,
            rows: [f1Intel],
          },
        ],
      })
    : spec(f1, {
        truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: [...f1Reasons], contradicting: contradictionsFor(f1Entry, facts(APP_HOST), f1Reasons) },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'no-exploitation-signal',
            label: 'Not on Sim-KEV, Sim-EPSS 0.004 (about the 31st percentile), no public exploit',
            why: `Same 7.5 score, but no sign of exploitation: 0.004 is a 0.4% chance in the next 30 days. The High deadline (${ymd(slaDeadline('high', f1FirstSeen))}, end of day) is after the standard cycle (${ymd(cal.cycle.start)}), so it can wait for it.`,
            rows: [f1Intel],
          },
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f2Entry, facts(TLS_HOST), ['low-exploitability']) }, weight: 1, evidence: [] }),
    spec(f3, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(f3Entry, facts(FILE_HOST, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      evidence: [
        {
          id: 'patched-since-scan',
          label: `${FILE_HOST} received the update after the scan run started, with no reboot pending, and the newer run's login failed there`,
          why: `The finding comes from the older run (last seen ${ymd(f3.row.row.LastSeen as number)}); the update that fixes it was installed after that run started, Result Installed, no reboot pending. The newer run tried ${FILE_HOST} but its login failed (an "Authentication failure: local checks not run" row, AuthFailures ${coverageOf(newRun).failures}), so nothing re-tested the host and the old result is still shown. It is no longer valid: remediated after the scan. Close it and request a rescan to confirm; a Sim-KEV listing does not make a patched host vulnerable.`,
          rows: [patch, authFailure],
        },
      ],
    }),
    spec(f4, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['low-exploitability'], contradicting: contradictionsFor(f4Entry, facts(DEV_HOST), ['low-exploitability']) },
      weight: 1,
      evidence: [
        {
          id: 'dev-box',
          label: 'The finding is on a low-criticality developer server that is not exposed to the internet',
          why: `A High score, but a low-value internal target with Sim-EPSS 0.004 and no public exploit: no emergency. Its High deadline (${ymd(slaDeadline('high', now - 22 * DAY))}, end of day) is after the next window (${ymd(cal.next.start)}) and before the standard cycle (${ymd(cal.cycle.start)}), so it goes in the next window.`,
          rows: [devRow],
        },
      ],
    }),
  ];

  const ids = { f1: f1.findingId, f2: f2.findingId, f3: f3.findingId, f4: f4.findingId };
  const newCov = coverageOf(newRun);
  const owners = ownersOf(ctx, [APP_HOST, FILE_HOST, TLS_HOST, DEV_HOST]);
  const devAge = Math.round((now - Number(f4.row.row.FirstSeen)) / DAY);
  const f1Age = Math.round((now - f1FirstSeen) / DAY);

  const briefing = `${world.org.name}: review of the latest scan results for the internal servers in scope (two scan runs, one of them partial). Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch and ticket data are in the SIEM tables. All data is simulated.`;

  // Hint 1 is the same text in both twins: it must not tell which one this is.
  const lead = 'Look past the score column: what does VulnIntel say about each finding, and do the scan runs and patch records still support each one?';

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: isKev ? [ids.f1, ids.f4, ids.f2] : [ids.f4, ids.f1, ids.f2],
    tiers: isKev ? [[ids.f1], [ids.f4], [ids.f2]] : [[ids.f4], [ids.f1], [ids.f2]],
    hints: [
      lead,
      `One finding comes from an older scan run. Compare its date with PatchHistory for ${FILE_HOST}, and check whether the newer run re-tested that device (ScanRuns and VulnFindings).`,
      isKev
        ? 'Work out the deadlines: the Sim-KEV rule counts 3 days from the later of first detection and the listing date; the High rule counts 30 days from first detection; a deadline is due at the end of its day. Compare each with the next window and the standard cycle.'
        : 'Work out the deadlines: High counts 30 days from first detection and is due at the end of its day. Compare each High finding with the next window and the standard cycle; the one whose deadline comes first goes first.',
    ],
    solution: [
      {
        title: 'What does the intel say about the headline vulnerability?',
        kql: `VulnIntel\n| where VulnId == "${f1Entry.id}"\n| project VulnId, CvssBase, KnownExploited, KnownExploitedAdded, ExploitProbability, ExploitPercentile, PublicExploit, VendorFix, RecordId`,
        why: isKev ? 'Sim-KEV listing (exploitation observed) and a public exploit (working code) are two separate signals; the listing is what triggers the 3-day rule.' : 'No Sim-KEV listing, no public exploit and Sim-EPSS 0.004 (about the 31st percentile): the score is the only alarming thing.',
      },
      {
        title: 'Which vulnerabilities are on Sim-KEV?',
        kql: 'VulnIntel\n| where KnownExploited\n| project VulnId, CvssBase, KnownExploitedAdded, ExploitProbability, PublicExploit, RecordId\n| sort by KnownExploitedAdded desc',
        why: isKev ? 'Two listed vulnerabilities in the worklist: one is still open, the other needs a second look.' : 'Only the file-server finding is listed, and it needs a second look.',
      },
      {
        title: 'Was the file server patched after its scan?',
        kql: `PatchHistory\n| where DeviceName == "${FILE_HOST}"\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: 'An update that names the vulnerability, installed after the scan run started, with Result Installed and no pending reboot, makes that scan result stale.',
      },
      {
        title: 'Did the newer run re-test the file server?',
        kql: `VulnFindings\n| where DeviceName == "${FILE_HOST}"\n| project FindingId, VulnId, Title, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId\n| sort by LastSeen desc`,
        why: 'The vulnerability row belongs to the older run; the newer run only logged an authentication failure for the host, so its local checks did not run.',
      },
      {
        title: 'When did each scan run and how much did it cover?',
        kql: 'ScanRuns\n| project ScanRunId, Method, Started, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `The newer run reached ${newCov.scanned} of ${newCov.planned} targets and had ${newCov.failures} login failure${newCov.failures === 1 ? '' : 's'}: the file server.`,
      },
      {
        title: 'Why did the older run not report the headline?',
        kql: `SoftwareInventory\n| where DeviceName == "${APP_HOST}"\n| project DeviceName, Product, Version, InstalledOn, RecordId`,
        why: 'The vulnerable version was installed after the older run started, so there was nothing to find yet.',
      },
      {
        title: 'Did the older run reach the application server at all?',
        kql: `VulnFindings\n| where DeviceName == "${APP_HOST}"\n| project FindingId, VulnId, Title, ScanRunId, FirstSeen, LastSeen, RecordId\n| sort by FirstSeen asc`,
        why: "A row first seen during the older run proves that run reached the host (the newer run re-reported it, so its ScanRunId and LastSeen show the newer run); the headline row is first seen only by the newer run.",
      },
      {
        title: 'What kind of device is the developer server?',
        kql: `DeviceInfo\n| where DeviceName == "${DEV_HOST}"\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, RecordId`,
        why: 'Low criticality, internal only, no production data: a High score without urgency.',
      },
      {
        title: 'When are the change windows and the freeze?',
        kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, RecordId\n| sort by WindowStart asc',
        why: 'The next window and the standard cycle are the dates each deadline is compared with; the freeze sits between them.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${owners.join(', ')} (the Owner of each affected server in DeviceInfo).`, keywords: lowered(owners) },
      {
        id: 'risk',
        text: isKev ? `States the risk in plain words: a known exploited ${f1Entry.component} flaw on an internal application server that lets anyone on the network read data without logging in.` : 'States that the same 7.5 carries little urgency: no exploitation signal and a low Sim-EPSS.',
        keywords: isKev
          ? lowered(['headline is on sim-kev', 'headline is on the sim-kev', 'headline is on the kev', "headline's on sim-kev", `headline on ${APP_HOST} is on sim-kev`, `headline on ${APP_HOST} is on the sim-kev`, 'headline is listed', `headline on ${APP_HOST} is listed`, 'headline is a known exploited', 'headline is known exploited', 'headline is actively exploited', 'headline is being exploited', 'headline has been exploited', `${APP_HOST} is on sim-kev`, `${APP_HOST} is on the sim-kev`, `${APP_HOST} is listed`, `${APP_HOST} finding is on sim-kev`, `finding on ${APP_HOST} is on sim-kev`, `${APP_HOST} is being exploited`, `${APP_HOST} is actively exploited`, `${APP_HOST} has been exploited`, 'application server finding is on sim-kev', 'application server finding is listed', 'kev-listed headline', 'listed headline'])
          : lowered(NOKEV_RISK),
      },
      {
        id: 'action',
        text: isKev ? 'Recommends an emergency patch for the listed finding, the next window for the developer server, the standard cycle for the TLS update, and a rescan of the file server.' : 'Recommends no emergency: the next window for the developer server first, the standard cycle for the headline and the TLS update, and a rescan of the file server.',
        keywords: isKev
          ? lowered(KW_EMERGENCY, ['emergency window tonight', 'emergency window today', 'emergency window now', 'in an emergency window'])
          : lowered(['no emergency for the headline', 'no emergency change for the headline', 'no emergency patch for the headline', 'headline is not an emergency', 'headline is no emergency', 'headline needs no emergency', 'headline does not need an emergency', 'without an emergency for the headline', 'no need for an emergency for the headline', 'headline in the standard', 'headline goes in the standard', 'headline to the standard', 'headline in the monthly', 'headline to the monthly', 'headline can go in the standard', 'headline can go in the regular', 'headline can go in the monthly', 'headline can go in the next standard', 'headline in the regular', 'headline goes in the regular', 'headline to the regular', '7.5 in the standard', '7.5 in the regular', '7.5 goes in the standard', '7.5 goes in the regular', '7.5 can go in the standard', '7.5 can go in the regular', '7.5 can wait', 'headline can wait']),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy.',
        keywords: dateRubricKeywords(cal, [isKev ? kevDeadline(f1FirstSeen, listed) : slaDeadline('high', f1FirstSeen), slaDeadline('high', now - 22 * DAY)], isKev ? [3, 30] : [30]),
      },
    ],
    explanation: isKev
      ? [
          'The headline scores 7.5, a High with a 30-day deadline, yet it is the emergency. The deciding clue is the Sim-KEV listing in VulnIntel: exploitation has been observed in the wild, and our own rule sets a 3-day deadline for a listing, counted from the later of first detection and the listing date and due at the end of that day. That ends before the next window, so only an emergency change meets it. The public exploit is a separate signal (working code is available); it adds urgency but is not what triggers the rule.',
          'The older, complete scan run did not report the headline because the vulnerable version was installed on the application server after that run started (SoftwareInventory InstalledOn); the run did scan the host. The newer run first detected it, so first detection is that run. (FirstSeen keeps the first detection across runs, while ScanRunId and LastSeen are the latest run that saw a finding: the TLS and developer-server findings were first detected by earlier scans and seen again by the newer run.)',
          'The file-server finding has the highest score and is also Sim-KEV listed, but it is no longer valid: PatchHistory shows the update installed after the older run started, Result Installed and no reboot pending, and the newer run only logged an authentication failure for the host ("local checks not run"), so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm. The listing describes the vulnerability, not this patched host.',
          'The developer-server finding is High, but Sim-EPSS is 0.004 (0.4% in the next 30 days, about the 31st percentile), there is no public exploit and the target is a low-value internal box. Its 30-day High deadline ends after the next window and before the monthly cycle, so it goes in the next window, not an emergency and not the cycle.',
          'The TLS update is Medium with a 90-day deadline and a vendor fix: patch it in the standard cycle.',
          'Sorting by CVSS puts the stale finding first and ranks the headline by its 7.5 alone, one place above a dev-box finding in the same High band; scheduling it by severity then misses the 3-day deadline.',
        ]
      : [
          `The headline scores 7.5 and is High, but it is not on Sim-KEV, has no public exploit and Sim-EPSS is 0.004 (0.4% in the next 30 days, about the 31st percentile). It was first detected ${f1Age} days ago, so its 30-day High deadline (end of day) is after the monthly standard cycle: patch it there. An emergency change would spend scarce capacity and change risk for no gain.`,
          'The older, complete scan run did not report the headline because the vulnerable version was installed on the application server after that run started (SoftwareInventory InstalledOn); the newer run first detected it. (FirstSeen keeps the first detection across runs, while ScanRunId and LastSeen are the latest run that saw a finding: the TLS and developer-server findings were first detected by earlier scans and seen again by the newer run.)',
          `The developer-server finding has the earlier deadline: first detected ${devAge} days ago, its 30-day High deadline ends after the next window and before the monthly cycle. So it is worked first, in the next window. Low Sim-EPSS lowers the urgency; it never removes the deadline.`,
          'The file-server finding has the highest score and is Sim-KEV listed, but it is no longer valid: PatchHistory shows the update installed after the older run started with no reboot pending, and the newer run only logged an authentication failure for the host, so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm.',
          'The TLS update is Medium with a 90-day deadline and a vendor fix: standard cycle.',
          'The order follows deadlines and exploitation signals, not the score column.',
        ],
    pitfalls: isKev
      ? [
          'Ranking by CVSS: the highest score is a stale finding and the emergency scores 7.5.',
          'Treating "Sim-KEV listed" as "this host is exposed": check PatchHistory and the scan dates first.',
          'Treating the public exploit as the trigger of the 3-day rule: it is a separate signal, the Sim-KEV listing sets the deadline.',
          'Reading a High score as an emergency: the developer server is High with almost no exploitation risk.',
        ]
      : [
          'Applying the emergency reflex to every 7.5: without exploitation signals the standard cycle meets the deadline.',
          'Treating a low Sim-EPSS as "ignore": the deadline still counts from first detection.',
          'Ordering by CVSS: the developer-server finding has the earlier deadline and goes first.',
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

export const kevInternal: VulnTemplate = {
  ...COMMON,
  id: 'vm-kev-internal',
  twin: 'vm-nokev-internal',
  lesson: 'The Sim-KEV listing in VulnIntel (exploitation observed), not the CVSS 7.5, triggers the 3-day rule and makes this an emergency; a public exploit adds urgency but is not the trigger. The twin has the same score and no listing.',
  build: (ctx) => build('kev', ctx),
};

export const noKevInternal: VulnTemplate = {
  ...COMMON,
  id: 'vm-nokev-internal',
  twin: 'vm-kev-internal',
  lesson: 'With no Sim-KEV listing, no public exploit and a Sim-EPSS of 0.004 in VulnIntel, the same CVSS 7.5 waits for the standard cycle; the twin is on Sim-KEV.',
  build: (ctx) => build('nokev', ctx),
};
