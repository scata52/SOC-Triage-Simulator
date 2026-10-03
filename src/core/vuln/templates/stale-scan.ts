// Templates vm-stale-scan (T2, A side) and vm-fresh-scan (T2, B side). A High finding
// on a file server comes from a scan run 21 days ago, and a second file server has the
// same kind of finding in the same run. The twins mirror the two hosts' roles.
//
// A (vm-stale-scan): the headline host (FS01) received the update after the scan run started, no reboot is
// pending, and the newer run was partial: its login to that file server failed ("Authentication failure:
// local checks not run"), so nothing re-tested the host and the finding is stale (a false positive:
// remediated after the scan, rescan to confirm). The decoy is the other file server (FS02) in the same old
// run whose only later update is an unrelated operating-system rollup: its finding is still real.
//
// B (vm-fresh-scan): the headline host (FS01) received the update BEFORE the scan run, yet the scan still
// found the flaw: PatchHistory shows the update installed with RebootPending true, and the credentialed
// check's Evidence in VulnFindings shows the running service still loading the old library. The finding is
// current (the update is on disk, not in effect): patch, scheduling the reboot in the next window. The other
// file server (FS02) is the stale one (updated after the run, no reboot pending, login failed in the newer run).
//
// Why they mirror: capacity is two emergency or next-window changes, and the Critical takes one; an identical
// second real finding would make a third. Both twins therefore hold exactly one false positive and one real
// next-window file-server finding, with the two hosts swapping roles. The worklist rows are identical.

import { DAY, MIN } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import { versionBelow, type WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  installedBefore,
  type ShapeWant,
  shapedOn,
  buildCalendar,
  type ContradictionFacts,
  contradictionsFor,
  coverageOf,
  dayStart,
  hostFacts,
  LOW_EPSS,
  lowerHalfEpss,
  ownersOf,
  policyAttachments,
  REF_CVSS,
  REF_EPSS,
  REF_EXAM,
  REF_KEV,
  sharedRng,
  sizeRunToHosts,
  softwareRef,
  slaDeadline,
  withPublished,
  withEpss,
  withFix,
  writeAuthFailure,
  writeChangeTickets,
  writeRiskException,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  dismissOn,
  lowered,
} from './common.ts';

const HEAD_HOST = 'FS01'; // findings[0] in both twins

// The reboot keywords of the fresh twin tick only on its deciding fact: HEAD_HOST has a reboot pending. A bare "reboot is pending" or
// "old library" also fits the stale twin's honest note ("no reboot is pending", "FS02 still runs the old library"), so each is bound
// to the host or phrased so that a negation does not contain it.
const FRESH_RISK = [
  ...['is pending a reboot', 'is still pending a reboot', 'is pending a restart', 'is still pending a restart', 'reboot is pending', 'reboot is still pending', 'restart is pending', 'restart is still pending', 'reboot still pending', 'restart still pending', 'needs a reboot', 'needs a restart', 'needs to be rebooted', 'needs to restart', 'requires a reboot', 'requires a restart', 'still loads the old library', 'still has the old library', 'still runs the old library', 'still loading the old library', 'still using the old library', 'has the old library loaded', 'is not in effect', 'is not yet in effect', 'update is not in effect', 'not in effect until'].flatMap((p) => [`${HEAD_HOST} ${p}`, `${HEAD_HOST} update ${p}`, `${HEAD_HOST} service ${p}`]),
  ...['pending a reboot on', 'pending a restart on', 'old library on', 'old library is still loaded on'].map((p) => `${p} ${HEAD_HOST}`),
  'rebootpending true', 'but a reboot is pending', 'but a restart is pending', 'a reboot is pending', 'a restart is pending', 'a reboot is still pending', 'a restart is still pending', 'until the reboot', 'until it restarts', 'until the restart', 'until the host restarts', 'until it is rebooted', 'installed but not in effect', 'installed but not yet in effect',
];
const SIB_HOST = 'FS02'; // findings[1] in both twins
const MEDIUM_HOST = 'BUILD01';
const CRIT_HOST = 'APP01';
const EXCEPTION_HOST = 'PRINT01';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(ctx: VulnContext, fresh: boolean): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'stale-scan');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));

  // ---- two credentialed runs: the old complete one, a newer partial one
  // Run ids, durations, "last seen" times, installed versions and install dates come from the shared stream, so the
  // twins' ScanRuns rows and worklist rows are identical (only FindingIds are writer-generated).
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 21 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 3 * DAY, targetsPlanned: 8, targetsScanned: 6 });
  const lastSeen = (run: typeof oldRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;
  const versionOf = (label: string, e: CatalogueEntry): string => {
    const r = sharedRng(ctx, `version/${label}`);
    return e.vendorFix ? versionBelow(r, e.fixedVersion) : `${r.int(1, 9)}.${r.int(0, 12)}.${r.int(0, 9)}`;
  };
  // The inventory row of a worklist finding, installed before its first detection (and before `notAfter`).
  const install = (label: string, host: string, e: CatalogueEntry, firstSeen: number, notAfter: number = firstSeen): void => {
    scan.software({ host, product: e.product, vendor: e.vendor, version: versionOf(label, e), installedOn: installedBefore(ctx, label, firstSeen, notAfter) });
  };

  // A quiet entry published before it is first seen, placed on the host and shaped from the worklist table
  // to what the case needs (class, component and vector agree by construction).
  const choose = (want: ShapeWant, firstSeen: number, host: string, avoid: ReadonlySet<string> = new Set()): CatalogueEntry => {
    const known = free().filter((x) => quiet(x) && x.published <= firstSeen);
    const e = shapedOn(withFix(rng.pick(known), rng), host, rng, want, avoid);
    used.add(e.id);
    return e;
  };
  const headEntry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, HEAD_HOST), LOW_EPSS);
  const sibEntry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, SIB_HOST, new Set([headEntry.product])), LOW_EPSS);
  const mediumEntry = withEpss(choose({ min: 4, max: 6.9 }, oldRun.started, MEDIUM_HOST), lowerHalfEpss(rng.fork('medium-epss'), 0.45));
  // The Critical is first detected by the newer run because its vulnerability was
  // published after the complete old run started: that run could not report it.
  const critPublished = dayStart(oldRun.started) + rng.int(5, 12) * DAY; // a day start, after the old run began
  const critEntry = withEpss(
    withPublished(choose({ classes: ['rce'], min: 9.8, max: 9.8 }, newRun.started, CRIT_HOST), critPublished, catalogue.entries.map((e) => e.id)),
    lowerHalfEpss(rng.fork('crit-epss'), 0.45),
  );

  // The accepted-risk item: a network-reachable flaw with no vendor fix (the exception's compensating measure limits who can reach it).
  const exFirstSeen = now - 120 * DAY;
  const exBase = choose({ min: 4, max: 6.9, network: true }, now - 130 * DAY, EXCEPTION_HOST);
  const exEntry: CatalogueEntry = { ...withEpss(exBase, lowerHalfEpss(rng.fork('ex-epss'), 0.45)), vendorFix: false, fixedVersion: '' };
  const pkgNos = [rng.int(1000, 9999), rng.int(1000, 9999)]; // drawn on both sides: the shared stream stays in step

  // ---- the two file servers' findings (package-level: no banner to fall back on); the same rows in both twins.
  // In B the headline's evidence says what the credentialed check saw: the fixed package on disk, the old library in memory.
  const headVersion = versionOf('head', headEntry);
  const headEvidence = `Credentialed local check: ${headEntry.product} ${headEntry.fixedVersion} is installed on disk (package source: vendor), but the running service still has the old library ${headVersion} loaded in memory (it was started before the update, which takes effect after the pending reboot). Fixed in ${headEntry.fixedVersion}.`;
  const headF = scan.finding(oldRun, { host: HEAD_HOST, entry: headEntry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'head'), installedVersion: headVersion, ...(fresh ? { evidence: headEvidence } : {}) });
  const sibF = scan.finding(oldRun, { host: SIB_HOST, entry: sibEntry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'sib'), installedVersion: versionOf('sib', sibEntry) });

  // ---- the stale host's update: installed after the old run started, no reboot pending (A: the headline; B: its sibling)
  const staleHost = fresh ? SIB_HOST : HEAD_HOST;
  const staleEntry = fresh ? sibEntry : headEntry;
  const staleF = fresh ? sibF : headF;
  const patchedAt = oldRun.started + 4 * DAY;
  const stalePatch = log.patch({
    DeviceName: staleHost,
    PatchId: `PKG-${pkgNos[0]}`,
    Description: `${staleEntry.product} update to ${staleEntry.fixedVersion} (addresses ${staleEntry.id})`,
    InstalledOn: patchedAt,
    RebootPending: false,
    Result: 'Installed',
  });
  const staleSoft = scan.software({ host: staleHost, product: staleEntry.product, vendor: staleEntry.vendor, version: staleEntry.fixedVersion, installedOn: patchedAt });

  // ---- the real host (A: the sibling, whose only later update is an unrelated rollup; B: the headline, whose update
  // went in before the scan but is not in effect until the reboot)
  const realHost = fresh ? HEAD_HOST : SIB_HOST;
  const realEntry = fresh ? headEntry : sibEntry;
  const realF = fresh ? headF : sibF;
  const preScanAt = oldRun.started - 2 * DAY;
  const rebootPatch = fresh
    ? log.patch({
        DeviceName: realHost,
        PatchId: `PKG-${pkgNos[1]}`,
        Description: `${realEntry.product} update to ${realEntry.fixedVersion} (addresses ${realEntry.id}); the running service loads the updated library only after the pending reboot`,
        InstalledOn: preScanAt,
        RebootPending: true,
        Result: 'Installed',
      })
    : null;
  const realSoft = fresh
    ? scan.software({ host: realHost, product: realEntry.product, vendor: realEntry.vendor, version: realEntry.fixedVersion, installedOn: preScanAt })
    : softwareRef(ctx, realHost, realEntry.product);
  const rollup = fresh
    ? null
    : log.patch({
        DeviceName: realHost,
        PatchId: `PKG-${pkgNos[1]}`,
        Description: 'Monthly operating system rollup (kernel and system libraries only; fixes no application vulnerability)',
        InstalledOn: oldRun.started + 6 * DAY,
        RebootPending: false,
        Result: 'Installed',
      });

  // ---- clear-cut others
  const mediumF = scan.finding(oldRun, { host: MEDIUM_HOST, entry: mediumEntry, firstSeen: oldRun.started, lastSeen: lastSeen(oldRun, 'medium'), installedVersion: versionOf('medium', mediumEntry) });
  const critF = scan.finding(newRun, { host: CRIT_HOST, entry: critEntry, port: 8443, firstSeen: newRun.started, lastSeen: lastSeen(newRun, 'crit'), installedVersion: versionOf('crit', critEntry) });
  const exF = scan.finding(newRun, { host: EXCEPTION_HOST, entry: exEntry, firstSeen: exFirstSeen, lastSeen: lastSeen(newRun, 'ex'), installedVersion: versionOf('ex', exEntry) });
  const approvedAt = now - 100 * DAY;
  const expires = now + 45 * DAY;
  const exTicket = writeRiskException(ctx, exEntry, EXCEPTION_HOST, 'print VLAN', approvedAt, expires);
  // the detected versions were installed on or before first detection (and before the exception ticket)
  install('medium', MEDIUM_HOST, mediumEntry, oldRun.started);
  install('crit', CRIT_HOST, critEntry, newRun.started);
  install('ex', EXCEPTION_HOST, exEntry, exFirstSeen, approvedAt);

  // ---- noise: the old-run hosts of the worklist get none (a row there would blur what was re-tested)
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['SQL01', 'JUMP01', 'WEB01'] },
      { run: newRun, hosts: ['DC01', 'SCCM01', 'BKP01'] },
    ],
    [headEntry, sibEntry, mediumEntry, critEntry, exEntry],
    { extraNonWorklist: 1 }, // the login-failure row
  );
  writeUnrelatedPatches(ctx, ['SQL01', 'JUMP01', 'WEB01', 'DC01', 'SCCM01', 'BKP01'], 2, sharedRng(ctx, 'unrelated-patches'));
  writeChangeTickets(ctx, cal);
  const authFailure = writeAuthFailure(ctx, newRun, staleHost); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  const spec = (w: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: w.findingId, row: w.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const critFirst = newRun.started;
  type Part = Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>;
  const highDeadline = slaDeadline('high', oldRun.started);
  const critDeadline = slaDeadline('critical', critFirst);
  const critIntel = scan.intel(critEntry);

  // the host updated after the scan and never re-tested: a stale result (false positive)
  const staleSpec: Part = {
    truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(staleEntry, facts(staleHost, { real: false, staleNoReboot: true }), ['stale-scan']) },
    weight: 1,
    lesson: true,
    evidence: [
      {
        id: 'patched-after-scan',
        label: `${staleHost} received the update after the scan run started, with no reboot pending`,
        why: `PatchHistory shows the update that addresses ${staleEntry.id} installed on ${ymd(patchedAt)}, after the run of ${ymd(oldRun.started)} started (Result Installed, no reboot pending). SoftwareInventory agrees: ${staleEntry.product} on ${staleHost} is at the fixed version ${staleEntry.fixedVersion}, installed ${ymd(patchedAt)}.`,
        rows: [stalePatch, staleSoft],
      },
      {
        id: 'never-rescanned',
        label: `The newer run's login to ${staleHost} failed: it was not re-tested`,
        why: `The newer run (${newRun.id}) logged "Authentication failure: local checks not run" for ${staleHost}: no local check ran there, so the scanner still shows the result of ${oldRun.id} (last seen ${ymd(staleF.row.row.LastSeen as number)}). It is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
        rows: [authFailure],
      },
    ],
  };

  // A: the other file server, whose later update is an unrelated rollup: still vulnerable, next window
  const rollupSpec: Part = {
    truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(realEntry, facts(realHost), ['sla-deadline', 'credentialed-confirmed']) },
    weight: 1,
    lesson: true,
    evidence: [
      {
        id: 'unrelated-rollup',
        label: `${realHost}'s only update since the scan is an operating system rollup that fixes no application vulnerability`,
        why: `PatchHistory has an update on ${ymd(oldRun.started + 6 * DAY)}, after the old run started, but its description shows a kernel and system library rollup that fixes no application vulnerability and names no vulnerability id. A date after the scan is not enough: the update has to fix this vulnerability. SoftwareInventory shows ${realEntry.product} on ${realHost} still below the fixed version ${realEntry.fixedVersion}, so the finding is real; the credentialed local check read the installed package version on ${realHost} (its Evidence says so), so credentialed-confirmed applies. Its 30-day High deadline (${ymd(highDeadline)}, end of day) is after the next window and before the standard cycle.`,
        rows: [rollup!, realSoft],
      },
    ],
  };

  // B: the headline host with the update installed but not in effect until the reboot: still vulnerable, next window
  const rebootSpec: Part = {
    truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['pending-reboot', 'sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(realEntry, facts(realHost), ['pending-reboot', 'sla-deadline', 'credentialed-confirmed']) },
    weight: 1,
    lesson: true,
    evidence: [
      {
        id: 'update-pending-reboot',
        label: `${realHost} has the update installed but not in effect: a reboot is pending`,
        why: `PatchHistory shows the update that addresses ${realEntry.id} installed on ${ymd(preScanAt)}, before the run of ${ymd(oldRun.started)} started, with Result Installed but RebootPending true: the package on disk is fixed (SoftwareInventory shows ${realEntry.product} ${realEntry.fixedVersion}), but the running service keeps the old library until the host restarts. Installed does not mean fixed.`,
        rows: [rebootPatch!, realSoft],
      },
      {
        id: 'service-loads-old-library',
        label: `The credentialed check found the service still loading the old library`,
        why: `The finding's Evidence in VulnFindings (${oldRun.id}, credentialed, after the update) says the fixed package is on disk but the running service still has ${headVersion} loaded; DetectedVersion is that running version. The result is current, not stale: restart the service. Its 30-day High deadline (${ymd(highDeadline)}, end of day) is after the next window and before the standard cycle: schedule the reboot in the next window.`,
        rows: [realF.row],
      },
    ],
  };

  const findings: FindingSpec[] = [
    spec(headF, fresh ? rebootSpec : staleSpec),
    spec(sibF, fresh ? staleSpec : rollupSpec),
    spec(mediumF, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(mediumEntry, facts(MEDIUM_HOST), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    // The real Critical: dismissing it as a false positive must fail the case, so it is a key finding (weight 3, an evidence point).
    spec(critF, {
      truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(critEntry, facts(CRIT_HOST), ['sla-deadline', 'credentialed-confirmed']) },
      weight: 3,
      mustNotMiss: true,
      evidence: [
        {
          id: 'new-critical',
          label: `The Critical on ${CRIT_HOST} is real: the newer run detected it and its 7-day deadline ends before the next window`,
          why: `VulnFindings shows the Critical on ${CRIT_HOST} first detected ${ymd(critFirst)} by the newer run (credentialed local check), and VulnIntel shows the vulnerability was published ${ymd(critEntry.published)}, after the old run started: no scan result is stale here, the old run could not have reported it. Its 7-day deadline (${ymd(critDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}), so it needs an emergency change.`,
          rows: [critF.row, critIntel],
        },
      ],
    }),
    spec(exF, {
      truth: { decision: 'accept', schedule: 'none', reasons: ['approved-exception', 'no-vendor-fix'], contradicting: contradictionsFor(exEntry, facts(EXCEPTION_HOST, { exception: true }), ['approved-exception', 'no-vendor-fix']) },
      weight: 0.5,
      evidence: [
        {
          id: 'exception-ticket',
          label: 'A time-boxed risk exception is approved and still valid',
          why: `The Tickets row shows an approved exception for ${exEntry.id} on ${EXCEPTION_HOST} valid until ${ymd(expires)}, with a compensating measure that limits network access to the print VLAN; the vendor has published no fix. The policy lets an approved, unexpired exception allow accept: accept it and note the expiry date for review.`,
          rows: [exTicket],
        },
      ],
    }),
  ];

  const ids = { head: headF.findingId, real: realF.findingId, medium: mediumF.findingId, crit: critF.findingId };
  const owners = ownersOf(ctx, [HEAD_HOST, SIB_HOST, MEDIUM_HOST, CRIT_HOST, EXCEPTION_HOST]);
  const ownerNames = [...new Set([...owners, 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const oldCov = coverageOf(oldRun);
  const newCov = coverageOf(newRun);
  const daysAgo = Math.round((now - oldRun.started) / DAY);

  return {
    briefing: `${world.org.name}: review of the latest scan results for the file servers and other internal servers in scope (two scan runs; the second did not cover every target). Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, order the worklist, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch and ticket data are in the SIEM tables. All data is simulated.`,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.crit, ids.real, ids.medium],
    tiers: [[ids.crit], [ids.real]],
    hints: [
      'A finding is only as current as the scan run that produced it. Which findings come from the older run, and did a later run test those hosts again?',
      fresh
        ? `Compare the date of the older run with PatchHistory for ${HEAD_HOST} and ${SIB_HOST}: when was each update installed, what does it fix, and is it in effect (RebootPending)? Then read the Evidence of each finding and look at every row the newer run wrote for those devices.`
        : `Compare the date of the older run with PatchHistory for ${HEAD_HOST} and ${SIB_HOST}, and read what each update actually fixes. Then look at every row the newer run wrote for those devices.`,
      fresh
        ? `${SIB_HOST} was updated after the old run started and the newer run could not log in to it, so it was never re-tested: dismiss the finding as no longer valid and ask for a rescan. ${HEAD_HOST}'s update went in before the scan but a reboot is pending and the scan found the service still loading the old library: the finding is current, so patch it by scheduling the reboot in the next window.`
        : `${HEAD_HOST} was updated after the old run started and the newer run could not log in to it, so it was never re-tested: dismiss the finding as no longer valid and ask for a rescan. ${SIB_HOST}'s only later update is an unrelated rollup, so its finding is real.`,
    ],
    solution: [
      {
        title: 'When did each scan run and how much did it cover?',
        kql: 'ScanRuns\n| project ScanRunId, Method, Started, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `The old run covered ${oldCov.scanned} of ${oldCov.planned} targets; the newer run reached ${newCov.scanned} of ${newCov.planned} and logged ${newCov.failures} authentication failure${newCov.failures === 1 ? '' : 's'}, so some hosts were not re-tested.`,
      },
      {
        title: 'What did the scans record for the two file servers?',
        kql: 'VulnFindings\n| where DeviceName in ("' + HEAD_HOST + '", "' + SIB_HOST + '")\n| project DeviceName, VulnId, Title, Severity, DetectedVersion, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId',
        why: fresh
          ? `Both file-server findings come from the old run. ${HEAD_HOST}'s Evidence says the fixed package is on disk but the running service still loads the old library. The newer run wrote one row for ${SIB_HOST} only: "Authentication failure: local checks not run".`
          : `Both file-server findings come from the old run. The newer run wrote one row for ${HEAD_HOST} only: "Authentication failure: local checks not run".`,
      },
      {
        title: 'Was either file server updated, when, and is the update in effect?',
        kql: `PatchHistory\n| where DeviceName in ("${HEAD_HOST}", "${SIB_HOST}")\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: fresh
          ? `${HEAD_HOST} has an update naming the vulnerability, installed before the old run started, with RebootPending true: it is not in effect. ${SIB_HOST} has an update naming its vulnerability, installed after the run started, with no reboot pending.`
          : `${HEAD_HOST} has an update naming the vulnerability, installed after the run started, with no reboot pending. ${SIB_HOST} has a later update too, but it is an operating system rollup that fixes no application vulnerability.`,
      },
      {
        title: `What did the newer run find on ${CRIT_HOST}?`,
        kql: `VulnFindings\n| where DeviceName == "${CRIT_HOST}"\n| project FindingId, VulnId, Severity, CvssBase, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId`,
        why: `The Critical on ${CRIT_HOST} comes from the newer run, first detected then, by a credentialed local check: it is current, not stale.`,
      },
      {
        title: `When was the ${CRIT_HOST} vulnerability published?`,
        kql: `VulnIntel\n| where VulnId == "${critEntry.id}"\n| project VulnId, CvssBase, Published, KnownExploited, ExploitProbability, VendorFix, RecordId`,
        why: 'It was published after the old run started, so the old run could not have reported it; its 7-day deadline ends before the next window.',
      },
      {
        title: 'Which package versions are installed on the two file servers?',
        kql: `SoftwareInventory\n| where DeviceName in ("${HEAD_HOST}", "${SIB_HOST}")\n| project DeviceName, Product, Version, InstalledOn, RecordId`,
        why: fresh
          ? `Both file servers show the fixed package version on disk; ${HEAD_HOST}'s was installed before the old run started, ${SIB_HOST}'s after it.`
          : `${HEAD_HOST} is at the fixed version, installed after the old run started; ${SIB_HOST} is still below the fix.`,
      },
      {
        title: 'Is there an approved risk exception?',
        kql: 'Tickets\n| where Title has "Risk exception"',
        why: 'The print server finding has an approved, time-boxed exception because the vendor has published no fix.',
      },
      {
        title: 'When are the change windows and the freeze?',
        kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, RecordId\n| sort by WindowStart asc',
        why: 'The next window and the standard cycle are the dates each deadline is compared with.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: lowered(ownerNames) },
      fresh
        ? { id: 'risk', text: `Explains that the update on ${HEAD_HOST} is installed but not in effect until the reboot (the service still loads the old library), so its finding is current, while the ${SIB_HOST} result is out of date.`, keywords: lowered(FRESH_RISK) }
        : { id: 'risk', text: `Explains that the ${HEAD_HOST} result is out of date, while ${SIB_HOST} is still vulnerable: its only update after the scan was an operating system rollup, so its package is still below the fix.`, keywords: lowered([`${SIB_HOST} rollup`, 'only a rollup', 'only an os rollup', 'only an operating system rollup', 'only a cumulative rollup', 'was a rollup', 'was an os rollup', 'was an operating system rollup', `${SIB_HOST} is below the fix`, `${SIB_HOST} is still below the fix`, `${SIB_HOST} still below the fix`, `${SIB_HOST} package is below`, `${SIB_HOST} package is still below`, 'no application fix', 'bugfix update', `${HEAD_HOST} result is out of date`, `${HEAD_HOST} finding is out of date`, `${HEAD_HOST} is out of date`, `${HEAD_HOST} is stale`, `${HEAD_HOST} result is stale`, `${HEAD_HOST} finding is stale`, `${HEAD_HOST} was patched after`, `${HEAD_HOST} was updated after`, `${SIB_HOST} is still vulnerable`, `${SIB_HOST} is still unpatched`, `${SIB_HOST} still vulnerable`, `${SIB_HOST} still unpatched`, `${SIB_HOST} never got the fix`]) },
      fresh
        ? { id: 'action', text: `Patches ${HEAD_HOST} by scheduling the reboot in the next window; dismisses the ${SIB_HOST} finding and requests a rescan; patches the others in the emergency or standard cycle; accepts the print server finding.`, keywords: lowered([`schedule the reboot of ${HEAD_HOST}`, `schedule a reboot of ${HEAD_HOST}`, `schedule the restart of ${HEAD_HOST}`, `reboot of ${HEAD_HOST}`, `restart of ${HEAD_HOST}`, `reboot ${HEAD_HOST}`, `restart ${HEAD_HOST}`, `reboot the ${HEAD_HOST}`, `restart the ${HEAD_HOST}`, `${HEAD_HOST} needs a reboot`, `${HEAD_HOST} needs a restart`, `${HEAD_HOST} needs to be rebooted`, `${HEAD_HOST} needs to restart`, `${HEAD_HOST} is rebooted`, `${HEAD_HOST} is restarted`, `${HEAD_HOST} gets a reboot`, `${HEAD_HOST} gets a restart`, `schedule ${HEAD_HOST} reboot`, `${HEAD_HOST} reboot is scheduled`, `${HEAD_HOST} restart is scheduled`], dismissOn(SIB_HOST)) }
        : { id: 'action', text: `Dismisses the ${HEAD_HOST} finding and requests a rescan; patches ${SIB_HOST} and the others in the emergency, next window or standard cycle; accepts the print server finding.`, keywords: lowered(dismissOn(HEAD_HOST)) },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy, and when the print server exception expires.',
        keywords: dateRubricKeywords(cal, [highDeadline, critDeadline, expires], [30, 7]),
      },
    ],
    explanation: [
      fresh
        ? `The scanner reports a High finding on ${HEAD_HOST} from ${oldRun.id}, ${daysAgo} days ago, and PatchHistory shows the update that addresses ${headEntry.id} installed on ${ymd(preScanAt)}: before that run started. Installed does not mean fixed. The row has Result Installed but RebootPending true, and the credentialed check's Evidence in VulnFindings says the fixed package is on disk while the running service still has the old library ${headVersion} loaded. The scan is accurate: the update is not in effect until the host restarts. Patch it: schedule the reboot. First detected ${daysAgo} days ago, its 30-day deadline (${ymd(highDeadline)}, end of day) falls after the next window and before the monthly cycle: next window.`
        : `The scanner reports a High finding on ${HEAD_HOST}, but the result is from ${oldRun.id}, ${daysAgo} days ago. PatchHistory shows the update that addresses ${headEntry.id} was installed after that run started (Result Installed, no reboot pending), and the newer run wrote an "Authentication failure: local checks not run" row for ${HEAD_HOST}: nothing re-tested the host, so the old result is still shown. The finding is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
      fresh
        ? `${SIB_HOST} is in the same old run and its update was installed after that run started (${ymd(patchedAt)}), with no reboot pending, and the newer run wrote the "Authentication failure: local checks not run" row for ${SIB_HOST}: nothing re-tested it, so the old result is still shown. That finding is stale: remediated after the scan. Close it and request a rescan to confirm. The two file servers look alike in the scan and differ in what the update history shows: on ${SIB_HOST} the update came after the scan and is in effect, on ${HEAD_HOST} it came before the scan but is waiting for a reboot.`
        : `${SIB_HOST} is in the same old run and also has an update dated after it, but the description shows an operating system rollup that fixes no application vulnerability. Its High finding is real: the credentialed local check read the installed package version (VulnFindings Evidence) and SoftwareInventory still shows ${sibEntry.product} below the fix, so credentialed-confirmed applies. Counted from first detection ${daysAgo} days ago, its 30-day deadline (end of day) falls after the next window and before the monthly cycle: next window.`,
      `The Critical finding on the internal server was first detected ${ymd(critFirst)} by the newer run: its vulnerability was only published on ${ymd(critEntry.published)} (VulnIntel Published), after the old run started, so the old run could not have reported it. The credentialed local check read the installed package version there too (credentialed-confirmed), and its 7-day deadline (end of day) falls before the next window, so it needs an emergency change. The Medium finding has a 90-day deadline: standard cycle.`,
      `The print server finding has no vendor fix and an approved, unexpired, time-boxed risk exception (valid until ${ymd(expires)}) whose compensating measure limits network access to the print VLAN, so accept it and record the expiry.`,
      fresh
        ? 'The lesson is to read what an update leaves in effect (RebootPending and what the running service loaded), not only that it was installed, and to check when a result was produced and whether anything re-tested the host.'
        : 'The lesson is to check when a result was produced, whether anything re-tested the host and what a later update actually fixes, before acting on the score or the date alone.',
    ],
    pitfalls: fresh
      ? [
          'Treating "update installed" as "fixed": with a reboot pending the running service still uses the old library, so the scan is accurate.',
          `Dismissing ${HEAD_HOST} because PatchHistory shows an update for the vulnerability: it went in before the scan, and the scan still saw the old library, so the update is not in effect.`,
          'Believing the scanner over the patch record: a result is only true at the time of the scan, and one host here was updated after it and never re-tested.',
          'Treating a newer partial run as if it re-tested every host.',
          `Patching ${SIB_HOST} as well: its update came after the scan with no reboot pending, and the newer run's failed login shows nothing re-tested it, so the finding is stale.`,
        ]
      : [
          'Believing the scanner over the patch record: a result is only true at the time of the scan.',
          'Treating a newer partial run as if it re-tested every host.',
          `Treating any update dated after the scan as the fix: ${SIB_HOST}'s later update is an unrelated rollup, so its finding stands.`,
          'Skipping the rescan request: dismissing without verification leaves the record unproven.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier1',
  title: 'Scan review: file servers',
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.2', '2.3', '2.5', '4.1'],
  kind: 'vuln',
};

export const staleScan: VulnTemplate = {
  ...COMMON,
  id: 'vm-stale-scan',
  twin: 'vm-fresh-scan',
  lesson:
    'The "Authentication failure: local checks not run" row shows the newer run never re-tested the file server, and the update in PatchHistory installed after the old ScanRuns row started makes its High finding stale; the second file server has a later update too, but only an unrelated rollup.',
  build: (ctx) => build(ctx, false),
};

export const freshScan: VulnTemplate = {
  ...COMMON,
  id: 'vm-fresh-scan',
  twin: 'vm-stale-scan',
  lesson:
    'PatchHistory shows the file server update installed before the old ScanRuns row started but with RebootPending true, and the finding Evidence in VulnFindings shows the running service still loading the old library: the update is installed but not in effect, so the High finding is current (patch, schedule the reboot); the second file server is the stale one, updated after the scan and never re-tested.',
  build: (ctx) => build(ctx, true),
};
