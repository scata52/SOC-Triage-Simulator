// Template vm-stale-scan (T2, A side; the B side comes in WP2). A High finding
// on a file server comes from a scan run 21 days ago. The update was installed
// after that run started, no reboot is pending, and the newer run was partial:
// its login to that file server failed ("Authentication failure: local checks
// not run"), so nothing re-tested the host and the finding is stale (a
// false positive: remediated after the scan, rescan to confirm). The decoy is
// another file server in the same old run whose only later update is an
// unrelated operating-system rollup: its finding is still real.

import { DAY } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
import type { WrittenFinding } from '../scan-writer.ts';
import {
  addBackgroundNoise,
  backdateInstall,
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
} from './common.ts';

const STALE_HOST = 'FS01';
const DECOY_HOST = 'FS02';
const MEDIUM_HOST = 'BUILD01';
const CRIT_HOST = 'APP01';
const EXCEPTION_HOST = 'PRINT01';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'stale-scan');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));

  // ---- two credentialed runs: the old complete one, a newer partial one
  const oldRun = scan.run({ method: 'Credentialed', started: now - 21 * DAY, targetsPlanned: 8, targetsScanned: 8 });
  const newRun = scan.run({ method: 'Credentialed', started: now - 3 * DAY, targetsPlanned: 8, targetsScanned: 6 });

  // A quiet entry published before it is first seen, placed on the host and shaped from the worklist table
  // to what the case needs (class, component and vector agree by construction).
  const choose = (want: ShapeWant, firstSeen: number, host: string, avoid: ReadonlySet<string> = new Set()): CatalogueEntry => {
    const known = free().filter((x) => quiet(x) && x.published <= firstSeen);
    const e = shapedOn(withFix(rng.pick(known), rng), host, rng, want, avoid);
    used.add(e.id);
    return e;
  };
  const staleEntry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, STALE_HOST), LOW_EPSS);
  const decoyEntry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, DECOY_HOST, new Set([staleEntry.product])), LOW_EPSS);
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

  // ---- headline: stale finding on the patched file server (package-level: no banner to fall back on)
  const stale = scan.finding(oldRun, { host: STALE_HOST, entry: staleEntry, firstSeen: oldRun.started });
  const patchedAt = oldRun.started + 4 * DAY;
  const patch = log.patch({
    DeviceName: STALE_HOST,
    PatchId: `PKG-${rng.int(1000, 9999)}`,
    Description: `${staleEntry.product} update to ${staleEntry.fixedVersion} (addresses ${staleEntry.id})`,
    InstalledOn: patchedAt,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- decoy: same old run, second file server. Its later update is a dated,
  // unrelated operating-system rollup that fixes no application vulnerability.
  const decoy = scan.finding(oldRun, { host: DECOY_HOST, entry: decoyEntry, firstSeen: oldRun.started });
  const staleSoft = scan.software({ host: STALE_HOST, product: staleEntry.product, vendor: staleEntry.vendor, version: staleEntry.fixedVersion, installedOn: patchedAt });
  const decoySoft = softwareRef(ctx, DECOY_HOST, decoyEntry.product);
  const rollup = log.patch({
    DeviceName: DECOY_HOST,
    PatchId: `PKG-${rng.int(1000, 9999)}`,
    Description: 'Monthly operating system rollup (kernel and system libraries only; fixes no application vulnerability)',
    InstalledOn: oldRun.started + 6 * DAY,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- clear-cut others
  const medium = scan.finding(oldRun, { host: MEDIUM_HOST, entry: mediumEntry, firstSeen: oldRun.started });
  const crit = scan.finding(newRun, { host: CRIT_HOST, entry: critEntry, port: 8443, firstSeen: newRun.started });
  const exF = scan.finding(newRun, { host: EXCEPTION_HOST, entry: exEntry, firstSeen: exFirstSeen });
  const approvedAt = now - 100 * DAY;
  const expires = now + 45 * DAY;
  const exTicket = writeRiskException(ctx, exEntry, EXCEPTION_HOST, 'print VLAN', approvedAt, expires);
  // the detected versions were installed on or before first detection (and before the exception ticket)
  backdateInstall(ctx, 'ex', EXCEPTION_HOST, exEntry.product, exFirstSeen, approvedAt);

  // ---- noise: the old-run hosts of the worklist get none (a row there would blur what was re-tested)
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['SQL01', 'JUMP01', 'WEB01'] },
      { run: newRun, hosts: ['DC01', 'SCCM01', 'BKP01'] },
    ],
    [staleEntry, decoyEntry, mediumEntry, critEntry, exEntry],
    { extraNonWorklist: 1 }, // the login-failure row
  );
  writeUnrelatedPatches(ctx, ['SQL01', 'JUMP01', 'WEB01', 'DC01', 'SCCM01', 'BKP01'], 2);
  writeChangeTickets(ctx, cal);
  const authFailure = writeAuthFailure(ctx, newRun, STALE_HOST); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  const spec = (w: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: w.findingId, row: w.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const critFirst = newRun.started;
  const findings: FindingSpec[] = [
    spec(stale, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(staleEntry, facts(STALE_HOST, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      lesson: true,
      evidence: [
        {
          id: 'patched-after-scan',
          label: `${STALE_HOST} received the update after the scan run started, with no reboot pending`,
          why: `PatchHistory shows the update that addresses ${staleEntry.id} installed on ${ymd(patchedAt)}, after the run of ${ymd(oldRun.started)} started (Result Installed, no reboot pending). SoftwareInventory agrees: ${staleEntry.product} on ${STALE_HOST} is at the fixed version ${staleEntry.fixedVersion}, installed ${ymd(patchedAt)}.`,
          rows: [patch, staleSoft],
        },
        {
          id: 'never-rescanned',
          label: `The newer run's login to ${STALE_HOST} failed: it was not re-tested`,
          why: `The newer run (${newRun.id}) logged "Authentication failure: local checks not run" for ${STALE_HOST}: no local check ran there, so the scanner still shows the result of ${oldRun.id} (last seen ${ymd(stale.row.row.LastSeen as number)}). It is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
          rows: [authFailure],
        },
      ],
    }),
    spec(decoy, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(decoyEntry, facts(DECOY_HOST), ['sla-deadline', 'credentialed-confirmed']) },
      weight: 1,
      lesson: true,
      evidence: [
        {
          id: 'unrelated-rollup',
          label: `${DECOY_HOST}'s only update since the scan is an operating system rollup that fixes no application vulnerability`,
          why: `PatchHistory has an update on ${ymd(oldRun.started + 6 * DAY)}, after the old run started, but its description shows a kernel and system library rollup that fixes no application vulnerability and names no vulnerability id. A date after the scan is not enough: the update has to fix this vulnerability. SoftwareInventory shows ${decoyEntry.product} on ${DECOY_HOST} still below the fixed version ${decoyEntry.fixedVersion}, so the finding is real; the credentialed local check read the installed package version on ${DECOY_HOST} (its Evidence says so), so credentialed-confirmed applies. Its 30-day High deadline (${ymd(slaDeadline('high', oldRun.started))}, end of day) is after the next window and before the standard cycle.`,
          rows: [rollup, decoySoft],
        },
      ],
    }),
    spec(medium, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(mediumEntry, facts(MEDIUM_HOST), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(crit, { truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['sla-deadline', 'credentialed-confirmed'], contradicting: contradictionsFor(critEntry, facts(CRIT_HOST), ['sla-deadline', 'credentialed-confirmed']) }, weight: 1, evidence: [] }),
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

  const ids = { stale: stale.findingId, decoy: decoy.findingId, medium: medium.findingId, crit: crit.findingId };
  const owners = ownersOf(ctx, [STALE_HOST, DECOY_HOST, MEDIUM_HOST, CRIT_HOST, EXCEPTION_HOST]);
  const ownerNames = [...new Set([...owners, 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const oldCov = coverageOf(oldRun);
  const newCov = coverageOf(newRun);
  const daysAgo = Math.round((now - oldRun.started) / DAY);

  return {
    briefing: `${world.org.name}: review of the latest scan results for the file servers and other internal servers in scope (two scan runs; the second did not cover every target). Decide for each worklist finding whether to patch, mitigate, accept or dismiss it, order the worklist, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch and ticket data are in the SIEM tables. All data is simulated.`,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.crit, ids.decoy, ids.medium],
    tiers: [[ids.crit], [ids.decoy]],
    hints: [
      'A finding is only as current as the scan run that produced it. Which findings come from the older run, and did a later run test those hosts again?',
      `Compare the date of the older run with PatchHistory for ${STALE_HOST} and ${DECOY_HOST}, and read what each update actually fixes. Then look at every row the newer run wrote for those devices.`,
      `${STALE_HOST} was updated after the old run started and the newer run could not log in to it, so it was never re-tested: dismiss the finding as no longer valid and ask for a rescan. ${DECOY_HOST}'s only later update is an unrelated rollup, so its finding is real.`,
    ],
    solution: [
      {
        title: 'When did each scan run and how much did it cover?',
        kql: 'ScanRuns\n| project ScanRunId, Method, Started, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `The old run covered ${oldCov.scanned} of ${oldCov.planned} targets; the newer run reached ${newCov.scanned} of ${newCov.planned} and logged ${newCov.failures} authentication failure${newCov.failures === 1 ? '' : 's'}, so some hosts were not re-tested.`,
      },
      {
        title: 'What did the scans record for the two file servers?',
        kql: 'VulnFindings\n| where DeviceName in ("' + STALE_HOST + '", "' + DECOY_HOST + '")\n| project DeviceName, VulnId, Title, Severity, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId',
        why: `Both file-server findings come from the old run. The newer run wrote one row for ${STALE_HOST} only: "Authentication failure: local checks not run".`,
      },
      {
        title: 'Was either file server updated after the old run started, and what did the update fix?',
        kql: `PatchHistory\n| where DeviceName in ("${STALE_HOST}", "${DECOY_HOST}")\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: `${STALE_HOST} has an update naming the vulnerability, installed after the run started, with no reboot pending. ${DECOY_HOST} has a later update too, but it is an operating system rollup that fixes no application vulnerability.`,
      },
      {
        title: 'Which package versions are installed on the two file servers?',
        kql: `SoftwareInventory\n| where DeviceName in ("${STALE_HOST}", "${DECOY_HOST}")\n| project DeviceName, Product, Version, InstalledOn, RecordId`,
        why: `${STALE_HOST} is at the fixed version, installed after the old run started; ${DECOY_HOST} is still below the fix.`,
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
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: ['owner', ...ownerNames.map((o) => o.toLowerCase())] },
      { id: 'risk', text: 'Explains that one scanner result is out of date and the other file server is still vulnerable (its package is below the fix).', keywords: ['stale', 'out of date', 'patched', 'still vulnerable', 'vulnerable'] },
      { id: 'action', text: `Dismisses the ${STALE_HOST} finding and requests a rescan; patches the others in the emergency, next window or standard cycle; accepts the print server finding.`, keywords: ['rescan', 'dismiss', 'next window', 'standard cycle', 'emergency'] },
      { id: 'date', text: 'Gives dates or deadlines and ties them to the policy.', keywords: ['30 days', '7 days', 'deadline', 'sla', 'window'] },
    ],
    explanation: [
      `The scanner reports a High finding on ${STALE_HOST}, but the result is from ${oldRun.id}, ${daysAgo} days ago. PatchHistory shows the update that addresses ${staleEntry.id} was installed after that run started (Result Installed, no reboot pending), and the newer run wrote an "Authentication failure: local checks not run" row for ${STALE_HOST}: nothing re-tested the host, so the old result is still shown. The finding is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
      `${DECOY_HOST} is in the same old run and also has an update dated after it, but the description shows an operating system rollup that fixes no application vulnerability. Its High finding is real: the credentialed local check read the installed package version (VulnFindings Evidence) and SoftwareInventory still shows ${decoyEntry.product} below the fix, so credentialed-confirmed applies. Counted from first detection ${daysAgo} days ago, its 30-day deadline (end of day) falls after the next window and before the monthly cycle: next window.`,
      `The Critical finding on the internal server was first detected ${ymd(critFirst)} by the newer run: its vulnerability was only published on ${ymd(critEntry.published)} (VulnIntel Published), after the old run started, so the old run could not have reported it. The credentialed local check read the installed package version there too (credentialed-confirmed), and its 7-day deadline (end of day) falls before the next window, so it needs an emergency change. The Medium finding has a 90-day deadline: standard cycle.`,
      `The print server finding has no vendor fix and an approved, unexpired, time-boxed risk exception (valid until ${ymd(expires)}) whose compensating measure limits network access to the print VLAN, so accept it and record the expiry.`,
      'The lesson is to check when a result was produced, whether anything re-tested the host and what a later update actually fixes, before acting on the score or the date alone.',
    ],
    pitfalls: [
      'Believing the scanner over the patch record: a result is only true at the time of the scan.',
      'Treating a newer partial run as if it re-tested every host.',
      `Treating any update dated after the scan as the fix: ${DECOY_HOST}'s later update is an unrelated rollup, so its finding stands.`,
      'Skipping the rescan request: dismissing without verification leaves the record unproven.',
    ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

export const staleScan: VulnTemplate = {
  id: 'vm-stale-scan',
  difficulty: 'tier1',
  title: 'Scan review: file servers',
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.1', '2.2', '2.3', '2.5', '4.1'],
  kind: 'vuln',
  lesson:
    'The "Authentication failure: local checks not run" row shows the newer run never re-tested the file server, and the update in PatchHistory installed after the old ScanRuns row started makes its High finding stale; the second file server has a later update too, but only an unrelated rollup.',
  build,
};
