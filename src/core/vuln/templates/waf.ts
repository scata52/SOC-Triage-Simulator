// Twin T5 (DESIGN section 4): the same Critical SQL injection in a public web
// application whose fix is a code release, in the same scan, with the same
// worklist and the same calendar: a change freeze is in effect from the case
// date and the next window is the first one after it, so a release cannot go in
// before that window while the Critical's 7-day deadline ends earlier. In
// `vm-waf-covers` the web application firewall has a rule in block mode that
// covers the vulnerability (ControlInventory) and the WAF's own records in
// FirewallLogs show the requests that match the rule denied: the written compensating-control
// rule lets the control meet the deadline while the permanent fix (the release)
// goes in the next window. In `vm-waf-bypass` the rule has the same id, target
// and vulnerability but its mode is detect: the same requests are allowed
// through, nothing blocks them, so the deadline needs an emergency change. One
// builder, the clue is a parameter. Everything else (the headline entry, hosts,
// versions and dates, the other seven findings, the noise) is chosen from the
// catalogue seed, not from the template id. The decoys: a second WAF rule in
// detect mode on an unrelated application (the public website, with its own
// High finding), and an enforcing MFA control on the same host that does not
// apply to the vulnerable page.

import { DAY, HOUR } from '../../logs/time.ts';
import type { CatalogueEntry } from '../catalogue.ts';
import type { FindingSpec, ReasonCode, VulnCaseSpec, VulnContext, VulnTemplate } from '../model.ts';
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
  writeRiskException,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  lowered,
  KW_EMERGENCY,
  KW_MITIGATE,
} from './common.ts';

type Variant = 'covers' | 'bypass';

const PORTAL = 'PORTAL01'; // the headline host: a public, customer-facing web application
const WAF = 'WAF01'; // the web application firewall in front of the public applications
const PUBLIC = 'WEB01'; // the public website (a world host): the decoy WAF rule's application
const APP = 'APP01';
const FILE = 'FS01';
const DB = 'SQL01';
const BUILD = 'BUILD01';
const JUMP = 'JUMP01';
const PRINT = 'PRINT01';
const HTTPS = 443;
const PORTAL_PRODUCTS = ['Larkspur Portal', 'Velmarrow Forms', 'Foxglove Helpdesk', 'Thistledown CMS'] as const;
// What customers do with each component the headline can sit in: the portal's role in DeviceInfo says so (the avoid ruling rests on it).
const COMPONENT_USE: Record<string, string> = { 'search endpoint': 'customers search their orders here', 'login form': 'customers sign in here to track their orders', 'API query parameter': 'the order-status page calls it' };

const TITLE = 'Scan review: public web applications and servers';

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const covers = variant === 'covers';
  const cal = buildCalendar(now, { freezeFirst: true });
  const rng = sharedRng(ctx, 'waf');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const version = (label: string, e: CatalogueEntry) => versionBelow(sharedRng(ctx, `version/${label}`), e.fixedVersion);

  // ---- two credentialed runs: an older complete one, a newer partial one whose login failed on the file server.
  const runRng = sharedRng(ctx, 'scan-runs');
  const oldId = `SCN-${runRng.int(1000, 4999)}`;
  const newId = `SCN-${runRng.int(5000, 9999)}`;
  const oldRun = scan.run({ id: oldId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 10 * DAY, targetsPlanned: 14, targetsScanned: 14 });
  const newRun = scan.run({ id: newId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 4 * DAY, targetsPlanned: 16, targetsScanned: 16 }); // sized to the devices that have a row once all rows are written
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
  // The headline: a quiet entry published well before the application was installed, placed on a customer-facing web
  // application product and shaped as the Critical SQL injection reachable without login. Not on Sim-KEV (the intel is
  // the same in both twins and does not decide the case).
  const headPick = rng.pick(free().filter((x) => quiet(x) && x.published <= now - 45 * DAY));
  used.add(headPick.id);
  const headPlaced = placedOn(withFix(headPick, rng), PORTAL, rng, new Set(AGENT_PRODUCTS), PORTAL_PRODUCTS) ?? headPick;
  const f1Entry = withEpss(shaped(headPlaced, rng, { classes: ['sqli'], min: 9, max: 9.9 }), LOW_EPSS);
  const avoid = new Set([f1Entry.product]);
  const use = COMPONENT_USE[f1Entry.component] ?? 'customers use it to reach their orders';
  const f2Entry = withEpss(choose({ min: 7.6, max: 8.9, network: true }, now - 45 * DAY, PUBLIC, avoid), LOW_EPSS);
  const f3Entry = withEpss(choose({ min: 7.6, max: 8.9 }, oldRun.started, FILE, avoid), LOW_EPSS);
  const f4Entry = withEpss(choose({ min: 4, max: 6.9 }, now - 60 * DAY, DB, avoid), lowerHalfEpss(rng.fork('f4-epss'), 0.45));
  const f5Entry = withEpss(choose({ min: 4, max: 6.9 }, now - 30 * DAY, APP, avoid), lowerHalfEpss(rng.fork('f5-epss'), 0.45));
  const f6Entry = withEpss(choose({ max: 3.9 }, now - 80 * DAY, JUMP, avoid), lowerHalfEpss(rng.fork('f6-epss'), 0.45));
  const f7Entry = withEpss(choose({ min: 7, max: 8.9 }, now - 45 * DAY, BUILD, avoid), lowerHalfEpss(rng.fork('f7-epss'), 0.45));
  // the accepted-risk item: a network-reachable (AV:N) flaw with no vendor fix
  const exBase = withEpss(choose({ min: 4, max: 6.9, network: true }, now - 130 * DAY, PRINT, avoid), lowerHalfEpss(rng.fork('ex-epss'), 0.45));
  const exVersion = version('f8', exBase); // chosen from the shared stream, below the fix the entry had before it lost it
  const exEntry: CatalogueEntry = { ...exBase, vendorFix: false, fixedVersion: '' };

  // ---- hosts authored for this case, identical in the twins: the public portal and the WAF in front of the public applications.
  const portal = scopeSharedHost(
    ctx,
    { name: PORTAL, role: `Customer order portal (public web application; ${f1Entry.component}: ${use})`, os: FICTIONAL_OS, owner: 'Web Platform', criticality: 'High', exposed: true },
    'portal',
  );
  const wafHost = scopeSharedHost(ctx, { name: WAF, role: 'Web application firewall (in front of the public web applications)', os: FICTIONAL_OS, owner: 'IT Infrastructure', criticality: 'High', deviceType: 'Appliance', exposed: true }, 'waf');
  const portalRow = log.deviceRef(portal);
  const portalIp = String(portalRow.row.IPAddress);
  const publicIp = String(log.deviceRef(PUBLIC).row.IPAddress);

  // The detected version was installed on or before first detection (and before an exception ticket): dates from the shared stream.
  const install = (label: string, host: string, e: CatalogueEntry, first: number, notAfter: number = first, installed: string = version(label, e)) =>
    scan.software({ host, product: e.product, vendor: e.vendor, version: installed, installedOn: installedBefore(ctx, label, first, notAfter) });

  // ---- F1 headline: first detected by the newer run (the application version was installed after the older run started).
  const f1FirstSeen = newRun.started;
  const f1Version = version('f1', f1Entry);
  const f1 = scan.finding(newRun, { host: portal, entry: f1Entry, port: HTTPS, firstSeen: f1FirstSeen, lastSeen: lastSeen(newRun, 'f1'), installedVersion: f1Version, title: f1Entry.title });
  scan.software({ host: portal, product: f1Entry.product, vendor: f1Entry.vendor, version: f1Version, installedOn: now - 6 * DAY });
  scan.intel(f1Entry);

  // ---- F2 the decoy: a High on the public website whose WAF rule only detects
  const f2FirstSeen = now - 21 * DAY;
  const f2 = scan.finding(newRun, { host: PUBLIC, entry: f2Entry, port: HTTPS, firstSeen: f2FirstSeen, lastSeen: lastSeen(newRun, 'f2'), installedVersion: version('f2', f2Entry), title: f2Entry.title });
  install('f2', PUBLIC, f2Entry, f2FirstSeen);

  // ---- F3 the stale result: High on the file server, patched after the older run started, never re-tested (the newer run's login failed)
  const f3FirstSeen = oldRun.started;
  const f3 = scan.finding(oldRun, { host: FILE, entry: f3Entry, firstSeen: f3FirstSeen, lastSeen: lastSeen(oldRun, 'f3'), installedVersion: version('f3', f3Entry), title: f3Entry.title });
  const patchedAt = oldRun.started + 3 * DAY;
  scan.software({ host: FILE, product: f3Entry.product, vendor: f3Entry.vendor, version: f3Entry.fixedVersion, installedOn: patchedAt });
  const patch = log.patch({
    DeviceName: FILE,
    PatchId: `PKG-${sharedRng(ctx, 'f3-patch').int(1000, 9999)}`,
    Description: `${f3Entry.product} update to ${f3Entry.fixedVersion} (addresses ${f3Entry.id})`,
    InstalledOn: patchedAt,
    RebootPending: false,
    Result: 'Installed',
  });

  // ---- padding with clear truths: standard cycle
  const f4FirstSeen = now - 40 * DAY;
  const f4 = scan.finding(newRun, { host: DB, entry: f4Entry, firstSeen: f4FirstSeen, lastSeen: lastSeen(newRun, 'f4'), installedVersion: version('f4', f4Entry), title: f4Entry.title });
  const f5FirstSeen = now - 10 * DAY;
  const f5 = scan.finding(newRun, { host: APP, entry: f5Entry, firstSeen: f5FirstSeen, lastSeen: lastSeen(newRun, 'f5'), installedVersion: version('f5', f5Entry), title: f5Entry.title });
  const f6FirstSeen = now - 50 * DAY;
  const f6 = scan.finding(newRun, { host: JUMP, entry: f6Entry, firstSeen: f6FirstSeen, lastSeen: lastSeen(newRun, 'f6'), installedVersion: version('f6', f6Entry), title: f6Entry.title });
  const f7FirstSeen = now - 5 * DAY;
  const f7 = scan.finding(newRun, { host: BUILD, entry: f7Entry, firstSeen: f7FirstSeen, lastSeen: lastSeen(newRun, 'f7'), installedVersion: version('f7', f7Entry), title: f7Entry.title });
  for (const [label, host, e, first] of [['f4', DB, f4Entry, f4FirstSeen], ['f5', APP, f5Entry, f5FirstSeen], ['f6', JUMP, f6Entry, f6FirstSeen], ['f7', BUILD, f7Entry, f7FirstSeen]] as const) install(label, host, e, first);

  // ---- F8 accepted risk with a valid, time-boxed exception (a network flaw: the print VLAN limits who can reach it)
  const f8FirstSeen = now - 120 * DAY;
  const f8 = scan.finding(newRun, { host: PRINT, entry: exEntry, firstSeen: f8FirstSeen, lastSeen: lastSeen(newRun, 'f8'), installedVersion: exVersion });
  const approvedAt = now - 100 * DAY;
  const expires = now + 45 * DAY;
  const exTicket = writeRiskException(ctx, exEntry, PRINT, 'print VLAN', approvedAt, expires);
  install('f8', PRINT, exEntry, f8FirstSeen, approvedAt, exVersion);

  // ---- controls: three rows in both twins. The first is the clue: the same rule (id, target, vulnerability) either blocks
  // (verified) or only detects. The others are decoys: a detect-mode rule on the public website for its own finding, and an
  // enforcing MFA control on the portal's administrator console.
  const crng = sharedRng(ctx, 'controls');
  const verified = now - crng.int(2, 4) * DAY;
  const wafId = `CTL-WAF-${crng.int(1000, 4999)}`;
  const decoyId = `CTL-WAF-${crng.int(5000, 9999)}`;
  const mfaId = `CTL-MFA-${crng.int(1000, 9999)}`;
  const trial = now - crng.int(1, 3) * DAY; // the block-mode trial that was rolled back (the detect-mode rule's Evidence): after first detection (now - 4 d), so after the vulnerable version was installed (now - 6 d)
  const wafRule = log.control(
    covers
      ? { ControlId: wafId, Kind: 'WAF', Target: `${portal} ${f1Entry.component} (public web application)`, Mode: 'block', CoversVulnId: f1Entry.id, Evidence: `Virtual patch rule. Verified ${ymd(verified)}: requests matching the rule against the ${f1Entry.component} were blocked at ${wafHost} (FirewallLogs show rule ${wafId} denying them).` }
      : { ControlId: wafId, Kind: 'WAF', Target: `${portal} ${f1Entry.component} (public web application)`, Mode: 'detect', CoversVulnId: f1Entry.id, Evidence: `Virtual patch rule in log-only mode: it records matching requests and lets them through. A block-mode trial on ${ymd(trial)} was rolled back after it rejected legitimate customer requests; the rule has not been verified as blocking.` },
  );
  const decoyRule = log.control({ ControlId: decoyId, Kind: 'WAF', Target: `${PUBLIC} public website (${f2Entry.component})`, Mode: 'detect', CoversVulnId: f2Entry.id, Evidence: 'Rule logs matching requests and blocks nothing; it has not been verified as enforcing.' });
  log.control({ ControlId: mfaId, Kind: 'MFA', Target: `${portal} administrator console`, Mode: 'block', CoversVulnId: '', Evidence: `Verified ${ymd(verified)}: administrators sign in with a second factor. It does not apply to the public ${f1Entry.component}.` });

  // ---- the WAF's own records (FirewallLogs, device WAF01): the same nine sessions (sources, times, ports) in both twins;
  // the action and rule differ for the requests that match the rule only: denied by the rule in block mode, allowed through in detect mode.
  const frng = sharedRng(ctx, 'waf-sessions');
  const w = world.internet;
  const sources = frng.sample(w.scanners, 6); // internet scanners: the requests that match the rules look like probing
  const customers = frng.sample(w.carriers, 3); // customers on mobile carriers
  const sessionTime = () => now - frng.int(1, 6) * DAY - frng.int(0, 20) * HOUR - frng.int(0, 3599) * 1000;
  const matchRows = sources.slice(0, 4).map((src) => {
    const t = sessionTime();
    const sent = frng.int(300, 1200);
    const received = frng.int(200, 1900); // a short error-sized reply, not a data transfer
    const duration = frng.int(1, 4);
    const port = frng.int(49152, 65000);
    return log.fw({
      TimeGenerated: t,
      DeviceName: wafHost,
      Direction: 'Inbound',
      Action: covers ? 'Deny' : 'Allow',
      SourceIP: src,
      SourcePort: port,
      DestinationIP: portalIp,
      DestinationPort: HTTPS,
      RuleName: covers ? wafId : `${wafId} (detect only)`,
      BytesSent: sent,
      BytesReceived: covers ? 0 : received,
      SessionDurationSec: covers ? 0 : duration,
    });
  });
  for (const src of customers)
    log.fw({
      TimeGenerated: sessionTime(),
      DeviceName: wafHost,
      Direction: 'Inbound',
      Action: 'Allow',
      SourceIP: src,
      SourcePort: frng.int(49152, 65000),
      DestinationIP: portalIp,
      DestinationPort: HTTPS,
      RuleName: 'waf-default-pass',
      BytesSent: frng.int(800, 6000),
      BytesReceived: frng.int(20_000, 900_000),
      SessionDurationSec: frng.int(2, 300),
    });
  const publicRows = sources.slice(4, 6).map((src) =>
    log.fw({
      TimeGenerated: sessionTime(),
      DeviceName: wafHost,
      Direction: 'Inbound',
      Action: 'Allow',
      SourceIP: src,
      SourcePort: frng.int(49152, 65000),
      DestinationIP: publicIp,
      DestinationPort: HTTPS,
      RuleName: `${decoyId} (detect only)`,
      BytesSent: frng.int(300, 1200),
      BytesReceived: frng.int(200, 1900),
      SessionDurationSec: frng.int(1, 4),
    }),
  );

  // ---- background scanner noise, tickets, calendar, unrelated updates.
  addBackgroundNoise(
    ctx,
    [
      { run: oldRun, hosts: ['FS02', 'DC01', 'SCCM01'] },
      { run: newRun, hosts: ['BKP01', 'DC02', 'ADCONNECT01'] },
    ],
    [f1Entry, f2Entry, f3Entry, f4Entry, f5Entry, f6Entry, f7Entry, exEntry],
    { worklistSize: 8, extraNonWorklist: 1 }, // the login-failure row
  );
  const tickets = writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'SCCM01', 'BKP01', 'DC02'], 2, sharedRng(ctx, 'unrelated-patches'));
  // The fix is an application release: it is requested for the first window after the freeze (the same ticket in both twins).
  const release = log.ticket({
    TicketId: log.nextTicketId('CHG'),
    Type: 'Change',
    Title: `Application release: ${f1Entry.product} ${f1Entry.fixedVersion} on ${portal}`,
    Requester: ctx.pick.person({ dept: 'IT', working: false }).upn,
    AssignedTo: 'IT Infrastructure',
    Status: 'Open',
    Created: now - 2 * DAY,
    WindowStart: cal.next.start,
    WindowEnd: cal.next.end,
    Scope: portal,
    Details: `Vendor release ${f1Entry.fixedVersion} of ${f1Entry.product} fixes ${f1Entry.id} (code change in the ${f1Entry.component}). A code release cannot be deployed during the finance freeze (until ${ymd(cal.freeze.end)} 00:00), so it is requested for the first window after it. Deploying it earlier would need an approved emergency change.`,
  });
  const authFailure = writeAuthFailure(ctx, newRun, FILE); // after every other write to the newer run
  sizeRunToHosts(ctx, newRun);

  // ---- the truth (derived from the policy, the calendar, the dates and the control rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const f1Deadline = slaDeadline('critical', f1FirstSeen);
  const f2Deadline = slaDeadline('high', f2FirstSeen);
  // A: the verified control is the whole justification (as in vm-segmented): the freeze changes neither the decision nor the schedule there.
  // B: three required codes (the worklist allows at most 3 per finding, so a fourth could never be matched). The freeze is
  // explained in the evidence but is not a required code: the emergency change has to go through it, and naming it is unneeded.
  const reasonsCovers: ReasonCode[] = ['compensating-control-verified'];
  const reasonsBypass: ReasonCode[] = ['control-not-covering', 'internet-exposed', 'sla-deadline'];
  const exposedEvidence = {
    id: 'exposed-and-after-freeze',
    label: `${portal} is exposed to the internet, its fix is a code release, and a change freeze runs until the first window`,
    why: `DeviceInfo shows ${portal} reachable from the internet (ExposedToInternet true) and the vulnerability needs no login. The fix is an application release (${f1Entry.product} ${f1Entry.fixedVersion}): the freeze runs until ${ymd(cal.freeze.end)} 00:00 and the next window (${ymd(cal.next.start)}) is the first after it, where the release is requested. The Critical's deadline, 7 days from first detection, is ${ymd(f1Deadline)} (end of day), before that window; ${covers ? 'the verified control is what meets it, so the release can wait for the window' : 'with no blocking control, only an approved emergency change released before the window can meet it'}. Sim-EPSS ${LOW_EPSS} and no Sim-KEV listing do not move it.`,
    rows: [portalRow, release, tickets.freeze, tickets.next],
  };
  const f1Spec: FindingSpec = covers
    ? spec(f1, {
        truth: {
          decision: 'mitigate',
          schedule: 'next-window',
          slaLatest: 'next-window',
          reasons: reasonsCovers,
          contradicting: contradictionsFor(f1Entry, facts(portal, { control: true }), reasonsCovers),
          mitigation: [wafId],
        },
        weight: 3,
        mustNotMiss: true,
        lesson: true,
        evidence: [
          {
            id: 'waf-blocks',
            label: `A WAF rule in block mode covers this vulnerability on ${portal}, and the WAF's records show the requests matching the rule denied`,
            why: `ControlInventory has ${wafId}: a WAF rule on ${portal} ${f1Entry.component}, Mode block, CoversVulnId ${f1Entry.id}, verified ${ymd(verified)}. The WAF's own records in FirewallLogs confirm it: ${matchRows.length} requests matching the rule, from internet scanner sources, were denied (rule ${wafId}), while customer traffic passed (rule waf-default-pass). The policy lets a control that blocks the path meet the deadline while it stays in effect, so the Critical deadline (${ymd(f1Deadline)}, end of day) is met by the control; it ends when the permanent fix is deployed.`,
            rows: [wafRule, ...matchRows],
          },
          exposedEvidence,
        ],
      })
    : spec(f1, {
        truth: {
          decision: 'patch',
          schedule: 'emergency',
          slaLatest: 'emergency',
          reasons: reasonsBypass,
          contradicting: contradictionsFor(f1Entry, facts(portal), reasonsBypass),
        },
        weight: 3,
        mustNotMiss: true,
        lesson: true,
        evidence: [
          {
            id: 'waf-detects-only',
            label: `The WAF rule for this vulnerability on ${portal} is in detect mode, and the WAF's records show the requests matching the rule allowed through`,
            why: `ControlInventory has ${wafId} for ${portal} ${f1Entry.component} and ${f1Entry.id}, but its Mode is detect: it records matching requests and blocks nothing. The WAF's own records in FirewallLogs confirm it: ${matchRows.length} requests matching the rule, from internet scanner sources, were allowed through (Action Allow, rule ${wafId} (detect only)). Having a WAF is not the same as being covered: under the policy a control must block, so this is not a compensating control and the Critical deadline (${ymd(f1Deadline)}, end of day) is not met by it.`,
            rows: [wafRule, ...matchRows],
          },
          exposedEvidence,
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['control-not-covering', 'sla-deadline'], contradicting: contradictionsFor(f2Entry, facts(PUBLIC), ['control-not-covering', 'sla-deadline']) },
      weight: 1,
      evidence: [
        {
          id: 'detect-only-waf-rule',
          label: `The WAF rule that names this vulnerability is in detect mode on ${PUBLIC}`,
          why: `ControlInventory lists ${decoyId} for ${f2Entry.id}, but its Mode is detect, and the WAF's records show the requests it matched allowed through (rule ${decoyId} (detect only)): it blocks nothing, so it is not a compensating control and does not change the decision. The High deadline (${ymd(f2Deadline)}, end of day) is after the next window and before the standard cycle: patch it in the next window. Those allowed requests reached the vulnerable ${PUBLIC}, so hand them to the SOC for a compromise check; that is separate from the patch decision and does not change it.`,
          rows: [decoyRule, ...publicRows],
        },
      ],
    }),
    spec(f3, {
      truth: { decision: 'false-positive', schedule: 'none', reasons: ['stale-scan'], contradicting: contradictionsFor(f3Entry, facts(FILE, { real: false, staleNoReboot: true }), ['stale-scan']) },
      weight: 1,
      evidence: [
        {
          id: 'patched-since-scan',
          label: `${FILE} received the update after the older scan run started, with no reboot pending, and the newer run's login failed there`,
          why: `The finding comes from the older run (last seen ${ymd(f3.row.row.LastSeen as number)}); the update that fixes it was installed after that run started (Result Installed, no reboot pending). The newer run tried ${FILE} but its login failed (an "Authentication failure: local checks not run" row), so nothing re-tested the host and the old result is still shown. It is no longer valid: remediated after the scan. Close it and request a rescan to confirm.`,
          rows: [patch, authFailure],
        },
      ],
    }),
    spec(f4, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f4Entry, facts(DB), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f5, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f5Entry, facts(APP), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f6, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f6Entry, facts(JUMP), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f7, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f7Entry, facts(BUILD), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
    spec(f8, {
      truth: { decision: 'accept', schedule: 'none', reasons: ['approved-exception', 'no-vendor-fix'], contradicting: contradictionsFor(exEntry, facts(PRINT, { exception: true }), ['approved-exception', 'no-vendor-fix']) },
      weight: 0.5,
      evidence: [
        {
          id: 'exception-ticket',
          label: 'A time-boxed risk exception is approved and still valid',
          why: `The Tickets row shows an approved exception for ${exEntry.id} on ${PRINT} valid until ${ymd(expires)}, with a compensating measure that limits network access to the print VLAN; there is no vendor fix. The policy lets an approved, unexpired exception allow accept: accept it and note the expiry date for review.`,
          rows: [exTicket],
        },
      ],
    }),
  ];

  const ids = { f1: f1.findingId, f2: f2.findingId, f4: f4.findingId, f5: f5.findingId, f6: f6.findingId, f7: f7.findingId };
  const owners = ownersOf(ctx, [PORTAL, PUBLIC, FILE, DB, APP, BUILD, JUMP, PRINT]);
  const ownerNames = [...new Set([...owners, 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure
  const f1Age = Math.round((now - f1FirstSeen) / DAY);

  const briefing = `${world.org.name}: review of the latest scan results for the public web applications and the internal servers in scope (two scan runs, the newer one partial). Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, patch, ticket, firewall and control data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'The headline is an injection flaw in a public web application whose fix is a code release. What stands in front of the vulnerable page, and does it stop an attack on this flaw or only record it?';
  const second = "ControlInventory lists the WAF rules: read Mode (block or detect) and CoversVulnId, then check what the WAF's own records in FirewallLogs show happened to the requests. Then compare the Critical's deadline with the freeze, the next window and the standard cycle in the calendar.";

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal),
    findings,
    constraints: cal.constraints,
    idealOrder: [ids.f1, ids.f2, ids.f7, ids.f4, ids.f5, ids.f6],
    tiers: covers ? [[ids.f1, ids.f2]] : [[ids.f1], [ids.f2]], // covered: both are next-window, so either order is sound
    hints: [
      lead,
      second,
      covers
        ? `The WAF rule for ${portal}'s ${f1Entry.component} is in block mode and names this vulnerability, and the WAF's records show the requests matching the rule denied: a verified control meets the deadline until the release, which goes in the first window after the freeze.`
        : `The WAF rule for ${portal}'s ${f1Entry.component} names this vulnerability but is in detect mode, and the WAF's records show the requests matching the rule allowed through: nothing is in front of the flaw. A Critical's deadline is 7 days from first detection; compare it with the freeze and the next window.`,
    ],
    solution: [
      {
        title: 'What did the scanner find on the public hosts?',
        kql: `VulnFindings\n| where DeviceName in ("${PORTAL}", "${PUBLIC}")\n| project FindingId, DeviceName, VulnId, Title, Severity, CvssBase, Port, FirstSeen, ScanRunId, RecordId`,
        why: `A Critical SQL injection on ${portal}, first detected by the newer run, and a High on ${PUBLIC} first detected 21 days ago and last seen by the newer run.`,
      },
      {
        title: 'What does the intel say about the headline?',
        kql: `VulnIntel\n| where VulnId == "${f1Entry.id}"\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, RecordId`,
        why: 'No Sim-KEV listing, a low Sim-EPSS and no public exploit in both twins: the intel does not decide this case. A vendor fix exists, as a code release.',
      },
      {
        title: 'Which hosts are public, and which one is the WAF?',
        kql: `DeviceInfo\n| where DeviceName in ("${PORTAL}", "${PUBLIC}", "${WAF}")\n| project DeviceName, Role, Owner, Criticality, ExposedToInternet, IPAddress, RecordId`,
        why: `${PORTAL} is exposed to the internet in both twins; ${WAF} is the web application firewall in front of the public applications.`,
      },
      {
        title: 'Which controls exist, and do they block or only detect?',
        kql: 'ControlInventory\n| project ControlId, Kind, Target, Mode, CoversVulnId, Evidence, RecordId',
        why: covers
          ? `The WAF rule for the portal's ${f1Entry.component} is in block mode and names the headline; the WAF rule on the public website is in detect mode; the MFA control protects the administrator console, not the public page.`
          : `The WAF rule for the portal's ${f1Entry.component} names the headline but is in detect mode, like the one on the public website; the MFA control protects the administrator console, not the public page.`,
      },
      {
        title: "What did the WAF do with the requests?",
        kql: `FirewallLogs\n| where DeviceName == "${WAF}"\n| project TimeGenerated, Direction, Action, SourceIP, DestinationIP, DestinationPort, RuleName, RecordId\n| sort by TimeGenerated desc`,
        why: covers ? `The ${matchRows.length} requests matching the rule to ${portal} were denied by rule ${wafId}; customer traffic passed (waf-default-pass); the public website's detect-only rule let its matches through.` : `The ${matchRows.length} requests matching the rule to ${portal} were allowed through (rule ${wafId} (detect only)); customer traffic passed (waf-default-pass); the public website's detect-only rule let its matches through too.`,
      },
      {
        title: 'When are the freeze, the next window and the release?',
        kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, Details, RecordId\n| sort by WindowStart asc',
        why: `The freeze runs from the case date until ${ymd(cal.freeze.end)}; the next window (${ymd(cal.next.start)}) is the first after it, and the release that fixes the headline is requested for it. The standard cycle is the next date after that.`,
      },
      {
        title: 'Was the file server patched after its scan?',
        kql: `PatchHistory\n| where DeviceName == "${FILE}"\n| project DeviceName, PatchId, Description, InstalledOn, RebootPending, Result, RecordId`,
        why: 'An update that names the vulnerability, installed after the older run started, with Result Installed and no pending reboot, makes that scan result stale.',
      },
      {
        title: 'Did the newer run re-test the file server?',
        kql: `VulnFindings\n| where DeviceName == "${FILE}"\n| project FindingId, VulnId, Title, ScanRunId, FirstSeen, LastSeen, Evidence, RecordId\n| sort by LastSeen desc`,
        why: 'The vulnerability row belongs to the older run; the newer run only logged an authentication failure for the host, so its local checks did not run.',
      },
      {
        title: 'Is there an approved risk exception?',
        kql: 'Tickets\n| where Title has "Risk exception"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope, Details, RecordId',
        why: 'The print server finding has an approved, time-boxed exception because no vendor fix exists.',
      },
    ],
    rubric: [
      { id: 'owner', text: `Names who acts: ${ownerNames.join(', ')} (the Owner values in DeviceInfo; the change tickets are assigned to IT Infrastructure).`, keywords: lowered(ownerNames) },
      {
        id: 'risk',
        text: covers
          ? 'States the risk in plain words: a public application with an injection flaw, covered for now by a verified blocking WAF rule that is only temporary until the code release.'
          : 'States the risk in plain words: a public application with an injection flaw, and a WAF rule that only detects, so nothing blocks the attack and the fix cannot wait for the release.',
        keywords: covers
          ? lowered(['rule in block mode', 'waf in block mode', 'set to block mode', 'is in block mode', 'rule blocks the', 'waf blocks the', 'rule is blocking', 'waf is blocking', 'waf rule is blocking', 'blocking waf rule', 'requests are denied', 'requests were denied', 'a virtual patch for', 'virtual patch until', 'as a virtual patch', 'acts as a virtual patch', 'verified control', 'verified blocking', 'waf rule until the release', 'waf rule until the code release', 'covered by the waf rule until', 'only temporary'])
          : lowered(['detect mode', 'detect-only', 'detect only', 'only detects', 'detects but', 'log only', 'logging only', 'not blocking', 'does not block', "doesn't block", 'nothing blocks', 'allowed through', 'not enforcing']),
      },
      {
        id: 'action',
        text: covers
          ? 'Recommends the WAF rule as the mitigation now, the code release in the next window after the freeze (the rule ends when it is deployed), the next window for the public website, the standard cycle for the remaining patches and a rescan of the file server.'
          : 'Recommends an emergency change to deploy the fix through the freeze, the next window for the public website, the standard cycle for the remaining patches and a rescan of the file server, and hands the requests that reached the vulnerable page to the SOC for a compromise check.',
        keywords: covers
          ? lowered(KW_MITIGATE, ['keep the rule', 'keep the waf rule', 'waf rule stays in effect until', 'rule stays in effect until the', 'rule stays in place until', 'rule has to stay in', 'rule must stay in', 'rule remains in effect until', 'waf rule in effect until the', 'in place until the release', 'in place until the code release', 'mitigate the portal with', 'waf rule is the mitigation', 'release in the next window', 'release goes in the next window', 'release after the freeze', 'use the waf rule', 'rely on the waf rule', 'waf rule as the'])
          : lowered(KW_EMERGENCY, ['despite the freeze', 'break the freeze', 'override the freeze', 'bypass the freeze', 'deploy the fix through the freeze', 'deploy the fix during the freeze', 'compromise check', 'check for compromise', 'for compromise']),
      },
      {
        id: 'date',
        text: 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy and the freeze, and when the print server exception expires.',
        keywords: dateRubricKeywords(cal, [f1Deadline, f2Deadline, cal.freeze.end, expires], [7, 30]),
      },
    ],
    explanation: covers
      ? [
          `The headline is a Critical SQL injection (CVSS ${f1Entry.base.toFixed(1)}) in ${f1Entry.product} on ${portal}, a public web application, reachable without login. Its 7-day deadline, counted from first detection ${f1Age} days ago, is ${ymd(f1Deadline)} (end of day). The fix is a code release and the next window (${ymd(cal.next.start)}), the first after the change freeze that runs until ${ymd(cal.freeze.end)} 00:00, is after the deadline: without a control only an emergency change (the only release the freeze allows) would meet it. The deciding clue is what stands in front of the page: ControlInventory has ${wafId}, a WAF rule in block mode that names this vulnerability on that exact endpoint, and the WAF's own records in FirewallLogs show the requests matching the rule denied while customer traffic passes. The written compensating-control rule lets that control meet the deadline while it stays in effect, so the answer is mitigate with ${wafId}, and the permanent fix (the code release) goes in the next window.`,
          `A WAF virtual patch does not replace the code fix: the rule ends when the release is deployed (the policy says so) and it only holds while it stays in effect and keeps blocking, so the release still needs its window and the control should be re-checked until then. Nor is it an emergency patch: with a verified control, an emergency change through the freeze would spend scarce change capacity where the deadline is already met. The twin has the same score, intel, rule id, target and vulnerability, but the rule is in detect mode and the requests pass.`,
          `The decoys are in ControlInventory: a WAF rule in detect mode for the High finding on the public website (it blocks nothing, so that finding is a normal next-window patch: its 30-day deadline, ${ymd(f2Deadline)}, is after the next window and before the standard cycle ${ymd(cal.cycle.start)}; the requests its rule let through reached the vulnerable ${PUBLIC} and go to the SOC for a compromise check, which does not change the patch decision), and an enforcing MFA control on the portal's administrator console (a different path). The remaining patches are standard-cycle (long deadlines), and the print server finding is an accepted risk with an approved, unexpired exception.`,
          `The file server's High finding is no longer valid: PatchHistory shows the update installed after the older run started, Result Installed and no reboot pending, and the newer (partial) run only logged an authentication failure for the host ("local checks not run"), so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm.`,
        ]
      : [
          `The headline is a Critical SQL injection (CVSS ${f1Entry.base.toFixed(1)}) in ${f1Entry.product} on ${portal}, a public web application, reachable without login. Its 7-day deadline, counted from first detection ${f1Age} days ago, is ${ymd(f1Deadline)} (end of day). The fix is a code release and the next window (${ymd(cal.next.start)}), the first after the change freeze that runs until ${ymd(cal.freeze.end)} 00:00, is after the deadline; the freeze allows only approved emergency changes, so that is the way to meet it. The deciding clue is that "we have a WAF" is not "it is covered": ControlInventory has ${wafId} for this vulnerability on that endpoint, but its Mode is detect, and the WAF's own records in FirewallLogs show the requests matching the rule allowed through. A control counts only if it blocks (the policy: block mode, covering this vulnerability, confirmed in the logs), so nothing is in front of the flaw and the deadline needs an emergency change through the freeze: patch, emergency.`,
          `Switching the rule to block mode is not the answer the data supports: its Evidence in ControlInventory records that a block-mode trial on ${ymd(trial)} was rolled back after it rejected legitimate customer requests, and the policy asks for a control that is in effect and confirmed in the logs, which this is not today. The same applies to the rule on the public website. Avoid (switching the feature off) is not accepted: the portal's role in DeviceInfo says ${f1Entry.component}: ${use}, so turning the feature off would break a needed business process, and nothing in the data shows it can be switched off safely. Requests that matched the rule and reached the vulnerable page (and any other unknown internet traffic that did) are handed to the SOC for a compromise check; that is separate from the remediation decision and does not change it. The twin has the same score, intel, rule id, target and vulnerability, but its rule blocks and the requests are denied.`,
          `The decoys are in ControlInventory: a WAF rule in detect mode for the High finding on the public website (it blocks nothing, so that finding is a normal next-window patch: its 30-day deadline, ${ymd(f2Deadline)}, is after the next window and before the standard cycle ${ymd(cal.cycle.start)}; the requests its rule let through reached the vulnerable ${PUBLIC} and go to the SOC for a compromise check, which does not change the patch decision), and an enforcing MFA control on the portal's administrator console (a different path, so it protects nothing here). The remaining patches are standard-cycle (long deadlines), and the print server finding is an accepted risk with an approved, unexpired exception.`,
          `The file server's High finding is no longer valid: PatchHistory shows the update installed after the older run started, Result Installed and no reboot pending, and the newer (partial) run only logged an authentication failure for the host ("local checks not run"), so nothing re-tested it. Remediated after the scan: close it and request a rescan to confirm.`,
        ],
    pitfalls: covers
      ? [
          'Patching the headline by emergency change because it is a Critical: a verified blocking control already meets the deadline, so an emergency change through the freeze is not needed.',
          'Reading a WAF rule without its Mode and the WAF logs: block mode, the vulnerability id and denied requests together prove the control; the detect-mode rule on the public website proves nothing.',
          'Stopping at the virtual patch: it is temporary and ends when the code release is deployed, so the permanent fix still needs the first window after the freeze.',
          `Using the MFA control on the same host as cover: it protects the administrator console, not the public ${f1Entry.component}.`,
          'Believing the scanner over the patch record for the file server.',
        ]
      : [
          'Treating the existence of a WAF rule as cover: a rule in detect mode logs the attack and lets it through, and the WAF logs show it.',
          'Choosing mitigate with the detect-mode rule: only an enforcing control that covers the vulnerability counts, and a rule you would still have to switch to block is not yet in effect.',
          'Waiting for the window because the fix is a code release and a freeze is on: the Critical deadline ends first, so an emergency change is the way through a freeze.',
          'Turning the feature off (avoid) without checking that the business needs it: customers use the vulnerable page.',
          'Treating the requests the detect-mode rule let through as only a scheduling question: the remediation decision is the emergency patch, and traffic that reached the vulnerable page is also handed to the SOC for a compromise check.',
          'Believing the scanner over the patch record for the file server.',
        ],
    references: [REF_CVSS, REF_KEV, REF_EPSS, REF_EXAM],
  };
}

const COMMON: Omit<VulnTemplate, 'id' | 'lesson' | 'build' | 'twin'> = {
  difficulty: 'tier2',
  title: TITLE,
  cysaDomains: ['2.0', '4.0'],
  objectives: ['2.3', '2.4', '2.5', '4.1'],
  kind: 'vuln',
};

export const wafCovers: VulnTemplate = {
  ...COMMON,
  id: 'vm-waf-covers',
  twin: 'vm-waf-bypass',
  lesson:
    "ControlInventory shows a WAF rule in block mode that covers the headline SQL injection on the public portal, and the WAF's own FirewallLogs records show the requests matching the rule denied: the verified control meets the Critical deadline, so mitigate with that rule now and ship the code release in the first window after the freeze (the virtual patch does not replace the fix). The twin has the same rule in detect mode.",
  build: (ctx) => build('covers', ctx),
};

export const wafBypass: VulnTemplate = {
  ...COMMON,
  id: 'vm-waf-bypass',
  twin: 'vm-waf-covers',
  lesson:
    "ControlInventory shows the WAF rule for the headline SQL injection in detect mode (it logs and blocks nothing) and the WAF's FirewallLogs records show the requests matching the rule allowed through: nothing covers the Critical, whose 7-day deadline ends before the first window after the freeze, so it needs an emergency change. The twin has the same rule in block mode.",
  build: (ctx) => build('bypass', ctx),
};
