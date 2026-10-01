// Shared conventions of the vulnerability-management templates. Everything a
// case needs from "the organisation" lives here so twins and later batches
// tell one consistent story: the remediation policy, the change calendar on
// the case date, the tickets that show it in the SIEM, and the unscored
// scanner noise (DESIGN sections 6.3 and 9). Scenario data only, fully
// fictional.
//
// The policy (it is this fictional organisation's own, never a directive):
//   SLA days by severity class  critical 7, high 30, medium 90, low 180,
//                               counted from first detection
//   Sim-KEV override            3 days regardless of score, counted from the
//                               later of first detection and the listing date
//   Deadline                    due by the end of its day (23:59 UTC)
//   Calendar                    next scheduled window 5 days after the case date,
//                               the monthly standard cycle 14 days out,
//                               one freeze between them (no window falls in it)
//   Emergency change            possible with approval
//   Capacity                    2 emergency + next-window changes per window
//   Risk exception              an approved, unexpired one allows `accept`
// A schedule truth is derived from these and the rows' dates: `emergency` when
// the deadline falls before the next window ends, `next-window` when it falls
// before the standard cycle ends, else `standard-cycle`; every deciding
// boundary is at least a day away from the deadline.

import { createRng, type Rng } from '../../rng.ts';
import { DAY, HOUR, MIN, iso, utcDayStart } from '../../logs/time.ts';
import type { Attachment } from '../../cases/model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import type { CaseReference } from '../../types.ts';
import { baseScore, severityOf } from '../cvss31.ts';
import type { CatalogueBand, CatalogueEntry, VulnClass } from '../catalogue.ts';
import { formatSimVulnId } from '../ids.ts';
import { SIM_EPSS_ALL, VULN_CLASS_LABELS, VULN_CLASSES, simEpssPercentile, simEpssScoreAt } from '../catalogue.ts';
import type { ChangeWindow, ReasonCode, SlaClass, VulnConstraints, VulnContext } from '../model.ts';
import type { PackageSource, ScanRunHandle, ScopeHostInput } from '../scan-writer.ts';
import { SUBNETS } from '../../synth/addresses.ts';

// ---- the policy -------------------------------------------------------------

export const SLA_DAYS: Record<SlaClass, number> = { critical: 7, high: 30, medium: 90, low: 180 };
export const KEV_SLA_DAYS = 3;
export const CAPACITY_PER_WINDOW = 2;
export const NEXT_WINDOW_DAYS = 5; // days after the case date
export const CYCLE_DAYS = 14;
export const FREEZE_START_DAYS = 8;
export const FREEZE_LENGTH_DAYS = 3;
const WINDOW_START_HOUR = 20; // UTC, an evening window
const WINDOW_HOURS = 4;

// The fictional operating system of every host a template adds to the CMDB.
// (The shared world's own hosts keep their platform strings; they are context,
// never the vulnerable product.)
export const FICTIONAL_OS = 'Dovrenix Linux 5.4';

// Ticket titles: the tests (and a reader) tell windows and the freeze from
// unrelated changes by these prefixes.
export const WINDOW_TITLE_PREFIX = 'Change window:';
export const FREEZE_TITLE_PREFIX = 'Change freeze:';

export const dayStart = (ms: number): number => utcDayStart(ms);
export const ymd = (ms: number): string => iso(ms).slice(0, 10);
export const ymdHm = (ms: number): string => iso(ms).slice(0, 16).replace('T', ' ');

// A deadline is due by the end of its day: 23:59 UTC on the deadline date.
export const endOfDay = (ms: number): number => dayStart(ms) + DAY - MIN;

// The severity class of a CVSS base score, as the policy table reads it.
export const slaClassOf = (score: number): SlaClass => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low');

// The SLA deadline of a finding of a severity class first detected at `firstSeen`.
export const slaDeadline = (cls: SlaClass, firstSeen: number): number => endOfDay(firstSeen + SLA_DAYS[cls] * DAY);
// The Sim-KEV deadline: 3 days from the later of first detection and listing.
export const kevDeadline = (firstSeen: number, listed: number): number => endOfDay(Math.max(firstSeen, listed) + KEV_SLA_DAYS * DAY);

// ---- the calendar -----------------------------------------------------------

export interface Calendar {
  today: number; // the case date (00:00 UTC)
  next: ChangeWindow;
  cycle: ChangeWindow;
  freeze: ChangeWindow;
  constraints: VulnConstraints;
}

export function buildCalendar(now: number): Calendar {
  const today = dayStart(now);
  const at = (days: number): ChangeWindow['start'] => today + days * DAY + WINDOW_START_HOUR * HOUR;
  const next: ChangeWindow = { id: 'next', label: 'Next scheduled maintenance window', start: at(NEXT_WINDOW_DAYS), end: at(NEXT_WINDOW_DAYS) + WINDOW_HOURS * HOUR };
  const cycle: ChangeWindow = { id: 'cycle', label: 'Monthly standard patch cycle', start: at(CYCLE_DAYS), end: at(CYCLE_DAYS) + WINDOW_HOURS * HOUR };
  const freeze: ChangeWindow = { id: 'freeze', label: 'Finance period-close freeze', start: today + FREEZE_START_DAYS * DAY, end: today + (FREEZE_START_DAYS + FREEZE_LENGTH_DAYS) * DAY };
  return { today, next, cycle, freeze, constraints: { windows: [next, cycle], freezes: [freeze], slaDays: { ...SLA_DAYS }, capacityPerWindow: CAPACITY_PER_WINDOW } };
}

// ---- briefing and attachments ----------------------------------------------

// The policy and calendar as the learner reads them (two key/value attachments).
export function policyAttachments(orgName: string, cal: Calendar): Attachment[] {
  const freezeLast = ymd(cal.freeze.end - DAY);
  return [
    {
      title: `${orgName}: vulnerability remediation standard (excerpt)`,
      kind: 'kv',
      body: [
        ['Deadline clock', 'Counted from the day a finding is first detected, unless a rule below says otherwise.'],
        ['Scan store', 'The scan store keeps one row per finding: FirstSeen is the first detection; ScanRunId and LastSeen are the latest run that saw it. A finding that a later run re-tested and no longer saw is closed (Status Fixed).'],
        ['When a deadline is due', 'A deadline is due by the end of its day (23:59 UTC) on the deadline date; a change window that ends by then meets it.'],
        ['Critical (CVSS 9.0 to 10.0)', `${SLA_DAYS.critical} days`],
        ['High (CVSS 7.0 to 8.9)', `${SLA_DAYS.high} days`],
        ['Medium (CVSS 4.0 to 6.9)', `${SLA_DAYS.medium} days`],
        ['Low (CVSS 0.1 to 3.9)', `${SLA_DAYS.low} days`],
        ['Sim-KEV override', `A finding whose vulnerability is on the Sim-KEV list is due in ${KEV_SLA_DAYS} days whatever its score, counted from the later of first detection and the Sim-KEV listing date. This is our own rule and is stricter than the table above. Sim-KEV is a simulated list modelled on the CISA KEV catalogue; it is a prioritisation signal here, and CISA sets its own deadlines for US federal agencies.`],
        ['Emergency change', 'Possible with change-manager approval. Use it when the deadline falls before the next window.'],
        ['Capacity', `${CAPACITY_PER_WINDOW} emergency and next-window changes per window; the rest wait for the following window.`],
        ['Dismissed findings', 'A finding shown not to exist (for example already fixed) needs no change; note why and ask for a rescan.'],
        ['Risk exception', 'An approved, unexpired risk exception allows accept until its expiry date; re-assess at expiry.'],
      ],
      caption: 'Simulated policy of a fictional organisation.',
    },
    {
      title: 'Change calendar (UTC)',
      kind: 'kv',
      body: [
        ['Case date (UTC)', ymd(cal.today)],
        [cal.next.label, `${ymdHm(cal.next.start)} to ${ymdHm(cal.next.end)}`],
        [cal.cycle.label, `${ymdHm(cal.cycle.start)} to ${ymdHm(cal.cycle.end)}`],
        [cal.freeze.label, `${ymd(cal.freeze.start)} 00:00 until ${ymd(cal.freeze.end)} 00:00 (last day ${freezeLast}, inclusive): no planned changes. No window above falls inside it.`],
      ],
    },
  ];
}

// ---- tickets ----------------------------------------------------------------

// The change tickets a real service desk would show: the two windows, the
// freeze and unrelated changes (never about the deciders). All in Tickets.
export function writeChangeTickets(ctx: VulnContext, cal: Calendar): void {
  const { log, rng, now } = ctx;
  const admin = ctx.pick.person({ dept: 'IT', working: false });
  const make = (title: string, scope: string, start: number, end: number, details: string, status: 'Approved' | 'Scheduled' = 'Approved') =>
    log.ticket({ TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: title, Requester: admin.upn, AssignedTo: 'IT Infrastructure', Status: status, Created: now - rng.int(3, 20) * DAY, WindowStart: start, WindowEnd: end, Scope: scope, Details: details });
  make(`${WINDOW_TITLE_PREFIX} next scheduled maintenance window`, 'Production servers', cal.next.start, cal.next.end, 'Approved routine window. Emergency and next-window patches are booked here; capacity is two changes.', 'Scheduled');
  make(`${WINDOW_TITLE_PREFIX} monthly standard patch cycle`, 'All servers', cal.cycle.start, cal.cycle.end, 'Monthly standard patch cycle for all managed servers.', 'Scheduled');
  make(`${FREEZE_TITLE_PREFIX} finance period close`, 'All production', cal.freeze.start, cal.freeze.end, `No planned production changes from ${ymd(cal.freeze.start)} 00:00 until ${ymd(cal.freeze.end)} 00:00. Approved emergency changes only.`);
  const soon = (d: number, h: number) => dayStart(now) + d * DAY + h * HOUR;
  make('Replace UPS batteries in the server room', 'Server room', soon(3, 7), soon(3, 9), 'Facilities work; no server impact expected.');
  make('Rotate the guest wireless passphrase', 'Guest wireless', soon(2, 17), soon(2, 18), 'Routine quarterly rotation.');
  make('Renew the intranet certificate', 'Intranet portal', soon(4, 6), soon(4, 7), 'Certificate renewal; brief reload of the reverse proxy.');
  make('Add storage shelf to the backup array', 'Backup infrastructure', soon(6, 18), soon(6, 22), 'Capacity extension approved by the storage owner.');
}

// ---- which product belongs on which host -------------------------------------

// The fictional products (catalogue names) a host of the shared world, or one a
// template adds, could plausibly run. A learner browsing VulnFindings should not
// meet a print server product on a file server.
const VENDOR_OF: Record<string, string> = {
  'Larkspur Portal': 'Quillon Software',
  'Ironbark Wiki': 'Ashgrove Labs',
  'Wrenwick Relay': 'Ravenmere Systems',
  'Foxglove Helpdesk': 'Larkfield Software',
  'Sablecrest Gateway': 'Tallowfield Networks',
  'Tamarind Backup': 'Brackenridge Data',
  'Copperfield Print Server': 'Ferrowick Industries',
  'Marrowgate Proxy': 'Tallowfield Networks',
  'Quillon Forms': 'Quillon Software',
  'Ombrelune Files': 'Ombrelune Digital',
  'Harrowgate Directory Sync': 'Harrowgate Tech',
  'Pinecrest Dashboards': 'Pinecrest Analytics',
  'Vantorn Build Runner': 'Vantorn Corp',
  'Wexcombe Object Store': 'Wexcombe Cloud',
  'Brackenridge DB Console': 'Brackenridge Data',
  'Thistledown CMS': 'Larkfield Software',
  'Cinderpath Scheduler': 'Ferrowick Industries',
  'Dunmore Badge Manager': 'Harrowgate Tech',
  'Elderfen Chat Server': 'Ravenmere Systems',
  'Tarnwick Inventory Agent': 'Ashgrove Labs',
  'Gallowglass Firewall Manager': 'Tallowfield Networks',
  'Hollowmere Reporting': 'Pinecrest Analytics',
  'Ivorygate Payments Adapter': 'Vantorn Corp',
  'Kestrelmoor Telemetry Agent': 'Wexcombe Cloud',
};
const FILES = ['Ombrelune Files', 'Tamarind Backup', 'Wexcombe Object Store'];
const APPS = ['Larkspur Portal', 'Quillon Forms', 'Foxglove Helpdesk', 'Pinecrest Dashboards', 'Hollowmere Reporting', 'Thistledown CMS', 'Elderfen Chat Server', 'Ivorygate Payments Adapter', 'Dunmore Badge Manager'];
const HOST_PRODUCTS: Record<string, readonly string[]> = {
  FS01: FILES,
  FS02: FILES,
  PRINT01: ['Copperfield Print Server'],
  APP01: APPS,
  WEB01: ['Larkspur Portal', 'Thistledown CMS', 'Quillon Forms', 'Marrowgate Proxy'],
  SQL01: ['Brackenridge DB Console', 'Pinecrest Dashboards', 'Hollowmere Reporting'],
  BUILD01: ['Vantorn Build Runner', 'Cinderpath Scheduler', 'Ironbark Wiki'],
  DEVBOX01: ['Vantorn Build Runner', 'Ironbark Wiki', 'Cinderpath Scheduler', 'Brackenridge DB Console'],
  JUMP01: ['Sablecrest Gateway', 'Marrowgate Proxy', 'Wrenwick Relay', 'Gallowglass Firewall Manager'],
  DC01: ['Harrowgate Directory Sync', 'Dunmore Badge Manager'],
  DC02: ['Harrowgate Directory Sync', 'Dunmore Badge Manager'],
  ADCONNECT01: ['Harrowgate Directory Sync'],
  SCCM01: ['Tarnwick Inventory Agent', 'Kestrelmoor Telemetry Agent'],
  BKP01: ['Tamarind Backup', 'Wexcombe Object Store'],
};
// Infrastructure agents and schedulers run on every managed server: the scanner finds their
// (low-risk) flaws in the background too, which gives each host more than its own few products.
export const AGENT_PRODUCTS: readonly string[] = ['Tarnwick Inventory Agent', 'Kestrelmoor Telemetry Agent', 'Cinderpath Scheduler'];
const productsOf = (host: string): readonly string[] | undefined => HOST_PRODUCTS[host];

// The entry re-branded to a product that fits the host (its id, score, class,
// component, feed values and dates stay), or itself when it already fits. Apply
// it before `shaped`, which rebuilds the title from the product. `avoid` are
// product names not to use (returns null when nothing else fits).
export function placedOn(entry: CatalogueEntry, host: string, rng: Rng, avoid: ReadonlySet<string> = new Set(), names: readonly string[] | undefined = productsOf(host)): CatalogueEntry | null {
  if (names === undefined || (names.includes(entry.product) && !avoid.has(entry.product))) return entry;
  const options = names.filter((n) => !avoid.has(n));
  if (options.length === 0) return null;
  const product = rng.pick(options);
  return { ...entry, product, vendor: VENDOR_OF[product], title: `${VULN_CLASS_LABELS[entry.vulnClass]} in ${product} ${entry.component}` };
}

// ---- background scanner noise (DESIGN 6.3) ---------------------------------

// Unscored findings so that 60 to 80% of VulnFindings rows are not on the
// worklist: about 70% of the total, whatever the worklist size.
export const backgroundTarget = (worklistSize: number): number => Math.round((worklistSize * 7) / 3);

export interface BackgroundRun {
  run: ScanRunHandle;
  hosts: string[]; // the devices this run's background findings may land on
}

// A catalogue entry that may appear as scanner noise in a run (DESIGN 6.3):
// nothing a careful analyst would want on the worklist. Not High or Critical,
// not on Sim-KEV, Sim-EPSS below 0.02, no public exploit, a vendor fix exists,
// and published before the run started (a run cannot find what is not yet known).
export const NOISE_EPSS_LIMIT = 0.02;
export function isNoiseEntry(e: CatalogueEntry, runStarted: number): boolean {
  return !e.knownExploited && (e.severity === 'medium' || e.severity === 'low') && e.epss < NOISE_EPSS_LIMIT && !e.publicExploit && e.vendorFix && e.published <= runStarted;
}

export interface NoiseOptions {
  worklistSize?: number; // default: the number of worklist entries
  extraNonWorklist?: number; // other unscored rows already written (they count towards the 60 to 80% share)
}

const isWindows = (os: string): boolean => /windows/i.test(os);
const BANNER_PORTS: readonly number[] = [443, 443, 8443, 80, 8080];
// The scan writer's hygiene plugins by index (2 is the SSH one, 3 is SMB signing) and their titles,
// so that no run ever shows the same plugin twice on one device.
const HYGIENE_INDEXES = [0, 1, 2, 3, 4, 5, 6] as const;
export const HYGIENE_TITLES: readonly string[] = [
  'Self-signed TLS certificate',
  'Legacy TLS protocol versions enabled',
  'SSH server offers weak key exchange algorithms',
  'SMB signing not required',
  'Service banner discloses version information',
  'HTTP TRACE method enabled',
  'Certificate expires within 30 days',
];
// The share of the background that is configuration hygiene, and the most it may grow to when
// the vulnerability rows run out of hosts and products to sit on.
const HYGIENE_SHARE = 0.3;
const HYGIENE_SHARE_MAX = 0.4;

// Background rows for a case: about 70% of all VulnFindings rows, none of them
// able to pass for a worklist item. Every vulnerability row is one whose class,
// title and vector agree, is not High or Critical, not on Sim-KEV, has a low
// Sim-EPSS, no public exploit and a vendor fix, was published before its run,
// and is on a product no worklist finding uses; the product suits the host and
// no product repeats on a host. Hygiene rows (no vulnerability id) fit the
// host's operating system (no SSH plugin on Windows, no SMB plugin elsewhere)
// and no plugin repeats on a host within a run (the scan store keeps one row
// per finding). Rows are spread over the runs in turn until each run's hosts
// have no room left; about 30% are hygiene (at most 40% when the vulnerability
// rows run out). The host lists of the runs must be disjoint, and a host a
// case's reasoning depends on (for example one that was not re-tested) must be
// on no list at all.
export function addBackgroundNoise(ctx: VulnContext, runs: BackgroundRun[], worklist: readonly CatalogueEntry[], opts: NoiseOptions = {}): void {
  const { catalogue, scan } = ctx.vuln;
  const rng = ctx.rng.fork('background-noise');
  const size = opts.worklistSize ?? worklist.length;
  const total = Math.max(0, backgroundTarget(size) - (opts.extraNonWorklist ?? 0));
  const products = new Set(worklist.map((e) => e.product));
  const taken = new Set(worklist.map((e) => e.id));
  const placed = new Set<string>(); // "host|product"
  const usedHygiene = new Set<string>(ctx.log.rowsOf('VulnFindings').filter((r) => String(r.VulnId) === '').map((r) => `${String(r.ScanRunId)}|${String(r.DeviceName).toUpperCase()}|${String(r.Title)}`));
  const osOf = (host: string): string => String(ctx.log.deviceRef(host).row.OSPlatform ?? '');
  const backgroundProducts = (host: string): readonly string[] | undefined => (productsOf(host) === undefined ? undefined : [...new Set([...productsOf(host)!, ...AGENT_PRODUCTS])]);
  const active = runs.map((run) => {
    const hosts = run.hosts.filter((h) => !isExposed(ctx, h));
    if (hosts.length === 0) throw new Error(`addBackgroundNoise: every host of run ${run.run.id} is exposed to the internet, which carries no background rows`);
    return { run: run.run, hosts };
  });
  type Active = (typeof active)[number];

  // A flaw the scanner already reported somewhere may be found on another host that runs the same
  // product (the same vulnerability on several servers is what a real scan shows); the entry is then
  // used exactly as first placed, so its product and title agree everywhere.
  const first = new Map<string, CatalogueEntry>();
  // The background is scanner noise: a Medium or Low flaw is written with a low Sim-EPSS, no public
  // exploit and a vendor fix (as first seen, when it already is), the same on every host it appears on.
  const quietOf = new Map<string, CatalogueEntry>();
  const quiet = (e: CatalogueEntry): CatalogueEntry => {
    const hit = quietOf.get(e.id);
    if (hit) return hit;
    const own = rng.fork(`quiet/${e.id}`);
    const q = isNoiseEntry(e, e.published) ? e : withEpss(withFix(e, own), e.epss < NOISE_EPSS_LIMIT ? e.epss : lowerHalfEpss(own, 0.45));
    quietOf.set(e.id, q);
    return q;
  };
  // Every entry is described to fit its vector and the product it names (an agent gets an agent component,
  // never a web-application one); a configuration weakness may stay one here (never on the worklist).
  const described = new Map<string, CatalogueEntry | null>();
  const describe = (e: CatalogueEntry): CatalogueEntry | null => {
    if (!described.has(e.id)) described.set(e.id, describedForProduct(e));
    return described.get(e.id)!;
  };
  let vulnRows = 0;
  let agentRows = 0;
  const agentOk = (): boolean => (agentRows + 1) * 2 < vulnRows + 1; // agent products stay below half of the vulnerability rows
  const writeVulnerability = (r: Active): boolean => {
    const pool = catalogue.entries
      .filter((e) => !taken.has(e.id) && !e.knownExploited && (e.severity === 'medium' || e.severity === 'low') && e.published <= r.run.started)
      .map(describe)
      .filter((e): e is CatalogueEntry => e !== null)
      .map(quiet);
    const again = [...first.values()].filter((e) => isNoiseEntry(e, r.run.started));
    if (pool.length === 0 && again.length === 0) return false;
    for (let attempt = 0; attempt < 30; attempt++) {
      const host = rng.pick(r.hosts);
      const agents = agentOk();
      const free = (e: CatalogueEntry) => !products.has(e.product) && (backgroundProducts(host)?.includes(e.product) ?? true) && !placed.has(`${host}|${e.product}`) && (agents || !isAgentProduct(e.product));
      const fits = pool.filter(free);
      let entry: CatalogueEntry | null;
      if (fits.length > 0) entry = rng.pick(fits);
      else {
        const repeats = again.filter(free);
        if (repeats.length > 0) entry = rng.pick(repeats);
        else if (pool.length > 0) {
          const base = rng.pick(pool);
          const avoid = new Set([...products, ...(backgroundProducts(host) ?? []).filter((p) => placed.has(`${host}|${p}`)), ...(agents ? [] : AGENT_PRODUCTS)]);
          const moved = placedOn(base, host, rng, avoid, backgroundProducts(host));
          entry = moved && describedForProduct(moved);
        } else entry = null;
      }
      if (!entry || placed.has(`${host}|${entry.product}`)) continue;
      const port = r.run.method === 'Unauthenticated' ? rng.pick(BANNER_PORTS) : undefined;
      scan.finding(r.run, { host, entry, port });
      vulnRows++;
      if (isAgentProduct(entry.product)) agentRows++;
      if (!first.has(entry.id)) first.set(entry.id, entry);
      taken.add(entry.id);
      placed.add(`${host}|${entry.product}`);
      return true;
    }
    return false;
  };
  const writeHygiene = (r: Active): boolean => {
    const options: [string, number][] = [];
    for (const host of r.hosts)
      for (const x of HYGIENE_INDEXES) {
        if (isWindows(osOf(host)) ? x === 2 : x === 3) continue;
        if (!usedHygiene.has(`${r.run.id}|${host.toUpperCase()}|${HYGIENE_TITLES[x]}`)) options.push([host, x]);
      }
    if (options.length === 0) return false;
    const [host, x] = rng.pick(options);
    scan.hygieneFinding(r.run, host, x);
    usedHygiene.add(`${r.run.id}|${host.toUpperCase()}|${HYGIENE_TITLES[x]}`);
    return true;
  };
  // One row per run in turn, until the quota is met or no run has room left.
  const spread = (left: number, write: (r: Active) => boolean): number => {
    const full = new Set<Active>();
    let done = 0;
    while (done < left && full.size < active.length) {
      for (const r of active) {
        if (done >= left) break;
        if (full.has(r)) continue;
        if (write(r)) done++;
        else full.add(r);
      }
    }
    return done;
  };
  // Vulnerability rows first, as many as the hosts and products allow; configuration hygiene fills up to
  // the total, but never more than HYGIENE_SHARE_MAX of the background rows actually in the store (the
  // vulnerability rows may fall short on a small catalogue, so the cap is measured on what was written).
  const hygieneTarget = Math.round(total * HYGIENE_SHARE);
  const vulnerabilities = spread(total - hygieneTarget, writeVulnerability);
  const hygieneNow = ctx.log.rowsOf('VulnFindings').filter((r) => String(r.VulnId) === '' && String(r.Title) !== AUTH_FAILURE_TITLE).length;
  const allowed = Math.max(0, Math.floor((HYGIENE_SHARE_MAX / (1 - HYGIENE_SHARE_MAX)) * vulnerabilities) - hygieneNow);
  spread(Math.min(total - vulnerabilities, allowed), writeHygiene);
}

// Whether a device is exposed to the internet (its DeviceInfo row says so).
export const isExposed = (ctx: VulnContext, host: string): boolean => ctx.log.deviceRef(host).row.ExposedToInternet === true;

// The host facts every contradicting-code computation needs, read from DeviceInfo.
export const hostFacts = (ctx: VulnContext, host: string): Pick<ContradictionFacts, 'exposed' | 'criticality'> => ({ exposed: isExposed(ctx, host), criticality: String(ctx.log.deviceRef(host).row.Criticality ?? '') });

// An explicit, visible row for a device whose login failed in a credentialed
// run: local checks did not run, so nothing was re-tested there. Counted in the
// run's AuthFailures. Call it after every other write to that run: it throws
// when the host already has a row in the run (a failed login leaves no other
// row), and the scan writer would not know about the failure for a later
// write. Its FindingId lives in its own namespace ("VFA-nnnnn"; the scan
// writer's are "VF-nnnnn"), so it can never collide. The device must be within
// the run's TargetsScanned: a call that would push the run's devices over it
// throws. The login is over WinRM on a Windows host and SSH elsewhere.
export const AUTH_FAILURE_TITLE = 'Authentication failure: local checks not run';
export function writeAuthFailure(ctx: VulnContext, run: ScanRunHandle, host: string): RowRef<'VulnFindings'> {
  if (run.method !== 'Credentialed') throw new RangeError('Only a credentialed run has a login failure');
  const hosts = new Set(ctx.log.rowsOf('VulnFindings').filter((r) => r.ScanRunId === run.id).map((r) => String(r.DeviceName).toUpperCase()));
  if (hosts.has(host.toUpperCase())) throw new RangeError(`${run.id}: ${host} already has a row in this run, so its login cannot have failed (call writeAuthFailure after every other write to the run)`);
  hosts.add(host.toUpperCase());
  if (hosts.size > Number(run.row.row.TargetsScanned)) throw new RangeError(`${run.id}: a login failure on ${host} would put more devices in the run than the ${String(run.row.row.TargetsScanned)} it reached`);
  const used = new Set(ctx.log.rowsOf('VulnFindings').map((r) => String(r.FindingId)));
  let findingId: string;
  do findingId = `VFA-${ctx.rng.int(10000, 99999)}`;
  while (used.has(findingId));
  const minutes = Math.max(1, Math.round((run.finished - run.started) / MIN));
  const seen = Math.min(run.finished, run.started + ctx.rng.int(1, minutes) * MIN);
  const windows = isWindows(String(ctx.log.deviceRef(host).row.OSPlatform ?? ''));
  const ref = ctx.log.finding({
    FindingId: findingId,
    DeviceName: host,
    VulnId: '',
    Title: AUTH_FAILURE_TITLE,
    Severity: 'Info',
    CvssBase: 0,
    Port: windows ? 5985 : 22,
    Service: windows ? 'winrm' : 'ssh',
    DetectedVersion: '',
    Evidence: `Credentialed login to ${host} failed (authentication error). Local package checks were not run on this device in this scan, so it was not re-tested.`,
    ScanRunId: run.id,
    FirstSeen: seen,
    LastSeen: seen,
    Status: 'Open',
    PluginFamily: 'General',
  });
  const failed = new Set(ctx.log.rowsOf('VulnFindings').filter((r) => r.ScanRunId === run.id && r.Title === AUTH_FAILURE_TITLE).map((r) => String(r.DeviceName).toUpperCase()));
  run.row.row.AuthFailures = Math.max(Number(run.row.row.AuthFailures ?? 0), failed.size);
  return ref;
}

// The distinct devices that have at least one row (a hygiene or login-failure row counts) in the run.
export function hostsWithRows(ctx: VulnContext, run: ScanRunHandle): string[] {
  return [...new Set(ctx.log.rowsOf('VulnFindings').filter((r) => r.ScanRunId === run.id).map((r) => String(r.DeviceName)))];
}

// Call last, after every row of the run is written: the run reached exactly the
// devices that have a row under it (TargetsScanned = distinct devices with a
// row), so the coverage a learner reads in ScanRuns matches VulnFindings. Create
// the run with a TargetsScanned that is an upper bound of the devices it will
// have (the scan writer refuses more), and keep it below TargetsPlanned when the
// case needs a partial run.
export function sizeRunToHosts(ctx: VulnContext, run: ScanRunHandle): void {
  const n = hostsWithRows(ctx, run).length;
  if (n > Number(run.row.row.TargetsScanned)) throw new RangeError(`${run.id}: ${n} devices have rows but the run reached ${String(run.row.row.TargetsScanned)}`);
  if (n < Number(run.row.row.AuthFailures ?? 0)) throw new RangeError(`${run.id}: fewer devices than login failures`);
  run.row.row.TargetsScanned = n;
}

// What a run covered, read from its ScanRuns row (so prose never hard-codes it).
export function coverageOf(run: ScanRunHandle): { scanned: number; planned: number; failures: number } {
  return { scanned: Number(run.row.row.TargetsScanned), planned: Number(run.row.row.TargetsPlanned), failures: Number(run.row.row.AuthFailures ?? 0) };
}

// The distinct Owner values of the given hosts in DeviceInfo, for owner rubrics.
export function ownersOf(ctx: VulnContext, hosts: readonly string[]): string[] {
  return [...new Set(hosts.map((h) => String(ctx.log.deviceRef(h).row.Owner)))];
}

// ---- catalogue helpers ------------------------------------------------------

// A seeded stream for choices that twins must share: derived from the
// catalogue seed (same for both twins on one seed), not from the template id.
export function sharedRng(ctx: VulnContext, label: string): Rng {
  return createRng(`vuln-shared/${ctx.vuln.catalogue.seed}/${label}`);
}

// Pick from `pool` an entry matching `prefer`, else one matching `any`. It throws when no entry matches
// `any`, so make `any` a filter the pool always satisfies (or author the missing entry) when the case must
// build on every seed.
export function pickEntry(rng: Rng, pool: readonly CatalogueEntry[], prefer: (e: CatalogueEntry) => boolean, any: (e: CatalogueEntry) => boolean = () => true): CatalogueEntry {
  const found = [pool.filter(prefer), pool.filter(any)].find((t) => t.length > 0);
  if (!found) throw new Error('pickEntry: the catalogue has no entry matching the fallback filter');
  return rng.pick(found);
}

// A copy of the entry with a different (authored) vector; the score comes from
// our calculator and the band from the score. The class, component and title
// stay as they were: use `withAuthoredVector` when the vector changes what the
// flaw can be.
export function withVector(entry: CatalogueEntry, vector: string): CatalogueEntry {
  const base = baseScore(vector);
  return { ...entry, vector, base, severity: severityOf(base) as CatalogueBand };
}

// ---- class and vector coherence (a finding's vector must fit what it is) ----

const metricsOf = (vector: string): Record<string, string> => Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));

// Component rules: a network-facing component cannot be attacked from the local
// machine only, and a login or pre-auth component needs no privileges. A local
// component (installer profile, permissions template, scripting console) may be AV:L.
const NETWORK_COMPONENT = /endpoint|login form|query parameter|callback|management interface|cross-origin|status page|file-upload|file-download|download handler|request parser|session handler|password reset|token check|admin console|directory listing|debug|update service|protocol negotiator|template engine|report filter|log viewer|error handler|image renderer|compression module/i;
// A scripting console (rce) may be reached locally or over the network; an installer profile or a permissions
// template is only ever a local matter.
const LOCAL_OK_COMPONENT = /installer profile|permissions template|scripting console/i;
const LOCAL_ONLY_COMPONENT = /installer profile|permissions template/i;
const PRE_AUTH_COMPONENT = /login form|sso callback|password reset|default credentials/i;
// Exposure components need no login and no user action. A physical vector fits only a physical component
// (never a web or network-facing one), and a physical component is never reached from the network.
const EXPOSURE_COMPONENT = /directory listing|debug endpoint|metrics endpoint|backup file exposure/i;
const PHYSICAL_COMPONENT = /firmware|boot loader|console port/i;

// Why a vector cannot belong to a flaw of this class and description, or null
// when it can. `text` is the component or the whole title.
export function vectorProblem(vector: string, vulnClass: VulnClass, text: string): string | null {
  const m = metricsOf(vector);
  const label = VULN_CLASS_LABELS[vulnClass];
  if (vulnClass === 'rce' && !((m.AV === 'N' || m.AV === 'A' || (m.AV === 'L' && LOCAL_OK_COMPONENT.test(text))) && m.I === 'H')) return `${label} needs a network-reachable vector with high integrity impact`;
  if (vulnClass === 'sqli' && m.AV !== 'N') return `${label} needs a network vector`;
  if (vulnClass === 'auth-bypass' && m.PR !== 'N') return `${label} needs no privileges required`;
  if ((vulnClass === 'sqli' || vulnClass === 'auth-bypass') && m.C === 'N' && m.I === 'N') return `${label} needs a confidentiality or integrity impact`;
  if (/license service|API token check|admin console|SSO callback/i.test(text) && m.UI !== 'N') return `"${text}" needs no user interaction`;
  if (/default credentials|admin console/i.test(text) && m.PR !== 'N') return `"${text}" needs no privileges required`;
  if (vulnClass === 'info-leak' && !((m.C === 'L' || m.C === 'H') && m.I === 'N')) return `${label} needs a confidentiality impact and no integrity impact`;
  if (vulnClass === 'dos' && !((m.A === 'L' || m.A === 'H') && m.C === 'N' && m.I === 'N')) return `${label} needs an availability impact only`;
  if (/tls/i.test(text) && !(m.AV === 'N' && m.PR === 'N' && m.C !== 'N')) return 'a TLS flaw needs a network vector, no privileges required and a confidentiality impact';
  if (/protocol/i.test(text) && !(m.AV === 'N' && m.PR === 'N')) return 'a protocol flaw needs a network vector and no privileges required';
  if (m.AV === 'P' && !PHYSICAL_COMPONENT.test(text)) return `"${text}" is not a physical component and cannot need physical access`;
  if (PHYSICAL_COMPONENT.test(text) && m.AV !== 'P' && m.AV !== 'L') return `"${text}" is a physical or local component and cannot be reached over the network`;
  if (NETWORK_COMPONENT.test(text) && !LOCAL_OK_COMPONENT.test(text) && m.AV !== 'N' && m.AV !== 'A') return `"${text}" is a network-facing component and needs a network or adjacent vector`;
  if (LOCAL_ONLY_COMPONENT.test(text) && m.AV !== 'L') return `"${text}" is a local component and needs a local vector`;
  if (/cross-origin policy/i.test(text) && !(m.UI === 'R' && m.A === 'N')) return `"${text}" needs user interaction and no availability impact`;
  if (/default credentials/i.test(text) && (m.UI !== 'N' || (m.C === 'N' && m.I === 'N'))) return `"${text}" needs no user interaction and a confidentiality or integrity impact`;
  if (EXPOSURE_COMPONENT.test(text) && m.C === 'N') return `"${text}" needs a confidentiality impact`;
  if (EXPOSURE_COMPONENT.test(text) && !(m.UI === 'N' && m.PR === 'N')) return `"${text}" needs no user interaction and no privileges required`;
  if (PRE_AUTH_COMPONENT.test(text) && m.PR !== 'N') return `"${text}" is reachable before login and needs no privileges required`;
  return null;
}

export const vectorFits = (vector: string, vulnClass: VulnClass, text: string): boolean => vectorProblem(vector, vulnClass, text) === null;

// A catalogue entry whose class, title and vector agree.
export const isCoherent = (e: CatalogueEntry): boolean => vectorFits(e.vector, e.vulnClass, `${e.component} ${e.title}`);

// The class a finding title names (titles read "<class label> in <product> <component>").
export function classOfTitle(title: string): VulnClass | null {
  const t = title.toLowerCase();
  return VULN_CLASSES.find((c) => t.includes(VULN_CLASS_LABELS[c].toLowerCase())) ?? null;
}

// ---- descriptions chosen to fit the vector (worklist and agent products) ----------

type Describable = Exclude<VulnClass, 'misconfig'>;
type ComponentTable = Record<Describable, readonly string[]>;

// Components a background (unscored) finding may be re-described with; worklist findings come only from
// WORKLIST_SHAPES. No configuration weaknesses: an insecure default is fixed by
// changing the configuration, which is neither a vendor patch nor a control in front, and the decision
// vocabulary cannot grade it honestly (background rows may keep them). No physical components (nothing that needs hands on the device). Background helper only: worklist findings come from WORKLIST_SHAPES.
export const BACKGROUND_COMPONENTS: ComponentTable = {
  rce: ['template engine', 'file-upload handler', 'update service', 'plugin loader', 'deserialization endpoint', 'scripting console'],
  sqli: ['search endpoint', 'report filter', 'login form', 'export module', 'API query parameter', 'audit viewer'],
  'auth-bypass': ['session handler', 'SSO callback', 'password reset flow', 'API token check', 'admin console', 'license service'],
  'info-leak': ['debug endpoint', 'backup file exposure', 'error handler', 'directory listing', 'metrics endpoint', 'log viewer'],
  dos: ['request parser', 'certificate handler', 'compression module', 'queue worker', 'image renderer'],
};
// What an agent (inventory, telemetry, scheduler) can be flawed in: no web application parts.
export const AGENT_COMPONENTS: ComponentTable = {
  rce: ['update service', 'plugin loader'],
  sqli: ['management API query parameter'],
  'auth-bypass': ['API token check', 'license service'],
  'info-leak': ['log collector', 'error handler'],
  dos: ['certificate handler', 'queue worker'],
};
const AGENT_ONLY_COMPONENTS: ReadonlySet<string> = new Set(Object.values(AGENT_COMPONENTS).flat().filter((c) => !Object.values(BACKGROUND_COMPONENTS).flat().includes(c)));
const titleOf = (cls: VulnClass, product: string, component: string): string => `${VULN_CLASS_LABELS[cls]} in ${product} ${component}`;

// The entry described (class, component, title) so that all three fit its vector, or null when nothing in
// the table can (score, band and every other field stay). The class stays when it fits; the choice depends
// only on the entry, so twins and repeated calls agree.
export function describedFor(entry: CatalogueEntry, table: ComponentTable = BACKGROUND_COMPONENTS): CatalogueEntry | null {
  const rng = createRng(`vuln-describe/${entry.id}/${entry.vector}/${entry.product}`);
  const fits = (cls: Describable): string[] => table[cls].filter((c) => vectorProblem(entry.vector, cls, titleOf(cls, entry.product, c)) === null);
  const classes = (Object.keys(table) as Describable[]).filter((c) => fits(c).length > 0);
  if (classes.length === 0) return null;
  const cls = classes.includes(entry.vulnClass as Describable) ? (entry.vulnClass as Describable) : rng.pick(classes);
  const component = rng.pick(fits(cls));
  return { ...entry, vulnClass: cls, component, title: titleOf(cls, entry.product, component) };
}

// The entry's description fitted to the kind of product it now names: an agent gets an agent component, any
// other product never one that only an agent has. Null when the vector fits no component of that kind.
export function describedForProduct(entry: CatalogueEntry): CatalogueEntry | null {
  const agent = AGENT_PRODUCTS.includes(entry.product);
  const own = agent ? Object.values(AGENT_COMPONENTS).some((l) => l.includes(entry.component)) : !AGENT_ONLY_COMPONENTS.has(entry.component);
  if (own && isCoherent(entry)) return entry;
  return describedFor(entry, agent ? AGENT_COMPONENTS : BACKGROUND_COMPONENTS);
}
export const isAgentProduct = (product: string): boolean => AGENT_PRODUCTS.includes(product);



// ---- worklist shapes: the one curated table a worklist finding's class, component and vector come from ----------

// What kind of thing a product is: its flaws can only be in the components that kind has (an agent has no login
// form; a web application has no update service of its own).
export type ProductKind = 'web-app' | 'agent' | 'server' | 'appliance';
export const PRODUCT_KINDS: Readonly<Record<string, ProductKind>> = {
  'Larkspur Portal': 'web-app',
  'Ironbark Wiki': 'web-app',
  'Foxglove Helpdesk': 'web-app',
  'Quillon Forms': 'web-app',
  'Pinecrest Dashboards': 'web-app',
  'Thistledown CMS': 'web-app',
  'Elderfen Chat Server': 'web-app',
  'Hollowmere Reporting': 'web-app',
  'Dunmore Badge Manager': 'web-app',
  'Brackenridge DB Console': 'web-app',
  'Ivorygate Payments Adapter': 'web-app',
  'Ombrelune Files': 'server',
  'Tamarind Backup': 'server',
  'Wexcombe Object Store': 'server',
  'Vantorn Build Runner': 'server',
  'Harrowgate Directory Sync': 'server',
  'Quorvane httpd': 'server',
  'Sablecrest Gateway': 'appliance',
  'Marrowgate Proxy': 'appliance',
  'Wrenwick Relay': 'appliance',
  'Gallowglass Firewall Manager': 'appliance',
  'Copperfield Print Server': 'appliance',
  'Tarnwick Inventory Agent': 'agent',
  'Kestrelmoor Telemetry Agent': 'agent',
  'Cinderpath Scheduler': 'agent',
};
export function productKindOf(product: string): ProductKind {
  const kind = PRODUCT_KINDS[product];
  if (!kind) throw new Error(`productKindOf: no kind for product "${product}"`);
  return kind;
}

export type WorklistClass = Exclude<VulnClass, 'misconfig'>;
export interface WorklistShape {
  vulnClass: WorklistClass;
  component: string;
  vector: string; // CVSS 3.1, written for this component and class; the score comes from cvss31.ts
  productKind: ProductKind;
  note: string; // why the vector is what it is
  detail?: string; // appended to the title after a colon
}

const TLS_DETAIL = 'outdated build still negotiates deprecated protocol versions';
type Components = Partial<Record<ProductKind, readonly string[]>>;
interface ShapeGroup {
  vulnClass: WorklistClass;
  vector: string;
  note: string;
  components: Components;
  detail?: string;
}

// Each group is one vector with the components of each product kind it fits. AV:P never appears and no physical
// component is offered. Scores: 9.8 / 9.1 critical; 8.8 / 8.2 / 8.1 high above 7.5; 7.5 the T3 headline; 7.4 / 7.2 / 7.1
// high below 7.5; 6.5 down to 4.3 medium; 3.3 / 3.1 low.
const SHAPE_GROUPS: readonly ShapeGroup[] = [
  // critical
  { vulnClass: 'rce', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', note: 'unauthenticated remote code execution', components: { 'web-app': ['template engine', 'file-upload handler', 'deserialization endpoint', 'plugin loader'], server: ['chunked transfer decoder', 'request parser', 'URL rewrite module', 'update service', 'deserialization endpoint'], appliance: ['update service', 'request parser', 'plugin loader'], agent: ['update service', 'plugin loader'] } },
  { vulnClass: 'sqli', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', note: 'injection reachable without login, reads and changes data', components: { 'web-app': ['search endpoint', 'API query parameter', 'login form'], server: ['API query parameter', 'export module'], appliance: ['API query parameter'] } },
  { vulnClass: 'auth-bypass', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', note: 'full access without credentials', components: { 'web-app': ['session handler', 'SSO callback', 'API token check', 'admin console'], server: ['API token check', 'license service', 'session handler'], appliance: ['admin console', 'API token check', 'license service'], agent: ['API token check', 'license service'] } },
  // high above 7.5
  { vulnClass: 'rce', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', note: 'remote code execution for a logged-in low-privilege user', components: { 'web-app': ['template engine', 'file-upload handler', 'plugin loader', 'deserialization endpoint'], server: ['update service', 'deserialization endpoint', 'plugin loader', 'request parser'], appliance: ['update service', 'plugin loader', 'request parser'], agent: ['update service', 'plugin loader'] } },
  { vulnClass: 'sqli', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', note: 'injection for a logged-in user, reads and changes data', components: { 'web-app': ['search endpoint', 'report filter', 'export module', 'API query parameter', 'audit viewer'], server: ['API query parameter', 'export module'], appliance: ['API query parameter', 'audit viewer', 'report filter'] } },
  { vulnClass: 'auth-bypass', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', note: 'access to data without credentials, limited change', components: { 'web-app': ['session handler', 'SSO callback', 'password reset flow', 'API token check', 'admin console'], server: ['session handler', 'API token check', 'license service'], appliance: ['API token check', 'admin console', 'license service'], agent: ['API token check', 'license service'] } },
  // the T3 headline: 7.5 remote information disclosure
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', note: 'remote read of sensitive data without login', components: { 'web-app': ['file-download handler', 'debug endpoint', 'backup file exposure', 'directory listing', 'metrics endpoint'], server: ['file-download handler', 'backup file exposure', 'directory listing', 'metrics endpoint'], appliance: ['debug endpoint', 'metrics endpoint', 'file-download handler'], agent: ['log collector', 'error handler'] } },
  // high 7.0 to 7.4
  { vulnClass: 'rce', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', note: 'code execution that needs an administrator account', components: { 'web-app': ['scripting console', 'plugin loader', 'template engine', 'deserialization endpoint'], server: ['scripting console', 'plugin loader', 'update service'], appliance: ['update service', 'plugin loader'], agent: ['update service', 'plugin loader'] } },
  { vulnClass: 'sqli', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N', note: 'injection for a logged-in user, mostly reads data', components: { 'web-app': ['search endpoint', 'report filter', 'export module', 'audit viewer', 'API query parameter'], server: ['API query parameter', 'export module'], appliance: ['audit viewer', 'report filter', 'API query parameter'], agent: ['management API query parameter'] } },
  { vulnClass: 'auth-bypass', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', note: 'hard-to-time bypass of the login check', components: { 'web-app': ['session handler', 'API token check', 'SSO callback', 'admin console'], server: ['session handler', 'API token check', 'license service'], appliance: ['API token check', 'admin console', 'license service'], agent: ['API token check', 'license service'] } },
  // medium
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', note: 'a little data readable without login', components: { 'web-app': ['debug endpoint', 'backup file exposure', 'directory listing', 'metrics endpoint', 'status page', 'diagnostics page'], server: ['directory listing', 'metrics endpoint', 'status page', 'backup file exposure', 'job status page'], appliance: ['status page', 'metrics endpoint', 'debug endpoint', 'diagnostics page', 'job status page'], agent: ['log collector', 'error handler'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', note: 'a logged-in user reads data they should not', components: { 'web-app': ['log viewer', 'error handler', 'file-download handler', 'job status page'], server: ['log viewer', 'error handler', 'job status page', 'file-download handler'], appliance: ['log viewer', 'error handler', 'job status page'], agent: ['log collector', 'error handler'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', note: 'a logged-in user reads a little data', components: { 'web-app': ['log viewer', 'error handler', 'diagnostics page', 'job status page'], server: ['log viewer', 'error handler', 'diagnostics page', 'job status page'], appliance: ['log viewer', 'error handler', 'diagnostics page', 'job status page'], agent: ['log collector', 'error handler'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', note: 'a network attacker reads a protected session when the weak protocol is negotiated', detail: TLS_DETAIL, components: { 'web-app': ['bundled TLS component'], server: ['bundled TLS component'], appliance: ['bundled TLS component'], agent: ['bundled TLS component'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', note: 'a network attacker reads a protected session when the handshake downgrades', components: { 'web-app': ['TLS handshake handler'], server: ['TLS handshake handler'], appliance: ['TLS handshake handler'], agent: ['TLS handshake handler'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', note: 'a network attacker reads fragments of a cached session', components: { 'web-app': ['TLS session cache'], server: ['TLS session cache'], appliance: ['TLS session cache'], agent: ['TLS session cache'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', note: 'an on-path attacker with a forged certificate reads the traffic', components: { 'web-app': ['TLS certificate validation'], server: ['TLS certificate validation'], appliance: ['TLS certificate validation'], agent: ['TLS certificate validation'] } },
  { vulnClass: 'dos', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', note: 'a request slows the service down', components: { 'web-app': ['request parser', 'compression module', 'image renderer'], server: ['request parser', 'compression module', 'certificate handler', 'queue worker'], appliance: ['request parser', 'certificate handler', 'queue worker'], agent: ['certificate handler', 'queue worker'] } },
  { vulnClass: 'dos', vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', note: 'a crafted exchange takes the service down', components: { 'web-app': ['request parser', 'compression module', 'image renderer'], server: ['request parser', 'protocol negotiator', 'certificate handler', 'queue worker'], appliance: ['request parser', 'protocol negotiator', 'certificate handler'], agent: ['certificate handler', 'queue worker'] } },
  { vulnClass: 'dos', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', note: 'a logged-in user takes the service down', components: { 'web-app': ['request parser', 'compression module', 'image renderer'], server: ['request parser', 'compression module', 'queue worker'], appliance: ['request parser', 'certificate handler', 'queue worker'], agent: ['certificate handler', 'queue worker'] } },
  { vulnClass: 'sqli', vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', note: 'injection for a logged-in user with limited reach', components: { 'web-app': ['search endpoint', 'report filter', 'export module', 'audit viewer'], server: ['API query parameter', 'export module'], appliance: ['audit viewer', 'report filter', 'API query parameter'], agent: ['management API query parameter'] } },
  { vulnClass: 'sqli', vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N', note: 'injection that needs an administrator account', components: { 'web-app': ['report filter', 'export module', 'audit viewer', 'API query parameter'], server: ['API query parameter', 'export module'], appliance: ['audit viewer', 'report filter', 'API query parameter'] } },
  { vulnClass: 'auth-bypass', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', note: 'partial access without credentials', components: { 'web-app': ['session handler', 'SSO callback', 'password reset flow', 'API token check'], server: ['session handler', 'API token check', 'license service'], appliance: ['API token check', 'admin console', 'license service'], agent: ['API token check', 'license service'] } },
  // low
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', note: 'a local user reads a little data', components: { server: ['temporary file handling', 'local log store'], appliance: ['local log store', 'diagnostic bundle'], agent: ['log collector', 'local cache'] } },
  { vulnClass: 'info-leak', vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N', note: 'a hard-to-time read of a little data by a logged-in user', components: { 'web-app': ['error handler', 'log viewer', 'job status page'], server: ['error handler', 'log viewer', 'job status page'], appliance: ['error handler', 'log viewer', 'job status page'], agent: ['log collector', 'error handler'] } },
  { vulnClass: 'dos', vector: 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L', note: 'a local user slows a worker down', components: { server: ['queue worker'], appliance: ['queue worker', 'certificate handler'], agent: ['queue worker', 'certificate handler'] } },
];

export const WORKLIST_SHAPES: readonly WorklistShape[] = SHAPE_GROUPS.flatMap((g) =>
  (Object.entries(g.components) as [ProductKind, readonly string[]][]).flatMap(([productKind, list]) =>
    list.map((component): WorklistShape => ({ vulnClass: g.vulnClass, component, vector: g.vector, productKind, note: g.note, ...(g.detail ? { detail: g.detail } : {}) })),
  ),
);

export interface ShapeWant {
  classes?: readonly WorklistClass[];
  min?: number; // inclusive base score bounds
  max?: number;
  network?: boolean; // AV:N only
  component?: RegExp;
}

export function shapesFor(kind: ProductKind, want: ShapeWant = {}): WorklistShape[] {
  return WORKLIST_SHAPES.filter((s) => {
    if (s.productKind !== kind) return false;
    if (want.classes && !want.classes.includes(s.vulnClass)) return false;
    const score = baseScore(s.vector);
    if (want.min !== undefined && score < want.min) return false;
    if (want.max !== undefined && score > want.max) return false;
    if (want.network && !s.vector.includes('/AV:N/')) return false;
    if (want.component && !want.component.test(s.component)) return false;
    return true;
  });
}

export const shapeTitle = (s: Pick<WorklistShape, 'vulnClass' | 'component' | 'detail'>, product: string): string => `${VULN_CLASS_LABELS[s.vulnClass]} in ${product} ${s.component}${s.detail ? `: ${s.detail}` : ''}`;

// The entry with the class, component, vector (so score and band) and title of a shape that fits its product's kind and
// what the case needs. The id, product, dates, feeds and fix data stay. Choose with the twins' shared stream.
export function shaped(entry: CatalogueEntry, rng: Rng, want: ShapeWant = {}): CatalogueEntry {
  const list = shapesFor(productKindOf(entry.product), want);
  if (list.length === 0) throw new Error(`shaped: no ${productKindOf(entry.product)} shape for ${JSON.stringify(want)}`);
  const s = rng.pick(list);
  return { ...withVector(entry, s.vector), vulnClass: s.vulnClass, component: s.component, title: shapeTitle(s, entry.product) };
}

// The entry placed on a host (an agent product is avoided when the host has any other) and shaped to fit that product.
export function shapedOn(entry: CatalogueEntry, host: string, rng: Rng, want: ShapeWant = {}, avoid: ReadonlySet<string> = new Set()): CatalogueEntry {
  const placed = placedOn(entry, host, rng, new Set([...avoid, ...AGENT_PRODUCTS])) ?? placedOn(entry, host, rng, avoid);
  if (!placed) throw new Error(`shapedOn: no product fits ${host}`);
  return shaped(placed, rng, want);
}

// A copy published on another date. The id carries the publication year, so it
// is re-issued (same number, next free one on a clash) when the year changes.
export function withPublished(entry: CatalogueEntry, published: number, ids: Iterable<string>): CatalogueEntry {
  const year = new Date(published).getUTCFullYear();
  if (Number(entry.id.slice(8, 12)) === year) return { ...entry, published };
  const taken = new Set(ids);
  let n = Number(entry.id.slice(13));
  let id = formatSimVulnId(year, n);
  while (taken.has(id)) id = formatSimVulnId(year, ++n);
  return { ...entry, id, published };
}

// A copy with an exploitation profile: not on Sim-KEV, the given Sim-EPSS score.
export function withEpss(entry: CatalogueEntry, epss: number, publicExploit = false): CatalogueEntry {
  return { ...entry, knownExploited: false, knownExploitedAdded: null, epss, epssPercentile: Math.round(simEpssPercentile(epss) * 100) / 100, publicExploit };
}

// The Sim-EPSS score every "low probability" decider uses: 0.4%, about the 31st percentile.
export const LOW_EPSS = 0.004;

// A Sim-EPSS score from the lower part of the all-vulnerabilities table (the
// lower half by default: at most 0.0067), for worklist items that are not
// deciders. Deterministic in the rng given.
export function lowerHalfEpss(rng: Rng, upperPercentile = 0.5): number {
  return Math.round(simEpssScoreAt(SIM_EPSS_ALL, rng.next() * upperPercentile) * 10000) / 10000;
}

// A vendor fix must exist for a `patch` truth to be honest.
export function withFix(entry: CatalogueEntry, rng: Rng): CatalogueEntry {
  return entry.vendorFix ? entry : { ...entry, vendorFix: true, fixedVersion: `${rng.int(1, 9)}.${rng.int(1, 12)}.${rng.int(1, 9)}` };
}

// ---- scenario-only hosts and install dates shared by twins ---------------------

// A device that exists only in this case, identical in both twins: its address
// and DeviceId come from the shared stream (the scan writer's own stream is
// seeded by template id, so it would differ). The address is the first free one
// of the shared sequence, and the world is the same for both twins.
export function scopeSharedHost(ctx: VulnContext, input: Omit<ScopeHostInput, 'ip'>, label: string): string {
  const rng = sharedRng(ctx, `host/${label}`);
  const site = ctx.world.sites.find((x) => x.id === (input.site ?? ctx.world.sites[0].id)) ?? ctx.world.sites[0];
  const taken = new Set(ctx.log.rowsOf('DeviceInfo').map((r) => String(r.IPAddress ?? '')));
  const third = input.exposed ? SUBNETS.dmz : SUBNETS.servers;
  let ip = '';
  for (let attempt = 0; attempt < 1000 && ip === ''; attempt++) {
    const candidate = `${site.prefix}.${third}.${rng.int(5, 250)}`;
    if (!taken.has(candidate)) ip = candidate;
  }
  if (ip === '') throw new Error(`scopeSharedHost: no free address in ${site.prefix}.${third}.0/24`);
  const name = ctx.vuln.scan.scopeHost({ ...input, ip });
  ctx.log.deviceRef(name).row.DeviceId = `${rng.hex(8)}-${rng.hex(4)}-4${rng.hex(3)}-${rng.pick(['8', '9', 'a', 'b'])}${rng.hex(3)}-${rng.hex(12)}`;
  return name;
}

// When the vulnerable version was installed, so that it is never after the
// finding's first detection (nor after an exception ticket, when one is passed
// as `notAfter`): 20 to 300 days before the earlier of the two, from the shared stream.
export function installedBefore(ctx: VulnContext, label: string, firstSeen: number, notAfter: number = firstSeen): number {
  const rng = sharedRng(ctx, `installed/${label}`);
  return Math.min(firstSeen, notAfter) - rng.int(20, 300) * DAY - rng.int(1, 20) * HOUR;
}

// Moves the install date of the (host, product) inventory row back so that it is
// never after the finding's first detection (nor after `notAfter`, e.g. an
// exception ticket). A row that is already early enough is left alone.
export function backdateInstall(ctx: VulnContext, label: string, host: string, product: string, firstSeen: number, notAfter: number = firstSeen): void {
  const row = ctx.log.rowsOf('SoftwareInventory').find((r) => String(r.DeviceName).toUpperCase() === host.toUpperCase() && r.Product === product);
  if (!row) return;
  if (Number(row.InstalledOn) > Math.min(firstSeen, notAfter)) (row as Record<string, unknown>).InstalledOn = installedBefore(ctx, label, firstSeen, notAfter);
}

// The inventory row of (host, product) as a RowRef for evidence, whatever wrote it.
export function softwareRef(ctx: VulnContext, host: string, product: string): RowRef<'SoftwareInventory'> {
  const row = ctx.log.rowsOf('SoftwareInventory').find((r) => String(r.DeviceName).toUpperCase() === host.toUpperCase() && r.Product === product);
  if (!row) throw new Error(`softwareRef: no inventory row for ${product} on ${host}`);
  return ctx.vuln.scan.software({ host, product, vendor: String(row.Vendor), version: String(row.Version), source: row.PackageSource as PackageSource });
}

// ---- contradicting reason codes ----------------------------------------------

export interface ContradictionFacts {
  real: boolean; // the finding exists (its decision is not false-positive)
  packageBasis: boolean; // credentialed or agent: the installed package was read (else the version is the banner's)
  staleNoReboot?: boolean; // a stale finding on a host with no reboot pending
  fixedBeforeScan?: boolean; // a false positive whose fix was installed BEFORE the scan (a backport, not a stale result)
  rebootPending?: boolean; // a reboot is pending on the host (only meaningful with fixedBeforeScan)
  exposed?: boolean; // the host's DeviceInfo ExposedToInternet (omit only if the case never uses the code)
  criticality?: string; // the host's DeviceInfo Criticality (a Low one proves 'critical-asset' false)
  exception?: boolean; // an exception ticket names this finding
  control?: boolean; // a ControlInventory row covers this finding
}

// Every code the visible data proves false for a finding, less the codes the
// truth requires (a code is never both): a package-level check is never
// banner-only, a banner-only one is never credentialed-confirmed, the vendor fix
// exists or not, the host is exposed or not, an exception ticket or a control
// row exists or not. Never a code a careful analyst could truthfully cite.
export function contradictionsFor(entry: CatalogueEntry, facts: ContradictionFacts, required: readonly ReasonCode[] = []): ReasonCode[] {
  const out: ReasonCode[] = [];
  if (facts.real) out.push('stale-scan');
  if (!entry.knownExploited) out.push('known-exploited');
  if (!entry.publicExploit) out.push('public-exploit');
  if (entry.knownExploited || entry.epss >= 0.1) out.push('low-exploitability');
  if (facts.packageBasis) out.push('banner-only', 'backported-fix');
  if (facts.staleNoReboot) out.push('pending-reboot');
  if (facts.fixedBeforeScan) {
    if (!facts.real) out.push('stale-scan');
    if (!facts.rebootPending) out.push('pending-reboot');
  }
  if (!facts.packageBasis) out.push('credentialed-confirmed');
  if (entry.vendorFix) out.push('no-vendor-fix');
  if (facts.exposed === false) out.push('internet-exposed');
  if (facts.criticality === 'Low') out.push('critical-asset');
  if (!entry.knownExploited && entry.epss < 0.1) out.push('high-exploit-probability');
  if (facts.exception === false) out.push('approved-exception');
  if (facts.control === false) out.push('compensating-control-verified');
  return [...new Set(out)].filter((c) => !required.includes(c));
}

// ---- risk exception and unrelated patch history ------------------------------

// The approved, time-boxed risk exception for a network-reachable flaw with no
// vendor fix. The compensating measure limits who can reach the service, which
// only makes sense for a network vector, so an entry without AV:N is refused.
// The ticket is dated on or after the entry was published, and not yet expired.
export function writeRiskException(ctx: VulnContext, entry: CatalogueEntry, host: string, segment: string, approvedAt: number, expires: number): RowRef<'Tickets'> {
  if (entry.vendorFix) throw new Error(`writeRiskException: ${entry.id} has a vendor fix`);
  if (metricsOf(entry.vector).AV !== 'N') throw new Error(`writeRiskException: ${entry.id} is not network-reachable (${entry.vector})`);
  if (approvedAt < entry.published) throw new Error(`writeRiskException: ${entry.id} was published after the ticket`);
  return ctx.log.ticket({
    TicketId: ctx.log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Risk exception: ${entry.product} on ${host} (no vendor fix)`,
    Requester: ctx.pick.person({ dept: 'IT', working: false }).upn,
    AssignedTo: 'Security - Vulnerability Management',
    Status: 'Approved',
    Created: approvedAt,
    WindowStart: approvedAt,
    WindowEnd: expires,
    Scope: host,
    Details: `Approved risk exception for ${entry.id} on ${host}: the vendor has published no fix. Compensating measure: the service is reachable over the network only from the ${segment}, so no other network segment can connect to it. Time-boxed: valid until ${ymd(expires)}, then it must be reviewed.`,
  });
}

// Unrelated update history on other hosts (operating system rollups that fix no
// application vulnerability, none naming a vulnerability id), so that
// PatchHistory is not only the rows a case is about. Never on a host in `hosts`
// that a case reasons about: pass only unrelated hosts.
// Twins pass `sharedRng(ctx, ...)` when both must show the same rows.
export function writeUnrelatedPatches(ctx: VulnContext, hosts: readonly string[], perHost: number, source?: Rng): void {
  const rng = source ?? ctx.rng.fork('unrelated-patches');
  for (const host of hosts) {
    ctx.log.deviceRef(host);
    for (let k = 0; k < perHost; k++) {
      ctx.log.patch({
        DeviceName: host,
        PatchId: `PKG-${rng.int(1000, 9999)}`,
        Description: rng.pick([
          'Monthly operating system rollup (kernel and system libraries only; fixes no application vulnerability)',
          'Time zone data update',
          'Firmware and driver bundle (no security fixes)',
          'Antivirus engine and signature update',
        ]),
        InstalledOn: dayStart(ctx.now) - rng.int(2, 75) * DAY + rng.int(1, 20) * HOUR,
        RebootPending: false,
        Result: 'Installed',
      });
    }
  }
}

// ---- references -------------------------------------------------------------

export const REF_CVSS: CaseReference = { label: 'FIRST: CVSS v3.1 specification', url: 'https://www.first.org/cvss/v3.1/specification-document' };
export const REF_KEV: CaseReference = { label: 'CISA: Known Exploited Vulnerabilities catalog (the real list Sim-KEV is modelled on)', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' };
export const REF_EPSS: CaseReference = { label: 'FIRST: Exploit Prediction Scoring System (the real score Sim-EPSS is modelled on)', url: 'https://www.first.org/epss/' };
export const REF_EXAM: CaseReference = { label: 'CompTIA CySA+ CS0-003 exam objectives', url: 'https://www.comptia.org/en-us/certifications/cybersecurity-analyst/v3/' };
