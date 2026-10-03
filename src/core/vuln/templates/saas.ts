// Twin T8 (DESIGN section 4): the same Critical remote flaw in a third-party ticketing product,
// read by the external scan as a version string from the organisation's own public hostname
// (a non-intrusive version read: nothing is sent to the vendor's systems that a visitor would not send).
// The headline, the host, the versions, the dates and the vendor's advisory are identical in both
// twins. What differs is who operates the system.
//
// vm-saas-transfer (A): DeviceInfo shows a vendor-hosted service that IT does not manage, and
// Tickets holds the subscription agreement: the vendor hosts it and installs the fixes. The
// advisory commits to patch every hosted tenant by a date before our own deadline. The policy row
// on vendor-operated services says what to do: transfer, track the vendor's date, verify on the
// vendor's confirmation, and never scan or test the vendor's platform. No change of ours is scheduled.
//
// vm-self-hosted (B): DeviceInfo shows an IT-managed server in the DMZ and Tickets holds the
// installation record: IT runs the self-managed edition, the advisory's hosted-tenant sentences
// are about someone else, and the vendor's update is ours to apply: patch, emergency change (a
// Critical, 7 days).
//
// Decoys, identical in both twins: a vendor support contract for a product that IT installed and
// runs on APP01 (a contract is not a transfer: patch it), and a second vendor-hosted service
// (analytics dashboards) whose finding is a transfer in both twins (so neither "vendor product,
// so transfer" nor "patch everything" is right in either twin). One builder, the clue is a
// parameter. Everything else is chosen from the catalogue seed, not from the template id.

import { DAY, MIN } from '../../logs/time.ts';
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
  softwareRef,
  withEpss,
  withFix,
  withPublished,
  writeChangeTickets,
  writeUnrelatedPatches,
  ymd,
  dateRubricKeywords,
  lowered,
  KW_EMERGENCY,
} from './common.ts';

type Variant = 'transfer' | 'self';

const HEAD_HOST = 'HELPDESK01'; // findings[0] in both twins
const HEAD_PRODUCT = 'Foxglove Helpdesk';
const HEAD_VENDOR = 'Dravenholt Software';
const HEAD_CLOUD = 'dravenholt-cloud.example'; // the vendor's hosting domain (reserved name)
const SAAS_HOST = 'DASHSVC01'; // findings[2] in both twins: a second vendor-hosted service
// The action keywords of the hosted twin name the ticketing service itself. The dashboards service is a transfer in both twins, with
// the same vendor confirmation notice, so "record transfer for DASHSVC01, wait for the confirmation" must not tick this item.
const HEAD_SUBJECTS = [HEAD_HOST, 'the ticketing service', 'the ticketing system', 'the ticketing platform', 'the hosted ticketing', 'the helpdesk service', 'the helpdesk system', 'the helpdesk'];
const HEAD_VERBS = ['transfer', 'transfer for', 'record transfer for', 'track the vendor date for', "track the vendor's date for", 'track the vendor fix for', 'track the vendor fix date for', 'monitor the vendor for', 'monitor the vendor fix for', 'monitor the vendor fix date for', 'monitor the vendor date for', 'wait for the vendor to confirm', 'wait for the vendor confirmation for', "wait for the vendor's confirmation for", 'written confirmation for', 'vendor confirmation for', "vendor's confirmation for", 'confirmation for', 'do not test', 'not scan or test', 'never scan', 'never test', 'no testing of', 'no scanning of'];
const HEAD_AFTER = ['is recorded as transfer', 'is marked as transfer', 'goes to transfer', 'as transfer', ': transfer', 'is transfer', 'is a transfer', 'to transfer', 'vendor confirmation', 'vendor confirms', "vendor's confirmation", 'written confirmation'];
const HEAD_ACTIONS: string[] = [...HEAD_SUBJECTS.flatMap((s) => [...HEAD_VERBS.map((v) => `${v} ${s}`), ...HEAD_AFTER.map((a) => `${s} ${a}`)]), 'ticketing transfer', 'ticketing vendor confirmation', 'monitor the ticketing vendor'];
const SAAS_PRODUCT = 'Pinecrest Dashboards';
const SAAS_VENDOR = 'Pinecrest Analytics';
const SAAS_CLOUD = 'pinecrest-cloud.example';
const APP = 'APP01'; // the contract decoy: installed and run by IT, with a vendor support contract
const BUILD = 'BUILD01';
const JUMP = 'JUMP01';
const OWNER = 'Service Desk';
const VENDOR_OS = 'Vendor-managed (hosted service)';
const PORT = 443;

const TITLE = 'Scan review: third-party ticketing service and internal servers';

// The template-local policy row (identical in both twins): who must fix a flaw follows who operates the system.
const VENDOR_ROW: [string, string] = [
  'Vendor-operated service',
  "Who fixes a flaw follows who operates the system. If a vendor hosts and operates the service (DeviceInfo shows a hosted service that IT does not manage, and Tickets holds the subscription agreement), the vendor fixes it on its own platform: record the finding as transfer (no change of ours, so no schedule), track the committed fix date in the vendor's advisory (Tickets), and close the finding on the vendor's confirmation of the fix. Do not scan or test the vendor's platform: many SaaS terms forbid it or restrict it to published rules or the vendor's written permission. The only check we make on a vendor-hosted service is a non-intrusive read of the version string an ordinary request to our own public hostname returns (what any visitor receives); no probes, payloads or logins are sent; confirm the fix from the vendor's advisory and its confirmation notice. If IT installs and runs the product on its own server (DeviceInfo shows an IT-managed server, Tickets the installation record), the vendor's update is ours to apply: patch by the standard rules. A vendor support contract alone transfers nothing: a product we run ourselves is still ours to patch.",
];

const quiet = (e: CatalogueEntry): boolean => !e.knownExploited && e.vendorFix;

function build(variant: Variant, ctx: VulnContext): VulnCaseSpec {
  const { log, now, world } = ctx;
  const { scan, catalogue } = ctx.vuln;
  const hosted = variant === 'transfer'; // A: the headline is a vendor-hosted service
  const cal = buildCalendar(now);
  const rng = sharedRng(ctx, 'saas');
  const used = new Set<string>();
  const free = () => catalogue.entries.filter((e) => !used.has(e.id));
  const allIds = catalogue.entries.map((e) => e.id);
  const versionOf = (label: string, e: CatalogueEntry): string => {
    const r = sharedRng(ctx, `version/${label}`);
    return e.vendorFix ? versionBelow(r, e.fixedVersion) : `${r.int(1, 9)}.${r.int(0, 12)}.${r.int(0, 9)}`;
  };
  const trng = sharedRng(ctx, 'tenants');
  const headTenant = `tenant-${trng.int(1000, 9999)}.${HEAD_CLOUD}`;
  const saasTenant = `tenant-${trng.int(1000, 9999)}.${SAAS_CLOUD}`;
  const headAlias = `helpdesk.${world.org.tenant}.test`; // our own public hostnames (reserved names, never the real-looking org domain: the reserved-domain guardrail): the external run reads these; where the service is vendor-hosted they are aliases (CNAME) for the vendor's tenant host
  const saasAlias = `dashboards.${world.org.tenant}.test`;

  // ---- two runs: an older credentialed internal run of the servers, a newer external run that reads the version strings of the
  // organisation's own public hostnames (it reached two of the four it planned).
  const runRng = sharedRng(ctx, 'scan-runs');
  const intId = `SCN-${runRng.int(1000, 4999)}`;
  const extId = `SCN-${runRng.int(5000, 9999)}`;
  const intRun = scan.run({ id: intId, durationMin: runRng.int(45, 180), method: 'Credentialed', started: now - 9 * DAY, targetsPlanned: 12, targetsScanned: 12 });
  const extRun = scan.run({ id: extId, durationMin: runRng.int(1, 10), method: 'Unauthenticated', vantage: 'External', started: now - 4 * DAY, targetsPlanned: 4, targetsScanned: 4 }); // sized to the devices that have a row
  const lastSeen = (run: typeof intRun, label: string): number => run.started + sharedRng(ctx, `last-seen/${label}`).int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN;

  // ---- dates (all relative to the case date, shared by the twins)
  const firstSeen = extRun.started; // the external run is the first to read the two hosted-looking versions
  const advisoryAt = now - 3 * DAY;
  const committed = dayStart(now) + 2 * DAY; // the vendor's committed date: before our own Critical deadline
  const f2First = now - 22 * DAY; // High: due 30 days on, after the next window and before the standard cycle
  const f4First = intRun.started; // High, first detected by the older run: standard cycle
  const f5First = now - 50 * DAY;

  // ---- entries (twins share every choice)
  // `recent`: the flaw was disclosed 2 to 10 days before its first detection (the vendor's advisory, the disclosure and the first read tell one recent story).
  const choose = (want: ShapeWant, first: number, epss: number, where: { host: string; avoid?: ReadonlySet<string> } | { brand: { product: string; vendor: string } }, recent = false): CatalogueEntry => {
    const candidates = free().filter(quiet);
    const known = candidates.filter((x) => x.published <= first);
    const base = rng.pick(recent || known.length === 0 ? candidates : known);
    const dated = withPublished(base, recent ? dayStart(first - rng.int(2, 10) * DAY) : Math.min(base.published, dayStart(first - DAY)), [...allIds, ...used]);
    const e = 'brand' in where ? shaped({ ...dated, ...where.brand }, rng, want) : shapedOn(dated, where.host, rng, want, where.avoid);
    used.add(base.id);
    used.add(e.id);
    return withEpss(withFix(e, rng), epss);
  };
  // The headline: a Critical network flaw in the ticketing product (a web application component).
  let head = choose({ classes: ['rce'], min: 9, network: true }, firstSeen, LOW_EPSS, { brand: { product: HEAD_PRODUCT, vendor: HEAD_VENDOR } }, true);
  if (!/^\d+\.\d+\.\d+$/.test(head.fixedVersion)) head = { ...head, fixedVersion: `${rng.int(2, 9)}.${rng.int(2, 9)}.${rng.int(2, 9)}` };
  const headVersion = versionBelow(rng, head.fixedVersion);
  // The second vendor-hosted service: a Medium, a transfer in both twins.
  const f3Entry = choose({ min: 4, max: 6.9, network: true }, firstSeen, lowerHalfEpss(rng.fork('f3'), 0.45), { brand: { product: SAAS_PRODUCT, vendor: SAAS_VENDOR } }, true);
  // The contract decoy: a High on a product IT installed and runs, with a vendor support contract.
  const f2Entry = choose({ min: 7, max: 8.9, network: true }, f2First, LOW_EPSS, { host: APP, avoid: new Set([HEAD_PRODUCT, SAAS_PRODUCT]) });
  const f4Entry = choose({ min: 7, max: 8.9 }, f4First, lowerHalfEpss(rng.fork('f4'), 0.45), { host: BUILD });
  const f5Entry = choose({ max: 3.9 }, f5First, lowerHalfEpss(rng.fork('f5'), 0.45), { host: JUMP });

  // ---- the two public-facing services: identical hosts except what the headline's role says (the clue).
  const headRole = hosted
    ? `Ticketing service (${HEAD_PRODUCT}), vendor-hosted at ${headTenant} (our public hostname ${headAlias} is an alias for it): ${HEAD_VENDOR} operates the servers, IT manages accounts and settings only`
    : `Ticketing server (${HEAD_PRODUCT} self-managed edition): installed and operated by IT (public hostname ${headAlias})`;
  scopeSharedHost(ctx, { name: HEAD_HOST, role: headRole, os: hosted ? VENDOR_OS : 'Dovrenix Linux 5.4', owner: OWNER, criticality: 'Medium', exposed: true, managed: !hosted }, 'helpdesk');
  scopeSharedHost(ctx, { name: SAAS_HOST, role: `Analytics dashboards service (${SAAS_PRODUCT}), vendor-hosted at ${saasTenant} (our public hostname ${saasAlias} is an alias for it): ${SAAS_VENDOR} operates the servers, IT manages accounts and settings only`, os: VENDOR_OS, owner: OWNER, criticality: 'Medium', exposed: true, managed: false }, 'dashsvc');
  const headDevice = log.deviceRef(HEAD_HOST);
  const saasDevice = log.deviceRef(SAAS_HOST);
  // A vendor-hosted service does not sit on our network: its row carries a vendor-cloud site and a documentation-range address (never one of ours).
  // The address is the first free one of the documentation range from a drawn start, free in DeviceInfo and in the world's external reservations (the
  // office and VPN egress addresses of NamedLocations, service addresses); it is reserved with the allocator so nothing else takes it.
  const vendorCloudIp = (from: number): string => {
    const taken = new Set([...log.rowsOf('DeviceInfo').map((r) => String(r.IPAddress ?? '')), ...log.ext.reserved()]);
    for (let n = from; n < from + 100; n++) {
      const ip = `203.0.113.${n}`;
      if (n <= 254 && !taken.has(ip)) {
        log.ext.reserve(ip);
        return ip;
      }
    }
    throw new Error(`saas: no free vendor-cloud address from 203.0.113.${from}`);
  };
  const placeInVendorCloud = (host: string, vendor: string, ip: string): void => {
    const row = log.deviceRef(host).row as Record<string, unknown>;
    row.IPAddress = ip;
    row.Site = `Vendor cloud (${vendor})`;
  };
  const vrng = sharedRng(ctx, 'vendor-cloud');
  const [headFrom, saasFrom] = [vrng.int(5, 100), vrng.int(120, 150)]; // both drawn and both addresses taken in both twins, so the shared host's address and the allocator are the same
  const [headIp, saasIp] = [vendorCloudIp(headFrom), vendorCloudIp(saasFrom)];
  if (hosted) placeInVendorCloud(HEAD_HOST, HEAD_VENDOR, headIp);
  placeInVendorCloud(SAAS_HOST, SAAS_VENDOR, saasIp);

  const fingerprint = (e: CatalogueEntry, version: string, host: string): string =>
    `Version fingerprint (non-intrusive): the https service on ${PORT}/tcp announces "${e.product.replace(/\s+/g, '-')}/${version}" (version read from the response header served at ${host}, the organisation's own public hostname; no exploit and no intrusive test was sent). Version taken from the banner only; installed packages were not inspected. Fixed in ${e.fixedVersion}.`;

  // ---- F1 headline and F3 second hosted service, from the external run
  const f1 = scan.finding(extRun, { host: HEAD_HOST, entry: head, port: PORT, firstSeen, lastSeen: lastSeen(extRun, 'f1'), installedVersion: headVersion, bannerVersion: headVersion, title: head.title, evidence: fingerprint(head, headVersion, headAlias) });
  const f1Installed = installedBefore(ctx, 'f1', firstSeen);
  scan.software({ host: HEAD_HOST, product: HEAD_PRODUCT, vendor: HEAD_VENDOR, version: headVersion, installedOn: f1Installed });
  scan.intel(head);
  const f3Version = versionOf('f3', f3Entry);
  const f3 = scan.finding(extRun, { host: SAAS_HOST, entry: f3Entry, port: PORT, firstSeen, lastSeen: lastSeen(extRun, 'f3'), installedVersion: f3Version, bannerVersion: f3Version, title: f3Entry.title, evidence: fingerprint(f3Entry, f3Version, saasAlias) });
  const f3Installed = installedBefore(ctx, 'f3', firstSeen);
  scan.software({ host: SAAS_HOST, product: SAAS_PRODUCT, vendor: SAAS_VENDOR, version: f3Version, installedOn: f3Installed });
  const f3Intel = scan.intel(f3Entry);

  // ---- the credentialed run's rows: the contract decoy (F2) and two clear-cut findings (F4, F5)
  const f2Version = versionOf('f2', f2Entry);
  const f2 = scan.finding(intRun, { host: APP, entry: f2Entry, firstSeen: f2First, lastSeen: lastSeen(intRun, 'f2'), installedVersion: f2Version, title: f2Entry.title });
  const f2Installed = installedBefore(ctx, 'f2', f2First);
  scan.software({ host: APP, product: f2Entry.product, vendor: f2Entry.vendor, version: f2Version, installedOn: f2Installed });
  const f2Intel = scan.intel(f2Entry);
  const f4 = scan.finding(intRun, { host: BUILD, entry: f4Entry, firstSeen: f4First, lastSeen: lastSeen(intRun, 'f4'), installedVersion: versionOf('f4', f4Entry), title: f4Entry.title });
  const f5 = scan.finding(intRun, { host: JUMP, entry: f5Entry, firstSeen: f5First, lastSeen: lastSeen(intRun, 'f5'), installedVersion: versionOf('f5', f5Entry), title: f5Entry.title });
  for (const [label, host, e, first] of [['f4', BUILD, f4Entry, f4First], ['f5', JUMP, f5Entry, f5First]] as const)
    scan.software({ host, product: e.product, vendor: e.vendor, version: versionOf(label, e), installedOn: installedBefore(ctx, label, first) });

  // ---- tickets: the vendor's advisories (the same text in both twins), the one record that differs (the clue), the contract decoy
  const requester = () => ctx.pick.person({ dept: 'IT', working: false }).upn;
  const advisory = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Vendor advisory ${head.id}: ${HEAD_PRODUCT}`,
    Requester: requester(),
    AssignedTo: 'Security - Vulnerability Management',
    Status: 'Open',
    Created: advisoryAt,
    Scope: HEAD_HOST,
    Details: `Advisory from ${HEAD_VENDOR}: ${head.id} affects ${HEAD_PRODUCT} releases below ${head.fixedVersion}. Hosted service: the vendor is updating every hosted tenant and commits to finish the rollout by ${ymd(committed)}; hosted customers need take no action and will receive a confirmation notice from the vendor. Self-managed edition: the vendor does not update customer-run servers; upgrade to ${head.fixedVersion} or later.`,
  });
  const clue = hosted
    ? log.ticket({
        TicketId: log.nextTicketId('REQ'),
        Type: 'Service request',
        Title: `Vendor subscription: ${HEAD_PRODUCT} (hosted service)`,
        Requester: requester(),
        AssignedTo: 'IT Service Management',
        Status: 'Approved',
        Created: f1Installed,
        Scope: HEAD_HOST,
        Details: `Subscription agreement with ${HEAD_VENDOR}: the vendor hosts and operates ${HEAD_PRODUCT} for us at ${headTenant} (our public hostname ${headAlias} is an alias for it) and installs all updates and security fixes on its own platform. IT manages accounts, queues and settings only and has no access to the servers. Fixing a flaw in the platform is the vendor's responsibility under the agreement.`,
      })
    : log.ticket({
        TicketId: log.nextTicketId('REQ'),
        Type: 'Service request',
        Title: `Installation record: ${HEAD_PRODUCT} on ${HEAD_HOST} (self-managed edition)`,
        Requester: requester(),
        AssignedTo: 'IT Infrastructure',
        Status: 'Closed',
        Created: f1Installed,
        Scope: HEAD_HOST,
        Details: `IT installed the self-managed edition of ${HEAD_PRODUCT} on ${HEAD_HOST} (a server in the DMZ, public hostname ${headAlias}), runs it and applies its updates. The vendor ships updates but has no access to the server, and an update reaches it only when IT applies it.`,
      });
  const f3Sub = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Vendor subscription: ${SAAS_PRODUCT} (hosted service)`,
    Requester: requester(),
    AssignedTo: 'IT Service Management',
    Status: 'Approved',
    Created: f3Installed,
    Scope: SAAS_HOST,
    Details: `Subscription agreement with ${SAAS_VENDOR}: the vendor hosts and operates ${SAAS_PRODUCT} for us at ${saasTenant} (our public hostname ${saasAlias} is an alias for it) and installs all updates and security fixes on its own platform. IT manages accounts and settings only and has no access to the servers. Fixing a flaw in the platform is the vendor's responsibility under the agreement.`,
  });
  const f3Advisory = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Vendor advisory ${f3Entry.id}: ${SAAS_PRODUCT}`,
    Requester: requester(),
    AssignedTo: 'Security - Vulnerability Management',
    Status: 'Open',
    Created: advisoryAt,
    Scope: SAAS_HOST,
    Details: `Advisory from ${SAAS_VENDOR}: ${f3Entry.id} affects the hosted ${SAAS_PRODUCT} service. The vendor is updating every hosted tenant and commits to finish the rollout by ${ymd(dayStart(now) + 20 * DAY)}; customers need take no action and will receive a confirmation notice from the vendor.`,
  });
  const contract = log.ticket({
    TicketId: log.nextTicketId('REQ'),
    Type: 'Service request',
    Title: `Vendor support contract: ${f2Entry.product} on ${APP}`,
    Requester: requester(),
    AssignedTo: 'IT Service Management',
    Status: 'Approved',
    Created: f2Installed,
    Scope: APP,
    Details: `Annual support contract with ${f2Entry.vendor} for ${f2Entry.product} on ${APP}: the vendor answers support calls and publishes updates. IT installed ${f2Entry.product} on ${APP}, runs it and applies its updates; the vendor has no access to the server.`,
  });

  // ---- noise, tickets, calendar, unrelated updates. The external run's two hosts are exposed to the internet and carry no background rows.
  addBackgroundNoise(ctx, [{ run: intRun, hosts: ['FS02', 'DC01', 'DC02', 'SCCM01', 'BKP01', 'ADCONNECT01'] }], [head, f2Entry, f3Entry, f4Entry, f5Entry]);
  writeChangeTickets(ctx, cal);
  writeUnrelatedPatches(ctx, ['FS02', 'DC01', 'DC02', 'SCCM01', 'BKP01', 'ADCONNECT01'], 2, sharedRng(ctx, 'unrelated-patches'));
  sizeRunToHosts(ctx, intRun);
  sizeRunToHosts(ctx, extRun);

  // ---- the truth (derived from the policy, the calendar, the dates and the rows)
  const spec = (x: WrittenFinding, over: Pick<FindingSpec, 'truth' | 'weight' | 'evidence'> & Partial<FindingSpec>): FindingSpec => ({ findingId: x.findingId, row: x.row, ...over });
  const facts = (host: string, over: Partial<ContradictionFacts> = {}): ContradictionFacts => ({ real: true, packageBasis: true, ...hostFacts(ctx, host), exception: false, control: false, ...over });
  const critDeadline = slaDeadline('critical', firstSeen);
  const f2Deadline = slaDeadline('high', f2First);
  const f4Deadline = slaDeadline('high', f4First);
  const firstAgo = Math.round((now - firstSeen) / DAY);

  const f1Spec: FindingSpec = hosted
    ? spec(f1, {
        truth: { decision: 'transfer', schedule: 'none', slaLatest: 'none', reasons: ['vendor-responsibility'], contradicting: contradictionsFor(head, facts(HEAD_HOST, { packageBasis: false }), ['vendor-responsibility']) },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'vendor-operates-it',
            label: `DeviceInfo shows ${HEAD_HOST} is a vendor-hosted service IT does not manage, and Tickets has the subscription agreement`,
            why: `DeviceInfo describes ${HEAD_HOST} as a service hosted by ${HEAD_VENDOR} at ${headTenant} (IsManaged false, OSPlatform "${VENDOR_OS}"), and Tickets has the subscription agreement: the vendor hosts and operates the product and installs security fixes on its own platform, and IT has no access to the servers. The policy row on vendor-operated services applies: the fix is the vendor's to make, so there is nothing for us to patch or schedule.`,
            rows: [headDevice, clue],
          },
          {
            id: 'vendor-committed-date',
            label: `The vendor's advisory commits to update every hosted tenant by ${ymd(committed)}`,
            why: `Tickets has the advisory for ${head.id}: for the hosted service the vendor commits to finish the rollout by ${ymd(committed)}, a day before our Critical deadline (7 days from first detection ${firstAgo} days ago, due ${ymd(critDeadline)}, end of day), and will send a confirmation notice. Record transfer, track that date and close the finding on the vendor's confirmation; the only check we make is a non-intrusive read of the version string an ordinary request to our own public hostname returns (no probes, payloads or logins); we never scan or test the vendor's platform (many SaaS terms forbid it or restrict it to published rules or the vendor's written permission) (VulnIntel shows the fix exists: ${head.fixedVersion}).`,
            rows: [advisory],
          },
        ],
      })
    : spec(f1, {
        truth: { decision: 'patch', schedule: 'emergency', slaLatest: 'emergency', reasons: ['sla-deadline', 'internet-exposed'], contradicting: [...new Set([...contradictionsFor(head, facts(HEAD_HOST, { packageBasis: false }), ['sla-deadline', 'internet-exposed']), 'vendor-responsibility' as const])] },
        weight: 1,
        lesson: true,
        evidence: [
          {
            id: 'it-runs-it',
            label: `DeviceInfo shows ${HEAD_HOST} is a server IT manages, and Tickets has the installation record`,
            why: `DeviceInfo describes ${HEAD_HOST} as a self-managed ${HEAD_PRODUCT} server in the DMZ, managed by IT (IsManaged true), and Tickets has the installation record: IT installed it, runs it and applies its updates. No vendor operates it, so the policy row on vendor-operated services does not apply: the vendor's update is ours to apply.`,
            rows: [headDevice, clue],
          },
          {
            id: 'advisory-self-managed',
            label: `The advisory's committed date is for hosted tenants; for the self-managed edition the vendor does not update customer-run servers`,
            why: `Tickets has the advisory for ${head.id}: its commitment to finish by ${ymd(committed)} is for the hosted service; for the self-managed edition it says the vendor does not update customer-run servers and to upgrade to ${head.fixedVersion} or later (VulnIntel shows the fix exists). SoftwareInventory shows ${headVersion} on ${HEAD_HOST}, below it.`,
            rows: [advisory],
          },
          {
            id: 'critical-deadline',
            label: 'A Critical, first detected by the external run, is due in 7 days: before the next window',
            why: `${extRun.id} first read the version on ${ymd(firstSeen)} (${firstAgo} days ago); the 7-day Critical deadline (${ymd(critDeadline)}, end of day) falls before the next window (${ymd(cal.next.start)}): emergency change. The host is reachable from the internet (DeviceInfo ExposedToInternet), which is why internet exposure is a reason.`,
            rows: [extRun.row, f1.row],
          },
        ],
      });

  const findings: FindingSpec[] = [
    f1Spec,
    spec(f2, {
      truth: { decision: 'patch', schedule: 'next-window', slaLatest: 'next-window', reasons: ['sla-deadline'], contradicting: [...new Set([...contradictionsFor(f2Entry, facts(APP), ['sla-deadline']), 'vendor-responsibility' as const])] },
      weight: 1,
      evidence: [
        {
          id: 'contract-is-not-hosting',
          label: `Tickets has a vendor support contract for ${f2Entry.product}, but IT installed and runs it on ${APP}`,
          why: `Tickets has a support contract with ${f2Entry.vendor}: the vendor answers calls and publishes updates, but IT installed ${f2Entry.product} on ${APP}, runs it and applies its updates (SoftwareInventory shows it installed on ${APP}). A support contract transfers nothing, so patch it. First detected ${Math.round((now - f2First) / DAY)} days ago, its 30-day High deadline (${ymd(f2Deadline)}, end of day) is after the next window and before the standard cycle: next window.`,
          rows: [contract, softwareRef(ctx, APP, f2Entry.product), f2Intel],
        },
      ],
    }),
    spec(f3, {
      truth: { decision: 'transfer', schedule: 'none', slaLatest: 'none', reasons: ['vendor-responsibility'], contradicting: contradictionsFor(f3Entry, facts(SAAS_HOST, { packageBasis: false }), ['vendor-responsibility']) },
      weight: 1,
      evidence: [
        {
          id: 'second-hosted-service',
          label: `${SAAS_HOST} is also a vendor-hosted service: subscription agreement and the vendor's committed date`,
          why: `DeviceInfo describes ${SAAS_HOST} as a service hosted by ${SAAS_VENDOR} at ${saasTenant} (IsManaged false); Tickets has the subscription agreement and the vendor's advisory for ${f3Entry.id}, which commits to update every hosted tenant by ${ymd(dayStart(now) + 20 * DAY)} (a Medium: due ${ymd(slaDeadline('medium', firstSeen))}). The vendor operates it: transfer, track the date, verify on the vendor's confirmation.`,
          rows: [saasDevice, f3Sub, f3Advisory, f3Intel],
        },
      ],
    }),
    spec(f4, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['sla-deadline'], contradicting: contradictionsFor(f4Entry, facts(BUILD), ['sla-deadline']) }, weight: 0.5, evidence: [] }),
    spec(f5, { truth: { decision: 'patch', schedule: 'standard-cycle', slaLatest: 'standard-cycle', reasons: ['low-exploitability'], contradicting: contradictionsFor(f5Entry, facts(JUMP), ['low-exploitability']) }, weight: 0.5, evidence: [] }),
  ];

  const ids = { f1: f1.findingId, f2: f2.findingId, f3: f3.findingId, f4: f4.findingId, f5: f5.findingId };
  const ownerNames = [...new Set([...ownersOf(ctx, [HEAD_HOST, SAAS_HOST, APP, BUILD, JUMP]), 'IT Infrastructure'])]; // the change tickets are assigned to IT Infrastructure

  const briefing = `${world.org.name}: review of the latest scan results for the public ticketing service, a second public service and the internal servers in scope (an older credentialed run of the servers and a newer external run that reads the version strings of our own public hostnames; neither covered every target). Decide for each worklist finding whether to patch, mitigate, avoid, accept, transfer or dismiss it as a false positive, put the worklist in order, choose when each change should happen and cite your reasons. Our remediation standard and the change calendar are attached. Scan results, vulnerability intelligence (simulated Sim-KEV and Sim-EPSS feeds), asset, software inventory and ticket data are in the SIEM tables. All data is simulated.`;

  // Hints 1 and 2 are the same text in both twins: they must not tell which one this is.
  const lead = 'A scanner reports a flaw in a product; it does not say who must fix it. Who operates the system the finding is on, and what has the vendor said about fixing it? Which tables show that?';
  const second = 'DeviceInfo says what the system is, whether IT manages it and who owns it. Tickets holds subscription and installation records, support contracts and the vendors\' advisories: read whom each advisory sentence is about. Then read the policy row on vendor-operated services.';

  return {
    briefing,
    attachments: policyAttachments(world.org.name, cal, [VENDOR_ROW]),
    findings,
    constraints: cal.constraints,
    idealOrder: hosted ? [ids.f2, ids.f4, ids.f5] : [ids.f1, ids.f2, ids.f4, ids.f5],
    tiers: hosted ? [[ids.f2], [ids.f4], [ids.f5]] : [[ids.f1, ids.f2], [ids.f4], [ids.f5]],
    hints: [
      lead,
      second,
      hosted
        ? `${HEAD_HOST} is a service the vendor hosts and operates (DeviceInfo, and the subscription agreement in Tickets), and the vendor's advisory commits to fix every hosted tenant by a date. The fix is the vendor's, so record transfer, track the date and verify on the vendor's confirmation. The support contract on ${APP} is a different case: IT runs that product.`
        : `${HEAD_HOST} is a server IT installed and runs (DeviceInfo, and the installation record in Tickets); the advisory's committed date is for hosted tenants, not for this install. The update is ours to apply: it is a Critical, so check how many days it has before the next window. ${SAAS_HOST} is the one the vendor hosts.`,
    ],
    solution: [
      {
        title: 'What did the scanner find, and which run found it?',
        kql: `VulnFindings\n| where DeviceName in ("${HEAD_HOST}", "${SAAS_HOST}", "${APP}", "${BUILD}", "${JUMP}")\n| project FindingId, DeviceName, VulnId, Title, Severity, CvssBase, Port, DetectedVersion, FirstSeen, ScanRunId, Evidence, RecordId`,
        why: `A Critical on ${HEAD_HOST} and a Medium on ${SAAS_HOST}, both from the external run: its Evidence says the version was read from the banner of our own public hostname, with no exploit or intrusive test. The other three come from the older credentialed run.`,
      },
      {
        title: 'How were the runs made, and what did each cover?',
        kql: 'ScanRuns\n| project ScanRunId, Tool, Method, Vantage, Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures, RecordId\n| sort by Started desc',
        why: `${extRun.id} is the external, unauthenticated run (it can read version strings only and reached 2 of 4 planned targets, our own public hostnames); ${intRun.id} is the older credentialed internal run.`,
      },
      {
        title: 'Who operates each system?',
        kql: `DeviceInfo\n| where DeviceName in ("${HEAD_HOST}", "${SAAS_HOST}", "${APP}")\n| project DeviceName, DeviceType, OSPlatform, Role, Owner, Criticality, IsManaged, ExposedToInternet, RecordId`,
        why: hosted ? `${HEAD_HOST} and ${SAAS_HOST} are vendor-hosted services IT does not manage (IsManaged false, the vendor operates the servers); ${APP} is an IT-managed server.` : `${HEAD_HOST} is a server IT manages and operates; ${SAAS_HOST} is the vendor-hosted one (IsManaged false); ${APP} is an IT-managed server.`,
      },
      {
        title: 'What do the vendor tickets say: subscriptions, installations, contracts and advisories?',
        kql: 'Tickets\n| where Title has "Vendor" or Title has "Installation"\n| project TicketId, Type, Title, Status, Created, Scope, Details, RecordId\n| sort by Created asc',
        why: hosted
          ? `The subscription agreements for ${HEAD_HOST} and ${SAAS_HOST} (the vendor hosts and fixes), the vendors' advisories with their committed dates, and a support contract for ${APP} (the vendor supports, IT runs it).`
          : `The installation record for ${HEAD_HOST} (IT runs it), the subscription agreement for ${SAAS_HOST} (the vendor hosts it), the advisories, and a support contract for ${APP} (the vendor supports, IT runs it).`,
      },
      {
        title: 'Which release of each product is installed, and since when?',
        kql: `SoftwareInventory\n| where DeviceName in ("${HEAD_HOST}", "${SAAS_HOST}", "${APP}")\n| project DeviceName, Product, Vendor, Version, PackageSource, InstalledOn, RecordId`,
        why: 'The product is listed on each of the three systems; the release is compared with the fixed release in the intel below. For a vendor-hosted service the row is the version the vendor\'s service reports, not an install IT performed.',
      },
      {
        title: 'What does the intel say?',
        kql: `VulnIntel\n| where VulnId in ("${head.id}", "${f3Entry.id}", "${f2Entry.id}")\n| project VulnId, CvssBase, CvssVector, KnownExploited, ExploitProbability, PublicExploit, VendorFix, FixedVersion, RecordId`,
        why: `A vendor fix exists for every one (so no-vendor-fix is not a reason); no Sim-KEV listing, a low Sim-EPSS, no public exploit: the Critical class and the 7-day SLA set the urgency of the headline where it is ours to fix.`,
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
        text: hosted ? `States the risk in plain words: the ticketing service is hosted and operated by the vendor, whose advisory commits to fix it by ${ymd(committed)}; the fix is the vendor's, but accountability for our data stays with us, so the finding stays open until the vendor confirms the fix.` : 'States the risk in plain words: the ticketing server is ours (installed and run by IT) and the vendor will not update it; a Critical on a server reachable from the internet.',
        keywords: hosted
          ? lowered([`${HEAD_HOST} is vendor-hosted`, `${HEAD_HOST} is saas`, `${HEAD_HOST} is a saas`, `${HEAD_HOST} is hosted`, `${HEAD_HOST} is operated by`, `${HEAD_HOST} is run by the vendor`, 'ticketing service is hosted', 'ticketing service is vendor', 'ticketing service is saas', 'ticketing service is operated', 'ticketing service is run by the vendor', 'ticketing system is hosted', 'ticketing system is vendor', 'ticketing system is saas', 'helpdesk is saas', 'helpdesk is hosted', 'helpdesk is vendor', 'vendor hosted ticketing', 'saas ticketing', 'vendor operates the ticketing', 'we do not run the ticketing', 'we do not run the helpdesk', 'we do not manage the ticketing', 'vendor runs the ticketing', 'vendor operated ticketing', 'hosted ticketing service', 'ticketing is hosted', 'ticketing is vendor hosted', 'vendor hosts the ticketing', 'vendor installs the fixes itself', 'vendor installs the update itself', 'vendor installs the fixes on the hosted', 'vendor installs the update on the hosted'])
          : lowered(['ticketing server is self-managed', 'ticketing server is self managed', 'ticketing server is self-hosted', 'ticketing server is ours', 'ticketing server is installed and run by it', 'ticketing server is run by it', 'it installed and runs the ticketing', 'it installed the ticketing', 'it runs the ticketing', 'it manages the ticketing', 'our ticketing server', 'our own ticketing server', 'we run the ticketing', 'we installed and run the ticketing', 'run the ticketing server ourselves', 'run this instance ourselves', 'we installed it ourselves', 'installed it ourselves', 'we installed the ticketing', 'no vendor update', 'vendor does not update', 'vendor does not patch', 'vendor will not patch', `${HEAD_HOST} is self-managed`, `${HEAD_HOST} is self-hosted`, `${HEAD_HOST} is ours`, `we run ${HEAD_HOST}`, 'vendor will not update']),
      },
      {
        id: 'action',
        text: hosted ? `Records transfer for the hosted ticketing service and the second hosted service (track the vendor's date, ask for its written confirmation, no scanning or testing of its platform) and patches the contract-covered server on ${APP} in the next window.` : `Patches the ticketing server by emergency change, records transfer for the hosted dashboards service and patches the contract-covered server on ${APP} in the next window.`,
        keywords: hosted
          ? lowered(HEAD_ACTIONS)
          : lowered(KW_EMERGENCY),
      },
      {
        id: 'date',
        text: hosted ? "Gives dates, not just \"soon\": the deadline of each urgent finding, the vendor's committed fix date, and the window or cycle each goes in, tied to the policy." : 'Gives dates, not just "soon": the deadline of each urgent finding and the window or cycle it goes in, tied to the policy.',
        keywords: dateRubricKeywords(cal, [critDeadline, f2Deadline, f4Deadline, committed], [7, 30]),
      },
    ],
    explanation: hosted
      ? [
          `The headline is a Critical (7 days from first detection ${firstAgo} days ago, due ${ymd(critDeadline)}, end of day) in a third-party ticketing product, read from the version string of our own public hostname by the external run. The deciding clue is who operates the system. DeviceInfo shows ${HEAD_HOST} is a service hosted by ${HEAD_VENDOR} that IT does not manage (IsManaged false, OSPlatform "${VENDOR_OS}"), and Tickets holds the subscription agreement: the vendor hosts it and installs the fixes; IT has no access to the servers. The vendor's advisory commits to update every hosted tenant by ${ymd(committed)}, before our deadline. The policy row on vendor-operated services says what to do: record transfer (no change of ours, no schedule), track that date, close the finding on the vendor's written confirmation, and never scan or test the vendor's platform (many SaaS terms forbid it or restrict it to published rules or the vendor's written permission). Transfer moves the fix, not the accountability for our data: until the vendor confirms, keep the finding open and tracked, and escalate if the committed date slips.`,
          `The twin has the same flaw, the same advisory and the same host name, but there DeviceInfo shows an IT-managed server and Tickets holds an installation record: IT runs it, the advisory's committed date is for hosted tenants, and the update is ours to apply (patch, emergency change). "Vendor product, so the vendor's problem" and "every finding is ours to patch" are both wrong somewhere in this pair.`,
          `The decoys: a support contract in Tickets for ${f2Entry.product} on ${APP}, but IT installed and runs that product, so a contract transfers nothing: patch it (High, first detected ${Math.round((now - f2First) / DAY)} days ago, due ${ymd(f2Deadline)}: the next window). ${SAAS_HOST} is a second vendor-hosted service: transfer, with the vendor's date in its own advisory. The High on ${BUILD} (due ${ymd(f4Deadline)}) goes in the standard cycle and the Low is standard cycle too.`,
        ]
      : [
          `The headline is a Critical (7 days from first detection ${firstAgo} days ago, due ${ymd(critDeadline)}, end of day) in a third-party ticketing product, read from the version string of our own public hostname by the external run. The deciding clue is who operates the system. DeviceInfo shows ${HEAD_HOST} is a server IT manages (IsManaged true, ${HEAD_PRODUCT} self-managed edition, in the DMZ) and Tickets holds the installation record: IT installed it, runs it and applies its updates; SoftwareInventory shows ${headVersion}, below the fixed release ${head.fixedVersion}. The vendor's advisory says hosted tenants are updated by the vendor, but for the self-managed edition the vendor does not update customer-run servers, so the committed date does not help us. The update is ours to apply, and the Critical deadline (${ymd(critDeadline)}) falls before the next window (${ymd(cal.next.start)}): patch by emergency change.`,
          `The twin has the same flaw, the same advisory and the same host name, but there DeviceInfo shows a vendor-hosted service IT does not manage and Tickets holds the subscription agreement: the vendor operates and fixes it, so the answer is transfer (track the vendor's date, verify on its confirmation). "Every finding is ours to patch" is the misconception; so is "a vendor is involved, so it is the vendor's problem".`,
          `The decoys: a support contract in Tickets for ${f2Entry.product} on ${APP}, but IT installed and runs that product, so a contract transfers nothing: patch it (High, due ${ymd(f2Deadline)}: the next window, which with the emergency change fills its capacity of two). ${SAAS_HOST} is a vendor-hosted service: transfer, with the vendor's date in its own advisory. The High on ${BUILD} (due ${ymd(f4Deadline)}) goes in the standard cycle and the Low is standard cycle too.`,
        ],
    pitfalls: hosted
      ? [
          'Patching the headline: IT cannot patch a service the vendor hosts and operates; the finding is recorded as transfer, tracked and verified.',
          'Scanning or testing the vendor\'s platform to "verify" the fix: many SaaS terms forbid it or restrict it to published rules or the vendor\'s written permission; wait for its confirmation (a non-intrusive read of the version string an ordinary request to our own hostname returns is the only check we make).',
          'Reading a vendor support contract as a transfer: the support contract on the application server only means the vendor answers calls; IT installed and runs that product, so patch it.',
          'Treating transfer as "done": the finding stays open until the vendor confirms the fix by its committed date; escalate if the date passes.',
          'Scheduling an emergency change for a finding whose fix is not ours to make.',
        ]
      : [
          'Transferring the headline because a vendor advisory promises a fix: the committed date is for the vendor\'s hosted tenants; IT runs this install and the vendor does not update customer-run servers.',
          'Reading the vendor as responsible without checking who operates the system: DeviceInfo and the installation record in Tickets show IT does.',
          'Scheduling the Critical in the next window or later: its 7-day deadline ends before the next window.',
          'Treating the vendor support contract on the application server as a transfer: IT installed and runs that product, so patch it.',
          'Patching the vendor-hosted dashboards service: the vendor operates it; record transfer and track its date.',
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

export const saasTransfer: VulnTemplate = {
  ...COMMON,
  id: 'vm-saas-transfer',
  twin: 'vm-self-hosted',
  lesson:
    "DeviceInfo shows the headline system is a vendor-hosted service IT does not manage, and Tickets holds the subscription agreement and the vendor's advisory with its committed fix date: the vendor operates and fixes it, so record transfer, track the date and verify on the vendor's confirmation (never scan or test the vendor's platform). The twin has the same flaw, but DeviceInfo shows an IT-managed server and Tickets an installation record: it is ours to patch.",
  build: (ctx) => build('transfer', ctx),
};

export const selfHosted: VulnTemplate = {
  ...COMMON,
  id: 'vm-self-hosted',
  twin: 'vm-saas-transfer',
  lesson:
    "DeviceInfo shows the headline system is a server IT installed and runs, and Tickets holds the installation record (the vendor's committed date in the advisory is for hosted tenants): the vendor's update is ours to apply, so patch it by emergency change (a Critical, 7 days). The twin has the same flaw on a vendor-hosted service, where the answer is transfer.",
  build: (ctx) => build('self', ctx),
};
