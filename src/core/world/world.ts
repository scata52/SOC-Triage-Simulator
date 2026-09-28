// The persistent organisation. A profile stores only the world seed; the world
// is regenerated deterministically on load. People, devices, servers, network
// egress points and the org's internet footprint all live here so that cases
// and shifts share one consistent environment.

import { createRng, type Rng } from '../rng.ts';
import { ExternalAllocator, InternalAllocator, SUBNETS } from '../synth/addresses.ts';
import { CITIES, EUROPEAN_HQ_CODES, geoEntry, type GeoCity, type GeoEntry, type NetworkKind, networkName } from '../synth/geo.ts';
import { asciiFold, FIRST_NAMES, LAST_NAMES } from '../synth/names.ts';
import { FICTITIOUS_ORGS, type FictitiousOrg } from '../synth/orgs.ts';
import { BULK_SENDERS, benignServices, type ExternalService } from '../synth/domains.ts';

export const WORLD_VERSION = 1;

export type Department =
  | 'Executive'
  | 'Finance'
  | 'Sales'
  | 'Marketing'
  | 'Engineering'
  | 'IT'
  | 'Helpdesk'
  | 'HR'
  | 'Legal'
  | 'Operations'
  | 'Security';

export const DEPT_CODE: Record<Department, string> = {
  Executive: 'EXE',
  Finance: 'FIN',
  Sales: 'SAL',
  Marketing: 'MKT',
  Engineering: 'ENG',
  IT: 'ITS',
  Helpdesk: 'HLP',
  HR: 'HRS',
  Legal: 'LEG',
  Operations: 'OPS',
  Security: 'SEC',
};

export type MfaMethod = 'Push notification' | 'Number matching' | 'FIDO2 security key';

export interface Site {
  id: string;
  name: string;
  city: GeoCity;
  prefix: string; // "10.24"
  natIp: string; // office internet egress
}

export interface Person {
  id: string;
  first: string;
  last: string;
  display: string;
  sam: string;
  upn: string;
  department: Department;
  title: string;
  managerId: string | null;
  siteId: string;
  remoteShare: number; // probability of working from home on a given day
  fieldSales: boolean;
  homeIp: string;
  laptop: string;
  mobileDevice: string | null;
  groups: string[];
  adminAccount: string | null; // separate tier-0 account for IT admins
  mfaMethod: MfaMethod;
  hired: string; // ISO date
  workStart: number; // local hour
  workEnd: number;
}

export type HostKind = 'laptop' | 'desktop' | 'server' | 'appliance' | 'mobile';
export type Criticality = 'Low' | 'Medium' | 'High' | 'Critical';

export interface Host {
  name: string;
  ip: string; // '' for mobiles
  kind: HostKind;
  os: string;
  role: string;
  criticality: Criticality;
  owner: string; // upn or team name
  siteId: string;
  deviceId: string;
  exposed: boolean; // reachable from the internet
  managed: boolean;
}

export interface ServiceAccount {
  name: string;
  purpose: string;
  owner: string;
  hosts: string[];
}

export interface VpnEgress {
  name: string;
  ip: string;
  city: GeoCity;
}

export interface Partner {
  org: FictitiousOrg;
  relationship: string;
  contacts: string[]; // email addresses
  mailIp: string;
}

export interface World {
  version: number;
  seed: string;
  org: FictitiousOrg & { netbios: string; tenant: string; adFqdn: string; utcOffset: number };
  sites: Site[];
  vpn: { egress: VpnEgress[]; poolCidr: string };
  people: Person[];
  hosts: Host[];
  serviceAccounts: ServiceAccount[];
  services: ExternalService[];
  serviceIps: Record<string, string[]>;
  bulkSenderIps: Record<string, string>;
  partners: Partner[];
  publicIps: { web: string; vpn: string };
  internet: {
    scanners: string[];
    tor: string[];
    hosting: string[];
    carriers: string[];
    hotels: string[];
  };
  geo: Record<string, GeoEntry>;
  reservedExternal: string[];
}

interface DeptPlan {
  dept: Department;
  count: [number, number];
  head: string;
  titles: string[];
}

const DEPT_PLAN: DeptPlan[] = [
  { dept: 'Executive', count: [3, 4], head: 'Chief Executive Officer', titles: ['Chief Financial Officer', 'Chief Operating Officer', 'Chief Technology Officer'] },
  { dept: 'Finance', count: [7, 9], head: 'Finance Director', titles: ['Accountant', 'Accounts Payable Clerk', 'Financial Controller', 'Payroll Specialist', 'Treasury Analyst'] },
  { dept: 'Sales', count: [9, 12], head: 'Sales Director', titles: ['Account Executive', 'Account Executive', 'Key Account Manager', 'Sales Operations Analyst', 'Inside Sales Representative'] },
  { dept: 'Marketing', count: [4, 5], head: 'Head of Marketing', titles: ['Content Marketing Manager', 'Marketing Coordinator', 'Brand Designer', 'Events Manager'] },
  { dept: 'Engineering', count: [11, 14], head: 'VP Engineering', titles: ['Software Engineer', 'Software Engineer', 'Senior Software Engineer', 'DevOps Engineer', 'QA Engineer', 'Engineering Manager'] },
  { dept: 'IT', count: [4, 5], head: 'IT Manager', titles: ['Systems Administrator', 'Systems Administrator', 'Endpoint Engineer', 'Network Engineer'] },
  { dept: 'Helpdesk', count: [3, 3], head: 'Service Desk Lead', titles: ['Service Desk Analyst'] },
  { dept: 'HR', count: [3, 4], head: 'HR Director', titles: ['HR Business Partner', 'Recruiter', 'HR Coordinator'] },
  { dept: 'Legal', count: [2, 2], head: 'General Counsel', titles: ['Legal Counsel'] },
  { dept: 'Operations', count: [6, 9], head: 'Operations Manager', titles: ['Logistics Coordinator', 'Procurement Specialist', 'Facilities Coordinator', 'Supply Chain Analyst'] },
  { dept: 'Security', count: [3, 3], head: 'Security Operations Lead', titles: ['SOC Analyst', 'Vulnerability Management Engineer'] },
];

const DEPT_GROUP: Record<Department, string> = {
  Executive: 'SG-Executives',
  Finance: 'SG-Finance',
  Sales: 'SG-Sales',
  Marketing: 'SG-Marketing',
  Engineering: 'SG-Engineering',
  IT: 'SG-IT',
  Helpdesk: 'SG-ServiceDesk',
  HR: 'SG-HR',
  Legal: 'SG-Legal',
  Operations: 'SG-Operations',
  Security: 'SG-Security',
};

function guid(rng: Rng): string {
  return `${rng.hex(8)}-${rng.hex(4)}-4${rng.hex(3)}-${rng.pick(['8', '9', 'a', 'b'])}${rng.hex(3)}-${rng.hex(12)}`;
}

function isoDate(year: number, month: number, day: number): string {
  return new Date(Date.UTC(year, month - 1, day)).toISOString().slice(0, 10);
}

export function generateWorld(seed: string): World {
  const root = createRng(`world:${seed}`);
  const rng = root.fork('core');
  const ext = new ExternalAllocator();
  const geo: Record<string, GeoEntry> = {};

  const allocExt = (r: Rng, city: GeoCity, kind: NetworkKind, network?: string, asn?: number): string => {
    const ip = ext.v4(r);
    geo[ip] = geoEntry(r, city, kind, network, asn);
    return ip;
  };

  // ---- organisation and sites -------------------------------------------
  const base = rng.pick(FICTITIOUS_ORGS);
  const europe = CITIES.filter((c) => EUROPEAN_HQ_CODES.includes(c.cc));
  const hqCity = rng.pick(europe);
  const branchCity = rng.pick(europe.filter((c) => c.city !== hqCity.city));
  const b = rng.int(16, 60) & ~1; // even second octet; branch takes the next one
  const orgNet = networkName(rng, 'corporate');
  const orgAsn = rng.int(64512, 65534);

  const org = {
    ...base,
    netbios: base.short.toUpperCase().slice(0, 15),
    tenant: base.short.toLowerCase(),
    adFqdn: `corp.${base.domain}`,
    utcOffset: hqCity.utcOffset,
  };

  const sites: Site[] = [
    { id: 'hq', name: `${hqCity.city} HQ`, city: hqCity, prefix: `10.${b}`, natIp: allocExt(rng, hqCity, 'corporate', orgNet, orgAsn) },
    { id: 'branch', name: `${branchCity.city} office`, city: branchCity, prefix: `10.${b + 1}`, natIp: allocExt(rng, branchCity, 'corporate', orgNet, orgAsn) },
  ];
  const internal: Record<string, InternalAllocator> = {
    hq: new InternalAllocator(sites[0].prefix),
    branch: new InternalAllocator(sites[1].prefix),
  };

  // The second VPN egress sits in a different city on purpose: it is what
  // makes "atypical travel" alerts fire on staff who never left the office.
  const vpnCity = rng.pick(europe.filter((c) => c.city !== hqCity.city && c.city !== branchCity.city));
  const vpn = {
    egress: [
      { name: `VPN egress — ${hqCity.city}`, ip: allocExt(rng, hqCity, 'corporate', orgNet, orgAsn), city: hqCity },
      { name: `VPN egress — ${vpnCity.city} (cloud gateway)`, ip: allocExt(rng, vpnCity, 'hosting', orgNet, orgAsn), city: vpnCity },
    ],
    poolCidr: `${sites[0].prefix}.${SUBNETS.vpnPoolFrom}.0/22`,
  };

  // ---- people --------------------------------------------------------------
  const pr = root.fork('people');
  const people: Person[] = [];
  const usedSam = new Set<string>();
  const usedNames = new Set<string>();
  let seq = 0;
  const hosts: Host[] = [];
  const deptCounters: Record<string, number> = {};

  const nextHostName = (prefix: string, dept: Department): string => {
    const key = `${prefix}-${dept}`;
    deptCounters[key] = (deptCounters[key] ?? pr.int(3, 40)) + pr.int(1, 7);
    return `${prefix}-${DEPT_CODE[dept]}-${String(deptCounters[key]).padStart(3, '0')}`;
  };

  let ceoId: string | null = null;
  for (const plan of DEPT_PLAN) {
    const count = pr.int(plan.count[0], plan.count[1]);
    let headId: string | null = null;
    for (let i = 0; i < count; i++) {
      let first = '';
      let last = '';
      for (let attempt = 0; attempt < 50; attempt++) {
        first = pr.pick(FIRST_NAMES);
        last = pr.pick(LAST_NAMES);
        if (!usedNames.has(`${first} ${last}`)) break;
      }
      usedNames.add(`${first} ${last}`);
      let sam = `${asciiFold(first)}.${asciiFold(last)}`;
      for (let n = 2; usedSam.has(sam); n++) sam = `${asciiFold(first)}.${asciiFold(last)}${n}`;
      usedSam.add(sam);

      const isHead = i === 0;
      const title = isHead ? plan.head : pr.pick(plan.titles);
      const fieldSales = plan.dept === 'Sales' && /Account|Key/.test(title);
      const siteId = plan.dept === 'Executive' || plan.dept === 'Security' ? 'hq' : pr.bool(0.72) ? 'hq' : 'branch';
      const site = sites.find((s) => s.id === siteId)!;
      const id = `p${String(++seq).padStart(3, '0')}`;
      const kind: HostKind = plan.dept === 'Engineering' && pr.bool(0.3) ? 'desktop' : 'laptop';
      const laptop = nextHostName(kind === 'desktop' ? 'WS' : 'LT', plan.dept);
      const initials = `${first[0]}${last[0]}`.toUpperCase();
      const mobileDevice = pr.bool(0.8) ? `${pr.pick(['iPhone', 'Pixel', 'Galaxy'])}-${initials}${pr.int(10, 99)}` : null;
      const isAdmin = plan.dept === 'IT' && /Systems Administrator|IT Manager/.test(title);
      const groups = ['SG-AllStaff', DEPT_GROUP[plan.dept]];
      if (plan.dept === 'Helpdesk') groups.push('Helpdesk Operators');
      if (plan.dept === 'Finance') groups.push('DL-Finance');
      if (plan.dept === 'Security') groups.push('SG-SOC');
      if (fieldSales) groups.push('SG-FieldSales');
      if (plan.dept === 'Engineering') groups.push('SG-Developers');

      const person: Person = {
        id,
        first,
        last,
        display: `${first} ${last}`,
        sam,
        upn: `${sam}@${org.domain}`,
        department: plan.dept,
        title,
        managerId: isHead ? (plan.dept === 'Executive' ? null : ceoId) : headId,
        siteId,
        remoteShare: fieldSales ? 0.6 : plan.dept === 'Engineering' ? 0.5 : pr.float(0.1, 0.4),
        fieldSales,
        homeIp: allocExt(pr, site.city, 'residential'),
        laptop,
        mobileDevice,
        groups,
        adminAccount: isAdmin ? `adm-${sam.replace('.', '')}`.slice(0, 20) : null,
        mfaMethod: plan.dept === 'IT' || plan.dept === 'Security' ? 'FIDO2 security key' : pr.bool(0.55) ? 'Number matching' : 'Push notification',
        hired: isoDate(pr.int(2012, 2026), pr.int(1, 12), pr.int(1, 28)),
        workStart: pr.int(7, 9),
        workEnd: pr.int(16, 18),
      };
      // Keep hire dates in the past relative to the simulated season.
      if (person.hired > '2026-08-01') person.hired = isoDate(pr.int(2015, 2025), pr.int(1, 12), pr.int(1, 28));
      if (isHead) headId = id;
      if (plan.dept === 'Executive' && isHead) ceoId = id;
      people.push(person);

      hosts.push({
        name: laptop,
        ip: internal[siteId].workstation(pr),
        kind,
        os: kind === 'desktop' && plan.dept === 'Engineering' && pr.bool(0.3) ? 'Ubuntu 24.04' : 'Windows 11 Enterprise',
        role: kind === 'desktop' ? 'Workstation' : 'Laptop',
        criticality: plan.dept === 'Executive' || plan.dept === 'Finance' ? 'High' : 'Medium',
        owner: person.upn,
        siteId,
        deviceId: guid(pr),
        exposed: false,
        managed: true,
      });
      if (mobileDevice) {
        hosts.push({
          name: mobileDevice,
          ip: '',
          kind: 'mobile',
          os: mobileDevice.startsWith('iPhone') ? 'iOS 19' : 'Android 16',
          role: 'Mobile phone',
          criticality: 'Low',
          owner: person.upn,
          siteId,
          deviceId: guid(pr),
          exposed: false,
          managed: pr.bool(0.85),
        });
      }
    }
  }

  // Domain Admins: the IT admins' separate tier-0 accounts.
  for (const p of people) {
    if (p.adminAccount) p.groups.push('Tier0-Admins (via adm account)');
  }

  // ---- servers and appliances ----------------------------------------------
  const sr = root.fork('servers');
  const itOwner = 'IT Infrastructure';
  const server = (name: string, role: string, criticality: Criticality, subnet: number, os = 'Windows Server 2022', siteId = 'hq', exposed = false): Host => ({
    name,
    ip: internal[siteId].inSubnet(sr, subnet),
    kind: 'server',
    os,
    role,
    criticality,
    owner: itOwner,
    siteId,
    deviceId: guid(sr),
    exposed,
    managed: true,
  });
  hosts.push(
    server('DC01', 'Domain controller', 'Critical', SUBNETS.servers),
    server('DC02', 'Domain controller', 'Critical', SUBNETS.servers),
    server('FS01', 'File server (departmental shares)', 'High', SUBNETS.servers),
    server('FS02', 'File server (branch shares)', 'High', SUBNETS.servers, 'Windows Server 2022', 'branch'),
    server('SCCM01', 'Endpoint management (software deployment)', 'High', SUBNETS.mgmt),
    { ...server('SCAN01', 'Vulnerability scanner (authorised)', 'Medium', SUBNETS.mgmt, 'Rocky Linux 9'), owner: 'Security — Vulnerability Management' },
    server('JUMP01', 'RDP jump host (admin access)', 'High', SUBNETS.servers),
    server('SQL01', 'Database server (ERP)', 'High', SUBNETS.servers),
    server('APP01', 'Line-of-business application server', 'Medium', SUBNETS.servers),
    server('WEB01', 'Public website', 'Medium', SUBNETS.dmz, 'Ubuntu 24.04', 'hq', true),
    server('BKP01', 'Backup server', 'Critical', SUBNETS.servers),
    server('PRINT01', 'Print server', 'Low', SUBNETS.servers),
    server('BUILD01', 'CI build server', 'Medium', SUBNETS.servers, 'Ubuntu 24.04'),
    server('ADCONNECT01', 'Entra Connect sync server', 'Critical', SUBNETS.servers),
    { ...server('FW01', 'Perimeter firewall', 'Critical', SUBNETS.mgmt, 'Firewall OS'), kind: 'appliance' },
    { ...server('VPN01', 'VPN concentrator', 'High', SUBNETS.mgmt, 'VPN appliance OS'), kind: 'appliance', exposed: true },
    { ...server('PROXY01', 'Web proxy', 'High', SUBNETS.mgmt, 'Proxy appliance OS'), kind: 'appliance' },
  );

  const serviceAccounts: ServiceAccount[] = [
    { name: 'svc-backup', purpose: 'Nightly backup jobs', owner: itOwner, hosts: ['BKP01', 'FS01', 'FS02', 'SQL01'] },
    { name: 'svc-sccm', purpose: 'Software deployment and remote administration', owner: itOwner, hosts: ['SCCM01'] },
    { name: 'svc-scan', purpose: 'Credentialed vulnerability scanning (read-only)', owner: 'Security — Vulnerability Management', hosts: ['SCAN01'] },
    { name: 'svc-sql', purpose: 'ERP database engine', owner: itOwner, hosts: ['SQL01'] },
    { name: 'svc-web', purpose: 'Public website application pool', owner: 'Marketing', hosts: ['WEB01'] },
    { name: 'svc-print', purpose: 'Print spooler integration', owner: itOwner, hosts: ['PRINT01'] },
    { name: 'svc-build', purpose: 'CI pipelines', owner: 'Engineering', hosts: ['BUILD01'] },
    { name: 'svc-adsync', purpose: 'Directory synchronisation to Entra ID', owner: itOwner, hosts: ['ADCONNECT01'] },
    { name: 'svc-monitor', purpose: 'Infrastructure monitoring agent', owner: itOwner, hosts: ['APP01'] },
  ];

  // ---- internet footprint --------------------------------------------------
  const nr = root.fork('internet');
  const hostingCities = ['Ashburn', 'Amsterdam', 'Frankfurt', 'Dublin', 'Singapore', 'San Francisco'].map((c) => CITIES.find((x) => x.city === c)!);
  const services = benignServices(org.tenant);
  const serviceIps: Record<string, string[]> = {};
  for (const s of services) {
    const city = nr.pick(hostingCities);
    const net = networkName(nr, 'hosting');
    const asn = nr.int(64512, 65534);
    serviceIps[s.domain] = Array.from({ length: nr.int(1, 2) }, () => allocExt(nr, city, 'hosting', net, asn));
  }
  const bulkSenderIps: Record<string, string> = {};
  for (const bs of BULK_SENDERS) bulkSenderIps[bs.from] = allocExt(nr, nr.pick(hostingCities), 'hosting');

  const partnerOrgs = nr.sample(FICTITIOUS_ORGS.filter((o) => o.domain !== org.domain), 4);
  const relationships = ['Supplier', 'Customer', 'External counsel', 'Logistics partner'];
  const partners: Partner[] = partnerOrgs.map((po, i) => ({
    org: po,
    relationship: relationships[i],
    contacts: Array.from({ length: nr.int(2, 3) }, () => `${asciiFold(nr.pick(FIRST_NAMES))}.${asciiFold(nr.pick(LAST_NAMES))}@${po.domain}`),
    mailIp: allocExt(nr, nr.pick(europe), 'corporate'),
  }));

  const publicIps = { web: allocExt(nr, hqCity, 'corporate', orgNet, orgAsn), vpn: vpn.egress[0].ip };
  const anyCity = () => nr.pick(CITIES);
  const internet = {
    scanners: Array.from({ length: 24 }, () => allocExt(nr, anyCity(), 'hosting')),
    tor: Array.from({ length: 6 }, () => allocExt(nr, anyCity(), 'anonymizer')),
    hosting: Array.from({ length: 16 }, () => allocExt(nr, anyCity(), 'hosting')),
    carriers: Array.from({ length: 6 }, () => allocExt(nr, nr.bool(0.7) ? hqCity : branchCity, 'mobile')),
    hotels: Array.from({ length: 8 }, () => allocExt(nr, anyCity(), 'residential', `${nr.pick(['Grand', 'Park', 'Central', 'Harbour'])} Hotel Guest WiFi`)),
  };

  return {
    version: WORLD_VERSION,
    seed,
    org,
    sites,
    vpn,
    people,
    hosts,
    serviceAccounts,
    services,
    serviceIps,
    bulkSenderIps,
    partners,
    publicIps,
    internet,
    geo,
    reservedExternal: ext.reserved(),
  };
}
