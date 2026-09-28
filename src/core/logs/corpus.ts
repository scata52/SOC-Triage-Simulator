// CorpusBuilder: the one place log rows are written. Noise generators and case
// templates both emit through it. Signal rows are identified by RowRef handles
// held by the case spec — never by anything stored in the data — so no query
// can tell signal from noise.

import type { Rng } from '../rng.ts';
import type { World } from '../world/world.ts';
import { WorldIndex } from '../world/index.ts';
import { ExternalAllocator } from '../synth/addresses.ts';
import { geoEntry, type GeoCity, type GeoEntry, type NetworkKind } from '../synth/geo.ts';
import { registeredDomain, registrar } from '../synth/domains.ts';
import { SCHEMA, TABLE_NAMES, type Cell, type RowInput, type TableName, tableInfo } from './schema.ts';
import { DAY, iso } from './time.ts';

type RowObject = Record<string, string | number | boolean | null | undefined>;

export interface RowRef<T extends TableName = TableName> {
  readonly table: T;
  readonly row: RowObject;
}

export interface CorpusTable {
  columns: string[];
  rows: Cell[][];
}

export interface Corpus {
  now: string;
  windowStart: string;
  windowEnd: string;
  tables: Record<TableName, CorpusTable>;
  rowCount: number;
}

export interface DomainIntelInfo {
  ageDays: number;
  category: string;
  reputation: 'Good' | 'Neutral' | 'Suspicious' | 'Malicious' | 'Unknown';
  registrar?: string;
}

export interface BuilderOptions {
  world: World;
  rng: Rng;
  windowStart: number;
  windowEnd: number;
  now: number;
  reservedExternal?: Iterable<string>; // e.g. campaign infrastructure
}

export class CorpusBuilder {
  readonly world: World;
  readonly idx: WorldIndex;
  readonly rng: Rng;
  readonly windowStart: number;
  readonly windowEnd: number;
  readonly now: number;
  readonly ext: ExternalAllocator;
  readonly geo: Record<string, GeoEntry>;

  private data = Object.fromEntries(TABLE_NAMES.map((t) => [t, [] as RowObject[]])) as Record<TableName, RowObject[]>;
  private dnsMap = new Map<string, string[]>();
  private domainIntel = new Map<string, DomainIntelInfo>();
  private identityRows = new Map<string, RowObject>();
  private deviceRows = new Map<string, RowObject>();
  private namedRows = new Map<string, RowObject>();
  private domainRows = new Map<string, RowObject>();
  private finalized = false;
  private ticketSeq: Record<string, number>;

  constructor(opts: BuilderOptions) {
    this.world = opts.world;
    this.idx = new WorldIndex(opts.world);
    this.rng = opts.rng;
    this.windowStart = opts.windowStart;
    this.windowEnd = opts.windowEnd;
    this.now = opts.now;
    this.ext = new ExternalAllocator([...opts.world.reservedExternal, ...(opts.reservedExternal ?? [])]);
    this.geo = { ...opts.world.geo };
    for (const [domain, ips] of Object.entries(opts.world.serviceIps)) this.dnsMap.set(domain, ips);
    const tr = opts.rng.fork('ticket-ids');
    this.ticketSeq = { CHG: 10000 + tr.int(100, 900), REQ: 20000 + tr.int(100, 900), TRV: 30000 + tr.int(10, 90), HR: 40000 + tr.int(10, 90), INC: 50000 + tr.int(10, 90) };
    this.initContextRows();
  }

  // Unique, increasing ticket numbers shared by noise and case templates.
  nextTicketId(prefix: 'CHG' | 'REQ' | 'TRV' | 'HR' | 'INC'): string {
    this.ticketSeq[prefix] += 1 + (this.ticketSeq[prefix] % 7);
    return `${prefix}-${this.ticketSeq[prefix]}`;
  }

  // ---------------------------------------------------------------- writing
  add<T extends TableName>(table: T, row: RowInput<T>): RowRef<T> {
    if (this.finalized) throw new Error('CorpusBuilder already finalised');
    const obj = { ...(row as RowObject) };
    this.data[table].push(obj);
    return { table, row: obj };
  }

  signin(r: RowInput<'SigninLogs'>): RowRef<'SigninLogs'> {
    const row = { ...r };
    if (row.IPAddress && (row.City == null || row.CountryOrRegion == null || row.AutonomousSystemNumber == null)) {
      const g = this.geo[row.IPAddress];
      if (g) {
        row.City ??= g.city;
        row.CountryOrRegion ??= g.cc;
        row.AutonomousSystemNumber ??= g.asn;
      }
    }
    if (row.UserPrincipalName && row.UserDisplayName == null) {
      row.UserDisplayName = this.idx.personByUpn(row.UserPrincipalName)?.display ?? row.UserPrincipalName.split('@')[0];
    }
    row.ResultDescription ??= resultDescription(row.ResultType ?? 0);
    return this.add('SigninLogs', row);
  }

  audit(r: RowInput<'AuditLogs'>) {
    return this.add('AuditLogs', { Result: 'success', ...r });
  }

  sec(r: RowInput<'SecurityEvent'>) {
    const row = { ...r };
    if (row.EventID != null) row.Activity ??= securityActivity(row.EventID);
    return this.add('SecurityEvent', row);
  }

  proc(r: RowInput<'DeviceProcessEvents'>) {
    const row = { ...r };
    if (row.FolderPath && row.FileName == null) row.FileName = row.FolderPath.split('\\').pop() ?? row.FolderPath;
    return this.add('DeviceProcessEvents', row);
  }

  net(r: RowInput<'DeviceNetworkEvents'>) {
    return this.add('DeviceNetworkEvents', { ActionType: 'ConnectionSuccess', Protocol: 'Tcp', ...r });
  }

  file(r: RowInput<'DeviceFileEvents'>) {
    return this.add('DeviceFileEvents', r);
  }

  email(r: RowInput<'EmailEvents'>) {
    const row = { ...r };
    if (row.SenderFromAddress && row.SenderFromDomain == null) row.SenderFromDomain = row.SenderFromAddress.split('@')[1];
    return this.add('EmailEvents', row);
  }

  proxy(r: RowInput<'WebProxy'>) {
    const row = { ...r };
    if (row.Url && row.DestinationHost == null) row.DestinationHost = hostOfUrl(row.Url);
    if (row.DestinationHost && row.DestinationIP == null) row.DestinationIP = this.resolve(row.DestinationHost);
    if (row.DestinationPort == null) row.DestinationPort = row.Url?.startsWith('http://') ? 80 : 443;
    return this.add('WebProxy', { Action: 'Allowed', ...row });
  }

  dns(r: RowInput<'DnsEvents'>) {
    const row = { ...r };
    if (row.Name && row.Domain == null) row.Domain = registeredDomain(row.Name);
    if (row.Name && row.IPAddresses == null && (row.QueryType ?? 'A') === 'A') row.IPAddresses = this.resolveAll(row.Name).join(',');
    return this.add('DnsEvents', { QueryType: 'A', ResponseCode: 'NOERROR', ...row });
  }

  fw(r: RowInput<'FirewallLogs'>) {
    return this.add('FirewallLogs', { DeviceName: 'FW01', Protocol: 'TCP', ...r });
  }

  alert(r: RowInput<'SecurityAlert'>) {
    return this.add('SecurityAlert', { Status: 'New', ...r });
  }

  ticket(r: RowInput<'Tickets'>) {
    return this.add('Tickets', r);
  }

  intel(r: RowInput<'ThreatIntel'>) {
    return this.add('ThreatIntel', r);
  }

  incident(r: RowInput<'IncidentHistory'>) {
    return this.add('IncidentHistory', r);
  }

  // Case-specific facts layered over the world's directory / CMDB rows.
  patchIdentity(upnOrSam: string, patch: RowInput<'IdentityInfo'>): RowRef<'IdentityInfo'> {
    const ref = this.identityRef(upnOrSam);
    Object.assign(ref.row, patch);
    return ref;
  }

  patchDevice(name: string, patch: RowInput<'DeviceInfo'>): RowRef<'DeviceInfo'> {
    const ref = this.deviceRef(name);
    Object.assign(ref.row, patch);
    return ref;
  }

  identityRef(upnOrSam: string): RowRef<'IdentityInfo'> {
    const row = this.identityRows.get(upnOrSam.toLowerCase());
    if (!row) throw new Error(`No IdentityInfo row for ${upnOrSam}`);
    return { table: 'IdentityInfo', row };
  }

  deviceRef(name: string): RowRef<'DeviceInfo'> {
    const row = this.deviceRows.get(name.toUpperCase());
    if (!row) throw new Error(`No DeviceInfo row for ${name}`);
    return { table: 'DeviceInfo', row };
  }

  namedLocationRef(ip: string): RowRef<'NamedLocations'> {
    const row = this.namedRows.get(ip);
    if (!row) throw new Error(`No NamedLocations row for ${ip}`);
    return { table: 'NamedLocations', row };
  }

  // The WHOIS/reputation row for a domain (filled in at finalise).
  domainIntelRef(domain: string): RowRef<'DomainIntel'> {
    const d = registeredDomain(domain);
    let row = this.domainRows.get(d);
    if (!row) {
      row = { Domain: d };
      this.domainRows.set(d, row);
      this.data.DomainIntel.push(row);
    }
    return { table: 'DomainIntel', row };
  }

  // Remove noise rows that would contradict a case (e.g. a phone that must
  // not be syncing successfully). Only for use before any RowRef to them.
  drop<T extends TableName>(table: T, predicate: (row: RowObject) => boolean): number {
    const before = this.data[table].length;
    this.data[table] = this.data[table].filter((r) => !predicate(r));
    return before - this.data[table].length;
  }

  // ------------------------------------------------------- infrastructure
  externalIp(kind: NetworkKind, city: GeoCity, network?: string): string {
    const ip = this.ext.v4(this.rng);
    this.geo[ip] = geoEntry(this.rng, city, kind, network);
    return ip;
  }

  // Make a domain resolvable (and give it WHOIS/reputation data).
  registerDomain(host: string, ips: string[], intel?: DomainIntelInfo): void {
    this.dnsMap.set(host.toLowerCase(), ips);
    if (intel) this.setDomainIntel(host, intel);
  }

  setDomainIntel(domain: string, intel: DomainIntelInfo): void {
    this.domainIntel.set(registeredDomain(domain), intel);
    this.domainIntelRef(domain);
  }

  resolveAll(host: string): string[] {
    const h = host.toLowerCase();
    const direct = this.dnsMap.get(h);
    if (direct) return direct;
    const viaParent = this.dnsMap.get(registeredDomain(h));
    return viaParent ?? [];
  }

  resolve(host: string): string {
    return this.resolveAll(host)[0] ?? '';
  }

  count(table?: TableName): number {
    if (table) return this.data[table].length;
    return TABLE_NAMES.reduce((s, t) => s + this.data[t].length, 0);
  }

  // Read-only view for noise generators that correlate across tables.
  rowsOf(table: TableName): readonly RowObject[] {
    return this.data[table];
  }

  // ------------------------------------------------------------- finalise
  finalize(): Corpus {
    if (this.finalized) throw new Error('CorpusBuilder already finalised');
    this.finalized = true;
    this.finalizeDomainIntel();

    const idRng = this.rng.fork('record-ids');
    const usedIds = new Set<string>();
    const nextId = () => {
      for (;;) {
        const id = idRng.alnum(10);
        if (!usedIds.has(id)) {
          usedIds.add(id);
          return id;
        }
      }
    };

    const tables = {} as Record<TableName, CorpusTable>;
    let rowCount = 0;
    for (const name of TABLE_NAMES) {
      const info = tableInfo(name);
      let rows = this.data[name];
      if ('TimeGenerated' in SCHEMA[name].columns) {
        // Logs only exist inside the window: nothing from the future, nothing
        // older than retention. A signal row dropped here never receives a
        // RecordId, so recordIdOf() fails loudly for the template that made it.
        rows = rows.filter((r) => {
          const t = r.TimeGenerated as number;
          return t >= this.windowStart && t <= this.windowEnd;
        });
        rows.sort((a, b) => (a.TimeGenerated as number) - (b.TimeGenerated as number));
      }
      const out: Cell[][] = [];
      for (const r of rows) {
        r.RecordId = nextId();
        out.push(
          info.columns.map((c) => {
            const v = r[c.name];
            // KQL strings are never null — empty string instead.
            if (v === undefined || v === null) return c.type === 'string' ? '' : null;
            if (c.type === 'datetime') return typeof v === 'number' ? iso(v) : String(v);
            if (c.type === 'bool') return v ? 1 : 0;
            if (c.type === 'int' || c.type === 'real') return typeof v === 'number' ? v : Number(v);
            return String(v);
          }),
        );
      }
      tables[name] = { columns: info.columns.map((c) => c.name), rows: out };
      rowCount += out.length;
    }

    return {
      now: iso(this.now),
      windowStart: iso(this.windowStart),
      windowEnd: iso(this.windowEnd),
      tables,
      rowCount,
    };
  }

  private initContextRows(): void {
    const w = this.world;
    const idx = this.idx;
    const ctxRng = this.rng.fork('context');

    // IdentityInfo: people, their admin accounts, and service accounts.
    const addIdentity = (row: RowObject, ...keys: string[]) => {
      this.data.IdentityInfo.push(row);
      for (const k of keys) this.identityRows.set(k.toLowerCase(), row);
    };
    for (const p of w.people) {
      const mgr = idx.manager(p);
      const created = Date.parse(`${p.hired}T09:00:00Z`);
      const pwd = this.now - ctxRng.int(3, 170) * DAY - ctxRng.int(0, 8) * 3_600_000;
      const base: RowObject = {
        AccountUpn: p.upn,
        AccountName: p.sam,
        AccountDisplayName: p.display,
        Department: p.department,
        JobTitle: p.title,
        Manager: mgr?.upn ?? '',
        Office: idx.site(p.siteId).name,
        EmploymentStatus: 'Active',
        AccountCreated: created,
        LastPasswordChange: Math.max(pwd, created),
        Groups: p.groups.join(', '),
        MfaMethod: p.mfaMethod,
        IsPrivileged: false,
        PrimaryDevice: p.laptop,
      };
      addIdentity(base, p.upn, p.sam);
      if (p.adminAccount) {
        addIdentity(
          {
            ...base,
            AccountUpn: `${p.adminAccount}@${w.org.domain}`,
            AccountName: p.adminAccount,
            AccountDisplayName: `${p.display} (admin)`,
            JobTitle: `Tier-0 admin account of ${p.display}`,
            Groups: 'Domain Admins, Tier0-Admins',
            MfaMethod: 'FIDO2 security key',
            IsPrivileged: true,
            PrimaryDevice: 'JUMP01',
          },
          p.adminAccount,
          `${p.adminAccount}@${w.org.domain}`,
        );
      }
    }
    for (const sa of w.serviceAccounts) {
      addIdentity(
        {
          AccountUpn: `${sa.name}@${w.org.domain}`,
          AccountName: sa.name,
          AccountDisplayName: sa.name,
          Department: 'Service account',
          JobTitle: sa.purpose,
          Manager: sa.owner,
          Office: '',
          EmploymentStatus: 'Service account',
          AccountCreated: Date.parse('2021-03-01T10:00:00Z'),
          LastPasswordChange: this.now - ctxRng.int(30, 400) * DAY,
          Groups: sa.name === 'svc-sccm' ? 'SCCM Admins, Workstation Local Admins' : sa.name === 'svc-backup' ? 'Backup Operators' : 'Service Accounts',
          MfaMethod: 'Not applicable',
          IsPrivileged: sa.name === 'svc-sccm' || sa.name === 'svc-backup' || sa.name === 'svc-adsync',
          PrimaryDevice: sa.hosts[0],
        },
        sa.name,
        `${sa.name}@${w.org.domain}`,
      );
    }

    // DeviceInfo: the CMDB.
    for (const h of w.hosts) {
      const row: RowObject = {
        DeviceName: h.name,
        DeviceId: h.deviceId,
        IPAddress: h.ip,
        DeviceType: h.kind === 'laptop' ? 'Laptop' : h.kind === 'desktop' ? 'Workstation' : h.kind === 'server' ? 'Server' : h.kind === 'mobile' ? 'Mobile' : 'Appliance',
        OSPlatform: h.os,
        Role: h.role,
        Owner: h.owner,
        Criticality: h.criticality,
        Site: idx.site(h.siteId).name,
        IsManaged: h.managed,
        ExposedToInternet: h.exposed,
      };
      this.data.DeviceInfo.push(row);
      this.deviceRows.set(h.name.toUpperCase(), row);
    }

    // NamedLocations: office egress and VPN gateways.
    const addNamed = (row: RowObject) => {
      this.data.NamedLocations.push(row);
      this.namedRows.set(String(row.IPAddress), row);
    };
    for (const s of w.sites) addNamed({ Name: `${s.name} internet egress`, IPAddress: s.natIp, Type: 'Office', City: s.city.city, CountryOrRegion: s.city.cc, IsTrusted: true });
    for (const v of w.vpn.egress) addNamed({ Name: v.name, IPAddress: v.ip, Type: 'VPN egress', City: v.city.city, CountryOrRegion: v.city.cc, IsTrusted: true });
  }

  private finalizeDomainIntel(): void {
    const w = this.world;
    const ctxRng = this.rng.fork('domain-intel');
    const add = (host: unknown) => {
      if (typeof host !== 'string' || !host.includes('.')) return;
      const d = registeredDomain(host);
      if (d === w.org.domain || d.endsWith(`.${w.org.domain}`) || /^\d+\.\d+\.\d+\.\d+$/.test(d) || d.endsWith('.local') || d.endsWith('.arpa')) return;
      this.domainIntelRef(d);
    };
    for (const r of this.data.WebProxy) add(r.DestinationHost);
    for (const r of this.data.DnsEvents) add(r.Name);
    for (const r of this.data.DeviceNetworkEvents) add(r.RemoteUrl);
    for (const r of this.data.EmailEvents) {
      add(r.SenderFromDomain);
      add(r.SenderMailFromDomain);
    }
    for (const [d, row] of [...this.domainRows.entries()].sort(([a], [b]) => cmp(a, b))) {
      const known = this.domainIntel.get(d);
      const service = w.services.find((s) => registeredDomain(s.domain) === d);
      const benign = !!service || w.partners.some((p) => p.org.domain === d);
      const info: DomainIntelInfo =
        known ?? (benign ? { ageDays: ctxRng.int(3000, 9500), category: service?.category ?? 'Business', reputation: 'Good' } : { ageDays: ctxRng.int(400, 6000), category: 'Business', reputation: 'Neutral' });
      Object.assign(row, {
        Domain: d,
        RegisteredOn: this.now - info.ageDays * DAY,
        AgeDays: info.ageDays,
        Registrar: info.registrar ?? registrar(ctxRng),
        Category: info.category,
        Reputation: info.reputation,
      });
    }
    this.data.DomainIntel.sort((a, b) => cmp(String(a.Domain), String(b.Domain)));
  }
}

// Code-unit comparison: locale-independent, so every machine builds the same corpus.
export function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function recordIdOf(ref: RowRef): string {
  const id = ref.row.RecordId;
  if (typeof id !== 'string') throw new Error('RowRef read before corpus was finalised');
  return id;
}

export function hostOfUrl(url: string): string {
  const m = /^[a-z]+:\/\/([^/:?#]+)/i.exec(url);
  return m ? m[1].toLowerCase() : url;
}

const RESULT_DESCRIPTIONS: Record<number, string> = {
  0: 'Success',
  50053: 'Account is locked',
  50055: 'Password is expired',
  50057: 'User account is disabled',
  50074: 'Strong Authentication is required',
  50076: 'MFA required due to a configuration change or location',
  50126: 'Invalid username or password',
  50140: 'Keep me signed in interrupt',
  50034: 'User account not found in directory',
  500121: 'Authentication failed during strong authentication request',
  53003: 'Access has been blocked by Conditional Access policies',
  50158: 'External security challenge not satisfied',
  70043: 'Session expired by Conditional Access sign-in frequency',
};

export function resultDescription(code: number): string {
  return RESULT_DESCRIPTIONS[code] ?? 'Other';
}

const SECURITY_ACTIVITIES: Record<number, string> = {
  4624: '4624 - An account was successfully logged on.',
  4625: '4625 - An account failed to log on.',
  4634: '4634 - An account was logged off.',
  4648: '4648 - A logon was attempted using explicit credentials.',
  4662: '4662 - An operation was performed on an object.',
  4672: '4672 - Special privileges assigned to new logon.',
  4688: '4688 - A new process has been created.',
  4697: '4697 - A service was installed in the system.',
  4698: '4698 - A scheduled task was created.',
  4720: '4720 - A user account was created.',
  4722: '4722 - A user account was enabled.',
  4724: "4724 - An attempt was made to reset an account's password.",
  4728: '4728 - A member was added to a security-enabled global group.',
  4732: '4732 - A member was added to a security-enabled local group.',
  4740: '4740 - A user account was locked out.',
  4768: '4768 - A Kerberos authentication ticket (TGT) was requested.',
  4776: '4776 - The computer attempted to validate the credentials for an account.',
  1102: '1102 - The audit log was cleared.',
  7045: '7045 - A new service was installed in the system.',
};

export function securityActivity(id: number): string {
  return SECURITY_ACTIVITIES[id] ?? `${id}`;
}
