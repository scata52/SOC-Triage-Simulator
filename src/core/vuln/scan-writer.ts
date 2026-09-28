// The scan writer (DESIGN section 6.2): emits ScanRuns and VulnFindings rows
// (plus the VulnIntel, SoftwareInventory and DeviceInfo rows they depend on)
// through the corpus builder, and applies the method semantics that make
// scanner output worth reading critically:
//
//   Unauthenticated  sees the network only: the version it reports is the one
//                    in the service banner. Distribution packages backport
//                    fixes without changing the banner, so this is a guess.
//   Credentialed     logs in and reads the package database: the version it
//                    reports is the installed package version. If the login
//                    fails on a device, that device falls back to the banner.
//   Agent            runs on the device and reports package versions too.
//
// Everything is fictional and deterministic: randomness comes from the Rng
// the writer is given, and no row carries a marker that says signal or noise.

import type { Rng } from '../rng.ts';
import type { CorpusBuilder, RowRef } from '../logs/corpus.ts';
import { DAY, MIN } from '../logs/time.ts';
import { SUBNETS } from '../synth/addresses.ts';
import type { Criticality } from '../world/world.ts';
import { severityOf } from './cvss31.ts';
import type { CatalogueEntry, VulnCatalogue } from './catalogue.ts';

export const SCAN_METHODS = ['Credentialed', 'Unauthenticated', 'Agent'] as const;
export type ScanMethod = (typeof SCAN_METHODS)[number];

export const SCAN_VANTAGES = ['Internal', 'External'] as const;
export type ScanVantage = (typeof SCAN_VANTAGES)[number];

export type FindingStatus = 'Open' | 'Fixed' | 'Risk accepted';
export type PackageSource = 'distro' | 'vendor' | 'source-built';
export type ScannerSeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

// Where a finding's DetectedVersion came from.
export type VersionBasis = 'banner' | 'package';

// Shown in VulnIntel.Source: the feeds are simulated, always.
export const SIM_INTEL_SOURCE = 'Simulated (Sim-KEV / Sim-EPSS)';

// The one rule that separates the three methods (see the file header).
export function versionBasis(method: ScanMethod, authFailed = false): VersionBasis {
  if (method === 'Unauthenticated') return 'banner';
  return authFailed ? 'banner' : 'package';
}

// The upstream part of a package version: "4.1.2-3+esm2" -> "4.1.2". This is
// what a service banner shows, since a distribution's backported fix does not
// change it.
export function upstreamVersion(version: string): string {
  return version.replace(/[-+~].*$/, '');
}

// Numeric comparison of the upstream parts of two dotted versions: -1, 0 or 1.
export function compareVersions(a: string, b: string): number {
  const pa = upstreamVersion(a).split('.').map((x) => Number(x) || 0);
  const pb = upstreamVersion(b).split('.').map((x) => Number(x) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

// A "x.y.z" version strictly below `fixed` (which must be "x.y.z" too).
export function versionBelow(rng: Rng, fixed: string): string {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(fixed);
  if (!m) throw new RangeError(`versionBelow expects x.y.z, got "${fixed}"`);
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (c > 0) return `${a}.${b}.${rng.int(0, c - 1)}`;
  if (b > 0) return `${a}.${rng.int(0, b - 1)}.${rng.int(0, 9)}`;
  if (a > 1) return `${a - 1}.${rng.int(0, 12)}.${rng.int(0, 9)}`;
  return `0.${rng.int(1, 9)}.${rng.int(0, 9)}`;
}

const DEFAULT_TOOL: Record<ScanMethod, string> = {
  Credentialed: 'Sim-Scan Enterprise',
  Unauthenticated: 'Sim-Scan Enterprise',
  Agent: 'Sim-Scan Agent',
};
const EXTERNAL_TOOL = 'Sim-Scan Cloud (external)';

export interface ScanRunInput {
  id?: string; // default: SCN-nnnn
  tool?: string;
  method: ScanMethod;
  vantage?: ScanVantage; // default Internal
  started: number; // epoch ms
  durationMin?: number; // default 45..180
  targetsPlanned: number;
  targetsScanned?: number; // default: targetsPlanned (partial coverage: give less)
  authFailures?: number; // devices whose login failed; raised automatically by findings marked authFailed
}

export interface ScanRunHandle {
  readonly id: string;
  readonly method: ScanMethod;
  readonly vantage: ScanVantage;
  readonly tool: string;
  readonly started: number;
  readonly finished: number;
  readonly row: RowRef<'ScanRuns'>;
}

export interface FindingInput {
  host: string; // DeviceName of an in-scope device
  entry: CatalogueEntry; // pass a modified copy to override a decider's values
  installedVersion?: string; // the package version at scan time (default: a version below the fix)
  bannerVersion?: string; // what the service banner announces (default: the upstream part of installedVersion)
  port?: number; // required when the version comes from a banner
  service?: string; // default: derived from the port
  packageSource?: PackageSource; // default 'vendor'
  authFailed?: boolean; // credentialed run only: the login failed on this device, so the result is banner-level
  status?: FindingStatus; // default 'Open'
  firstSeen?: number;
  lastSeen?: number;
  scannerSeverity?: ScannerSeverity; // default: the CVSS band of the score the scanner reports
  scannerCvss?: number; // default: entry.base
  title?: string;
  pluginFamily?: string;
  evidence?: string; // replaces the generated scanner output
  recordInventory?: boolean; // default true: keep SoftwareInventory consistent with the finding
}

export interface WrittenFinding {
  findingId: string;
  row: RowRef<'VulnFindings'>;
  basis: VersionBasis;
}

export interface SoftwareInput {
  host: string;
  product: string;
  vendor: string;
  version: string;
  source?: PackageSource;
  installedOn?: number;
}

export interface ScopeHostInput {
  name: string;
  role: string;
  os: string;
  owner: string;
  criticality: Criticality;
  deviceType?: 'Server' | 'Appliance' | 'Workstation'; // default Server
  exposed?: boolean; // reachable from the internet (default false)
  site?: string; // world site id (default: the first site)
  ip?: string; // default: a free address in the site's server (or DMZ) subnet
  managed?: boolean; // default true
}

export interface BackgroundOptions {
  hosts: readonly string[]; // pool the findings are spread over
  count: number; // findings drawn from the catalogue
  hygiene?: number; // extra configuration-hygiene findings with no vulnerability id
  exclude?: Iterable<string>; // vulnerability ids to keep out
}

const FAMILY_BY_CLASS: Record<CatalogueEntry['vulnClass'], string> = {
  rce: 'Remote Code Execution',
  sqli: 'Web Applications',
  'auth-bypass': 'Authentication',
  'info-leak': 'Information Disclosure',
  dos: 'Denial of Service',
  misconfig: 'Configuration',
};

const SERVICE_BY_PORT: Record<number, string> = {
  22: 'ssh',
  25: 'smtp',
  80: 'http',
  443: 'https',
  445: 'smb',
  1433: 'mssql',
  3389: 'rdp',
  5432: 'postgresql',
  8080: 'http',
  8443: 'https',
};

const WEB_PORTS: readonly number[] = [443, 443, 8443, 80, 8080];

// Configuration-hygiene plugins: real scanners are full of them and they carry
// no vulnerability id. [title, scanner severity, score, port, detail]
const HYGIENE: readonly (readonly [string, ScannerSeverity, number, number, string])[] = [
  ['Self-signed TLS certificate', 'Low', 3.1, 443, 'The certificate is not signed by a trusted authority.'],
  ['Legacy TLS protocol versions enabled', 'Medium', 5.3, 443, 'The service still negotiates TLS 1.0 and 1.1.'],
  ['SSH server offers weak key exchange algorithms', 'Low', 2.6, 22, 'Deprecated key exchange algorithms are enabled.'],
  ['SMB signing not required', 'Medium', 5.3, 445, 'The server does not require SMB message signing.'],
  ['Service banner discloses version information', 'Info', 0, 80, 'The Server response header names the product and version.'],
  ['HTTP TRACE method enabled', 'Low', 3.7, 80, 'The web server answers TRACE requests.'],
  ['Certificate expires within 30 days', 'Low', 2.1, 8443, 'The certificate is close to its expiry date.'],
];

const cap = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const softwareKey = (host: string, product: string): string => `${host.toUpperCase()}|${product}`;

function guid(rng: Rng): string {
  return `${rng.hex(8)}-${rng.hex(4)}-4${rng.hex(3)}-${rng.pick(['8', '9', 'a', 'b'])}${rng.hex(3)}-${rng.hex(12)}`;
}

function scannerSeverityOf(score: number): ScannerSeverity {
  const band = severityOf(score);
  return band === 'none' ? 'Info' : (cap(band) as ScannerSeverity);
}

export class ScanWriter {
  private readonly log: CorpusBuilder;
  private readonly rng: Rng;
  private readonly catalogue: VulnCatalogue;
  private readonly intelRows = new Map<string, RowRef<'VulnIntel'>>();
  private readonly softwareRows = new Map<string, RowRef<'SoftwareInventory'>>();
  private readonly usedVulnIds = new Set<string>();
  private readonly usedFindingIds = new Set<string>();
  private readonly usedRunIds = new Set<string>();
  private readonly runHosts = new Map<string, Map<string, boolean>>(); // run id -> device -> login failed?

  constructor(log: CorpusBuilder, rng: Rng, catalogue: VulnCatalogue) {
    this.log = log;
    this.rng = rng;
    this.catalogue = catalogue;
  }

  // ------------------------------------------------------------ scope
  // A device that exists only in this case, added to the CMDB. Returns its name.
  scopeHost(input: ScopeHostInput): string {
    const world = this.log.world;
    const site = world.sites.find((s) => s.id === (input.site ?? world.sites[0].id));
    if (!site) throw new RangeError(`Unknown site "${input.site}"`);
    const taken = new Set(this.log.rowsOf('DeviceInfo').map((r) => String(r.IPAddress ?? '')));
    let ip = input.ip;
    if (!ip) {
      const third = input.exposed ? SUBNETS.dmz : SUBNETS.servers;
      for (let attempt = 0; attempt < 1000 && !ip; attempt++) {
        const candidate = `${site.prefix}.${third}.${this.rng.int(5, 250)}`;
        if (!taken.has(candidate)) ip = candidate;
      }
      if (!ip) throw new Error(`Subnet ${site.prefix}.${third}.0/24 exhausted`);
    } else if (taken.has(ip)) {
      throw new RangeError(`Address ${ip} is already in use`);
    }
    this.log.device({
      DeviceName: input.name,
      DeviceId: guid(this.rng),
      IPAddress: ip,
      DeviceType: input.deviceType ?? 'Server',
      OSPlatform: input.os,
      Role: input.role,
      Owner: input.owner,
      Criticality: input.criticality,
      Site: site.name,
      IsManaged: input.managed ?? true,
      ExposedToInternet: input.exposed ?? false,
    });
    return input.name;
  }

  // ------------------------------------------------------------ runs
  run(input: ScanRunInput): ScanRunHandle {
    const vantage = input.vantage ?? 'Internal';
    if (vantage === 'External' && input.method !== 'Unauthenticated') {
      throw new RangeError('An external scan can only be unauthenticated: it has no way to log in');
    }
    if (input.method === 'Agent' && vantage !== 'Internal') throw new RangeError('An agent runs on the device, so its vantage is Internal');
    const planned = input.targetsPlanned;
    const scanned = input.targetsScanned ?? planned;
    const failures = input.authFailures ?? 0;
    if (!Number.isInteger(planned) || planned < 1) throw new RangeError('targetsPlanned must be a positive integer');
    if (!Number.isInteger(scanned) || scanned < 0 || scanned > planned) throw new RangeError('targetsScanned must be between 0 and targetsPlanned');
    if (!Number.isInteger(failures) || failures < 0 || failures > scanned) throw new RangeError('authFailures must be between 0 and targetsScanned');
    if (failures > 0 && input.method !== 'Credentialed') throw new RangeError('Only a credentialed scan has login failures');

    let id = input.id;
    if (id === undefined) {
      do id = `SCN-${this.rng.int(1000, 9999)}`;
      while (this.usedRunIds.has(id));
    }
    if (this.usedRunIds.has(id)) throw new RangeError(`Scan run ${id} already exists`);
    this.usedRunIds.add(id);

    const durationMin = input.durationMin ?? this.rng.int(45, 180);
    const tool = input.tool ?? (vantage === 'External' ? EXTERNAL_TOOL : DEFAULT_TOOL[input.method]);
    const finished = input.started + durationMin * MIN;
    const row = this.log.scanRun({
      ScanRunId: id,
      Tool: tool,
      Method: input.method,
      Vantage: vantage,
      Started: input.started,
      Finished: finished,
      TargetsPlanned: planned,
      TargetsScanned: scanned,
      AuthFailures: failures,
    });
    this.runHosts.set(id, new Map());
    return { id, method: input.method, vantage, tool, started: input.started, finished, row };
  }

  // ------------------------------------------------------------ findings
  finding(run: ScanRunHandle, input: FindingInput): WrittenFinding {
    const { entry } = input;
    const device = this.log.deviceRef(input.host).row; // throws for a device that is not in scope
    const authFailed = input.authFailed ?? false;
    if (authFailed && run.method !== 'Credentialed') throw new RangeError('Only a credentialed run can have a login failure on a device');
    if (run.vantage === 'External' && device.ExposedToInternet !== true) {
      throw new RangeError(`${input.host} is not exposed to the internet, so an external scan cannot see it`);
    }
    const basis = versionBasis(run.method, authFailed);
    if (basis === 'banner' && input.port === undefined) throw new RangeError('A banner-derived finding needs the port of the service that showed the banner');
    if (input.port !== undefined && (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535)) throw new RangeError(`Bad port ${input.port}`);

    // One installed version per (device, product): a second finding on the same
    // product reuses what the inventory already says.
    const known = this.softwareRows.get(softwareKey(input.host, entry.product))?.row.Version;
    const installed =
      input.installedVersion ??
      (typeof known === 'string' ? known : entry.vendorFix ? versionBelow(this.rng, entry.fixedVersion) : `${this.rng.int(1, 9)}.${this.rng.int(0, 12)}.${this.rng.int(0, 9)}`);
    const banner = input.bannerVersion ?? upstreamVersion(installed);
    const detected = basis === 'banner' ? banner : installed;
    const source = input.packageSource ?? 'vendor';
    const service = input.service ?? (input.port !== undefined ? (SERVICE_BY_PORT[input.port] ?? 'tcp') : '');
    const score = input.scannerCvss ?? entry.base;
    const lastSeen = input.lastSeen ?? Math.min(run.finished, run.started + this.rng.int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN);
    const firstSeen = input.firstSeen ?? lastSeen;
    if (firstSeen > lastSeen) throw new RangeError('firstSeen is after lastSeen');

    this.recordDevice(run, input.host, authFailed);
    this.intel(entry);
    this.usedVulnIds.add(entry.id);
    if (input.recordInventory ?? true) this.ensureSoftware(input.host, entry, installed, source, run.started);

    const findingId = this.nextFindingId();
    const row = this.log.finding({
      FindingId: findingId,
      DeviceName: input.host,
      VulnId: entry.id,
      Title: input.title ?? entry.title,
      Severity: input.scannerSeverity ?? scannerSeverityOf(score),
      CvssBase: score,
      Port: input.port ?? null,
      Service: service,
      DetectedVersion: detected,
      Evidence: input.evidence ?? this.evidence(run, basis, authFailed, entry, { installed, banner, port: input.port, service, source }),
      ScanRunId: run.id,
      FirstSeen: firstSeen,
      LastSeen: lastSeen,
      Status: input.status ?? 'Open',
      PluginFamily: input.pluginFamily ?? (basis === 'package' ? 'Local Security Checks' : FAMILY_BY_CLASS[entry.vulnClass]),
    });
    return { findingId, row, basis };
  }

  // A configuration-hygiene finding: no vulnerability id, no intel row.
  hygieneFinding(run: ScanRunHandle, host: string, index: number): WrittenFinding {
    const [title, severity, score, port, detail] = HYGIENE[((index % HYGIENE.length) + HYGIENE.length) % HYGIENE.length];
    const device = this.log.deviceRef(host).row;
    if (run.vantage === 'External' && device.ExposedToInternet !== true) throw new RangeError(`${host} is not exposed to the internet, so an external scan cannot see it`);
    this.recordDevice(run, host, this.loginFailed(run, host));
    const lastSeen = Math.min(run.finished, run.started + this.rng.int(1, Math.max(1, Math.round((run.finished - run.started) / MIN))) * MIN);
    const findingId = this.nextFindingId();
    const service = SERVICE_BY_PORT[port] ?? 'tcp';
    const row = this.log.finding({
      FindingId: findingId,
      DeviceName: host,
      VulnId: '',
      Title: title,
      Severity: severity,
      CvssBase: score,
      Port: port,
      Service: service,
      DetectedVersion: '',
      Evidence: `${run.method === 'Unauthenticated' ? 'Remote' : 'Configuration'} check on ${port}/tcp (${service}): ${detail}`,
      ScanRunId: run.id,
      FirstSeen: lastSeen,
      LastSeen: lastSeen,
      Status: 'Open',
      PluginFamily: port === 443 || port === 8443 ? 'SSL/TLS' : 'General',
    });
    return { findingId, row, basis: versionBasis(run.method) };
  }

  // Background findings (DESIGN section 6.3): mostly medium and low, never on
  // the Sim-KEV list, spread over the given devices, no vulnerability used twice.
  background(run: ScanRunHandle, opts: BackgroundOptions): WrittenFinding[] {
    if (opts.hosts.length === 0) throw new RangeError('background needs at least one host');
    const skip = new Set(opts.exclude ?? []);
    const weight: Record<CatalogueEntry['severity'], number> = { critical: 0, high: 1, medium: 4, low: 2 };
    const pool = this.catalogue.entries.filter((e) => !e.knownExploited && weight[e.severity] > 0 && !this.usedVulnIds.has(e.id) && !skip.has(e.id));
    if (opts.count > pool.length) throw new RangeError(`background: asked for ${opts.count} findings but only ${pool.length} catalogue entries are free`);
    const out: WrittenFinding[] = [];
    for (let i = 0; i < opts.count; i++) {
      const at = this.rng.pickWeighted(pool.map((e, k) => ({ value: k, weight: weight[e.severity] })));
      const [entry] = pool.splice(at, 1);
      // A device whose inventory already shows this product at or above the fix
      // cannot carry the finding: pick another.
      let host = this.rng.pick(opts.hosts);
      for (let tries = 0; tries < 20 && this.alreadyFixed(host, entry); tries++) host = this.rng.pick(opts.hosts);
      if (this.alreadyFixed(host, entry)) throw new Error(`background: no device in the pool can carry ${entry.id} (${entry.product} is already fixed there)`);
      // A device whose login failed in this run only yields banner-level findings.
      const authFailed = this.loginFailed(run, host);
      const port = versionBasis(run.method, authFailed) === 'banner' ? this.rng.pick(WEB_PORTS) : undefined; // a banner needs a listening service
      out.push(this.finding(run, { host, entry, port, authFailed }));
    }
    for (let i = 0; i < (opts.hygiene ?? 0); i++) out.push(this.hygieneFinding(run, this.rng.pick(opts.hosts), this.rng.int(0, HYGIENE.length - 1)));
    return out;
  }

  // ------------------------------------------------------------ intel and inventory
  // The VulnIntel row for a vulnerability: created on first use, patched by a
  // later call (so a template can override its deciders' values).
  intel(entry: CatalogueEntry): RowRef<'VulnIntel'> {
    const values = {
      VulnId: entry.id,
      CvssVector: entry.vector,
      CvssBase: entry.base,
      KnownExploited: entry.knownExploited,
      KnownExploitedAdded: entry.knownExploitedAdded,
      ExploitProbability: entry.epss,
      ExploitPercentile: entry.epssPercentile,
      PublicExploit: entry.publicExploit,
      VendorFix: entry.vendorFix,
      FixedVersion: entry.vendorFix ? entry.fixedVersion : '',
      Published: entry.published,
      Source: SIM_INTEL_SOURCE,
    };
    const existing = this.intelRows.get(entry.id);
    if (existing) {
      Object.assign(existing.row, values);
      return existing;
    }
    const ref = this.log.vulnIntel(values);
    this.intelRows.set(entry.id, ref);
    return ref;
  }

  // The installed-software row for (device, product): created, or patched if it exists.
  software(input: SoftwareInput): RowRef<'SoftwareInventory'> {
    this.log.deviceRef(input.host);
    const key = softwareKey(input.host, input.product);
    const values = {
      DeviceName: input.host,
      Product: input.product,
      Vendor: input.vendor,
      Version: input.version,
      PackageSource: input.source ?? 'vendor',
    };
    const existing = this.softwareRows.get(key);
    if (existing) {
      Object.assign(existing.row, values);
      if (input.installedOn !== undefined) existing.row.InstalledOn = input.installedOn;
      return existing;
    }
    const ref = this.log.software({ ...values, InstalledOn: input.installedOn ?? this.log.now - this.rng.int(30, 700) * DAY });
    this.softwareRows.set(key, ref);
    return ref;
  }

  // ------------------------------------------------------------ internals
  private loginFailed(run: ScanRunHandle, host: string): boolean {
    return this.runHosts.get(run.id)?.get(host.toUpperCase()) === true;
  }

  // Coverage bookkeeping for a device that has a finding in a run: the run can
  // only have reached as many devices as it says, a device's login either
  // worked or failed for the whole run, and failures are counted in ScanRuns.
  private recordDevice(run: ScanRunHandle, host: string, authFailed: boolean): void {
    const hosts = this.runHosts.get(run.id)!;
    const key = host.toUpperCase();
    const seen = hosts.get(key);
    if (seen !== undefined && seen !== authFailed) {
      throw new RangeError(`${run.id}: the login on ${host} ${seen ? 'failed' : 'worked'} for other findings in this run, so it cannot ${authFailed ? 'fail' : 'work'} here`);
    }
    if (seen === undefined) {
      if (hosts.size + 1 > Number(run.row.row.TargetsScanned)) throw new RangeError(`${run.id}: findings on more devices than the ${String(run.row.row.TargetsScanned)} the run reached`);
      hosts.set(key, authFailed);
    }
    if (authFailed) {
      const failures = [...hosts.values()].filter(Boolean).length;
      run.row.row.AuthFailures = Math.max(Number(run.row.row.AuthFailures ?? 0), failures);
      if (Number(run.row.row.AuthFailures) > Number(run.row.row.TargetsScanned)) throw new RangeError(`${run.id}: more login failures than devices scanned`);
    }
  }

  private alreadyFixed(host: string, entry: CatalogueEntry): boolean {
    const v = this.softwareRows.get(softwareKey(host, entry.product))?.row.Version;
    return typeof v === 'string' && entry.vendorFix && compareVersions(v, entry.fixedVersion) >= 0;
  }

  private ensureSoftware(host: string, entry: CatalogueEntry, version: string, source: PackageSource, scanStarted: number): void {
    const key = softwareKey(host, entry.product);
    if (this.softwareRows.has(key)) return;
    const installedOn = scanStarted - this.rng.int(20, 700) * DAY;
    this.softwareRows.set(key, this.log.software({ DeviceName: host, Product: entry.product, Vendor: entry.vendor, Version: version, PackageSource: source, InstalledOn: installedOn }));
  }

  private nextFindingId(): string {
    let id: string;
    do id = `VF-${this.rng.int(10000, 99999)}`;
    while (this.usedFindingIds.has(id));
    this.usedFindingIds.add(id);
    return id;
  }

  private evidence(
    run: ScanRunHandle,
    basis: VersionBasis,
    authFailed: boolean,
    entry: CatalogueEntry,
    v: { installed: string; banner: string; port: number | undefined; service: string; source: PackageSource },
  ): string {
    const fix = entry.vendorFix ? `Fixed in ${entry.fixedVersion}.` : 'No vendor fix is available.';
    if (basis === 'banner') {
      const banner = `${entry.product.replace(/\s+/g, '-')}/${v.banner}`;
      const lead = authFailed
        ? `Credentialed login failed on this device (authentication error); the check fell back to the service banner on ${v.port}/tcp (${v.service}): "${banner}".`
        : `Remote check: the ${v.service} service on ${v.port}/tcp announces "${banner}".`;
      return `${lead} Version taken from the banner only; installed packages and vendor backports were not inspected. ${fix}`;
    }
    const how = run.method === 'Agent' ? 'Agent local check' : 'Credentialed local check';
    const via = run.method === 'Agent' ? 'reported by the endpoint agent' : 'read from the package database over an authenticated session';
    return `${how}: ${entry.product} ${v.installed} installed (package source: ${v.source}), ${via}. ${fix}`;
  }
}
