// Attacker infrastructure. Within one case a role ("c2", "phish") always
// resolves to the same value. When a campaign preset is supplied, roles
// resolve to the actor's persistent infrastructure so it can resurface across
// shifts; otherwise fresh, synthetic infrastructure is minted and registered
// (DNS answers, WHOIS age, reputation) in the corpus.

import type { Rng } from '../rng.ts';
import type { CorpusBuilder, DomainIntelInfo } from '../logs/corpus.ts';
import { attackerDomain, type AttackerDomainStyle } from '../synth/domains.ts';
import { CITIES, type GeoCity } from '../synth/geo.ts';

export type DomainRole = 'phish' | 'c2' | 'c2b' | 'payload' | 'exfil' | 'tunnel' | 'sender';
export type IpRole = 'phish' | 'c2' | 'c2b' | 'payload' | 'exfil' | 'tunnel' | 'login' | 'bruteforce' | 'bruteforce2' | 'vps' | 'sender';
export type HashRole = 'loader' | 'payload' | 'tool' | 'attachment' | 'ransomware';

export interface InfraRecord {
  domains: Partial<Record<DomainRole, string>>;
  ips: Partial<Record<IpRole, string>>;
  hashes: Partial<Record<HashRole, string>>;
  ipCities?: Partial<Record<IpRole, string>>;
  domainAgeDays?: Partial<Record<DomainRole, number>>;
}

const DEFAULT_STYLE: Record<DomainRole, AttackerDomainStyle> = {
  phish: 'lookalike',
  sender: 'lure',
  c2: 'tech',
  c2b: 'dga',
  payload: 'tech',
  exfil: 'tech',
  tunnel: 'dga',
};

const HOSTING_CITIES = ['Amsterdam', 'Frankfurt', 'Ashburn', 'Singapore', 'Moscow', 'Hong Kong', 'São Paulo', 'Kyiv', 'Istanbul', 'Lagos', 'Dubai', 'Manila'];

export class Infra {
  private log: CorpusBuilder;
  private rng: Rng;
  private orgShort: string;
  private preset: InfraRecord | undefined;
  private used: InfraRecord = { domains: {}, ips: {}, hashes: {}, ipCities: {}, domainAgeDays: {} };

  constructor(log: CorpusBuilder, rng: Rng, orgShort: string, preset?: InfraRecord) {
    this.log = log;
    this.rng = rng;
    this.orgShort = orgShort;
    this.preset = preset;
  }

  get campaign(): boolean {
    return !!this.preset;
  }

  record(): InfraRecord {
    return JSON.parse(JSON.stringify(this.used)) as InfraRecord;
  }

  ip(role: IpRole, city?: GeoCity): string {
    const existing = this.used.ips[role];
    if (existing) return existing;
    const preset = this.preset?.ips[role];
    let ip: string;
    if (preset) {
      ip = preset;
      if (!this.log.geo[ip]) {
        const c = CITIES.find((x) => x.city === this.preset?.ipCities?.[role]) ?? city ?? this.hostingCity();
        this.log.geo[ip] = { city: c.city, country: c.country, cc: c.cc, asn: this.rng.int(64512, 65534), network: 'Offshore VPS', kind: 'hosting' };
      }
      this.log.ext.reserve(ip);
    } else {
      const c = city ?? this.hostingCity();
      ip = this.log.externalIp(role === 'login' ? 'residential' : 'hosting', c);
    }
    this.used.ips[role] = ip;
    this.used.ipCities![role] = this.log.geo[ip]?.city;
    return ip;
  }

  domain(role: DomainRole, opts: { style?: AttackerDomainStyle; ageDays?: number; reputation?: DomainIntelInfo['reputation']; category?: string } = {}): string {
    const existing = this.used.domains[role];
    if (existing) return existing;
    const preset = this.preset?.domains[role];
    const domain = preset ?? attackerDomain(this.rng, opts.style ?? DEFAULT_STYLE[role], this.orgShort);
    const ipRole: IpRole = role === 'sender' ? 'sender' : role;
    const ip = this.ip(ipRole);
    // A campaign domain keeps its own (ageing) registration date.
    const presetAge = preset ? this.preset?.domainAgeDays?.[role] : undefined;
    const age = presetAge ?? opts.ageDays ?? this.rng.int(2, 28);
    this.log.registerDomain(domain, [ip], {
      ageDays: age,
      category: opts.category ?? (age < 30 ? 'Newly Registered Domain' : 'Uncategorized'),
      reputation: opts.reputation ?? 'Unknown',
    });
    this.used.domains[role] = domain;
    this.used.domainAgeDays![role] = age;
    return domain;
  }

  hash(role: HashRole): string {
    const existing = this.used.hashes[role];
    if (existing) return existing;
    const h = this.preset?.hashes[role] ?? this.rng.hex(64);
    this.used.hashes[role] = h;
    return h;
  }

  private hostingCity(): GeoCity {
    const name = this.rng.pick(HOSTING_CITIES);
    return CITIES.find((c) => c.city === name) ?? this.rng.pick(CITIES);
  }
}
