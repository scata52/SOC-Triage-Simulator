// Selection helpers for templates: people, their devices, where they were at
// a given moment (so attacker activity lines up with — or conspicuously
// doesn't match — the victim's real pattern), cities and external addresses.

import type { Rng } from '../rng.ts';
import type { CorpusBuilder } from '../logs/corpus.ts';
import type { Session } from '../logs/noise/presence.ts';
import type { Department, Host, Person } from '../world/world.ts';
import type { WorldIndex } from '../world/index.ts';
import { CITIES, haversineKm, type GeoCity, type NetworkKind } from '../synth/geo.ts';

export interface PersonFilter {
  dept?: Department | Department[];
  exclude?: (Person | undefined)[];
  fieldSales?: boolean;
  mobile?: boolean;
  admin?: boolean;
  windows?: boolean;
  working?: boolean; // has a work session covering the alert time (default: prefer)
}

export interface Whereabouts {
  cloudIp: string;
  lanIp: string;
  device: Host;
  location: 'office' | 'home' | 'travel';
  session?: Session;
}

export class Picker {
  private rng: Rng;
  private idx: WorldIndex;
  private sessions: Session[];
  private log: CorpusBuilder;
  private at: number;

  constructor(rng: Rng, idx: WorldIndex, sessions: Session[], log: CorpusBuilder, at: number) {
    this.rng = rng;
    this.idx = idx;
    this.sessions = sessions;
    this.log = log;
    this.at = at;
  }

  private matches(p: Person, f: PersonFilter): boolean {
    if (f.dept) {
      const depts = Array.isArray(f.dept) ? f.dept : [f.dept];
      if (!depts.includes(p.department)) return false;
    }
    if (f.exclude?.some((x) => x && x.id === p.id)) return false;
    if (f.fieldSales !== undefined && p.fieldSales !== f.fieldSales) return false;
    if (f.mobile && !p.mobileDevice) return false;
    if (f.admin !== undefined && !!p.adminAccount !== f.admin) return false;
    if (f.windows && !this.idx.deviceOf(p).os.startsWith('Windows')) return false;
    return true;
  }

  sessionAt(p: Person, t: number): Session | undefined {
    return this.sessions.find((s) => s.person.id === p.id && s.start <= t && s.end >= t);
  }

  person(f: PersonFilter = {}): Person {
    const all = this.idx.world.people.filter((p) => this.matches(p, f));
    if (all.length === 0) throw new Error(`No person matches ${JSON.stringify({ ...f, exclude: undefined })}`);
    if (f.working === false) return this.rng.pick(all);
    const working = all.filter((p) => this.sessionAt(p, this.at));
    return this.rng.pick(working.length ? working : all);
  }

  people(n: number, f: PersonFilter = {}): Person[] {
    const out: Person[] = [];
    for (let i = 0; i < n; i++) out.push(this.person({ ...f, exclude: [...(f.exclude ?? []), ...out], working: false }));
    return out;
  }

  device(p: Person): Host {
    return this.idx.deviceOf(p);
  }

  // Where the person was at time t, according to the noise sessions.
  where(p: Person, t: number = this.at): Whereabouts {
    const s = this.sessionAt(p, t) ?? this.sessions.filter((x) => x.person.id === p.id).sort((a, b) => Math.abs(a.start - t) - Math.abs(b.start - t))[0];
    const device = this.idx.deviceOf(p);
    if (!s) return { cloudIp: this.idx.siteOf(p).natIp, lanIp: device.ip, device, location: 'office' };
    return { cloudIp: s.cloudIp, lanIp: s.lanIp, device, location: s.location, session: s };
  }

  server(name: string): Host {
    return this.idx.host(name);
  }

  city(opts: { farFrom?: GeoCity; minKm?: number; notCc?: string[]; europe?: boolean } = {}): GeoCity {
    let pool = CITIES.filter((c) => !opts.notCc?.includes(c.cc));
    if (opts.farFrom) pool = pool.filter((c) => haversineKm(c, opts.farFrom!) >= (opts.minKm ?? 1500));
    if (opts.europe) pool = pool.filter((c) => c.utcOffset >= 0 && c.utcOffset <= 3 && c.lon > -12 && c.lon < 32);
    if (pool.length === 0) pool = [...CITIES];
    return this.rng.pick(pool);
  }

  ip(kind: NetworkKind, city?: GeoCity): string {
    return this.log.externalIp(kind, city ?? this.city());
  }

  hash(): string {
    return this.rng.hex(64);
  }

  guid(): string {
    const r = this.rng;
    return `${r.hex(8)}-${r.hex(4)}-4${r.hex(3)}-${r.pick(['8', '9', 'a', 'b'])}${r.hex(3)}-${r.hex(12)}`;
  }
}
