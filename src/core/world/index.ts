// Lookup helpers over a World. Not serialised — rebuilt from the world.

import type { Department, Host, Person, Site, World } from './world.ts';
import type { GeoEntry } from '../synth/geo.ts';

export class WorldIndex {
  readonly world: World;
  private peopleById = new Map<string, Person>();
  private peopleBySam = new Map<string, Person>();
  private peopleByUpn = new Map<string, Person>();
  private hostsByName = new Map<string, Host>();
  private hostsByIp = new Map<string, Host>();

  constructor(world: World) {
    this.world = world;
    for (const p of world.people) {
      this.peopleById.set(p.id, p);
      this.peopleBySam.set(p.sam, p);
      this.peopleByUpn.set(p.upn.toLowerCase(), p);
    }
    for (const h of world.hosts) {
      this.hostsByName.set(h.name.toUpperCase(), h);
      if (h.ip) this.hostsByIp.set(h.ip, h);
    }
  }

  get org() {
    return this.world.org;
  }

  person(id: string): Person {
    const p = this.peopleById.get(id);
    if (!p) throw new Error(`Unknown person ${id}`);
    return p;
  }

  personBySam(sam: string): Person | undefined {
    return this.peopleBySam.get(sam);
  }

  personByUpn(upn: string): Person | undefined {
    return this.peopleByUpn.get(upn.toLowerCase());
  }

  host(name: string): Host {
    const h = this.hostsByName.get(name.toUpperCase());
    if (!h) throw new Error(`Unknown host ${name}`);
    return h;
  }

  hostByIp(ip: string): Host | undefined {
    return this.hostsByIp.get(ip);
  }

  deviceOf(p: Person): Host {
    return this.host(p.laptop);
  }

  mobileOf(p: Person): Host | undefined {
    return p.mobileDevice ? this.hostsByName.get(p.mobileDevice.toUpperCase()) : undefined;
  }

  site(id: string): Site {
    const s = this.world.sites.find((x) => x.id === id);
    if (!s) throw new Error(`Unknown site ${id}`);
    return s;
  }

  siteOf(p: Person): Site {
    return this.site(p.siteId);
  }

  inDept(...depts: Department[]): Person[] {
    return this.world.people.filter((p) => depts.includes(p.department));
  }

  servers(): Host[] {
    return this.world.hosts.filter((h) => h.kind === 'server');
  }

  endpoints(): Host[] {
    return this.world.hosts.filter((h) => h.kind === 'laptop' || h.kind === 'desktop');
  }

  geo(ip: string): GeoEntry | undefined {
    return this.world.geo[ip];
  }

  // DOMAIN\sam
  account(sam: string): string {
    return `${this.world.org.netbios}\\${sam}`;
  }

  manager(p: Person): Person | undefined {
    return p.managerId ? this.peopleById.get(p.managerId) : undefined;
  }
}
