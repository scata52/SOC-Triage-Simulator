// Address policy. Every external address the simulator ever shows comes from
// the RFC 5737 IPv4 documentation ranges or the RFC 3849 IPv6 documentation
// prefix, so no real host can be implicated. Attackers, employees' home
// connections, SaaS endpoints and internet scanners all draw from the same
// pools — the range itself must never be a tell.

import type { Rng } from '../rng.ts';

export const DOC_V4_BLOCKS = ['192.0.2', '198.51.100', '203.0.113'] as const;
export const DOC_V6_PREFIX = '2001:db8:';

export function isDocumentationV4(ip: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const prefix = `${m[1]}.${m[2]}.${m[3]}`;
  const last = Number(m[4]);
  return (DOC_V4_BLOCKS as readonly string[]).includes(prefix) && last >= 1 && last <= 254;
}

export function isDocumentationV6(ip: string): boolean {
  return ip.toLowerCase().startsWith(DOC_V6_PREFIX);
}

export function isPrivateV4(ip: string): boolean {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
}

// Allowed anywhere in a corpus.
export function isSyntheticAddress(ip: string): boolean {
  return isDocumentationV4(ip) || isDocumentationV6(ip) || isPrivateV4(ip);
}

// Hands out unique external addresses. A world reserves its own; a corpus
// (case or shift) continues from the world's reservations so case-level
// attacker infrastructure can never collide with an employee's home IP.
export class ExternalAllocator {
  private used: Set<string>;

  constructor(reserved: Iterable<string> = []) {
    this.used = new Set(reserved);
  }

  get size(): number {
    return this.used.size;
  }

  reserved(): string[] {
    return [...this.used];
  }

  reserve(ip: string): void {
    this.used.add(ip);
  }

  v4(rng: Rng): string {
    for (let attempt = 0; attempt < 4000; attempt++) {
      const ip = `${rng.pick(DOC_V4_BLOCKS)}.${rng.int(1, 254)}`;
      if (!this.used.has(ip)) {
        this.used.add(ip);
        return ip;
      }
    }
    throw new Error('External IPv4 documentation pool exhausted');
  }

  v6(rng: Rng): string {
    for (;;) {
      const groups = Array.from({ length: 6 }, () => rng.hex(4).replace(/^0+(?=.)/, ''));
      const ip = `${DOC_V6_PREFIX}${groups.join(':')}`;
      if (!this.used.has(ip)) {
        this.used.add(ip);
        return ip;
      }
    }
  }
}

// Internal addressing for one site: 10.<b>.0.0/16 carved into roles.
export interface SiteNetwork {
  prefix: string; // "10.24"
  cidr: string; // "10.24.0.0/16"
}

export const SUBNETS = {
  servers: 10,
  dmz: 100,
  workstationsFrom: 20,
  workstationsTo: 39,
  vpnPoolFrom: 200,
  vpnPoolTo: 203,
  mgmt: 250,
} as const;

export class InternalAllocator {
  private used = new Set<string>();
  readonly prefix: string;

  constructor(prefix: string) {
    this.prefix = prefix;
  }

  inSubnet(rng: Rng, third: number): string {
    for (let attempt = 0; attempt < 1000; attempt++) {
      const ip = `${this.prefix}.${third}.${rng.int(5, 250)}`;
      if (!this.used.has(ip)) {
        this.used.add(ip);
        return ip;
      }
    }
    throw new Error(`Subnet ${this.prefix}.${third}.0/24 exhausted`);
  }

  workstation(rng: Rng): string {
    return this.inSubnet(rng, rng.int(SUBNETS.workstationsFrom, SUBNETS.workstationsTo));
  }

  vpnClient(rng: Rng): string {
    return this.inSubnet(rng, rng.int(SUBNETS.vpnPoolFrom, SUBNETS.vpnPoolTo));
  }
}

// Private-use autonomous system numbers (RFC 6996).
export function privateAsn(rng: Rng): number {
  return rng.int(64512, 65534);
}
