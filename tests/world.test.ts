import { describe, expect, it } from 'vitest';
import { generateWorld } from '../src/core/world/world.ts';
import { WorldIndex } from '../src/core/world/index.ts';
import { isDocumentationV4, isPrivateV4, isSyntheticAddress, ExternalAllocator } from '../src/core/synth/addresses.ts';
import { FICTITIOUS_DOMAINS } from '../src/core/synth/orgs.ts';
import { attackerDomain, registeredDomain } from '../src/core/synth/domains.ts';
import { createRng } from '../src/core/rng.ts';

const SEEDS = Array.from({ length: 25 }, (_, i) => `world-test-${i}`);

describe('rng', () => {
  it('is deterministic and forks are independent of parent draws', () => {
    const a = createRng('x');
    const b = createRng('x');
    expect([a.next(), a.int(1, 100), a.hex(8)]).toEqual([b.next(), b.int(1, 100), b.hex(8)]);
    const f1 = createRng('x').fork('child').next();
    const parent = createRng('x');
    parent.next();
    parent.next();
    expect(parent.fork('child').next()).toBe(f1);
  });
});

describe('world generation', () => {
  it('is deterministic for a seed', () => {
    expect(JSON.stringify(generateWorld('same'))).toBe(JSON.stringify(generateWorld('same')));
    expect(generateWorld('a').org.domain + generateWorld('a').people[0].upn).not.toBe(
      generateWorld('b').org.domain + generateWorld('b').people[5].upn,
    );
  });

  for (const seed of SEEDS) {
    it(`${seed}: consistent, unique and synthetic`, () => {
      const w = generateWorld(seed);
      const idx = new WorldIndex(w);

      // Organisation is a documentation-reserved fictitious company.
      expect(FICTITIOUS_DOMAINS.has(w.org.domain)).toBe(true);

      // Sensible size and uniqueness.
      expect(w.people.length).toBeGreaterThanOrEqual(55);
      expect(w.people.length).toBeLessThanOrEqual(80);
      expect(new Set(w.people.map((p) => p.sam)).size).toBe(w.people.length);
      expect(new Set(w.people.map((p) => p.display)).size).toBe(w.people.length);
      expect(new Set(w.hosts.map((h) => h.name)).size).toBe(w.hosts.length);
      const hostIps = w.hosts.filter((h) => h.ip).map((h) => h.ip);
      expect(new Set(hostIps).size).toBe(hostIps.length);

      // Every person has a laptop that exists; managers exist.
      for (const p of w.people) {
        expect(idx.deviceOf(p).owner).toBe(p.upn);
        if (p.managerId) expect(idx.person(p.managerId)).toBeDefined();
        expect(p.upn.endsWith(`@${w.org.domain}`)).toBe(true);
      }
      expect(w.people.filter((p) => p.managerId === null)).toHaveLength(1);

      // Tier-0 admins exist and helpdesk does not hold them.
      expect(w.people.some((p) => p.adminAccount)).toBe(true);
      expect(w.people.filter((p) => p.department === 'Helpdesk').every((p) => !p.adminAccount)).toBe(true);

      // Core infrastructure is present.
      for (const name of ['DC01', 'DC02', 'FS01', 'SCCM01', 'SCAN01', 'JUMP01', 'VPN01', 'FW01']) {
        expect(idx.host(name)).toBeDefined();
      }

      // Guardrails: internal = RFC 1918, external = RFC 5737 only.
      for (const ip of hostIps) expect(isPrivateV4(ip), ip).toBe(true);
      for (const ip of Object.keys(w.geo)) expect(isDocumentationV4(ip), ip).toBe(true);
      for (const ip of w.reservedExternal) expect(isSyntheticAddress(ip), ip).toBe(true);
      expect(new Set(w.reservedExternal).size).toBe(w.reservedExternal.length);

      // Leave plenty of the pool for case infrastructure.
      expect(762 - w.reservedExternal.length).toBeGreaterThan(300);

      // VPN egress points are distinct and one is away from HQ.
      expect(w.vpn.egress[0].city.city).not.toBe(w.vpn.egress[1].city.city);
      expect(w.vpn.egress[1].city.city).not.toBe(w.sites[0].city.city);
    });
  }
});

describe('synthetic domains and addresses', () => {
  it('attacker domains are never fictitious-org domains and look-alikes on common TLDs carry a token', () => {
    const rng = createRng('domains');
    for (let i = 0; i < 2000; i++) {
      for (const style of ['lookalike', 'lure', 'dga', 'tech'] as const) {
        const d = attackerDomain(rng, style, 'Contoso');
        expect(FICTITIOUS_DOMAINS.has(registeredDomain(d))).toBe(false);
        expect(d).toMatch(/^[a-z0-9.-]+$/);
        if (style === 'lookalike' && /\.(com|net|co)$/.test(d)) expect(d).toMatch(/\d+\.(com|net|co)$/);
      }
    }
  });

  it('allocator never repeats and stays in documentation ranges', () => {
    const alloc = new ExternalAllocator();
    const rng = createRng('alloc');
    const seen = new Set<string>();
    for (let i = 0; i < 700; i++) {
      const ip = alloc.v4(rng);
      expect(seen.has(ip)).toBe(false);
      expect(isDocumentationV4(ip)).toBe(true);
      seen.add(ip);
    }
    expect(alloc.v6(rng).startsWith('2001:db8:')).toBe(true);
  });

  it('registeredDomain handles subdomains and two-level suffixes', () => {
    expect(registeredDomain('a.b.example.com')).toBe('example.com');
    expect(registeredDomain('www.bbc.co.uk')).toBe('bbc.co.uk');
    expect(registeredDomain('x.top')).toBe('x.top');
  });
});
