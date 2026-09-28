// Who is working, when, and from where. Every other noise source hangs off
// these sessions so the tables agree with each other: the laptop that logs on
// at 08:12 is the one whose browser shows up in the proxy at 08:15, from the
// address the person's sign-ins came from.

import type { Rng } from '../../rng.ts';
import type { Host, Person, World } from '../../world/world.ts';
import type { CorpusBuilder } from '../corpus.ts';
import { InternalAllocator } from '../../synth/addresses.ts';
import { atLocalHour, DAY, HOUR, isWeekend, MIN } from '../time.ts';

export type Location = 'office' | 'home' | 'travel';

export interface Session {
  person: Person;
  device: Host;
  start: number;
  end: number;
  location: Location;
  cloudIp: string; // address Entra ID / SaaS sees
  lanIp: string; // address the proxy/DNS/firewall see (office LAN or VPN pool)
  onVpn: boolean;
  userAgent: string;
  browser: 'Edge' | 'Chrome';
  travelCity?: string;
  hotelIp?: string;
}

const EDGE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.70';
const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

export function browserOf(p: Person): 'Edge' | 'Chrome' {
  // Stable per person.
  let h = 0;
  for (let i = 0; i < p.sam.length; i++) h = (h * 31 + p.sam.charCodeAt(i)) | 0;
  return Math.abs(h) % 3 === 0 ? 'Chrome' : 'Edge';
}

export function userAgentOf(p: Person): string {
  return browserOf(p) === 'Chrome' ? CHROME_UA : EDGE_UA;
}

export function planSessions(b: CorpusBuilder, rng: Rng): Session[] {
  const w: World = b.world;
  const off = w.org.utcOffset;
  const sessions: Session[] = [];
  // VPN clients draw from the pool subnets, which never overlap office LANs.
  const vpnPool = new InternalAllocator(w.sites[0].prefix);

  // Local days overlapping the window.
  const firstDay = atLocalHour(b.windowStart - DAY, 0, off);
  for (let day = firstDay; day < b.windowEnd; day += DAY) {
    const weekend = isWeekend(day + 12 * HOUR, off);
    for (const p of w.people) {
      const device = b.idx.deviceOf(p);
      if (weekend && !rng.bool(0.05)) continue;
      if (!weekend && rng.bool(0.05)) continue; // out of office
      let start = atLocalHour(day, p.workStart + rng.gaussian(0, 0.35), off);
      let end = atLocalHour(day, p.workEnd + rng.gaussian(0.2, 0.6), off);
      if (weekend) end = start + rng.int(40, 150) * MIN;
      if (end <= b.windowStart || start >= b.windowEnd) continue;
      start = Math.max(start, b.windowStart + rng.int(1, 20) * MIN);
      end = Math.min(end, b.windowEnd - MIN);
      if (end - start < 20 * MIN) continue;

      let location: Location = 'office';
      if (p.fieldSales && rng.bool(0.35)) location = 'travel';
      else if (weekend || rng.bool(p.remoteShare)) location = 'home';

      const site = b.idx.siteOf(p);
      let cloudIp = site.natIp;
      let lanIp = device.ip;
      let onVpn = false;
      let travelCity: string | undefined;
      let hotelIp: string | undefined;
      if (location === 'home') {
        onVpn = rng.bool(0.8);
        // Always-on VPN: cloud traffic mostly still egresses via the VPN.
        cloudIp = onVpn && rng.bool(0.5) ? w.vpn.egress[0].ip : p.homeIp;
        lanIp = onVpn ? vpnPool.vpnClient(rng) : device.ip;
      } else if (location === 'travel') {
        onVpn = true;
        const hotel = rng.pick(w.internet.hotels);
        hotelIp = hotel;
        travelCity = b.geo[hotel]?.city;
        // Field staff hit either the hotel network or the cloud VPN gateway.
        cloudIp = rng.bool(0.5) ? hotel : rng.pick(w.vpn.egress).ip;
        lanIp = vpnPool.vpnClient(rng);
      }
      sessions.push({
        person: p,
        device,
        start,
        end,
        location,
        cloudIp,
        lanIp,
        onVpn,
        userAgent: userAgentOf(p),
        browser: browserOf(p),
        travelCity,
        hotelIp,
      });
    }
  }
  return sessions.sort((a, b2) => a.start - b2.start);
}

// A random instant inside a session, biased away from lunch.
export function within(rng: Rng, s: Session, marginMin = 5): number {
  const lo = s.start + marginMin * MIN;
  const hi = Math.max(lo + MIN, s.end - marginMin * MIN);
  return Math.floor(rng.float(lo, hi));
}
