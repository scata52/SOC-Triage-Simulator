// Web proxy, DNS and firewall noise. Decoys for the network templates:
//  - periodic telemetry check-ins (fixed cadence, to a known-good domain) —
//    what a C2 beacon must be distinguished from
//  - CDN hostnames with random-looking labels — what DNS-tunnel "entropy"
//    must be distinguished from
//  - a steady stream of internet scanners hitting the perimeter
//  - personal file-sharing uploads of normal size by marketing/sales

import type { Rng } from '../../rng.ts';
import type { Person } from '../../world/world.ts';
import type { ExternalService } from '../../synth/domains.ts';
import { MIN, SEC } from '../time.ts';
import { within, type Session } from './presence.ts';
import type { NoiseCtx } from './context.ts';

const SEARCHES: Record<string, string[]> = {
  default: ['weather+tomorrow', 'train+timetable', 'excel+xlookup+example', 'teams+meeting+recording+location', 'public+holidays+2026'],
  Engineering: ['typescript+satisfies+operator', 'sqlite+window+functions', 'git+rebase+onto', 'docker+compose+healthcheck', 'regex+lookbehind'],
  IT: ['group+policy+drive+mapping', 'windows+event+4740+source', 'intune+compliance+policy', 'powershell+get-aduser+lastlogon'],
  Finance: ['ifrs+16+lease', 'vat+reverse+charge', 'excel+pivot+refresh+all'],
  Sales: ['conference+venues', 'crm+pipeline+stages', 'hotel+near+exhibition+centre'],
  Security: ['kql+summarize+bin', 'cve+2026+advisory', 'mitre+attack+t1566'],
};

function pathFor(svc: ExternalService, rng: Rng, p: Person, tenant: string): string {
  const d = svc.domain;
  if (d === 'outlook.office365.com') return rng.pick(['/owa/', '/mail/inbox', '/owa/service.svc?action=GetItem&app=Mail', '/owa/service.svc?action=FindConversation']);
  if (d === 'teams.microsoft.com') return rng.pick(['/api/chatsvc/emea/v1/users/ME/conversations', '/api/mt/emea/beta/users/tenants', '/v2/']);
  if (d.endsWith('-my.sharepoint.com')) return `/personal/${p.sam.replace('.', '_')}_${tenant}_com/_api/web/lists`;
  if (d.endsWith('.sharepoint.com')) return `/sites/${p.department}/Shared%20Documents/Forms/AllItems.aspx`;
  if (d === 'login.microsoftonline.com') return '/common/oauth2/v2.0/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&response_type=code';
  if (d === 'graph.microsoft.com') return rng.pick(['/v1.0/me/events', '/v1.0/me/presence', '/beta/me/chats']);
  if (d === 'www.google.com' || d === 'www.bing.com') return `/search?q=${rng.pick(SEARCHES[p.department] ?? SEARCHES.default)}`;
  if (d === 'github.com') return `/${tenant}/${rng.pick(['platform', 'infra', 'web', 'tools'])}/pull/${rng.int(100, 2400)}`;
  if (d === 'api.github.com') return `/repos/${tenant}/platform/commits`;
  if (d === 'registry.npmjs.org') return `/${rng.pick(['preact', 'vite', 'typescript', 'zod', 'date-fns'])}`;
  if (d === 'pypi.org') return `/simple/${rng.pick(['requests', 'pandas', 'pytest', 'numpy'])}/`;
  if (d.endsWith('.my.salesforce.com')) return rng.pick(['/lightning/o/Opportunity/list', '/lightning/r/Account/001', '/services/data/v61.0/query']);
  if (d.endsWith('.atlassian.net')) return rng.pick([`/browse/${tenant.slice(0, 3).toUpperCase()}-${rng.int(100, 900)}`, '/wiki/spaces/ENG/overview']);
  if (d === 'settings-win.data.microsoft.com') return '/settings/v3.0/wsd/muse';
  if (d === 'ctldl.windowsupdate.com') return '/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab';
  return '/';
}

export function webNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const tenant = w.org.tenant;
  const dnsCache = new Map<string, number>();
  const resolverFor = (s: Session) => (s.person.siteId === 'branch' && !s.onVpn ? 'DC02' : 'DC01');

  const dnsQuery = (clientIp: string, resolver: string, name: string, t: number, type = 'A') => {
    const key = `${clientIp}|${name}`;
    const last = dnsCache.get(key);
    if (last !== undefined && t - last < 10 * MIN && t >= last) return;
    dnsCache.set(key, t);
    b.dns({ TimeGenerated: t - rng.int(50, 400), ClientIP: clientIp, Computer: resolver, Name: name, QueryType: type });
  };

  for (const s of n.sessions) {
    const p = s.person;
    const services = w.services.filter((svc) => !svc.depts || svc.depts.includes(p.department));
    const weights = services.map((svc) => ({ value: svc, weight: svc.weight }));
    const hours = (s.end - s.start) / 3_600_000;
    const requests = Math.max(4, Math.round(hours * rng.float(1.8, 4)));
    const resolver = resolverFor(s);
    for (let i = 0; i < requests; i++) {
      const svc = rng.pickWeighted(weights);
      let host = svc.domain;
      if (host.endsWith('.cloudfront.net')) {
        host = `${rng.pick(['d', 'd1', 'd2', 'd3'])}${rng.alnum(12)}.cloudfront.net`;
        b.registerDomain(host, w.serviceIps[svc.domain]);
      }
      const t = within(rng, s);
      const blocked = !!svc.blocked;
      const post = !blocked && svc.kind === 'saas' && rng.bool(0.25);
      const upload = svc.kind === 'personal-storage' && rng.bool(0.4);
      const status = blocked ? 403 : rng.pickWeighted([
        { value: 200, weight: 14 },
        { value: 304, weight: 3 },
        { value: 302, weight: 2 },
        { value: 204, weight: 2 },
        { value: 404, weight: 0.3 },
      ]);
      const ua = svc.process === 'svchost.exe' || svc.process === 'OfficeClickToRun.exe' ? 'Microsoft-CryptoAPI/10.0' : s.userAgent;
      b.proxy({
        TimeGenerated: t,
        SourceIP: s.lanIp,
        SourceUser: p.sam,
        Method: upload || post ? 'POST' : 'GET',
        Url: `https://${host}${pathFor(svc, rng, p, tenant)}`,
        DestinationHost: host,
        StatusCode: status,
        BytesSent: upload ? rng.int(200_000, 18_000_000) : post ? rng.int(900, 12_000) : rng.int(350, 2_200),
        BytesReceived: blocked ? rng.int(900, 1_500) : rng.int(2_000, svc.kind === 'update' ? 4_000_000 : 380_000),
        Category: svc.category,
        Action: blocked ? 'Blocked' : 'Allowed',
        UserAgent: ua,
      });
      dnsQuery(s.lanIp, resolver, host, t);
      if (rng.bool(0.3) && s.device.os.startsWith('Windows')) {
        b.net({ TimeGenerated: t + rng.int(0, 900), DeviceName: s.device.name, LocalIP: s.lanIp, RemoteIP: b.resolve(host), RemotePort: 443, RemoteUrl: host, InitiatingProcessFileName: (svc.process ?? 'msedge.exe').toLowerCase(), InitiatingProcessAccountName: svc.process === 'svchost.exe' ? 'SYSTEM' : p.sam });
      }
    }
    // Internal name lookups.
    const ad = w.org.adFqdn;
    dnsQuery(s.lanIp, resolver, `_ldap._tcp.dc._msdcs.${ad}`, s.start + rng.int(3, 30) * SEC, 'SRV');
    dnsQuery(s.lanIp, resolver, `${p.siteId === 'branch' ? 'fs02' : 'fs01'}.${ad}`, s.start + rng.int(30, 300) * SEC);
    if (rng.bool(0.3)) {
      b.dns({ TimeGenerated: s.start + rng.int(5, 60) * SEC, ClientIP: s.lanIp, Computer: resolver, Name: `wpad.${ad}`, QueryType: 'A', ResponseCode: 'NXDOMAIN', IPAddresses: '' });
    }
  }

  // Periodic telemetry: a known-good domain at a near-fixed cadence from a
  // handful of machines. Looks exactly like beaconing to a naive detector.
  const telemetry = 'settings-win.data.microsoft.com';
  const chatty = rng.sample(n.sessions.filter((s) => s.device.os.startsWith('Windows')), Math.min(6, n.sessions.length));
  for (const s of chatty) {
    const period = rng.pick([15, 20, 30]) * MIN;
    for (let t = s.start + rng.int(1, 10) * MIN; t < s.end; t += period + rng.int(-20, 20) * SEC) {
      b.proxy({ TimeGenerated: t, SourceIP: s.lanIp, SourceUser: s.person.sam, Method: 'GET', Url: `https://${telemetry}/settings/v3.0/wsd/muse`, DestinationHost: telemetry, StatusCode: 200, BytesSent: rng.int(610, 640), BytesReceived: rng.int(1_900, 2_050), Category: 'Telemetry', UserAgent: 'MSDW' });
    }
  }
}

export function perimeterNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const targets = [w.sites[0].natIp, w.sites[1].natIp, w.publicIps.web, w.publicIps.vpn];
  const ports = [22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443];
  for (const scanner of w.internet.scanners) {
    const hits = rng.int(3, 14);
    for (let i = 0; i < hits; i++) {
      const dst = rng.pick(targets);
      const port = rng.pick(ports);
      const allowed = (dst === w.publicIps.web && (port === 80 || port === 443)) || (dst === w.publicIps.vpn && port === 443);
      b.fw({
        TimeGenerated: rng.int(b.windowStart, b.windowEnd),
        Direction: 'Inbound',
        Action: allowed ? 'Allow' : 'Deny',
        Protocol: 'TCP',
        SourceIP: scanner,
        SourcePort: rng.int(1024, 65000),
        DestinationIP: dst,
        DestinationPort: port,
        RuleName: allowed ? (dst === w.publicIps.web ? 'allow-web-dmz' : 'allow-vpn-portal') : 'deny-inbound-default',
        BytesSent: allowed ? rng.int(300, 2_000) : 60,
        BytesReceived: allowed ? rng.int(500, 12_000) : 0,
        SessionDurationSec: allowed ? rng.int(1, 4) : 0,
      });
    }
  }
  // Legitimate public web traffic.
  const visitors = rng.int(40, 90);
  for (let i = 0; i < visitors; i++) {
    b.fw({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), Direction: 'Inbound', Action: 'Allow', SourceIP: rng.pick([...w.people.map((p) => p.homeIp), ...w.internet.carriers, ...w.internet.hotels]), SourcePort: rng.int(20000, 65000), DestinationIP: w.publicIps.web, DestinationPort: 443, RuleName: 'allow-web-dmz', BytesSent: rng.int(800, 4_000), BytesReceived: rng.int(20_000, 900_000), SessionDurationSec: rng.int(1, 40) });
  }
  // VPN tunnels for remote and travelling staff.
  for (const s of n.sessions) {
    if (!s.onVpn) continue;
    const src = s.location === 'home' ? s.person.homeIp : s.cloudIp;
    b.fw({ TimeGenerated: s.start - rng.int(1, 4) * MIN, Direction: 'Inbound', Action: 'Allow', SourceIP: src, SourcePort: rng.int(20000, 65000), DestinationIP: w.publicIps.vpn, DestinationPort: 443, RuleName: 'allow-vpn-portal', BytesSent: rng.int(20_000_000, 400_000_000), BytesReceived: rng.int(40_000_000, 900_000_000), SessionDurationSec: Math.round((s.end - s.start) / 1000) });
  }
  // A little east-west friction.
  const sql = b.idx.host('SQL01');
  const denies = rng.int(1, 4);
  for (let i = 0; i < denies && n.sessions.length; i++) {
    const s = rng.pick(n.sessions);
    b.fw({ TimeGenerated: within(rng, s), Direction: 'Internal', Action: 'Deny', SourceIP: s.lanIp, SourcePort: rng.int(49152, 65000), DestinationIP: sql.ip, DestinationPort: 1433, RuleName: 'deny-workstations-to-db', BytesSent: 0, BytesReceived: 0, SessionDurationSec: 0 });
  }
  // Sample of allowed east-west SMB to file servers.
  for (const s of n.sessions) {
    if (!rng.bool(0.5)) continue;
    const fs = b.idx.host(s.person.siteId === 'branch' ? 'FS02' : 'FS01');
    b.fw({ TimeGenerated: within(rng, s), Direction: 'Internal', Action: 'Allow', SourceIP: s.lanIp, SourcePort: rng.int(49152, 65000), DestinationIP: fs.ip, DestinationPort: 445, RuleName: 'allow-smb-fileservers', BytesSent: rng.int(20_000, 3_000_000), BytesReceived: rng.int(50_000, 30_000_000), SessionDurationSec: rng.int(10, 3_600) });
  }
}
