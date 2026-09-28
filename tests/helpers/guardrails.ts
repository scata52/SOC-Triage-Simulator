// Guardrail assertions over a finished corpus: every address anywhere in any
// cell must be synthetic, and every external domain must be either a known
// benign service or one the simulator generated (and therefore tracked).

import type { Corpus } from '../../src/core/logs/corpus.ts';
import type { World } from '../../src/core/world/world.ts';
import { isSyntheticAddress } from '../../src/core/synth/addresses.ts';
import { BULK_SENDERS, registeredDomain } from '../../src/core/synth/domains.ts';
import { FICTITIOUS_DOMAINS } from '../../src/core/synth/orgs.ts';

const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const IPV6 = /\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){3,7}\b/gi;

export function syntheticViolations(corpus: Corpus, world: World): string[] {
  const problems: string[] = [];
  const allowedDomains = new Set<string>([
    world.org.domain,
    ...FICTITIOUS_DOMAINS,
    ...world.services.map((s) => registeredDomain(s.domain)),
    ...BULK_SENDERS.flatMap((s) => [registeredDomain(s.fromDomain), registeredDomain(s.esp)]),
    'sendgrid.net',
    'mktomail.com',
    'microsoft.com',
    'windowsupdate.com',
    'office365.com',
    'microsoftonline.com',
  ]);
  const intel = corpus.tables.DomainIntel;
  const repIdx = intel.columns.indexOf('Reputation');
  const domIdx = intel.columns.indexOf('Domain');
  const generated = new Set(intel.rows.filter((r) => r[repIdx] !== 'Good' && r[repIdx] !== 'Neutral').map((r) => String(r[domIdx])));

  for (const [name, table] of Object.entries(corpus.tables)) {
    for (const row of table.rows) {
      row.forEach((cell, i) => {
        if (typeof cell !== 'string') return;
        const col = table.columns[i];
        if (col === 'SHA256' || col === 'AttachmentSHA256' || col === 'DeviceId' || col === 'NetworkMessageId' || col === 'RecordId') return;
        for (const m of cell.matchAll(IPV4)) {
          const ip = m[0];
          if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
          // Browser versions ("Chrome/131.0.0.0") are the only dotted quads
          // that are not addresses.
          if (col === 'UserAgent' || col === 'Browser') continue;
          if (!isSyntheticAddress(ip)) problems.push(`${name}.${col}: non-synthetic IPv4 ${ip}`);
        }
        if (col.toLowerCase().includes('ip')) {
          for (const m of cell.matchAll(IPV6)) {
            if (!m[0].toLowerCase().startsWith('2001:db8:')) problems.push(`${name}.${col}: non-documentation IPv6 ${m[0]}`);
          }
        }
      });
    }
  }

  const domainCols: [string, string][] = [
    ['WebProxy', 'DestinationHost'],
    ['DnsEvents', 'Name'],
    ['DeviceNetworkEvents', 'RemoteUrl'],
    ['EmailEvents', 'SenderFromDomain'],
    ['EmailEvents', 'SenderMailFromDomain'],
  ];
  for (const [t, c] of domainCols) {
    const table = corpus.tables[t as keyof Corpus['tables']];
    const ci = table.columns.indexOf(c);
    for (const row of table.rows) {
      const host = row[ci];
      if (typeof host !== 'string' || !host.includes('.')) continue;
      const d = registeredDomain(host);
      if (d.endsWith(world.org.domain) || host.toLowerCase().endsWith(world.org.adFqdn)) continue;
      if (allowedDomains.has(d) || generated.has(d)) continue;
      problems.push(`${t}.${c}: untracked external domain ${host}`);
    }
  }
  return [...new Set(problems)];
}
