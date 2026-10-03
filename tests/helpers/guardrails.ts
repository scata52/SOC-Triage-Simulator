// Guardrail assertions over a finished corpus: every address anywhere in any
// cell must be synthetic, and every external domain must be either a known
// benign service or one the simulator generated (and therefore tracked).
// With a case spec, the text of the case (alert, briefing, attachments, hints,
// solution, explanation, pitfalls, evidence labels) is held to the same rules
// for addresses, and to the no-CVE-id rule.
//
// Known limitation: a domain is "generated" when the corpus's own DomainIntel
// table lists it with a reputation other than Good or Neutral, so a template
// that hard-coded a real domain and gave it a Malicious row would pass. The
// vulnerability tests close that gap (reserved names only); the SOC side relies
// on review and on the e2e check that no data domain is rendered as a link.

import type { Corpus } from '../../src/core/logs/corpus.ts';
import type { World } from '../../src/core/world/world.ts';
import { isSyntheticAddress } from '../../src/core/synth/addresses.ts';
import { BULK_SENDERS, registeredDomain } from '../../src/core/synth/domains.ts';
import { FICTITIOUS_DOMAINS } from '../../src/core/synth/orgs.ts';
import { cveViolations } from './cve-guard.ts';

const IPV4 = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const IPV6 = /\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){3,7}\b/gi;
// A real IPv6 address (full or "::" compressed) in running text. MAC addresses and clock times do not match.
const IPV6_TEXT =
  /(?<![0-9a-z:.])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,5})?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}))(?![0-9a-z:])/gi;
// Hosts inside URLs and e-mail addresses, wherever they sit in a string.
const URL_HOST = /\b[a-z][a-z0-9+.-]*:\/\/(?:[^/\s@]*@)?([a-z0-9.-]+)/gi;
const MAIL_HOST = /[\w.%+-]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)/gi;
const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost']);
const RESERVED_NAMES = new Set(['example.com', 'example.net', 'example.org']);
// A browser version ("Chrome/131.0.0.0") is the only dotted quad that is not an address.
const BROWSER_VERSION = /^\d+\.0\.0\.0$/;

// Every string leaf of a value (a case spec, a list of cases), depth first.
export function stringsOf(value: unknown, out: string[] = []): string[] {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) stringsOf(v, out);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) stringsOf(v, out);
  return out;
}

// Addresses and CVE ids in the text of a case spec (or a list of them).
export function specViolations(spec: unknown, label = 'case text'): string[] {
  const problems: string[] = [];
  const texts = stringsOf(spec);
  for (const text of texts) {
    for (const m of text.matchAll(IPV4)) {
      if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
      if (BROWSER_VERSION.test(m[0])) continue;
      if (!isSyntheticAddress(m[0])) problems.push(`${label}: non-synthetic IPv4 ${m[0]}`);
    }
    for (const m of text.matchAll(IPV6_TEXT)) {
      if (!m[0].toLowerCase().startsWith('2001:db8:')) problems.push(`${label}: non-documentation IPv6 ${m[0]}`);
    }
  }
  problems.push(...cveViolations({ label, text: texts.join('\n') }));
  return [...new Set(problems)];
}

// `spec`, when given, is the built case (or cases): its text is scanned too.
//
// `extraGenerated` lists domains the engine generated outside this corpus: a campaign carries the indicators of
// earlier shifts into ThreatIntel and IncidentHistory.
export function syntheticViolations(corpus: Corpus, world: World, spec?: unknown, extraGenerated: Iterable<string> = []): string[] {
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
  for (const d of extraGenerated) generated.add(registeredDomain(d));

  const isOrg = (host: string) => {
    const org = world.org.domain.toLowerCase();
    const ad = world.org.adFqdn.toLowerCase();
    return host === org || host.endsWith(`.${org}`) || host === ad || host.endsWith(`.${ad}`);
  };
  // True when a host is neither the organisation, a reserved name, a known service nor a generated domain.
  const hostProblem = (host: string): boolean => {
    const h = host.toLowerCase().replace(/\.$/, '');
    if (!h.includes('.') || /^[\d.]+$/.test(h)) return false; // not a domain name (addresses are checked separately)
    if (RESERVED_TLDS.has(h.split('.').pop()!) || RESERVED_NAMES.has(registeredDomain(h))) return false;
    if (isOrg(h)) return false;
    const d = registeredDomain(h);
    return !(allowedDomains.has(d) || generated.has(d));
  };

  for (const [name, table] of Object.entries(corpus.tables)) {
    for (const row of table.rows) {
      row.forEach((cell, i) => {
        if (typeof cell !== 'string') return;
        const col = table.columns[i];
        if (col === 'SHA256' || col === 'AttachmentSHA256' || col === 'DeviceId' || col === 'NetworkMessageId' || col === 'RecordId') return;
        for (const m of cell.matchAll(IPV4)) {
          const ip = m[0];
          if ([m[1], m[2], m[3], m[4]].some((o) => Number(o) > 255)) continue;
          if ((col === 'UserAgent' || col === 'Browser') && BROWSER_VERSION.test(ip)) continue;
          if (!isSyntheticAddress(ip)) problems.push(`${name}.${col}: non-synthetic IPv4 ${ip}`);
        }
        if (col.toLowerCase().includes('ip')) {
          for (const m of cell.matchAll(IPV6)) {
            if (!m[0].toLowerCase().startsWith('2001:db8:')) problems.push(`${name}.${col}: non-documentation IPv6 ${m[0]}`);
          }
        }
        // Hosts of URLs and e-mail addresses in any string cell, not only the columns listed below.
        for (const re of [URL_HOST, MAIL_HOST]) {
          for (const m of cell.matchAll(re)) {
            if (hostProblem(m[1])) problems.push(`${name}.${col}: untracked external domain ${m[1]} (in a URL or e-mail address)`);
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
      if (typeof host !== 'string') continue;
      if (hostProblem(host)) problems.push(`${t}.${c}: untracked external domain ${host}`);
    }
  }
  if (spec !== undefined) problems.push(...specViolations(spec));
  return [...new Set(problems)];
}
