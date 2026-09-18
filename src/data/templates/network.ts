import type { CaseTemplate } from '../../types.ts';
import { artifact, kvBlock, table, rubric } from './util.ts';

// ---------------------------------------------------------------------------
// Internal host running a horizontal port scan (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const internalPortScan: CaseTemplate = {
  id: 'network-internal-portscan',
  category: 'recon',
  difficulty: 'tier2',
  title: 'A workstation is scanning the internal network',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const user = faker.identity();
    const host = faker.laptop();
    const srcIp = faker.privateIp();
    const hosts = rng.int(240, 800);

    return {
      alert: `IDS (High): "Horizontal port scan" — ${srcIp} (${host}) attempted connections to ${hosts}+ internal hosts across ports 22/135/139/445/3389 in 4 minutes.`,
      context: `${faker.env.company} — ${host} is a finance laptop; there is no reason for it to enumerate the server subnets.`,
      artifacts: [
        artifact(
          'IDS — Scan detection',
          'kv',
          kvBlock([
            ['Source', `${srcIp} (${host})`],
            ['Distinct destinations', `${hosts}`],
            ['Ports probed', '22, 135, 139, 445, 3389, 5985'],
            ['Pattern', 'Sequential /24 sweep, SYN only (half-open)'],
            ['Duration', '~4 minutes'],
            ['Tooling fingerprint', 'Matches nmap default SYN scan timing'],
          ]),
        ),
        artifact(
          'Firewall — East/West sample',
          'table',
          table(
            ['Time', 'Src', 'Dst', 'Port', 'Action'],
            [
              [faker.clock(0), srcIp, `${faker.env.internalPrefix}.10.11`, '445', 'ALLOW'],
              [faker.clock(1), srcIp, `${faker.env.internalPrefix}.10.12`, '445', 'DROP'],
              [faker.clock(1), srcIp, `${faker.env.internalPrefix}.10.13`, '3389', 'ALLOW'],
              [faker.clock(2), srcIp, `${faker.env.internalPrefix}.10.14`, '22', 'DROP'],
              ['...', srcIp, `(${hosts - 4} more)`, '...', '...'],
            ],
          ),
        ),
        artifact(
          'Endpoint context',
          'kv',
          kvBlock([
            ['Logged-on user', user.username],
            ['New process before scan', 'powershell.exe (encoded) 6 min earlier'],
            ['Asset role', 'Finance workstation (non-technical user)'],
            ['Authorized scanner?', 'No — not in the vuln-scan asset group'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1046'],
        tactics: ['discovery'],
      },
      rubric: rubric([
        ['pattern', 'Sequential /24 SYN sweep across admin ports = active network discovery.', ['scan', 'sweep', 'syn', 'discovery', 'nmap']],
        ['wronghost', 'The source is a finance laptop with a non-technical user — it has no business scanning.', ['finance', 'laptop', 'non-technical', 'unexpected', 'workstation']],
        ['precursor', 'An encoded PowerShell ran minutes earlier — likely the compromise that led to recon.', ['powershell', 'precursor', 'compromise', 'earlier', 'foothold']],
        ['contain', 'Isolate the host and treat the scan as post-compromise internal recon.', ['isolate', 'contain', 'post-compromise', 'escalate']],
      ]),
      explanation: [
        `A single internal host fanning out to hundreds of destinations on 22/135/139/445/3389 in a few minutes, SYN-only and sequential, is a horizontal port scan — network service discovery. The tooling timing even matches nmap defaults.`,
        `Context makes it malicious rather than administrative: ${host} is a finance laptop used by a non-technical employee, it is not in the authorized-scanner group, and an encoded PowerShell process ran on it minutes earlier. That sequence — foothold, then internal enumeration — is an attacker mapping the network before lateral movement.`,
        `Escalate and isolate ${host}. Scope back to the PowerShell execution as the likely initial access, and forward to whatever the scan was preparing for (look for follow-on SMB/RDP connections to the hosts that answered).`,
      ],
      pitfalls: [
        'The identical scan pattern from an authorized scanner appliance would be benign — the source identity is decisive.',
        'The earlier PowerShell event is the thread to pull; the scan is a symptom, not the start.',
      ],
      references: [
        { label: 'ATT&CK T1046 Network Service Discovery', url: 'https://attack.mitre.org/techniques/T1046/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: authorized vulnerability scan (BENIGN)
// ---------------------------------------------------------------------------
const authorizedScan: CaseTemplate = {
  id: 'network-authorized-vulnscan',
  category: 'recon',
  difficulty: 'tier1',
  title: 'Flood of scan alerts from one host',
  cysaDomains: ['1.0', '2.0'],
  build({ rng, faker }) {
    const scanner = faker.server('SCAN');
    const scannerIp = `${faker.env.internalPrefix}.250.${rng.int(2, 20)}`;

    return {
      alert: `IDS (High): thousands of "port scan" and "vulnerability probe" alerts from ${scannerIp} against multiple subnets over the last hour.`,
      context: `${faker.env.company} — the vulnerability-management team runs weekly authenticated scans; today is the scheduled day.`,
      artifacts: [
        artifact(
          'IDS — Aggregate',
          'kv',
          kvBlock([
            ['Source', `${scannerIp} (${scanner})`],
            ['Alert volume', `${rng.int(4000, 12000)} in 60 min`],
            ['Destinations', 'Entire server + workstation VLANs'],
            ['Probe types', 'Full TCP connect, service/version, credentialed checks'],
            ['Reverse DNS', `${scanner}.${faker.env.emailDomain.replace('.com', '.local')}`],
          ]),
        ),
        artifact(
          'Asset & schedule enrichment',
          'kv',
          kvBlock([
            ['Asset role', `Authorized vulnerability scanner (Nessus/Qualys)`],
            ['Scanner asset group', 'Yes — in the sanctioned-scanner allowlist'],
            ['Schedule', `Weekly ${new Date(faker.anchorTime).toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' })} 09:00 window`],
            ['Change record', 'Standing approval CHG for recurring scans'],
            ['Credentialed', 'Yes — using the read-only scan service account'],
            ['Owner', 'Vulnerability Management team'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'benign',
        severity: 'informational',
        action: 'close',
        techniques: [],
        tactics: [],
      },
      rubric: rubric([
        ['knownscanner', `Source is the sanctioned scanner appliance (${scanner}) in the scanner allowlist.`, ['scanner', 'nessus', 'qualys', 'allowlist', 'authorized']],
        ['schedule', 'Timing matches the standing weekly scan schedule and approval.', ['schedule', 'weekly', 'window', 'approved', 'standing']],
        ['credentialed', 'Credentialed checks from a read-only scan account = vuln management, not an attacker.', ['credentialed', 'read-only', 'scan account', 'vuln management']],
        ['tune', 'Benign; consider suppressing IDS scan alerts from the scanner source.', ['benign', 'close', 'suppress', 'tune', 'allowlist']],
      ]),
      explanation: [
        `The traffic looks identical to an attacker's network sweep, which is the point of the twin: you cannot disposition on pattern alone. The source here is the organisation's authorized vulnerability scanner — in the sanctioned-scanner asset group, with reverse DNS to match — running its standing weekly credentialed scan on schedule.`,
        `Everything corroborates authorized activity: a recurring change approval, credentialed checks using the read-only scan service account, and coverage of the expected VLANs. None of the internal-recon red flags (unexpected source host, preceding compromise) are present.`,
        `Disposition benign, informational. Close it, and reduce future noise by suppressing or allowlisting IDS scan alerts sourced from the scanner's IP — a standard bit of tuning that keeps the queue focused on the sweeps you do care about.`,
      ],
      pitfalls: [
        'Huge scan-alert volume is expected from a real scanner; volume is not severity.',
        'Confirm the source is genuinely the scanner IP/asset — an attacker spoofing "it\'s just the scan" is exactly why you verify.',
      ],
      references: [
        { label: 'Vulnerability scanning basics', url: 'https://csrc.nist.gov/glossary/term/vulnerability_scanning' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// DNS tunneling (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const dnsTunneling: CaseTemplate = {
  id: 'network-dns-tunneling',
  category: 'c2',
  difficulty: 'tier3',
  title: 'Abnormal DNS query volume and entropy',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const host = faker.workstation();
    const srcIp = faker.privateIp();
    const tunnelDomain = faker.maliciousDomain();
    const q = () => `${faker.hex(rng.int(28, 40))}.${tunnelDomain}`;

    return {
      alert: `DNS analytics (High): ${host} (${srcIp}) issued ${rng.int(9000, 40000)} DNS queries to a single second-level domain in 1 hour, almost all TXT/NULL with long, high-entropy subdomains.`,
      context: `${faker.env.company} — DNS is allowed outbound to the internal resolvers for everyone; it is a common covert channel.`,
      artifacts: [
        artifact(
          'DNS resolver — Query sample',
          'raw',
          [
            `${faker.clock(0)}  ${srcIp}  TXT?  ${q()}`,
            `${faker.clock(1)}  ${srcIp}  TXT?  ${q()}`,
            `${faker.clock(1)}  ${srcIp}  NULL? ${q()}`,
            `${faker.clock(2)}  ${srcIp}  TXT?  ${q()}`,
            `   ... thousands more, all *.${tunnelDomain}`,
          ],
        ),
        artifact(
          'DNS analytics — Aggregates',
          'kv',
          kvBlock([
            ['Second-level domain', tunnelDomain],
            ['Query count (1h)', `${rng.int(9000, 40000)}`],
            ['Record types', 'TXT (71%), NULL (24%), A (5%)'],
            ['Avg subdomain length', `${rng.int(30, 52)} chars`],
            ['Subdomain entropy', 'High (looks encoded/base32)'],
            ['Unique subdomains', '≈ query count (no caching benefit)'],
            ['Authoritative NS', `ns1.${tunnelDomain} (registered ${rng.int(2, 9)} days ago)`],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1071.004', 'T1048'],
        tactics: ['command-and-control', 'exfiltration'],
      },
      rubric: rubric([
        ['volume', 'Thousands of unique high-entropy subdomains to one domain = data encoded into DNS.', ['volume', 'entropy', 'subdomain', 'encoded', 'unique']],
        ['recordtype', 'Heavy TXT/NULL use is abnormal for normal browsing and typical of tunneling.', ['txt', 'null', 'record', 'tunnel', 'abnormal']],
        ['newdomain', 'The domain and its nameserver were registered days ago — attacker infrastructure.', ['newly registered', 'nameserver', 'ns', 'infrastructure', 'new domain']],
        ['contain', 'Isolate the host, sinkhole/block the domain, and assess for data exfiltration.', ['isolate', 'sinkhole', 'block', 'exfil', 'contain']],
      ]),
      explanation: [
        `Normal DNS is low-volume and benefits from caching. Here one host fires tens of thousands of queries in an hour, nearly all with unique 30–50 character high-entropy subdomains and heavy TXT/NULL record types. That is data being base32-encoded into the query names and answers — DNS tunneling used as a covert C2 and exfiltration channel that slips through firewalls because DNS is universally allowed.`,
        `The destination domain and its authoritative nameserver were both registered days ago, i.e. purpose-built attacker infrastructure. The lack of any caching benefit (unique subdomain per query) is the giveaway that these are data carriers, not real lookups.`,
        `Escalate: isolate ${host}, sinkhole or block ${tunnelDomain} at the resolver, and investigate what may have been exfiltrated. Root-cause the endpoint for the implant driving the tunnel.`,
      ],
      pitfalls: [
        'Some CDNs and AV products are chatty over DNS — but not with thousands of unique high-entropy TXT subdomains to a days-old domain.',
        'Blocking the domain stops the channel but does not remove the implant generating it.',
      ],
      references: [
        { label: 'ATT&CK T1071.004 DNS', url: 'https://attack.mitre.org/techniques/T1071/004/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Regular-interval C2 beacon (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const c2Beacon: CaseTemplate = {
  id: 'network-c2-beacon',
  category: 'c2',
  difficulty: 'tier3',
  title: 'Periodic outbound connections with fixed cadence',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const host = faker.workstation();
    const srcIp = faker.privateIp();
    const c2 = faker.maliciousDomain();
    const c2Ip = faker.publicIp();
    const interval = rng.pick([30, 45, 60, 90]);
    const bytes = rng.int(280, 460);

    return {
      alert: `Network analytics (Medium): ${host} makes an outbound HTTPS connection to ${c2} every ~${interval}s (±10% jitter) with near-constant byte counts — a beaconing pattern.`,
      context: `${faker.env.company} — proxy allows general web; the destination is not a known SaaS provider.`,
      artifacts: [
        artifact(
          'Proxy — Connection cadence',
          'table',
          table(
            ['Time', 'Dst', 'Bytes out', 'Bytes in', 'Status'],
            [
              [faker.clock(0), c2, `${bytes}`, `${rng.int(120, 240)}`, '200'],
              [faker.clock(interval), c2, `${bytes + rng.int(-6, 6)}`, `${rng.int(120, 240)}`, '200'],
              [faker.clock(interval * 2), c2, `${bytes + rng.int(-6, 6)}`, `${rng.int(120, 240)}`, '200'],
              [faker.clock(interval * 3), c2, `${bytes + rng.int(-6, 6)}`, `${rng.int(120, 240)}`, '200'],
              ['...', c2, '≈ constant', 'small', '200'],
            ],
          ),
          'Fixed interval + near-constant payload size across hours.',
        ),
        artifact(
          'Enrichment',
          'kv',
          kvBlock([
            ['Source', `${srcIp} (${host})`],
            ['Destination', `${c2} -> ${c2Ip}`],
            ['Domain age', `${rng.int(1, 12)} days`],
            ['TLS JA3', 'Rare fingerprint, not seen elsewhere in the org'],
            ['User agent', 'Absent / non-browser'],
            ['Duration', `Continuous for ${rng.int(6, 40)} hours`],
            ['Business relevance', 'None — destination not a known service'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1071.001'],
        tactics: ['command-and-control'],
      },
      rubric: rubric([
        ['cadence', 'Fixed interval with jitter and near-constant payload size is a classic beacon.', ['beacon', 'interval', 'cadence', 'jitter', 'constant']],
        ['newdest', 'Destination is a days-old domain with no business relevance and a rare JA3.', ['new domain', 'ja3', 'no business', 'rare', 'destination']],
        ['nobrowser', 'No/absent user agent and non-browser TLS points at an implant, not a person.', ['user agent', 'non-browser', 'implant', 'automated']],
        ['contain', 'Isolate the host, block the C2, and identify the beaconing process.', ['isolate', 'block', 'contain', 'process', 'implant']],
      ]),
      explanation: [
        `Human web traffic is irregular. An implant checking in with its controller is periodic: here a connection every ~${interval} seconds with a little jitter, near-constant small payloads, sustained for many hours. That regularity is the signature of a C2 beacon (Cobalt Strike, Sliver, and commodity RATs all do this).`,
        `Enrichment removes the doubt — a days-old destination domain with no business purpose, a rare TLS JA3 fingerprint seen nowhere else in the environment, and no browser user agent. That is machine-to-controller traffic, not someone browsing.`,
        `Escalate: isolate ${host}, block ${c2}/${c2Ip}, and pivot on the endpoint to find the process owning the beacon and its persistence. Extract the interval/jitter/JA3 as hunting IOCs for other beaconing hosts.`,
      ],
      pitfalls: [
        'Some legitimate software polls on a schedule — but to known domains, with a normal user agent, and a common TLS fingerprint.',
        'Jitter is meant to defeat naive interval detection; look at payload-size consistency and destination reputation together.',
      ],
      references: [
        { label: 'ATT&CK T1071.001 Web Protocols', url: 'https://attack.mitre.org/techniques/T1071/001/' },
      ],
    };
  },
};

export const networkTemplates: CaseTemplate[] = [
  internalPortScan,
  authorizedScan,
  dnsTunneling,
  c2Beacon,
];
