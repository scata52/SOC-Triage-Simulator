// Network scenarios. Twin: an internal host sweeping the network after a
// foothold vs. the authorised vulnerability scanner. C2 templates compete with
// the fixed-cadence telemetry and CDN-label noise the generators plant.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { HOUR, MIN, SEC } from '../../logs/time.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { base32 } from '../../synth/encoding.ts';
import { domain, host, ip, kdt, rubric, technique, user } from './util.ts';

// ---------------------------------------------------------------------------
// Internal host running a horizontal port scan after a foothold (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const internalPortScan: CaseTemplate = {
  id: 'network-internal-portscan',
  category: 'recon',
  difficulty: 'tier2',
  title: 'A workstation is scanning the internal network',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  twin: 'network-authorized-vulnscan',
  stages: ['discovery'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true, dept: ['Finance', 'Sales', 'HR', 'Marketing', 'Operations', 'Legal'] });
    const dev = idx.deviceOf(victim);
    const w = pick.where(victim, at);
    const src = w.lanIp;
    const prefix = idx.siteOf(victim).prefix;
    const ports = [22, 135, 139, 445, 3389, 5985];
    const t0 = at - rng.int(5, 9) * MIN;
    // Foothold: an encoded PowerShell minutes earlier.
    const c2 = ctx.infra.domain('c2', { style: 'tech' });
    const c2ip = ctx.infra.ip('c2');
    const foot = log.proc({ TimeGenerated: t0 - rng.int(3, 6) * MIN, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA…', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'winword.exe', InitiatingProcessCommandLine: '"WINWORD.EXE"' });
    const scanTool = log.proc({ TimeGenerated: t0, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -nop -c "[script block truncated by EDR — 1.9 KB: loop over subnet hosts and ports 22,135,139,445,3389,5985]"', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden -enc …' });
    const scans: RowRef[] = [];
    const dsts = rng.int(240, 520);
    for (let i = 0; i < dsts; i++) {
      const third = rng.pick([10, 10, 10, 20, 21, 100]);
      const dstIp = `${prefix}.${third}.${rng.int(2, 250)}`;
      const port = rng.pick(ports);
      const open = [10].includes(third) && [445, 3389, 135].includes(port) && rng.bool(0.3);
      const row = log.fw({ TimeGenerated: t0 + Math.floor((i / dsts) * 3.5 * MIN) + rng.int(0, 200), Direction: 'Internal', Action: open ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: src, SourcePort: rng.int(49152, 65000), DestinationIP: dstIp, DestinationPort: port, RuleName: open ? 'allow-smb-fileservers' : 'east-west-default', BytesSent: open ? rng.int(120, 400) : 0, BytesReceived: 0, SessionDurationSec: 0 });
      if (i < 40 || open) scans.push(row);
    }
    // Follow-on: connections to the hosts that answered.
    const answered = [`${prefix}.10.11`, `${prefix}.10.13`];
    const follow = answered.map((dip) => log.net({ TimeGenerated: t0 + 4 * MIN + rng.int(0, 60) * SEC, DeviceName: dev.name, LocalIP: src, RemoteIP: dip, RemotePort: 445, RemoteUrl: '', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam }));
    log.dns({ TimeGenerated: t0 - 4 * MIN, ClientIP: src, Computer: 'DC01', Name: c2 });
    log.net({ TimeGenerated: t0 - 4 * MIN + 2 * SEC, DeviceName: dev.name, LocalIP: src, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam });
    const devInfo = log.deviceRef(dev.name);

    return {
      alert: {
        rule: 'Horizontal port scan from internal host',
        product: 'Network Detection & Response',
        severity: 'high',
        time: at,
        summary: `${src} (${dev.name}) attempted connections to ${dsts}+ internal hosts across ports 22/135/139/445/3389/5985 in ~4 minutes.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'ip', value: src },
        ],
        fields: [['Distinct destinations', String(dsts)], ['Pattern', 'Sequential sweep, SYN only']],
      },
      briefing: `${world.org.name} runs a weekly authorised vulnerability scan from SCAN01. ${dev.name} belongs to ${victim.display} (${victim.title}, ${victim.department}).`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1046'], tactics: ['discovery'], alsoAccept: ['T1018', 'T1135', 'T1059.001', 'T1021.002'] },
      evidence: [
        { id: 'source', label: `The scanning host is ${dev.name} — a ${victim.department} ${dev.role.toLowerCase()}, not the vulnerability scanner`, why: 'The identical pattern from SCAN01 would be routine. From a finance laptop it is not.', rows: [devInfo] },
        { id: 'sweep', label: 'A sequential sweep of the internal ranges across admin ports', why: 'Network service discovery — mapping what is reachable before moving.', rows: scans },
        { id: 'foothold', label: 'An encoded PowerShell ran on the same host minutes earlier and the scan was launched by PowerShell', why: 'The scan is a symptom; the foothold is the cause. It is already beaconing.', rows: [foot, scanTool] },
        { id: 'follow', label: 'It then connected to the hosts that answered on 445', why: 'Moving from discovery toward lateral movement.', rows: follow },
      ],
      indicators: { block: [domain(c2, 'C2 from the foothold'), ip(c2ip)], scope: [host(dev.name), user(victim)], mustNot: [host('SCAN01'), ip(idx.host('SCAN01').ip, 'Authorised scanner')] },
      hints: [
        'A sweep like this is exactly what the authorised scanner does. So the only question that matters: is the source SCAN01, or something that has no business scanning?',
        `DeviceInfo | where DeviceName == "${dev.name}"`,
        `What ran on that host just before the scan? DeviceProcessEvents | where DeviceName == "${dev.name}" and TimeGenerated > ${kdt(t0 - 10 * MIN)}`,
      ],
      solution: [
        { title: 'Who is the source?', kql: `DeviceInfo\n| where DeviceName == "${dev.name}"`, why: `A ${victim.department} ${dev.role.toLowerCase()} owned by ${victim.display}, not SCAN01. (Over VPN its address comes from the VPN pool, so look it up by name.)` },
        { title: 'The sweep', kql: `FirewallLogs\n| where SourceIP == "${src}" and Direction == "Internal"\n| summarize Destinations = dcount(DestinationIP), Ports = make_set(DestinationPort) by SourceIP`, why: 'Hundreds of destinations across admin ports in minutes.' },
        { title: 'What launched it?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and TimeGenerated > ${kdt(t0 - 10 * MIN)}\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'A macro-spawned encoded PowerShell, then a Test-NetConnection sweep.' },
        { title: 'Where did it go next?', kql: `FirewallLogs\n| where SourceIP == "${src}" and Action == "Allow" and Direction == "Internal"\n| project TimeGenerated, DestinationIP, DestinationPort`, why: 'Connections to the hosts that answered on SMB.' },
        { title: "PowerShell's connections from the host", kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and InitiatingProcessFileName == "powershell.exe"\n| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessAccountName`, why: `A beacon to ${c2} from the foothold, then SMB to the hosts the sweep found.` },
      ],
      rubric: rubric([
        ['pattern', 'A sequential internal sweep across admin ports = active network discovery.', ['scan', 'sweep', 'discovery', 'port', 'horizontal']],
        ['wronghost', `The source is a ${victim.department} workstation, not the authorised scanner — it has no business scanning.`, ['finance', 'workstation', 'not scanner', 'unexpected', victim.department.toLowerCase()]],
        ['precursor', 'An encoded PowerShell ran minutes earlier — the compromise that led to the recon.', ['powershell', 'precursor', 'compromise', 'foothold', 'macro']],
        ['contain', 'Isolate the host, treat the scan as post-compromise recon, and follow the SMB connections it made.', ['isolate', 'contain', 'post-compromise', 'lateral', 'escalate']],
      ]),
      explanation: [
        `A single internal host fanning out to hundreds of destinations across 22/135/139/445/3389/5985 in a few minutes is a horizontal port scan — network service discovery. The pattern is identical to the weekly authorised scan, which is the whole point of the twin: you cannot disposition on the pattern.`,
        `The source decides it. ${dev.name} is ${victim.first}'s ${dev.role.toLowerCase()} in ${victim.department}, not SCAN01, and it is not in the scanner asset group. Minutes before the sweep, a macro-spawned encoded PowerShell ran on it and began beaconing to ${c2}; the scan itself was launched by PowerShell. That sequence — foothold, then internal enumeration, then connections to the hosts that answered on SMB — is an attacker mapping the network before lateral movement.`,
        `Escalate and isolate ${dev.name}. Scope back to the PowerShell execution as the initial access and forward to the SMB connections the scan was preparing for.`,
      ],
      pitfalls: [
        'The same scan pattern from SCAN01 would be benign — the source identity is decisive.',
        'The earlier PowerShell is the thread to pull; the scan is a symptom, not the start.',
      ],
      references: [technique('T1046')],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: authorised vulnerability scan (BENIGN)
// ---------------------------------------------------------------------------
const authorizedScan: CaseTemplate = {
  id: 'network-authorized-vulnscan',
  category: 'recon',
  difficulty: 'tier1',
  title: 'Flood of scan alerts from one host',
  cysaDomains: ['1.0', '2.0'],
  kind: 'benign',
  twin: 'network-internal-portscan',
  when: 'business',
  build(ctx) {
    const { rng, log, idx, at, world } = ctx;
    const scanner = idx.host('SCAN01');
    const src = scanner.ip;
    const t0 = at - rng.int(45, 70) * MIN;
    const chg = log.ticket({
      TicketId: 'CHG-STD-0007', Type: 'Change', Title: 'Standing approval — weekly authenticated vulnerability scan', Requester: 'Security — Vulnerability Management', AssignedTo: 'svc-scan',
      Status: 'Approved', Created: at - rng.int(30, 120) * 24 * HOUR, WindowStart: t0 - 10 * MIN, WindowEnd: t0 + 4 * HOUR, Scope: 'All server and workstation VLANs',
      Details: 'Recurring credentialed scan from SCAN01 (Nessus) using the read-only svc-scan account. Runs weekly during business hours.',
    });
    const scans: RowRef[] = [];
    const dsts = rng.int(300, 500);
    const prefix = world.sites[0].prefix;
    for (let i = 0; i < dsts; i++) {
      const third = rng.pick([10, 20, 21, 100]);
      const dstIp = `${prefix}.${third}.${rng.int(2, 250)}`;
      const port = rng.pick([22, 80, 135, 139, 443, 445, 1433, 3389, 5985, 8080]);
      const row = log.fw({ TimeGenerated: t0 + Math.floor((i / dsts) * 50 * MIN) + rng.int(0, 200), Direction: 'Internal', Action: rng.bool(0.5) ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: src, SourcePort: rng.int(49152, 65000), DestinationIP: dstIp, DestinationPort: port, RuleName: 'allow-scanner', BytesSent: rng.int(200, 4000), BytesReceived: rng.int(0, 8000), SessionDurationSec: rng.int(0, 3) });
      if (i < 60) scans.push(row);
    }
    // Credentialed logons from the scan account.
    const ad = world.org.netbios;
    const creds: RowRef[] = [];
    for (const target of rng.sample(idx.servers(), 8)) {
      creds.push(log.sec({ TimeGenerated: t0 + rng.int(1, 45) * MIN, Computer: target.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-scan`, LogonType: 3, IpAddress: src, WorkstationName: 'SCAN01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'No' }));
    }
    const scannerInfo = log.deviceRef('SCAN01');
    const acctInfo = log.identityRef('svc-scan');

    return {
      alert: {
        rule: 'Excessive port scan / probe alerts from one host',
        product: 'Network Detection & Response',
        severity: 'high',
        time: at,
        summary: `Thousands of scan and probe alerts from ${src} against multiple VLANs over the last hour.`,
        entities: [
          { kind: 'host', value: 'SCAN01' },
          { kind: 'ip', value: src },
        ],
        fields: [['Alert volume', `${rng.int(4000, 12000)} in 60 min`], ['Probe types', 'TCP connect, service/version, credentialed checks']],
      },
      briefing: `${world.org.name}: the Vulnerability Management team runs weekly authenticated scans. SCAN01 is the scanner appliance; svc-scan is its read-only account.`,
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'source', label: 'The source is SCAN01, the authorised vulnerability scanner', why: 'Same traffic pattern as an attacker sweep, but from the sanctioned scanner asset.', rows: [scannerInfo] },
        { id: 'change', label: 'A standing change approval covers the weekly scan window', why: 'Recurring authorised activity, on schedule.', rows: [chg] },
        { id: 'credentialed', label: 'Credentialed Kerberos logons from the read-only svc-scan account', why: 'Vulnerability management, not an intruder — attackers do not have the scan account or run credentialed checks.', rows: [...creds, acctInfo] },
      ],
      indicators: { block: [], scope: [], mustNot: [host('SCAN01'), ip(src, 'Authorised scanner'), { kind: 'user', value: 'svc-scan', aliases: [`${ad}\\svc-scan`] }] },
      hints: [
        'Volume is not severity. The scanner produces exactly this. Confirm the source really is SCAN01 and that there is an approval, then close.',
        `DeviceInfo | where IPAddress == "${src}"`,
        'Tickets | where AssignedTo == "svc-scan"',
      ],
      solution: [
        { title: 'What is the source?', kql: `DeviceInfo\n| where IPAddress == "${src}"`, why: 'SCAN01, the authorised vulnerability scanner.' },
        { title: 'Is it approved?', kql: 'Tickets\n| where Scope has "VLAN" or AssignedTo == "svc-scan"', why: 'A standing weekly change approval.' },
        { title: 'Credentialed checks?', kql: 'SecurityEvent\n| where TargetAccount has "svc-scan" and EventID == 4624\n| summarize Hosts = dcount(Computer) by AuthenticationPackage, WorkstationName', why: 'Kerberos logons from SCAN01 using the read-only scan account.' },
        { title: 'What account is that?', kql: 'IdentityInfo\n| where AccountName == "svc-scan"', why: 'Read-only, owned by Vulnerability Management.' },
      ],
      rubric: rubric([
        ['knownscanner', 'The source is the sanctioned scanner (SCAN01) in the scanner asset group.', ['scanner', 'nessus', 'scan01', 'authorised', 'authorized']],
        ['schedule', 'The timing matches the standing weekly scan approval.', ['schedule', 'weekly', 'window', 'approved', 'standing']],
        ['credentialed', 'Credentialed checks from a read-only scan account = vuln management, not an attacker.', ['credentialed', 'read-only', 'scan account', 'svc-scan', 'kerberos']],
        ['tune', 'Benign; close and suppress NDR scan alerts from the scanner source.', ['benign', 'close', 'suppress', 'tune', 'allowlist']],
      ]),
      explanation: [
        `The traffic looks identical to an attacker's sweep — that is the twin. The source is SCAN01, the organisation's authorised scanner, in the scanner asset group, running its weekly credentialed scan on schedule.`,
        `Everything corroborates authorised activity: a standing change approval, credentialed Kerberos logons from the read-only svc-scan account, and coverage of the expected VLANs. None of the internal-recon red flags — an unexpected source workstation, a preceding compromise — are present.`,
        `Disposition benign, informational. Close it and reduce noise by suppressing NDR scan alerts sourced from SCAN01, so the queue keeps flagging the sweeps you do care about.`,
      ],
      pitfalls: [
        'Huge scan-alert volume is expected from a real scanner; volume is not severity.',
        'Do confirm the source really is the scanner asset — verifying is exactly why the twin exists.',
      ],
      references: [{ label: 'Vulnerability scanning (NIST)', url: 'https://csrc.nist.gov/glossary/term/vulnerability_scanning' }],
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
  kind: 'incident',
  stages: ['objective'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true });
    const dev = idx.deviceOf(victim);
    const w = pick.where(victim, at);
    const src = w.lanIp;
    const tunnel = ctx.infra.domain('tunnel', { style: 'dga', ageDays: rng.int(2, 9), category: 'Newly Registered Domain', reputation: 'Suspicious' });
    const resolver = victim.siteId === 'branch' ? 'DC02' : 'DC01';
    const t0 = at - rng.int(55, 75) * MIN;
    const total = rng.int(9000, 40000);
    const shown: RowRef[] = [];
    const bytes = () => new Uint8Array(Array.from({ length: rng.int(18, 26) }, () => rng.int(0, 255)));
    for (let i = 0; i < 60; i++) {
      const label = base32(bytes()).slice(0, rng.int(30, 50));
      shown.push(log.dns({ TimeGenerated: t0 + i * rng.int(1, 4) * SEC, ClientIP: src, Computer: resolver, Name: `${label}.${tunnel}`, QueryType: rng.pickWeighted([{ value: 'TXT', weight: 7 }, { value: 'NULL', weight: 2 }, { value: 'A', weight: 1 }]), ResponseCode: 'NOERROR', IPAddresses: '' }));
    }
    const avgLen = rng.int(32, 48);
    const intel = log.domainIntelRef(tunnel);
    // The process behind it: a beaconing implant using nslookup-like resolver calls.
    const proc = log.proc({ TimeGenerated: t0 - 30 * SEC, DeviceName: dev.name, AccountName: victim.sam, FileName: 'rundll32.exe', FolderPath: BIN.rundll32.path, ProcessCommandLine: 'rundll32.exe C:\\Users\\Public\\svc.dll,Run', SHA256: ctx.infra.hash('loader'), Signer: 'Unsigned', ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: 'C:\\Windows\\Explorer.EXE' });

    return {
      alert: {
        rule: 'Possible DNS tunneling',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${dev.name} (${src}) issued ${total.toLocaleString('en-US')} DNS queries to a single domain in one hour — almost all TXT/NULL with long, high-entropy labels.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'domain', value: tunnel },
        ],
        fields: [['Queries (1h)', total.toLocaleString('en-US')], ['Record types', 'TXT 71% / NULL 24% / A 5%'], ['Avg label length', `${avgLen} chars`]],
      },
      briefing: `${world.org.name}: DNS is allowed outbound to the internal resolvers for everyone — the classic covert channel. Some legitimate software is chatty over DNS.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1071.004', 'T1048'], tactics: ['command-and-control', 'exfiltration'], alsoAccept: ['T1568.002', 'T1041', 'T1048.003', 'T1105'] },
      evidence: [
        { id: 'volume', label: `Thousands of unique high-entropy subdomains under ${tunnel}, mostly TXT/NULL`, why: 'Normal DNS is low-volume and caches. Unique long base32 labels are data encoded into query names, not lookups.', rows: shown },
        { id: 'newdomain', label: `${tunnel} is a days-old, suspicious domain`, why: 'Purpose-built tunneling infrastructure.', rows: [intel] },
        { id: 'process', label: 'An unsigned rundll32-loaded DLL on the host is driving it', why: 'The implant behind the channel — root-cause the endpoint.', rows: [proc] },
      ],
      indicators: { block: [domain(tunnel, 'DNS tunnel / C2')], scope: [host(dev.name), user(victim)], mustNot: [domain('microsoft.com'), host(resolver), ip(idx.host(resolver).ip, 'Internal resolver')] },
      hints: [
        'Some software is chatty over DNS. Tunneling is different in volume, record type, label length and caching. And which internal host is the source?',
        `DnsEvents | where Domain == "${tunnel}" | summarize Queries = count(), Unique = dcount(Name), AvgLen = avg(strlen(Name)) by ClientIP`,
        'DnsEvents\n| summarize Queries = count(), Unique = dcount(Name) by Domain\n| sort by Unique',
      ],
      solution: [
        { title: 'Which domains are anomalous?', kql: 'DnsEvents\n| summarize Queries = count(), Unique = dcount(Name), TXT = countif(QueryType == "TXT") by Domain\n| sort by Unique', why: `${tunnel} dwarfs everything: thousands of unique names, almost all TXT.` },
        { title: 'Confirm the signature', kql: `DnsEvents\n| where Domain == "${tunnel}"\n| summarize Queries = count(), UniqueNames = dcount(Name), AvgLabelLen = avg(strlen(Name)) by ClientIP, QueryType`, why: 'One host, ~unique-per-query, long labels — data carriers, not lookups.' },
        { title: 'How old is the domain?', kql: `DomainIntel\n| where Domain == "${tunnel}"`, why: 'Days old, suspicious.' },
        { title: 'Which host is it?', kql: `DeviceInfo\n| where IPAddress == "${src}" or DeviceName == "${dev.name}"`, why: `${dev.name}, ${victim.display}'s ${dev.role.toLowerCase()}.` },
        { title: 'What on that host is generating it?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and Signer == "Unsigned"\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'An unsigned DLL loaded by rundll32 — the implant driving the tunnel.' },
        { title: 'Sample the queries', kql: `DnsEvents\n| where ClientIP == "${src}" and Domain == "${tunnel}"\n| project TimeGenerated, Name, QueryType\n| take 20`, why: 'Long base32 labels, one per query.' },
      ],
      rubric: rubric([
        ['volume', 'Thousands of unique high-entropy subdomains to one domain = data encoded into DNS.', ['volume', 'entropy', 'subdomain', 'encoded', 'unique']],
        ['recordtype', 'Heavy TXT/NULL use is abnormal for browsing and typical of tunneling.', ['txt', 'null', 'record', 'tunnel', 'abnormal']],
        ['newdomain', 'The domain is days old and suspicious — attacker infrastructure.', ['newly registered', 'new domain', 'days old', 'suspicious', 'infrastructure']],
        ['contain', 'Isolate the host, sinkhole/block the domain, assess for exfiltration, and find the implant.', ['isolate', 'sinkhole', 'block', 'exfil', 'implant']],
      ]),
      explanation: [
        `Normal DNS is low-volume and benefits from caching. Here one host fires tens of thousands of queries in an hour, almost all with unique 30–50 character high-entropy labels and TXT/NULL record types. That is base32-encoded data in the query names — DNS tunneling used as covert C2 and exfiltration, which slips through firewalls because DNS is universally allowed. Chatty legitimate software does not produce thousands of unique long TXT labels to a days-old domain.`,
        `${tunnel} and its records point to purpose-built attacker infrastructure — registered days ago, suspicious reputation. The lack of any caching benefit (a unique name per query) is the giveaway that these are carriers, not lookups.`,
        `Escalate: isolate ${dev.name}, sinkhole or block ${tunnel} at the resolver, and assess what may have been exfiltrated. On the endpoint an unsigned DLL loaded by rundll32 is driving the channel — that is the implant to remove.`,
      ],
      pitfalls: [
        'Some CDNs and AV products are chatty over DNS — but not thousands of unique high-entropy TXT labels to a days-old domain.',
        'Blocking the domain stops the channel but leaves the implant generating it.',
        `Don't flag ${resolver} — it is your resolver forwarding the queries, not the source.`,
      ],
      references: [technique('T1071.004'), technique('T1048')],
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
  kind: 'incident',
  stages: ['execution'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true });
    const dev = idx.deviceOf(victim);
    const w = pick.where(victim, at);
    const src = w.lanIp;
    const c2 = ctx.infra.domain('c2', { style: 'tech', ageDays: rng.int(1, 12) });
    const c2ip = ctx.infra.ip('c2');
    const interval = rng.pick([30, 45, 60]);
    const bytes = rng.int(280, 460);
    const t0 = at - rng.int(6, 20) * HOUR;
    const beacons: RowRef[] = [];
    for (let t = t0; t < ctx.now - MIN; t += interval * SEC + rng.int(-interval * 100, interval * 100)) {
      if (beacons.length < 80) {
        beacons.push(log.proxy({ TimeGenerated: t, SourceIP: src, SourceUser: victim.sam, Method: 'GET', Url: `https://${c2}/api/v1/status`, DestinationHost: c2, DestinationIP: c2ip, DestinationPort: 443, StatusCode: 200, BytesSent: bytes + rng.int(-6, 6), BytesReceived: rng.int(120, 240), Category: 'Uncategorized', UserAgent: '' }));
      }
      log.dns({ TimeGenerated: t - 1 * SEC, ClientIP: src, Computer: 'DC01', Name: c2 });
    }
    const proc = log.proc({ TimeGenerated: t0 - 30 * SEC, DeviceName: dev.name, AccountName: victim.sam, FileName: 'onedriveupdater.exe', FolderPath: `C:\\Users\\${victim.sam}\\AppData\\Local\\Temp\\OneDriveUpdater.exe`, ProcessCommandLine: 'C:\\Users\\...\\Temp\\OneDriveUpdater.exe', SHA256: ctx.infra.hash('loader'), Signer: 'Unsigned', ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: 'C:\\Windows\\Explorer.EXE' });
    const netRows = beacons.slice(0, 20).map((_, i) => log.net({ TimeGenerated: t0 + i * interval * SEC, DeviceName: dev.name, LocalIP: src, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: 'onedriveupdater.exe', InitiatingProcessAccountName: victim.sam }));
    const intel = log.domainIntelRef(c2);
    const hours = Math.round((ctx.now - t0) / HOUR);

    return {
      alert: {
        rule: 'Beaconing to a rare external destination',
        product: 'Network Detection & Response',
        severity: 'medium',
        time: at,
        summary: `${dev.name} connects to ${c2} every ~${interval}s (±jitter) with near-constant payload sizes, for ${hours}+ hours.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'domain', value: c2 },
        ],
        fields: [['Interval', `~${interval}s with jitter`], ['User agent', 'Absent']],
      },
      briefing: `${world.org.name}: the web proxy allows general browsing. Legitimate software also polls on a schedule — telemetry, update checks — so cadence alone is not enough.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1071.001'], tactics: ['command-and-control'], alsoAccept: ['T1573', 'T1105', 'T1036.005'] },
      evidence: [
        { id: 'cadence', label: `A fixed ~${interval}s interval with jitter and near-constant payloads for hours, to ${c2}`, why: 'Machine-to-controller regularity, unlike human browsing — and, unlike telemetry, to a rare days-old destination with no user agent.', rows: beacons },
        { id: 'destination', label: `${c2} is a days-old domain with no business relevance and no user agent`, why: 'Legitimate telemetry goes to known vendor domains with a normal client string.', rows: [intel] },
        { id: 'process', label: 'An unsigned "OneDriveUpdater.exe" in a Temp folder owns the connection', why: 'A masquerading implant, not the real updater.', rows: [proc, ...netRows] },
      ],
      indicators: { block: [domain(c2, 'C2'), ip(c2ip, 'C2')], scope: [host(dev.name), user(victim)], mustNot: [domain('settings-win.data.microsoft.com'), domain('officecdn.microsoft.com')] },
      hints: [
        'Legitimate polling exists — telemetry, updaters. What separates a beacon: destination age and reputation, user agent, and where the traffic actually comes from on the host.',
        `WebProxy | where DestinationHost == "${c2}" | summarize Count = count(), Bytes = make_set(BytesSent) by DestinationHost, UserAgent`,
        `Compare to the known-good pollers: WebProxy | summarize count() by DestinationHost, UserAgent | sort by count_`,
      ],
      solution: [
        { title: 'Profile the periodic destinations', kql: 'WebProxy\n| where isempty(UserAgent) or UserAgent !has "Mozilla"\n| summarize Count = count(), Dest = take_any(DestinationIP) by DestinationHost, UserAgent\n| sort by Count', why: `settings-win… (telemetry, known) and ${c2} (rare, no user agent).` },
        { title: 'How old / reputable is it?', kql: `DomainIntel\n| where Domain == "${c2}"`, why: 'Days old, no business use.' },
        { title: 'Confirm the cadence', kql: `WebProxy\n| where DestinationHost == "${c2}"\n| sort by TimeGenerated asc\n| extend Gap = datetime_diff("second", TimeGenerated, prev(TimeGenerated))\n| summarize Beacons = count(), MedianGap = avg(Gap), Bytes = make_set(BytesSent)`, why: 'A tight interval and near-constant payload size.' },
        { title: 'Look at the raw beacons', kql: `WebProxy\n| where DestinationHost == "${c2}"\n| project TimeGenerated, SourceUser, Url, BytesSent, BytesReceived, UserAgent\n| take 30`, why: 'Same URL, same size, no user agent, a steady rhythm.' },
        { title: 'What process owns it?', kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and RemoteUrl == "${c2}"\n| summarize count() by InitiatingProcessFileName`, why: 'An unsigned "OneDriveUpdater.exe" from a Temp folder — masquerading.' },
        { title: 'Is that the real updater?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and FileName == "onedriveupdater.exe"\n| project TimeGenerated, FolderPath, Signer, InitiatingProcessFileName`, why: 'Unsigned, from Temp — the genuine updater lives under the OneDrive program folder and is signed.' },
      ],
      rubric: rubric([
        ['cadence', 'Fixed interval with jitter and near-constant payload size is a classic beacon.', ['beacon', 'interval', 'cadence', 'jitter', 'constant']],
        ['newdest', 'Destination is a days-old domain with no business relevance.', ['new domain', 'days old', 'no business', 'destination', 'rare']],
        ['nobrowser', 'No user agent and a masquerading process point at an implant, not a person.', ['user agent', 'non-browser', 'implant', 'masquerad', 'onedriveupdater']],
        ['contain', 'Isolate the host, block the C2, and identify/remove the beaconing process.', ['isolate', 'block', 'contain', 'process', 'implant']],
      ]),
      explanation: [
        `Human web traffic is irregular. An implant checking in with its controller is periodic: here a connection every ~${interval} seconds with jitter, near-constant small payloads, sustained for ${hours} hours. Legitimate software polls too — the fleet's telemetry check-ins look similar — so cadence alone is not the verdict.`,
        `The destination is: ${c2} is days old, has no business purpose, and the traffic carries no user agent at all — whereas the telemetry pollers go to known Microsoft domains with a normal client string. On the endpoint the connection is owned by an unsigned "OneDriveUpdater.exe" running from a Temp folder — a masquerading implant, not the real updater.`,
        `Escalate: isolate ${dev.name}, block ${c2}/${c2ip}, and remove the process and its persistence. Extract the interval, payload size and destination as hunting indicators for other beaconing hosts.`,
      ],
      pitfalls: [
        'Some legitimate software polls on a schedule — but to known domains, with a normal user agent.',
        'Jitter defeats naive interval detection; weigh payload consistency, destination reputation and the owning process together.',
      ],
      references: [technique('T1071.001')],
    };
  },
};

export const networkTemplates: CaseTemplate[] = [internalPortScan, authorizedScan, dnsTunneling, c2Beacon];
