// Network scenarios. Twin: an internal host sweeping the network after a
// foothold vs. the authorised vulnerability scanner. C2 templates compete with
// the fixed-cadence telemetry and CDN-label noise the generators plant.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { HOUR, MIN, SEC } from '../../logs/time.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { base32 } from '../../synth/encoding.ts';
import { domain, host, ip, kdt, rubric, sha, technique, user } from './util.ts';

// ---------------------------------------------------------------------------
// Internal host running a horizontal port scan after a foothold (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const SCAN_BRIEFING = (org: string) =>
  `${org}: the NDR sensor watches east-west traffic between VLANs. The security team runs an authorised weekly vulnerability scan.`;

const internalPortScan: CaseTemplate = {
  id: 'network-internal-portscan',
  category: 'recon',
  difficulty: 'tier2',
  title: 'Horizontal port scan from an internal address',
  lesson: 'Post-compromise discovery from a user laptop',
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
    const site = idx.siteOf(victim);
    const prefix = site.prefix;
    const ports = [22, 135, 139, 445, 3389, 5985];
    const minutes = rng.int(4, 25);
    const t0 = at - minutes * MIN - rng.int(2, 6) * MIN;
    const c2 = ctx.infra.domain('c2', { style: 'tech' });
    const c2ip = ctx.infra.ip('c2');
    const tFoot = t0 - rng.int(4, 8) * MIN;
    const foot = log.proc({ TimeGenerated: tFoot, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA…', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'winword.exe', InitiatingProcessCommandLine: '"WINWORD.EXE"' });
    log.dns({ TimeGenerated: tFoot + 3 * SEC, ClientIP: src, Computer: 'DC01', Name: c2 });
    const beacon: RowRef[] = [];
    for (let t = tFoot + 5 * SEC; t < ctx.now - 30 * SEC && beacon.length < 12; t += rng.int(50, 70) * SEC) {
      beacon.push(log.net({ TimeGenerated: t, DeviceName: dev.name, LocalIP: src, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam }));
    }
    const scanTool = log.proc({ TimeGenerated: t0, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -nop -c "[script block truncated by EDR — 1.9 KB: loop over subnet hosts and ports 22,135,139,445,3389,5985]"', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden -enc …' });
    // The sweep. Real servers on this site answer on SMB/RDP.
    const servers = idx.servers().filter((h) => h.siteId === site.id && h.ip.startsWith(`${prefix}.`));
    const answering = rng.sample(servers.filter((h) => h.name !== 'DC01' && h.name !== 'DC02'), Math.min(3, servers.length));
    const answerIps = new Set(answering.map((h) => h.ip));
    const targets = new Set<string>(answerIps);
    const want = rng.int(180, 420);
    while (targets.size < want) targets.add(`${prefix}.${rng.pick([10, 10, 20, 21, 22, 100])}.${rng.int(2, 250)}`);
    const scans: RowRef[] = [];
    const list = rng.shuffle([...targets]);
    list.forEach((dst, i) => {
      const t = t0 + Math.floor((i / list.length) * minutes * MIN);
      for (const port of rng.sample(ports, rng.int(1, 3))) {
        const open = answerIps.has(dst) && (port === 445 || port === 3389);
        const row = log.fw({ TimeGenerated: t + rng.int(0, 900), Direction: 'Internal', Action: open ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: src, SourcePort: rng.int(49152, 65000), DestinationIP: dst, DestinationPort: port, RuleName: open ? 'allow-smb-fileservers' : 'east-west-default', BytesSent: open ? rng.int(120, 400) : 0, BytesReceived: open ? rng.int(80, 300) : 0, SessionDurationSec: 0 });
        if (scans.length < 60 || open) scans.push(row);
      }
    });
    // Follow-on: SMB sessions to the hosts that answered.
    const follow: RowRef[] = [];
    answering.forEach((h, i) => {
      const t = t0 + minutes * MIN + (i + 1) * rng.int(30, 90) * SEC;
      follow.push(log.net({ TimeGenerated: t, DeviceName: dev.name, LocalIP: src, RemoteIP: h.ip, RemotePort: 445, RemoteUrl: `${h.name.toLowerCase()}.${world.org.adFqdn}`, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam }));
      follow.push(log.fw({ TimeGenerated: t, Direction: 'Internal', Action: 'Allow', Protocol: 'TCP', SourceIP: src, SourcePort: rng.int(49152, 65000), DestinationIP: h.ip, DestinationPort: 445, RuleName: 'allow-smb-fileservers', BytesSent: rng.int(4_000, 60_000), BytesReceived: rng.int(8_000, 200_000), SessionDurationSec: rng.int(5, 90) }));
    });
    const devInfo = log.deviceRef(dev.name);

    return {
      alert: {
        rule: 'Horizontal port scan from internal host',
        product: 'Network Detection & Response',
        severity: 'high',
        time: at,
        summary: `${src} attempted connections to ${targets.size} internal hosts across ports ${ports.join('/')} in ~${minutes} minutes.`,
        entities: [{ kind: 'ip', value: src, label: 'Source' }],
        fields: [['Distinct destinations', String(targets.size)], ['Ports probed', ports.join(', ')]],
      },
      briefing: SCAN_BRIEFING(world.org.name),
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1046'], tactics: ['discovery'], alsoAccept: ['T1018', 'T1135', 'T1059.001', 'T1021.002'] },
      evidence: [
        { id: 'source', label: `The scanning address belongs to ${dev.name}, a ${victim.department} ${dev.role.toLowerCase()} — not the vulnerability scanner`, why: 'The identical pattern from SCAN01 would be routine. From a user laptop it is not.', rows: [devInfo] },
        { id: 'sweep', label: 'A sweep of the internal ranges across admin ports', why: 'Network service discovery — mapping what is reachable before moving.', rows: scans },
        { id: 'foothold', label: 'A macro-spawned encoded PowerShell ran on the host minutes earlier, is beaconing out, and launched the scan', why: 'The scan is a symptom; the foothold is the cause.', rows: [foot, scanTool, ...beacon] },
        { id: 'follow', label: `It then opened SMB sessions to the servers that answered (${answering.map((h) => h.name).join(', ')})`, why: 'Discovery turning into lateral movement.', rows: follow },
      ],
      indicators: { block: [domain(c2, 'C2 from the foothold'), ip(c2ip)], scope: [host(dev.name), user(victim)], mustNot: [host('SCAN01'), ip(idx.host('SCAN01').ip, 'Authorised scanner'), ...answering.map((h) => host(h.name))] },
      hints: [
        'A sweep like this is exactly what the authorised scanner does. Everything turns on one question: is the source the scanner, or something with no business scanning?',
        `Resolve the address to a device. It may not be in the CMDB if it is a VPN address — endpoints report their own local IP: DeviceNetworkEvents | where LocalIP == "${src}" | summarize count() by DeviceName`,
        'Once you have the device, look at what ran on it in the minutes before the sweep, and where it connected afterwards.',
      ],
      solution: [
        { title: 'Which device has that address?', kql: `DeviceNetworkEvents\n| where LocalIP == "${src}"\n| summarize count() by DeviceName`, why: `${dev.name}. (Over VPN, the CMDB address differs — the endpoint's own telemetry is the reliable link.)` },
        { title: 'What is that device?', kql: `DeviceInfo\n| where DeviceName == "${dev.name}"`, why: `A ${victim.department} ${dev.role.toLowerCase()} owned by ${victim.display} — not SCAN01.` },
        { title: 'The sweep', kql: `FirewallLogs\n| where SourceIP == "${src}" and Direction == "Internal"\n| summarize Destinations = dcount(DestinationIP), Ports = make_set(DestinationPort), Allowed = countif(Action == "Allow") by SourceIP`, why: 'Hundreds of destinations across admin ports in minutes.' },
        { title: 'Sample of the sweep', kql: `FirewallLogs\n| where SourceIP == "${src}" and Direction == "Internal"\n| project TimeGenerated, DestinationIP, DestinationPort, Action\n| take 60`, why: 'Mostly denied — a few servers answered.' },
        { title: 'What launched it?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and TimeGenerated > ${kdt(tFoot - 2 * MIN)}\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'A macro-spawned encoded PowerShell, then the sweep.' },
        { title: "PowerShell's connections from the host", kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and InitiatingProcessFileName == "powershell.exe"\n| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl`, why: `Beaconing to ${c2}, then SMB to the servers that answered.` },
        { title: 'Firewall view of the follow-on', kql: `FirewallLogs\n| where SourceIP == "${src}" and Action == "Allow" and SessionDurationSec > 0\n| project TimeGenerated, DestinationIP, DestinationPort, BytesSent, BytesReceived`, why: 'Real SMB sessions, not just probes.' },
      ],
      rubric: rubric([
        ['pattern', 'A sweep of internal ranges across admin ports = active network discovery.', ['scan', 'sweep', 'discovery', 'port', 'horizontal']],
        ['wronghost', `The source is a ${victim.department} laptop, not the authorised scanner.`, ['workstation', 'laptop', 'not scanner', 'unexpected', victim.department.toLowerCase()]],
        ['precursor', 'An encoded PowerShell ran minutes earlier and is beaconing — the compromise that led to the recon.', ['powershell', 'precursor', 'compromise', 'foothold', 'beacon']],
        ['contain', 'Isolate the host, treat the scan as post-compromise recon, and check the servers it reached over SMB.', ['isolate', 'contain', 'post-compromise', 'lateral', 'smb']],
      ]),
      explanation: [
        `One internal address fanning out to ${targets.size} hosts across admin ports in about ${minutes} minutes is a horizontal port scan — network service discovery. The pattern is indistinguishable from the weekly authorised scan, which is the whole point of the twin: you cannot disposition on the pattern.`,
        `The source decides it. ${src} is ${dev.name} (${victim.first}'s ${dev.role.toLowerCase()} in ${victim.department}), not SCAN01 — and because it may be a VPN address, the CMDB alone might not say so; the endpoint's own network telemetry does. Minutes before the sweep a macro-spawned encoded PowerShell ran on it and began beaconing to ${c2}; the scan itself was launched by PowerShell; and afterwards it opened SMB sessions to the servers that answered. Foothold, enumeration, lateral movement.`,
        `Escalate and isolate ${dev.name}. Scope back to the PowerShell execution as initial access, and forward to ${answering.map((h) => h.name).join(', ')}, which it reached over SMB.`,
      ],
      pitfalls: [
        'The same scan from SCAN01 would be benign — the source identity is decisive.',
        'A VPN address may not match the CMDB. Resolve the source through endpoint telemetry before concluding it is unknown.',
        "Don't flag the servers it reached — they are victims to check, not indicators to block.",
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
  difficulty: 'tier2',
  title: 'Horizontal port scan from an internal address',
  lesson: 'The authorised weekly vulnerability scan',
  cysaDomains: ['1.0', '2.0'],
  kind: 'benign',
  twin: 'network-internal-portscan',
  when: 'business',
  build(ctx) {
    const { rng, log, idx, at, world } = ctx;
    const scanner = idx.host('SCAN01');
    const src = scanner.ip;
    const ports = [22, 135, 139, 445, 3389, 5985];
    const minutes = rng.int(15, 45);
    const t0 = at - minutes * MIN - rng.int(2, 6) * MIN;
    const chg = log.ticket({
      TicketId: 'CHG-STD-0007', Type: 'Change', Title: 'Standing approval — weekly authenticated vulnerability scan', Requester: 'Security — Vulnerability Management', AssignedTo: 'svc-scan',
      Status: 'Approved', Created: at - rng.int(30, 120) * 24 * HOUR, WindowStart: t0 - 10 * MIN, WindowEnd: t0 + 4 * HOUR, Scope: 'All server and workstation VLANs',
      Details: 'Recurring credentialed scan from SCAN01 (Nessus) using the read-only svc-scan account. Runs weekly during business hours.',
    });
    const prefix = world.sites[0].prefix;
    const targets = new Set<string>();
    const want = rng.int(180, 420);
    while (targets.size < want) targets.add(`${prefix}.${rng.pick([10, 10, 20, 21, 22, 100])}.${rng.int(2, 250)}`);
    const scans: RowRef[] = [];
    const list = rng.shuffle([...targets]);
    list.forEach((dst, i) => {
      const t = t0 + Math.floor((i / list.length) * minutes * MIN);
      for (const port of rng.sample(ports, rng.int(1, 3))) {
        const row = log.fw({ TimeGenerated: t + rng.int(0, 900), Direction: 'Internal', Action: rng.bool(0.5) ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: src, SourcePort: rng.int(49152, 65000), DestinationIP: dst, DestinationPort: port, RuleName: 'allow-scanner', BytesSent: rng.int(200, 4000), BytesReceived: rng.int(0, 8000), SessionDurationSec: rng.int(0, 3) });
        if (scans.length < 60) scans.push(row);
      }
    });
    const ad = world.org.netbios;
    const creds: RowRef[] = [];
    for (const target of rng.sample(idx.servers(), 8)) {
      creds.push(log.sec({ TimeGenerated: t0 + rng.int(1, minutes) * MIN, Computer: target.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-scan`, LogonType: 3, IpAddress: src, WorkstationName: 'SCAN01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'No' }));
    }
    const scannerInfo = log.deviceRef('SCAN01');
    const acctInfo = log.identityRef('svc-scan');

    return {
      alert: {
        rule: 'Horizontal port scan from internal host',
        product: 'Network Detection & Response',
        severity: 'high',
        time: at,
        summary: `${src} attempted connections to ${targets.size} internal hosts across ports ${ports.join('/')} in ~${minutes} minutes.`,
        entities: [{ kind: 'ip', value: src, label: 'Source' }],
        fields: [['Distinct destinations', String(targets.size)], ['Ports probed', ports.join(', ')]],
      },
      briefing: SCAN_BRIEFING(world.org.name),
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'source', label: 'The source is SCAN01, the authorised vulnerability scanner', why: 'Same traffic pattern as an attacker sweep, but from the sanctioned scanner asset.', rows: [scannerInfo] },
        { id: 'change', label: 'A standing change approval covers the weekly scan window', why: 'Recurring authorised activity, on schedule.', rows: [chg] },
        { id: 'credentialed', label: 'Credentialed Kerberos logons from the read-only svc-scan account', why: 'Vulnerability management, not an intruder — attackers do not hold the scan account.', rows: [...creds, acctInfo] },
      ],
      indicators: { block: [], scope: [], mustNot: [host('SCAN01'), ip(src, 'Authorised scanner'), { kind: 'user', value: 'svc-scan', aliases: [`${ad}\\svc-scan`] }] },
      hints: [
        'A sweep like this is exactly what the authorised scanner does. Everything turns on one question: is the source the scanner, or something with no business scanning?',
        `Resolve the address to a device: DeviceInfo | where IPAddress == "${src}"`,
        'If it is the scanner, confirm the approval and how it authenticated.',
      ],
      solution: [
        { title: 'What is the source?', kql: `DeviceInfo\n| where IPAddress == "${src}"`, why: 'SCAN01, the authorised vulnerability scanner.' },
        { title: 'Is it approved?', kql: 'Tickets\n| where Scope has "VLAN" or AssignedTo == "svc-scan"', why: 'A standing weekly change approval.' },
        { title: 'Credentialed checks?', kql: 'SecurityEvent\n| where TargetAccount has "svc-scan" and EventID == 4624\n| project TimeGenerated, Computer, AuthenticationPackage, WorkstationName', why: 'Kerberos logons from SCAN01 using the read-only scan account.' },
        { title: 'What account is that?', kql: 'IdentityInfo\n| where AccountName == "svc-scan"', why: 'Read-only, owned by Vulnerability Management.' },
      ],
      rubric: rubric([
        ['knownscanner', 'The source is the sanctioned scanner (SCAN01) in the scanner asset group.', ['scanner', 'nessus', 'scan01', 'authorised', 'authorized']],
        ['schedule', 'The timing matches the standing weekly scan approval.', ['schedule', 'weekly', 'window', 'approved', 'standing']],
        ['credentialed', 'Credentialed checks from a read-only scan account = vuln management, not an attacker.', ['credentialed', 'read-only', 'scan account', 'svc-scan', 'kerberos']],
        ['tune', 'Benign; close and suppress NDR scan alerts from the scanner source.', ['benign', 'close', 'suppress', 'tune', 'allowlist']],
      ]),
      explanation: [
        `The traffic is indistinguishable from an attacker's sweep — that is the twin. The source is SCAN01, the organisation's authorised scanner, running its weekly credentialed scan on schedule.`,
        `Everything corroborates authorised activity: a standing change approval, credentialed Kerberos logons from the read-only svc-scan account, and coverage of the expected VLANs. None of the internal-recon red flags — an unexpected source device, a preceding compromise, follow-on SMB sessions — are present.`,
        `Disposition benign, informational. Close it and reduce noise by suppressing NDR scan alerts sourced from SCAN01, so the queue keeps flagging the sweeps you do care about.`,
      ],
      pitfalls: [
        'Huge scan volume is expected from a real scanner; volume is not severity.',
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
  title: 'Unusual DNS query volume',
  lesson: 'DNS tunnelling to a days-old domain',
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
    const t0 = at - rng.int(65, 90) * MIN;
    const dllHash = ctx.infra.hash('loader');
    const dllPath = `C:\\Users\\Public\\${rng.pick(['svc', 'msupd', 'cache'])}.dll`;
    const dllFile = log.file({ TimeGenerated: t0 - 2 * MIN, DeviceName: dev.name, ActionType: 'FileCreated', FileName: dllPath.split('\\').pop()!, FolderPath: dllPath, FileSize: rng.int(180_000, 420_000), SHA256: dllHash, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam });
    const proc = log.proc({ TimeGenerated: t0 - 30 * SEC, DeviceName: dev.name, AccountName: victim.sam, FileName: 'rundll32.exe', FolderPath: BIN.rundll32.path, ProcessCommandLine: `rundll32.exe ${dllPath},Run`, SHA256: binaryHash('rundll32.exe'), Signer: BIN.rundll32.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden' });
    const shown: RowRef[] = [];
    let lastHour = 0;
    const bytes = () => Array.from({ length: rng.int(18, 28) }, () => rng.int(0, 255));
    for (let t = t0; t < ctx.now - 5 * SEC; t += rng.int(2, 6) * SEC) {
      const label = base32(bytes()).slice(0, rng.int(30, 50));
      const row = log.dns({ TimeGenerated: t, ClientIP: src, Computer: resolver, Name: `${label}.${tunnel}`, QueryType: rng.pickWeighted([{ value: 'TXT', weight: 7 }, { value: 'NULL', weight: 2 }, { value: 'A', weight: 1 }]), ResponseCode: 'NOERROR', IPAddresses: '' });
      if (shown.length < 200) shown.push(row);
      if (t >= at - HOUR && t <= at) lastHour++;
    }
    const intel = log.domainIntelRef(tunnel);

    return {
      alert: {
        rule: 'Possible DNS tunneling',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${src} made ${lastHour.toLocaleString('en-US')} DNS queries to a single domain in the last hour — mostly TXT/NULL with long, high-entropy labels.`,
        entities: [
          { kind: 'ip', value: src, label: 'Client' },
          { kind: 'domain', value: tunnel },
        ],
        fields: [['Queries (last hour)', lastHour.toLocaleString('en-US')], ['Typical per domain', '< 30 per hour']],
      },
      briefing: `${world.org.name}: DNS is allowed outbound to the internal resolvers for everyone — the classic covert channel. Some legitimate software is chatty over DNS.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1071.004'], tactics: ['command-and-control'], alsoAccept: ['T1572', 'T1048', 'T1568.002', 'T1041', 'T1048.003', 'T1105'] },
      evidence: [
        { id: 'volume', label: `A continuous stream of unique high-entropy subdomains under ${tunnel}, mostly TXT/NULL`, why: 'Normal DNS is low-volume and caches. Unique long base32 labels are data carried in query names, not lookups.', rows: shown },
        { id: 'newdomain', label: `${tunnel} is a days-old, suspicious domain`, why: 'Purpose-built tunneling infrastructure.', rows: [intel] },
        { id: 'process', label: `rundll32 on ${dev.name} is running an unsigned DLL from C:\\Users\\Public`, why: 'rundll32 itself is a signed Windows binary; what it loads is the implant driving the channel.', rows: [proc, dllFile] },
      ],
      indicators: { block: [domain(tunnel, 'DNS tunnel / C2'), sha(dllHash, 'Implant DLL')], scope: [host(dev.name), user(victim)], mustNot: [domain('microsoft.com'), host(resolver), ip(idx.host(resolver).ip, 'Internal resolver')] },
      hints: [
        'Some software is chatty over DNS. Tunneling differs in volume, record type, label length and caching. Which client is it, and which device is that?',
        `DnsEvents | summarize Queries = count(), Unique = dcount(Name), TXT = countif(QueryType == "TXT") by Domain | sort by Unique`,
        `Resolve the client to a device (DeviceNetworkEvents or DeviceInfo), then look at what is running there.`,
      ],
      solution: [
        { title: 'Which domains are anomalous?', kql: 'DnsEvents\n| summarize Queries = count(), Unique = dcount(Name), TXT = countif(QueryType == "TXT") by Domain\n| sort by Unique', why: `${tunnel} dwarfs everything: nearly one unique name per query, almost all TXT.` },
        { title: 'Confirm the signature', kql: `DnsEvents\n| where Domain == "${tunnel}"\n| summarize Queries = count(), UniqueNames = dcount(Name), AvgLen = avg(strlen(Name)) by ClientIP, QueryType`, why: 'One client, ~unique-per-query, long labels — data carriers.' },
        { title: 'Sample the queries', kql: `DnsEvents\n| where Domain == "${tunnel}"\n| project TimeGenerated, ClientIP, Name, QueryType\n| take 50`, why: 'Base32-looking labels, one per query.' },
        { title: 'How old is the domain?', kql: `DomainIntel\n| where Domain == "${tunnel}"`, why: 'Days old, suspicious.' },
        { title: 'Which device is the client?', kql: `DeviceInfo\n| where IPAddress == "${src}" or DeviceName == "${dev.name}"`, why: `${dev.name}, ${victim.display}'s ${dev.role.toLowerCase()}.` },
        { title: 'What on that host is doing it?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and FileName == "rundll32.exe"\n| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessCommandLine`, why: 'rundll32 loading a DLL from C:\\Users\\Public, launched by hidden PowerShell.' },
        { title: 'The DLL itself', kql: `DeviceFileEvents\n| where DeviceName == "${dev.name}" and FileName endswith ".dll"\n| project TimeGenerated, FolderPath, SHA256, InitiatingProcessFileName`, why: 'Unsigned, written minutes before the tunnel started — the hash to block and hunt.' },
      ],
      rubric: rubric([
        ['volume', 'Thousands of unique high-entropy subdomains to one domain = data encoded into DNS.', ['volume', 'entropy', 'subdomain', 'encoded', 'unique']],
        ['recordtype', 'Heavy TXT/NULL use is abnormal for browsing and typical of tunneling.', ['txt', 'null', 'record', 'tunnel', 'abnormal']],
        ['newdomain', 'The domain is days old and suspicious — attacker infrastructure.', ['newly registered', 'new domain', 'days old', 'suspicious', 'infrastructure']],
        ['contain', 'Isolate the host, sinkhole/block the domain, assess for exfiltration, and remove the implant.', ['isolate', 'sinkhole', 'block', 'exfil', 'implant']],
      ]),
      explanation: [
        `Normal DNS is low-volume and benefits from caching. Here one client sent ${lastHour.toLocaleString('en-US')} queries to a single domain in the hour before the alert, nearly all with unique 30–50 character high-entropy labels and TXT/NULL record types — base32 data in the query names. That is DNS tunneling, a covert C2 (and potential exfiltration) channel that slips through firewalls because DNS is universally allowed.`,
        `${tunnel} was registered days ago and has a suspicious reputation — purpose-built infrastructure. The client is ${dev.name}, where rundll32 (itself a signed Windows binary) is running an unsigned DLL from C:\\Users\\Public that was written by hidden PowerShell minutes before the tunnel started.`,
        `Escalate: isolate ${dev.name}, sinkhole or block ${tunnel} at the resolver, block and hunt the DLL hash, and assess what may have left through the channel.`,
      ],
      pitfalls: [
        'Some CDNs and security products are chatty over DNS — but not with thousands of unique high-entropy TXT labels to a days-old domain.',
        'Blocking the domain stops the channel but leaves the implant generating it.',
        `Don't flag ${resolver} — it is your resolver forwarding the queries, not the source.`,
        'rundll32 is signed and normal; the unsigned DLL it loads is the finding.',
      ],
      references: [technique('T1071.004'), technique('T1572')],
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
  title: 'Periodic outbound connections',
  lesson: 'C2 beacon from a masquerading updater',
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
    const interval = rng.pick([45, 60, 90]);
    const bytes = rng.int(280, 460);
    // Every beacon is logged, right up to now; the series starts inside the
    // window and is capped so the table stays a reasonable size.
    const maxBeacons = 420;
    const wanted = rng.int(5, 12) * HOUR;
    const span = Math.min(wanted, maxBeacons * interval * SEC, ctx.now - ctx.log.windowStart - 30 * MIN);
    const t0 = ctx.now - span;
    const beacons: RowRef[] = [];
    const netRows: RowRef[] = [];
    let lastDns = -Infinity;
    for (let t = t0, i = 0; t < ctx.now - 20 * SEC; t += interval * SEC + rng.int(-interval * 100, interval * 100), i++) {
      beacons.push(log.proxy({ TimeGenerated: t, SourceIP: src, SourceUser: victim.sam, Method: 'GET', Url: `https://${c2}/api/v1/status`, DestinationHost: c2, DestinationIP: c2ip, DestinationPort: 443, StatusCode: 200, BytesSent: bytes + rng.int(-6, 6), BytesReceived: rng.int(120, 240), Category: 'Uncategorized', UserAgent: '' }));
      // The resolver answer is cached for five minutes.
      if (t - lastDns > 5 * MIN) {
        log.dns({ TimeGenerated: t - 1 * SEC, ClientIP: src, Computer: 'DC01', Name: c2 });
        lastDns = t;
      }
      // EDR aggregates repeated connections; roughly one event in five is kept.
      if (i % 5 === 0) netRows.push(log.net({ TimeGenerated: t, DeviceName: dev.name, LocalIP: src, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: 'onedriveupdater.exe', InitiatingProcessAccountName: victim.sam }));
    }
    const proc = log.proc({ TimeGenerated: t0 - 30 * SEC, DeviceName: dev.name, AccountName: victim.sam, FileName: 'onedriveupdater.exe', FolderPath: `C:\\Users\\${victim.sam}\\AppData\\Local\\Temp\\OneDriveUpdater.exe`, ProcessCommandLine: `C:\\Users\\${victim.sam}\\AppData\\Local\\Temp\\OneDriveUpdater.exe`, SHA256: ctx.infra.hash('loader'), Signer: 'Unsigned', ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: 'C:\\Windows\\Explorer.EXE' });
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
