// EDR and Windows Security noise for endpoints and servers. Deliberate decoys
// for every endpoint template:
//  - the SCCM agent runs *encoded* PowerShell as SYSTEM (inventory script)
//  - admins run certutil -hashfile and PowerShell interactively
//  - engineers create 7z archives
//  - updaters register scheduled tasks and services; IT registers a
//    PowerShell cleanup task under a change ticket
//  - Kerberos/NTLM logons to file servers and DCs all day, fat-fingered 4625s
//  - nightly backup service-account logons across servers

import type { Person } from '../../world/world.ts';
import type { CorpusBuilder } from '../corpus.ts';
import { BIN, binaryHash, binaryPath, documentName, type Binary } from '../../synth/software.ts';
import { utf16leBase64 } from '../../synth/encoding.ts';
import { atLocalHour, DAY, HOUR, MIN, SEC } from '../time.ts';
import { within, type Session } from './presence.ts';
import type { NoiseCtx } from './context.ts';

const INVENTORY_SCRIPT =
  "$ErrorActionPreference='SilentlyContinue'; Get-CimInstance -ClassName Win32_InstalledWin32Program | Select-Object Name,Version,Vendor | ConvertTo-Json -Compress | Out-File -Encoding utf8 'C:\\Windows\\CCM\\Inventory\\apps.json'";
export const SCCM_INVENTORY_B64 = utf16leBase64(INVENTORY_SCRIPT);

function isWindows(s: Session): boolean {
  return s.device.os.startsWith('Windows');
}

interface ProcOpts {
  t: number;
  device: string;
  account: string;
  bin: Binary;
  cmd: string;
  parent: Binary;
  parentCmd?: string;
  integrity?: string;
  user?: string;
}

export function emitProc(b: CorpusBuilder, o: ProcOpts) {
  return b.proc({
    TimeGenerated: o.t,
    DeviceName: o.device,
    AccountName: o.account,
    FileName: o.bin.file,
    FolderPath: binaryPath(o.bin, o.user ?? o.account),
    ProcessCommandLine: o.cmd,
    SHA256: binaryHash(o.bin.file),
    Signer: o.bin.signer,
    ProcessIntegrityLevel: o.integrity ?? (o.account === 'SYSTEM' ? 'System' : 'Medium'),
    InitiatingProcessFileName: o.parent.file,
    InitiatingProcessCommandLine: o.parentCmd ?? o.parent.file,
  });
}

function q(path: string): string {
  return path.includes(' ') ? `"${path}"` : path;
}

export function endpointNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const ad = w.org.netbios;
  const fileServerFor = (p: Person) => (p.siteId === 'branch' ? 'FS02' : 'FS01');
  let certutilSeen = false;

  for (const s of n.sessions) {
    const p = s.person;
    const dev = s.device.name;
    const sam = p.sam;
    const win = isWindows(s);
    const t0 = s.start;

    // ---- Windows Security: interactive logon on the laptop, Kerberos to DC/FS.
    if (win) {
      b.sec({ TimeGenerated: t0, Computer: dev, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${sam}`, LogonType: s.location === 'office' ? 2 : 11, IpAddress: '127.0.0.1', WorkstationName: dev, AuthenticationPackage: 'Negotiate', ElevatedToken: 'No' });
      if (rng.bool(0.04)) {
        b.sec({ TimeGenerated: t0 - rng.int(10, 60) * SEC, Computer: dev, EventID: 4625, Account: '-', TargetAccount: `${ad}\\${sam}`, LogonType: 2, IpAddress: '127.0.0.1', WorkstationName: dev, AuthenticationPackage: 'Negotiate', Status: '0xC000006D', SubStatus: '0xC000006A' });
      }
      const unlocks = rng.int(0, 3);
      for (let i = 0; i < unlocks; i++) {
        b.sec({ TimeGenerated: within(rng, s), Computer: dev, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${sam}`, LogonType: 7, IpAddress: '127.0.0.1', WorkstationName: dev, AuthenticationPackage: 'Negotiate', ElevatedToken: 'No' });
      }
    }
    const dc = rng.pick(['DC01', 'DC02']);
    b.sec({ TimeGenerated: t0 + rng.int(2, 20) * SEC, Computer: dc, EventID: 4768, Account: '-', TargetAccount: `${ad}\\${sam}`, IpAddress: s.lanIp, WorkstationName: dev, AuthenticationPackage: 'Kerberos', Status: '0x0' });
    const fsLogons = rng.int(1, 4);
    for (let i = 0; i < fsLogons; i++) {
      const fs = rng.bool(0.8) ? fileServerFor(p) : rng.pick(['FS01', 'FS02', 'APP01', 'PRINT01']);
      const t = within(rng, s);
      b.sec({ TimeGenerated: t, Computer: fs, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${sam}`, LogonType: 3, IpAddress: s.lanIp, WorkstationName: dev, AuthenticationPackage: 'Kerberos', ElevatedToken: 'No' });
      if (rng.bool(0.6)) b.sec({ TimeGenerated: t + rng.int(1, 90) * MIN, Computer: fs, EventID: 4634, Account: '-', TargetAccount: `${ad}\\${sam}`, LogonType: 3 });
    }

    if (!win) continue;

    // ---- Processes: logon chain, then the working day.
    const user = sam;
    emitProc(b, { t: t0 + 2 * SEC, device: dev, account: user, bin: BIN.explorer, cmd: 'C:\\Windows\\Explorer.EXE', parent: BIN.userinit });
    const startup: Binary[] = [BIN.onedrive, BIN.teams, BIN.outlook, s.browser === 'Chrome' ? BIN.chrome : BIN.msedge];
    startup.forEach((bin, i) => {
      emitProc(b, { t: t0 + (10 + i * rng.int(4, 30)) * SEC, device: dev, account: user, bin, cmd: bin === BIN.onedrive ? `${q(binaryPath(bin, user))} /background` : q(binaryPath(bin, user)), parent: BIN.explorer, parentCmd: 'C:\\Windows\\Explorer.EXE' });
    });
    const docs = rng.int(2, 6);
    for (let i = 0; i < docs; i++) {
      const kind = rng.pickWeighted([
        { value: 'docx', weight: 3 },
        { value: 'xlsx', weight: p.department === 'Finance' ? 6 : 3 },
        { value: 'pptx', weight: 1 },
        { value: 'pdf', weight: 2 },
      ]);
      const bin = kind === 'docx' ? BIN.winword : kind === 'xlsx' ? BIN.excel : kind === 'pptx' ? BIN.powerpnt : BIN.acrobat;
      const doc = documentName(rng, p.department, kind);
      const path = `C:\\Users\\${user}\\OneDrive - ${w.org.name}\\${p.department}\\${doc}`;
      const t = within(rng, s);
      emitProc(b, { t, device: dev, account: user, bin, cmd: `${q(binaryPath(bin, user))} /n "${path}"`, parent: BIN.explorer, parentCmd: 'C:\\Windows\\Explorer.EXE' });
      if (kind !== 'pdf' && rng.bool(0.6)) {
        b.file({ TimeGenerated: t + rng.int(3, 50) * MIN, DeviceName: dev, ActionType: 'FileModified', FileName: doc, FolderPath: path, FileSize: rng.int(18_000, 2_400_000), SHA256: rng.hex(64), InitiatingProcessFileName: bin.file, InitiatingProcessAccountName: user });
      }
    }
    if (rng.bool(0.35)) {
      const t = within(rng, s);
      const name = rng.pick([`Invoice_${rng.int(10000, 99999)}.pdf`, `Statement_${rng.int(1, 12)}_2026.pdf`, `agenda_${rng.int(1, 30)}.pdf`, 'ZoomInstallerFull.msi', `brochure-${rng.alnum(4)}.pdf`]);
      b.file({ TimeGenerated: t, DeviceName: dev, ActionType: 'FileCreated', FileName: name, FolderPath: `C:\\Users\\${user}\\Downloads\\${name}`, FileSize: rng.int(40_000, 9_000_000), SHA256: rng.hex(64), InitiatingProcessFileName: s.browser === 'Chrome' ? 'chrome.exe' : 'msedge.exe', InitiatingProcessAccountName: user });
    }
    if (rng.bool(0.2)) emitProc(b, { t: within(rng, s), device: dev, account: user, bin: BIN.zoom, cmd: `${q(binaryPath(BIN.zoom, user))} --url=zoommtg://zoom.us/join?confno=${rng.int(80000000000, 99999999999)}`, parent: BIN.outlook });

    // Engineers: editor, terminal, git, node, and release archives (7z decoy).
    if (p.department === 'Engineering') {
      emitProc(b, { t: within(rng, s), device: dev, account: user, bin: BIN.code, cmd: `${q(binaryPath(BIN.code, user))} C:\\src\\${w.org.tenant}-platform`, parent: BIN.explorer });
      const ops = rng.int(3, 8);
      for (let i = 0; i < ops; i++) {
        const t = within(rng, s);
        const op = rng.pick(['git fetch --prune', 'git pull --rebase', 'git push origin HEAD', 'npm run build', 'npm test', 'python -m pytest -q']);
        const bin = op.startsWith('git') ? BIN.git : op.startsWith('npm') ? BIN.node : BIN.python;
        emitProc(b, { t, device: dev, account: user, bin, cmd: op.startsWith('npm') ? `"C:\\Program Files\\nodejs\\node.exe" "C:\\Program Files\\nodejs\\node_modules\\npm\\bin\\npm-cli.js" ${op.slice(4)}` : op.startsWith('python') ? `${q(binaryPath(BIN.python, user))} ${op.slice(7)}` : `"C:\\Program Files\\Git\\cmd\\git.exe" ${op.slice(4)}`, parent: BIN.pwsh, parentCmd: '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo' });
      }
      if (rng.bool(0.3)) {
        const t = within(rng, s);
        const ver = `${rng.int(3, 5)}.${rng.int(0, 20)}.${rng.int(0, 9)}`;
        emitProc(b, { t, device: dev, account: user, bin: BIN.sevenzip, cmd: `"C:\\Program Files\\7-Zip\\7z.exe" a release-${ver}.7z .\\dist\\*`, parent: BIN.pwsh, parentCmd: '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -NoLogo' });
        b.file({ TimeGenerated: t + rng.int(5, 40) * SEC, DeviceName: dev, ActionType: 'FileCreated', FileName: `release-${ver}.7z`, FolderPath: `C:\\src\\${w.org.tenant}-platform\\release-${ver}.7z`, FileSize: rng.int(8_000_000, 90_000_000), SHA256: rng.hex(64), InitiatingProcessFileName: '7z.exe', InitiatingProcessAccountName: user });
      }
    }

    // IT: interactive PowerShell, RDP to the jump host, certutil -hashfile (decoy).
    if (p.department === 'IT' || p.department === 'Security') {
      const cmds = [
        'Get-ADUser -Filter * -Properties LastLogonDate | Sort-Object LastLogonDate | Select-Object -First 20',
        'Test-NetConnection FS01 -Port 445',
        'Get-Service -ComputerName APP01 -Name W3SVC',
        'Get-WinEvent -LogName Security -MaxEvents 50',
        'Invoke-Command -ComputerName PRINT01 -ScriptBlock { Restart-Service Spooler }',
      ];
      const ps = rng.int(1, 3);
      for (let i = 0; i < ps; i++) {
        emitProc(b, { t: within(rng, s), device: dev, account: user, bin: BIN.powershell, cmd: `powershell.exe -NoExit -Command "${rng.pick(cmds)}"`, parent: BIN.explorer });
      }
      if (rng.bool(0.6)) {
        // Admins reach servers through the jump host with their -adm account.
        const t = within(rng, s);
        emitProc(b, { t, device: dev, account: user, bin: BIN.mstsc, cmd: 'mstsc.exe /v:JUMP01', parent: BIN.explorer });
        const acct = p.adminAccount ?? sam;
        if (rng.bool(0.15)) b.sec({ TimeGenerated: t + 5 * SEC, Computer: 'JUMP01', EventID: 4625, Account: '-', TargetAccount: `${ad}\\${acct}`, LogonType: 10, IpAddress: s.lanIp, WorkstationName: dev, AuthenticationPackage: 'Negotiate', Status: '0xC000006D', SubStatus: '0xC000006A' });
        b.sec({ TimeGenerated: t + 20 * SEC, Computer: 'JUMP01', EventID: 4624, Account: '-', TargetAccount: `${ad}\\${acct}`, LogonType: 10, IpAddress: s.lanIp, WorkstationName: dev, AuthenticationPackage: 'Kerberos', ElevatedToken: 'Yes' });
      }
      if (rng.bool(0.6) || !certutilSeen) {
        certutilSeen = true;
        emitProc(b, { t: within(rng, s), device: dev, account: user, bin: BIN.certutil, cmd: `certutil.exe -hashfile "C:\\Users\\${user}\\Downloads\\${rng.pick(['vendor-agent-2.8.1.msi', 'firmware_fw01_9.4.bin', 'PowerShell-7.4.6-win-x64.msi'])}" SHA256`, parent: BIN.powershell, parentCmd: 'powershell.exe -NoExit' });
      }
    }

    // Everyone: management agents as SYSTEM.
    if (rng.bool(0.45)) {
      emitProc(b, { t: within(rng, s, 30), device: dev, account: 'SYSTEM', bin: BIN.powershell, cmd: `powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ${SCCM_INVENTORY_B64}`, parent: BIN.ccmexec, parentCmd: 'C:\\Windows\\CCM\\CcmExec.exe', integrity: 'System' });
    }
    if (rng.bool(0.5)) emitProc(b, { t: within(rng, s), device: dev, account: 'SYSTEM', bin: BIN.mpcmdrun, cmd: '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe" SignatureUpdate -ScheduleJob -RestrictPrivileges', parent: BIN.svchost, parentCmd: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', integrity: 'System' });
    if (rng.bool(0.3)) emitProc(b, { t: within(rng, s), device: dev, account: 'SYSTEM', bin: BIN.googleupdater, cmd: `${q(BIN.googleupdater.path)} --wake --system`, parent: BIN.svchost, parentCmd: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', integrity: 'System' });
    if (rng.bool(0.25)) emitProc(b, { t: within(rng, s), device: dev, account: 'SYSTEM', bin: BIN.officec2r, cmd: `${q(BIN.officec2r.path)} /frequentupdate SCHEDULEDTASK displaylevel=False`, parent: BIN.svchost, parentCmd: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', integrity: 'System' });

    // ---- Network: internal services by the right processes.
    const internal: [string, number, Binary][] = [
      [fileServerFor(p), 445, { file: 'system', path: 'System', signer: 'Microsoft Windows' }],
      [dc, 389, BIN.lsass],
      [dc, 88, BIN.lsass],
      ['SCCM01', 443, BIN.ccmexec],
    ];
    for (const [hostName, port, proc] of internal) {
      if (!rng.bool(0.7)) continue;
      const h = b.idx.host(hostName);
      b.net({ TimeGenerated: within(rng, s), DeviceName: dev, LocalIP: s.lanIp, RemoteIP: h.ip, RemotePort: port, RemoteUrl: `${hostName.toLowerCase()}.${w.org.adFqdn}`, Protocol: port === 88 && rng.bool(0.3) ? 'Udp' : 'Tcp', InitiatingProcessFileName: proc.file, InitiatingProcessAccountName: proc === BIN.ccmexec || proc === BIN.lsass || proc.file === 'system' ? 'SYSTEM' : user });
    }
  }

  serverNoise(n);
  installerNoise(n);
}

function serverNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const ad = w.org.netbios;
  const off = n.off;
  const bkp = b.idx.host('BKP01');

  // Nightly backups: svc-backup logs on to file and DB servers.
  for (let day = atLocalHour(b.windowStart - DAY, 0, off); day < b.windowEnd; day += DAY) {
    const start = atLocalHour(day, 1 + rng.float(0, 0.5), off);
    for (const target of ['FS01', 'FS02', 'SQL01', 'APP01']) {
      const t = start + rng.int(0, 90) * MIN;
      if (t < b.windowStart || t > b.windowEnd) continue;
      b.sec({ TimeGenerated: t, Computer: target, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-backup`, LogonType: 3, IpAddress: bkp.ip, WorkstationName: 'BKP01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'Yes' });
      b.fw({ TimeGenerated: t + 5 * SEC, Direction: 'Internal', Action: 'Allow', SourceIP: bkp.ip, SourcePort: rng.int(49152, 65000), DestinationIP: b.idx.host(target).ip, DestinationPort: 445, RuleName: 'allow-backup-smb', BytesSent: rng.int(40_000, 400_000), BytesReceived: rng.int(2_000_000_000, 9_000_000_000), SessionDurationSec: rng.int(1200, 5400) });
    }
  }

  // SCCM pushes: svc-sccm network logons to endpoints during the day.
  const sccm = b.idx.host('SCCM01');
  const pushes = rng.int(4, 10);
  for (let i = 0; i < pushes; i++) {
    const target = rng.pick(b.idx.endpoints());
    const t = atLocalHour(rng.int(b.windowStart, b.windowEnd), rng.float(9, 17), off);
    if (t < b.windowStart || t > b.windowEnd) continue;
    b.sec({ TimeGenerated: t, Computer: target.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-sccm`, LogonType: 3, IpAddress: sccm.ip, WorkstationName: 'SCCM01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'Yes' });
  }

  // DCs forward DNS upstream.
  const upstream = w.internet.hosting.slice(0, 2);
  for (let t = b.windowStart + rng.int(1, 30) * MIN; t < b.windowEnd; t += rng.int(15, 45) * MIN) {
    const dc = b.idx.host(rng.pick(['DC01', 'DC02']));
    b.fw({ TimeGenerated: t, Direction: 'Outbound', Action: 'Allow', Protocol: 'UDP', SourceIP: dc.ip, SourcePort: rng.int(49152, 65000), DestinationIP: rng.pick(upstream), DestinationPort: 53, RuleName: 'allow-dns-forwarders', BytesSent: rng.int(60, 300), BytesReceived: rng.int(90, 900), SessionDurationSec: 0 });
  }
}

// Updaters and IT tooling that register tasks/services — the decoys for
// persistence and remote-service alerts.
function installerNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const ad = w.org.netbios;
  const endpoints = b.idx.endpoints().filter((h) => h.os.startsWith('Windows'));
  const tasks = [
    { name: '\\GoogleSystem\\GoogleUpdater\\GoogleUpdaterTaskSystem131.0.6727.0{8E1B6F42-2F52-4B39-B5D1-6C7B8C0E1A7D}', action: `"${BIN.googleupdater.path}" --wake --system` },
    { name: '\\Microsoft\\Office\\Office Automatic Updates 2.0', action: `"${BIN.officec2r.path}" /frequentupdate SCHEDULEDTASK displaylevel=False` },
    { name: '\\OneDrive Standalone Update Task-S-1-5-21-2217428907-1137862516-2918475122-1604', action: '%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe /reporting' },
    { name: '\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB', action: '"C:\\Program Files\\Mozilla Firefox\\default-browser-agent.exe" do-task "308046B0AF4A39CB"' },
    { name: '\\Adobe Acrobat Update Task', action: '"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"' },
  ];
  const count = rng.int(3, 7);
  for (let i = 0; i < count; i++) {
    const host = rng.pick(endpoints);
    const task = rng.pick(tasks);
    b.sec({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), Computer: host.name, EventID: 4698, Account: `${ad}\\${host.name}$`, TaskName: task.name, TaskAction: task.action });
  }
  const services = [
    { name: 'GoogleUpdaterInternalService131.0.6727.0', file: `"${BIN.googleupdater.path}" --system --windows-service --service=update-internal` },
    { name: 'AdobeARMservice', file: '"C:\\Program Files (x86)\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe"' },
    { name: 'ZoomCptService', file: '"C:\\Program Files\\Common Files\\Zoom\\Support\\CptService.exe" -user_path "C:\\Users\\Public"' },
  ];
  const svcCount = rng.int(1, 3);
  for (let i = 0; i < svcCount; i++) {
    const host = rng.pick(endpoints);
    const svc = rng.pick(services);
    b.sec({ TimeGenerated: rng.int(b.windowStart, b.windowEnd), Computer: host.name, EventID: 7045, Account: 'LocalSystem', ServiceName: svc.name, ServiceFileName: svc.file });
  }

  // IT's own maintenance task, created by an admin account under a change.
  const admins = w.people.filter((p) => p.adminAccount);
  if (admins.length && rng.bool(0.6)) {
    const adm = rng.pick(admins);
    const host = rng.pick(['APP01', 'FS01', 'PRINT01']);
    const t = rng.int(b.windowStart + HOUR, b.windowEnd - HOUR);
    const chg = n.nextTicket('CHG');
    b.ticket({ TicketId: chg, Type: 'Change', Title: `Deploy temp-file cleanup task to ${host}`, Requester: adm.upn, AssignedTo: `${adm.adminAccount}@${w.org.domain}`, Status: 'Approved', Created: t - rng.int(2, 6) * DAY, WindowStart: t - HOUR, WindowEnd: t + 2 * HOUR, Scope: host, Details: 'Weekly cleanup of C:\\Windows\\Temp older than 14 days. Script reviewed in IT repo.' });
    b.sec({ TimeGenerated: t, Computer: host, EventID: 4698, Account: `${ad}\\${adm.adminAccount}`, TaskName: '\\IT\\WeeklyTempCleanup', TaskAction: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\IT\\Scripts\\Cleanup-Temp.ps1 (Weekly, Sunday 03:00, SYSTEM)' });
  }

  // Fleet updates pushed from SCCM, under a standing change.
  if (rng.bool(0.5)) {
    const chg = n.nextTicket('CHG');
    const t = atLocalHour(rng.int(b.windowStart, b.windowEnd), rng.float(12, 16), n.off);
    b.ticket({ TicketId: chg, Type: 'Change', Title: 'Monthly application updates via SCCM (pilot ring)', Requester: 'IT Infrastructure', AssignedTo: 'svc-sccm', Status: 'Scheduled', Created: t - 5 * DAY, WindowStart: t - HOUR, WindowEnd: t + 5 * HOUR, Scope: 'Pilot ring workstations', Details: 'Browser, PDF reader and conferencing client updates.' });
  }
}
