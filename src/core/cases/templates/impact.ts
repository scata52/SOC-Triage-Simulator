// Lateral movement, privilege escalation, exfiltration and ransomware. The
// destructive and credential-theft steps are shown the way a defender sees
// them in EDR/Windows telemetry — process image, parent, host, account and a
// summarised argument string — never as reproducible commands.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { DAY, MIN, SEC } from '../../logs/time.ts';
import { BIN, binaryHash, documentName } from '../../synth/software.ts';
import { domain, host, ip, kdt, rubric, technique, user } from './util.ts';

// ---------------------------------------------------------------------------
// PsExec from a user laptop to a domain controller (TRUE POSITIVE, critical)
// ---------------------------------------------------------------------------
const lateralPsExec: CaseTemplate = {
  id: 'impact-lateral-psexec',
  category: 'lateral',
  difficulty: 'tier3',
  title: 'PsExec service installed remotely',
  lesson: 'Pass-the-hash to a domain controller and AD database theft',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  twin: 'endpoint-benign-admin-psexec',
  stages: ['lateral', 'objective'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const ad = world.org.netbios;
    const opUser = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true, dept: ['Finance', 'Sales', 'HR', 'Marketing', 'Operations'] });
    const src = ctx.foothold?.host ? idx.host(ctx.foothold.host) : idx.deviceOf(opUser);
    const dc = idx.host(rng.pick(['DC01', 'DC02']));
    const adminAcct = rng.pick(world.people.filter((p) => p.adminAccount)).adminAccount!;
    const t0 = at - rng.int(7, 14) * MIN;
    // Credential theft on the source: a handle to lsass by an unusual tool.
    const lsass = log.proc({ TimeGenerated: t0 - rng.int(3, 6) * MIN, DeviceName: src.name, AccountName: opUser.sam, FileName: 'rundll32.exe', FolderPath: BIN.rundll32.path, ProcessCommandLine: 'rundll32.exe [summarised by EDR] — LSASS process memory dump', SHA256: ctx.infra.hash('tool'), Signer: 'Microsoft Windows', ProcessIntegrityLevel: 'High', InitiatingProcessFileName: 'cmd.exe', InitiatingProcessCommandLine: 'cmd.exe' });
    // PsExec launched from the workstation.
    const psexec = log.proc({ TimeGenerated: t0, DeviceName: src.name, AccountName: opUser.sam, FileName: 'psexec64.exe', FolderPath: `C:\\Users\\${opUser.sam}\\Downloads\\PsExec64.exe`, ProcessCommandLine: `PsExec64.exe [summarised by EDR] — remote command on ${dc.name} as SYSTEM using ${ad}\\${adminAcct}`, SHA256: binaryHash('psexec64.exe'), Signer: BIN.psexec.signer, ProcessIntegrityLevel: 'High', InitiatingProcessFileName: 'cmd.exe', InitiatingProcessCommandLine: 'cmd.exe' });
    const logon = log.sec({ TimeGenerated: t0 + 2 * SEC, Computer: dc.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${adminAcct}`, LogonType: 3, IpAddress: src.ip, WorkstationName: src.name, AuthenticationPackage: 'NTLM', ElevatedToken: 'Yes' });
    const svc = log.sec({ TimeGenerated: t0 + 3 * SEC, Computer: dc.name, EventID: 7045, Account: 'LocalSystem', ServiceName: 'PSEXESVC', ServiceFileName: '%SystemRoot%\\PSEXESVC.exe' });
    const proc = (t: number, file: string, folder: string, cmd: string) =>
      log.proc({ TimeGenerated: t, DeviceName: dc.name, AccountName: 'SYSTEM', FileName: file, FolderPath: folder, ProcessCommandLine: cmd, SHA256: binaryHash(file), Signer: 'Microsoft Windows', ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'psexesvc.exe', InitiatingProcessCommandLine: 'C:\\Windows\\PSEXESVC.exe' });
    const dcCmd = proc(t0 + 5 * SEC, 'cmd.exe', BIN.cmd.path, 'cmd.exe');
    // The objective: a shadow copy of the AD database.
    const vss = proc(t0 + 40 * SEC, 'ntdsutil.exe', BIN.ntdsutil.path, 'ntdsutil.exe [summarised by EDR] — snapshot of the Active Directory database (NTDS.dit)');
    const ntdsFile = log.file({ TimeGenerated: t0 + 70 * SEC, DeviceName: dc.name, ActionType: 'FileCreated', FileName: 'ntds.dit', FolderPath: 'C:\\Windows\\Temp\\ifm\\Active Directory\\ntds.dit', FileSize: rng.int(60_000_000, 240_000_000), SHA256: rng.hex(64), InitiatingProcessFileName: 'ntdsutil.exe', InitiatingProcessAccountName: 'SYSTEM' });
    const srcInfo = log.deviceRef(src.name);

    return {
      alert: {
        rule: 'Remote service creation on a domain controller',
        product: 'Microsoft Defender for Identity',
        severity: 'high',
        time: at,
        summary: `PSEXESVC was installed on ${dc.name} from ${src.name} using a privileged account over NTLM.`,
        entities: [
          { kind: 'host', value: dc.name, label: 'Domain controller' },
          { kind: 'host', value: src.name },
          { kind: 'user', value: `${ad}\\${adminAcct}` },
        ],
        fields: [['Target', `${dc.name} (domain controller)`], ['Auth', 'NTLM']],
      },
      briefing: `${world.org.name}: ${dc.name} is a domain controller. Administrators reach servers through JUMP01 with their -adm accounts; ${src.name} is ${opUser.display}'s ${src.role.toLowerCase()}.`,
      truth: { disposition: 'true-positive', severity: 'critical', action: 'escalate', techniques: ['T1021.002', 'T1003.003', 'T1550.002'], tactics: ['lateral-movement', 'credential-access'], alsoAccept: ['T1570', 'T1569.002', 'T1078.002', 'T1003.001', 'T1078'] },
      evidence: [
        { id: 'source', label: `PsExec ran from ${src.name} — a ${opUser.department} ${src.role.toLowerCase()}, which has no administrative function`, why: 'The benign twin runs from SCCM01. Admin tooling from a user laptop, targeting a DC, is inherently wrong.', rows: [psexec, srcInfo] },
        { id: 'pth', label: 'The DC logon is NTLM with a privileged account and no interactive session; LSASS was dumped on the source first', why: 'Credential theft feeding pass-the-hash — a real admin would log on interactively via the jump host with Kerberos.', rows: [logon, lsass] },
        { id: 'ntds', label: 'On the DC, ntdsutil made a copy of the AD database (NTDS.dit)', why: 'The endgame: the entire domain’s password hashes. If that copy leaves, the whole domain is compromised.', rows: [vss, ntdsFile, svc, dcCmd] },
      ],
      indicators: {
        block: [],
        scope: [host(dc.name), host(src.name), { kind: 'user', value: `${ad}\\${adminAcct}`, aliases: [adminAcct, `${adminAcct}@${world.org.domain}`] }, user(opUser)],
        mustNot: [host('SCCM01'), { kind: 'user', value: 'svc-sccm' }],
      },
      hints: [
        'PsExec is the same tool as the benign deployment case. The difference is the source host, the account, the auth type, and the target. Look at each.',
        `DeviceProcessEvents | where FileName =~ "psexec64.exe" | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
        `SecurityEvent | where Computer == "${dc.name}" and TimeGenerated > ${kdt(t0 - MIN)} | project TimeGenerated, EventID, Activity, TargetAccount, LogonType, IpAddress, AuthenticationPackage`,
      ],
      solution: [
        { title: 'Where did PsExec run from?', kql: 'DeviceProcessEvents\n| where FileName =~ "psexec64.exe"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName', why: `Not SCCM01 — a ${opUser.department} workstation, from a Downloads folder.` },
        { title: 'How did it authenticate to the DC?', kql: `SecurityEvent\n| where Computer == "${dc.name}" and EventID in (4624, 7045)\n| project TimeGenerated, EventID, TargetAccount, LogonType, IpAddress, WorkstationName, AuthenticationPackage, ServiceName`, why: 'A privileged account, NTLM, network logon from the workstation, then PSEXESVC.' },
        { title: 'Was credentials theft involved?', kql: `DeviceProcessEvents\n| where DeviceName == "${src.name}" and ProcessCommandLine has "LSASS"\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine`, why: 'An LSASS memory dump on the source — the hash came from here.' },
        { title: 'What ran on the DC?', kql: `DeviceProcessEvents\n| where DeviceName == "${dc.name}" and InitiatingProcessFileName == "psexesvc.exe"\n| project TimeGenerated, FileName, ProcessCommandLine`, why: 'ntdsutil making an IFM snapshot of the AD database.' },
        { title: 'The AD database copy', kql: `DeviceFileEvents\n| where DeviceName == "${dc.name}" and FileName == "ntds.dit"`, why: 'NTDS.dit written to a temp folder — domain-wide credential theft.' },
      ],
      rubric: rubric([
        ['source', 'A user laptop driving PsExec against a DC is inherently wrong — no admin function lives there.', ['workstation', 'laptop', 'source', 'dc', 'unexpected']],
        ['pth', 'NTLM logon with a prior LSASS dump = stolen hash / pass-the-hash, not a real admin session.', ['ntlm', 'pass-the-hash', 'lsass', 'stolen', 'hash', 'dump']],
        ['ntds', 'ntdsutil copying NTDS.dit is a full AD credential-store theft attempt.', ['ntds', 'ntds.dit', 'credential', 'domain', 'ifm', 'ad database']],
        ['contain', 'DC compromise = major incident: isolate both hosts, disable the account, invoke IR, plan for domain-wide credential reset.', ['isolate', 'incident', 'ir', 'disable', 'critical', 'krbtgt']],
      ]),
      explanation: [
        `This is the malicious face of the PsExec twin. The benign case runs from SCCM01 under change control; here PsExec runs from ${src.name}, ${opUser.first}'s ${src.role.toLowerCase()}, launched from a Downloads folder. Admin tooling does not live on user laptops.`,
        `The authentication gives it away: the DC logon is NTLM with a privileged -adm account and no interactive session, and minutes earlier LSASS was dumped on ${src.name}. That is credential theft feeding pass-the-hash — a real admin would come through the jump host and log on interactively with Kerberos. The follow-on is the worst part: on the DC, ntdsutil made an IFM snapshot and wrote NTDS.dit, the Active Directory credential database, to a temp folder.`,
        `This is a critical incident, not a triage close. Isolate ${dc.name} and ${src.name}, disable the abused admin account, and invoke incident response. If the NTDS.dit copy left the DC, assume every domain credential is compromised — that means a domain-wide password reset and rolling the krbtgt account, decided by IR and leadership.`,
      ],
      pitfalls: [
        'Same tool as the benign case — wrong source host, privileged account, NTLM/PtH and a DC target flip it to critical.',
        'The NTDS.dit access means credentials must be assumed compromised domain-wide, not just for one account.',
      ],
      references: [technique('T1003.003'), technique('T1550.002')],
    };
  },
};

// ---------------------------------------------------------------------------
// Account added to Domain Admins off-hours by a helpdesk account (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const domainAdminAdded: CaseTemplate = {
  id: 'impact-domain-admin-added',
  category: 'privesc',
  difficulty: 'tier2',
  title: 'Member added to Domain Admins',
  lesson: 'A compromised helpdesk account escalating privileges',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  stages: ['persistence'],
  when: 'off-hours',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const ad = world.org.netbios;
    const dc = idx.host(rng.pick(['DC01', 'DC02']));
    const actor = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ dept: 'Helpdesk', working: false });
    const added = pick.person({ dept: ['Finance', 'Sales', 'Operations', 'Marketing', 'HR'], exclude: [actor] });
    const t0 = at - rng.int(4, 9) * MIN;
    // The actor's account was itself used from a flagged workstation earlier.
    const actorWs = idx.deviceOf(actor);
    const earlierLogon = log.sec({ TimeGenerated: t0 - rng.int(40, 120) * MIN, Computer: dc.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${actor.sam}`, LogonType: 3, IpAddress: actorWs.ip, WorkstationName: actorWs.name, AuthenticationPackage: 'NTLM', ElevatedToken: 'No' });
    const added4728 = log.sec({ TimeGenerated: t0, Computer: dc.name, EventID: 4728, Account: `${ad}\\${actor.sam}`, TargetAccount: `${ad}\\${added.sam}`, GroupName: 'Domain Admins', MemberName: `CN=${added.display},OU=${added.department},DC=corp,DC=${world.org.short.toLowerCase()},DC=local` });
    // A recently created account (the added one) — foothold identity.
    const addedIdentity = log.patchIdentity(added.upn, { AccountCreated: at - rng.int(2, 6) * DAY });
    // Priv-esc used immediately: the added account logs into a server.
    const useLogon = log.sec({ TimeGenerated: t0 + rng.int(3, 8) * MIN, Computer: 'FS01', EventID: 4624, Account: '-', TargetAccount: `${ad}\\${added.sam}`, LogonType: 3, IpAddress: actorWs.ip, WorkstationName: actorWs.name, AuthenticationPackage: 'NTLM', ElevatedToken: 'Yes' });

    return {
      alert: {
        rule: 'Member added to a sensitive privileged group',
        product: 'Microsoft Defender for Identity',
        severity: 'medium',
        time: at,
        summary: `${added.sam} was added to Domain Admins by ${actor.sam} on ${dc.name}.`,
        entities: [
          { kind: 'user', value: `${ad}\\${added.sam}`, label: 'Added member' },
          { kind: 'user', value: `${ad}\\${actor.sam}`, label: 'Performed by' },
        ],
        fields: [['Group', 'Domain Admins'], ['Event', '4728']],
      },
      briefing: `${world.org.name}: Domain Admins membership is tightly controlled and changed only through approved requests during business hours. ${actor.display} works on the ${actor.department} desk; ${added.display} is in ${added.department}.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1098', 'T1078.002'], tactics: ['persistence', 'privilege-escalation'], alsoAccept: ['T1136.002', 'T1078'] },
      evidence: [
        { id: 'sensitive', label: 'A member was added to Domain Admins — the crown-jewel group', why: 'Any unsanctioned change to Domain Admins is high severity by itself.', rows: [added4728] },
        { id: 'actor', label: `The change was made by ${actor.sam}, a helpdesk account that should never modify privileged groups, off-hours with no change ticket`, why: 'Helpdesk cannot legitimately edit Domain Admins; the timing is outside all process.', rows: [added4728] },
        { id: 'chain', label: `${actor.sam} was used from ${actorWs.name} earlier, and the newly created ${added.sam} immediately logged into a server`, why: 'A compromised lower-privileged account escalating and establishing durable admin access.', rows: [earlierLogon, addedIdentity, useLogon] },
      ],
      indicators: {
        block: [],
        scope: [{ kind: 'user', value: `${ad}\\${added.sam}`, aliases: [added.sam, added.upn] }, { kind: 'user', value: `${ad}\\${actor.sam}`, aliases: [actor.sam, actor.upn] }, host(actorWs.name)],
        mustNot: [],
      },
      hints: [
        'Adding to Domain Admins can be legitimate. Ask: who did it, are they supposed to be able to, is there a change ticket, and what time was it?',
        `SecurityEvent | where EventID == 4728 and GroupName == "Domain Admins" | project TimeGenerated, Account, MemberName`,
        `Look at the performing account: is it privileged? IdentityInfo | where AccountName == "${actor.sam}"`,
      ],
      solution: [
        { title: 'The group change', kql: 'SecurityEvent\n| where EventID == 4728 and GroupName == "Domain Admins"\n| project TimeGenerated, Computer, Account, MemberName', why: `${actor.sam} added ${added.sam}, off-hours.` },
        { title: 'Should the actor be able to do this?', kql: `IdentityInfo\n| where AccountName == "${actor.sam}"\n| project AccountName, Department, JobTitle, IsPrivileged, Groups`, why: 'A helpdesk account — not privileged, no business modifying Domain Admins.' },
        { title: 'Is there a change ticket?', kql: 'Tickets\n| where Type == "Change"\n| project TicketId, Title, Status, WindowStart, WindowEnd, Scope', why: 'Nothing about Domain Admins — this change was never requested.' },
        { title: 'What is the added account?', kql: `IdentityInfo\n| where AccountName == "${added.sam}"\n| project AccountName, Department, AccountCreated`, why: 'Recently created.' },
        { title: 'Was the actor account already misused?', kql: `SecurityEvent\n| where TargetAccount has "${actor.sam}" and EventID == 4624\n| project TimeGenerated, Computer, IpAddress, WorkstationName, AuthenticationPackage`, why: `Earlier NTLM logon from ${actorWs.name}, then the added account used within minutes.` },
      ],
      rubric: rubric([
        ['sensitive', 'Domain Admins is the crown-jewel group; any unsanctioned change is high severity.', ['domain admins', 'privileged', 'crown', 'sensitive', 'da']],
        ['nochange', 'No change ticket and off-hours timing — outside all normal process.', ['no ticket', 'change', 'off-hours', 'process', 'unapproved']],
        ['actor', `The performing account (${actor.sam}) is helpdesk and cannot legitimately modify Domain Admins.`, ['helpdesk', 'actor', 'should not', 'not privileged', actor.sam]],
        ['contain', 'Remove the member, disable both accounts, investigate the actor’s workstation, and check for other privileged-group changes.', ['remove', 'disable', 'revert', 'investigate', 'contain']],
      ]),
      explanation: [
        `Adding a member to Domain Admins grants control over the whole domain, so event 4728 for that group is always worth a hard look. Here it was performed off-hours by ${actor.sam} — a helpdesk account with no privileged role and no business editing Domain Admins — with no change ticket to justify it.`,
        `The surrounding context makes it abuse rather than an odd-but-legitimate change: the added account, ${added.sam}, was created only days ago, ${actor.sam} was used from ${actorWs.name} earlier in the shift over NTLM, and the new admin account logged into a server within minutes. That reads as an attacker who compromised a low-privileged helpdesk account and is now escalating and planting durable admin access.`,
        `Escalate: remove ${added.sam} from Domain Admins, disable both accounts pending investigation, pull ${actorWs.name} for analysis, and check whether any other privileged-group changes happened around the same time.`,
      ],
      pitfalls: [
        'A legitimate emergency change can lack a ticket — but a helpdesk account making it off-hours is not that; confirm with the identity team fast.',
        'Removing the membership is step one; the access that enabled it must be found and closed.',
      ],
      references: [technique('T1098'), technique('T1078.002')],
    };
  },
};

// ---------------------------------------------------------------------------
// Insider exfiltration to personal cloud storage (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const cloudExfil: CaseTemplate = {
  id: 'impact-cloud-exfil',
  category: 'exfil',
  difficulty: 'tier2',
  title: 'Large upload to a file-sharing site',
  lesson: 'Insider exfiltration during a notice period',
  cysaDomains: ['1.0', '3.0', '4.0'],
  kind: 'incident',
  stages: ['objective'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const leaver = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ windows: true, dept: ['Sales', 'Engineering', 'Finance', 'Marketing'] });
    const dev = idx.deviceOf(leaver);
    const w = pick.where(leaver, at);
    const personal = world.services.filter((svc) => svc.kind === 'personal-storage');
    const dest = rng.pick(personal).domain;
    const destIp = world.serviceIps[dest][0];
    const gb = rng.int(18, 74) / 10;
    const fs = leaver.siteId === 'branch' ? 'FS02' : 'FS01';
    const t0 = at - rng.int(50, 80) * MIN;
    const ad = world.org.netbios;
    // Mark as resigning.
    const identity = log.patchIdentity(leaver.upn, { EmploymentStatus: `Notice period — last day ${new Date(at + rng.int(2, 6) * DAY).toISOString().slice(0, 10)}` });
    // Bulk read of a confidential share.
    const reads: RowRef[] = [];
    for (let i = 0; i < 12; i++) {
      reads.push(log.sec({ TimeGenerated: t0 + i * rng.int(3, 12) * SEC, Computer: fs, EventID: 4624, Account: '-', TargetAccount: `${ad}\\${leaver.sam}`, LogonType: 3, IpAddress: w.lanIp, WorkstationName: dev.name, AuthenticationPackage: 'Kerberos', ElevatedToken: 'No' }));
    }
    const bulkFiles: RowRef[] = [];
    for (let i = 0; i < 8; i++) {
      bulkFiles.push(log.file({ TimeGenerated: t0 + rng.int(10, 300) * SEC, DeviceName: dev.name, ActionType: 'FileRenamed', FileName: documentName(rng, 'Sales', rng.pick(['docx', 'xlsx', 'pdf'])), FolderPath: `\\\\${fs}\\Shared\\Clients\\${rng.hex(4)}`, PreviousFileName: '', FileSize: rng.int(200_000, 4_000_000), SHA256: rng.hex(64), InitiatingProcessFileName: 'explorer.exe', InitiatingProcessAccountName: leaver.sam }));
    }
    // Archive creation (7z, password-protected).
    const archive = log.proc({ TimeGenerated: t0 + 6 * MIN, DeviceName: dev.name, AccountName: leaver.sam, FileName: '7z.exe', FolderPath: BIN.sevenzip.path, ProcessCommandLine: `7z.exe [summarised by EDR] — password-protected archive export.7z of \\\\${fs}\\Shared\\Clients`, SHA256: binaryHash('7z.exe'), Signer: BIN.sevenzip.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: 'C:\\Windows\\Explorer.EXE' });
    const archiveFile = log.file({ TimeGenerated: t0 + 8 * MIN, DeviceName: dev.name, ActionType: 'FileCreated', FileName: 'export.7z', FolderPath: `C:\\Users\\${leaver.sam}\\Documents\\export.7z`, FileSize: Math.round(gb * 1e9), SHA256: rng.hex(64), InitiatingProcessFileName: '7z.exe', InitiatingProcessAccountName: leaver.sam });
    // Upload.
    const upStart = t0 + 12 * MIN;
    const uploads: RowRef[] = [];
    const chunks = rng.int(6, 12);
    for (let i = 0; i < chunks; i++) {
      uploads.push(log.proxy({ TimeGenerated: upStart + i * rng.int(120, 300) * SEC, SourceIP: w.lanIp, SourceUser: leaver.sam, Method: 'POST', Url: `https://${dest}/upload`, DestinationHost: dest, DestinationIP: destIp, DestinationPort: 443, StatusCode: 200, BytesSent: Math.round((gb * 1e9) / chunks), BytesReceived: rng.int(200, 800), Category: 'Personal Storage', UserAgent: w.session?.browser === 'Chrome' ? 'Chrome' : 'Edge', Action: 'Allowed' }));
    }

    return {
      alert: {
        rule: 'Large upload to personal file-sharing site',
        product: 'Cloud Access Security Broker',
        severity: 'medium',
        time: at,
        summary: `${gb.toFixed(1)} GB uploaded from ${dev.name} (${leaver.sam}) to ${dest} in under an hour.`,
        entities: [
          { kind: 'user', value: leaver.upn, label: leaver.display },
          { kind: 'host', value: dev.name },
          { kind: 'domain', value: dest },
        ],
        fields: [['Destination category', 'Personal file sharing'], ['Volume', `${gb.toFixed(1)} GB`]],
      },
      briefing: `${world.org.name}: corporate storage is OneDrive/SharePoint. ${leaver.display} is ${leaver.title} in ${leaver.department}.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1567.002', 'T1560.001'], tactics: ['exfiltration', 'collection'], alsoAccept: ['T1039', 'T1074'] },
      evidence: [
        { id: 'stage', label: `A bulk read of the confidential client share, then a password-protected 7z archive`, why: 'Collection then staging. The password both hides intent and blocks DLP inspection.', rows: [archive, archiveFile, ...bulkFiles, ...reads] },
        { id: 'dest', label: `${gb.toFixed(1)} GB uploaded to ${dest} — personal file-sharing, not corporate storage`, why: 'Sanctioned data does not leave through personal cloud accounts.', rows: uploads },
        { id: 'insider', label: `${leaver.first} is in their notice period`, why: 'A resigning employee plus never-before-seen upload volume is the classic insider-exfiltration signature.', rows: [identity] },
      ],
      indicators: {
        block: [],
        scope: [user(leaver), host(dev.name)],
        mustNot: [domain(`${world.org.tenant}.sharepoint.com`, 'Corporate storage'), domain(`${world.org.tenant}-my.sharepoint.com`, 'Corporate OneDrive'), domain(dest, 'A legitimate service — the problem is the user, not the site'), ip(destIp)],
      },
      hints: [
        'Uploads happen all day. What makes this exfiltration: what was read first, how it was packaged, where it went, and who the user is right now.',
        `WebProxy | where SourceUser == "${leaver.sam}" and Category == "Personal Storage" | summarize Bytes = sum(BytesSent) by DestinationHost`,
        `What did they do just before? DeviceProcessEvents | where DeviceName == "${dev.name}" and FileName == "7z.exe"`,
      ],
      solution: [
        { title: 'The upload', kql: `WebProxy\n| where SourceUser == "${leaver.sam}" and Category == "Personal Storage"\n| summarize Bytes = sum(BytesSent), Requests = count() by DestinationHost`, why: `Gigabytes to ${dest}, not corporate storage.` },
        { title: 'The upload requests', kql: `WebProxy\n| where SourceUser == "${leaver.sam}" and DestinationHost == "${dest}" and Method == "POST"\n| project TimeGenerated, Url, BytesSent, StatusCode`, why: 'Chunk after chunk of a multi-gigabyte upload.' },
        { title: 'What was packaged?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and FileName == "7z.exe"\n| project TimeGenerated, AccountName, ProcessCommandLine`, why: 'A password-protected archive of the client share — hides content from DLP.' },
        { title: 'What was collected first?', kql: `DeviceFileEvents\n| where DeviceName == "${dev.name}" and FolderPath has "Clients"\n| summarize Files = count() by InitiatingProcessAccountName`, why: 'A bulk sweep of the confidential client folder.' },
        { title: 'Who is this user?', kql: `IdentityInfo\n| where AccountName == "${leaver.sam}"\n| project AccountName, JobTitle, EmploymentStatus`, why: 'In their notice period.' },
      ],
      rubric: rubric([
        ['stage', 'Bulk read of a confidential share then a password-protected 7z = collection and staging.', ['staging', 'archive', '7z', 'bulk', 'collect', 'password']],
        ['dest', 'Destination is personal file-sharing, not sanctioned OneDrive/SharePoint.', ['personal', 'mega', 'not corporate', 'file sharing', 'destination']],
        ['insider', 'A resigning employee plus never-before-seen upload volume = likely insider exfiltration.', ['insider', 'resign', 'notice', 'leaving', 'volume']],
        ['handling', 'Escalate with HR and Legal; preserve evidence for the data-handling case.', ['hr', 'legal', 'preserve', 'evidence', 'escalate']],
      ]),
      explanation: [
        `The sequence is collection then exfiltration: a bulk read of the confidential client share, a password-protected 7z archive (the password hides intent and blocks DLP from inspecting the contents), then a multi-gigabyte upload to ${dest} — a personal file-sharing site, not the company's own OneDrive or SharePoint.`,
        `Context turns a policy oddity into a likely insider incident. ${leaver.first} is in their notice period, and the upload volume is far above their normal baseline. Whether it is malicious or "just taking my work", it is unauthorised removal of confidential data.`,
        `Escalate — and note the people dimension. Loop in HR and Legal early, preserve the endpoint and proxy/DLP evidence for the data-handling case, and consider disabling external upload or the account per policy. The write-up (Domain 4) matters as much as the technical containment here.`,
      ],
      pitfalls: [
        'A password-protected archive is itself a red flag — it defeats content inspection and is rarely how work is legitimately shared.',
        'Insider cases need careful evidence handling and HR/Legal involvement — do not just block and close.',
      ],
      references: [technique('T1567.002'), technique('T1560.001')],
    };
  },
};

// ---------------------------------------------------------------------------
// Ransomware detonation in progress (TRUE POSITIVE, critical)
// ---------------------------------------------------------------------------
const ransomware: CaseTemplate = {
  id: 'impact-ransomware',
  category: 'ransomware',
  difficulty: 'tier1',
  title: 'Mass file modification on a file server',
  lesson: 'Active ransomware detonation',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  stages: ['objective'],
  when: 'off-hours',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const server = idx.host(rng.pick(['FS01', 'FS02']));
    const ad = world.org.netbios;
    const ext = rng.pick(['.locked', '.crypt', `.${rng.hex(6)}`, '.eking']);
    const rate = rng.int(900, 4200);
    const origin = ctx.foothold?.host ? idx.host(ctx.foothold.host) : idx.deviceOf(pick.person({ windows: true }));
    const t0 = at - rng.int(4, 8) * MIN;
    // Session from the origin host to the server.
    const logon = log.sec({ TimeGenerated: t0 - 40 * SEC, Computer: server.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-backup`, LogonType: 3, IpAddress: origin.ip, WorkstationName: origin.name, AuthenticationPackage: 'NTLM', ElevatedToken: 'Yes' });
    const proc = (t: number, file: string, folder: string, cmd: string) =>
      log.proc({ TimeGenerated: t, DeviceName: server.name, AccountName: 'svc-backup', FileName: file, FolderPath: folder, ProcessCommandLine: cmd, SHA256: binaryHash(file), Signer: 'Microsoft Windows', ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'cmd.exe', InitiatingProcessCommandLine: 'cmd.exe' });
    const vss = proc(t0, 'vssadmin.exe', BIN.vssadmin.path, 'vssadmin.exe [summarised by EDR] — delete all volume shadow copies');
    const bcd = proc(t0 + 3 * SEC, 'bcdedit.exe', BIN.bcdedit.path, 'bcdedit.exe [summarised by EDR] — disable automatic recovery');
    const wbadmin = proc(t0 + 5 * SEC, 'wbadmin.exe', BIN.wbadmin.path, 'wbadmin.exe [summarised by EDR] — delete backup catalog');
    const encryptor = log.proc({ TimeGenerated: t0 + 8 * SEC, DeviceName: server.name, AccountName: 'svc-backup', FileName: 'svchost.exe', FolderPath: 'C:\\ProgramData\\svchost.exe', ProcessCommandLine: 'C:\\ProgramData\\svchost.exe [summarised by EDR]', SHA256: ctx.infra.hash('ransomware'), Signer: 'Unsigned', ProcessIntegrityLevel: 'System', InitiatingProcessFileName: 'cmd.exe', InitiatingProcessCommandLine: 'cmd.exe' });
    const renames: RowRef[] = [];
    for (let i = 0; i < 30; i++) {
      const orig = documentName(rng, rng.pick(['Finance', 'Sales', 'Operations']), rng.pick(['docx', 'xlsx', 'pdf']));
      renames.push(log.file({ TimeGenerated: t0 + 10 * SEC + i * rng.int(50, 200), DeviceName: server.name, ActionType: 'FileRenamed', FileName: `${orig}${ext}`, FolderPath: `D:\\Shares\\${rng.pick(['Finance', 'Sales', 'HR'])}\\${orig}${ext}`, PreviousFileName: orig, FileSize: rng.int(20_000, 4_000_000), SHA256: rng.hex(64), InitiatingProcessFileName: 'svchost.exe', InitiatingProcessAccountName: 'svc-backup' }));
    }
    const note = log.file({ TimeGenerated: t0 + 12 * SEC, DeviceName: server.name, ActionType: 'FileCreated', FileName: `!!!_HOW_TO_RESTORE_${ext.replace('.', '')}.txt`, FolderPath: `D:\\Shares\\Finance\\!!!_HOW_TO_RESTORE.txt`, FileSize: rng.int(800, 2200), SHA256: rng.hex(64), InitiatingProcessFileName: 'svchost.exe', InitiatingProcessAccountName: 'svc-backup' });

    return {
      alert: {
        rule: 'Ransomware behaviour detected',
        product: 'Microsoft Defender for Endpoint',
        severity: 'high',
        time: at,
        summary: `Mass file rename to ${ext} on ${server.name} (${rate}+ files/min), shadow copies deleted, ransom note dropped. In progress now.`,
        entities: [
          { kind: 'host', value: server.name, label: 'File server' },
          { kind: 'host', value: origin.name },
        ],
        fields: [['Rate', `${rate}+ files/min`], ['Anti-recovery', 'vssadmin / bcdedit / wbadmin']],
      },
      briefing: `${world.org.name}: ${server.name} hosts the primary departmental file shares. This is happening right now.`,
      truth: { disposition: 'true-positive', severity: 'critical', action: 'escalate', techniques: ['T1486', 'T1490'], tactics: ['impact'], alsoAccept: ['T1489', 'T1078', 'T1021.002'] },
      evidence: [
        { id: 'active', label: `Files are being renamed to ${ext} in bulk, right now`, why: 'Active encryption — every minute increases the damage. Speed is the whole game.', rows: renames },
        { id: 'antirecovery', label: 'Shadow copies deleted, recovery disabled, backup catalog cleared before encryption', why: 'Deliberate anti-recovery so victims cannot roll back — the signature of human-operated ransomware.', rows: [vss, bcd, wbadmin] },
        { id: 'origin', label: `Driven by an unsigned binary running as svc-backup, in a session from ${origin.name}`, why: 'The service account was abused over SMB from an already-compromised host — the intrusion that led here.', rows: [encryptor, logon, note] },
      ],
      indicators: {
        block: [],
        scope: [host(server.name), host(origin.name), { kind: 'user', value: 'svc-backup', aliases: [`${ad}\\svc-backup`] }],
        mustNot: [host('BKP01')],
      },
      hints: [
        'This is active. Containment comes before investigation. But confirm what is happening, where it is driven from, and what identity it uses so you isolate the right hosts.',
        `DeviceFileEvents | where DeviceName == "${server.name}" and ActionType == "FileRenamed" | summarize count() by InitiatingProcessFileName`,
        `SecurityEvent | where Computer == "${server.name}" and EventID == 4624 | project TimeGenerated, TargetAccount, IpAddress, WorkstationName`,
      ],
      solution: [
        { title: 'Confirm the encryption', kql: `DeviceFileEvents\n| where DeviceName == "${server.name}" and ActionType == "FileRenamed"\n| summarize Files = count(), Extensions = make_set(FileName) by InitiatingProcessFileName`, why: `Thousands of renames to ${ext} by an unsigned svchost.exe in ProgramData.` },
        { title: 'Watch it happen', kql: `DeviceFileEvents\n| where DeviceName == "${server.name}" and ActionType in ("FileRenamed", "FileCreated")\n| project TimeGenerated, FileName, PreviousFileName, FolderPath, InitiatingProcessFileName\n| sort by TimeGenerated desc\n| take 40`, why: 'Renames every few hundred milliseconds, and the ransom note.' },
        { title: 'Anti-recovery', kql: `DeviceProcessEvents\n| where DeviceName == "${server.name}" and FileName in ("vssadmin.exe", "bcdedit.exe", "wbadmin.exe")\n| project TimeGenerated, FileName, ProcessCommandLine, AccountName`, why: 'Shadow copies, recovery and the backup catalog destroyed first.' },
        { title: 'What identity and where from?', kql: `SecurityEvent\n| where Computer == "${server.name}" and EventID == 4624 and TimeGenerated > ${kdt(t0 - 2 * MIN)}\n| project TimeGenerated, TargetAccount, LogonType, IpAddress, WorkstationName, AuthenticationPackage`, why: `svc-backup over SMB from ${origin.name} — the source host to isolate too.` },
      ],
      rubric: rubric([
        ['active', 'Encryption is actively in progress — every minute matters; speed is the priority.', ['in progress', 'active', 'now', 'fast', 'immediately']],
        ['antirecovery', 'vssadmin/bcdedit/wbadmin before encryption = deliberate anti-recovery.', ['vssadmin', 'shadow', 'bcdedit', 'recovery', 'backup', 'anti-recovery']],
        ['isolate', 'Immediate containment: isolate the server and the source host to stop the spread.', ['isolate', 'contain', 'disconnect', 'stop spread', 'network']],
        ['ir', 'Invoke the IR plan and notify leadership; do not pay or interact with the note.', ['ir', 'incident response', 'leadership', 'notify', 'plan']],
      ]),
      explanation: [
        `This is not a triage-and-monitor case — it is an active ransomware detonation. The chain is unmistakable: shadow copies deleted, automatic recovery disabled and the backup catalog cleared (anti-recovery, so victims cannot roll back), then thousands of files a minute renamed to ${ext} by an unsigned binary masquerading as svchost.exe from ProgramData, with a ransom note dropped in the shares.`,
        `The acting identity is svc-backup over SMB, in a session from ${origin.name} — the human-operated intrusion that led here. Root-causing that matters, but it comes second: the immediate priority is stopping the encryption.`,
        `Act now: isolate ${server.name} and ${origin.name} from the network to halt the spread, invoke the incident-response plan, and notify leadership. Preserve evidence, find the last known-good backup, and do not interact with or pay the note. Every minute of delay is more encrypted data.`,
      ],
      pitfalls: [
        'Speed is everything with active ransomware — containment precedes investigation.',
        'Deleted shadow copies mean local rollback is gone; backup integrity becomes the recovery question.',
      ],
      references: [technique('T1486'), technique('T1490')],
    };
  },
};

export const impactTemplates: CaseTemplate[] = [lateralPsExec, domainAdminAdded, cloudExfil, ransomware];
