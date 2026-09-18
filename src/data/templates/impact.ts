import type { CaseTemplate } from '../../types.ts';
import { artifact, kvBlock, table, rubric } from './util.ts';

// ---------------------------------------------------------------------------
// Malicious lateral movement via PsExec / pass-the-hash (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const lateralPsExec: CaseTemplate = {
  id: 'impact-lateral-psexec',
  category: 'lateral',
  difficulty: 'tier3',
  title: 'PsExec from a user workstation to a domain controller',
  cysaDomains: ['1.0', '3.0'],
  build({ faker }) {
    const user = faker.identity();
    const src = faker.laptop();
    const srcIp = faker.privateIp();
    const dc = faker.domainController();

    return {
      alert: `EDR (High): PsExec service (PSEXESVC) installed on ${dc}, initiated from ${src} (${user.username}'s workstation). Authentication used an admin account via NTLM.`,
      context: `${faker.env.company} — ${src} is a standard user laptop; it has no operational reason to run remote-admin tooling against a domain controller.`,
      artifacts: [
        artifact(
          'Windows Security / EDR — Chain',
          'table',
          table(
            ['Time', 'Host', 'Event', 'Detail'],
            [
              [faker.clock(0), src, 'LSASS access', 'Handle to lsass.exe by unknown tool (cred theft)'],
              [faker.clock(120), dc, '4624', `Logon type 3, NTLM, acct: admin-svc from ${srcIp}`],
              [faker.clock(122), dc, '7045', 'Service PSEXESVC installed'],
              [faker.clock(125), dc, '4688', 'cmd.exe spawned by PSEXESVC (SYSTEM)'],
              [faker.clock(140), dc, '4688', 'ntdsutil.exe / vss shadow of NTDS.dit'],
            ],
          ),
        ),
        artifact(
          'Context',
          'kv',
          kvBlock([
            ['Source host role', `Standard user laptop (${src})`],
            ['Auth method', 'NTLM (pass-the-hash indicators) — no interactive logon'],
            ['Account used', 'admin-svc (privileged) from a non-admin workstation'],
            ['Change ticket', 'None'],
            ['Target', `${dc} — domain controller`],
            ['Post-access', 'Attempt to copy the NTDS.dit database (AD credential store)'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'critical',
        action: 'escalate',
        techniques: ['T1021.002', 'T1570', 'T1550.002'],
        tactics: ['lateral-movement', 'defense-evasion'],
      },
      rubric: rubric([
        ['source', 'A standard user laptop driving PsExec against a DC is inherently wrong — no admin function lives there.', ['workstation', 'laptop', 'source', 'dc', 'unexpected']],
        ['pth', 'NTLM logon with LSASS access first suggests stolen hash / pass-the-hash, not a real admin session.', ['ntlm', 'pass-the-hash', 'lsass', 'stolen', 'hash']],
        ['ntds', 'The endgame — copying NTDS.dit — is a full AD credential-store theft attempt.', ['ntds', 'ntds.dit', 'credential', 'domain', 'dcsync']],
        ['contain', 'DC compromise = major incident: isolate, disable the account, and invoke IR immediately.', ['isolate', 'incident', 'ir', 'disable', 'critical']],
      ]),
      explanation: [
        `This is the malicious face of the PsExec twin. The decisive difference from sanctioned admin use is the source and the account: remote-admin tooling is running from a standard user laptop, using a privileged account over NTLM with no interactive logon and no change ticket — and it is preceded by LSASS access on the source, the fingerprint of credential theft feeding a pass-the-hash.`,
        `The target and follow-on are what make it critical: PSEXESVC lands on a domain controller and immediately reaches for NTDS.dit, the Active Directory credential database. If that copy succeeds the attacker can forge access to the entire domain.`,
        `This is a full incident, not a triage close. Isolate ${dc} and ${src}, disable the abused admin account, preserve volatile evidence, and invoke incident response — a domain controller compromise is escalated to IR/leadership without delay.`,
      ],
      pitfalls: [
        'Same tool as the benign case — but wrong source host, privileged account, NTLM/PtH, and a DC target flip it to critical.',
        'The NTDS.dit access means credentials must be assumed compromised domain-wide, not just for one account.',
      ],
      references: [
        { label: 'ATT&CK T1550.002 Pass the Hash', url: 'https://attack.mitre.org/techniques/T1550/002/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Privilege escalation: user added to Domain Admins (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const domainAdminAdded: CaseTemplate = {
  id: 'impact-domain-admin-added',
  category: 'privesc',
  difficulty: 'tier2',
  title: 'Account added to Domain Admins outside change control',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const added = faker.identity();
    const actor = faker.identity();
    const dc = faker.domainController();
    const hour = rng.int(1, 4);

    return {
      alert: `Event 4728 (member added to a security-enabled global group): ${added.username} was added to "Domain Admins" at ${hour}:${rng.int(10, 59)} AM, by ${actor.username}. No change ticket exists.`,
      context: `${faker.env.company} — Domain Admins membership is tightly controlled and normally changed only via approved requests during business hours.`,
      artifacts: [
        artifact(
          'Windows Security — Event 4728',
          'kv',
          kvBlock([
            ['Event ID', '4728 (Member added to security-enabled global group)'],
            ['Group', 'Domain Admins'],
            ['Member added', `${faker.env.adDomain.split('.')[0]}\\${added.username}`],
            ['Performed by', `${faker.env.adDomain.split('.')[0]}\\${actor.username}`],
            ['On DC', dc],
            ['Time', `${faker.winTime(0)} (off-hours)`],
          ]),
        ),
        artifact(
          'Enrichment',
          'kv',
          kvBlock([
            ['Change ticket', 'None found'],
            ['Actor normally an admin?', `${actor.username} is a helpdesk account — should not modify DA`],
            ['Added user role', `${added.first} ${added.last} — recently created account`],
            ['Actor recent activity', 'Logged in from a workstation flagged earlier today'],
            ['Business hours?', 'No — off-hours change'],
            ['Prior DA changes this quarter', '0'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1098', 'T1078.004'],
        tactics: ['persistence', 'privilege-escalation'],
      },
      rubric: rubric([
        ['sensitive', 'Domain Admins is the crown-jewel group; any unsanctioned change is high severity.', ['domain admins', 'privileged', 'crown', 'sensitive', 'da']],
        ['nochange', 'No change ticket and off-hours timing — outside all normal process.', ['no ticket', 'change', 'off-hours', 'process', 'unapproved']],
        ['actor', `The performing account (${actor.username}) is helpdesk and should not be able to modify DA.`, ['helpdesk', 'actor', 'should not', 'unexpected', actor.username]],
        ['contain', 'Remove the member, disable involved accounts, and investigate the actor workstation.', ['remove', 'disable', 'revert', 'investigate', 'contain']],
      ]),
      explanation: [
        `Adding a member to Domain Admins is one of the highest-value events in a Windows environment — it grants control over the entire domain. Event 4728 here shows exactly that, performed off-hours by a helpdesk account that has no business modifying privileged groups, with no change ticket to justify it.`,
        `The surrounding context points to abuse rather than error: the added account was recently created, and the performing account logged in from a workstation already flagged earlier in the day. That reads as an attacker who compromised a lower-privileged account and is now escalating and establishing durable admin access.`,
        `Escalate: remove ${added.username} from Domain Admins, disable both the added and performing accounts pending investigation, and pull the actor's workstation for analysis. Verify whether any other privileged-group changes occurred.`,
      ],
      pitfalls: [
        'Occasionally a legitimate emergency change lacks a ticket — but a helpdesk account making it off-hours is not that; verify with the identity/AD team fast.',
        'Removing the membership is only step one; the access that enabled it must be found and closed.',
      ],
      references: [
        { label: 'ATT&CK T1098 Account Manipulation', url: 'https://attack.mitre.org/techniques/T1098/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Data exfiltration to personal cloud storage (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const cloudExfil: CaseTemplate = {
  id: 'impact-cloud-exfil',
  category: 'exfil',
  difficulty: 'tier2',
  title: 'Large upload to personal cloud storage',
  cysaDomains: ['1.0', '3.0', '4.0'],
  build({ rng, faker }) {
    const user = faker.identity();
    const host = faker.laptop();
    const dest = rng.pick(['mega.nz', 'anonfiles-mirror.top', 'personal Google Drive (consumer)', 'wetransfer.com']);
    const gb = (rng.int(18, 74) / 10).toFixed(1);

    return {
      alert: `DLP (High): ${gb} GB uploaded from ${host} (${user.username}) to ${dest} in 40 minutes, shortly after a large archive was created locally.`,
      context: `${faker.env.company} — ${user.username} handed in their notice last week; their last day is Friday.`,
      artifacts: [
        artifact(
          'Endpoint — Staging then upload',
          'table',
          table(
            ['Time', 'Event', 'Detail'],
            [
              [faker.clock(0), 'File access', `Bulk read of \\\\${faker.server('FILE')}\\Shared\\Clients (2,400 files)`],
              [faker.clock(300), 'Archive create', `7z.exe a export.7z -p (password-protected, ${gb} GB)`],
              [faker.clock(600), 'Upload start', `HTTPS PUT to ${dest}`],
              [faker.clock(3000), 'Upload done', `${gb} GB transferred`],
            ],
          ),
        ),
        artifact(
          'Proxy / DLP',
          'kv',
          kvBlock([
            ['Destination', dest],
            ['Category', 'Personal file sharing (not corporate OneDrive/SharePoint)'],
            ['Bytes out', `${gb} GB`],
            ['Content inspected', 'Archive password-protected — DLP could not read contents'],
            ['Source data', 'Client contract folder (confidential)'],
            ['User status', 'Resigning — final week'],
            ['Prior baseline', 'This user has never uploaded > 50 MB externally'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1567.002', 'T1560'],
        tactics: ['exfiltration', 'collection'],
      },
      rubric: rubric([
        ['stage', 'Bulk read of a confidential share then a password-protected 7z archive = data staging.', ['staging', 'archive', '7z', 'bulk', 'collect']],
        ['dest', 'Destination is personal file-sharing, not sanctioned corporate storage.', ['personal', 'mega', 'not corporate', 'file sharing', 'destination']],
        ['insider', 'A resigning employee + never-before-seen upload volume = likely insider exfiltration.', ['insider', 'resign', 'leaving', 'baseline', 'volume']],
        ['handling', 'Escalate with HR/Legal in the loop; preserve evidence for the data-handling case.', ['hr', 'legal', 'preserve', 'evidence', 'escalate']],
      ]),
      explanation: [
        `The sequence is collection-then-exfiltration: a bulk read of a confidential client share, a password-protected 7z archive (the password both hides intent and blocks DLP inspection), then a multi-gigabyte upload to a personal file-sharing site rather than the company's own OneDrive/SharePoint.`,
        `Context turns a policy oddity into a likely insider incident: the user resigned and is in their final week, and the upload volume is orders of magnitude above their own historical baseline. Whether malicious or "just taking my work", it is unauthorized removal of confidential data.`,
        `Escalate — but this one has a people dimension. Loop in HR and Legal early, preserve the endpoint and proxy/DLP evidence for the data-handling case, and consider disabling external upload / the account per policy. The write-up (Domain 4) matters as much as the technical containment here.`,
      ],
      pitfalls: [
        'A password-protected archive is itself a red flag — it defeats content inspection and is rarely how normal work is shared.',
        'Insider cases require evidence handling and HR/Legal involvement; do not "just block and close".',
      ],
      references: [
        { label: 'ATT&CK T1567.002 Exfil to Cloud Storage', url: 'https://attack.mitre.org/techniques/T1567/002/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Ransomware: mass encryption in progress (TRUE POSITIVE, critical)
// ---------------------------------------------------------------------------
const ransomware: CaseTemplate = {
  id: 'impact-ransomware',
  category: 'ransomware',
  difficulty: 'tier1',
  title: 'Mass file modification on a file server',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const server = faker.server('FILE');
    const acct = faker.serviceAccount();
    const ext = rng.pick(['.locked', '.crypt', '.' + faker.hex(6), '.eking']);
    const rate = rng.int(900, 4200);

    return {
      alert: `EDR (Critical): mass file rename/modification on ${server} — ${rate}+ files/minute renamed to ${ext}, a ransom note dropped in every folder, and shadow copies deleted.`,
      context: `${faker.env.company} — ${server} hosts the primary departmental file shares. This is happening right now.`,
      artifacts: [
        artifact(
          'EDR — Behavioural detections',
          'table',
          table(
            ['Time', 'Event', 'Detail'],
            [
              [faker.clock(0), 'Process', `vssadmin.exe delete shadows /all /quiet`],
              [faker.clock(3), 'Process', `bcdedit /set recoveryenabled No`],
              [faker.clock(6), 'Mass rename', `*.docx,*.xlsx,*.pdf -> *${ext} (${rate}/min)`],
              [faker.clock(9), 'File create', `!!!_READ_ME_${ext.replace('.', '')}.txt in every folder`],
              [faker.clock(12), 'Encryption', 'High-entropy writes across shares'],
            ],
          ),
        ),
        artifact(
          'Context',
          'kv',
          kvBlock([
            ['Acting account', `${acct} (service account, over SMB)`],
            ['Origin', `Session from ${faker.workstation()} — earlier alert on that host`],
            ['Shadow copies', 'Deleted (anti-recovery)'],
            ['Backups', 'Last known-good backup: needs verification'],
            ['Spread', 'Encryption walking through share subfolders now'],
            ['Ransom note', 'Contains a TOR URL and a victim ID'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'critical',
        action: 'escalate',
        techniques: ['T1486', 'T1490'],
        tactics: ['impact'],
      },
      rubric: rubric([
        ['active', 'Encryption is actively in progress — every minute increases damage; speed matters.', ['in progress', 'active', 'now', 'fast', 'contain immediately']],
        ['antirecovery', 'vssadmin delete shadows + bcdedit = deliberate anti-recovery before encryption.', ['vssadmin', 'shadow', 'bcdedit', 'recovery', 'anti-recovery']],
        ['isolate', 'Immediate containment: isolate the server/source host to stop the spread.', ['isolate', 'contain', 'disconnect', 'stop spread', 'network']],
        ['ir', 'Invoke the IR plan and notify leadership; do not pay or interact with the note.', ['ir', 'incident response', 'leadership', 'notify', 'plan']],
      ]),
      explanation: [
        `This is not a triage-and-monitor case — it is an active ransomware detonation. The tell-tale chain is unmistakable: shadow copies deleted and recovery disabled (anti-recovery, so victims can't roll back), followed by thousands of files per minute renamed to ${ext} and a ransom note dropped in every folder, with high-entropy writes confirming encryption.`,
        `The acting identity is a service account operating over SMB, and the session traces back to a workstation that alerted earlier — the human-operated intrusion that led here. But root-causing comes second; the immediate priority is stopping the spread.`,
        `Act now: isolate ${server} and the source host from the network to halt encryption, invoke the incident-response plan, and notify leadership. Preserve evidence, identify the last known-good backup, and do not interact with or pay the note. Every minute of delay is more encrypted data.`,
      ],
      pitfalls: [
        'Speed is the whole game with active ransomware — containment precedes investigation.',
        'Deleted shadow copies mean local rollback is gone; backup integrity becomes the recovery question.',
      ],
      references: [
        { label: 'ATT&CK T1486 Data Encrypted for Impact', url: 'https://attack.mitre.org/techniques/T1486/' },
      ],
    };
  },
};

export const impactTemplates: CaseTemplate[] = [
  lateralPsExec,
  domainAdminAdded,
  cloudExfil,
  ransomware,
];
