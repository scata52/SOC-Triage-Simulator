import type { MitreTechnique, Tactic } from '../types.ts';

// A curated slice of the MITRE ATT&CK Enterprise matrix — the techniques that
// actually show up in SOC alert queues. Enough for correct answers plus a
// realistic set of distractors in the technique picker.

function url(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

interface Raw {
  id: string;
  name: string;
  tactics: Tactic[];
}

const RAW: Raw[] = [
  // Initial access / phishing
  { id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactics: ['initial-access'] },
  { id: 'T1566.002', name: 'Phishing: Spearphishing Link', tactics: ['initial-access'] },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactics: ['initial-access'] },
  { id: 'T1133', name: 'External Remote Services', tactics: ['initial-access', 'persistence'] },
  { id: 'T1078', name: 'Valid Accounts', tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'] },
  { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactics: ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'] },

  // Execution
  { id: 'T1059.001', name: 'Command and Scripting Interpreter: PowerShell', tactics: ['execution'] },
  { id: 'T1059.003', name: 'Command and Scripting Interpreter: Windows Command Shell', tactics: ['execution'] },
  { id: 'T1204.001', name: 'User Execution: Malicious Link', tactics: ['execution'] },
  { id: 'T1204.002', name: 'User Execution: Malicious File', tactics: ['execution'] },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactics: ['defense-evasion'] },
  { id: 'T1218.011', name: 'System Binary Proxy Execution: Rundll32', tactics: ['defense-evasion'] },

  // Persistence / priv-esc
  { id: 'T1053.005', name: 'Scheduled Task/Job: Scheduled Task', tactics: ['execution', 'persistence', 'privilege-escalation'] },
  { id: 'T1547.001', name: 'Boot or Logon Autostart: Registry Run Keys / Startup Folder', tactics: ['persistence', 'privilege-escalation'] },
  { id: 'T1136.001', name: 'Create Account: Local Account', tactics: ['persistence'] },
  { id: 'T1098', name: 'Account Manipulation', tactics: ['persistence', 'privilege-escalation'] },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactics: ['privilege-escalation'] },

  // Defense evasion
  { id: 'T1027', name: 'Obfuscated Files or Information', tactics: ['defense-evasion'] },
  { id: 'T1140', name: 'Deobfuscate/Decode Files or Information', tactics: ['defense-evasion'] },
  { id: 'T1112', name: 'Modify Registry', tactics: ['defense-evasion'] },
  { id: 'T1070.001', name: 'Indicator Removal: Clear Windows Event Logs', tactics: ['defense-evasion'] },
  { id: 'T1562.001', name: 'Impair Defenses: Disable or Modify Tools', tactics: ['defense-evasion'] },

  // Credential access
  { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactics: ['credential-access'] },
  { id: 'T1110.003', name: 'Brute Force: Password Spraying', tactics: ['credential-access'] },
  { id: 'T1110.004', name: 'Brute Force: Credential Stuffing', tactics: ['credential-access'] },
  { id: 'T1003.001', name: 'OS Credential Dumping: LSASS Memory', tactics: ['credential-access'] },
  { id: 'T1555', name: 'Credentials from Password Stores', tactics: ['credential-access'] },
  { id: 'T1556', name: 'Modify Authentication Process', tactics: ['credential-access', 'defense-evasion', 'persistence'] },
  { id: 'T1621', name: 'Multi-Factor Authentication Request Generation', tactics: ['credential-access'] },

  // Discovery
  { id: 'T1046', name: 'Network Service Discovery', tactics: ['discovery'] },
  { id: 'T1018', name: 'Remote System Discovery', tactics: ['discovery'] },
  { id: 'T1087', name: 'Account Discovery', tactics: ['discovery'] },
  { id: 'T1069', name: 'Permission Groups Discovery', tactics: ['discovery'] },
  { id: 'T1082', name: 'System Information Discovery', tactics: ['discovery'] },
  { id: 'T1057', name: 'Process Discovery', tactics: ['discovery'] },
  { id: 'T1526', name: 'Cloud Service Discovery', tactics: ['discovery'] },

  // Lateral movement
  { id: 'T1021.001', name: 'Remote Services: Remote Desktop Protocol', tactics: ['lateral-movement'] },
  { id: 'T1021.002', name: 'Remote Services: SMB/Windows Admin Shares', tactics: ['lateral-movement'] },
  { id: 'T1021.006', name: 'Remote Services: Windows Remote Management', tactics: ['lateral-movement'] },
  { id: 'T1550.002', name: 'Use Alternate Authentication Material: Pass the Hash', tactics: ['lateral-movement', 'defense-evasion'] },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactics: ['lateral-movement'] },

  // Collection
  { id: 'T1560', name: 'Archive Collected Data', tactics: ['collection'] },
  { id: 'T1005', name: 'Data from Local System', tactics: ['collection'] },
  { id: 'T1074', name: 'Data Staged', tactics: ['collection'] },
  { id: 'T1113', name: 'Screen Capture', tactics: ['collection'] },

  // Command and control
  { id: 'T1071.001', name: 'Application Layer Protocol: Web Protocols', tactics: ['command-and-control'] },
  { id: 'T1071.004', name: 'Application Layer Protocol: DNS', tactics: ['command-and-control'] },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactics: ['command-and-control'] },
  { id: 'T1090', name: 'Proxy', tactics: ['command-and-control'] },
  { id: 'T1219', name: 'Remote Access Software', tactics: ['command-and-control'] },
  { id: 'T1568', name: 'Dynamic Resolution', tactics: ['command-and-control'] },

  // Exfiltration
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactics: ['exfiltration'] },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactics: ['exfiltration'] },
  { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', tactics: ['exfiltration'] },

  // Impact
  { id: 'T1486', name: 'Data Encrypted for Impact', tactics: ['impact'] },
  { id: 'T1490', name: 'Inhibit System Recovery', tactics: ['impact'] },
  { id: 'T1489', name: 'Service Stop', tactics: ['impact'] },
  { id: 'T1531', name: 'Account Access Removal', tactics: ['impact'] },
];

export const MITRE_TECHNIQUES: MitreTechnique[] = RAW.map((r) => ({
  ...r,
  url: url(r.id),
})).sort((a, b) => a.id.localeCompare(b.id));

const BY_ID = new Map(MITRE_TECHNIQUES.map((t) => [t.id, t]));

export function technique(id: string): MitreTechnique | undefined {
  return BY_ID.get(id);
}

export function techniqueName(id: string): string {
  return BY_ID.get(id)?.name ?? id;
}

export const TACTIC_LABELS: Record<Tactic, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource Development',
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Escalation',
  'defense-evasion': 'Defense Evasion',
  'credential-access': 'Credential Access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  'command-and-control': 'Command and Control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
};

// Canonical tactic order (kill-chain-ish) for the coverage matrix.
export const TACTIC_ORDER: Tactic[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];
