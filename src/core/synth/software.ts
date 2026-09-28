// Windows software catalogue for endpoint telemetry. Hashes are stable per
// binary (derived from its name), so the same signed binary carries the same
// SHA256 across the fleet — as it does in real EDR data — while attacker
// payloads get unique random hashes.

import { createRng } from '../rng.ts';

export interface Binary {
  file: string; // lower-case image name as EDR reports it here
  path: string; // may contain {user}
  signer: string;
}

const B = (file: string, path: string, signer: string): Binary => ({ file, path, signer });

export const BIN = {
  userinit: B('userinit.exe', 'C:\\Windows\\System32\\userinit.exe', 'Microsoft Windows'),
  explorer: B('explorer.exe', 'C:\\Windows\\explorer.exe', 'Microsoft Windows'),
  cmd: B('cmd.exe', 'C:\\Windows\\System32\\cmd.exe', 'Microsoft Windows'),
  powershell: B('powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'Microsoft Windows'),
  pwsh: B('pwsh.exe', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', 'Microsoft Corporation'),
  certutil: B('certutil.exe', 'C:\\Windows\\System32\\certutil.exe', 'Microsoft Windows'),
  mstsc: B('mstsc.exe', 'C:\\Windows\\System32\\mstsc.exe', 'Microsoft Windows'),
  notepad: B('notepad.exe', 'C:\\Windows\\System32\\notepad.exe', 'Microsoft Windows'),
  nslookup: B('nslookup.exe', 'C:\\Windows\\System32\\nslookup.exe', 'Microsoft Windows'),
  whoami: B('whoami.exe', 'C:\\Windows\\System32\\whoami.exe', 'Microsoft Windows'),
  net: B('net.exe', 'C:\\Windows\\System32\\net.exe', 'Microsoft Windows'),
  schtasks: B('schtasks.exe', 'C:\\Windows\\System32\\schtasks.exe', 'Microsoft Windows'),
  svchost: B('svchost.exe', 'C:\\Windows\\System32\\svchost.exe', 'Microsoft Windows'),
  services: B('services.exe', 'C:\\Windows\\System32\\services.exe', 'Microsoft Windows'),
  lsass: B('lsass.exe', 'C:\\Windows\\System32\\lsass.exe', 'Microsoft Windows'),
  taskhostw: B('taskhostw.exe', 'C:\\Windows\\System32\\taskhostw.exe', 'Microsoft Windows'),
  rundll32: B('rundll32.exe', 'C:\\Windows\\System32\\rundll32.exe', 'Microsoft Windows'),
  wmiprvse: B('wmiprvse.exe', 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', 'Microsoft Windows'),
  vssadmin: B('vssadmin.exe', 'C:\\Windows\\System32\\vssadmin.exe', 'Microsoft Windows'),
  bcdedit: B('bcdedit.exe', 'C:\\Windows\\System32\\bcdedit.exe', 'Microsoft Windows'),
  wbadmin: B('wbadmin.exe', 'C:\\Windows\\System32\\wbadmin.exe', 'Microsoft Windows'),
  ntdsutil: B('ntdsutil.exe', 'C:\\Windows\\System32\\ntdsutil.exe', 'Microsoft Windows'),
  msedge: B('msedge.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'Microsoft Corporation'),
  chrome: B('chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'Google LLC'),
  outlook: B('outlook.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'Microsoft Corporation'),
  winword: B('winword.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'Microsoft Corporation'),
  excel: B('excel.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', 'Microsoft Corporation'),
  powerpnt: B('powerpnt.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE', 'Microsoft Corporation'),
  teams: B('ms-teams.exe', 'C:\\Program Files\\WindowsApps\\MSTeams_25198.1112.3855.2365_x64__8wekyb3d8bbwe\\ms-teams.exe', 'Microsoft Corporation'),
  onedrive: B('onedrive.exe', 'C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe', 'Microsoft Corporation'),
  acrobat: B('acrobat.exe', 'C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe', 'Adobe Inc.'),
  zoom: B('zoom.exe', 'C:\\Users\\{user}\\AppData\\Roaming\\Zoom\\bin\\Zoom.exe', 'Zoom Video Communications, Inc.'),
  code: B('code.exe', 'C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', 'Microsoft Corporation'),
  git: B('git.exe', 'C:\\Program Files\\Git\\cmd\\git.exe', 'Johannes Schindelin'),
  node: B('node.exe', 'C:\\Program Files\\nodejs\\node.exe', 'OpenJS Foundation'),
  python: B('python.exe', 'C:\\Users\\{user}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe', 'Python Software Foundation'),
  sevenzip: B('7z.exe', 'C:\\Program Files\\7-Zip\\7z.exe', 'Igor Pavlov'),
  ccmexec: B('ccmexec.exe', 'C:\\Windows\\CCM\\CcmExec.exe', 'Microsoft Corporation'),
  mpcmdrun: B('mpcmdrun.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MpCmdRun.exe', 'Microsoft Corporation'),
  msmpeng: B('msmpeng.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe', 'Microsoft Corporation'),
  googleupdater: B('updater.exe', 'C:\\Program Files (x86)\\Google\\GoogleUpdater\\131.0.6727.0\\updater.exe', 'Google LLC'),
  officec2r: B('officeclicktorun.exe', 'C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe', 'Microsoft Corporation'),
  psexec: B('psexec64.exe', 'C:\\Tools\\SysinternalsSuite\\PsExec64.exe', 'Microsoft Corporation (Sysinternals)'),
  psexesvc: B('psexesvc.exe', 'C:\\Windows\\PSEXESVC.exe', 'Microsoft Corporation (Sysinternals)'),
  vmtoolsd: B('backupagent.exe', 'C:\\Program Files\\Backup Agent\\BackupAgent.exe', 'Northgate Backup Software'),
} as const;

export type BinaryKey = keyof typeof BIN;

const hashCache = new Map<string, string>();

// Stable SHA256 for a known binary (same everywhere in every world).
export function binaryHash(file: string): string {
  let h = hashCache.get(file);
  if (!h) {
    h = createRng(`binary-hash:${file}`).hex(64);
    hashCache.set(file, h);
  }
  return h;
}

export function binaryPath(b: Binary, user: string): string {
  return b.path.replace('{user}', user);
}

const DOC_WORDS = ['Q3', 'Q4', 'Budget', 'Forecast', 'Roadmap', 'Minutes', 'Proposal', 'Contract', 'Invoice', 'Report', 'Plan', 'Review', 'Onboarding', 'Pricing', 'Timeline', 'Draft', 'Summary', 'Specs', 'Inventory', 'Schedule'];
const DOC_TOPICS: Record<string, string[]> = {
  Finance: ['vendor payments', 'month-end close', 'cash forecast', 'audit prep', 'payroll run'],
  Sales: ['pipeline', 'client pitch', 'territory plan', 'renewals', 'pricing sheet'],
  Marketing: ['campaign brief', 'content calendar', 'event plan', 'brand guidelines'],
  Engineering: ['architecture', 'release notes', 'incident review', 'sprint plan', 'API design'],
  HR: ['hiring plan', 'benefits overview', 'org chart', 'training schedule'],
  Operations: ['shipping schedule', 'supplier list', 'warehouse layout', 'procurement plan'],
  Legal: ['NDA template', 'contract review', 'policy update'],
  Executive: ['board deck', 'strategy offsite', 'quarterly results'],
  IT: ['asset inventory', 'patch schedule', 'network diagram', 'licence review'],
  Helpdesk: ['ticket stats', 'knowledge base', 'onboarding checklist'],
  Security: ['vulnerability report', 'phishing test results', 'access review'],
};

export function documentName(rng: import('../rng.ts').Rng, dept: string, ext: string): string {
  const topic = rng.pick(DOC_TOPICS[dept] ?? DOC_TOPICS.Operations);
  const cap = topic.replace(/\b\w/g, (c) => c.toUpperCase());
  return `${rng.pick(DOC_WORDS)} - ${cap}${rng.bool(0.3) ? ` v${rng.int(2, 6)}` : ''}.${ext}`;
}
