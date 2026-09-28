// Entra ID sign-ins and Microsoft 365 audit noise, including the decoys that
// make identity alerts require judgement: field staff on hotel networks and the
// cloud VPN gateway, fat-fingered passwords, stale ActiveSync clients, benign
// inbox rules, and the internet's constant background of legacy-auth guessing.

import type { Person } from '../../world/world.ts';
import type { MfaMethod } from '../../world/world.ts';
import { DAY, HOUR, MIN, SEC } from '../time.ts';
import { within, type Session } from './presence.ts';
import type { NoiseCtx } from './context.ts';
import { documentName } from '../../synth/software.ts';

const CORE_APPS = ['Office 365 Exchange Online', 'Microsoft Teams', 'Office 365 SharePoint Online', 'OneDrive SyncEngine'];
const DEPT_APPS: Record<string, string[]> = {
  Sales: ['Salesforce'],
  Marketing: ['Salesforce'],
  Executive: ['Salesforce'],
  Engineering: ['GitHub Enterprise Cloud', 'Atlassian Cloud'],
  IT: ['Azure Portal', 'Microsoft Intune', 'Atlassian Cloud'],
  Security: ['Azure Portal', 'Microsoft Defender XDR', 'Atlassian Cloud'],
  HR: ['Workday'],
  Finance: ['Workday'],
  Operations: ['Atlassian Cloud'],
};

export function mfaDetail(m: MfaMethod): string {
  return m === 'Push notification' ? 'Mobile app notification' : m === 'Number matching' ? 'Mobile app notification (number match)' : 'FIDO2 security key';
}

function osOf(s: Session): string {
  return s.device.os.startsWith('Ubuntu') ? 'Linux' : 'Windows 11';
}

export function signinNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  for (const s of n.sessions) {
    const p = s.person;
    const apps = [...CORE_APPS, ...(DEPT_APPS[p.department] ?? [])];
    const t0 = s.start + rng.int(1, 6) * MIN;
    const base = {
      UserPrincipalName: p.upn,
      IPAddress: s.cloudIp,
      DeviceId: s.device.deviceId,
      DeviceName: s.device.name,
      IsCompliant: true,
      IsManaged: true,
      OperatingSystem: osOf(s),
      Browser: s.browser === 'Chrome' ? 'Chrome 131.0.0' : 'Edge 131.0.2903',
      UserAgent: s.userAgent,
      ConditionalAccessStatus: 'success',
      RiskLevelDuringSignIn: 'none',
    } as const;

    // Occasional fat-fingered password first.
    if (rng.bool(0.03)) {
      b.signin({ ...base, TimeGenerated: t0 - rng.int(20, 90) * SEC, AppDisplayName: 'Office 365 Exchange Online', ClientAppUsed: 'Browser', ResultType: 50126, AuthenticationRequirement: 'multiFactorAuthentication', MfaDetail: '', MfaResult: '', ConditionalAccessStatus: 'notApplied', IncomingTokenType: 'none' });
    }
    // First interactive sign-in of the day completes MFA.
    b.signin({ ...base, TimeGenerated: t0, AppDisplayName: rng.pick(apps.slice(0, 3)), ClientAppUsed: 'Browser', ResultType: 0, AuthenticationRequirement: 'multiFactorAuthentication', MfaDetail: mfaDetail(p.mfaMethod), MfaResult: 'MFA completed in Azure AD', IncomingTokenType: 'none' });
    // Further sign-ins ride the session's primary refresh token.
    const more = rng.int(2, 5);
    for (let i = 0; i < more; i++) {
      b.signin({
        ...base,
        TimeGenerated: within(rng, s),
        AppDisplayName: rng.pick(apps),
        ClientAppUsed: rng.bool(0.5) ? 'Mobile Apps and Desktop clients' : 'Browser',
        ResultType: rng.bool(0.04) ? 50140 : 0,
        AuthenticationRequirement: 'multiFactorAuthentication',
        MfaDetail: '',
        MfaResult: 'MFA requirement satisfied by claim in the token',
        IncomingTokenType: 'primaryRefreshToken',
      });
    }
  }

  // Mobile mail, spread through the day and evening.
  const mobileDays = new Map<string, Session>();
  for (const s of n.sessions) mobileDays.set(`${s.person.id}:${Math.floor(s.start / DAY)}`, s);
  for (const s of mobileDays.values()) {
    const p = s.person;
    const mobile = p.mobileDevice ? b.idx.mobileOf(p) : undefined;
    if (!mobile) continue;
    const activeSync = hashPick(p.sam, 7) === 0;
    const count = rng.int(1, 3);
    for (let i = 0; i < count; i++) {
      const t = Math.min(b.windowEnd - MIN, Math.max(b.windowStart, s.start + rng.float(-1.5, 12) * HOUR));
      const home = rng.bool(0.4);
      b.signin({
        TimeGenerated: Math.floor(t),
        UserPrincipalName: p.upn,
        AppDisplayName: 'Office 365 Exchange Online',
        ClientAppUsed: activeSync ? 'Exchange ActiveSync' : 'Mobile Apps and Desktop clients',
        IPAddress: home ? p.homeIp : rng.pick(b.world.internet.carriers),
        ResultType: 0,
        AuthenticationRequirement: 'multiFactorAuthentication',
        MfaDetail: '',
        MfaResult: 'MFA requirement satisfied by claim in the token',
        ConditionalAccessStatus: 'success',
        IncomingTokenType: 'refreshToken',
        DeviceId: mobile.deviceId,
        DeviceName: mobile.name,
        IsCompliant: mobile.managed,
        IsManaged: mobile.managed,
        OperatingSystem: mobile.os.startsWith('iOS') ? 'iOS 19.0' : 'Android 16',
        Browser: activeSync ? 'Native mail client' : 'Outlook Mobile',
        UserAgent: activeSync ? (mobile.os.startsWith('iOS') ? 'Apple-iPhone17C1/2201.100' : 'Android-Mail/2026.08') : 'Outlook-iOS/4.2438.0',
        RiskLevelDuringSignIn: 'none',
      });
    }
  }
}

// Constant internet background: password guessing against the tenant from
// scanners, VPS and anonymizers. Mostly legacy protocols, mostly failing, a
// handful of attempts per source — which is what a real spray must be told
// apart from.
export function internetAuthNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const sources = [...w.internet.scanners, ...w.internet.hosting, ...w.internet.tor];
  const hours = (b.windowEnd - b.windowStart) / HOUR;
  const attempts = Math.round(hours * rng.float(1.0, 1.8));
  const guesses = ['admin', 'administrator', 'info', 'test', 'scanner', 'office', 'support', 'noreply', 'backup'];
  for (let i = 0; i < attempts; i++) {
    const ip = rng.pick(sources);
    const real = rng.bool(0.55) ? rng.pick(w.people) : null;
    const upn = real ? real.upn : `${rng.pick(guesses)}@${w.org.domain}`;
    const client = rng.pickWeighted([
      { value: 'IMAP4', weight: 4 },
      { value: 'Authenticated SMTP', weight: 3 },
      { value: 'Browser', weight: 2 },
      { value: 'Exchange ActiveSync', weight: 1 },
    ]);
    const code = !real ? 50034 : client === 'Browser' ? rng.pick([50126, 53003]) : 50126;
    const burst = rng.int(1, 3);
    const t0 = rng.int(b.windowStart, b.windowEnd - 5 * MIN);
    for (let k = 0; k < burst; k++) {
      b.signin({
        TimeGenerated: t0 + k * rng.int(5, 90) * SEC,
        UserPrincipalName: upn,
        UserDisplayName: real?.display ?? upn.split('@')[0],
        AppDisplayName: 'Office 365 Exchange Online',
        ClientAppUsed: client,
        IPAddress: ip,
        ResultType: code,
        AuthenticationRequirement: 'singleFactorAuthentication',
        MfaDetail: '',
        MfaResult: '',
        ConditionalAccessStatus: code === 53003 ? 'failure' : 'notApplied',
        IncomingTokenType: 'none',
        DeviceId: '',
        DeviceName: '',
        IsCompliant: false,
        IsManaged: false,
        OperatingSystem: client === 'Browser' ? 'Windows 10' : '',
        Browser: client === 'Browser' ? 'Chrome 118.0.0' : '',
        UserAgent: client === 'Browser' ? 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36' : rng.pick(['BAV2ROPC', 'python-requests/2.31.0', 'Mozilla/5.0 (compatible; MSAL 1.0)']),
        RiskLevelDuringSignIn: rng.pick(['none', 'low', 'medium']),
      });
    }
  }
}

export function auditNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const tenant = w.org.tenant;
  for (const s of n.sessions) {
    const p = s.person;
    // SharePoint / OneDrive file activity (sampled).
    const files = rng.int(0, 3);
    for (let i = 0; i < files; i++) {
      const op = rng.pickWeighted([
        { value: 'FileAccessed', weight: 5 },
        { value: 'FileModified', weight: 3 },
        { value: 'FileUploaded', weight: 1 },
        { value: 'FileDownloaded', weight: 1 },
      ]);
      const doc = documentName(rng, p.department, rng.pick(['docx', 'xlsx', 'pptx', 'pdf']));
      b.audit({
        TimeGenerated: within(rng, s),
        Workload: 'SharePoint',
        OperationName: op,
        Category: 'File',
        InitiatedBy: p.upn,
        TargetResource: `https://${tenant}.sharepoint.com/sites/${p.department}/Shared Documents/${doc}`,
        ClientIP: s.cloudIp,
        Details: `UserAgent: ${s.browser}; Site: ${p.department}`,
      });
    }
    // Benign inbox rules — the decoy for business-email-compromise rules.
    if (rng.bool(0.035)) {
      const sender = rng.pick(['noreply@github.com', 'news@linkedin.com', 'info@e.atlassian.com', 'no-reply@zoom.us', 'mail@mail.adobe.com']);
      const folder = rng.pick(['Newsletters', 'Notifications', 'Vendors', 'Later']);
      b.audit({
        TimeGenerated: within(rng, s),
        Workload: 'Exchange',
        OperationName: 'New-InboxRule',
        Category: 'Mailbox',
        InitiatedBy: p.upn,
        TargetResource: p.upn,
        ClientIP: s.cloudIp,
        Details: `Name: ${folder}; From: ${sender}; MoveToFolder: ${folder}; MarkAsRead: False; StopProcessingRules: False`,
      });
    }
    if (rng.bool(0.01)) {
      b.audit({
        TimeGenerated: within(rng, s),
        Workload: 'AzureActiveDirectory',
        OperationName: 'User registered security info',
        Category: 'UserManagement',
        InitiatedBy: p.upn,
        TargetResource: p.upn,
        ClientIP: s.cloudIp,
        Details: 'Method: Authenticator app; Device: new phone (replacement)',
      });
    }
  }

  // Helpdesk and IT administration, with matching tickets.
  const helpdesk = w.people.filter((p) => p.department === 'Helpdesk');
  const admins = w.people.filter((p) => p.adminAccount);
  const workSessions = n.sessions.filter((s) => s.location !== 'travel' && !s.person.fieldSales);
  const resets = rng.int(2, 5);
  for (let i = 0; i < resets && workSessions.length; i++) {
    const s = rng.pick(workSessions);
    const hd = rng.pick(helpdesk);
    const t = within(rng, s);
    const req = n.nextTicket('REQ');
    b.ticket({ TicketId: req, Type: 'Service request', Title: `Password reset — ${s.person.display}`, Requester: s.person.upn, AssignedTo: hd.upn, Status: 'Closed', Created: t - rng.int(5, 40) * MIN, Scope: s.person.sam, Details: rng.pick(['Forgot password after holiday.', 'Password expired while travelling.', 'Locked out after too many attempts.']) });
    b.audit({ TimeGenerated: t, Workload: 'AzureActiveDirectory', OperationName: 'Reset user password', Category: 'UserManagement', InitiatedBy: hd.upn, TargetResource: s.person.upn, ClientIP: b.idx.siteOf(hd).natIp, Details: `Ticket: ${req}; ForceChangePasswordNextSignIn: True` });
  }
  const groupChanges = rng.int(1, 3);
  for (let i = 0; i < groupChanges && admins.length; i++) {
    const adm = rng.pick(admins);
    const target = rng.pick(w.people);
    const group = rng.pick(['VPN-Users', 'SG-Finance-ReadOnly', 'App-Salesforce-Users', 'SharePoint-Projects-Members', 'Printers-Floor2']);
    const t = rng.int(b.windowStart + 2 * HOUR, b.windowEnd - HOUR);
    const req = n.nextTicket('REQ');
    b.ticket({ TicketId: req, Type: 'Service request', Title: `Access request — add ${target.display} to ${group}`, Requester: target.upn, AssignedTo: `${adm.adminAccount}@${w.org.domain}`, Status: 'Closed', Created: t - rng.int(1, 20) * HOUR, Scope: target.sam, Details: 'Approved by line manager.' });
    b.audit({ TimeGenerated: t, Workload: 'AzureActiveDirectory', OperationName: 'Add member to group', Category: 'GroupManagement', InitiatedBy: `${adm.adminAccount}@${w.org.domain}`, TargetResource: `${group} / ${target.upn}`, ClientIP: w.sites[0].natIp, Details: `Ticket: ${req}` });
  }
  if (rng.bool(0.5)) {
    const user = rng.pick(w.people);
    b.audit({ TimeGenerated: rng.int(b.windowStart + HOUR, b.windowEnd - HOUR), Workload: 'AzureActiveDirectory', OperationName: 'Consent to application', Category: 'ApplicationManagement', InitiatedBy: user.upn, TargetResource: 'Zoom for Outlook', ClientIP: user.homeIp, Details: 'Permissions: Calendars.ReadWrite, User.Read; Publisher verified: Yes; Admin pre-approved app' });
  }
}

function hashPick(s: string, mod: number): number {
  let h = 7;
  for (let i = 0; i < s.length; i++) h = (h * 33 + s.charCodeAt(i)) | 0;
  return Math.abs(h) % mod;
}

export function isActiveSyncUser(p: Person): boolean {
  return hashPick(p.sam, 7) === 0;
}
