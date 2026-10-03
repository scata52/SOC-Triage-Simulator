// Domains. Two populations:
//  - Benign internet services the organisation uses (real, well-known sites
//    appearing only as ordinary destinations — never as bad actors).
//  - Attacker-controlled domains, always generated: look-alikes of the
//    fictitious org, lure words plus random tokens, DGA strings, and
//    innocuous-sounding "tech" names for C2. Random tokens keep generated
//    names from coinciding with anything registered in the real world.

import type { Rng } from '../rng.ts';

export type ServiceKind = 'saas' | 'web' | 'update' | 'cdn' | 'telemetry' | 'personal-storage' | 'dev';

export interface ExternalService {
  domain: string;
  category: string; // proxy web category
  kind: ServiceKind;
  weight: number; // relative popularity in noise
  depts?: readonly string[]; // restrict to departments (undefined = everyone)
  process?: string; // typical initiating process on endpoints
  blocked?: boolean; // proxy policy blocks the category
}

export function benignServices(tenant: string): ExternalService[] {
  const t = tenant.toLowerCase();
  return [
    { domain: 'login.microsoftonline.com', category: 'Identity and Access', kind: 'saas', weight: 10, process: 'msedge.exe' },
    { domain: 'outlook.office365.com', category: 'Web-based Email', kind: 'saas', weight: 12, process: 'outlook.exe' },
    { domain: 'teams.microsoft.com', category: 'Collaboration', kind: 'saas', weight: 10, process: 'ms-teams.exe' },
    { domain: `${t}.sharepoint.com`, category: 'Collaboration', kind: 'saas', weight: 9, process: 'msedge.exe' },
    { domain: `${t}-my.sharepoint.com`, category: 'Collaboration', kind: 'saas', weight: 6, process: 'OneDrive.exe' },
    { domain: 'graph.microsoft.com', category: 'Business Applications', kind: 'saas', weight: 5, process: 'ms-teams.exe' },
    { domain: 'officecdn.microsoft.com', category: 'Software Updates', kind: 'update', weight: 3, process: 'OfficeClickToRun.exe' },
    { domain: 'ctldl.windowsupdate.com', category: 'Software Updates', kind: 'update', weight: 3, process: 'svchost.exe' },
    { domain: 'settings-win.data.microsoft.com', category: 'Telemetry', kind: 'telemetry', weight: 4, process: 'svchost.exe' },
    { domain: 'edge.microsoft.com', category: 'Software Updates', kind: 'update', weight: 2, process: 'msedge.exe' },
    { domain: 'www.bing.com', category: 'Search Engines', kind: 'web', weight: 4, process: 'msedge.exe' },
    { domain: 'www.google.com', category: 'Search Engines', kind: 'web', weight: 6, process: 'chrome.exe' },
    { domain: 'fonts.googleapis.com', category: 'Content Delivery', kind: 'cdn', weight: 3, process: 'chrome.exe' },
    { domain: 'cdn.jsdelivr.net', category: 'Content Delivery', kind: 'cdn', weight: 2, process: 'chrome.exe' },
    { domain: 'www.linkedin.com', category: 'Social Networking', kind: 'web', weight: 3, process: 'chrome.exe' },
    { domain: 'www.youtube.com', category: 'Streaming Media', kind: 'web', weight: 2, process: 'chrome.exe' },
    { domain: 'en.wikipedia.org', category: 'Reference', kind: 'web', weight: 2, process: 'chrome.exe' },
    { domain: 'www.reuters.com', category: 'News', kind: 'web', weight: 2, process: 'msedge.exe' },
    { domain: 'www.bbc.co.uk', category: 'News', kind: 'web', weight: 1, process: 'chrome.exe' },
    { domain: 'zoom.us', category: 'Collaboration', kind: 'saas', weight: 2, process: 'Zoom.exe' },
    { domain: `${t}.my.salesforce.com`, category: 'Business Applications', kind: 'saas', weight: 6, depts: ['Sales', 'Marketing', 'Executive'], process: 'chrome.exe' },
    { domain: `${t}.atlassian.net`, category: 'Business Applications', kind: 'saas', weight: 5, depts: ['Engineering', 'IT', 'Security', 'Operations'], process: 'chrome.exe' },
    { domain: 'github.com', category: 'Software Development', kind: 'dev', weight: 6, depts: ['Engineering', 'IT', 'Security'], process: 'chrome.exe' },
    { domain: 'api.github.com', category: 'Software Development', kind: 'dev', weight: 4, depts: ['Engineering'], process: 'git.exe' },
    { domain: 'registry.npmjs.org', category: 'Software Development', kind: 'dev', weight: 3, depts: ['Engineering'], process: 'node.exe' },
    { domain: 'pypi.org', category: 'Software Development', kind: 'dev', weight: 2, depts: ['Engineering'], process: 'python.exe' },
    { domain: 'stackoverflow.com', category: 'Software Development', kind: 'web', weight: 3, depts: ['Engineering', 'IT'], process: 'chrome.exe' },
    { domain: 'www.booking.com', category: 'Travel', kind: 'web', weight: 1, depts: ['Sales', 'Executive'], process: 'msedge.exe' },
    { domain: 'www.dropbox.com', category: 'Personal Storage', kind: 'personal-storage', weight: 1, depts: ['Marketing', 'Sales'], process: 'chrome.exe' },
    { domain: 'wetransfer.com', category: 'Personal Storage', kind: 'personal-storage', weight: 1, depts: ['Marketing', 'Engineering'], process: 'chrome.exe' },
    { domain: 'drive.google.com', category: 'Personal Storage', kind: 'personal-storage', weight: 1, process: 'chrome.exe' },
    { domain: 'www.twitch.tv', category: 'Streaming Media', kind: 'web', weight: 0.3, process: 'chrome.exe', blocked: true },
    { domain: 'store.steampowered.com', category: 'Games', kind: 'web', weight: 0.3, process: 'chrome.exe', blocked: true },
    { domain: 'd1x7k2m9q3v5.cloudfront.net', category: 'Content Delivery', kind: 'cdn', weight: 1.5, process: 'msedge.exe' },
  ];
}

// Newsletters and vendor mail: bulk senders that legitimately mail the org.
export interface BulkSender {
  brand: string;
  from: string; // e.g. news@marketing.github.com
  fromDomain: string;
  esp: string; // envelope/return-path domain
  subjects: readonly string[];
}

export const BULK_SENDERS: readonly BulkSender[] = [
  { brand: 'GitHub', from: 'noreply@github.com', fromDomain: 'github.com', esp: 'github.com', subjects: ['[GitHub] A new SSH key was added', 'Your GitHub Copilot usage report', 'GitHub Universe: agenda announced'] },
  { brand: 'LinkedIn', from: 'news@linkedin.com', fromDomain: 'linkedin.com', esp: 'bounce.linkedin.com', subjects: ['New jobs match your preferences', 'You appeared in 12 searches this week'] },
  { brand: 'Atlassian', from: 'info@e.atlassian.com', fromDomain: 'atlassian.com', esp: 'mktomail.com', subjects: ['New in Jira this month', 'Your Confluence weekly digest'] },
  { brand: 'Zoom', from: 'no-reply@zoom.us', fromDomain: 'zoom.us', esp: 'sendgrid.net', subjects: ['Zoom Workplace: new features this month', 'Your cloud recording is ready'] },
  { brand: 'Adobe', from: 'mail@mail.adobe.com', fromDomain: 'adobe.com', esp: 'mail.adobe.com', subjects: ['Adobe Acrobat: tips for teams', 'Your Creative Cloud invoice'] },
];

export const SUSPICIOUS_TLDS = ['top', 'xyz', 'shop', 'live', 'click', 'cam', 'support', 'help', 'icu', 'buzz', 'cfd', 'sbs', 'rest', 'monster'] as const;
export const GENERIC_TLDS = ['com', 'net', 'org', 'io', 'app', 'cloud', 'online', 'site'] as const;

const LURE_WORDS = ['m365', 'o365', 'sso', 'docs-share', 'secure-files', 'invoice', 'payroll', 'hr-portal', 'voicemail', 'efax', 'parcel-track', 'mfa-verify', 'account-review', 'doc-sign'];
const LURE_SUFFIX = ['verify', 'login', 'portal', 'access', 'secure', 'auth', 'online', 'center'];
const TECH_A = ['cdn', 'api', 'sync', 'telemetry', 'update', 'edge', 'static', 'metrics', 'cache', 'relay'];
const TECH_B = ['service', 'node', 'cloud', 'hub', 'stack', 'gateway', 'check', 'data', 'stream', 'ops'];
const LOOKALIKE_WORDS = ['sso', 'helpdesk', 'it-support', 'portal', 'hr', 'payroll', 'secure', 'login', 'vpn', 'mail'];

export type AttackerDomainStyle = 'lookalike' | 'lure' | 'dga' | 'tech';

function typo(base: string, rng: Rng): string {
  const variants: (() => string)[] = [
    () => base.replace(/o/, '0'),
    () => base.replace(/i/, '1'),
    () => base.replace(/l/, '1'),
    () => {
      const i = rng.int(1, base.length - 2);
      return base.slice(0, i) + base[i] + base.slice(i);
    },
    () => {
      const i = rng.int(1, base.length - 2);
      return base.slice(0, i) + base.slice(i + 1);
    },
  ];
  for (let i = 0; i < 6; i++) {
    const v = rng.pick(variants)();
    if (v !== base) return v;
  }
  return base + 's';
}

function pronounceable(rng: Rng, len: number): string {
  const c = 'bcdfghjklmnprstvwxz';
  const v = 'aeiou';
  let s = '';
  for (let i = 0; i < len; i++) s += i % 2 === 0 ? rng.pick([...c]) : rng.pick([...v]);
  return s;
}

export function attackerDomain(rng: Rng, style: AttackerDomainStyle, orgShort: string): string {
  const org = orgShort.toLowerCase().replace(/[^a-z0-9]/g, '');
  switch (style) {
    case 'lookalike': {
      // Every look-alike carries a numeric token, so a generated name can
      // never coincide with a real registration of a plain typosquat.
      const shape = rng.int(0, 2);
      if (shape === 0) {
        return `${org}-${rng.pick(LOOKALIKE_WORDS)}${rng.int(2, 99)}.${rng.pick(['com', 'net', 'co'])}`;
      }
      if (shape === 1) return `${typo(org, rng)}${rng.int(2, 99)}.${rng.pick(SUSPICIOUS_TLDS)}`;
      return `${rng.pick(LOOKALIKE_WORDS)}-${typo(org, rng)}${rng.int(2, 99)}.${rng.pick(SUSPICIOUS_TLDS)}`;
    }
    case 'lure':
      return `${rng.pick(LURE_WORDS)}-${rng.pick(LURE_SUFFIX)}-${rng.alnum(3)}.${rng.pick(SUSPICIOUS_TLDS)}`;
    case 'dga':
      return rng.bool()
        ? `${rng.hex(rng.int(10, 16))}.${rng.pick(SUSPICIOUS_TLDS)}`
        : `${pronounceable(rng, rng.int(9, 14))}${rng.int(2, 99)}.${rng.pick([...SUSPICIOUS_TLDS, 'com', 'net'])}`;
    case 'tech':
      return `${rng.pick(TECH_A)}-${rng.pick(TECH_B)}-${rng.alnum(3)}.${rng.pick(GENERIC_TLDS)}`;
  }
}

// Registrable ("second-level") domain of a host name, good enough for the
// simulator's own domains (handles co.uk-style suffixes it generates).
export function registeredDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const twoLevel = ['co.uk', 'org.uk', 'com.au', 'co.jp'];
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevel.includes(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

const REGISTRARS = ['Namehold Registrar', 'Ardovane Domains', 'Halvern Names', 'Parcel Registry Services', 'Skerrin Name Co.', 'Lattice Domains'];

export function registrar(rng: Rng): string {
  return rng.pick(REGISTRARS);
}
