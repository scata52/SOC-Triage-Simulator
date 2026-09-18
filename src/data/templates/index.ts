import type { CaseTemplate, Category } from '../../types.ts';
import { identityTemplates } from './identity.ts';
import { emailTemplates } from './email.ts';
import { endpointTemplates } from './endpoint.ts';
import { networkTemplates } from './network.ts';
import { impactTemplates } from './impact.ts';

export const ALL_TEMPLATES: CaseTemplate[] = [
  ...identityTemplates,
  ...emailTemplates,
  ...endpointTemplates,
  ...networkTemplates,
  ...impactTemplates,
];

const BY_ID = new Map(ALL_TEMPLATES.map((t) => [t.id, t]));

export function templateById(id: string): CaseTemplate | undefined {
  return BY_ID.get(id);
}

export const CATEGORY_LABELS: Record<Category, string> = {
  phishing: 'Phishing & Email',
  identity: 'Identity & Access',
  malware: 'Malware & Endpoint',
  recon: 'Reconnaissance',
  privesc: 'Privilege Escalation',
  exfil: 'Data Exfiltration',
  lateral: 'Lateral Movement',
  persistence: 'Persistence',
  c2: 'Command & Control',
  ransomware: 'Ransomware',
};

export const ALL_CATEGORIES: Category[] = Object.keys(CATEGORY_LABELS) as Category[];

// Sanity check at module load: every template id must be unique.
{
  const seen = new Set<string>();
  for (const t of ALL_TEMPLATES) {
    if (seen.has(t.id)) throw new Error(`Duplicate template id: ${t.id}`);
    seen.add(t.id);
  }
}
