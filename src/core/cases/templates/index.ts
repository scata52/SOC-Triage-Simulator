import type { CaseTemplate } from '../model.ts';
import type { Category } from '../../types.ts';
import { identityTemplates } from './identity.ts';
import { emailTemplates } from './email.ts';
import { endpointTemplates } from './endpoint.ts';
import { networkTemplates } from './network.ts';
import { impactTemplates } from './impact.ts';
import { opsTemplates } from './ops.ts';
import { LINKED_TEMPLATES } from './vuln-link.ts';

export const ALL_TEMPLATES: CaseTemplate[] = [...identityTemplates, ...emailTemplates, ...endpointTemplates, ...networkTemplates, ...impactTemplates, ...opsTemplates];

// Linked templates are built only from context another mode supplies (the
// vulnerability hook, DESIGN section 8), so they stay out of ALL_TEMPLATES: the
// library, the daily case, the study pool and random shift picks never see them.
// templateById still resolves them for scenario building, grading and titles.
export { LINKED_TEMPLATES };
const BY_ID = new Map([...ALL_TEMPLATES, ...LINKED_TEMPLATES].map((t) => [t.id, t]));

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
  vulnmgmt: 'Vulnerability Management',
};

export const ALL_CATEGORIES = Object.keys(CATEGORY_LABELS) as Category[];

{
  const seen = new Set<string>();
  for (const t of ALL_TEMPLATES) {
    if (seen.has(t.id)) throw new Error(`Duplicate template id: ${t.id}`);
    seen.add(t.id);
  }
}
