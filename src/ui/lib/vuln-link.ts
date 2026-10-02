// The way back from a SOC alert to the vulnerability case that led to it
// (DESIGN section 8, brief W8): a pure resolver, so it is testable without the DOM.

import type { VulnLink } from '../../core/cases/scenario.ts';
import { VULN_TEMPLATES } from '../../core/vuln/registry.ts';
import { resolveVulnTemplate, vulnCaseTypes, DECISION_LABELS, SCHEDULE_LABELS } from '../../core/vuln/worklist.ts';
import { href } from '../router.ts';

export interface ResolvedVulnLink {
  vulnId: string;
  host: string;
  decision: string;
  schedule: string;
  caseTitle: string;
  href: string;
}

// The attempt id is `${templateId}~${seed}` and a seed may itself contain `~`, so
// split at the first one. Returns null when the template is unknown or the seed does
// not lead back to that template.
export function resolveVulnLink(link: VulnLink): ResolvedVulnLink | null {
  const cut = link.caseRef.indexOf('~');
  if (cut <= 0) return null;
  const templateId = link.caseRef.slice(0, cut);
  const seed = link.caseRef.slice(cut + 1);
  const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.templates.some((x) => x.id === templateId));
  if (!type || !seed || resolveVulnTemplate(type, seed).id !== templateId) return null;
  return {
    vulnId: link.vulnId,
    host: link.host,
    decision: DECISION_LABELS[link.decision].toLowerCase(),
    schedule: SCHEDULE_LABELS[link.schedule].toLowerCase(),
    caseTitle: type.title,
    href: href({ name: 'vuln-case', slug: type.slug, seed }),
  };
}
