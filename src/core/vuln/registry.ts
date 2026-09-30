// The registered vulnerability-management templates. Kept outside
// `templates/` on purpose: the scenario author owns that directory, this file
// only lists what is there. Fixtures are not registered; tests pass them
// straight to buildVulnScenario.

import type { VulnTemplate } from './model.ts';
import { VULN_CASE_TEMPLATES } from './templates/index.ts';

export const VULN_TEMPLATES: readonly VulnTemplate[] = [...VULN_CASE_TEMPLATES];

// Vuln template ids are namespaced so they can never collide with SOC ids.
export const VULN_TEMPLATE_PREFIX = 'vm-';

export function isVulnTemplateId(id: string): boolean {
  return id.startsWith(VULN_TEMPLATE_PREFIX);
}

export function vulnTemplateById(id: string): VulnTemplate | undefined {
  return VULN_TEMPLATES.find((t) => t.id === id);
}
