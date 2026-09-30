// Vulnerability-management case templates (DESIGN section 4). The scenario
// author owns this directory; registry.ts only lists what this file exports.
// Add a template here and tests/vuln-scenarios/slice.test.ts covers it.

import type { VulnTemplate } from '../model.ts';
import { kevInternal, noKevInternal } from './kev-internal.ts';
import { staleScan } from './stale-scan.ts';
import { backportFp } from './backport-fp.ts';

export const VULN_CASE_TEMPLATES: readonly VulnTemplate[] = [kevInternal, noKevInternal, staleScan, backportFp];
