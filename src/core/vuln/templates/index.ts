// Vulnerability-management case templates (DESIGN section 4). The scenario
// author owns this directory; registry.ts only lists what this file exports.
// Add a template here and tests/vuln-scenarios/slice.test.ts covers it.

import type { VulnTemplate } from '../model.ts';
import { kevInternal, noKevInternal } from './kev-internal.ts';
import { freshScan, staleScan } from './stale-scan.ts';
import { backportFp, backportReal } from './backport-fp.ts';
import { exposedEdge, segmented } from './exposed-edge.ts';
import { wafBypass, wafCovers } from './waf.ts';

export const VULN_CASE_TEMPLATES: readonly VulnTemplate[] = [kevInternal, noKevInternal, staleScan, freshScan, backportFp, backportReal, exposedEdge, segmented, wafCovers, wafBypass];
