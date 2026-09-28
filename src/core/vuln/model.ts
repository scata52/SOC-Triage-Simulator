// Vulnerability-management case model (DESIGN section 2.2). A VulnTemplate is
// a sibling of CaseTemplate, not a variant: the truth of a vulnerability case
// is a set of per-finding decisions, not a single disposition. It reuses the
// lower layers (world, RNG, corpus builder, query harness) and the SOC types
// for attachments, evidence, solution steps, rubric and references.

import type { Attachment, CaseContext, EvidenceSpec, SolutionStep } from '../cases/model.ts';
import type { RowRef } from '../logs/corpus.ts';
import type { CaseReference, Difficulty, RubricItem } from '../types.ts';
import type { VulnCatalogue } from './catalogue.ts';

// avoid = remove or disable the vulnerable component or service entirely;
// mitigate = keep it, put a control in front of it.
export const VULN_DECISIONS = ['patch', 'mitigate', 'avoid', 'accept', 'transfer', 'false-positive'] as const;
export type VulnDecision = (typeof VULN_DECISIONS)[number];

export const VULN_SCHEDULES = ['emergency', 'next-window', 'standard-cycle', 'none'] as const;
export type VulnSchedule = (typeof VULN_SCHEDULES)[number];

// Justification vocabulary (DESIGN section 5.4): the learner picks up to three
// per finding; each finding lists required and contradicting codes.
export const REASON_CODES = [
  'known-exploited',
  'high-exploit-probability',
  'public-exploit',
  'internet-exposed',
  'critical-asset',
  'sensitive-data',
  'compensating-control-verified',
  'control-not-covering',
  'credentialed-confirmed',
  'banner-only',
  'backported-fix',
  'stale-scan',
  'pending-reboot',
  'duplicate-root-cause',
  'vendor-responsibility',
  'approved-exception',
  'no-vendor-fix',
  'low-exploitability',
  'sla-deadline',
  'change-freeze',
  'unused-component',
] as const;
export type ReasonCode = (typeof REASON_CODES)[number];

// SLA classes follow the severity bands the organisation's policy uses.
export type SlaClass = 'critical' | 'high' | 'medium' | 'low';

// A ControlInventory ControlId (WAF rule, ACL, EDR rule, MFA, config).
export type ControlId = string;

export interface FindingTruth {
  decision: VulnDecision;
  alsoAccept?: VulnDecision[];
  schedule: VulnSchedule;
  reasons: ReasonCode[]; // required justification codes
  // Codes that count against the learner when chosen (e.g. `stale-scan` on a
  // real finding). Optional; the grader treats a missing list as empty.
  contradicting?: ReasonCode[];
  mitigation?: ControlId[]; // acceptable controls when decision = mitigate
}

export interface FindingSpec {
  findingId: string;
  row: RowRef; // the finding's row in the corpus (a handle, never a marker in the data)
  truth: FindingTruth;
  weight: number;
  mustNotMiss?: boolean;
  evidence: EvidenceSpec[];
}

// A change window (or, in `freezes`, a period in which no change may land).
export interface ChangeWindow {
  id: string;
  label: string;
  start: number; // epoch ms
  end: number; // epoch ms
}

export interface VulnConstraints {
  windows: ChangeWindow[];
  freezes?: ChangeWindow[];
  slaDays: Record<SlaClass, number>;
  capacityPerWindow: number;
}

export interface VulnCaseSpec {
  briefing: string;
  attachments?: Attachment[];
  findings: FindingSpec[];
  constraints: VulnConstraints;
  idealOrder: string[]; // findingIds, most urgent first
  tiers?: string[][]; // findingIds grouped by urgency tier, when ties are allowed
  hints: string[];
  solution: SolutionStep[]; // runnable KQL, same harness as SOC
  rubric: RubricItem[]; // stakeholder-note coaching
  explanation: string[];
  pitfalls: string[];
  references: CaseReference[];
}

// What a vuln template receives beyond the SOC case context. The scan writer
// (ScanRuns and finding rows) joins this in WP1b, additively.
export interface VulnToolkit {
  catalogue: VulnCatalogue;
}

export interface VulnContext extends CaseContext {
  vuln: VulnToolkit;
}

export interface VulnTemplate {
  id: string; // 'vm-<slug>'; the namespace prevents collisions with SOC ids
  difficulty: Difficulty;
  title: string; // neutral name, safe to show before the case is solved
  lesson: string; // shown only in the debrief and stats
  cysaDomains: string[];
  objectives: string[];
  twin?: string;
  kind: 'vuln';
  build(ctx: VulnContext): VulnCaseSpec;
}
