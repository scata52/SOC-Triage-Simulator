// Shared domain types for the v2 core. Union types, no enums (the project
// uses erasable TypeScript syntax only).

export type Disposition = 'true-positive' | 'false-positive' | 'benign';
export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type TriageAction = 'escalate' | 'monitor' | 'close';
export type Difficulty = 'tier1' | 'tier2' | 'tier3';

export type Tactic =
  | 'reconnaissance'
  | 'resource-development'
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'defense-evasion'
  | 'credential-access'
  | 'discovery'
  | 'lateral-movement'
  | 'collection'
  | 'command-and-control'
  | 'exfiltration'
  | 'impact';

export type Category =
  | 'phishing'
  | 'identity'
  | 'malware'
  | 'recon'
  | 'privesc'
  | 'exfil'
  | 'lateral'
  | 'persistence'
  | 'c2'
  | 'ransomware'
  | 'vulnmgmt';

// The alert categories of SOC cases (vulnerability cases have their own).
export type SocCategory = Exclude<Category, 'vulnmgmt'>;

export interface MitreTechnique {
  id: string;
  name: string;
  tactics: Tactic[];
  url: string;
}

export interface CysaDomain {
  id: string;
  name: string;
  blurb: string;
}

export interface GroundTruth {
  disposition: Disposition;
  severity: Severity;
  action: TriageAction;
  techniques: string[];
  tactics: Tactic[];
  // Defensible alternative mappings: not required, but not penalised as extras.
  alsoAccept?: string[];
}

export interface RubricItem {
  id: string;
  text: string;
  keywords: string[];
}

export interface CaseReference {
  label: string;
  url: string;
}

export const SEVERITY_ORDER: Severity[] = ['informational', 'low', 'medium', 'high', 'critical'];
export const ACTION_ORDER: TriageAction[] = ['close', 'monitor', 'escalate'];
