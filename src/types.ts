// Core domain types for the SOC Triage Simulator.
// No enums (tsconfig uses erasableSyntaxOnly); union types + const maps instead.

export type Disposition = 'true-positive' | 'false-positive' | 'benign';

export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';

export type TriageAction = 'escalate' | 'monitor' | 'close';

export type Difficulty = 'tier1' | 'tier2' | 'tier3';

// MITRE ATT&CK Enterprise tactics (short ids).
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
  | 'ransomware';

export interface MitreTechnique {
  id: string; // e.g. "T1566.002"
  name: string;
  tactics: Tactic[];
  url: string;
}

export interface CysaDomain {
  id: string; // e.g. "1.0"
  name: string;
  blurb: string;
}

// A block of log/evidence shown to the analyst. Lines are pre-rendered, monospace.
export type ArtifactFormat = 'kv' | 'json' | 'raw' | 'table' | 'email';

export interface LogArtifact {
  source: string; // "Microsoft Entra ID — Sign-in logs", "Sysmon", "EDR — Falcon", ...
  format: ArtifactFormat;
  lines: string[];
  caption?: string;
}

// A checklist item a strong analyst would capture in their notes.
// keywords are lowercased tokens auto-detected in the analyst's free-text notes.
export interface RubricItem {
  id: string;
  text: string;
  keywords: string[];
}

export interface CaseGroundTruth {
  disposition: Disposition;
  severity: Severity;
  action: TriageAction;
  techniques: string[]; // MITRE technique ids; empty for clean benign/FP cases
  tactics: Tactic[];
}

export interface CaseReference {
  label: string;
  url: string;
}

// The concrete, fully-materialized case handed to the UI.
export interface TriageCase {
  id: string; // unique per generated instance
  templateId: string;
  category: Category;
  difficulty: Difficulty;
  title: string;
  alert: string; // the SIEM/queue alert that put this in front of you
  context: string; // one-line environment context
  artifacts: LogArtifact[];
  groundTruth: CaseGroundTruth;
  rubric: RubricItem[];
  explanation: string[]; // answer-key paragraphs
  pitfalls: string[];
  cysaDomains: string[];
  references: CaseReference[];
}

// What a template's build() produces (meta is layered on by the generator).
export interface CaseBody {
  alert: string;
  context: string;
  artifacts: LogArtifact[];
  groundTruth: CaseGroundTruth;
  rubric: RubricItem[];
  explanation: string[];
  pitfalls: string[];
  references: CaseReference[];
}

export interface BuildContext {
  rng: import('./engine/rng.ts').Rng;
  faker: import('./engine/fakes.ts').Faker;
}

export interface CaseTemplate {
  id: string;
  category: Category;
  difficulty: Difficulty;
  title: string;
  cysaDomains: string[];
  build(ctx: BuildContext): CaseBody;
}

// The analyst's submitted triage.
export interface TriageResponse {
  disposition: Disposition | null;
  severity: Severity | null;
  action: TriageAction | null;
  techniques: string[];
  notes: string;
}

export interface GradeBreakdown {
  label: string;
  earned: number;
  possible: number;
  detail: string;
  ok: boolean;
}

export interface GradeResult {
  score: number;
  maxScore: number;
  percent: number;
  dispositionCorrect: boolean;
  breakdown: GradeBreakdown[];
  matchedTechniques: string[];
  missedTechniques: string[];
  extraTechniques: string[];
  rubricAutoHits: string[]; // rubric item ids detected in notes
  xpAwarded: number;
}
