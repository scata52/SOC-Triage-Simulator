// Case template v2. A template is a generator that emits log rows into the
// shared corpus and returns the alert, the answer key, the evidence points
// (as handles on the rows it emitted), the indicators, and a reference
// investigation. Nothing about a row marks it as signal except the handle.

import type { Rng } from '../rng.ts';
import type { Category, CaseReference, Difficulty, GroundTruth, RubricItem, Severity } from '../types.ts';
import type { CorpusBuilder, RowRef } from '../logs/corpus.ts';
import type { World } from '../world/world.ts';
import type { WorldIndex } from '../world/index.ts';
import type { Picker } from './picker.ts';
import type { Infra } from './infra.ts';
import type { Session } from '../logs/noise/presence.ts';

export type EntityKind = 'user' | 'host' | 'ip' | 'domain' | 'url' | 'sha256' | 'email' | 'file' | 'process';

export interface AlertEntity {
  kind: EntityKind;
  value: string;
  label?: string;
}

export interface AlertSpec {
  rule: string; // detection name — also the queue title
  product: string; // detecting product
  severity: Severity; // as rated by the tool (often wrong!)
  time: number; // epoch ms
  summary: string; // what the detection says — never the deciding fact
  entities: AlertEntity[];
  fields?: [string, string][];
}

export type AttachmentKind = 'email' | 'text' | 'kv' | 'json';

export interface Attachment {
  title: string;
  kind: AttachmentKind;
  body: string | [string, string][];
  caption?: string;
}

export interface EvidenceSpec {
  id: string;
  label: string; // what the analyst should have found
  why: string; // why it matters (debrief)
  rows: RowRef[]; // pinning any one of these satisfies the point
}

export type IndicatorKind = 'ip' | 'domain' | 'url' | 'sha256' | 'email' | 'user' | 'host' | 'file';

export interface IndicatorSpec {
  kind: IndicatorKind;
  value: string;
  note?: string;
  aliases?: string[]; // other spellings that count (e.g. sam vs UPN)
}

export interface Indicators {
  block: IndicatorSpec[]; // malicious — block and hunt
  scope: IndicatorSpec[]; // affected users/hosts — contain
  mustNot: IndicatorSpec[]; // own or benign infrastructure that must not be flagged
}

export interface SolutionStep {
  title: string;
  kql: string;
  why: string;
}

export interface CaseSpec {
  alert: AlertSpec;
  briefing: string;
  attachments?: Attachment[];
  truth: GroundTruth;
  evidence: EvidenceSpec[];
  indicators: Indicators;
  hints: string[];
  solution: SolutionStep[];
  rubric: RubricItem[];
  explanation: string[];
  pitfalls: string[];
  references: CaseReference[];
}

export type CaseKind = 'incident' | 'benign' | 'ops';
export type CampaignStage = 'initial-access' | 'execution' | 'persistence' | 'discovery' | 'lateral' | 'objective';
export type TimePreference = 'business' | 'off-hours' | 'any';

export interface CaseContext {
  rng: Rng;
  world: World;
  idx: WorldIndex;
  log: CorpusBuilder;
  at: number; // alert time
  now: number; // corpus "now" (≥ at)
  sessions: Session[];
  pick: Picker;
  infra: Infra;
  // Campaign continuity: the person/host the actor already controls, if any.
  foothold?: { personId?: string; host?: string };
}

export interface CaseTemplate {
  id: string;
  category: Category;
  difficulty: Difficulty;
  title: string; // scenario name (stats, study plan)
  cysaDomains: string[];
  kind: CaseKind;
  twin?: string;
  stages?: CampaignStage[];
  when?: TimePreference;
  build(ctx: CaseContext): CaseSpec;
}
