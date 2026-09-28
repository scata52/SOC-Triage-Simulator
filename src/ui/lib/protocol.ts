// Messages between the UI and the SIEM worker. The worker owns the corpus
// and the SQLite database; the UI only ever sees cases and query results.

import type { ResolvedCase, Scenario } from '../../core/cases/scenario.ts';
import type { QueryError, QueryLang, QueryResult } from '../../core/query/engine.ts';
import type { Cell, TableName } from '../../core/logs/schema.ts';
import type { ShiftPlan, Budget } from '../../core/shift/plan.ts';
import type { CampaignState } from '../../core/campaign/campaign.ts';

export type OpenSpec =
  | { kind: 'practice'; worldSeed: string; templateId: string; seed: string }
  | { kind: 'shift'; worldSeed: string; number: number; budget: Budget; campaign: CampaignState | null; recent: string[] };

export interface SessionInfo {
  key: string;
  now: string;
  windowStart: string;
  windowEnd: string;
  rowCount: number;
  rowsByTable: Record<TableName, number>;
  cases: ResolvedCase[];
  infra: Scenario['infra'];
  plan?: ShiftPlan;
  buildMs: number;
}

export interface LookupRow {
  table: string;
  columns: string[];
  row: Cell[];
}

export type Request =
  | { id: number; type: 'open'; spec: OpenSpec }
  | { id: number; type: 'run'; text: string; lang: QueryLang; maxRows: number }
  | { id: number; type: 'lookup'; ids: string[] };

export type Response =
  | { id: number; ok: true; type: 'open'; data: SessionInfo }
  | { id: number; ok: true; type: 'run'; data: QueryResult }
  | { id: number; ok: true; type: 'lookup'; data: LookupRow[] }
  | { id: number; ok: false; error: QueryError };

export function sessionKey(spec: OpenSpec): string {
  return spec.kind === 'practice' ? `practice:${spec.worldSeed}:${spec.templateId}:${spec.seed}` : `shift:${spec.worldSeed}:${spec.number}`;
}
