// Pure helpers behind the vulnerability worklist UI (WP1e): labels, the
// default order, sorting and moving rows, the learner's draft and the
// submission built from it, the per-mode table lists and the case types the
// library shows. No DOM, no storage, no clock, so all of it is unit-testable.
//
// Leak boundary: nothing here reads truth, weights, tiers or the ideal order
// to build what the learner sees before submitting. The default order is the
// scanner's export order (FindingId ascending), computed from ids alone.

import { createRng } from '../rng.ts';
import { TABLES, type Cell, type TableInfo, type TableName } from '../logs/schema.ts';
import type { Difficulty } from '../types.ts';
import type { VulnFindingAnswer, VulnSubmission } from './grade.ts';
import { REASON_CODES, VULN_DECISIONS, VULN_SCHEDULES, type ReasonCode, type VulnDecision, type VulnSchedule, type VulnTemplate } from './model.ts';
import type { ResolvedVulnCase } from './scenario.ts';

// ---------------------------------------------------------------- constants

// The pass mark of a vulnerability case (the SOC pass mark, also the SRS one).
export const VULN_PASS_PERCENT = 70;
export const MAX_REASONS = 3;

export type SchemaMode = 'soc' | 'vuln';

export const DECISION_OPTION_TEXT: Record<VulnDecision | '', string> = {
  '': 'Choose…',
  patch: 'Patch',
  mitigate: 'Mitigate: put a control in front',
  avoid: 'Avoid: remove or disable the component',
  accept: 'Accept the risk',
  transfer: 'Transfer',
  'false-positive': 'False positive',
};

export const DECISION_LABELS: Record<VulnDecision, string> = {
  patch: 'Patch',
  mitigate: 'Mitigate',
  avoid: 'Avoid',
  accept: 'Accept',
  transfer: 'Transfer',
  'false-positive': 'False positive',
};

export const SCHEDULE_LABELS: Record<VulnSchedule, string> = {
  emergency: 'Emergency change',
  'next-window': 'Next maintenance window',
  'standard-cycle': 'Standard patch cycle',
  none: 'No change',
};

export const REASON_LABELS: Record<ReasonCode, string> = {
  'known-exploited': 'Known exploited (Sim-KEV)',
  'high-exploit-probability': 'High exploit probability (Sim-EPSS)',
  'public-exploit': 'Public exploit',
  'low-exploitability': 'Low exploitability',
  'internet-exposed': 'Internet-exposed',
  'critical-asset': 'Critical asset',
  'sensitive-data': 'Sensitive data',
  'compensating-control-verified': 'Compensating control verified',
  'control-not-covering': 'Control does not cover it',
  'credentialed-confirmed': 'Confirmed by a credentialed scan',
  'banner-only': 'Banner-only detection',
  'backported-fix': 'Backported fix',
  'stale-scan': 'Stale scan',
  'pending-reboot': 'Reboot pending',
  'duplicate-root-cause': 'Duplicate root cause',
  'vendor-responsibility': "Vendor's responsibility",
  'no-vendor-fix': 'No vendor fix',
  'approved-exception': 'Approved risk exception',
  'unused-component': 'Unused component',
  'sla-deadline': 'SLA deadline',
  'change-freeze': 'Change freeze',
};

// The same groups and order for every finding; required codes never stand out.
export const REASON_GROUPS: readonly {
  title: string;
  codes: readonly ReasonCode[];
}[] = [
  {
    title: 'Exploitation',
    codes: ['known-exploited', 'high-exploit-probability', 'public-exploit', 'low-exploitability'],
  },
  {
    title: 'Exposure and asset',
    codes: ['internet-exposed', 'critical-asset', 'sensitive-data'],
  },
  {
    title: 'Controls',
    codes: ['compensating-control-verified', 'control-not-covering'],
  },
  {
    title: 'Scan evidence',
    codes: ['credentialed-confirmed', 'banner-only', 'backported-fix', 'stale-scan', 'pending-reboot', 'duplicate-root-cause'],
  },
  {
    title: 'Fix and ownership',
    codes: ['vendor-responsibility', 'no-vendor-fix', 'approved-exception', 'unused-component'],
  },
  { title: 'Timing', codes: ['sla-deadline', 'change-freeze'] },
];

export type SortKey = 'finding' | 'host' | 'vulnerability' | 'severity' | 'cvss' | 'firstSeen';
export type SortDir = 'asc' | 'desc';
export interface WorklistSort {
  key: SortKey;
  dir: SortDir;
}
export interface SortUndo {
  order: string[];
  sort: WorklistSort | null;
}

export const SORT_KEYS: readonly SortKey[] = ['finding', 'host', 'vulnerability', 'severity', 'cvss', 'firstSeen'];

// Visible column headers (a sort button's accessible name starts with its header).
export const SORT_HEADERS: Record<SortKey, string> = {
  finding: 'Finding',
  host: 'Host',
  vulnerability: 'Vulnerability',
  severity: 'Severity (scanner)',
  cvss: 'CVSS',
  firstSeen: 'First seen',
};

// The direction a first click sorts in (the bold one of the two labels).
export const SORT_FIRST_DIR: Record<SortKey, SortDir> = {
  finding: 'asc',
  host: 'asc',
  vulnerability: 'asc',
  severity: 'desc',
  cvss: 'desc',
  firstSeen: 'asc',
};

// ---------------------------------------------------------------- rows

export interface WorklistRow {
  findingId: string;
  recordId: string;
  host: string; // DeviceName
  vulnId: string; // '' for hygiene findings
  title: string;
  severity: string; // the scanner's own rating
  cvss: number | null;
  firstSeen: string; // ISO
}

// What the screens that show a case before submitting may read: six fields,
// copied. Never the id, template id, twin, lesson, findings, tiers or rubric.
export type VulnCaseView = Pick<ResolvedVulnCase, 'title' | 'difficulty' | 'now' | 'briefing' | 'attachments' | 'hints'>;

export function caseView(c: ResolvedVulnCase): VulnCaseView {
  return {
    title: c.title,
    difficulty: c.difficulty,
    now: c.now,
    briefing: c.briefing,
    attachments: c.attachments.map((a) => ({ ...a })),
    hints: [...c.hints],
  };
}

const byCodeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

// The scanner's export order: FindingId ascending. Takes ids only, so it can
// never depend on the spec order, the truth, the tiers or the ideal order.
export function defaultOrder(ids: readonly string[]): string[] {
  return [...new Set(ids)].sort(byCodeUnit);
}

export interface LookupRowLike {
  columns: readonly string[];
  row: readonly Cell[];
}

const cellStr = (v: Cell | undefined): string => (v === null || v === undefined ? '' : String(v));

// The worklist rows, keyed by FindingId and built in default order (so even
// iterating the map never shows spec order). Independent of the order of the
// pairs and of the lookup rows.
export function worklistRows(pairs: readonly { findingId: string; recordId: string }[], lookupRows: readonly LookupRowLike[]): Map<string, WorklistRow> {
  const byRecord = new Map<string, Record<string, Cell>>();
  for (const r of lookupRows) {
    const o: Record<string, Cell> = {};
    r.columns.forEach((c, i) => (o[c] = r.row[i] ?? null));
    const id = o.RecordId;
    if (typeof id === 'string') byRecord.set(id, o);
  }
  const recordOf = new Map(pairs.map((p) => [p.findingId, p.recordId]));
  const out = new Map<string, WorklistRow>();
  for (const findingId of defaultOrder(pairs.map((p) => p.findingId))) {
    const recordId = recordOf.get(findingId)!;
    const o = byRecord.get(recordId) ?? {};
    const cvss = o.CvssBase;
    out.set(findingId, {
      findingId,
      recordId,
      host: cellStr(o.DeviceName),
      vulnId: cellStr(o.VulnId),
      title: cellStr(o.Title),
      severity: cellStr(o.Severity),
      cvss: typeof cvss === 'number' && Number.isFinite(cvss) ? cvss : null,
      firstSeen: cellStr(o.FirstSeen),
    });
  }
  return out;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

// Critical 4 .. Info 0, anything else -1.
export function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? -1;
}

export function formatCvss(cvss: number | null): string {
  return cvss === null ? 'no score' : cvss.toFixed(1);
}

// ---------------------------------------------------------------- sorting

export function dirLabel(key: SortKey, dir: SortDir): string {
  const asc = dir === 'asc';
  switch (key) {
    case 'finding':
      return asc ? 'scanner order' : 'reverse scanner order';
    case 'host':
    case 'vulnerability':
      return asc ? 'A to Z' : 'Z to A';
    case 'severity':
      return asc ? 'least severe first' : 'most severe first';
    case 'cvss':
      return asc ? 'lowest first' : 'highest first';
    case 'firstSeen':
      return asc ? 'oldest first' : 'newest first';
  }
}

// Same column again flips the direction; a new column starts in its first direction.
export function nextSort(cur: WorklistSort | null, key: SortKey): WorklistSort {
  if (cur && cur.key === key) return { key, dir: cur.dir === 'asc' ? 'desc' : 'asc' };
  return { key, dir: SORT_FIRST_DIR[key] };
}

// The name of a sort button: its visible header text first (WCAG 2.5.3).
export function sortButtonLabel(key: SortKey, dir: SortDir): string {
  return `${SORT_HEADERS[key]}: sort ${dirLabel(key, dir)}`;
}

export function sortMessage(key: SortKey, dir: SortDir): string {
  return `Worklist sorted by ${SORT_HEADERS[key]}, ${dirLabel(key, dir)}. Undo sort restores your previous order.`;
}

export const UNDO_SORT_MESSAGE = 'Sort undone. Your previous order is back.';

export function sortStatus(sort: WorklistSort | null): string {
  return sort ? `Sorted by ${SORT_HEADERS[sort.key]}, ${dirLabel(sort.key, sort.dir)}` : 'Your own order';
}

function sortValue(row: WorklistRow | undefined, key: SortKey, id: string): string | number | null {
  if (key === 'finding') return id;
  if (!row) return null;
  switch (key) {
    case 'host':
      return row.host ? row.host.toLowerCase() : null;
    case 'vulnerability':
      return row.title ? row.title.toLowerCase() : null;
    case 'severity':
      return severityRank(row.severity);
    case 'cvss':
      return row.cvss;
    case 'firstSeen':
      return row.firstSeen || null;
  }
}

// A total order by the column (missing values last in both directions, ties by
// FindingId ascending), so the result does not depend on the incoming order.
export function sortOrder(order: readonly string[], rows: ReadonlyMap<string, WorklistRow>, sort: WorklistSort): string[] {
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...new Set(order)].sort((a, b) => {
    const va = sortValue(rows.get(a), sort.key, a);
    const vb = sortValue(rows.get(b), sort.key, b);
    if (va !== vb) {
      if (va === null) return 1;
      if (vb === null) return -1;
      const c = typeof va === 'number' && typeof vb === 'number' ? va - vb : byCodeUnit(String(va), String(vb));
      if (c !== 0) return sign * c;
    }
    return byCodeUnit(a, b);
  });
}

export function applySort(draft: VulnDraft, rows: ReadonlyMap<string, WorklistRow>, key: SortKey, undo: SortUndo | null): { draft: VulnDraft; undo: SortUndo; message: string } {
  const sort = nextSort(draft.sort, key);
  return {
    draft: { ...draft, order: sortOrder(draft.order, rows, sort), sort },
    // Consecutive sorts keep the snapshot taken before the first: the learner's own order.
    undo: undo ?? { order: [...draft.order], sort: draft.sort },
    message: sortMessage(sort.key, sort.dir),
  };
}

export function undoSort(draft: VulnDraft, undo: SortUndo): VulnDraft {
  return { ...draft, order: [...undo.order], sort: undo.sort };
}

// ---------------------------------------------------------------- moving

export interface MoveResult {
  order: string[];
  from: number; // 0-based; -1 when the id is not in the order
  to: number; // 0-based
}

export function moveTo(order: readonly string[], id: string, index: number): MoveResult {
  const from = order.indexOf(id);
  if (from < 0) return { order: order as string[], from: -1, to: -1 };
  const to = Math.max(0, Math.min(order.length - 1, Number.isFinite(index) ? Math.trunc(index) : from));
  if (to === from) return { order: order as string[], from, to };
  const next = [...order];
  next.splice(from, 1);
  next.splice(to, 0, id);
  return { order: next, from, to };
}

export function moveBy(order: readonly string[], id: string, delta: number): MoveResult {
  const from = order.indexOf(id);
  return moveTo(order, id, from + delta);
}

// `to` is the 0-based index a move returns; the message counts from 1.
export function positionMessage(id: string, to: number, n: number): string {
  return `${id} moved to position ${to + 1} of ${n}.`;
}

export function stayMessage(id: string, at: number, n: number): string {
  return `${id} stays at position ${at + 1} of ${n}.`;
}

export function boundsMessage(id: string, edge: 'first' | 'last'): string {
  return `${id} is already ${edge}.`;
}

// ---------------------------------------------------------------- reasons

export function toggleReason(reasons: readonly ReasonCode[], code: ReasonCode, max = MAX_REASONS): { reasons: ReasonCode[]; capped: boolean } {
  if (!(REASON_CODES as readonly string[]).includes(code)) return { reasons: [...reasons], capped: false };
  if (reasons.includes(code)) return { reasons: reasons.filter((r) => r !== code), capped: false };
  if (reasons.length >= max) return { reasons: [...reasons], capped: true };
  return { reasons: [...reasons, code], capped: false };
}

export function capMessage(id: string): string {
  return `Three reasons chosen for ${id}. Uncheck one to choose another.`;
}

// ---------------------------------------------------------------- draft

export interface VulnDraft {
  v: 1;
  order: string[]; // findingIds; the table order IS the priority order
  answers: Record<string, VulnFindingAnswer>;
  pins: string[]; // RecordIds
  notes: string;
  hintsUsed: number;
  sort: WorklistSort | null; // the last column sort; null after a manual move or an undo
}

export function emptyDraft(ids: readonly string[]): VulnDraft {
  return {
    v: 1,
    order: defaultOrder(ids),
    answers: {},
    pins: [],
    notes: '',
    hintsUsed: 0,
    sort: null,
  };
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function distinctReasons(v: unknown): ReasonCode[] {
  const out: ReasonCode[] = [];
  if (!Array.isArray(v)) return out;
  for (const r of v) {
    if (out.length === MAX_REASONS) break;
    if ((REASON_CODES as readonly string[]).includes(r as string) && !out.includes(r as ReasonCode)) out.push(r as ReasonCode);
  }
  return out;
}

// Anything malformed becomes an empty draft; a draft with stale ids is repaired.
export function restoreDraft(raw: unknown, ids: readonly string[], hintCount: number): VulnDraft {
  const all = defaultOrder(ids);
  if (!isRecord(raw) || raw.v !== 1) return emptyDraft(all);
  const known = new Set(all);
  const order: string[] = [];
  if (Array.isArray(raw.order)) for (const id of raw.order) if (typeof id === 'string' && known.has(id) && !order.includes(id)) order.push(id);
  for (const id of all) if (!order.includes(id)) order.push(id);

  const answers: Record<string, VulnFindingAnswer> = {};
  if (isRecord(raw.answers)) {
    for (const id of all) {
      const a = Object.hasOwn(raw.answers, id) ? raw.answers[id] : undefined;
      if (!isRecord(a)) continue;
      answers[id] = {
        decision: (VULN_DECISIONS as readonly unknown[]).includes(a.decision) ? (a.decision as VulnDecision) : null,
        control: typeof a.control === 'string' ? a.control : null,
        schedule: (VULN_SCHEDULES as readonly unknown[]).includes(a.schedule) ? (a.schedule as VulnSchedule) : null,
        reasons: distinctReasons(a.reasons),
      };
    }
  }

  const pins = Array.isArray(raw.pins) ? [...new Set(raw.pins.filter((p): p is string => typeof p === 'string'))] : [];
  const hints = typeof raw.hintsUsed === 'number' && Number.isFinite(raw.hintsUsed) ? Math.floor(raw.hintsUsed) : 0;
  let sort: WorklistSort | null = null;
  if (isRecord(raw.sort) && (SORT_KEYS as readonly unknown[]).includes(raw.sort.key) && (raw.sort.dir === 'asc' || raw.sort.dir === 'desc')) {
    sort = { key: raw.sort.key as SortKey, dir: raw.sort.dir };
  }
  return {
    v: 1,
    order,
    answers,
    pins,
    notes: typeof raw.notes === 'string' ? raw.notes : '',
    hintsUsed: Math.max(0, Math.min(Math.max(0, hintCount), hints)),
    sort,
  };
}

// ---------------------------------------------------------------- submission

const hasAnswer = (a: VulnFindingAnswer) => a.decision !== null || a.control !== null || a.schedule !== null || a.reasons.length > 0;

// The draft as the grader reads it. The table order is the submitted order;
// findings with no decision are unranked, so an untouched worklist grades 0.
export function buildSubmission(d: VulnDraft): VulnSubmission {
  const answers: Record<string, VulnFindingAnswer> = {};
  for (const id of Object.keys(d.answers)) {
    const a = d.answers[id];
    if (!hasAnswer(a)) continue;
    answers[id] = {
      decision: a.decision,
      control: a.decision === 'mitigate' ? (a.control ?? null) : null,
      schedule: a.schedule,
      reasons: distinctReasons(a.reasons),
    };
  }
  return {
    answers,
    order: d.order.filter((id) => d.answers[id]?.decision != null),
    pins: [...new Set(d.pins)],
    notes: d.notes,
    hintsUsed: d.hintsUsed,
  };
}

export interface MissingItem {
  findingId: string;
  field: 'decision' | 'control' | 'schedule';
}

// What still blocks a submit, in table order (per finding: decision, control,
// schedule). A control is asked for only when the decision is mitigate and the
// inventory lists controls at all; with none, mitigate and a schedule is complete.
export function missingForSubmit(d: VulnDraft, controlCount: number): MissingItem[] {
  const out: MissingItem[] = [];
  for (const findingId of d.order) {
    const a = d.answers[findingId];
    if (!a || a.decision === null) out.push({ findingId, field: 'decision' });
    if (a && a.decision === 'mitigate' && controlCount > 0 && !a.control) out.push({ findingId, field: 'control' });
    if (!a || a.schedule === null) out.push({ findingId, field: 'schedule' });
  }
  return out;
}

export function stillNeededMessage(missing: readonly MissingItem[], rows: ReadonlyMap<string, WorklistRow>): string {
  const text = (m: MissingItem) => {
    const host = rows.get(m.findingId)?.host;
    return `${m.field} for ${m.findingId}${host ? ` on ${host}` : ''}`;
  };
  const shown = missing.slice(0, 3).map(text).join(', ');
  const more = missing.length > 3 ? ` and ${missing.length - 3} more` : '';
  return `Still needed: ${shown}${more}.`;
}

// Pinned rows (any table) that mention this finding's id, its vulnerability id
// or its host. Display only, never graded.
export function pinCount(row: Pick<WorklistRow, 'findingId' | 'vulnId' | 'host'>, pinnedRows: readonly { row: readonly unknown[] }[]): number {
  const wanted = new Set([row.findingId, row.vulnId, row.host].filter((s) => s !== ''));
  return pinnedRows.filter((p) => p.row.some((cell) => typeof cell === 'string' && wanted.has(cell))).length;
}

// ---------------------------------------------------------------- tables per mode

// The six tables vulnerability cases add; SOC sessions leave them out of the
// schema browser, autocomplete and Help (they are empty there).
export const VULN_TABLE_NAMES = ['VulnFindings', 'ScanRuns', 'VulnIntel', 'SoftwareInventory', 'PatchHistory', 'ControlInventory'] as const satisfies readonly TableName[];

const VULN_TABLE_SET: ReadonlySet<string> = new Set(VULN_TABLE_NAMES);

export function isVulnTable(name: string): boolean {
  return VULN_TABLE_SET.has(name);
}

const SOC_TABLES: readonly TableInfo[] = TABLES.filter((t) => !VULN_TABLE_SET.has(t.name));

export function tablesFor(mode: SchemaMode): readonly TableInfo[] {
  return mode === 'vuln' ? TABLES : SOC_TABLES;
}

// ---------------------------------------------------------------- case types

export function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

export interface VulnCaseType {
  slug: string;
  title: string;
  templates: VulnTemplate[];
  difficulty: Difficulty;
  cysaDomains: string[];
  objectives: string[];
}

const TIER_ORDER: Record<Difficulty, number> = { tier1: 1, tier2: 2, tier3: 3 };

// Templates that share a title are one case type (twins); ordered by tier, then title.
export function vulnCaseTypes(templates: readonly VulnTemplate[]): VulnCaseType[] {
  const by = new Map<string, VulnTemplate[]>();
  for (const t of templates) by.set(t.title, [...(by.get(t.title) ?? []), t]);
  return [...by.entries()]
    .map(([title, ts]) => ({
      slug: slugify(title),
      title,
      templates: ts,
      difficulty: ts[0].difficulty,
      cysaDomains: [...new Set(ts.flatMap((t) => t.cysaDomains))].sort(),
      objectives: [...new Set(ts.flatMap((t) => t.objectives))].sort(),
    }))
    .sort((a, b) => TIER_ORDER[a.difficulty] - TIER_ORDER[b.difficulty] || byCodeUnit(a.title, b.title));
}

// Which twin a start gets is decided by the seed; neither the card nor the URL says.
export function resolveVulnTemplate(type: VulnCaseType, seed: string): VulnTemplate {
  const n = type.templates.length;
  if (n === 1) return type.templates[0];
  return type.templates[createRng(`vuln-variant:${type.slug}:${seed}`).int(0, n - 1)];
}

// A seed (derived from `base`) whose twin is the given template, found like the
// SOC `seedFor`. `types` is the case-type list (`vulnCaseTypes(VULN_TEMPLATES)`);
// it is passed in so this file does not depend on the registry.
export function vulnSeedFor(types: readonly VulnCaseType[], templateId: string, base: string): { slug: string; seed: string } | null {
  const type = types.find((t) => t.templates.some((x) => x.id === templateId));
  if (!type) return null;
  for (let i = 0; i < 200; i++) {
    const seed = i === 0 ? base : `${base}${i.toString(36)}`;
    if (resolveVulnTemplate(type, seed).id === templateId) return { slug: type.slug, seed };
  }
  return { slug: type.slug, seed: base };
}
