// Continuity between the two modes (DESIGN section 8, ADR-14): a real
// must-not-miss finding left open in a vulnerability case is remembered in the
// profile's ledger, and the next shift gets exactly one alert in which that
// host is exploited. The choice sits behind one pure function so that a later,
// attacker-driven version can replace it without changing the ledger or the
// SOC template that receives the hook.

import { VULN_DECISIONS, VULN_SCHEDULES, type VulnDecision, type VulnSchedule } from '../vuln/model.ts';
import { SIMVULN_ID_PATTERN } from '../vuln/ids.ts';
import type { VulnGrade, VulnSubmission } from '../vuln/grade.ts';
import type { ResolvedVulnCase } from '../vuln/scenario.ts';

export interface VulnLedgerEntry {
  id: string; // `${caseRef}/${findingId}@${completedAt}`, unique per graded attempt and finding
  vulnId: string; // SIMVULN-YYYY-NNNNN of the finding
  host: string; // DeviceName of the finding (a device of the shared world)
  decision: VulnDecision; // what the learner chose
  schedule: VulnSchedule; // what the learner scheduled
  decidedDay: number; // local day number of the attempt; orders the ledger, never shown or turned into a time
  caseRef: string; // the vuln attempt id: `${templateId}~${seed}`
  consumed?: boolean; // set when a shift took it
}

// What a shift receives: the entry it took and the seed its one extra alert is built from.
export interface VulnHook {
  ledgerId: string;
  host: string;
  vulnId: string;
  decidedDay: number;
  caseRef: string;
  decision: VulnDecision;
  schedule: VulnSchedule;
  seed: string;
}

// The SOC template that receives the hook (src/core/cases/templates/vuln-link.ts).
export const VULN_LINK_TEMPLATE_ID = 'endpoint-known-vuln-exploit';

// ---------------------------------------------------------------- ledger

// The ledger keeps at most this many entries (DESIGN section 8); consumed ones go first.
export const MAX_LEDGER = 50;

const nonEmpty = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

export function isLedgerEntry(x: unknown): x is VulnLedgerEntry {
  if (!x || typeof x !== 'object') return false;
  const e = x as Record<string, unknown>;
  return (
    nonEmpty(e.id) &&
    typeof e.vulnId === 'string' &&
    SIMVULN_ID_PATTERN.test(e.vulnId) &&
    nonEmpty(e.host) &&
    (VULN_DECISIONS as readonly unknown[]).includes(e.decision) &&
    (VULN_SCHEDULES as readonly unknown[]).includes(e.schedule) &&
    typeof e.decidedDay === 'number' &&
    Number.isFinite(e.decidedDay) &&
    nonEmpty(e.caseRef) &&
    (e.consumed === undefined || typeof e.consumed === 'boolean')
  );
}

export function isVulnHook(x: unknown): x is VulnHook {
  if (!x || typeof x !== 'object') return false;
  const h = x as Record<string, unknown>;
  return (
    nonEmpty(h.ledgerId) &&
    nonEmpty(h.host) &&
    typeof h.vulnId === 'string' &&
    SIMVULN_ID_PATTERN.test(h.vulnId) &&
    typeof h.decidedDay === 'number' &&
    Number.isFinite(h.decidedDay) &&
    nonEmpty(h.caseRef) &&
    (VULN_DECISIONS as readonly unknown[]).includes(h.decision) &&
    (VULN_SCHEDULES as readonly unknown[]).includes(h.schedule) &&
    nonEmpty(h.seed)
  );
}

// Keep the valid entries of a stored or imported ledger; undefined when nothing is left to keep.
export function coerceLedger(raw: unknown): VulnLedgerEntry[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const seen = new Set<string>();
  const kept: VulnLedgerEntry[] = [];
  for (const e of raw) {
    if (!isLedgerEntry(e) || seen.has(e.id)) continue;
    seen.add(e.id);
    kept.push({ id: e.id, vulnId: e.vulnId, host: e.host, decision: e.decision, schedule: e.schedule, decidedDay: e.decidedDay, caseRef: e.caseRef, ...(e.consumed ? { consumed: true } : {}) });
  }
  return trimLedger(kept);
}

// At most MAX_LEDGER entries: consumed entries are dropped before unconsumed
// ones, oldest (first in the list) first.
export function trimLedger(ledger: VulnLedgerEntry[]): VulnLedgerEntry[] {
  let excess = ledger.length - MAX_LEDGER;
  if (excess <= 0) return ledger;
  const drop = new Set<number>();
  for (const wantConsumed of [true, false]) {
    for (let i = 0; i < ledger.length && excess > 0; i++) {
      if (!!ledger[i].consumed === wantConsumed && !drop.has(i)) {
        drop.add(i);
        excess--;
      }
    }
  }
  return ledger.filter((_, i) => !drop.has(i));
}

// Entries a graded vulnerability case adds (DESIGN section 8, brief W1): the
// real must-not-miss findings the grader counts as left open, minus those a
// verified control already blocks, those on a host the shift corpus cannot
// show and those without a SIMVULN id. At most one unconsumed entry per
// (vulnId, host).
export function ledgerEntriesFor(
  c: Pick<ResolvedVulnCase, 'findings'>,
  grade: Pick<VulnGrade, 'mustNotMiss'>,
  submission: Pick<VulnSubmission, 'answers'>,
  attempt: { caseRef: string; completedAt: number; day: number },
  existing: readonly VulnLedgerEntry[] = [],
): VulnLedgerEntry[] {
  const open = new Set([...grade.mustNotMiss.dismissed, ...grade.mustNotMiss.late]);
  const taken = new Set(existing.filter((e) => !e.consumed).map((e) => `${e.vulnId}|${e.host}`));
  const out: VulnLedgerEntry[] = [];
  for (const f of c.findings) {
    if (!open.has(f.findingId) || !f.mustNotMiss || f.truth.decision === 'false-positive') continue;
    if (f.truth.decision === 'mitigate' || (f.truth.mitigation?.length ?? 0) > 0) continue;
    if (!f.sharedHost || !f.host || !SIMVULN_ID_PATTERN.test(f.vulnId)) continue;
    const answer = submission.answers[f.findingId];
    if (!answer?.decision) continue;
    const key = `${f.vulnId}|${f.host}`;
    if (taken.has(key)) continue;
    taken.add(key);
    out.push({
      id: `${attempt.caseRef}/${f.findingId}@${attempt.completedAt}`,
      vulnId: f.vulnId,
      host: f.host,
      decision: answer.decision,
      schedule: answer.schedule ?? 'none',
      decidedDay: attempt.day,
      caseRef: attempt.caseRef,
    });
  }
  return out;
}

export function addLedgerEntries(ledger: readonly VulnLedgerEntry[] | undefined, entries: readonly VulnLedgerEntry[]): VulnLedgerEntry[] | undefined {
  if (!entries.length) return ledger ? [...ledger] : undefined;
  return trimLedger([...(ledger ?? []), ...entries]);
}

// The one pure choice behind the hook (ADR-14): the oldest unconsumed entry, by
// decidedDay and then ledger order, or null. A later attacker-driven version can
// replace this function and nothing else.
export function selectVulnFollowUp(ledger: readonly VulnLedgerEntry[] | undefined, shiftSeed: string): VulnHook | null {
  let best: VulnLedgerEntry | null = null;
  for (const e of ledger ?? []) {
    if (e.consumed) continue;
    if (!best || e.decidedDay < best.decidedDay) best = e;
  }
  if (!best) return null;
  return {
    ledgerId: best.id,
    host: best.host,
    vulnId: best.vulnId,
    decidedDay: best.decidedDay,
    caseRef: best.caseRef,
    decision: best.decision,
    schedule: best.schedule,
    seed: `${shiftSeed}:vuln:${best.id}`,
  };
}

export function markConsumed(ledger: readonly VulnLedgerEntry[] | undefined, ledgerId: string): VulnLedgerEntry[] | undefined {
  if (!ledger) return undefined;
  return ledger.map((e) => (e.id === ledgerId ? { ...e, consumed: true } : e));
}
