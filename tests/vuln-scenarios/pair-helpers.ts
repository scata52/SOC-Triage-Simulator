// Shared by the twin-pair suites of the content batches (batch-a.test.ts, batch-b.test.ts): the row helpers, the pair
// table types and the generic checks every twin pair must pass, written as a table keyed by twin pair. A later author adds a
// row to a batch's PAIRS; nothing else changes. The checks, per pair, on the standard seeds:
//   - both twins are registered and name each other (tests/vuln-scenarios/slice.test.ts checks this for every pair too);
//   - same title, difficulty and headline row (VulnId, host, CVSS base, FirstSeen, DetectedVersion);
//   - the lesson findings differ by decision, by two or more schedule steps, or across the SLA (DESIGN 5.8; 1 to 3 of them, any number in tier 3);
//   - each twin's lesson text names its deciding clue (the table and the fact);
//   - the deciding clue is in the data on every run, A vs B;
//   - the pre-submit surface does not give the twin away: same briefing, attachments and hint 1, and the same
//     number of rows in every table (the T3 test in kev-internal.test.ts does the same for its pair).
// It is not a test file (no .test suffix): importing it registers nothing; a suite calls `registerPairSuite`.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { VULN_SCHEDULES, type FindingTruth, type VulnTemplate } from '../../src/core/vuln/model.ts';
import type { VulnScenario } from '../../src/core/vuln/scenario.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

export type Row = Record<string, unknown>;
export const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
export const flag = (v: unknown): boolean => v === true || v === 1;

// The same seed set as the T3 pre-submit test (kev-internal.test.ts).
export const STANDARD = vulnRuns(20, 20);
export const SEEDS = [...STANDARD, ...Array.from({ length: 20 }, (_, i) => ({ world: 'vuln-world-0', seed: `wl${i}` })), { world: 'e2e-world', seed: 'e2e' }];

// What a clue check sees: both twins built on one seed.
export interface Pair {
  a: VulnScenario;
  b: VulnScenario;
  label: string;
}

export interface PairRow {
  pair: string; // T1, T2, T4, T5, ...
  a: string; // template ids
  b: string;
  // Tokens (case-insensitive) each twin's lesson must contain: the deciding table and the fact in it.
  lesson: { a: string[]; b: string[] };
  // The deciding clue is present in the data of each twin, and only there (throws through expect).
  clue: (p: Pair) => void;
  // Template-specific facts of the pair that the batch checks (optional).
  extra?: (p: Pair) => void;
}

export const headRow = (s: VulnScenario): Row => rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[0].recordId)!;

// The row of a worklist finding (by its place in the worklist).
export const findingRow = (s: VulnScenario, index: number): Row => rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[index].recordId)!;

// The intel row of the headline, without its RecordId, as one string: the twins' intel must be identical.
export const headIntel = (s: VulnScenario): string => JSON.stringify(rows(s.corpus, 'VulnIntel').filter((r) => r.VulnId === headRow(s).VulnId).map(({ RecordId: _r, ...rest }) => rest));

const TEMPLATES: readonly VulnTemplate[] = VULN_CASE_TEMPLATES;
export const byId = (id: string): VulnTemplate => {
  const t = TEMPLATES.find((x) => x.id === id);
  if (!t) throw new Error(`${id} is not registered`);
  return t;
};
export const build = (t: VulnTemplate, run: { world: string; seed: string }): VulnScenario => buildFor(t, world(run.world), run.seed);
export const pairOn = (r: PairRow, run: { world: string; seed: string }): Pair => ({ a: build(byId(r.a), run), b: build(byId(r.b), run), label: `${r.pair} ${run.world}/${run.seed}` });

// DESIGN 5.8: the twins' lesson findings differ by decision, by two or more schedule steps, or across the SLA.
export function differsByRule3(x: FindingTruth, y: FindingTruth): boolean {
  if (x.decision !== y.decision) return true;
  const at = (s: FindingTruth['schedule']) => VULN_SCHEDULES.indexOf(s);
  if (Math.abs(at(x.schedule) - at(y.schedule)) >= 2) return true;
  const late = (p: FindingTruth, q: FindingTruth) => q.slaLatest !== undefined && at(p.schedule) > at(q.slaLatest);
  return late(x, y) || late(y, x);
}

// The generic checks for one batch's pair table (describe blocks named "<batch> twin pair <T>").
export function registerPairSuite(batch: string, pairs: readonly PairRow[]): void {
  describe.each(pairs.map((r) => [r.pair, r] as const))(`${batch} twin pair %s`, (_pair, r) => {
    it('shares title, difficulty and headline row, and differs by rule 3', () => {
      const [ta, tb] = [byId(r.a), byId(r.b)];
      expect(ta.title, 'title').toBe(tb.title);
      expect(ta.difficulty, 'difficulty').toBe(tb.difficulty);
      for (const run of STANDARD) {
        const p = pairOn(r, run);
        const [ha, hb] = [headRow(p.a), headRow(p.b)];
        for (const col of ['VulnId', 'DeviceName', 'CvssBase', 'FirstSeen', 'DetectedVersion', 'Title']) expect(ha[col], `${p.label}: headline ${col}`).toEqual(hb[col]);
        const [fa, fb] = [p.a.case.findings[0], p.b.case.findings[0]];
        expect(fa.lesson && fb.lesson, `${p.label}: findings[0] is a lesson finding in both twins`).toBe(true);
        for (const s of [p.a, p.b]) {
          const lessons = s.case.findings.filter((f) => f.lesson).length;
          expect(lessons, `${p.label}: ${s.case.templateId} flags 1 to 3 lesson findings`).toBeGreaterThanOrEqual(1);
          // DESIGN 5.8: 1 to 3 lesson findings; tier 3 lifts the upper bound (the rule there is to flag every finding the lesson names).
          expect(lessons, `${p.label}: ${s.case.templateId} flags at most ${byId(s.case.templateId).difficulty === 'tier3' ? 'half the case as' : '3'} lesson findings`).toBeLessThanOrEqual(byId(s.case.templateId).difficulty === 'tier3' ? Math.floor(s.case.findings.length / 2) : 3); // DESIGN 5.8
          for (const f of s.case.findings.filter((x) => (x.lesson || x.mustNotMiss) && x.truth.decision !== 'false-positive')) expect(f.truth.slaLatest, `${p.label}: key finding ${f.findingId} has slaLatest`).toBeDefined();
        }
        expect(differsByRule3(fa.truth, fb.truth), `${p.label}: the headline truths differ by decision, two schedule steps or across the SLA`).toBe(true);
      }
    });

    it("names each twin's deciding clue in its lesson: the table and the fact in it", () => {
      for (const [id, tokens] of [[r.a, r.lesson.a], [r.b, r.lesson.b]] as const) {
        const lesson = byId(id).lesson.toLowerCase();
        for (const token of tokens) expect(lesson, `${id}: lesson names "${token}"`).toContain(token.toLowerCase());
      }
    });

    it('has the deciding clue in the data on every run, A against B', () => {
      for (const run of STANDARD) {
        const p = pairOn(r, run);
        r.clue(p);
        r.extra?.(p);
      }
    });

    it('has no empty interpolation slot (a double space) in any explanation, hint, pitfall, solution step or rubric text', () => {
      for (const run of STANDARD) {
        const p = pairOn(r, run);
        for (const s of [p.a, p.b]) {
          const c = s.case;
          const texts = [...c.explanation, ...c.hints, ...c.pitfalls, ...c.solution.flatMap((x) => [x.title, x.why]), ...c.rubric.map((x) => x.text), ...c.findings.flatMap((f) => f.evidence.flatMap((e) => [e.label, e.why]))];
          for (const t of texts) expect(t, `${p.label}: ${c.templateId}: a double space in "${t.slice(0, 60)}"`).not.toMatch(/\S {2,}\S/);
        }
      }
    });

    it('presents the same pre-submit surface: briefing, attachments, hint 1 and the row count of every table', () => {
      for (const run of SEEDS) {
        const p = pairOn(r, run);
        expect(p.a.case.briefing, `${p.label}: briefing`).toBe(p.b.case.briefing);
        expect(JSON.stringify(p.a.case.attachments), `${p.label}: attachments`).toBe(JSON.stringify(p.b.case.attachments));
        expect(p.a.case.hints[0], `${p.label}: hint 1`).toBe(p.b.case.hints[0]);
        for (const name of Object.keys(p.a.corpus.tables) as (keyof Corpus['tables'])[]) {
          expect(p.a.corpus.tables[name].rows.length, `${p.label}: rows of ${name}`).toBe(p.b.corpus.tables[name].rows.length);
        }
      }
    });
  });
}
