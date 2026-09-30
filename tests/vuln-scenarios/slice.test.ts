// WP1d: every registered vulnerability-management template (VULN_CASE_TEMPLATES)
// is built on many seeds and checked for: the shared engine checks (database,
// determinism, perfect = 100, empty = 0, every evidence row found by the
// reference KQL), metadata, the DESIGN 6.3 noise budget, twin symmetry, and
// the DESIGN 5.6 worked example on the T3 case. A new template only needs to
// be added to templates/index.ts to be covered here.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
type RowObject = Record<string, unknown>;
import { gradeVulnCase, type VulnGrade, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import type { VulnTemplate } from '../../src/core/vuln/model.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import { AUTH_FAILURE_TITLE, FREEZE_TITLE_PREFIX, WINDOW_TITLE_PREFIX } from '../../src/core/vuln/templates/common.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, checkVulnTemplate, vulnRuns } from '../helpers/vuln-scenario-check.ts';

const RUNS = vulnRuns(20, 20);
const TIMEOUT = 600_000;
const TEMPLATES: readonly VulnTemplate[] = VULN_CASE_TEMPLATES;
const OBJECTIVES = ['2.1', '2.2', '2.3', '2.4', '2.5', '4.1'];
const SIZE: Record<string, [number, number]> = { tier1: [4, 6], tier2: [8, 12], tier3: [15, 25] };

function rows(corpus: Corpus, table: keyof Corpus['tables']): RowObject[] {
  const t = corpus.tables[table];
  return t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])) as RowObject);
}

const build = (t: VulnTemplate, run: (typeof RUNS)[number]) => buildFor(t, world(run.world), run.seed);

it('registers at least one template', () => {
  expect(TEMPLATES.length).toBeGreaterThan(0);
  expect(new Set(TEMPLATES.map((t) => t.id)).size).toBe(TEMPLATES.length);
});

describe.each(TEMPLATES.map((t) => [t.id, t] as const))('%s', (_id, t) => {
  it('passes the shared engine checks on 20 seeds, every evidence row found by the reference KQL', async () => {
    await checkVulnTemplate(t, RUNS, 20, { everyEvidenceRow: true });
  }, TIMEOUT);

  it('has valid metadata and a worklist that fits its difficulty', () => {
    expect(t.id.startsWith('vm-')).toBe(true);
    expect(t.kind).toBe('vuln');
    expect(t.title.trim()).not.toBe('');
    expect(t.lesson.trim()).not.toBe('');
    expect(t.cysaDomains).toContain('2.0');
    expect(t.objectives.length).toBeGreaterThan(0);
    for (const o of t.objectives) expect(OBJECTIVES, `${t.id}: objective ${o}`).toContain(o);
    if (t.twin) {
      const twin = TEMPLATES.find((x) => x.id === t.twin);
      expect(twin, `${t.id}: twin ${t.twin} is registered`).toBeDefined();
      expect(twin!.twin, `${t.twin} names ${t.id} back`).toBe(t.id);
    }
    const [lo, hi] = SIZE[t.difficulty];
    for (const run of RUNS) {
      const c = build(t, run).case;
      expect(c.findings.length, `${t.id} ${run.seed}: worklist size for ${t.difficulty}`).toBeGreaterThanOrEqual(lo);
      expect(c.findings.length, `${t.id} ${run.seed}: worklist size for ${t.difficulty}`).toBeLessThanOrEqual(hi);
    }
  });

  it('keeps the DESIGN 6.3 noise budget on every seed', () => {
    for (const run of RUNS) {
      const { corpus, case: c } = build(t, run);
      const label = `${t.id} ${run.world}/${run.seed}`;

      const runs = rows(corpus, 'ScanRuns');
      expect(runs.length, `${label}: scan runs`).toBeGreaterThanOrEqual(2);
      expect(
        runs.some((r) => Number(r.TargetsScanned) < Number(r.TargetsPlanned) || Number(r.AuthFailures) > 0),
        `${label}: one run is partial or has login failures`,
      ).toBe(true);

      const findings = rows(corpus, 'VulnFindings');
      const worklist = new Set(c.findings.map((f) => f.recordId));
      const background = findings.filter((r) => !worklist.has(String(r.RecordId)));
      const share = background.length / findings.length;
      expect(share, `${label}: background share ${background.length}/${findings.length}`).toBeGreaterThanOrEqual(0.6);
      expect(share, `${label}: background share ${background.length}/${findings.length}`).toBeLessThanOrEqual(0.8);
      const listed = new Set(rows(corpus, 'VulnIntel').filter((r) => r.KnownExploited === true).map((r) => String(r.VulnId)));
      for (const r of background) expect(listed.has(String(r.VulnId)), `${label}: background ${String(r.FindingId)} is not on Sim-KEV`).toBe(false);
      expect(background.some((r) => String(r.VulnId) === '' && String(r.Title) !== AUTH_FAILURE_TITLE), `${label}: some configuration-hygiene rows`).toBe(true);

      const changes = rows(corpus, 'Tickets').filter((r) => r.Type === 'Change');
      const title = (r: RowObject) => String(r.Title);
      const unrelated = changes.filter((r) => !title(r).startsWith(WINDOW_TITLE_PREFIX) && !title(r).startsWith(FREEZE_TITLE_PREFIX));
      expect(unrelated.length, `${label}: unrelated change tickets`).toBeGreaterThanOrEqual(3);
      expect(changes.filter((r) => title(r).startsWith(FREEZE_TITLE_PREFIX)).length, `${label}: freeze tickets`).toBe(1);
    }
  });
});

describe('twin pairs', () => {
  const pairs = TEMPLATES.filter((t) => t.twin && t.id < t.twin && TEMPLATES.some((x) => x.id === t.twin)).map((t) => [t, TEMPLATES.find((x) => x.id === t.twin)!] as const);

  it.each(pairs.map(([a, b]) => [a.id, b.id, a, b] as const))('%s / %s share title, headline vulnerability and score but differ in the answer', (_a, _b, a, b) => {
    expect(a.title).toBe(b.title);
    for (const run of RUNS) {
      const sa = build(a, run);
      const sb = build(b, run);
      const head = (s: ReturnType<typeof build>) => {
        const f = s.case.findings[0];
        const row = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === f.recordId)!;
        return { f, vulnId: String(row.VulnId), cvss: Number(row.CvssBase) };
      };
      const ha = head(sa);
      const hb = head(sb);
      expect(ha.vulnId, `${run.seed}: same headline vulnerability`).toBe(hb.vulnId);
      expect(ha.cvss, `${run.seed}: same headline CvssBase`).toBe(hb.cvss);
      const differs = ha.f.truth.decision !== hb.f.truth.decision || ha.f.truth.schedule !== hb.f.truth.schedule;
      expect(differs, `${run.seed}: the headline truth differs`).toBe(true);
    }
  });
});

// ---- DESIGN 5.6 on the built vm-kev-internal ------------------------------------

const KEV = TEMPLATES.find((t) => t.id === 'vm-kev-internal');

describe.skipIf(!KEV)('DESIGN 5.6 worked example on vm-kev-internal', () => {
  const part = (g: VulnGrade, id: string) => g.components.find((x) => x.id === id)!.earned;

  function answers(ids: string[], map: [decision: string, schedule: string | null][]) {
    return Object.fromEntries(ids.map((id, i) => [id, { decision: map[i][0], control: null, schedule: map[i][1], reasons: [] }])) as VulnSubmission['answers'];
  }

  it('perfect, sort-by-CVSS and dismiss-F1 analysts score as the design says, on every seed', () => {
    for (const run of RUNS) {
      const { corpus, case: c } = build(KEV!, run);
      const label = `${run.world}/${run.seed}`;
      const [f1, f2, f3, f4] = c.findings.map((f) => f.findingId);
      expect(c.findings.length, label).toBe(4);
      const cvss = (id: string) => Number(rows(corpus, 'VulnFindings').find((r) => r.FindingId === id)!.CvssBase);

      // Sorted by CVSS the order must come out F3, F1, F4, F2, strictly.
      const byScore = [f1, f2, f3, f4].sort((x, y) => cvss(y) - cvss(x));
      expect(byScore, `${label}: CVSS order`).toEqual([f3, f1, f4, f2]);
      expect(new Set([f1, f2, f3, f4].map(cvss)).size, `${label}: scores are all different`).toBe(4);
      expect(cvss(f1), `${label}: headline score`).toBe(7.5);

      const pin = c.findings[3].evidence[0].recordIds[0];
      const sort: VulnSubmission = {
        answers: answers([f1, f2, f3, f4], [['patch', 'next-window'], ['patch', 'standard-cycle'], ['patch', 'next-window'], ['patch', 'next-window']]),
        order: byScore,
        pins: [pin],
        notes: '',
        hintsUsed: 0,
      };
      const g = gradeVulnCase(c, sort);
      expect(Math.abs(g.score - 57.3), `${label}: sort-by-CVSS ${g.score}`).toBeLessThanOrEqual(0.5);
      expect(part(g, 'decisions'), label).toBe(33.3);
      expect(part(g, 'ordering'), label).toBe(14);
      expect(part(g, 'schedule'), label).toBe(5);
      expect(part(g, 'justification'), label).toBe(0);
      expect(part(g, 'evidence'), label).toBe(5);

      const dismiss: VulnSubmission = {
        answers: answers([f1, f2, f3, f4], [['false-positive', null], ['patch', 'standard-cycle'], ['false-positive', 'none'], ['patch', 'next-window']]),
        order: [f4, f2],
        pins: [],
        notes: '',
        hintsUsed: 0,
      };
      const d = gradeVulnCase(c, dismiss);
      expect(part(d, 'decisions'), `${label}: dismiss-F1 decisions`).toBe(15);
      expect(d.mustNotMiss.orderingPenalty, `${label}: must-not-miss ordering penalty`).toBe(4);
      expect(d.mustNotMiss.dismissed, label).toEqual([f1]);
    }
  });
});

