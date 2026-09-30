// Rare-seed regressions (WP1d) and the wide crash sweep. The named seeds once failed: the Sim-KEV twins
// found no coherent Sim-KEV entry old enough, and the web-server case fell out of the DESIGN 6.3 noise
// budget. VULN_SWEEP=2000 builds that many seeds of every template (slow, off by default).
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import type { VulnTemplate } from '../../src/core/vuln/model.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import { backportFp } from '../../src/core/vuln/templates/backport-fp.ts';
import { kevInternal, noKevInternal } from '../../src/core/vuln/templates/kev-internal.ts';
import { AUTH_FAILURE_TITLE, classOfTitle, vectorProblem } from '../../src/core/vuln/templates/common.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));

// The DESIGN 6.3 budget as it is measured on the rows actually written, plus the worklist descriptions.
function checkBuilt(t: VulnTemplate, worldName: string, seed: string): void {
  const { corpus, case: c } = buildFor(t, world(worldName), seed);
  const label = `${t.id} ${worldName}/${seed}`;
  const findings = rows(corpus, 'VulnFindings');
  const work = new Set(c.findings.map((f) => f.recordId));
  const background = findings.filter((r) => !work.has(String(r.RecordId)));
  const share = background.length / findings.length;
  expect(share, `${label}: background share ${background.length}/${findings.length}`).toBeGreaterThanOrEqual(0.6);
  expect(share, `${label}: background share ${background.length}/${findings.length}`).toBeLessThanOrEqual(0.8);
  const quiet = background.filter((r) => String(r.Title) !== AUTH_FAILURE_TITLE);
  const hygiene = quiet.filter((r) => String(r.VulnId) === '').length;
  expect(hygiene / quiet.length, `${label}: hygiene ${hygiene}/${quiet.length}`).toBeLessThanOrEqual(0.5);
  const intel = new Map(rows(corpus, 'VulnIntel').map((r) => [String(r.VulnId), r]));
  for (const r of findings.filter((x) => work.has(String(x.RecordId)))) {
    const title = String(r.Title);
    const cls = classOfTitle(title);
    expect(cls, `${label}: "${title}" is not a configuration weakness`).not.toBe('misconfig');
    expect(vectorProblem(String(intel.get(String(r.VulnId))!.CvssVector), cls!, title), `${label}: "${title}"`).toBeNull();
  }
}

describe('rare seeds that once failed', () => {
  it.each([
    ['c9-world-0', 'c9s14038'],
    ['c9-world-0', 'c9s15082'],
  ])('the Sim-KEV twins build on %s/%s', (w, seed) => {
    for (const t of [kevInternal, noKevInternal]) checkBuilt(t, w, seed);
  }, 120_000);

  it.each([
    ['r2-world-26', 'r2s586'],
    ['r2-world-17', 'r2s257'],
    ['r2-world-2', 'r2s14'],
    ['r2-world-8', 'r2s8'],
    ['r2-world-0', 'r2s0'],
  ])('the web-server case keeps its noise budget and its descriptions on %s/%s', (w, seed) => {
    checkBuilt(backportFp, w, seed);
  }, 120_000);
});

const SWEEP = Number(process.env.VULN_SWEEP ?? 0);
describe.skipIf(SWEEP === 0)('wide crash sweep', () => {
  it.each(VULN_CASE_TEMPLATES.map((t) => [t.id, t] as const))('%s builds on %i seeds within the budget', (_id, t) => {
    for (let i = 0; i < SWEEP; i++) checkBuilt(t, `sweep-world-${i % 30}`, `sw${i}`);
  }, 3_600_000);
});
