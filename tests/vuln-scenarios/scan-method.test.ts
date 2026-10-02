// T7 twins (vm-noncred-low / vm-cred-high): what the data and the grader do with the scan-method lesson on every seed. The generic
// twin checks and the coverage clue (which host the credentialed run reached, which one failed to log in, the inventory against the
// fix) are the T7 row of batch-b.test.ts.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { credHigh, noncredLow } from '../../src/core/vuln/templates/scan-method.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const ms = (v: unknown): number => Date.parse(String(v));
const RUNS = vulnRuns(20, 20);

describe.each([noncredLow, credHigh].map((t) => [t.id, t] as const))('%s', (_id, t) => {
  it('dates the story so the scan store stays consistent: the credentialed run is older than the sweep, installs predate what they explain, no row is closed', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const label = `${t.id} ${run.world}/${run.seed}`;
      const runs = rows(s.corpus, 'ScanRuns');
      const sweep = runs.find((r) => r.Method === 'Unauthenticated')!;
      const cred = runs.find((r) => r.Method === 'Credentialed')!;
      expect(sweep.Vantage, `${label}: an internal sweep (an external one cannot be shown reaching a host with configuration rows)`).toBe('Internal');
      expect(ms(cred.Finished), `${label}: the credentialed run finished before the sweep started`).toBeLessThan(ms(sweep.Started));
      const [h1, h2] = [0, 1].map((i) => rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[i].recordId)!);
      for (const h of [h1, h2]) {
        expect(h.Status, `${label}: the sweep row is open (the credentialed run came first, it could not close it)`).toBe('Open');
        expect(ms(h.FirstSeen), `${label}: first detected by the sweep`).toBe(ms(sweep.Started));
      }
      const fpTruth = s.case.findings.find((f) => f.truth.decision === 'false-positive')!;
      const fpRow = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === fpTruth.recordId)!;
      const realRow = [h1, h2].find((h) => h !== fpRow)!;
      const inv = (h: Row) => rows(s.corpus, 'SoftwareInventory').find((x) => x.DeviceName === h.DeviceName && String(h.Title).includes(` in ${String(x.Product)} `))!;
      expect(ms(inv(fpRow).InstalledOn), `${label}: the false positive's release was installed before the credentialed run`).toBeLessThan(ms(cred.Started));
      expect(ms(inv(realRow).InstalledOn), `${label}: the real one was installed before first detection`).toBeLessThanOrEqual(ms(realRow.FirstSeen));
      // The credentialed run's rows on the reached host are not "Authentication failure", and carry the words that tell the login worked.
      const reached = rows(s.corpus, 'VulnFindings').filter((r) => r.ScanRunId === cred.ScanRunId && r.DeviceName === fpRow.DeviceName);
      expect(reached.length, `${label}: one row from the credentialed run on the host it reached`).toBe(1);
      expect(String(reached[0].Evidence), `${label}: the row says the login succeeded`).toContain('login');
      expect(String(reached[0].Evidence), `${label}: the row says the login succeeded`).toContain('succeeded');
    }
  });

  it('is not the backport lesson: no update record, no advisory text, no PackageSource other than vendor on the two servers', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const label = `${t.id} ${run.world}/${run.seed}`;
      const hosts = [0, 1].map((i) => String(rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[i].recordId)!.DeviceName));
      expect(rows(s.corpus, 'PatchHistory').filter((p) => hosts.includes(String(p.DeviceName))), `${label}: no update history on the two servers`).toEqual([]);
      for (const x of rows(s.corpus, 'SoftwareInventory').filter((r) => hosts.includes(String(r.DeviceName)))) expect(x.PackageSource, `${label}: ${String(x.DeviceName)}`).toBe('vendor');
      const text = [t.lesson, ...s.case.hints, ...s.case.explanation].join(' ').toLowerCase();
      expect(text, `${label}: the lesson is not named a backport`).not.toMatch(/backported fix|distro package|advisory lists/);
    }
  });
});

// The grader on the built twins: answering the headline like the other twin fails the lesson gate whatever else is right.
describe('answering a twin with the other twin\'s headline answer fails the case', () => {
  it.each([
    ['vm-noncred-low', noncredLow, 'patch', 'emergency', ['sla-deadline']],
    ['vm-cred-high', credHigh, 'false-positive', 'none', ['banner-only']],
  ] as const)('%s', (_id, t, decision, schedule, reasons) => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const c = s.case;
      const perfect = perfectVulnSubmission(c);
      expect(gradeVulnCase(c, perfect).score, `${run.seed}: perfect`).toBe(100);
      const head = c.findings[0].findingId;
      const wrong: VulnSubmission = { ...perfect, answers: { ...perfect.answers, [head]: { decision, control: null, schedule, reasons: [...reasons] } } };
      const g = gradeVulnCase(c, wrong);
      expect(g.gate.missed.map((m) => m.findingId), `${run.seed}: the headline is a missed key finding`).toContain(head);
      expect(g.score, `${run.seed}: capped`).toBeLessThanOrEqual(60);
    }
  }, 120_000);

  it('the real Critical cannot be dismissed, and the false positive cannot be patched, in either twin', () => {
    for (const t of [noncredLow, credHigh]) {
      for (const run of RUNS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        const real = c.findings.find((f) => f.lesson && f.truth.decision === 'patch')!;
        const fp = c.findings.find((f) => f.lesson && f.truth.decision === 'false-positive')!;
        const dismissReal = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [real.findingId]: { decision: 'false-positive', control: null, schedule: 'none', reasons: [] } } });
        expect(dismissReal.gate.missed.map((m) => m.findingId), `${t.id} ${run.seed}: dismissing the real one`).toContain(real.findingId);
        const patchFp = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [fp.findingId]: { decision: 'patch', control: null, schedule: 'emergency', reasons: ['sla-deadline'] } } });
        expect(patchFp.gate.missed.map((m) => m.findingId), `${t.id} ${run.seed}: patching the false positive`).toContain(fp.findingId);
      }
    }
  }, 120_000);
});
