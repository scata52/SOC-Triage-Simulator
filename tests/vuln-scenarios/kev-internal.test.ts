// T3 twins (vm-kev-internal / vm-nokev-internal): the story the data has to tell
// on every seed: why the complete old run missed the headline, why the file
// server was not re-tested, and what F2 and F3 look like.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { DAY } from '../../src/core/logs/time.ts';
import { kevInternal, noKevInternal } from '../../src/core/vuln/templates/kev-internal.ts';
import { AUTH_FAILURE_TITLE, dayStart } from '../../src/core/vuln/templates/common.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const ms = (v: unknown): number => Date.parse(String(v));
const RUNS = vulnRuns(20, 20);

const norm = (c: Corpus, t: keyof Corpus['tables']): string[] => rows(c, t).map(({ RecordId: _r, ...rest }) => JSON.stringify(rest)).sort();

describe.each([kevInternal, noKevInternal].map((t) => [t.id, t] as const))('%s', (_id, t) => {
  it('tells the story of the old run, the login failure and the deciders on every seed', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const corpus = s.corpus as Corpus;
      const label = `${t.id} ${run.world}/${run.seed}`;
      const now = ms(s.now);
      const findings = rows(corpus, 'VulnFindings');
      const byFinding = (id: string) => findings.find((r) => r.FindingId === id)!;
      const [f1, f2, f3, f4] = s.case.findings.map((f) => byFinding(f.findingId));
      const runs = rows(corpus, 'ScanRuns').sort((a, b) => ms(a.Started) - ms(b.Started));
      const [oldRun, newRun] = runs;
      const intel = (row: Row) => rows(corpus, 'VulnIntel').find((r) => r.VulnId === row.VulnId)!;

      // K1: first detection is the newer run; the complete old run reached the host but the vulnerable version came later.
      expect(ms(f1.FirstSeen), `${label}: F1 first seen`).toBe(ms(newRun.Started));
      expect(f1.ScanRunId, `${label}: F1 is from the newer run`).toBe(newRun.ScanRunId);
      expect(oldRun.TargetsScanned, `${label}: the old run is complete`).toBe(oldRun.TargetsPlanned);
      expect(findings.some((r) => r.DeviceName === f1.DeviceName && ms(r.FirstSeen) >= ms(oldRun.Started) && ms(r.FirstSeen) <= ms(oldRun.Finished)), `${label}: a row first seen during the old run shows it reached the application server`).toBe(true);
      const product = rows(corpus, 'SoftwareInventory').find((r) => r.DeviceName === f1.DeviceName && r.Version === f1.DetectedVersion)!;
      expect(product, `${label}: the installed vulnerable version is in the inventory`).toBeDefined();
      expect(ms(product.InstalledOn), `${label}: installed after the old run started`).toBeGreaterThan(ms(oldRun.Started));
      expect(ms(product.InstalledOn), `${label}: installed before it was found`).toBeLessThan(ms(f1.FirstSeen));
      if (t.id === 'vm-kev-internal') {
        const added = ms(intel(f1).KnownExploitedAdded);
        expect([1, 2].map((d) => dayStart(now) - d * DAY), `${label}: listed 1 or 2 days before the case day`).toContain(added);
      }

      // K2: F2 is a Medium network TLS finding, below F4, with a Sim-EPSS in the lower half.
      expect(String(intel(f2).CvssVector), `${label}: F2 vector`).toMatch(/AV:N/);
      expect(f2.Severity, `${label}: F2 severity`).toBe('Medium');
      expect(Number(f2.CvssBase), `${label}: F2 below F4`).toBeLessThan(Number(f4.CvssBase));
      expect(Number(intel(f2).ExploitProbability), `${label}: F2 Sim-EPSS`).toBeLessThanOrEqual(0.004);
      expect(String(f2.Title), `${label}: F2 title`).toMatch(/TLS/);

      // K3: F3 was first detected about 35 days before the case date and the old run still reported it.
      const age = (now - ms(f3.FirstSeen)) / DAY;
      expect(age, `${label}: F3 age ${age}`).toBeGreaterThan(34);
      expect(age, `${label}: F3 age ${age}`).toBeLessThan(36.5);
      expect(f3.ScanRunId, `${label}: F3 is from the old run`).toBe(oldRun.ScanRunId);
      expect(f3.Port, `${label}: F3 is a package-level finding`).toBeNull();

      // C13: the newer run's only row for the file server is the explicit login failure.
      const onFileServer = findings.filter((r) => r.DeviceName === f3.DeviceName && r.ScanRunId === newRun.ScanRunId);
      expect(onFileServer.map((r) => r.Title), `${label}: newer-run rows for the file server`).toEqual([AUTH_FAILURE_TITLE]);
      expect(newRun.AuthFailures, `${label}: AuthFailures`).toBe(1);
      expect(Number(newRun.TargetsScanned), `${label}: partial run`).toBeLessThan(Number(newRun.TargetsPlanned));
    }
  });
});

describe('T3 twins share their unrelated inputs', () => {
  it('PatchHistory holds unrelated rows on background hosts, identical in both twins; DEVBOX01 is one device in both', () => {
    for (const run of RUNS) {
      const a = buildFor(kevInternal, world(run.world), run.seed).corpus as Corpus;
      const b = buildFor(noKevInternal, world(run.world), run.seed).corpus as Corpus;
      const label = `${run.world}/${run.seed}`;
      const patches = rows(a, 'PatchHistory');
      expect(new Set(patches.map((p) => p.DeviceName)).size, `${label}: patch history spans several hosts`).toBeGreaterThanOrEqual(4);
      expect(norm(a, 'PatchHistory'), `${label}: same PatchHistory`).toEqual(norm(b, 'PatchHistory'));
      const dev = (c: Corpus) => rows(c, 'DeviceInfo').filter((d) => d.DeviceName === 'DEVBOX01').map(({ RecordId: _r, ...rest }) => rest);
      expect(dev(a), `${label}: DEVBOX01 DeviceInfo`).toEqual(dev(b));
      expect(dev(a).length, label).toBe(1);
    }
  });
});
