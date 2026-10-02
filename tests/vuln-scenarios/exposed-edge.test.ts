// T4 twins (vm-exposed-edge / vm-segmented): the story the data has to tell on every seed. The generic twin checks
// (same surface, the clue in the data, the lesson text) are in batch-a.test.ts.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { DAY } from '../../src/core/logs/time.ts';
import { endOfDay, ymd } from '../../src/core/vuln/templates/common.ts';
import { exposedEdge, segmented } from '../../src/core/vuln/templates/exposed-edge.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const ms = (v: unknown): number => Date.parse(String(v));
const RUNS = vulnRuns(20, 20);

describe.each([exposedEdge, segmented].map((t) => [t.id, t] as const))('%s', (_id, t) => {
  it('has the Critical deadline before the next window, a day clear of it, and the permanent fix in the next window', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const label = `${t.id} ${run.world}/${run.seed}`;
      const head = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[0].recordId)!;
      expect(Number(head.CvssBase), `${label}: 9.8`).toBe(9.8);
      expect(head.Severity, `${label}: scanner severity`).toBe('Critical');
      const next = [...s.case.constraints.windows].sort((a, b) => ms(a.start) - ms(b.start))[0];
      const deadline = endOfDay(ms(head.FirstSeen) + s.case.constraints.slaDays.critical * DAY);
      expect(deadline, `${label}: deadline ${ymd(deadline)} is a day before the next window ends`).toBeLessThanOrEqual(next.end - DAY);
      const truth = s.case.findings[0].truth;
      if (t.id === 'vm-exposed-edge') {
        expect([truth.decision, truth.schedule, truth.slaLatest], label).toEqual(['patch', 'emergency', 'emergency']);
        expect(truth.mitigation, `${label}: no control covers the path`).toBeUndefined();
        expect(truth.reasons, label).toContain('internet-exposed');
        expect(truth.contradicting, `${label}: compensating-control-verified contradicts`).toContain('compensating-control-verified');
      } else {
        expect([truth.decision, truth.schedule, truth.slaLatest], label).toEqual(['mitigate', 'next-window', 'next-window']);
        expect(truth.alsoAccept ?? [], `${label}: patch is not accepted (it would be a one-step slip)`).not.toContain('patch');
        expect(truth.reasons, label).toContain('compensating-control-verified');
        expect(truth.contradicting, `${label}: internet-exposed contradicts`).toContain('internet-exposed');
      }
      // The headline's vulnerable version was installed after the older run started and before the newer run found it.
      const runs = rows(s.corpus, 'ScanRuns').sort((a, b) => ms(a.Started) - ms(b.Started));
      const software = rows(s.corpus, 'SoftwareInventory').find((r) => r.DeviceName === head.DeviceName && r.Version === head.DetectedVersion)!;
      expect(software, `${label}: inventory row`).toBeDefined();
      expect(ms(software.InstalledOn), `${label}: installed after the old run started`).toBeGreaterThan(ms(runs[0].Started));
      expect(ms(software.InstalledOn), `${label}: installed before it was found`).toBeLessThan(ms(head.FirstSeen));
    }
  });

  it('shows the written compensating-control and severity-class rules in the policy', () => {
    const s = buildFor(t, world(RUNS[0].world), RUNS[0].seed);
    const policy = JSON.stringify(s.case.attachments.find((a) => a.title.includes('remediation standard'))!.body);
    expect(policy).toContain('Compensating control');
    expect(policy).toContain('ControlInventory shows it in block mode covering this vulnerability on this host');
    expect(policy).toContain('Severity class');
    expect(policy).toContain('CvssBase');
  });
});

describe('T4 twins write the same sessions and controls apart from the clue', () => {
  it('the same sources, times and ports in FirewallLogs, and the same ControlId and Target in ControlInventory', () => {
    for (const run of RUNS) {
      const a = buildFor(exposedEdge, world(run.world), run.seed).corpus as Corpus;
      const b = buildFor(segmented, world(run.world), run.seed).corpus as Corpus;
      const label = `${run.world}/${run.seed}`;
      const sessions = (c: Corpus) => rows(c, 'FirewallLogs').filter((f) => f.DestinationPort === 8443 && String(f.RuleName).includes('edge-mgmt')).map((f) => [f.TimeGenerated, f.Direction, f.SourceIP, f.SourcePort, f.DestinationIP].join('|')).sort();
      expect(sessions(a).length, `${label}: management sessions`).toBe(6);
      expect(sessions(a), `${label}: same sessions`).toEqual(sessions(b));
      const controls = (c: Corpus) => rows(c, 'ControlInventory').map((r) => `${String(r.ControlId)}|${String(r.Kind)}|${String(r.Target)}`).sort();
      expect(controls(a), `${label}: same controls`).toEqual(controls(b));
    }
  });
});

describe('T4 data realism (review round 1)', () => {
  it('the edge gateway has the same address in the management range in both twins, and the internet sessions are short probes', () => {
    for (const run of RUNS) {
      const a = buildFor(exposedEdge, world(run.world), run.seed);
      const b = buildFor(segmented, world(run.world), run.seed);
      const label = `${run.world}/${run.seed}`;
      const ip = (s: typeof a) => String(rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'EDGE01')!.IPAddress);
      expect(ip(a), `${label}: same address`).toBe(ip(b));
      expect(ip(a).split('.')[2], `${label}: management range`).toBe('250');
      for (const f of rows(a.corpus, 'FirewallLogs').filter((x) => x.Direction === 'Inbound' && x.DestinationPort === 8443)) {
        expect(Number(f.BytesReceived), `${label}: a short reply`).toBeLessThan(2000);
        expect(Number(f.SessionDurationSec), `${label}: a short session`).toBeLessThanOrEqual(4);
      }
      const ta = a.case.findings[0].truth;
      expect(ta.reasons, label).toEqual(expect.arrayContaining(['internet-exposed', 'control-not-covering', 'sla-deadline']));
      expect(a.case.explanation.join(' '), `${label}: compromise check`).toContain('compromise check');
      expect(a.case.explanation.join(' '), `${label}: no "no exploitation signal"`).not.toContain('no exploitation signal');
      expect(b.case.findings[0].truth.contradicting, `${label}: a verified block ACL proves control-not-covering false`).toContain('control-not-covering');
      expect(a.case.findings[1].truth.contradicting, `${label}: the detect-mode decoy`).toContain('compensating-control-verified');
    }
  });
});
