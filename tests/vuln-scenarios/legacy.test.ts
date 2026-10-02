// T6 (vm-legacy-accept / vm-legacy-isolate): the scanner session and the headline's LastSeen agree on every seed (the generic T6 row of
// batch-b.test.ts checks that the one SCAN01 session lies inside the newer sweep; this checks that it is consistent with the finding it
// produced), the objectives and the scoped pitfall.
import { describe, expect, it } from 'vitest';
import { build, byId, headRow, rows, SEEDS } from './pair-helpers.ts';

const TWINS = ['vm-legacy-accept', 'vm-legacy-isolate'] as const;

describe('T6 scanner session', () => {
  it('lies in the newer sweep and is not after the headline LastSeen: the finding is observed during or after that session, on every seed', () => {
    for (const id of TWINS) {
      for (const run of SEEDS) {
        const s = build(byId(id), run);
        const label = `${id} ${run.world}/${run.seed}`;
        const head = headRow(s);
        const scanner = String(rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'SCAN01')!.IPAddress);
        const controller = String(rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === head.DeviceName)!.IPAddress);
        const sessions = rows(s.corpus, 'FirewallLogs').filter((f) => f.SourceIP === scanner && f.DestinationIP === controller && Number(f.DestinationPort) === Number(head.Port));
        expect(sessions.length, `${label}: one scanner session to the controller port`).toBe(1);
        const t = Date.parse(String(sessions[0].TimeGenerated));
        const sweep = rows(s.corpus, 'ScanRuns').find((r) => r.ScanRunId === head.ScanRunId)!;
        expect(t, `${label}: not before the sweep started`).toBeGreaterThanOrEqual(Date.parse(String(sweep.Started)));
        expect(t, `${label}: not after the sweep finished`).toBeLessThanOrEqual(Date.parse(String(sweep.Finished)));
        expect(t, `${label}: the headline's LastSeen is not before the only session to its port`).toBeLessThanOrEqual(Date.parse(String(head.LastSeen)));
        expect(Date.parse(String(head.LastSeen)) - t, `${label}: the session is at the observation (within a few minutes)`).toBeLessThanOrEqual(2 * 60_000);
      }
    }
  }, 120_000);
});

describe('T6 text and tags', () => {
  it('tags 2.1 (OT scanning considerations) with 2.4, 2.5 and 4.1 in both twins', () => {
    for (const id of TWINS) expect(byId(id).objectives, id).toEqual(['2.1', '2.4', '2.5', '4.1']);
  });

  it('scopes the "ticket alone" pitfall to this exception, which names the isolation it relies on', () => {
    for (const run of SEEDS.slice(0, 6)) {
      const s = build(byId('vm-legacy-accept'), run);
      const p = s.case.pitfalls.find((x) => x.startsWith('Accepting on the ticket alone'))!;
      expect(p, `${run.seed}: the pitfall`).toContain("this exception's approval names the isolation it relies on");
      expect(p, `${run.seed}: the pitfall is not a general rule`).not.toMatch(/^Accepting on the ticket alone: the exception counts/);
      const ticket = rows(s.corpus, 'Tickets').find((t) => String(t.Title).startsWith('Risk exception') && String(t.Scope) === String(headRow(s).DeviceName))!;
      expect(String(ticket.Details), `${run.seed}: the exception names the isolation`).toMatch(/OT management hosts/);
    }
  });
});
