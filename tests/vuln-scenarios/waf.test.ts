// T5 twins (vm-waf-covers / vm-waf-bypass): the story the data has to tell on every seed. The generic twin checks (same
// surface, the clue in the data, the lesson text) are in batch-a.test.ts.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { DAY, utcDayStart } from '../../src/core/logs/time.ts';
import { buildCalendar, endOfDay, FREEZE_TITLE_PREFIX, ymd } from '../../src/core/vuln/templates/common.ts';
import { exposedEdge } from '../../src/core/vuln/templates/exposed-edge.ts';
import { wafBypass, wafCovers } from '../../src/core/vuln/templates/waf.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type Row = Record<string, unknown>;
const rows = (c: Corpus, t: keyof Corpus['tables']): Row[] => c.tables[t].rows.map((r) => Object.fromEntries(c.tables[t].columns.map((k, i) => [k, r[i]])));
const ms = (v: unknown): number => Date.parse(String(v));
const RUNS = vulnRuns(20, 20);

describe.each([wafCovers, wafBypass].map((t) => [t.id, t] as const))('%s', (_id, t) => {
  it('has a freeze from the case date, the next window the first after it, and the Critical deadline a day clear of that window', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const label = `${t.id} ${run.world}/${run.seed}`;
      const head = rows(s.corpus, 'VulnFindings').find((r) => r.RecordId === s.case.findings[0].recordId)!;
      expect(Number(head.CvssBase), `${label}: Critical`).toBeGreaterThanOrEqual(9);
      expect(String(head.Title), `${label}: SQL injection`).toMatch(/^SQL injection/);
      const k = s.case.constraints;
      const [next, cycle] = [...k.windows].sort((a, b) => a.start - b.start);
      const freeze = k.freezes![0];
      const today = utcDayStart(ms(s.now));
      expect(freeze.start, `${label}: freeze starts on the case date`).toBe(today);
      expect(freeze.end, `${label}: the freeze ends on the day of the next window`).toBe(utcDayStart(next.start));
      expect(next.start, `${label}: next window is the first after the freeze`).toBeGreaterThan(freeze.end);
      expect(cycle.start, `${label}: the standard cycle follows`).toBeGreaterThan(next.end);
      const deadline = endOfDay(ms(head.FirstSeen) + k.slaDays.critical * DAY);
      expect(deadline, `${label}: the deadline ${ymd(deadline)} is a day before the next window ends`).toBeLessThanOrEqual(next.end - DAY);
      expect(deadline, `${label}: the deadline is still ahead`).toBeGreaterThan(ms(s.now));
      // The calendar attachment and the tickets agree: the freeze ticket carries the same dates, no other change falls inside it.
      const tickets = rows(s.corpus, 'Tickets').filter((r) => r.Type === 'Change');
      const freezeTicket = tickets.find((r) => String(r.Title).startsWith(FREEZE_TITLE_PREFIX))!;
      expect([ms(freezeTicket.WindowStart), ms(freezeTicket.WindowEnd)], `${label}: freeze ticket`).toEqual([freeze.start, freeze.end]);
      for (const r of tickets.filter((x) => x !== freezeTicket && !String(x.Title).startsWith('Application release'))) {
        const [a, b] = [ms(r.WindowStart), ms(r.WindowEnd)];
        expect(b <= freeze.start || a >= freeze.end, `${label}: "${String(r.Title)}" is planned inside the freeze`).toBe(true);
      }
      // The fix is an application release requested for the first window after the freeze, in both twins.
      const release = tickets.filter((r) => String(r.Title).startsWith('Application release'));
      expect(release.length, `${label}: one release ticket`).toBe(1);
      expect(ms(release[0].WindowStart), `${label}: the release is requested for the next window`).toBe(next.start);
      expect(String(release[0].Details), `${label}: the release names the vulnerability`).toContain(String(head.VulnId));
    }
  });

  it('keeps the case within the capacity of a window and its sizes within tier 2', () => {
    for (const run of RUNS) {
      const s = buildFor(t, world(run.world), run.seed);
      const label = `${t.id} ${run.world}/${run.seed}`;
      expect(s.case.findings.length, `${label}: findings`).toBeGreaterThanOrEqual(8);
      expect(s.case.findings.length, `${label}: findings`).toBeLessThanOrEqual(12);
      const changes = s.case.findings.filter((f) => f.truth.schedule === 'emergency' || f.truth.schedule === 'next-window').length;
      expect(changes, `${label}: emergency and next-window changes fit one window`).toBeLessThanOrEqual(s.case.constraints.capacityPerWindow);
    }
  });

  it('shows the written compensating-control rule, which names the WAF records, in the policy', () => {
    const s = buildFor(t, world(RUNS[0].world), RUNS[0].seed);
    const policy = JSON.stringify(s.case.attachments.find((a) => a.title.includes('remediation standard'))!.body);
    expect(policy).toContain('Compensating control');
    expect(policy).toContain("the WAF's own records confirm it");
  });
});

describe('T5 truths', () => {
  it('A is mitigate with the WAF rule in the next window, B is an emergency patch with no control, and the explanations say why', () => {
    for (const run of RUNS) {
      const a = buildFor(wafCovers, world(run.world), run.seed);
      const b = buildFor(wafBypass, world(run.world), run.seed);
      const label = `${run.world}/${run.seed}`;
      const [ta, tb] = [a.case.findings[0].truth, b.case.findings[0].truth];
      expect([ta.decision, ta.schedule, ta.slaLatest], `${label}: A`).toEqual(['mitigate', 'next-window', 'next-window']);
      expect(ta.alsoAccept ?? [], `${label}: patch is not accepted on A (an emergency patch would be a one-step slip)`).not.toContain('patch');
      expect(ta.reasons, label).toContain('compensating-control-verified');
      expect(ta.contradicting, `${label}: control-not-covering contradicts A`).toContain('control-not-covering');
      expect([tb.decision, tb.schedule, tb.slaLatest], `${label}: B`).toEqual(['patch', 'emergency', 'emergency']);
      expect(tb.reasons, label).toEqual(expect.arrayContaining(['control-not-covering', 'internet-exposed']));
      expect(tb.reasons.length, `${label}: the worklist allows 3 codes per finding, so more than 3 required could never all be matched`).toBeLessThanOrEqual(3);
      expect(a.case.findings[0].evidence.concat(b.case.findings[0].evidence).map((e) => e.label).join(' '), label).not.toContain('cannot go in before');
      expect(a.case.explanation.join(' '), `${label}: A says the virtual patch does not replace the code fix`).toContain('does not replace the code fix');
      expect(b.case.explanation.join(' '), `${label}: B says why avoid is not accepted`).toContain('Avoid (switching the feature off) is not accepted');
    }
  });

  it('writes the same nine WAF sessions in both twins; only the attack requests differ (action and rule)', () => {
    for (const run of RUNS) {
      const a = buildFor(wafCovers, world(run.world), run.seed).corpus as Corpus;
      const b = buildFor(wafBypass, world(run.world), run.seed).corpus as Corpus;
      const label = `${run.world}/${run.seed}`;
      const sessions = (c: Corpus) => rows(c, 'FirewallLogs').filter((f) => f.DeviceName === 'WAF01').map((f) => [f.TimeGenerated, f.Direction, f.SourceIP, f.SourcePort, f.DestinationIP, f.DestinationPort].join('|')).sort();
      expect(sessions(a).length, `${label}: WAF sessions`).toBe(9);
      expect(sessions(a), `${label}: same sessions`).toEqual(sessions(b));
      const controls = (c: Corpus) => rows(c, 'ControlInventory').map((r) => `${String(r.ControlId)}|${String(r.Kind)}|${String(r.Target)}|${String(r.CoversVulnId)}`).sort();
      expect(controls(a), `${label}: same controls (id, kind, target, vulnerability)`).toEqual(controls(b));
      expect(controls(a).length, `${label}: three controls`).toBe(3);
    }
  });
});

describe('the standard calendar is unchanged', () => {
  it('buildCalendar without the variant keeps the freeze between the next window and the cycle; the T4 twins still use it', () => {
    const now = Date.UTC(2026, 9, 2, 10, 0, 0);
    const standard = buildCalendar(now);
    expect(standard.freeze.start - standard.today, 'freeze starts on day 8').toBe(8 * DAY);
    expect(standard.freeze.end - standard.today, 'and lasts 3 days').toBe(11 * DAY);
    expect(standard.next.start).toBeLessThan(standard.freeze.start);
    const variant = buildCalendar(now, { freezeFirst: true });
    expect(variant.next, 'the windows do not move').toEqual(standard.next);
    expect(variant.cycle).toEqual(standard.cycle);
    const run = RUNS[0];
    const s = buildFor(exposedEdge, world(run.world), run.seed);
    const freeze = s.case.constraints.freezes![0];
    const next = [...s.case.constraints.windows].sort((a, b) => a.start - b.start)[0];
    expect(freeze.start, 'T4 keeps the standard calendar: its freeze comes after the next window').toBeGreaterThan(next.end);
  });
});

describe('T5 data realism (review round 1)', () => {
  it('the requests that match the rule are short probes from internet scanners, the portal role names a real use of the component, and no text calls them attacks', () => {
    for (const run of RUNS) {
      for (const t of [wafCovers, wafBypass]) {
        const s = buildFor(t, world(run.world), run.seed);
        const label = `${t.id} ${run.world}/${run.seed}`;
        const wafRows = rows(s.corpus, 'FirewallLogs').filter((f) => f.DeviceName === 'WAF01' && String(f.RuleName).startsWith('CTL-WAF'));
        expect(wafRows.length, `${label}: rows matched by a rule`).toBe(6);
        for (const f of wafRows) {
          expect(Number(f.BytesReceived), `${label}: a short reply`).toBeLessThan(2000);
          expect(Number(f.SessionDurationSec), `${label}: a short session`).toBeLessThanOrEqual(4);
        }
        const portal = rows(s.corpus, 'DeviceInfo').find((d) => d.DeviceName === 'PORTAL01')!;
        expect(String(portal.Role), `${label}: role`).toMatch(/: (customers search their orders here|customers sign in here to track their orders|the order-status page calls it)\)$/);
        const text = [...s.case.explanation, ...s.case.hints, ...s.case.pitfalls, s.case.lesson].join(' ');
        expect(text, `${label}: no "attack requests"`).not.toMatch(/attack requests/);
      }
    }
  });

  it('B hands matched traffic to the SOC for a compromise check, rejects the block-mode switch with a data reason, and A ties the pair at next-window', () => {
    for (const run of RUNS) {
      const a = buildFor(wafCovers, world(run.world), run.seed);
      const b = buildFor(wafBypass, world(run.world), run.seed);
      const label = `${run.world}/${run.seed}`;
      expect(b.case.explanation.join(' '), `${label}: compromise check`).toContain('compromise check');
      const headId = String(rows(b.corpus, 'VulnFindings').find((r) => r.RecordId === b.case.findings[0].recordId)!.VulnId);
      const rule = rows(b.corpus, 'ControlInventory').find((c) => c.Kind === 'WAF' && c.Mode === 'detect' && String(c.CoversVulnId) === headId)!;
      expect(String(rule.Evidence), `${label}: the data gives a reason against block mode`).toContain('rolled back');
      expect(b.case.explanation.join(' '), `${label}: B cites it`).toContain('rolled back');
      expect(b.case.explanation.join(' '), `${label}: no unapproved-change claim`).not.toContain('unapproved');
      // A block-mode control proves 'control-not-covering' false, a detect-mode rule proves 'compensating-control-verified' false.
      expect(a.case.findings[0].truth.contradicting, label).toContain('control-not-covering');
      expect(b.case.findings[0].truth.contradicting, label).toContain('compensating-control-verified');
      expect(b.case.findings[1].truth.contradicting, `${label}: the detect-mode decoy`).toContain('compensating-control-verified');
      expect(a.case.tiers, `${label}: A ties the two next-window findings`).toEqual([[a.case.findings[0].findingId, a.case.findings[1].findingId]]);
      for (const s of [a, b]) {
        const standard = s.case.findings.filter((f) => f.truth.decision === 'patch' && f.truth.schedule === 'standard-cycle').length;
        expect(standard, `${label}: four standard-cycle patches`).toBe(4);
        expect(s.case.explanation.join(' '), `${label}: the count in the text`).not.toContain('other three patches');
      }
    }
  });
});
