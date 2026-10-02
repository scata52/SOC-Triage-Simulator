// T10 twins with T9 inside (vm-dup-plugins / vm-distinct, tier 3): what the grader and the written text do with the three lessons on every seed:
// count fixes, not findings (and close a duplicate honestly), order by what is due first (the asset tier row), and the capacity squeeze. The
// generic twin checks and the data (SoftwareInventory usage rows, the two runs, the stale-versus-fresh conflict, the T9 pair, capacity) are the
// T10 row of batch-b.test.ts.
import { describe, expect, it } from 'vitest';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { distinct, dupPlugins } from '../../src/core/vuln/templates/tier3.ts';
import { compareVersions } from '../../src/core/vuln/scan-writer.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

const RUNS = vulnRuns(20, 20);
const TWINS = [dupPlugins, distinct] as const;

type Answer = VulnSubmission['answers'][string];
const answer = (decision: Answer['decision'], schedule: Answer['schedule'], reasons: Answer['reasons'] = []): Answer => ({ decision, control: null, schedule, reasons });

// The worklist places, fixed by the template: 0 the portal's detection (headline), 1 the package-level finding, 2 and 3 services that link the
// system package, 4 and 5 services that bundle their own copy, 6 payments, 7 developer test server, 8 the Sim-KEV Critical.
describe('answering a lesson finding wrongly fails the case, whatever else is right', () => {
  it('answers the headline like the twin: the other half of the pair', () => {
    for (const run of RUNS) {
      for (const [t, wrong] of [
        [dupPlugins, answer('patch', 'standard-cycle', ['low-exploitability'])],
        [distinct, answer('false-positive', 'none', ['duplicate-root-cause'])],
      ] as const) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        expect(gradeVulnCase(c, perfect).score, `${run.seed}: ${t.id} perfect`).toBe(100);
        const head = c.findings[0];
        const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [head.findingId]: wrong } });
        expect(g.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} the headline is a missed key finding`).toContain(head.findingId);
        expect(g.gate.cap, `${run.seed}: ${t.id} cap`).toBe(60);
        expect(g.score, `${run.seed}: ${t.id} capped below the pass mark`).toBeLessThanOrEqual(60);
      }
    }
  }, 120_000);

  it('closes every per-service detection as a duplicate (the blanket rule), or schedules the payments Medium by the table alone (standard cycle): both are missed key findings', () => {
    for (const t of TWINS) {
      for (const run of RUNS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        const [head, , , , relay, , pay] = c.findings;
        // The blanket rule: "close every per-service detection as a duplicate" (the portal, forms, directory, mail relay and chat service) and patch the package. It leaves the bundled copies open.
        const blanket = Object.fromEntries(c.findings.slice(0, 6).filter((_, i) => i !== 1).map((f) => [f.findingId, answer('false-positive', 'none', ['duplicate-root-cause'])]));
        const closed = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, ...blanket } });
        expect(relay.lesson, `${run.seed}: ${t.id} the mail relay's bundled copy is a lesson finding`).toBe(true);
        expect(closed.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} the blanket duplicate rule leaves the relay's bundled copy open`).toContain(relay.findingId);
        expect(closed.score, `${run.seed}: ${t.id} the blanket duplicate rule is capped`).toBeLessThanOrEqual(60);
        expect(head.lesson, `${run.seed}: ${t.id} the headline is a lesson finding`).toBe(true);
        const alone = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [relay.findingId]: answer('false-positive', 'none', ['duplicate-root-cause']) } });
        expect(alone.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} closing the relay's bundled copy alone is the gate`).toContain(relay.findingId);
        const late = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [pay.findingId]: answer('patch', 'standard-cycle', ['sla-deadline']) } });
        expect(late.findings[6].schedule.verdict, `${run.seed}: ${t.id} the table's schedule for a Medium is later than the asset tier deadline allows`).toBe('sla-breach');
        expect(late.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} a missed lesson finding`).toContain(pay.findingId);
        expect(late.score, `${run.seed}: ${t.id} capped`).toBeLessThanOrEqual(60);
      }
    }
  }, 120_000);
});

// A tier-3 case carries several independent decisions the lesson names, and DESIGN 5.8 lifts the 1-3 lesson findings guidance for it: the
// rule is to flag every finding the lesson names. Each of these, dismissed as a false positive on its own with everything else perfect, fails.
describe('every finding the lesson names is a key finding (a probe: dismissing one alone passed at 94 to 95)', () => {
  const NAMED = [
    ['the package-level finding', 1],
    ['the chat service bundled copy', 5],
    ['the developer test server Critical', 7],
  ] as const;

  it('dismissing any one of them alone is a missed key finding, capped below the pass mark, and each has an SLA', () => {
    for (const t of TWINS) {
      for (const run of RUNS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        const rollup = c.findings.find((f) => f.evidence.some((e) => e.id === 'unrelated-rollup'))!;
        const named = [...NAMED.map(([what, i]) => [what, c.findings[i]] as const), ['the old-run High updated only by a rollup', rollup] as const];
        expect(c.findings.filter((f) => f.lesson).length, `${run.seed}: ${t.id} lesson findings`).toBe(7);
        for (const [what, f] of named) {
          expect(f.lesson, `${run.seed}: ${t.id} ${what} is a lesson finding`).toBe(true);
          expect(f.truth.slaLatest, `${run.seed}: ${t.id} ${what} has an SLA`).toBeDefined();
          const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [f.findingId]: answer('false-positive', 'none', ['stale-scan']) }, order: perfect.order.filter((id) => id !== f.findingId) });
          expect(g.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} dismissing ${what} alone`).toContain(f.findingId);
          expect(g.score, `${run.seed}: ${t.id} dismissing ${what} alone fails`).toBeLessThanOrEqual(60);
        }
      }
    }
  }, 120_000);

  it('names each of them in the lesson text of both twins', () => {
    for (const t of TWINS) {
      expect(t.lesson, `${t.id} package-level`).toMatch(/package-level finding is that one fix|package-level finding \(itself patched/);
      expect(t.lesson, `${t.id} chat service`).toMatch(/chat service/);
      expect(t.lesson, `${t.id} developer test server`).toMatch(/isolated developer test server/);
      expect(t.lesson, `${t.id} rollup`).toMatch(/operating system rollup/);
    }
  });
});

describe('the decoys are graded on their own truth', () => {
  it('closing the chat service or the package-level finding as a duplicate costs points and is the gate (both are lesson findings: the chat service bundles its own copy, the package is the one fix)', () => {
    for (const run of RUNS) {
      for (const t of TWINS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        for (const other of [c.findings[5], c.findings[1]]) {
          const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [other.findingId]: answer('false-positive', 'none', ['duplicate-root-cause']) } });
          expect(g.score, `${run.seed}: ${t.id} ${other.findingId} is not a duplicate`).toBeLessThan(100);
          expect(g.gate.missed.map((m) => m.findingId), `${run.seed}: ${t.id} ${other.findingId} is a key finding`).toContain(other.findingId);
        }
      }
    }
  }, 120_000);

  it('patching a duplicate (a linked service) is not full credit either, and the order of payments and developer test server is graded', () => {
    for (const t of TWINS) {
      for (const run of RUNS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        const linked = c.findings[2];
        const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [linked.findingId]: answer('patch', 'standard-cycle', ['low-exploitability']) } });
        expect(g.score, `${run.seed}: ${t.id} a linked service is one fix with the package-level finding`).toBeLessThan(100);
        // Severity order puts the developer test server's Critical ahead of the payments Medium: the ordering component loses points, the gate does not fire.
        const [, , , , , , pay, dev] = c.findings;
        const swapped = perfect.order.map((id) => (id === pay.findingId ? dev.findingId : id === dev.findingId ? pay.findingId : id));
        const o = gradeVulnCase(c, { ...perfect, order: swapped });
        const part = (x: typeof o, id: string) => x.components.find((y) => y.id === id)!.earned;
        expect(part(o, 'ordering'), `${run.seed}: ${t.id} severity order costs ordering points`).toBeLessThan(part(gradeVulnCase(c, perfect), 'ordering'));
        expect(o.gate.missed.length, `${run.seed}: ${t.id} ordering alone never gates`).toBe(0);
      }
    }
  }, 120_000);
});

describe('the written text', () => {
  it('words the duplicate closure honestly in the policy, the lesson, the explanation and the pitfalls, with bundled copies first and a restart', () => {
    for (const run of RUNS.slice(0, 6)) {
      for (const t of TWINS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const policy = JSON.stringify(c.attachments.find((x) => x.title.includes('remediation standard'))!.body);
        expect(policy, `${run.seed}: ${t.id} policy`).toContain('not a claim that the vulnerability is absent');
        expect(policy, `${run.seed}: ${t.id} policy: bundled copies first`).toContain('check SoftwareInventory for a copy of the component that the service bundles with itself');
        expect(policy, `${run.seed}: ${t.id} policy: restart`).toContain('a running process keeps the old library in memory');
        expect(t.lesson, `${t.id} lesson`).toMatch(/closed (as a duplicate|with duplicate-root-cause)|duplicate/);
        const prose = [...c.explanation, ...c.pitfalls].join(' ');
        expect(prose, `${run.seed}: ${t.id} says the vulnerability is real`).toMatch(/real and is fixed once, on the package-level finding|is real and is fixed once/);
        expect(prose, `${run.seed}: ${t.id} says it is not a claim of absence`).toMatch(/not a claim that the vulnerability is absent|duplicate as if the vulnerability were absent|not declared harmless|as "not vulnerable"|"closed as a duplicate" as "not vulnerable"/);
        expect(prose, `${run.seed}: ${t.id} restarts the services`).toMatch(/restart/);
        expect(prose, `${run.seed}: ${t.id} never says the duplicates are absent or false alarms`).not.toMatch(/does not exist|is absent from|false alarm|not vulnerable\b(?!")/i);
      }
    }
  });

  it('keeps hints 1 and 2 the same in both twins and neutral about where the portal gets its copy, and uses a fictional library', () => {
    for (const run of RUNS.slice(0, 8)) {
      const [a, b] = TWINS.map((t) => buildFor(t, world(run.world), run.seed));
      expect(a.case.hints[0], `${run.seed}: hint 1`).toBe(b.case.hints[0]);
      expect(a.case.hints[1], `${run.seed}: hint 2`).toBe(b.case.hints[1]);
      for (const s of [a, b]) {
        for (const hint of s.case.hints.slice(0, 2)) expect(hint, `${run.seed}: ${s.case.templateId} hint tells the twin`).not.toMatch(/linked by|bundled with|portal|bundles its own/i);
        // The library is fictional: none of the real transport libraries' names appears in the case or its data.
        const text = JSON.stringify(s.case) + JSON.stringify(s.corpus.tables.SoftwareInventory) + JSON.stringify(s.corpus.tables.VulnFindings);
        expect(text, `${run.seed}: ${s.case.templateId} a real library name`).not.toMatch(/openssl|libssl|gnutls|boringssl|wolfssl|mbed\s?tls|libressl|\bnss\b|schannel/i);
        expect(text, `${run.seed}: ${s.case.templateId} the fictional library`).toContain('Skerrimoor Secure Transport Library');
      }
    }
  });
});

// A worklist product is not also installed, below that flaw's fix, on another worklist host that has no finding for it: a Sim-KEV flaw in a
// product that the payments database also runs below the fix would be an unexplained second exposure (round-2 review of WP3).
describe('no product is installed below another worklist flaw fix on another host', () => {
  it('holds over 60 seeds of both twins', () => {
    const rowsOf = (s: ReturnType<typeof buildFor>, t: 'SoftwareInventory' | 'VulnFindings' | 'VulnIntel') => s.corpus.tables[t].rows.map((r) => Object.fromEntries(s.corpus.tables[t].columns.map((k, i) => [k, r[i]])));
    for (const t of TWINS) {
      for (let i = 0; i < 60; i++) {
        const s = buildFor(t, world(`vuln-sweep-${i % 5}`), `sweep-${i}`);
        const inventory = rowsOf(s, 'SoftwareInventory');
        const intel = new Map(rowsOf(s, 'VulnIntel').map((r) => [String(r.VulnId), r]));
        const all = rowsOf(s, 'VulnFindings');
        const worklist = s.case.findings.map((f) => all.find((r) => r.RecordId === f.recordId)!);
        for (const f of worklist) {
          const fix = String(intel.get(String(f.VulnId))!.FixedVersion);
          for (const inv of inventory) {
            if (inv.DeviceName === f.DeviceName || !String(f.Title).includes(` in ${String(inv.Product)} `)) continue;
            const below = compareVersions(String(inv.Version), fix) < 0;
            const hasFinding = worklist.some((w) => w.DeviceName === inv.DeviceName && String(w.Title).includes(` in ${String(inv.Product)} `));
            expect(!below || hasFinding, `${t.id} sweep-${i}: ${String(inv.Product)} ${String(inv.Version)} on ${String(inv.DeviceName)} is below the fix ${fix} of ${String(f.VulnId)} (${String(f.DeviceName)}) with no finding`).toBe(true);
          }
        }
      }
    }
  }, 300_000);
});
