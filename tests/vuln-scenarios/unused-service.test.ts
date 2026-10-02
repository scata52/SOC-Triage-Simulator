// T11 twins (vm-unused-service / vm-needed-service): what the grader does with the avoid decision on the built cases, on every seed.
// The generic twin checks and the clue in the data (Tickets, FirewallLogs, SoftwareInventory, the decoys) are the T11 row of batch-b.test.ts.
//   A (truth avoid, patch not in alsoAccept): answering patch is the near miss of DESIGN 5.1, half credit on the decision, and a lesson finding
//     needs full credit, so the case is capped below the pass mark whatever else is right.
//   B (truth patch): answering avoid removes a component the business needs and earns 0 on the decision (and, by coherence, 0 on the finding's
//     schedule and reasons), and the lesson gate caps the case too.
import { describe, expect, it } from 'vitest';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { neededService, unusedService } from '../../src/core/vuln/templates/unused-service.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

const RUNS = vulnRuns(20, 20);

type Answer = VulnSubmission['answers'][string];
const answer = (decision: Answer['decision'], schedule: Answer['schedule'], reasons: Answer['reasons'] = []): Answer => ({ decision, control: null, schedule, reasons });

describe('A: patch instead of avoid is a near miss on a lesson finding', () => {
  it('earns half credit on the decision, misses the key finding and is capped below the pass mark, with everything else right', () => {
    for (const run of RUNS) {
      const c = buildFor(unusedService, world(run.world), run.seed).case;
      const perfect = perfectVulnSubmission(c);
      const head = c.findings[0];
      expect(gradeVulnCase(c, perfect).score, `${run.seed}: perfect`).toBe(100);
      expect(head.truth.decision, `${run.seed}: the truth is avoid`).toBe('avoid');
      expect(head.truth.alsoAccept ?? [], `${run.seed}: patch is not accepted`).not.toContain('patch');
      const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [head.findingId]: answer('patch', head.truth.schedule, ['sla-deadline']) } });
      const f = g.findings[0];
      expect([f.decision.verdict, f.decision.credit], `${run.seed}: near miss`).toEqual(['near-miss', 0.5]);
      expect(g.gate.missed.map((m) => [m.findingId, m.why]), `${run.seed}: a missed lesson finding`).toContainEqual([head.findingId, 'near-miss']);
      expect(g.gate.cap, `${run.seed}: cap`).toBe(60);
      expect(g.score, `${run.seed}: capped below the pass mark`).toBeLessThanOrEqual(60);
    }
  }, 120_000);

  it('does not let the same answer on the unused console of the second host or the used one on the database server pass for the lesson', () => {
    for (const run of RUNS) {
      const c = buildFor(unusedService, world(run.world), run.seed).case;
      const perfect = perfectVulnSubmission(c);
      const [, second, used] = c.findings;
      // The second unused console: avoid is its truth, patch is the near miss, but it is not a key finding.
      const patchSecond = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [second.findingId]: answer('patch', second.truth.schedule, ['sla-deadline']) } });
      expect(patchSecond.findings[1].decision.verdict, `${run.seed}: patch on the second unused console`).toBe('near-miss');
      expect(patchSecond.gate.missed.map((m) => m.findingId), `${run.seed}: not a key finding`).not.toContain(second.findingId);
      // The used console: avoid earns 0 and, being no key finding, does not gate the case.
      const avoidUsed = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [used.findingId]: answer('avoid', used.truth.schedule, ['unused-component']) } });
      expect([avoidUsed.findings[2].decision.verdict, avoidUsed.findings[2].decision.credit], `${run.seed}: avoid on the used console`).toEqual(['wrong', 0]);
      expect(avoidUsed.score, `${run.seed}: costs points`).toBeLessThan(100);
      expect(avoidUsed.gate.missed.map((m) => m.findingId), `${run.seed}: not a key finding`).not.toContain(used.findingId);
    }
  }, 120_000);
});

describe('B: avoid instead of patch earns no credit on the decision', () => {
  it('earns 0 on the decision (and so on the finding\'s schedule and reasons), misses the key finding and is capped below the pass mark', () => {
    for (const run of RUNS) {
      const c = buildFor(neededService, world(run.world), run.seed).case;
      const perfect = perfectVulnSubmission(c);
      const head = c.findings[0];
      expect(gradeVulnCase(c, perfect).score, `${run.seed}: perfect`).toBe(100);
      expect(head.truth.decision, `${run.seed}: the truth is patch`).toBe('patch');
      // Exactly the twin's answer: avoid, in the twin's window, with the twin's reason.
      const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [head.findingId]: answer('avoid', 'next-window', ['unused-component']) } });
      const f = g.findings[0];
      expect([f.decision.verdict, f.decision.credit], `${run.seed}: no decision credit`).toEqual(['wrong', 0]);
      expect(f.schedule.credit, `${run.seed}: a decision that earns 0 earns 0 for its schedule`).toBe(0);
      expect(f.reasons.credit, `${run.seed}: and for its reasons`).toBe(0);
      expect(f.reasons.contradicting, `${run.seed}: unused-component is a code the data contradicts`).toContain('unused-component');
      expect(g.gate.missed.map((m) => [m.findingId, m.why]), `${run.seed}: a missed lesson finding`).toContainEqual([head.findingId, 'wrong-decision']);
      expect(g.gate.cap, `${run.seed}: cap`).toBe(60);
      expect(g.score, `${run.seed}: capped below the pass mark`).toBeLessThanOrEqual(60);
    }
  }, 120_000);
});

describe('the written text', () => {
  it('keeps hints 1 and 2 neutral and has the lesson and explanations name the near miss and the asymmetry', () => {
    for (const run of RUNS.slice(0, 8)) {
      const [a, b] = [unusedService, neededService].map((t) => buildFor(t, world(run.world), run.seed).case);
      expect(a.hints[0], `${run.seed}: hint 1`).toBe(b.hints[0]);
      expect(a.hints[1], `${run.seed}: hint 2`).toBe(b.hints[1]);
      for (const s of [a, b]) for (const hint of s.hints.slice(0, 2)) expect(hint, `${run.seed}: ${s.templateId} hint tells the twin`).not.toMatch(/nothing uses|owner of APP01|stock export|finance|process record/i);
      expect(a.explanation.join(' '), `${run.seed}: A explains the patch near miss`).toContain('Patching is the near miss');
      expect(a.pitfalls.join(' '), `${run.seed}: A names the patch misconception`).toContain('Patching the headline');
      expect(b.pitfalls.join(' '), `${run.seed}: B names the avoid misconception`).toContain('Avoiding the headline');
      expect(b.explanation.join(' '), `${run.seed}: B says avoid earns nothing`).toContain('Avoid is wrong here and earns nothing on the decision');
    }
  });

  it('puts the log window, the longest cycle and the scanner decoy in the solution and the explanation', () => {
    for (const run of RUNS.slice(0, 8)) {
      for (const t of [unusedService, neededService]) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const text = [...c.explanation, ...c.solution.flatMap((x) => [x.title, x.why, x.kql])].join(' ');
        expect(text, `${run.seed}: ${t.id} the log window`).toMatch(/Earliest = min\(TimeGenerated\)/);
        expect(text, `${run.seed}: ${t.id} the cycle`).toContain('3 to 4 days');
        expect(text, `${run.seed}: ${t.id} the scanner decoy`).toContain('the scanner');
      }
    }
  });
});
