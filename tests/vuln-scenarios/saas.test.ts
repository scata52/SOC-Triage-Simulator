// T8 twins (vm-saas-transfer / vm-self-hosted): what the grader and the written text do with the "who operates the system" lesson on every
// seed. The generic twin checks and the clue in the data (DeviceInfo, Tickets, the shared advisory, the decoys) are the T8 row of
// batch-b.test.ts.
import { describe, expect, it } from 'vitest';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { saasTransfer, selfHosted } from '../../src/core/vuln/templates/saas.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, checkVulnCorpus, vulnRuns } from '../helpers/vuln-scenario-check.ts';

const RUNS = vulnRuns(20, 20);
const TWINS = [saasTransfer, selfHosted] as const;

type Answer = VulnSubmission['answers'][string];
const answer = (decision: Answer['decision'], schedule: Answer['schedule'], reasons: Answer['reasons'] = []): Answer => ({ decision, control: null, schedule, reasons });

describe('answering the headline like the other twin fails the case, whatever else is right', () => {
  it.each([
    ['vm-saas-transfer', saasTransfer, answer('patch', 'emergency', ['sla-deadline', 'internet-exposed'])],
    ['vm-self-hosted', selfHosted, answer('transfer', 'none', ['vendor-responsibility'])],
    // transfer and accept are a near miss in the matrix, and a near miss on a lesson finding is not full credit
    ['vm-saas-transfer, accept', saasTransfer, answer('accept', 'none', ['vendor-responsibility'])],
  ] as const)('%s', (_id, t, wrong) => {
    for (const run of RUNS) {
      const c = buildFor(t, world(run.world), run.seed).case;
      const perfect = perfectVulnSubmission(c);
      expect(gradeVulnCase(c, perfect).score, `${run.seed}: perfect`).toBe(100);
      const head = c.findings[0].findingId;
      const g = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [head]: wrong } });
      expect(g.gate.missed.map((m) => m.findingId), `${run.seed}: the headline is a missed key finding`).toContain(head);
      expect(g.score, `${run.seed}: capped`).toBeLessThanOrEqual(60);
    }
  }, 120_000);
});

describe('the decoys are graded on their own truth, not as the lesson', () => {
  it('transferring the contract-covered server, or patching the second hosted service, costs points but is not the gate', () => {
    for (const t of TWINS) {
      for (const run of RUNS) {
        const c = buildFor(t, world(run.world), run.seed).case;
        const perfect = perfectVulnSubmission(c);
        const [, contract, hosted] = c.findings;
        const transferContract = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [contract.findingId]: answer('transfer', 'none', ['vendor-responsibility']) } });
        expect(transferContract.score, `${t.id} ${run.seed}: a contract is not a transfer`).toBeLessThan(100);
        expect(transferContract.gate.missed.map((m) => m.findingId), `${t.id} ${run.seed}: not a key finding`).not.toContain(contract.findingId);
        const patchHosted = gradeVulnCase(c, { ...perfect, answers: { ...perfect.answers, [hosted.findingId]: answer('patch', 'standard-cycle', ['sla-deadline']) } });
        expect(patchHosted.score, `${t.id} ${run.seed}: the vendor operates it`).toBeLessThan(100);
        expect(patchHosted.gate.missed.map((m) => m.findingId), `${t.id} ${run.seed}: not a key finding`).not.toContain(hosted.findingId);
      }
    }
  }, 120_000);
});

describe('the written text', () => {
  it('keeps hints 1 and 2 neutral and never presents a test of the vendor\'s systems as normal', () => {
    for (const run of RUNS.slice(0, 8)) {
      const [a, b] = TWINS.map((t) => buildFor(t, world(run.world), run.seed).case);
      for (const s of [a, b]) {
        for (const hint of s.hints.slice(0, 2)) expect(hint, `${run.seed}: ${s.templateId} hint tells the twin`).not.toMatch(/vendor-hosted|installed and operated|self-managed edition|committed date|hosted and operates/i);
        // Every mention of the vendor's systems (in any text of the case) is a limit, never an instruction.
        const texts = [...s.hints, ...s.explanation, ...s.pitfalls, ...s.solution.flatMap((x) => [x.title, x.why]), ...s.rubric.map((x) => x.text), ...s.findings.flatMap((f) => f.evidence.flatMap((e) => [e.label, e.why])), JSON.stringify(s.attachments)];
        for (const t of texts.filter((x) => /vendor's (systems|platform)|vendor\\'s (systems|platform)/.test(x))) expect(t, `${run.seed}: ${s.templateId}: "${t.slice(0, 80)}"`).toMatch(/\b(not|never|no)\b|written permission|forbid/i);
        // The two twins read the same pre-submit text.
        expect(s.hints[0]).toBe(a.hints[0]);
      }
    }
  });
});

describe("the hand-placed vendor-cloud addresses never collide with the organisation's own", () => {
  it('holds over a wide world and seed sweep (DeviceInfo vs NamedLocations, and DeviceInfo among itself)', () => {
    for (let i = 0; i < 200; i++) {
      for (const t of TWINS) {
        const s = buildFor(t, world(`probe-world-${i}`), `wide-${i}`);
        checkVulnCorpus(s.corpus, `${t.id} probe-world-${i}`);
      }
    }
  }, 120_000);
});
