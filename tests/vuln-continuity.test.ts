// Continuity (DESIGN section 8, ADR-14), the parts that do not need the SOC template:
// the answer-key data on vuln findings, the ledger functions, the choice of the hook
// and the way back from the SOC debrief to the vuln case.

import { describe, expect, it } from 'vitest';
import { buildVulnScenario, type ResolvedVulnCase } from '../src/core/vuln/scenario.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { gradeVulnCase, perfectVulnSubmission, type VulnSubmission } from '../src/core/vuln/grade.ts';
import { resolveVulnTemplate, vulnCaseTypes, vulnSeedFor } from '../src/core/vuln/worklist.ts';
import { SIMVULN_ID_PATTERN } from '../src/core/vuln/ids.ts';
import { ALL_TEMPLATES, LINKED_TEMPLATES, templateById } from '../src/core/cases/templates/index.ts';
import { FULL_STUDY_POOL, SOC_STUDY_POOL, skills, skillTactics, studyTemplateById } from '../src/core/study/scheduler.ts';
import { MAX_LEDGER, VULN_LINK_TEMPLATE_ID, addLedgerEntries, coerceLedger, isLedgerEntry, isVulnHook, ledgerEntriesFor, markConsumed, selectVulnFollowUp, trimLedger, type VulnLedgerEntry } from '../src/core/shift/vuln-hook.ts';
import { shiftSeedFor } from '../src/core/shift/plan.ts';
import { resolveVulnLink } from '../src/ui/lib/vuln-link.ts';
import { parse } from '../src/ui/router.ts';
import { sessionKey } from '../src/ui/lib/protocol.ts';
import { world } from './helpers/scenario-check.ts';

const entry = (n: number, extra: Partial<VulnLedgerEntry> = {}): VulnLedgerEntry => ({
  id: `vm-kev-internal~s${n}/F${n}@${1000 + n}`,
  vulnId: `SIMVULN-2026-${String(10000 + n).padStart(5, '0')}`,
  host: n % 2 ? 'APP01' : 'WEB01',
  decision: 'false-positive',
  schedule: 'none',
  decidedDay: 100 + n,
  caseRef: `vm-kev-internal~s${n}`,
  ...extra,
});

describe('vuln findings carry host, vulnId and sharedHost', () => {
  it('resolves them from the VulnFindings row for every real must-not-miss finding of every template', () => {
    let real = 0;
    let shared = 0;
    let local = 0;
    for (const ws of ['cont-w0', 'cont-w1']) {
      const w = world(ws);
      const devices = new Set(w.hosts.map((h) => h.name));
      for (const t of VULN_TEMPLATES) {
        for (const seed of ['a', 'b', 'c']) {
          const s = buildVulnScenario({ worldSeed: ws, templateId: t.id, seed, world: w });
          const table = s.corpus.tables.VulnFindings;
          const col = (n: string) => table.columns.indexOf(n);
          for (const f of s.case.findings) {
            const row = table.rows.find((r) => r[col('RecordId')] === f.recordId)!;
            expect(f.host, `${t.id} ${f.findingId}`).toBe(String(row[col('DeviceName')]));
            expect(f.vulnId, `${t.id} ${f.findingId}`).toBe(String(row[col('VulnId')]));
            expect(f.sharedHost, `${t.id} ${f.findingId}`).toBe(devices.has(f.host));
            if (f.mustNotMiss && f.truth.decision !== 'false-positive') {
              real++;
              expect(f.host).not.toBe('');
              expect(f.vulnId, `${t.id} ${f.findingId}`).toMatch(SIMVULN_ID_PATTERN);
              if (f.sharedHost) shared++;
              else local++;
            }
          }
        }
      }
    }
    expect(real).toBeGreaterThan(0);
    // both kinds exist: shared-world hosts (APP01, WEB01) and the hosts a case adds to its own scope
    expect(shared).toBeGreaterThan(0);
    expect(local).toBeGreaterThan(0);
  });
});

describe('selectVulnFollowUp', () => {
  it('returns null for no ledger, an empty ledger and an all-consumed ledger', () => {
    expect(selectVulnFollowUp(undefined, 's')).toBeNull();
    expect(selectVulnFollowUp([], 's')).toBeNull();
    expect(selectVulnFollowUp([entry(1, { consumed: true }), entry(2, { consumed: true })], 's')).toBeNull();
  });

  it('takes the oldest unconsumed entry by decidedDay, then ledger order', () => {
    const a = entry(1, { decidedDay: 120 });
    const b = entry(2, { decidedDay: 110 });
    const c = entry(3, { decidedDay: 110 });
    const d = entry(4, { decidedDay: 100, consumed: true });
    expect(selectVulnFollowUp([a, b, c, d], 's')!.ledgerId).toBe(b.id);
    expect(selectVulnFollowUp([a, c, b, d], 's')!.ledgerId).toBe(c.id);
    expect(selectVulnFollowUp([a], 's')!.ledgerId).toBe(a.id);
  });

  it('builds the hook from the entry and the shift seed, deterministically, without touching the ledger', () => {
    const ledger = [entry(1), entry(2)];
    const frozen = JSON.stringify(ledger);
    const h = selectVulnFollowUp(ledger, shiftSeedFor('world-x', 4))!;
    expect(h).toEqual({
      ledgerId: ledger[0].id,
      host: ledger[0].host,
      vulnId: ledger[0].vulnId,
      decidedDay: ledger[0].decidedDay,
      caseRef: ledger[0].caseRef,
      decision: ledger[0].decision,
      schedule: ledger[0].schedule,
      seed: `world-x:shift:4:vuln:${ledger[0].id}`,
    });
    expect(selectVulnFollowUp(ledger, shiftSeedFor('world-x', 4))).toEqual(h);
    expect(selectVulnFollowUp(ledger, shiftSeedFor('world-x', 5))!.seed).not.toBe(h.seed);
    expect(JSON.stringify(ledger)).toBe(frozen);
    expect(isVulnHook(h)).toBe(true);
  });

  it('never re-selects a consumed entry', () => {
    const ledger = [entry(1), entry(2), entry(3)];
    const seen: string[] = [];
    let cur: VulnLedgerEntry[] | undefined = ledger;
    for (let i = 0; i < 5; i++) {
      const h = selectVulnFollowUp(cur, `s${i}`);
      if (!h) break;
      seen.push(h.ledgerId);
      cur = markConsumed(cur, h.ledgerId);
    }
    expect(seen).toEqual(ledger.map((e) => e.id));
    expect(selectVulnFollowUp(cur, 'again')).toBeNull();
  });
});

describe('ledger cap and coercion', () => {
  it('keeps at most 50 entries, dropping consumed ones first, oldest first', () => {
    const many = Array.from({ length: 60 }, (_, i) => entry(i, i < 5 || (i >= 20 && i < 25) ? { consumed: true } : {}));
    const trimmed = trimLedger(many);
    expect(trimmed).toHaveLength(MAX_LEDGER);
    const ids = new Set(trimmed.map((e) => e.id));
    // ten consumed entries go first
    for (const i of [0, 1, 2, 3, 4, 20, 21, 22, 23, 24]) expect(ids.has(many[i].id)).toBe(false);
    expect(trimmed.every((e) => !e.consumed)).toBe(true);
    // with more excess than consumed entries, the oldest unconsumed ones go next
    const trimmed2 = trimLedger(Array.from({ length: 56 }, (_, i) => entry(i, i < 2 ? { consumed: true } : {})));
    expect(trimmed2).toHaveLength(MAX_LEDGER);
    expect(trimmed2[0].id).toBe(entry(6).id);
    // under the cap nothing changes
    const few = [entry(1), entry(2, { consumed: true })];
    expect(trimLedger(few)).toBe(few);
  });

  it('addLedgerEntries appends, trims and leaves an absent ledger absent when there is nothing to add', () => {
    expect(addLedgerEntries(undefined, [])).toBeUndefined();
    expect(addLedgerEntries([entry(1)], [])).toEqual([entry(1)]);
    const full = Array.from({ length: MAX_LEDGER }, (_, i) => entry(i));
    const next = addLedgerEntries(full, [entry(99)])!;
    expect(next).toHaveLength(MAX_LEDGER);
    expect(next.at(-1)!.id).toBe(entry(99).id);
    expect(next[0].id).toBe(entry(1).id);
  });

  it('coerceLedger keeps valid entries and drops malformed ones', () => {
    const good = entry(1);
    const raw = [
      good,
      { ...entry(2), id: '' },
      { ...entry(3), vulnId: 'CVE-2021-44228' },
      { ...entry(4), vulnId: 'SIMVULN-26-1' },
      { ...entry(5), host: '' },
      { ...entry(6), decision: 'ignore' },
      { ...entry(7), schedule: 'soon' },
      { ...entry(8), decidedDay: Number.NaN },
      { ...entry(9), caseRef: '' },
      { ...entry(10), consumed: 'yes' },
      null,
      7,
      'x',
      { ...good }, // a duplicate id
      entry(11, { consumed: true }),
    ];
    const out = coerceLedger(raw)!;
    expect(out.map((e) => e.id)).toEqual([good.id, entry(11).id]);
    expect(out[1].consumed).toBe(true);
    expect(coerceLedger('nope')).toBeUndefined();
    expect(coerceLedger(undefined)).toBeUndefined();
    expect(coerceLedger(Array.from({ length: 70 }, (_, i) => entry(i)))).toHaveLength(MAX_LEDGER);
    expect(isLedgerEntry(good)).toBe(true);
  });
});

describe('ledgerEntriesFor', () => {
  const w = world('cont-w0');
  // a case with a real must-not-miss finding on a shared-world host
  const c = buildVulnScenario({ worldSeed: w.seed, templateId: 'vm-kev-internal', seed: 'led1', world: w }).case;
  const target = c.findings.find((f) => f.mustNotMiss && f.truth.decision !== 'false-positive' && f.sharedHost)!;
  const attempt = { caseRef: c.id, completedAt: 5_000, day: 77 };
  const entriesFor = (cs: Pick<ResolvedVulnCase, 'findings'>, sub: VulnSubmission, existing: VulnLedgerEntry[] = []) => ledgerEntriesFor(cs, gradeVulnCase(c, sub), sub, attempt, existing);
  const withAnswer = (patch: Partial<VulnSubmission['answers'][string]>, id = target.findingId): VulnSubmission => {
    const s = perfectVulnSubmission(c);
    return { ...s, answers: { ...s.answers, [id]: { ...s.answers[id], ...patch } } };
  };

  it('writes nothing for a perfect answer', () => {
    expect(entriesFor(c, perfectVulnSubmission(c))).toEqual([]);
  });

  it('writes an entry for a real must-not-miss finding dismissed as a false positive', () => {
    const sub = withAnswer({ decision: 'false-positive', schedule: 'none' });
    const [e, ...rest] = entriesFor(c, sub);
    expect(rest).toEqual([]);
    expect(e).toEqual({
      id: `${c.id}/${target.findingId}@5000`,
      vulnId: target.vulnId,
      host: target.host,
      decision: 'false-positive',
      schedule: 'none',
      decidedDay: 77,
      caseRef: c.id,
    });
    expect(isLedgerEntry(e)).toBe(true);
  });

  it('writes an entry when it is left unscheduled, accepted or scheduled past its SLA', () => {
    expect(entriesFor(c, withAnswer({ schedule: null }))[0]).toMatchObject({ decision: target.truth.decision, schedule: 'none' });
    expect(entriesFor(c, withAnswer({ decision: 'accept', schedule: 'none' }))[0]).toMatchObject({ decision: 'accept', schedule: 'none' });
    const late = entriesFor(c, withAnswer({ schedule: 'standard-cycle' }));
    if (target.truth.slaLatest && target.truth.slaLatest !== 'standard-cycle') expect(late[0]).toMatchObject({ schedule: 'standard-cycle' });
  });

  it('writes nothing for a finding the answer key does not mark must-not-miss, nor for an unanswered decision', () => {
    const decoy = c.findings.find((f) => !f.mustNotMiss)!;
    expect(entriesFor(c, withAnswer({ decision: 'false-positive', schedule: 'none' }, decoy.findingId))).toEqual([]);
    const s = perfectVulnSubmission(c);
    expect(entriesFor(c, { ...s, answers: { ...s.answers, [target.findingId]: { decision: null, control: null, schedule: null, reasons: [] } } })).toEqual([]);
  });

  it('excludes mitigated findings, case-local hosts, findings without a SIMVULN id and false positives', () => {
    const dismissed = withAnswer({ decision: 'false-positive', schedule: 'none' });
    const mod = (patch: Partial<typeof target>) => ({ findings: c.findings.map((f) => (f.findingId === target.findingId ? { ...f, ...patch } : f)) });
    expect(entriesFor(mod({ truth: { ...target.truth, decision: 'mitigate' } }), dismissed)).toEqual([]);
    expect(entriesFor(mod({ truth: { ...target.truth, mitigation: ['waf-block' as never] } }), dismissed)).toEqual([]);
    expect(entriesFor(mod({ sharedHost: false }), dismissed)).toEqual([]);
    expect(entriesFor(mod({ vulnId: '' }), dismissed)).toEqual([]);
    expect(entriesFor(mod({ truth: { ...target.truth, decision: 'false-positive', schedule: 'none' } }), dismissed)).toEqual([]);
    // the unmodified case does write one
    expect(entriesFor(c, dismissed)).toHaveLength(1);
  });

  it('adds no second unconsumed entry for the same (vulnId, host), but does after the first was consumed', () => {
    const dismissed = withAnswer({ decision: 'false-positive', schedule: 'none' });
    const first = entriesFor(c, dismissed)[0];
    expect(entriesFor(c, dismissed, [{ ...first, id: 'other' }])).toEqual([]);
    expect(entriesFor(c, dismissed, [{ ...first, id: 'other', consumed: true }])).toHaveLength(1);
    expect(entriesFor(c, dismissed, [{ ...first, id: 'other', host: 'ELSE01' }])).toHaveLength(1);
    // two findings of one batch on the same pair make one entry
    const twin = { ...target, findingId: 'F-twin' };
    const both = { findings: [...c.findings, twin] };
    const s = withAnswer({ decision: 'false-positive', schedule: 'none' });
    const sub: VulnSubmission = { ...s, answers: { ...s.answers, 'F-twin': { ...s.answers[target.findingId] } } };
    const g = gradeVulnCase(c, s);
    const grade = { mustNotMiss: { ...g.mustNotMiss, dismissed: [...g.mustNotMiss.dismissed, 'F-twin'] } };
    expect(ledgerEntriesFor(both, grade, sub, attempt, [])).toHaveLength(1);
  });
});

describe('the way back from the SOC debrief', () => {
  const types = vulnCaseTypes(VULN_TEMPLATES);
  const link = (caseRef: string) => ({ caseRef, vulnId: 'SIMVULN-2026-00042', host: 'APP01', decision: 'false-positive' as const, schedule: 'none' as const });

  it('round-trips every registered template: the route resolves back to the same template', () => {
    for (const t of VULN_TEMPLATES) {
      for (const base of ['seed-a', 'x~y']) {
        const found = vulnSeedFor(types, t.id, base);
        expect(found).not.toBeNull();
        const caseRef = `${t.id}~${found!.seed}`;
        const r = resolveVulnLink(link(caseRef))!;
        expect(r, caseRef).not.toBeNull();
        expect(r.caseTitle).toBe(t.title);
        const route = parse(r.href);
        expect(route).toMatchObject({ name: 'vuln-case', seed: found!.seed });
        const type = types.find((x) => x.slug === (route as { slug: string }).slug)!;
        expect(resolveVulnTemplate(type, (route as { seed: string }).seed).id).toBe(t.id);
      }
    }
  });

  it('splits at the first tilde: a seed may contain tildes', () => {
    const t = VULN_TEMPLATES[0];
    const type = types.find((x) => x.templates.some((y) => y.id === t.id))!;
    let seed = '';
    for (let i = 0; i < 100 && !seed; i++) if (resolveVulnTemplate(type, `a~b~${i}`).id === t.id) seed = `a~b~${i}`;
    expect(seed).not.toBe('');
    const r = resolveVulnLink(link(`${t.id}~${seed}`))!;
    expect(parse(r.href)).toMatchObject({ name: 'vuln-case', slug: type.slug, seed });
  });

  it('shows labels without dates, and no link for an unknown template or a malformed reference', () => {
    const t = VULN_TEMPLATES[0];
    const found = vulnSeedFor(types, t.id, 's')!;
    const r = resolveVulnLink(link(`${t.id}~${found.seed}`))!;
    expect(r).toMatchObject({ vulnId: 'SIMVULN-2026-00042', host: 'APP01', decision: 'false positive', schedule: 'no change' });
    expect(resolveVulnLink(link('vm-nope~s'))).toBeNull();
    expect(resolveVulnLink(link('endpoint-known-vuln-exploit~s'))).toBeNull();
    expect(resolveVulnLink(link('no-tilde'))).toBeNull();
    expect(resolveVulnLink(link(`${t.id}~`))).toBeNull();
    expect(resolveVulnLink(link(`~${found.seed}`))).toBeNull();
  });
});

describe('the worker session key of a hooked shift', () => {
  const spec = { kind: 'shift' as const, worldSeed: 'w', number: 3, budget: 30 as const, campaign: null, recent: [] as string[] };
  const hook = (ledgerId: string) => ({ ledgerId, host: 'APP01', vulnId: 'SIMVULN-2026-00007', decidedDay: 90, caseRef: 'vm-kev-internal~z', decision: 'accept' as const, schedule: 'none' as const, seed: `s:vuln:${ledgerId}` });

  it('includes the hook ledger id, so a different hook (or none) opens a different session', () => {
    expect(sessionKey(spec)).toBe('shift:w:3');
    expect(sessionKey({ ...spec, vulnHook: hook('e1') })).toBe('shift:w:3:vuln:e1');
    expect(sessionKey({ ...spec, vulnHook: hook('e2') })).not.toBe(sessionKey({ ...spec, vulnHook: hook('e1') }));
    expect(sessionKey({ ...spec, vulnHook: hook('e1') })).not.toBe(sessionKey(spec));
  });
});

describe('the round-trip guard of resolveVulnLink', () => {
  it('gives null for a reference whose seed resolves to the sibling twin', () => {
    const types = vulnCaseTypes(VULN_TEMPLATES);
    let checked = 0;
    for (const type of types) {
      if (type.templates.length < 2) continue;
      const [a, b] = type.templates;
      const found = vulnSeedFor(types, b.id, 'guard');
      expect(found).not.toBeNull();
      expect(resolveVulnTemplate(type, found!.seed).id).toBe(b.id);
      const link = { caseRef: `${a.id}~${found!.seed}`, vulnId: 'SIMVULN-2026-00042', host: 'APP01', decision: 'false-positive' as const, schedule: 'none' as const };
      expect(resolveVulnLink(link), link.caseRef).toBeNull();
      checked++;
    }
    expect(checked).toBeGreaterThan(0);
  });
});

describe('the linked template is a registry member but not a learner choice', () => {
  it('has a unique id across SOC, linked and vulnerability templates, and resolves by id', () => {
    const ids = [...ALL_TEMPLATES, ...LINKED_TEMPLATES, ...VULN_TEMPLATES].map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(LINKED_TEMPLATES.map((t) => t.id)).toContain(VULN_LINK_TEMPLATE_ID);
    for (const t of LINKED_TEMPLATES) {
      expect(templateById(t.id)).toBe(t);
      expect(ALL_TEMPLATES.includes(t)).toBe(false);
    }
  });

  it('stays out of every study pool, but its attempts still train its domains and tactics', () => {
    for (const t of LINKED_TEMPLATES) {
      expect(SOC_STUDY_POOL.some((x) => x.id === t.id)).toBe(false);
      expect(FULL_STUDY_POOL.some((x) => x.id === t.id)).toBe(false);
      const looked = studyTemplateById(t.id)!;
      expect(looked).toMatchObject({ id: t.id, kind: 'soc', cysaDomains: t.cysaDomains });
      const trained = skills([{ templateId: t.id, percent: 100, day: 1, mode: 'shift', correct: true }]);
      for (const d of t.cysaDomains) expect(trained.find((s) => s.kind === 'domain' && s.key === d)!.attempts).toBe(1);
      for (const tac of skillTactics(t)) expect(trained.find((s) => s.kind === 'tactic' && s.key === tac)!.attempts).toBe(1);
    }
  });
});
