// WP1e: the pure helpers behind the vulnerability worklist UI (src/core/vuln/worklist.ts):
// the default order (scanner export order, never the answer key), what the
// twins show before submit, sorting, moving, reasons, the draft and the
// submission built from it, the per-mode table lists and the case types.
import { describe, expect, it } from 'vitest';
import { createRng } from '../src/core/rng.ts';
import { quality } from '../src/core/study/srs.ts';
import { TABLE_NAMES, TABLES, type Cell } from '../src/core/logs/schema.ts';
import { gradeVulnCase, perfectVulnSubmission, type VulnFindingAnswer, type VulnSubmission } from '../src/core/vuln/grade.ts';
import { REASON_CODES, VULN_DECISIONS, VULN_SCHEDULES, type ReasonCode } from '../src/core/vuln/model.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import type { ResolvedVulnCase, VulnScenario } from '../src/core/vuln/scenario.ts';
import {
  DECISION_LABELS,
  DECISION_OPTION_TEXT,
  REASON_GROUPS,
  REASON_LABELS,
  SCHEDULE_LABELS,
  SORT_FIRST_DIR,
  SORT_HEADERS,
  SORT_KEYS,
  VULN_PASS_PERCENT,
  VULN_TABLE_NAMES,
  applySort,
  boundsMessage,
  buildSubmission,
  caseView,
  defaultOrder,
  dirLabel,
  emptyDraft,
  formatCvss,
  isVulnTable,
  missingForSubmit,
  moveBy,
  moveTo,
  nextSort,
  pinCount,
  positionMessage,
  resolveVulnTemplate,
  restoreDraft,
  severityRank,
  sortButtonLabel,
  sortMessage,
  sortOrder,
  stillNeededMessage,
  tablesFor,
  toggleReason,
  undoSort,
  vulnCaseTypes,
  worklistRows,
  type SortKey,
  type VulnDraft,
  type WorklistRow,
} from '../src/core/vuln/worklist.ts';
import { world } from './helpers/scenario-check.ts';
import { buildFor } from './helpers/vuln-scenario-check.ts';

const SEEDS = Array.from({ length: 20 }, (_, i) => `wl${i}`);
const W = world('wl-world');

const cache = new Map<string, VulnScenario>();
function built(templateId: string, seed: string): VulnScenario {
  const key = `${templateId}/${seed}`;
  let s = cache.get(key);
  if (!s) {
    const t = VULN_TEMPLATES.find((x) => x.id === templateId)!;
    s = buildFor(t, W, seed);
    cache.set(key, s);
  }
  return s;
}

// The rows a lookup of the findings' RecordIds returns: full corpus rows.
function lookupFor(s: VulnScenario): { columns: string[]; row: Cell[] }[] {
  const table = s.corpus.tables.VulnFindings;
  const ri = table.columns.indexOf('RecordId');
  const wanted = new Set(s.case.findings.map((f) => f.recordId));
  return table.rows.filter((r) => wanted.has(String(r[ri]))).map((row) => ({ columns: table.columns, row }));
}

function rowsOf(s: VulnScenario): Map<string, WorklistRow> {
  return worklistRows(
    s.case.findings.map(({ findingId, recordId }) => ({ findingId, recordId })),
    lookupFor(s),
  );
}

const ids = (c: ResolvedVulnCase) => c.findings.map((f) => f.findingId);

describe('default order and rows', () => {
  it('is FindingId ascending (scanner export order)', () => {
    expect(defaultOrder(['VF-30000', 'VF-10000', 'VF-20000', 'VF-10000'])).toEqual(['VF-10000', 'VF-20000', 'VF-30000']);
  });

  it('does not depend on spec order', () => {
    for (const t of VULN_TEMPLATES) {
      for (const seed of SEEDS.slice(0, 5)) {
        const c = built(t.id, seed).case;
        const want = defaultOrder(ids(c));
        for (let k = 0; k < 5; k++) {
          const permuted = createRng(`perm:${t.id}:${seed}:${k}`).shuffle(c.findings);
          expect(defaultOrder(permuted.map((f) => f.findingId))).toEqual(want);
        }
      }
    }
  });

  it('differs from idealOrder on some seed, and the headline finding is not always first', () => {
    for (const t of VULN_TEMPLATES) {
      const cases = SEEDS.map((seed) => built(t.id, seed).case);
      // idealOrder lists only the top findings, so compare with the full ideal-first order (ideal, then the rest in spec order).
      const idealFirst = (c: ResolvedVulnCase) => [...c.idealOrder, ...ids(c).filter((id) => !c.idealOrder.includes(id))];
      expect(cases.some((c) => defaultOrder(ids(c)).join() !== idealFirst(c).join()), t.id).toBe(true);
      expect(cases.some((c) => defaultOrder(ids(c)).join() !== ids(c).join()), `${t.id} default differs from spec order`).toBe(true);
      expect(cases.some((c) => defaultOrder(ids(c))[0] !== c.findings[0].findingId), t.id).toBe(true);
    }
  });

  it('the e2e web-servers case has a spec order that is not FindingId-ascending (proof for the e2e default-order test)', () => {
    const type = vulnCaseTypes(VULN_TEMPLATES).find((x) => x.slug === 'scan-review-web-servers')!;
    const t = resolveVulnTemplate(type, 'e2e');
    const w = world('e2e-world');
    const c = buildFor(t, w, 'e2e').case;
    expect(ids(c)).not.toEqual([...ids(c)].sort());
    expect(defaultOrder(ids(c))).toEqual([...ids(c)].sort());
  });

  it('takes only finding ids: twins with the same seed each get the sorted ids of their own case', () => {
    for (const t of VULN_TEMPLATES.filter((x) => x.twin)) {
      for (const seed of SEEDS.slice(0, 5)) {
        for (const id of [t.id, t.twin!]) {
          const c = built(id, seed).case;
          expect(defaultOrder(ids(c))).toEqual([...ids(c)].sort());
        }
      }
    }
  });

  it('worklistRows builds its map in default order, whatever the order of pairs and lookup rows', () => {
    for (const t of VULN_TEMPLATES) {
      for (const seed of SEEDS) {
        const s = built(t.id, seed);
        const c = s.case;
        const pairs = c.findings.map(({ findingId, recordId }) => ({ findingId, recordId }));
        const lookup = lookupFor(s);
        const rng = createRng(`rows:${t.id}:${seed}`);
        const rows = worklistRows(rng.shuffle(pairs), rng.shuffle(lookup));
        expect([...rows.keys()], `${t.id}/${seed}`).toEqual(defaultOrder(ids(c)));
        expect([...worklistRows(pairs, lookup).entries()]).toEqual([...rows.entries()]);
        // columns are read by name from the VulnFindings row
        for (const f of c.findings) {
          const r = rows.get(f.findingId)!;
          const src = lookup.find((l) => l.row[l.columns.indexOf('RecordId')] === f.recordId)!;
          const col = (n: string) => src.row[src.columns.indexOf(n)];
          expect(r).toEqual({
            findingId: f.findingId,
            recordId: f.recordId,
            host: col('DeviceName'),
            vulnId: col('VulnId') ?? '',
            title: col('Title'),
            severity: col('Severity'),
            cvss: col('CvssBase'),
            firstSeen: col('FirstSeen'),
          });
        }
      }
    }
  });
});

// Pairs whose pre-submit surface may differ in a named column; needs a coordinator decision.
const TWIN_SURFACE_WHITELIST: Record<string, string[]> = {};

describe('twins present the same pre-submit surface', () => {
  const pairs = VULN_TEMPLATES.filter((t) => t.twin && t.id < t.twin).map((t) => [t.id, t.twin!] as const);
  it('has at least one twin pair in the slice', () => expect(pairs.length).toBeGreaterThan(0));

  const COLUMNS = ['host', 'title', 'vulnId', 'severity', 'cvss', 'firstSeen'] as const;
  for (const [a, b] of pairs) {
    it(`${a} and ${b}: briefing, attachments, counts, worklist columns and table row counts`, () => {
      const skip = new Set(TWIN_SURFACE_WHITELIST[`${a}|${b}`] ?? []);
      for (const seed of SEEDS) {
        const sa = built(a, seed);
        const sb = built(b, seed);
        const va = caseView(sa.case);
        const vb = caseView(sb.case);
        const label = `${a}|${b} ${seed}`;
        for (const k of ['title', 'difficulty', 'now', 'briefing', 'attachments'] as const) {
          if (!skip.has(k)) expect(va[k], `${label} ${k}`).toEqual(vb[k]);
        }
        expect(va.hints.length, label).toBe(vb.hints.length);
        expect(sa.case.findings.length, label).toBe(sb.case.findings.length);
        const ra = [...rowsOf(sa).values()];
        const rb = [...rowsOf(sb).values()];
        for (const col of COLUMNS) {
          if (skip.has(col)) continue;
          const ms = (rows: WorklistRow[]) => rows.map((r) => JSON.stringify(r[col])).sort();
          expect(ms(ra), `${label} column ${col}`).toEqual(ms(rb));
        }
        for (const name of TABLE_NAMES) {
          if (skip.has(name)) continue;
          expect(sa.corpus.tables[name].rows.length, `${label} rows of ${name}`).toBe(sb.corpus.tables[name].rows.length);
        }
      }
    });
  }
});

it('T3 twins write the same number of rows per table', () => {
  for (const seed of SEEDS) {
    const a = built('vm-kev-internal', seed).corpus;
    const b = built('vm-nokev-internal', seed).corpus;
    for (const name of TABLE_NAMES) expect(a.tables[name].rows.length, `${seed} ${name}`).toBe(b.tables[name].rows.length);
  }
});

describe('sorting', () => {
  const rows = new Map<string, WorklistRow>(
    (
      [
        ['VF-10003', 'WEB01', 'Zeta flaw', 'High', 7.5, '2026-09-01T00:00:00Z'],
        ['VF-10001', 'app01', 'alpha flaw', 'Critical', 9.8, '2026-08-01T00:00:00Z'],
        ['VF-10002', 'FS01', 'Mid flaw', 'Medium', null, ''],
        ['VF-10004', 'DB01', 'Config check', 'Info', 5, '2026-09-01T00:00:00Z'],
        ['VF-10005', '', 'Odd flaw', 'Weird', 7.5, '2026-07-01T00:00:00Z'],
      ] as const
    ).map(([findingId, host, title, severity, cvss, firstSeen]) => [findingId, { findingId, recordId: `R-${findingId}`, host, vulnId: '', title, severity, cvss, firstSeen }]),
  );
  const all = [...rows.keys()];

  it('nextSort flips the same key and starts a new key in its first direction', () => {
    expect(nextSort(null, 'cvss')).toEqual({ key: 'cvss', dir: 'desc' });
    expect(nextSort({ key: 'cvss', dir: 'desc' }, 'cvss')).toEqual({ key: 'cvss', dir: 'asc' });
    expect(nextSort({ key: 'cvss', dir: 'asc' }, 'cvss')).toEqual({ key: 'cvss', dir: 'desc' });
    expect(nextSort({ key: 'cvss', dir: 'asc' }, 'host')).toEqual({ key: 'host', dir: SORT_FIRST_DIR.host });
    expect(SORT_FIRST_DIR).toEqual({ finding: 'asc', host: 'asc', vulnerability: 'asc', severity: 'desc', cvss: 'desc', firstSeen: 'asc' });
  });

  it('sorts by every key, ties by FindingId, missing values last in both directions', () => {
    const by = (key: SortKey, dir: 'asc' | 'desc') => sortOrder(all, rows, { key, dir });
    expect(by('finding', 'asc')).toEqual(['VF-10001', 'VF-10002', 'VF-10003', 'VF-10004', 'VF-10005']);
    expect(by('finding', 'desc')).toEqual(['VF-10005', 'VF-10004', 'VF-10003', 'VF-10002', 'VF-10001']);
    expect(by('host', 'asc')).toEqual(['VF-10001', 'VF-10004', 'VF-10002', 'VF-10003', 'VF-10005']); // case-insensitive, empty last
    expect(by('host', 'desc')).toEqual(['VF-10003', 'VF-10002', 'VF-10004', 'VF-10001', 'VF-10005']);
    expect(by('vulnerability', 'asc')).toEqual(['VF-10001', 'VF-10004', 'VF-10002', 'VF-10005', 'VF-10003']);
    expect(by('severity', 'desc')).toEqual(['VF-10001', 'VF-10003', 'VF-10002', 'VF-10004', 'VF-10005']); // Weird ranks below Info
    expect(by('severity', 'asc')).toEqual(['VF-10005', 'VF-10004', 'VF-10002', 'VF-10003', 'VF-10001']);
    expect(by('cvss', 'desc')).toEqual(['VF-10001', 'VF-10003', 'VF-10005', 'VF-10004', 'VF-10002']); // 7.5 tie by id, null last
    expect(by('cvss', 'asc')).toEqual(['VF-10004', 'VF-10003', 'VF-10005', 'VF-10001', 'VF-10002']); // null still last
    expect(by('firstSeen', 'asc')).toEqual(['VF-10005', 'VF-10001', 'VF-10003', 'VF-10004', 'VF-10002']);
    expect(by('firstSeen', 'desc')).toEqual(['VF-10003', 'VF-10004', 'VF-10001', 'VF-10005', 'VF-10002']);
  });

  it('is independent of the incoming order and idempotent', () => {
    for (const key of SORT_KEYS) {
      for (const dir of ['asc', 'desc'] as const) {
        const want = sortOrder(all, rows, { key, dir });
        for (let k = 0; k < 5; k++) expect(sortOrder(createRng(`s:${key}:${k}`).shuffle(all), rows, { key, dir })).toEqual(want);
        expect(sortOrder(want, rows, { key, dir })).toEqual(want);
      }
    }
  });

  it('labels: every button name starts with its visible header', () => {
    for (const key of SORT_KEYS) {
      for (const dir of ['asc', 'desc'] as const) {
        expect(sortButtonLabel(key, dir).startsWith(SORT_HEADERS[key])).toBe(true);
        expect(dirLabel(key, dir)).not.toBe('');
      }
    }
    expect(sortButtonLabel('severity', 'desc')).toBe('Severity (scanner): sort most severe first');
    expect(sortButtonLabel('cvss', 'desc')).toBe('CVSS: sort highest first');
    expect(sortMessage('cvss', 'desc')).toBe('Worklist sorted by CVSS, highest first. Undo sort restores your previous order.');
  });

  it('applySort reorders the draft, keeps the first undo snapshot and undoSort restores order and sort', () => {
    const d0: VulnDraft = { ...emptyDraft(all), order: [...all].reverse() };
    const a = applySort(d0, rows, 'cvss', null);
    expect(a.draft.sort).toEqual({ key: 'cvss', dir: 'desc' });
    expect(a.draft.order).toEqual(sortOrder(all, rows, { key: 'cvss', dir: 'desc' }));
    expect(a.undo).toEqual({ order: d0.order, sort: null });
    expect(a.message).toBe(sortMessage('cvss', 'desc'));
    const b = applySort(a.draft, rows, 'cvss', a.undo);
    expect(b.draft.sort).toEqual({ key: 'cvss', dir: 'asc' });
    expect(b.undo).toEqual({ order: d0.order, sort: null });
    const c = applySort(b.draft, rows, 'host', b.undo);
    expect(c.undo).toEqual({ order: d0.order, sort: null });
    const back = undoSort(c.draft, c.undo);
    expect(back.order).toEqual(d0.order);
    expect(back.sort).toBeNull();
    // the inputs are not mutated
    expect(d0.order).toEqual([...all].reverse());
  });

  it('formats CVSS and ranks severity', () => {
    expect(formatCvss(7)).toBe('7.0');
    expect(formatCvss(9.83)).toBe('9.8');
    expect(formatCvss(null)).toBe('no score');
    expect(['Critical', 'High', 'Medium', 'Low', 'Info', 'nope'].map(severityRank)).toEqual([4, 3, 2, 1, 0, -1]);
  });
});

describe('moving', () => {
  const o = ['a', 'b', 'c', 'd'];
  it('moveBy and moveTo clamp and report no-ops', () => {
    expect(moveBy(o, 'b', 1)).toEqual({ order: ['a', 'c', 'b', 'd'], from: 1, to: 2 });
    expect(moveBy(o, 'b', -1)).toEqual({ order: ['b', 'a', 'c', 'd'], from: 1, to: 0 });
    const top = moveBy(o, 'a', -1);
    expect(top).toMatchObject({ from: 0, to: 0 });
    expect(top.order).toBe(o);
    const bottom = moveBy(o, 'd', 1);
    expect(bottom).toMatchObject({ from: 3, to: 3 });
    expect(bottom.order).toBe(o);
    expect(moveTo(o, 'a', 99)).toEqual({ order: ['b', 'c', 'd', 'a'], from: 0, to: 3 });
    expect(moveTo(o, 'd', -5)).toEqual({ order: ['d', 'a', 'b', 'c'], from: 3, to: 0 });
    expect(moveTo(o, 'c', 2).order).toBe(o);
    expect(moveTo(o, 'zz', 1)).toMatchObject({ from: -1, to: -1 });
    expect(o).toEqual(['a', 'b', 'c', 'd']);
  });

  it('messages', () => {
    expect(positionMessage('VF-12345', 1, 6)).toBe('VF-12345 moved to position 2 of 6.');
    expect(boundsMessage('VF-12345', 'first')).toBe('VF-12345 is already first.');
    expect(boundsMessage('VF-12345', 'last')).toBe('VF-12345 is already last.');
  });
});

describe('reasons and labels', () => {
  it('toggleReason caps at 3, unchecks, ignores unknown codes', () => {
    let r: ReasonCode[] = [];
    for (const code of ['known-exploited', 'internet-exposed', 'critical-asset'] as const) {
      const t = toggleReason(r, code);
      expect(t.capped).toBe(false);
      r = t.reasons;
    }
    expect(r).toHaveLength(3);
    const over = toggleReason(r, 'sla-deadline');
    expect(over).toEqual({ reasons: r, capped: true });
    expect(toggleReason(r, 'internet-exposed')).toEqual({ reasons: ['known-exploited', 'critical-asset'], capped: false });
    expect(toggleReason(r, 'made-up' as ReasonCode)).toEqual({ reasons: r, capped: false });
    expect(toggleReason([], 'known-exploited', 1).reasons).toEqual(['known-exploited']);
  });

  it('the decision options gloss the two codes the labels leave unclear; the labels and codes stay', () => {
    expect(DECISION_OPTION_TEXT['false-positive']).toBe('False positive: not affected, fixed or a duplicate');
    expect(DECISION_OPTION_TEXT.transfer).toBe('Transfer: another party owns the fix');
    expect(DECISION_LABELS['false-positive']).toBe('False positive');
    expect(DECISION_LABELS.transfer).toBe('Transfer');
  });

  it('REASON_GROUPS partition REASON_CODES exactly', () => {
    const flat = REASON_GROUPS.flatMap((g) => g.codes);
    expect([...flat].sort()).toEqual([...REASON_CODES].sort());
    expect(new Set(flat).size).toBe(flat.length);
  });

  it('label tables are exhaustive', () => {
    expect(Object.keys(REASON_LABELS).sort()).toEqual([...REASON_CODES].sort());
    expect(Object.keys(DECISION_LABELS).sort()).toEqual([...VULN_DECISIONS].sort());
    expect(Object.keys(DECISION_OPTION_TEXT).sort()).toEqual(['', ...VULN_DECISIONS].sort());
    expect(Object.keys(SCHEDULE_LABELS).sort()).toEqual([...VULN_SCHEDULES].sort());
    for (const v of [...Object.values(REASON_LABELS), ...Object.values(DECISION_LABELS), ...Object.values(SCHEDULE_LABELS)]) expect(v.length).toBeGreaterThan(0);
  });
});

// A UI state that answers every finding the way a perfect analyst would.
function perfectDraft(c: ResolvedVulnCase): VulnDraft {
  const all = ids(c);
  const answers: Record<string, VulnFindingAnswer> = {};
  for (const f of c.findings) {
    answers[f.findingId] = {
      decision: f.truth.decision,
      control: f.truth.decision === 'mitigate' ? (f.truth.mitigation?.[0] ?? null) : null,
      schedule: f.truth.schedule,
      reasons: [...new Set(f.truth.reasons)].slice(0, 3),
    };
  }
  const rest = defaultOrder(all).filter((id) => !c.idealOrder.includes(id));
  const pins = [...new Set(c.findings.flatMap((f) => f.evidence.filter((e) => e.recordIds.length > 0).map((e) => e.recordIds[0])))];
  return { v: 1, order: [...c.idealOrder, ...rest], answers, pins, notes: '', hintsUsed: 0, sort: null };
}

describe('submission', () => {
  it('field names match VulnSubmission', () => {
    const c = built(VULN_TEMPLATES[0].id, 'wl0').case;
    const s: VulnSubmission = buildSubmission(perfectDraft(c));
    expect(Object.keys(s).sort()).toEqual(['answers', 'hintsUsed', 'notes', 'order', 'pins']);
    const a = Object.values(s.answers)[0];
    expect(Object.keys(a).sort()).toEqual(['control', 'decision', 'reasons', 'schedule']);
  });

  it('the perfect UI state grades 100 and an untouched draft grades 0, every template x 20 seeds', () => {
    for (const t of VULN_TEMPLATES) {
      for (const seed of SEEDS) {
        const c = built(t.id, seed).case;
        expect(gradeVulnCase(c, buildSubmission(perfectDraft(c))).percent, `${t.id}/${seed} perfect`).toBe(100);
        const empty = buildSubmission(emptyDraft(ids(c)));
        expect(empty.order).toEqual([]);
        expect(gradeVulnCase(c, empty).percent, `${t.id}/${seed} empty`).toBe(0);
        // same answers as the grader's own perfect submission
        expect(gradeVulnCase(c, perfectVulnSubmission(c)).percent).toBe(100);
      }
    }
  });

  it('the submitted order is the draft order, and gaps are listed in that order', () => {
    const c = built(VULN_TEMPLATES[0].id, 'wl1').case;
    const base = perfectDraft(c);
    for (const order of [[...defaultOrder(ids(c))].reverse(), [...ids(c)].reverse()]) {
      const d = { ...base, order };
      expect(buildSubmission(d).order).toEqual(order);
    }
    const reversed = [...defaultOrder(ids(c))].reverse();
    const d = { ...emptyDraft(ids(c)), order: reversed };
    expect(missingForSubmit(d, 0).map((m) => m.findingId)).toEqual(reversed.flatMap((id) => [id, id]));
  });

  it('leaves undecided findings out of the order, sends a control only for mitigate, and caps reasons at 3', () => {
    const d: VulnDraft = {
      ...emptyDraft(['A', 'B', 'C']),
      answers: {
        A: { decision: 'patch', control: 'CTL-1', schedule: 'next-window', reasons: ['known-exploited', 'internet-exposed', 'critical-asset', 'sla-deadline', 'known-exploited'] },
        B: { decision: null, control: null, schedule: 'none', reasons: [] },
        C: { decision: 'mitigate', control: 'CTL-2', schedule: null, reasons: [] },
      },
    };
    const s = buildSubmission(d);
    expect(s.order).toEqual(['A', 'C']);
    expect(s.answers.A).toEqual({ decision: 'patch', control: null, schedule: 'next-window', reasons: ['known-exploited', 'internet-exposed', 'critical-asset'] });
    expect(s.answers.C.control).toBe('CTL-2');
    expect(s.answers.B.schedule).toBe('none');
    // a control picked earlier is kept in the draft but not sent once the decision moved away
    expect(d.answers.A.control).toBe('CTL-1');
  });

  it('missingForSubmit asks for a control only with a non-empty inventory', () => {
    const d: VulnDraft = {
      ...emptyDraft(['A', 'B']),
      answers: {
        A: { decision: 'mitigate', control: null, schedule: 'next-window', reasons: [] },
        B: { decision: null, control: null, schedule: null, reasons: [] },
      },
    };
    expect(missingForSubmit(d, 0)).toEqual([
      { findingId: 'B', field: 'decision' },
      { findingId: 'B', field: 'schedule' },
    ]);
    expect(missingForSubmit(d, 2)).toEqual([
      { findingId: 'A', field: 'control' },
      { findingId: 'B', field: 'decision' },
      { findingId: 'B', field: 'schedule' },
    ]);
    expect(missingForSubmit(perfectDraft(built(VULN_TEMPLATES[0].id, 'wl2').case), 3)).toEqual([]);
  });

  it('stillNeededMessage: first three, then "and n more"', () => {
    const rows = new Map<string, WorklistRow>([['VF-1', { findingId: 'VF-1', recordId: 'r', host: 'APP01', vulnId: '', title: '', severity: '', cvss: null, firstSeen: '' }]]);
    const one = [{ findingId: 'VF-1', field: 'decision' as const }];
    expect(stillNeededMessage(one, rows)).toBe('Still needed: decision for VF-1 on APP01.');
    const three = [...one, { findingId: 'VF-1', field: 'schedule' as const }, { findingId: 'VF-1', field: 'control' as const }];
    expect(stillNeededMessage(three, rows)).toBe('Still needed: decision for VF-1 on APP01, schedule for VF-1 on APP01, control for VF-1 on APP01.');
    const five = [...three, ...three.slice(0, 2)];
    expect(stillNeededMessage(five, rows)).toBe('Still needed: decision for VF-1 on APP01, schedule for VF-1 on APP01, control for VF-1 on APP01 and 2 more.');
  });
});

describe('drafts', () => {
  const all = ['VF-2', 'VF-1', 'VF-3'];

  it('an empty draft is in default order', () => {
    expect(emptyDraft(all)).toEqual({ v: 1, order: ['VF-1', 'VF-2', 'VF-3'], answers: {}, pins: [], notes: '', hintsUsed: 0, sort: null });
  });

  it('restoreDraft turns garbage into an empty draft', () => {
    for (const raw of [null, undefined, 5, 'x', [], {}, { v: 2 }, { v: 1, order: 'no' }]) {
      const d = restoreDraft(raw, all, 3);
      expect(d.order).toEqual(['VF-1', 'VF-2', 'VF-3']);
      expect(d.answers).toEqual({});
    }
    expect(restoreDraft(JSON.parse('{"v":1,"order":"no","answers":[],"pins":7,"notes":5,"hintsUsed":"x","sort":"y"}'), all, 3)).toEqual(emptyDraft(all));
  });

  it('repairs unknown, missing and repeated ids', () => {
    const d = restoreDraft({ v: 1, order: ['VF-3', 'ZZ', 'VF-3', 'VF-2'], answers: { ZZ: { decision: 'patch' }, 'VF-3': { decision: 'patch', schedule: 'none' } } }, all, 0);
    expect(d.order).toEqual(['VF-3', 'VF-2', 'VF-1']);
    expect(Object.keys(d.answers)).toEqual(['VF-3']);
  });

  it('bad enums become null, reasons are filtered and capped, hints are clamped, bad sorts dropped', () => {
    const d = restoreDraft(
      {
        v: 1,
        order: all,
        answers: { 'VF-1': { decision: 'nuke', control: 5, schedule: 'soon', reasons: ['known-exploited', 'nope', 'known-exploited', 'internet-exposed', 'critical-asset', 'sla-deadline'] } },
        pins: ['a', 'a', 3, 'b'],
        notes: 'hello',
        hintsUsed: 99,
        sort: { key: 'cvss', dir: 'up' },
      },
      all,
      2,
    );
    expect(d.answers['VF-1']).toEqual({ decision: null, control: null, schedule: null, reasons: ['known-exploited', 'internet-exposed', 'critical-asset'] });
    expect(d.pins).toEqual(['a', 'b']);
    expect(d.notes).toBe('hello');
    expect(d.hintsUsed).toBe(2);
    expect(d.sort).toBeNull();
    expect(restoreDraft({ v: 1, hintsUsed: -4 }, all, 2).hintsUsed).toBe(0);
    expect(restoreDraft({ v: 1, hintsUsed: Number.NaN }, all, 2).hintsUsed).toBe(0);
    expect(restoreDraft({ v: 1, sort: { key: 'cvss', dir: 'asc' } }, all, 2).sort).toEqual({ key: 'cvss', dir: 'asc' });
  });

  it('round-trips through JSON', () => {
    const c = built(VULN_TEMPLATES[0].id, 'wl3').case;
    const d = { ...perfectDraft(c), notes: 'note', hintsUsed: 1, sort: { key: 'host' as const, dir: 'desc' as const } };
    expect(restoreDraft(JSON.parse(JSON.stringify(d)), ids(c), c.hints.length)).toEqual(d);
  });
});

describe('case view', () => {
  it('has exactly the six pre-submit keys and nothing of the answer key', () => {
    const c = built(VULN_TEMPLATES[0].id, 'wl0').case;
    const v = caseView(c);
    expect(Object.keys(v).sort()).toEqual(['attachments', 'briefing', 'difficulty', 'hints', 'now', 'title']);
    for (const k of ['id', 'templateId', 'twin', 'lesson', 'findings', 'idealOrder', 'tiers', 'rubric']) expect(k in v).toBe(false);
    // a copy: changing the view does not reach the case
    v.hints.push('x');
    expect(c.hints).not.toContain('x');
  });
});

describe('pin count', () => {
  it('counts pinned rows that mention the finding id, the vulnerability id or the host', () => {
    const row = { findingId: 'VF-1', vulnId: 'SIMVULN-2024-00001', host: 'APP01' };
    const pinned = [{ row: ['x', 'VF-1', 3] }, { row: ['SIMVULN-2024-00001'] }, { row: ['APP01', 'APP01'] }, { row: ['APP02', 'VF-10'] }, { row: [null, 7] }];
    expect(pinCount(row, pinned)).toBe(3);
    expect(pinCount({ findingId: 'VF-2', vulnId: '', host: 'DB01' }, [{ row: ['', 'DB01'] }, { row: [''] }])).toBe(1);
    expect(pinCount(row, [])).toBe(0);
  });
});

describe('pass mark', () => {
  it('is 70 and the study cards agree', () => {
    expect(VULN_PASS_PERCENT).toBe(70);
    expect(quality(VULN_PASS_PERCENT - 1)).toBeLessThan(3);
    expect(quality(VULN_PASS_PERCENT)).toBe(3);
  });
});

describe('case types', () => {
  const types = vulnCaseTypes(VULN_TEMPLATES);

  it('groups templates by title; the T3 twins share one type', () => {
    const t3 = types.find((t) => t.slug === 'scan-review-internal-servers')!;
    expect(t3.templates.map((t) => t.id).sort()).toEqual(['vm-kev-internal', 'vm-nokev-internal']);
    expect(new Set(VULN_TEMPLATES.map((t) => t.title)).size).toBe(types.length);
    expect(types.flatMap((t) => t.templates)).toHaveLength(VULN_TEMPLATES.length);
    expect(new Set(types.map((t) => t.slug)).size).toBe(types.length);
  });

  it('twins share their difficulty and every registered difficulty appears', () => {
    for (const t of types) for (const x of t.templates) expect(x.difficulty).toBe(t.difficulty);
    expect(new Set(types.map((t) => t.difficulty))).toEqual(new Set(VULN_TEMPLATES.map((t) => t.difficulty)));
    const tiers = types.map((t) => t.difficulty);
    expect(tiers).toEqual([...tiers].sort());
    for (const t of types) {
      expect(t.cysaDomains).toEqual([...t.cysaDomains].sort());
      expect(t.objectives).toEqual([...t.objectives].sort());
    }
  });

  it('resolveVulnTemplate is deterministic and reaches both twins', () => {
    const t3 = types.find((t) => t.templates.length === 2)!;
    const seen = new Set<string>();
    for (let i = 0; i < 40; i++) {
      const a = resolveVulnTemplate(t3, `s${i}`);
      expect(resolveVulnTemplate(t3, `s${i}`)).toBe(a);
      seen.add(a.id);
    }
    expect(seen.size).toBe(2);
    // A one-template type is built from a one-element list: the registry no longer holds one.
    const single = vulnCaseTypes([VULN_TEMPLATES[0]])[0];
    expect(single.templates).toHaveLength(1);
    expect(resolveVulnTemplate(single, 'any')).toBe(single.templates[0]);
  });

  it('every registered case type is a twin pair', () => {
    for (const t of types) expect(t.templates, t.slug).toHaveLength(2);
  });
});

describe('tables per mode', () => {
  it('the six vulnerability tables are the ones after IncidentHistory, all context tables', () => {
    const after = TABLE_NAMES.slice(TABLE_NAMES.indexOf('IncidentHistory') + 1);
    expect([...VULN_TABLE_NAMES]).toEqual(after);
    for (const n of VULN_TABLE_NAMES) {
      expect(isVulnTable(n)).toBe(true);
      expect(TABLES.find((t) => t.name === n)!.kind).toBe('context');
    }
    expect(isVulnTable('SigninLogs')).toBe(false);
  });

  it('tablesFor soc is TABLES minus the six, in order; vuln is all of them', () => {
    expect(tablesFor('soc').map((t) => t.name)).toEqual(TABLE_NAMES.filter((n) => !isVulnTable(n)));
    expect(tablesFor('soc')).toHaveLength(18);
    expect(tablesFor('vuln')).toEqual(TABLES);
  });
});
