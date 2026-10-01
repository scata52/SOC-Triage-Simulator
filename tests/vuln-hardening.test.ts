// WP1f hardening: the four strategies of DESIGN 5.8 run over every vuln template
// x the standard 20 runs, with the real grader. They define "done" for the
// grading rules: a table-blind shotgun must fail, getting only the lesson
// finding wrong must fail, the ideal answer must clear 90, and the lesson right
// with minor slips must pass. Perfect stays 100 and empty stays 0.
//
// The strategies are the ones the WP1f probe harness measured (ADR-22); a new
// template only has to be registered to be held to them.

import { describe, expect, it } from 'vitest';
import type { Corpus } from '../src/core/logs/corpus.ts';
import { DAY } from '../src/core/logs/time.ts';
import { emptyVulnSubmission, gradeVulnCase, perfectVulnSubmission, type VulnFindingAnswer, type VulnGrade, type VulnSubmission } from '../src/core/vuln/grade.ts';
import { REASON_CODES, VULN_SCHEDULES, type VulnSchedule, type VulnTemplate } from '../src/core/vuln/model.ts';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import type { ResolvedVulnCase, ResolvedVulnFinding } from '../src/core/vuln/scenario.ts';
import { endOfDay, slaClassOf } from '../src/core/vuln/templates/common.ts';
import { world } from './helpers/scenario-check.ts';
import { buildFor, vulnRuns } from './helpers/vuln-scenario-check.ts';

const RUNS = vulnRuns(20, 20);
const SCHEDULE_OPTIONS: VulnSchedule[] = ['emergency', 'next-window', 'standard-cycle'];
const VULN_TABLES = ['VulnFindings', 'ScanRuns', 'VulnIntel', 'SoftwareInventory', 'PatchHistory', 'ControlInventory', 'DeviceInfo'];

type Row = Record<string, unknown>;

interface Side {
  c: ResolvedVulnCase;
  corpus: Corpus;
  work: { f: ResolvedVulnFinding; row: Row }[]; // case findings with their VulnFindings row
  rowOf: Map<string, Row>;
}

interface Run extends Side {
  label: string;
  template: VulnTemplate;
  twin: Side | null; // the twin template's case, same world and seed
}

// ---- building (each case once) --------------------------------------------------

const sides = new Map<string, Side>();
function side(template: VulnTemplate, worldSeed: string, seed: string): Side {
  const key = `${template.id}|${worldSeed}|${seed}`;
  let s = sides.get(key);
  if (!s) {
    const built = buildFor(template, world(worldSeed), seed);
    const t = built.corpus.tables.VulnFindings;
    const rows = new Map(t.rows.map((r) => [String(r[t.columns.indexOf('RecordId')]), Object.fromEntries(t.columns.map((col, i) => [col, r[i]])) as Row]));
    const work = built.case.findings.map((f) => ({ f, row: rows.get(f.recordId)! }));
    s = { c: built.case, corpus: built.corpus, work, rowOf: new Map(work.map((x) => [x.f.findingId, x.row])) };
    sides.set(key, s);
  }
  return s;
}

const twinOf = (t: VulnTemplate): VulnTemplate | undefined => (t.twin ? VULN_TEMPLATES.find((x) => x.id === t.twin) : undefined);

function runsOf(t: VulnTemplate): Run[] {
  const twin = twinOf(t);
  return RUNS.map((r) => ({ ...side(t, r.world, r.seed), label: `${t.id} ${r.world}/${r.seed}`, template: t, twin: twin ? side(twin, r.world, r.seed) : null }));
}

// ---- helpers -------------------------------------------------------------------------

const ms = (v: unknown) => Date.parse(String(v));
const clone = (s: VulnSubmission): VulnSubmission => JSON.parse(JSON.stringify(s)) as VulnSubmission;
const uniq = <T>(xs: T[]) => [...new Set(xs)];
const required = (f: ResolvedVulnFinding) => uniq(f.truth.reasons);

function recordIds(corpus: Corpus, tables?: string[]): string[] {
  return Object.entries(corpus.tables)
    .filter(([name]) => !tables || tables.includes(name))
    .flatMap(([, t]) => t.rows.map((r) => String(r[t.columns.indexOf('RecordId')])));
}

// The SLA table alone (CVSS class counted from first detection, no Sim-KEV rule), as a table-blind analyst reads it.
const tableDeadline = (v: Side, row: Row): number => endOfDay(ms(row.FirstSeen) + v.c.constraints.slaDays[slaClassOf(Number(row.CvssBase))] * DAY);
function tableSchedule(v: Side, row: Row): VulnSchedule {
  const deadline = tableDeadline(v, row);
  const ends = [...v.c.constraints.windows].sort((a, b) => a.start - b.start).map((w) => w.end);
  let latest: VulnSchedule = 'emergency';
  ends.slice(0, 2).forEach((end, i) => {
    if (end <= deadline) latest = SCHEDULE_OPTIONS[i + 1];
  });
  return latest;
}

// Key findings (DESIGN 5.8): the lesson findings and the must-not-miss findings, read from the case data.
const lessonsOf = (v: Side): ResolvedVulnFinding[] => v.c.findings.filter((f) => f.lesson);
const keyIds = (v: Side): Set<string> => new Set(v.c.findings.filter((f) => f.lesson || f.mustNotMiss).map((f) => f.findingId));

// Drop `remove` from the pins, then re-pin (with a row outside `remove`) any point `keep` says must stay found.
function unpin(c: ResolvedVulnCase, pins: string[], remove: Set<string>, keep: (f: ResolvedVulnFinding, e: ResolvedVulnFinding['evidence'][number]) => boolean): string[] {
  const out = pins.filter((p) => !remove.has(p));
  const set = new Set(out);
  for (const f of c.findings) {
    for (const e of f.evidence) {
      if (!keep(f, e) || e.recordIds.some((id) => set.has(id))) continue;
      const alt = e.recordIds.find((id) => !remove.has(id));
      if (alt) {
        out.push(alt);
        set.add(alt);
      }
    }
  }
  return out;
}

function moveTo(order: string[], id: string, place: number | null): string[] {
  const rest = order.filter((x) => x !== id);
  if (place !== null) rest.splice(Math.min(place, rest.length), 0, id);
  return rest;
}

// ---- the strategies --------------------------------------------------------------------

interface Strategy {
  group: string; // 'S1', 'S2/<place of the lesson finding>', 'S3', 'S4', 'PERFECT' or 'EMPTY'
  name: string;
  build: () => VulnSubmission;
  check?: (g: VulnGrade) => string | null; // a property of the grade the strategy itself relies on
}

function strategies(v: Run): Strategy[] {
  const c = v.c;
  const out: Strategy[] = [];
  const perfect = () => clone(perfectVulnSubmission(c));
  type Item = Side['work'][number];
  const byScore = [...v.work].sort((a, b) => Number(b.row.CvssBase) - Number(a.row.CvssBase));
  const rank = (s: unknown) => ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(String(s));
  const bySeverity = [...v.work].sort((a, b) => rank(a.row.Severity) - rank(b.row.Severity) || Number(b.row.CvssBase) - Number(a.row.CvssBase));
  const byDeadline = [...bySeverity].sort((a, b) => tableDeadline(v, a.row) - tableDeadline(v, b.row));
  const everyRecord = recordIds(v.corpus);
  const vulnRecords = recordIds(v.corpus, [...VULN_TABLES]);
  const submit = (order: Item[], decision: VulnFindingAnswer['decision'], schedule: (i: Item) => VulnSchedule, reasons: string[], pins: string[]): VulnSubmission => ({
    answers: Object.fromEntries(v.work.map((i) => [i.f.findingId, { decision, control: null, schedule: schedule(i), reasons: [...reasons] as VulnFindingAnswer['reasons'] }])),
    order: order.map((i) => i.f.findingId),
    pins: [...pins],
    notes: '',
    hintsUsed: 0,
  });

  // S1 shotgun: patch everything, the SLA-table schedule, every reason code or the common spam, every row pinned.
  const counts = new Map<string, number>();
  for (const f of c.findings) for (const r of required(f)) counts.set(r, (counts.get(r) ?? 0) + 1);
  const mostRequired = [...counts].sort((a, b) => b[1] - a[1] || REASON_CODES.indexOf(a[0] as (typeof REASON_CODES)[number]) - REASON_CODES.indexOf(b[0] as (typeof REASON_CODES)[number])).slice(0, 3).map(([r]) => r);
  const reasonSets: [string, string[]][] = [['all codes', [...REASON_CODES]], ['spam set', ['low-exploitability', 'stale-scan', 'sla-deadline']], ['three most required', mostRequired]];
  const orders: [string, Item[]][] = [['by deadline', byDeadline], ['by CVSS', byScore]];
  const pinSets: [string, string[]][] = [['every row', everyRecord], ['vuln tables', vulnRecords]];
  for (const [rn, rs] of reasonSets) {
    for (const [on, o] of orders) {
      for (const [pn, ps] of pinSets) out.push({ group: 'S1', name: `shotgun: ${rn}, ${on}, ${pn}`, build: () => submit(o, 'patch', (i) => tableSchedule(v, i.row), rs, ps) });
    }
  }

  // S2 only one lesson finding wrong, for each lesson finding in turn: the targeted misconception. In a twin pair the
  // headline (findings[0]) gets the twin's truth and place in the order; any other lesson finding is flipped: a false
  // positive is trusted (patch at the SLA-table schedule, placed by its table deadline) and a real finding is
  // dismissed as a false positive and left out of the order.
  type Misconception = { decision: VulnFindingAnswer['decision']; control: string | null; schedule: VulnSchedule; reasons: string[]; place: number | null; what: string };
  const base = perfect().order;
  for (const L of lessonsOf(v)) {
    const lessonRows = new Set(L.evidence.flatMap((e) => e.recordIds));
    const at = c.findings.indexOf(L);
    let mis: Misconception;
    if (v.twin && at === 0) {
      const tf = v.twin.c.findings[0];
      const t = tf.truth;
      const pos = v.twin.c.idealOrder.indexOf(tf.findingId);
      mis = { decision: t.decision, control: t.decision === 'mitigate' ? (t.mitigation?.[0] ?? null) : null, schedule: t.schedule, reasons: required(tf).slice(0, 3), place: pos < 0 ? null : pos, what: `the twin's answer (${v.twin.c.templateId})` };
    } else if (L.truth.decision === 'false-positive') {
      // Trust the scanner: patch at the SLA-table schedule, placed by the table deadline.
      const row = v.rowOf.get(L.findingId)!;
      const dl = tableDeadline(v, row);
      const rest = base.filter((id) => id !== L.findingId);
      const place = rest.findIndex((id) => tableDeadline(v, v.rowOf.get(id)!) > dl);
      mis = { decision: 'patch', control: null, schedule: tableSchedule(v, row), reasons: ['sla-deadline'], place: place < 0 ? rest.length : place, what: 'trust a false positive' };
    } else {
      // Dismiss a real finding: false positive, no change, left out of the order.
      mis = { decision: 'false-positive', control: null, schedule: 'none', reasons: ['stale-scan'], place: null, what: 'dismiss a real finding' };
    }
    const s2Reasons: [string, string[]][] = [['misconception reasons', mis.reasons], ['true reasons', required(L).slice(0, 3)], ['no reasons', []]];
    for (const [rn, rs] of s2Reasons) {
      for (const pn of ['perfect pins', 'pins without the lesson evidence']) {
        out.push({
          group: `S2/${at}`,
          name: `lesson finding ${at} wrong, ${mis.what}, ${rn}, ${pn}`,
          build: () => {
            const s = perfect();
            s.answers[L.findingId] = { decision: mis.decision, control: mis.control as VulnFindingAnswer['control'], schedule: mis.schedule, reasons: [...rs] as VulnFindingAnswer['reasons'] };
            s.order = moveTo(s.order, L.findingId, mis.place);
            if (pn !== 'perfect pins') s.pins = unpin(c, s.pins, lessonRows, (f) => f.findingId !== L.findingId);
            return s;
          },
        });
      }
    }
  }

  // S3 ideal: every row of every evidence point plus each finding's own scan row.
  out.push({
    group: 'S3',
    name: 'ideal, every evidence row and every own scan row pinned',
    build: () => {
      const s = perfect();
      s.pins = uniq([...c.findings.flatMap((f) => f.evidence.flatMap((e) => e.recordIds)), ...c.findings.map((f) => f.recordId)]);
      return s;
    },
  });
  out.push({ group: 'PERFECT', name: 'perfect', build: perfect });
  out.push({ group: 'EMPTY', name: 'empty', build: () => clone(emptyVulnSubmission()) });

  // S4 lesson right: key findings perfect, minor slips on the others, all that apply at once.
  const key = keyIds(v);
  const nonKey = c.findings.filter((f) => !key.has(f.findingId));
  const steps: ((s: VulnSubmission) => void)[] = [];
  const a = nonKey.find((f) => f.truth.schedule !== 'emergency'); // one step earlier
  if (a) {
    const earlier = VULN_SCHEDULES[VULN_SCHEDULES.indexOf(a.truth.schedule) - 1];
    steps.push((s) => void (s.answers[a.findingId].schedule = earlier));
  }
  const b = nonKey.find((f) => required(f).length > 0); // one required code dropped
  if (b) {
    const drop = required(b).slice(0, 3).at(-1);
    steps.push((s) => void (s.answers[b.findingId].reasons = s.answers[b.findingId].reasons.filter((r) => r !== drop)));
  }
  const cf = nonKey.find((f) => f.evidence.length > 0); // one evidence point unpinned
  if (cf) {
    const point = cf.evidence[0];
    steps.push((s) => void (s.pins = unpin(c, s.pins, new Set(point.recordIds), (_f, e) => e !== point)));
  }
  const order0 = perfect().order; // two adjacent other findings swapped
  const d = order0.findIndex((id, i) => i + 1 < order0.length && !key.has(id) && !key.has(order0[i + 1]));
  if (d >= 0) {
    steps.push((s) => {
      const i = s.order.indexOf(order0[d]);
      const j = s.order.indexOf(order0[d + 1]);
      [s.order[i], s.order[j]] = [s.order[j], s.order[i]];
    });
  }
  steps.push((s) => void (s.hintsUsed = 1)); // one hint
  // Two pins that are neither evidence rows nor any finding's own scan row (those are never irrelevant).
  const relevant = new Set([...c.findings.flatMap((f) => f.evidence.flatMap((e) => e.recordIds)), ...c.findings.map((f) => f.recordId)]);
  const extra = recordIds(v.corpus).filter((id) => !relevant.has(id));
  steps.push((s) => void (s.pins = [...s.pins, ...extra.filter((id) => !s.pins.includes(id)).slice(0, 2)])); // two irrelevant pins
  out.push({
    group: 'S4',
    name: 'lesson right with minor slips',
    build: () => {
      const s = perfect();
      for (const step of steps) step(s);
      return s;
    },
    check: (g) => (g.irrelevantPins === 2 ? null : `slip (f) pinned ${g.irrelevantPins} irrelevant rows, expected 2`),
  });
  return out;
}

// ---- measuring ---------------------------------------------------------------------------

interface Extreme {
  min: number;
  max: number;
  atMin: string;
  atMax: string;
}

interface Measured {
  groups: Record<string, Extreme>;
  problems: string[]; // a strategy's own check failed
}

const measured = new Map<string, Measured>();
function measure(t: VulnTemplate): Measured {
  const cached = measured.get(t.id);
  if (cached) return cached;
  const result: Measured = { groups: {}, problems: [] };
  for (const v of runsOf(t)) {
    for (const st of strategies(v)) {
      const g = gradeVulnCase(v.c, st.build());
      const where = `${st.name} @ ${v.label}`;
      const e = (result.groups[st.group] ??= { min: Infinity, max: -Infinity, atMin: '', atMax: '' });
      if (g.score < e.min) [e.min, e.atMin] = [g.score, where];
      if (g.score > e.max) [e.max, e.atMax] = [g.score, where];
      const problem = st.check?.(g);
      if (problem) result.problems.push(`${where}: ${problem}`);
    }
  }
  measured.set(t.id, result);
  return result;
}

// The groups of one strategy ('S2' has one per lesson finding), as [group, extremes].
const groupsOf = (m: Measured, prefix: string): [string, Extreme][] => Object.entries(m.groups).filter(([k]) => k === prefix || k.startsWith(`${prefix}/`));

const TEMPLATES: readonly VulnTemplate[] = VULN_TEMPLATES;
const SLOW = 180_000;

describe('every template is held to the WP1f strategies', () => {
  it('has templates to hold', () => {
    expect(TEMPLATES.length).toBeGreaterThanOrEqual(3);
  });

  // Opt-in numbers per template (VULN_HARDENING_REPORT=1): S1 max, S2 max per lesson finding, S3 min, S4 min, as percents.
  it.skipIf(!process.env.VULN_HARDENING_REPORT)('reports the extremes per template', { timeout: SLOW * TEMPLATES.length }, () => {
    for (const t of TEMPLATES) {
      const m = measure(t);
      const pct = (r: Extreme, which: 'min' | 'max') => `${Math.round(r[which])} (${r[which]})`;
      const s2 = groupsOf(m, 'S2').map(([k, r]) => `${k}=${pct(r, 'max')}`).join(' ');
      console.log(`${t.id}: S1max ${pct(m.groups.S1, 'max')}; S2max ${s2}; S3min ${m.groups.S3.min}; S4min ${pct(m.groups.S4, 'min')}`);
    }
  });

  describe.each(TEMPLATES.map((t) => [t.id, t] as const))('%s', (_id, t) => {
    // Bounds 1, 2 and 4 are checked on the percent the pass decision uses, Math.round(score); rounding is monotone,
    // so rounding the extreme is the extreme of the rounded scores.
    it('S1: the table-blind shotgun fails (percent < 70, the best of its variants)', { timeout: SLOW }, () => {
      for (const [k, r] of groupsOf(measure(t), 'S1')) expect(Math.round(r.max), `${k}: ${r.atMax}`).toBeLessThan(70);
    });

    it('S2: getting only one lesson finding wrong fails, for each lesson finding (percent < 70, the best of its variants)', { timeout: SLOW }, () => {
      const m = measure(t);
      const groups = groupsOf(m, 'S2');
      expect(groups.length, 'one S2 group per lesson finding').toBe(runsOf(t)[0].c.findings.filter((f) => f.lesson).length);
      for (const [k, r] of groups) expect(Math.round(r.max), `${k}: ${r.atMax}`).toBeLessThan(70);
    });

    it('S3: the ideal answer scores at least 90, even pinning every evidence row and every own scan row', { timeout: SLOW }, () => {
      for (const [k, r] of groupsOf(measure(t), 'S3')) expect(r.min, `${k}: ${r.atMin}`).toBeGreaterThanOrEqual(90);
    });

    it('S4: the lesson right with minor slips still passes (percent >= 70), and slip (f) pins exactly two irrelevant rows', { timeout: SLOW }, () => {
      const m = measure(t);
      expect(m.problems).toEqual([]);
      for (const [k, r] of groupsOf(m, 'S4')) expect(Math.round(r.min), `${k}: ${r.atMin}`).toBeGreaterThanOrEqual(70);
    });

    it('keeps perfect = 100 and empty = 0', { timeout: SLOW }, () => {
      const m = measure(t).groups;
      expect([m.PERFECT.min, m.PERFECT.max], m.PERFECT.atMin).toEqual([100, 100]);
      expect(m.EMPTY.max, m.EMPTY.atMax).toBe(0);
    });
  });
});

describe('every case names its lesson findings', () => {
  it.each(TEMPLATES.map((t) => [t.id, t] as const))('%s: a lesson finding, an SLA on every real key finding, and an evidence point', { timeout: SLOW }, (_id, t) => {
    for (const v of runsOf(t)) {
      const lessons = v.c.findings.filter((f) => f.lesson);
      expect(lessons.length, `${v.label}: lesson findings`).toBeGreaterThanOrEqual(1);
      expect(lessons.length, `${v.label}: lesson findings stay few`).toBeLessThanOrEqual(3);
      for (const f of v.c.findings.filter((x) => x.lesson || x.mustNotMiss)) {
        if (f.truth.decision !== 'false-positive') expect(f.truth.slaLatest, `${v.label}: ${f.findingId} slaLatest`).toBeDefined();
      }
      expect(v.c.findings.some((f) => f.evidence.length > 0), `${v.label}: evidence point`).toBe(true);
    }
  });

  it('puts a lesson finding of a twin pair first, on the same vulnerability in both twins', { timeout: SLOW }, () => {
    for (const t of TEMPLATES) {
      const twin = twinOf(t);
      if (!twin) continue;
      expect(twin.twin, `${t.id} and ${twin.id} name each other`).toBe(t.id);
      for (const r of RUNS) {
        const a = side(t, r.world, r.seed);
        const b = side(twin, r.world, r.seed);
        const label = `${t.id} / ${twin.id} ${r.world}/${r.seed}`;
        expect(a.c.findings[0].lesson, `${label}: ${t.id} findings[0] is the lesson finding`).toBe(true);
        expect(b.c.findings[0].lesson, `${label}: ${twin.id} findings[0] is the lesson finding`).toBe(true);
        expect(String(a.rowOf.get(a.c.findings[0].findingId)!.VulnId), `${label}: shared VulnId`).toBe(String(b.rowOf.get(b.c.findings[0].findingId)!.VulnId));
      }
    }
  });
});
