// Data rules every vulnerability-management template must satisfy on every seed
// (WP1d review #1): class/vector coherence, honest background noise, dates that
// do not predate what they refer to, derivable deadlines, contradicting codes,
// weights, naive-strategy resistance and twin symmetry. The tests run over the
// 20 seeds of every template in VULN_CASE_TEMPLATES, so a new template only has
// to be registered to be held to them.
import { describe, expect, it } from 'vitest';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { readdirSync, readFileSync } from 'node:fs';
import { DAY } from '../../src/core/logs/time.ts';
import { generateCatalogue, SIM_EPSS_ALL, simEpssScoreAt } from '../../src/core/vuln/catalogue.ts';
import { baseScore, severityOf } from '../../src/core/vuln/cvss31.ts';
import { gradeVulnCase, type VulnSubmission } from '../../src/core/vuln/grade.ts';
import { VULN_SCHEDULES, type ReasonCode, type VulnSchedule, type VulnTemplate } from '../../src/core/vuln/model.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import { AGENT_COMPONENTS, AUTH_FAILURE_TITLE, classOfTitle, endOfDay, isAgentProduct, KEV_SLA_DAYS, PRODUCT_KINDS, shapeTitle, shapesFor, slaClassOf, vectorProblem, WORKLIST_SHAPES, type ProductKind, type ShapeWant } from '../../src/core/vuln/templates/common.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

type RowObject = Record<string, unknown>;

// VULN_DATA_RUNS=1000 sweeps a thousand seeds (slow); the default is the 20 seeds every template is held to.
const N = Number(process.env.VULN_DATA_RUNS ?? 20);
const RUNS = N === 20 ? vulnRuns(20, 20) : Array.from({ length: N }, (_, i) => ({ world: `probe-world-${i % 20}`, seed: `pv${i}`, db: false }));
const TEMPLATES: readonly VulnTemplate[] = VULN_CASE_TEMPLATES;
const OPTIONS: readonly VulnSchedule[] = ['emergency', 'next-window', 'standard-cycle'];
const SIMVULN = /SIMVULN-\d{4}-\d{5}/g;

const ms = (v: unknown): number => Date.parse(String(v));
const flag = (v: unknown): boolean => v === true || v === 1;

function rows(corpus: Corpus, table: keyof Corpus['tables']): RowObject[] {
  const t = corpus.tables[table];
  return t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])) as RowObject);
}

type Built = ReturnType<typeof buildFor>;
interface View {
  label: string;
  now: number;
  run: (typeof RUNS)[number];
  c: Built['case'];
  corpus: Corpus;
  vulnFindings: RowObject[];
  work: { f: Built['case']['findings'][number]; row: RowObject }[];
  isWork: (row: RowObject) => boolean;
  intel: Map<string, RowObject>;
  runs: Map<string, RowObject>;
  latestRun: string;
}

const cache = new Map<string, View>();
function view(t: VulnTemplate, run: (typeof RUNS)[number]): View {
  const key = `${t.id}|${run.world}|${run.seed}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const built = buildFor(t, world(run.world), run.seed);
  const { corpus, case: c } = built;
  const vulnFindings = rows(corpus, 'VulnFindings');
  const byRecord = new Map(vulnFindings.map((r) => [String(r.RecordId), r]));
  const workIds = new Set(c.findings.map((f) => f.recordId));
  const runs = new Map(rows(corpus, 'ScanRuns').map((r) => [String(r.ScanRunId), r]));
  const v: View = {
    label: `${t.id} ${run.world}/${run.seed}`,
    now: ms(built.now),
    run,
    c,
    corpus,
    vulnFindings,
    work: c.findings.map((f) => ({ f, row: byRecord.get(f.recordId)! })),
    isWork: (r) => workIds.has(String(r.RecordId)),
    intel: new Map(rows(corpus, 'VulnIntel').map((r) => [String(r.VulnId), r])),
    runs,
    latestRun: String([...runs.values()].sort((a, b) => ms(b.Started) - ms(a.Started))[0].ScanRunId),
  };
  cache.set(key, v);
  return v;
}

// The latest option whose window ends by the deadline (emergency always does), and the window ends.
function slaOf(v: View, deadline: number): { latest: VulnSchedule; ends: number[] } {
  const ends = [...v.c.constraints.windows].sort((a, b) => a.start - b.start).map((w) => w.end);
  let latest: VulnSchedule = 'emergency';
  ends.slice(0, 2).forEach((end, i) => {
    if (end <= deadline) latest = OPTIONS[i + 1];
  });
  return { latest, ends };
}

// The deadline of a worklist finding: the Sim-KEV rule when listed, else the SLA of its CVSS class.
function deadlineOf(v: View, row: RowObject): number {
  const intel = v.intel.get(String(row.VulnId))!;
  const first = ms(row.FirstSeen);
  if (flag(intel.KnownExploited)) return endOfDay(Math.max(first, ms(intel.KnownExploitedAdded)) + KEV_SLA_DAYS * DAY);
  return endOfDay(first + v.c.constraints.slaDays[slaClassOf(Number(row.CvssBase))] * DAY);
}

// The SLA table alone (no Sim-KEV rule), as a table-blind analyst reads it.
const tableDeadline = (v: View, row: RowObject): number => endOfDay(ms(row.FirstSeen) + v.c.constraints.slaDays[slaClassOf(Number(row.CvssBase))] * DAY);

describe.each(TEMPLATES.map((t) => [t.id, t] as const))('%s data rules', (_id, t) => {
  const each = (fn: (v: View) => void) => {
    for (const run of RUNS) fn(view(t, run));
  };

  it('C1: every worklist title names a class its vector allows', () => {
    each((v) => {
      for (const { row } of v.work) {
        const title = String(row.Title);
        const cls = classOfTitle(title);
        expect(cls, `${v.label}: "${title}" names a vulnerability class`).not.toBeNull();
        const vector = String(v.intel.get(String(row.VulnId))!.CvssVector);
        expect(vectorProblem(vector, cls!, title), `${v.label}: "${title}" with ${vector}`).toBeNull();
      }
    });
  });

  it('C15: no worklist finding is a configuration weakness (it is fixed by a change of configuration, which no decision grades honestly), and its component fits its vector', () => {
    each((v) => {
      for (const { row } of v.work) {
        const title = String(row.Title);
        expect(classOfTitle(title), `${v.label}: "${title}"`).not.toBe('misconfig');
      }
    });
  });

  it('C17: every worklist row is one entry of the shape table for its product kind (class, component and vector agree with the product it is placed on)', () => {
    const products = Object.keys(PRODUCT_KINDS);
    each((v) => {
      for (const { row } of v.work) {
        const title = String(row.Title);
        const at = `${v.label}: "${title}"`;
        const product = products.find((p) => title.includes(` in ${p} `));
        expect(product, `${at}: names a known product`).toBeDefined();
        const kind = PRODUCT_KINDS[product!];
        const cls = classOfTitle(title)!;
        const vector = String(v.intel.get(String(row.VulnId))!.CvssVector);
        expect(vector, `${at}: never a physical vector`).not.toContain('AV:P');
        const match = WORKLIST_SHAPES.some((sh) => sh.productKind === kind && sh.vulnClass === cls && sh.vector === vector && shapeTitle(sh, product!) === title);
        expect(match, `${at}: no ${kind} shape has class ${cls}, this component and ${vector}`).toBe(true);
      }
    });
  });

  it('C16: an agent product in the background has an agent component, and agent products are under half of the background vulnerability rows', () => {
    const agentComponents = new Set(Object.values(AGENT_COMPONENTS).flat());
    each((v) => {
      const products = [...new Set(rows(v.corpus, 'SoftwareInventory').map((r) => String(r.Product)))];
      const background = v.vulnFindings.filter((r) => !v.isWork(r) && String(r.VulnId) !== '');
      let agents = 0;
      for (const r of background) {
        const title = String(r.Title);
        const product = products.find((p) => title.includes(` in ${p} `));
        if (!product || !isAgentProduct(product)) continue;
        agents++;
        const component = title.slice(title.indexOf(` in ${product} `) + ` in ${product} `.length);
        expect(agentComponents.has(component), `${v.label}: "${title}" is a web component on an agent`).toBe(true);
      }
      expect(agents * 2, `${v.label}: ${agents} agent rows of ${background.length}`).toBeLessThan(Math.max(1, background.length));
    });
  });

  it('C2: background rows cannot pass for worklist items and keep the runs apart', () => {
    each((v) => {
      const background = v.vulnFindings.filter((r) => !v.isWork(r));
      for (const r of background) {
        if (String(r.VulnId) === '') continue;
        const i = v.intel.get(String(r.VulnId))!;
        const at = `${v.label}: background ${String(r.FindingId)} (${String(r.VulnId)})`;
        expect(Number(i.CvssBase), `${at}: below High`).toBeLessThan(7);
        expect(['High', 'Critical'], `${at}: scanner severity`).not.toContain(String(r.Severity));
        expect(flag(i.KnownExploited), `${at}: not on Sim-KEV`).toBe(false);
        expect(Number(i.ExploitProbability), `${at}: Sim-EPSS`).toBeLessThan(0.02);
        expect(flag(i.PublicExploit), `${at}: no public exploit`).toBe(false);
        expect(flag(i.VendorFix), `${at}: vendor fix`).toBe(true);
        expect(ms(i.Published), `${at}: published before its run started`).toBeLessThanOrEqual(ms(v.runs.get(String(r.ScanRunId))!.Started));
      }
      // No product repeats on a host: a background row never shares a product with a worklist finding there.
      for (const sw of rows(v.corpus, 'SoftwareInventory')) {
        const same = v.vulnFindings.filter((r) => r.DeviceName === sw.DeviceName && String(r.VulnId) !== '' && String(r.Title).includes(` in ${String(sw.Product)} `));
        expect(same.length, `${v.label}: ${String(sw.Product)} on ${String(sw.DeviceName)} has ${same.length} findings`).toBeLessThanOrEqual(1);
      }
      // Old and new runs: disjoint background host lists (a login-failure row is not background).
      const hostsByRun = new Map<string, Set<string>>();
      for (const r of background.filter((x) => String(x.Title) !== AUTH_FAILURE_TITLE)) {
        const set = hostsByRun.get(String(r.ScanRunId)) ?? new Set<string>();
        set.add(String(r.DeviceName));
        hostsByRun.set(String(r.ScanRunId), set);
      }
      const lists = [...hostsByRun.entries()];
      for (let a = 0; a < lists.length; a++)
        for (let b = a + 1; b < lists.length; b++) {
          const shared = [...lists[a][1]].filter((h) => lists[b][1].has(h));
          expect(shared, `${v.label}: background hosts of ${lists[a][0]} and ${lists[b][0]} are disjoint`).toEqual([]);
        }
      // A host whose worklist finding is from an older run (and so not re-tested) has no background row.
      for (const { row } of v.work) {
        if (row.ScanRunId === v.latestRun) continue;
        const noise = background.filter((r) => r.DeviceName === row.DeviceName && String(r.Title) !== AUTH_FAILURE_TITLE);
        expect(noise.length, `${v.label}: ${String(row.DeviceName)} (older-run finding) has no background rows`).toBe(0);
      }
    });
  });

  it('C1b: every background row also names a class its vector allows, and hygiene rows fit the host', () => {
    each((v) => {
      const os = new Map(rows(v.corpus, 'DeviceInfo').map((d) => [String(d.DeviceName), String(d.OSPlatform)]));
      const windows = (host: unknown) => /windows/i.test(os.get(String(host)) ?? '');
      for (const r of v.vulnFindings.filter((x) => !v.isWork(x))) {
        const title = String(r.Title);
        const at = `${v.label}: ${String(r.FindingId)} "${title}" on ${String(r.DeviceName)}`;
        if (String(r.VulnId) !== '') {
          const cls = classOfTitle(title);
          expect(cls, `${at}: names a class`).not.toBeNull();
          const vector = String(v.intel.get(String(r.VulnId))!.CvssVector);
          expect(vectorProblem(vector, cls!, title), `${at} with ${vector}`).toBeNull();
        }
        if (/^SSH /.test(title)) expect(windows(r.DeviceName), `${at}: an SSH plugin on a Windows host`).toBe(false);
        if (/^SMB /.test(title)) expect(windows(r.DeviceName), `${at}: an SMB plugin on a non-Windows host`).toBe(true);
        if (title === AUTH_FAILURE_TITLE) {
          expect(r.Service, `${at}: login protocol`).toBe(windows(r.DeviceName) ? 'winrm' : 'ssh');
        }
      }
    });
  });

  it('C5: the calendar shows both dates of every window and the freeze is not a year-end freeze', () => {
    each((v) => {
      const cal = v.c.attachments.find((a) => a.title === 'Change calendar (UTC)');
      expect(cal, `${v.label}: calendar attachment`).toBeDefined();
      const body = cal!.body as [string, string][];
      for (const [label, value] of body.filter(([l]) => l !== 'Case date (UTC)').slice(0, 2)) expect(value, `${v.label}: ${label}`).toMatch(/^\d{4}-\d\d-\d\d \d\d:\d\d to \d{4}-\d\d-\d\d \d\d:\d\d$/);
      const text = JSON.stringify(v.c.attachments) + JSON.stringify(rows(v.corpus, 'Tickets'));
      expect(text, `${v.label}: no year-end freeze`).not.toMatch(/year-end/i);
      expect(text, `${v.label}: no weekly window`).not.toMatch(/weekly/i);
    });
  });

  it('C3: no row predates what it refers to', () => {
    each((v) => {
      for (const r of v.vulnFindings) {
        if (String(r.VulnId) === '') continue;
        expect(ms(r.FirstSeen), `${v.label}: ${String(r.FindingId)} first seen after ${String(r.VulnId)} was published`).toBeGreaterThanOrEqual(ms(v.intel.get(String(r.VulnId))!.Published));
      }
      const dated = (table: 'Tickets' | 'PatchHistory', when: string) => {
        for (const r of rows(v.corpus, table)) {
          for (const id of new Set(JSON.stringify(r).match(SIMVULN) ?? [])) {
            const published = v.intel.get(id)?.Published;
            if (published) expect(ms(r[when]), `${v.label}: ${table} row ${String(r.RecordId)} names ${id}`).toBeGreaterThanOrEqual(ms(published));
          }
        }
      };
      dated('Tickets', 'Created');
      dated('PatchHistory', 'InstalledOn');
    });
  });

  it('C4: slaLatest is the latest option that meets the end-of-day deadline, a day clear of every deciding boundary', () => {
    each((v) => {
      for (const { f, row } of v.work) {
        if (f.truth.schedule === 'none') continue;
        const deadline = deadlineOf(v, row);
        const { latest, ends } = slaOf(v, deadline);
        const at = `${v.label}: ${f.findingId}`;
        expect(f.truth.slaLatest, `${at}: slaLatest`).toBe(latest);
        expect(VULN_SCHEDULES.indexOf(f.truth.schedule), `${at}: schedule is not later than slaLatest`).toBeLessThanOrEqual(VULN_SCHEDULES.indexOf(latest));
        const deciding = latest === 'emergency' ? [ends[0]] : latest === 'next-window' ? [ends[0], ends[1]] : [ends[1]];
        for (const end of deciding) expect(Math.abs(end - deadline), `${at}: window end vs deadline`).toBeGreaterThanOrEqual(DAY);
      }
    });
  });

  it('C7: contradicting codes list what the data proves false, never a required code, and no required code is false', () => {
    each((v) => {
      const patches = rows(v.corpus, 'PatchHistory');
      const tickets = rows(v.corpus, 'Tickets');
      const controls = rows(v.corpus, 'ControlInventory');
      const devices = new Map(rows(v.corpus, 'DeviceInfo').map((d) => [String(d.DeviceName), d]));
      for (const { f, row } of v.work) {
        const intel = v.intel.get(String(row.VulnId))!;
        const contra = new Set<ReasonCode>(f.truth.contradicting ?? []);
        const required = new Set<ReasonCode>(f.truth.reasons);
        const at = `${v.label}: ${f.findingId}`;
        for (const code of required) expect(contra.has(code), `${at}: ${code} is both required and contradicting`).toBe(false);
        const listed = flag(intel.KnownExploited);
        const epss = Number(intel.ExploitProbability);
        const packageBasis = /^(Credentialed|Agent) local check/.test(String(row.Evidence));
        const stale = required.has('stale-scan');
        const rebootPending = patches.some((p) => p.DeviceName === row.DeviceName && flag(p.RebootPending));
        const proven: ReasonCode[] = [];
        if (f.truth.decision !== 'false-positive') proven.push('stale-scan');
        if (!listed) proven.push('known-exploited');
        if (!flag(intel.PublicExploit)) proven.push('public-exploit');
        if (listed || epss >= 0.1) proven.push('low-exploitability');
        if (packageBasis) proven.push('banner-only', 'backported-fix');
        if (stale && !rebootPending) proven.push('pending-reboot');
        const vulnId = String(row.VulnId);
        const excepted = tickets.some((x) => String(x.Title).startsWith('Risk exception') && JSON.stringify(x).includes(vulnId));
        const controlled = controls.some((x) => String(x.CoversVulnId) === vulnId);
        const exposed = flag(devices.get(String(row.DeviceName))?.ExposedToInternet);
        if (!packageBasis) proven.push('credentialed-confirmed');
        if (!exposed) proven.push('internet-exposed');
        if (flag(intel.VendorFix)) proven.push('no-vendor-fix');
        if (!excepted) proven.push('approved-exception');
        if (!controlled) proven.push('compensating-control-verified');
        if (!listed && epss < 0.1) proven.push('high-exploit-probability');
        if (String(devices.get(String(row.DeviceName))?.Criticality) === 'Low') proven.push('critical-asset');
        // a false positive whose fix was installed before the scan (not a stale result)
        if (f.truth.decision === 'false-positive' && !stale) proven.push('stale-scan', ...(rebootPending ? [] : (['pending-reboot'] as const)));
        for (const code of proven) if (!required.has(code)) expect(contra.has(code), `${at}: ${code} is proven false by the data`).toBe(true);
        // A required code must be true in the data (e.g. 'public-exploit' needs PublicExploit = 1).
        for (const code of required) expect(proven.includes(code), `${at}: required ${code} is false in the data`).toBe(false);
        // ...and never a code a careful analyst could truthfully cite.
        if (listed) expect(contra.has('known-exploited'), `${at}: known-exploited is true`).toBe(false);
        if (flag(intel.PublicExploit)) expect(contra.has('public-exploit'), `${at}: public-exploit is true`).toBe(false);
        if (!listed && epss < 0.1) expect(contra.has('low-exploitability'), `${at}: low-exploitability is true`).toBe(false);
        if (rebootPending) expect(contra.has('pending-reboot'), `${at}: a reboot is pending`).toBe(false);
        if (packageBasis) expect(contra.has('credentialed-confirmed'), `${at}: credentialed-confirmed is true`).toBe(false);
        if (exposed) expect(contra.has('internet-exposed'), `${at}: the host is exposed`).toBe(false);
        if (!flag(intel.VendorFix)) expect(contra.has('no-vendor-fix'), `${at}: no vendor fix exists`).toBe(false);
        if (excepted) expect(contra.has('approved-exception'), `${at}: an exception ticket exists`).toBe(false);
        if (controlled) expect(contra.has('compensating-control-verified'), `${at}: a control covers it`).toBe(false);
      }
    });
  });

  it('C8: worklist padding takes its Sim-EPSS from the lower half of the non-Sim-KEV table', () => {
    const lowerHalfMax = simEpssScoreAt(SIM_EPSS_ALL, 0.5);
    each((v) => {
      for (const { f, row } of v.work) {
        const intel = v.intel.get(String(row.VulnId))!;
        if (flag(intel.KnownExploited) || f.evidence.length > 0) continue; // deciders carry an evidence point
        expect(Number(intel.ExploitProbability), `${v.label}: ${f.findingId} Sim-EPSS`).toBeLessThanOrEqual(lowerHalfMax);
      }
    });
  });

  it('C9: weights are 0.5, 1 or 3, and 3 is exactly the must-not-miss', () => {
    each((v) => {
      for (const { f } of v.work) {
        expect([0.5, 1, 3], `${v.label}: ${f.findingId} weight`).toContain(f.weight);
        expect(f.weight === 3, `${v.label}: ${f.findingId} weight 3 iff must-not-miss`).toBe(f.mustNotMiss);
      }
    });
  });

  it('C10: rubric keywords are unique per item, and every owner the owner item names is an Owner in DeviceInfo (or the change-ticket assignee)', () => {
    each((v) => {
      const owners = new Set([...rows(v.corpus, 'DeviceInfo').map((d) => String(d.Owner).toLowerCase()), ...rows(v.corpus, 'Tickets').map((x) => String(x.AssignedTo).toLowerCase())]);
      for (const item of v.c.rubric) {
        const kws = item.keywords.map((k) => k.toLowerCase());
        expect(new Set(kws).size, `${v.label}: rubric "${item.id}" keywords are unique`).toBe(kws.length);
        if (item.id !== 'owner') continue;
        for (const k of kws.filter((x) => x !== 'owner')) expect(owners.has(k), `${v.label}: owner keyword "${k}" is an owner in DeviceInfo`).toBe(true);
      }
    });
  });

  it('C11: Published and KnownExploitedAdded are at 00:00 UTC', () => {
    each((v) => {
      for (const i of v.intel.values()) {
        for (const col of ['Published', 'KnownExploitedAdded']) {
          if (i[col] === null || i[col] === undefined || i[col] === '') continue;
          expect(ms(i[col]) % DAY, `${v.label}: ${String(i.VulnId)} ${col} is a day start`).toBe(0);
        }
      }
    });
  });

  it('C12: no Open row keeps an older run on a host that a later credentialed or agent run reached without a login failure', () => {
    each((v) => {
      const all = [...v.runs.values()];
      for (const r of v.vulnFindings) {
        if (String(r.Status) !== 'Open') continue;
        const from = v.runs.get(String(r.ScanRunId))!;
        for (const later of all.filter((x) => ms(x.Started) > ms(from.Started) && x.Method !== 'Unauthenticated')) {
          const there = v.vulnFindings.filter((x) => x.ScanRunId === later.ScanRunId && x.DeviceName === r.DeviceName);
          if (there.length === 0 || there.some((x) => String(x.Title) === AUTH_FAILURE_TITLE)) continue;
          throw new Error(`${v.label}: ${String(r.FindingId)} "${String(r.Title)}" on ${String(r.DeviceName)} stays with ${String(from.ScanRunId)} though ${String(later.ScanRunId)} reached the host`);
        }
      }
    });
  });

  it('C13: a run never has rows on more devices than it reached, and its AuthFailures cover the login-failure rows', () => {
    each((v) => {
      for (const [id, run] of v.runs) {
        const mine = v.vulnFindings.filter((r) => r.ScanRunId === id);
        const hosts = new Set(mine.map((r) => String(r.DeviceName)));
        const failed = new Set(mine.filter((r) => String(r.Title) === AUTH_FAILURE_TITLE).map((r) => String(r.DeviceName)));
        expect(hosts.size, `${v.label}: ${id} devices with rows vs TargetsScanned`).toBeLessThanOrEqual(Number(run.TargetsScanned));
        // the newest run's coverage is readable: every device it reached has a row under it
        if (id === v.latestRun) expect(Number(run.TargetsScanned), `${v.label}: newest run ${id} TargetsScanned equals the devices with a row`).toBe(hosts.size);
        expect(Number(run.AuthFailures), `${v.label}: ${id} AuthFailures vs login-failure rows`).toBeGreaterThanOrEqual(failed.size);
        // A host whose login failed in this run gets only its login-failure row from that run: no vulnerability row and no
        // credentialed configuration check (the banner fallback would need a port, and no template relies on it there).
        for (const h of failed) expect(mine.filter((r) => r.DeviceName === h && String(r.Title) !== AUTH_FAILURE_TITLE).length, `${v.label}: ${id} ${h} has a login failure and other rows`).toBe(0);
      }
    });
  });

  it('fix C1/C2: an accepted risk is never a misconfiguration and only with no vendor fix; internet-exposed needs AV:N and an exposed host', () => {
    each((v) => {
      const devices = new Map(rows(v.corpus, 'DeviceInfo').map((d) => [String(d.DeviceName), d]));
      for (const { f, row } of v.work) {
        const intel = v.intel.get(String(row.VulnId))!;
        const at = `${v.label}: ${f.findingId}`;
        if (f.truth.decision === 'accept') {
          expect(classOfTitle(String(row.Title)), `${at}: an accepted risk is not a configuration weakness`).not.toBe('misconfig');
          expect(flag(intel.VendorFix), `${at}: an accepted risk has no vendor fix`).toBe(false);
        }
        if (f.truth.reasons.includes('no-vendor-fix')) expect(flag(intel.VendorFix), `${at}: no-vendor-fix is required but a fix exists`).toBe(false);
        if (f.truth.reasons.includes('internet-exposed')) {
          expect(String(intel.CvssVector), `${at}: internet-exposed needs a network vector`).toMatch(/\/AV:N\//);
          expect(flag(devices.get(String(row.DeviceName))?.ExposedToInternet), `${at}: internet-exposed needs an exposed host`).toBe(true);
        }
      }
    });
  });

  it('fix C4: the detected version was installed on or before first detection (and before the exception ticket)', () => {
    const upstream = (x: unknown) => String(x).replace(/[-+~].*$/, '');
    each((v) => {
      const software = rows(v.corpus, 'SoftwareInventory');
      const tickets = rows(v.corpus, 'Tickets');
      for (const { f, row } of v.work) {
        const at = `${v.label}: ${f.findingId}`;
        const inv = software.find((s) => s.DeviceName === row.DeviceName && String(row.Title).includes(` in ${String(s.Product)} `));
        if (!inv || upstream(inv.Version) !== upstream(row.DetectedVersion)) continue; // the inventory shows another (fixed) version
        expect(ms(inv.InstalledOn), `${at}: installed on or before first detection`).toBeLessThanOrEqual(ms(row.FirstSeen));
        if (f.truth.decision === 'accept') {
          for (const t of tickets.filter((x) => String(x.Title).startsWith('Risk exception') && JSON.stringify(x).includes(String(row.VulnId))))
            expect(ms(inv.InstalledOn), `${at}: installed on or before the exception ticket`).toBeLessThanOrEqual(ms(t.Created));
        }
      }
    });
  });

  it('fix C6/C11: the policy explains the scan store, and the calendar shows the case date', () => {
    each((v) => {
      const policy = v.c.attachments.find((a) => a.title.includes('remediation standard'));
      expect(JSON.stringify(policy?.body), `${v.label}: policy explains the scan store`).toContain('The scan store keeps one row per finding: FirstSeen is the first detection; ScanRunId and LastSeen are the latest run that saw it. A finding that a later run re-tested and no longer saw is closed (Status Fixed).');
      const cal = v.c.attachments.find((a) => a.title === 'Change calendar (UTC)')!;
      expect(cal.body as [string, string][], `${v.label}: case date`).toContainEqual(['Case date (UTC)', new Date(v.now).toISOString().slice(0, 10)]);
    });
  });

  it('fix C13: no background row sits on a device exposed to the internet', () => {
    each((v) => {
      const exposed = new Set(rows(v.corpus, 'DeviceInfo').filter((d) => flag(d.ExposedToInternet)).map((d) => String(d.DeviceName)));
      for (const r of v.vulnFindings.filter((x) => !v.isWork(x) && String(x.Title) !== AUTH_FAILURE_TITLE))
        expect(exposed.has(String(r.DeviceName)), `${v.label}: background ${String(r.FindingId)} on exposed ${String(r.DeviceName)}`).toBe(false);
    });
  });

  // Grading as of DESIGN 5.4/5.5/5.8: reason codes outside the required set cost 0.25 each, pins beyond one per evidence
  // point cost 1 each with no cap, and a missed key finding caps the total at 60.
  it('C14: naive strategies stay below the pass mark', () => {
    const SPAM: ReasonCode[] = ['low-exploitability', 'stale-scan', 'sla-deadline'];
    each((v) => {
      type Item = (typeof v.work)[number];
      const byScore = [...v.work].sort((a, b) => Number(b.row.CvssBase) - Number(a.row.CvssBase));
      const rank = (s: unknown) => ['Critical', 'High', 'Medium', 'Low', 'Info'].indexOf(String(s));
      const bySeverity = [...v.work].sort((a, b) => rank(a.row.Severity) - rank(b.row.Severity) || Number(b.row.CvssBase) - Number(a.row.CvssBase));
      const byDeadline = [...bySeverity].sort((a, b) => tableDeadline(v, a.row) - tableDeadline(v, b.row));
      const tableSchedule = (i: Item): VulnSchedule => slaOf(v, tableDeadline(v, i.row)).latest;
      const everyRecord = (Object.values(v.corpus.tables) as { columns: string[]; rows: unknown[][] }[]).flatMap((t) => t.rows.map((r) => String(r[t.columns.indexOf('RecordId')])));
      const submit = (order: Item[], decision: 'patch' | 'false-positive', schedule: (i: Item) => VulnSchedule, spam: boolean, pins: string[] = []): VulnSubmission => ({
        answers: Object.fromEntries(v.work.map((i) => [i.f.findingId, { decision, control: null, schedule: schedule(i), reasons: spam ? SPAM : [] }])) as VulnSubmission['answers'],
        order: order.map((i) => i.f.findingId),
        pins,
        notes: '',
        hintsUsed: 0,
      });
      for (const spam of [false, true]) {
        const tag = spam ? ' + reason spam' : '';
        const strategies: [string, VulnSubmission][] = [
          [`a: all patch + emergency, by CVSS${tag}`, submit(byScore, 'patch', () => 'emergency', spam)],
          [`b: all false-positive${tag}`, submit(byScore, 'false-positive', () => 'none', spam)],
          [`c: by scanner severity, SLA-table schedule${tag}`, submit(bySeverity, 'patch', tableSchedule, spam)],
          [`e: by computed deadline, SLA-table schedule${tag}`, submit(byDeadline, 'patch', tableSchedule, spam)],
          [`f: all patch + emergency, by CVSS, every row pinned${tag}`, submit(byScore, 'patch', () => 'emergency', spam, everyRecord)],
        ];
        // The pass decision is on percent = Math.round(score), so the guard is too (a 69.6 passes).
        for (const [name, s] of strategies) expect(Math.round(gradeVulnCase(v.c, s).score), `${v.label}: ${name}`).toBeLessThan(70);
      }
    });
  });
});

describe('twin pairs share one world (K5)', () => {
  const pairs = TEMPLATES.filter((t) => t.twin && t.id < t.twin && TEMPLATES.some((x) => x.id === t.twin)).map((t) => [t, TEMPLATES.find((x) => x.id === t.twin)!] as const);

  it.each(pairs.map(([a, b]) => [a.id, b.id, a, b] as const))('%s / %s agree on every worklist row and differ only in the headline truth', (_a, _b, a, b) => {
    for (const run of RUNS) {
      const va = view(a, run);
      const vb = view(b, run);
      expect(va.work.length, `${run.seed}: same worklist size`).toBe(vb.work.length);
      va.work.forEach((x, i) => {
        const y = vb.work[i];
        for (const col of ['VulnId', 'DeviceName', 'CvssBase', 'FirstSeen', 'DetectedVersion', 'Title']) expect(x.row[col], `${run.seed}: finding ${i + 1} ${col}`).toEqual(y.row[col]);
        if (i > 0) expect(x.f.truth, `${run.seed}: finding ${i + 1} truth`).toEqual(y.f.truth);
      });
      // ...and on the shared inputs: the worklist hosts' DeviceInfo, the worklist products' SoftwareInventory rows, their PatchHistory.
      const hostsOf = new Set(va.work.map((x) => String(x.row.DeviceName)));
      const titlesOf = (v: View) => v.work.map((x) => ({ host: String(x.row.DeviceName), title: String(x.row.Title) }));
      const shared = (v: View, table: 'DeviceInfo' | 'SoftwareInventory' | 'PatchHistory') =>
        rows(v.corpus, table)
          .filter((r) => hostsOf.has(String(r.DeviceName)) && (table !== 'SoftwareInventory' || titlesOf(v).some((w) => w.host === r.DeviceName && w.title.includes(` in ${String(r.Product)} `))))
          .map(({ RecordId: _r, ...rest }) => JSON.stringify(rest))
          .sort();
      for (const table of ['DeviceInfo', 'SoftwareInventory', 'PatchHistory'] as const) expect(shared(va, table), `${run.seed}: same ${table} rows on the worklist hosts`).toEqual(shared(vb, table));
      // ...the twins' ScanRuns rows (ids, times, coverage) and the worklist rows' run and last-seen columns are identical.
      const runRows = (v: View) => rows(v.corpus, 'ScanRuns').map(({ RecordId: _r, ...rest }) => JSON.stringify(rest)).sort();
      expect(runRows(va), `${run.seed}: same ScanRuns rows`).toEqual(runRows(vb));
      va.work.forEach((x, i) => {
        for (const col of ['ScanRunId', 'LastSeen']) expect(x.row[col], `${run.seed}: finding ${i + 1} ${col}`).toEqual(vb.work[i].row[col]);
      });
      const [ha, hb] = [va.work[0].f.truth, vb.work[0].f.truth];
      expect(ha.decision !== hb.decision || ha.schedule !== hb.schedule, `${run.seed}: the headline truth differs`).toBe(true);
    }
  });
});

describe.each(TEMPLATES.map((t) => [t.id, t] as const))('%s scan store rows', (_id, t) => {
  it('the scan store keeps one row per finding: no run shows a plugin twice on a host, and hygiene stays a minority of the background', () => {
    for (const run of RUNS) {
      const v = view(t, run);
      const seen = new Set<string>();
      for (const r of v.vulnFindings) {
        const key = `${String(r.ScanRunId)}|${String(r.DeviceName)}|${String(r.Title)}|${String(r.Port)}`;
        expect(seen.has(key), `${v.label}: duplicate row ${key}`).toBe(false);
        seen.add(key);
      }
      const background = v.vulnFindings.filter((r) => !v.isWork(r) && String(r.Title) !== AUTH_FAILURE_TITLE);
      const hygiene = background.filter((r) => String(r.VulnId) === '').length;
      expect(hygiene / background.length, `${v.label}: hygiene ${hygiene}/${background.length}`).toBeLessThanOrEqual(0.5);
    }
  });
});

describe('worklist description rules (vectorProblem)', () => {
  const N = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
  const cases: [string, string, Parameters<typeof vectorProblem>[1], string][] = [
    ['a directory listing needs no user interaction', N.replace('UI:N', 'UI:R'), 'info-leak', 'Information disclosure in Acme Hub directory listing'],
    ['a debug endpoint needs no privileges', N.replace('PR:N', 'PR:L'), 'info-leak', 'Information disclosure in Acme Hub debug endpoint'],
    ['a metrics endpoint needs no user interaction', N.replace('UI:N', 'UI:R'), 'info-leak', 'Information disclosure in Acme Hub metrics endpoint'],
    ['a backup file exposure needs no privileges', N.replace('PR:N', 'PR:H'), 'info-leak', 'Information disclosure in Acme Hub backup file exposure'],
    ['default credentials need no user interaction', N.replace('UI:N', 'UI:R'), 'misconfig', 'Insecure default configuration in Acme Hub default credentials'],
    ['a log viewer is never physical', N.replace('AV:N', 'AV:P'), 'info-leak', 'Information disclosure in Acme Hub log viewer'],
    ['a TLS flaw needs no privileges', N.replace('PR:N', 'PR:H'), 'misconfig', 'Insecure default configuration in Acme Hub TLS settings'],
    ['a TLS flaw needs a confidentiality impact', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'auth-bypass', 'Authentication bypass in Acme Hub TLS settings'],
    ['a physical component is never network-reachable', N, 'info-leak', 'Information disclosure in Acme Hub firmware dump interface'],
  ];
  it.each(cases)('rejects: %s', (_why, vector, cls, title) => {
    expect(vectorProblem(vector, cls, title)).not.toBeNull();
  });
  it('accepts a directory listing that fits and a physical component with a physical vector', () => {
    expect(vectorProblem(N, 'info-leak', 'Information disclosure in Acme Hub directory listing')).toBeNull();
    expect(vectorProblem(N.replace('AV:N', 'AV:P'), 'info-leak', 'Information disclosure in Acme Hub firmware dump interface')).toBeNull();
  });
});

describe('worklist shape table (WORKLIST_SHAPES)', () => {
  const metrics = (vector: string): Record<string, string> => Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));
  const KINDS: ProductKind[] = ['web-app', 'agent', 'server', 'appliance'];
  const SAMPLE: Record<ProductKind, string> = { 'web-app': 'Larkspur Portal', agent: 'Tarnwick Inventory Agent', server: 'Ombrelune Files', appliance: 'Copperfield Print Server' };
  const WEB_ONLY = /login form|template engine|file-upload|SSO callback|search endpoint|report filter|export module|audit viewer|session handler|password reset|admin console|directory listing|debug endpoint|backup file|file-download|image renderer|compression module|request parser/;

  it('every entry scores, fits its class and component by the shared rules, and has a note', () => {
    for (const sh of WORKLIST_SHAPES) {
      const title = shapeTitle(sh, SAMPLE[sh.productKind]);
      expect(vectorProblem(sh.vector, sh.vulnClass, title), title + ' ' + sh.vector).toBeNull();
      expect(sh.note.length, title).toBeGreaterThan(10);
      expect(severityOf(baseScore(sh.vector)), title).not.toBe('none');
    }
  });

  it('has no physical vector or component, and no configuration weakness', () => {
    for (const sh of WORKLIST_SHAPES) {
      expect(sh.vector, sh.component).not.toContain('AV:P');
      expect(sh.component, sh.vector).not.toMatch(/firmware|boot loader|console port|installer profile|default credentials/i);
      expect(sh.vulnClass as string).not.toBe('misconfig');
    }
  });

  it('class rules: injection and bypass have C or I impact; DoS is availability only; disclosure is confidentiality only; RCE has integrity impact', () => {
    for (const sh of WORKLIST_SHAPES) {
      const m = metrics(sh.vector);
      const at = `${sh.vulnClass} ${sh.component} ${sh.vector}`;
      if (sh.vulnClass === 'sqli' || sh.vulnClass === 'auth-bypass') expect(m.C !== 'N' || m.I !== 'N', at).toBe(true);
      if (sh.vulnClass === 'sqli') expect(m.AV, at).toBe('N');
      if (sh.vulnClass === 'auth-bypass') expect(m.PR, at).toBe('N');
      if (sh.vulnClass === 'dos') expect([m.C, m.I, m.A !== 'N'], at).toEqual(['N', 'N', true]);
      if (sh.vulnClass === 'info-leak') expect([m.C !== 'N', m.I], at).toEqual([true, 'N']);
      if (sh.vulnClass === 'rce') {
        expect(m.I, at).toBe('H');
        if (m.AV === 'L') expect(sh.component, at).toMatch(/installer profile|scripting console/);
        else expect(['N', 'A'], at).toContain(m.AV);
      }
    }
  });

  it('component rules: bypass of a licence, token, console or SSO check needs no user action; exposures need no login, no user action and a confidentiality impact; TLS and protocol flaws are network and unauthenticated', () => {
    for (const sh of WORKLIST_SHAPES) {
      const m = metrics(sh.vector);
      const at = `${sh.vulnClass} ${sh.component} ${sh.vector}`;
      if (/license service|API token check|admin console|SSO callback/.test(sh.component)) expect(m.UI, at).toBe('N');
      if (/directory listing|debug endpoint|metrics endpoint|backup file exposure/.test(sh.component)) expect([m.UI, m.PR, m.C !== 'N'], at).toEqual(['N', 'N', true]);
      if (/TLS|protocol/i.test(sh.component + (sh.detail ?? ''))) expect([m.AV, m.PR], at).toEqual(['N', 'N']);
    }
  });

  it('agent shapes never use a web application component, and every product has a kind', () => {
    for (const sh of WORKLIST_SHAPES.filter((x) => x.productKind === 'agent')) expect(sh.component).not.toMatch(WEB_ONLY);
    for (const seed of ['a', 'b', 'c']) for (const e of generateCatalogue(seed, Date.UTC(2026, 5, 1)).entries) expect(PRODUCT_KINDS[e.product], e.product).toBeDefined();
    expect(PRODUCT_KINDS['Dunmarrow httpd']).toBe('server');
  });

  it('is unique and varied: every band the templates use has at least three shapes, and each of web-app, server and appliance has some in each', () => {
    const keys = WORKLIST_SHAPES.map((x) => [x.productKind, x.vulnClass, x.component, x.vector, x.detail ?? ''].join('|'));
    expect(new Set(keys).size).toBe(keys.length);
    const bands: [string, ShapeWant][] = [
      ['9.8 RCE headline', { classes: ['rce'], min: 9.8, max: 9.8 }],
      ['critical', { min: 9 }],
      ['high above 7.5', { min: 7.6, max: 8.9 }],
      ['7.5 disclosure headline', { classes: ['info-leak'], min: 7.5, max: 7.5 }],
      ['high 7.0 to 7.4', { min: 7, max: 7.4 }],
      ['medium', { min: 4, max: 6.9 }],
      ['medium TLS', { component: /TLS/, min: 5, max: 6.9 }],
      ['medium, network', { min: 4, max: 6.9, network: true }],
      ['low', { max: 3.9 }],
    ];
    for (const [name, want] of bands) {
      let total = 0;
      for (const kind of KINDS) {
        const n = shapesFor(kind, want).length;
        total += n;
        if (kind !== 'agent') expect(n, `${name} for ${kind}`).toBeGreaterThanOrEqual(1);
      }
      expect(total, name).toBeGreaterThanOrEqual(3);
    }
  });
});

describe('template sources', () => {
  it('write every solution query on one line with \n, never a literal newline inside a template literal', () => {
    const dir = new URL('../../src/core/vuln/templates/', import.meta.url);
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts'))) {
      const src = readFileSync(new URL(file, dir), 'utf8');
      for (const m of src.matchAll(/kql:\s*`([^`]*)`/g)) expect(m[1], `${file}: kql with a literal newline`).not.toContain('\n');
    }
  });
});
