// The linked SOC template `endpoint-known-vuln-exploit` (WP5, DESIGN section 8).
// It is built two ways: without a hook (the harness path, a deterministic
// fallback host and id) and with a hook (a shift-like scenario in which the
// vulnerability ledger names a host and a SIMVULN id). Hooks for the sweep come
// from real vuln builds: every eligible finding of every registered vuln
// template, over several seeds and worlds.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import type { VulnHook } from '../../src/core/shift/vuln-hook.ts';
import { buildScenario, practiceTiming, type ResolvedCase, type Scenario } from '../../src/core/cases/scenario.ts';
import { LINKED_TEMPLATES } from '../../src/core/cases/templates/vuln-link.ts';
import { ALL_TEMPLATES, templateById } from '../../src/core/cases/templates/index.ts';
import { SIMVULN_ID_PATTERN } from '../../src/core/vuln/ids.ts';
import { VULN_TEMPLATES } from '../../src/core/vuln/registry.ts';
import { buildVulnScenario } from '../../src/core/vuln/scenario.ts';
import type { World } from '../../src/core/world/world.ts';
import { SiemDatabase } from '../../src/core/query/engine.ts';
import { atLocalHour, HOUR, localHour, MIN } from '../../src/core/logs/time.ts';
import { cveViolations } from '../helpers/cve-guard.ts';
import { syntheticViolations } from '../helpers/guardrails.ts';
import { sqljs } from '../helpers/sql.ts';
import { checkGrading, checkSolvable, checkStructure, checkTemplate, standardRuns, world } from '../helpers/scenario-check.ts';
import { buildShift, planShift, shiftSeedFor } from '../../src/core/shift/plan.ts';
import { campaignContext, campaignSlot, recordShift, startCampaign, type CampaignState } from '../../src/core/campaign/campaign.ts';
import { scoreShift, type Submission } from '../../src/core/shift/score.ts';
import { perfectVerdict, type Verdict } from '../../src/core/grading/grade.ts';
import { selectVulnFollowUp, VULN_LINK_TEMPLATE_ID } from '../../src/core/shift/vuln-hook.ts';
import { resolveVulnLink } from '../../src/ui/lib/vuln-link.ts';
import { resolveVulnTemplate, vulnCaseTypes } from '../../src/core/vuln/worklist.ts';

const ID = 'endpoint-known-vuln-exploit';
const WORLDS = ['hook-world-0', 'hook-world-1'];
const SEEDS = ['h0', 'h1', 'h2'];

function makeHook(host: string, vulnId: string, seed: string): VulnHook {
  return {
    ledgerId: `vm-test~${seed}/FND-0001@1`,
    host,
    vulnId,
    decidedDay: 1,
    caseRef: `vm-test~${seed}`,
    decision: 'false-positive',
    schedule: 'none',
    seed: `${seed}:vuln:${host}`,
  };
}

// A shift-like scenario: one item carrying the hook, a 22-hour window, the
// timing a practice case would get. `items: []` gives the same noise without it.
function buildHooked(w: World, hook: VulnHook | undefined, withItem = true): Scenario {
  const { at, now } = practiceTiming(ID, hook?.seed ?? 'none', templateById(ID)!.when, w.org.utcOffset);
  return buildScenario({
    world: w,
    seed: `hooked:${hook?.seed ?? 'none'}`,
    now,
    windowHours: 22,
    items: withItem ? [{ alertId: 'A1', templateId: ID, seed: hook?.seed ?? 'none', at, vulnHook: hook }] : [],
    historyFiller: true,
  });
}

async function checkHooked(w: World, hook: VulnHook, db: boolean): Promise<Scenario> {
  const s = buildHooked(w, hook);
  expect(s.cases).toHaveLength(1);
  const c = s.cases[0];
  checkStructure(c);
  checkGrading(c);
  expect(syntheticViolations(s.corpus, w), `${hook.host}/${hook.vulnId}`).toEqual([]);
  if (db) await checkSolvable(s, c);
  return s;
}

type Row = Record<string, string | number | null>;
function rows(s: Scenario, table: keyof Scenario['corpus']['tables']): Row[] {
  const t = s.corpus.tables[table];
  return t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])));
}

// Hooks taken from real vuln builds: the VulnFindings row of every eligible finding.
// Eligible: a real must-not-miss finding, not mitigate and no mitigation, on a
// device of the shared world, with a SIMVULN id.
function eligibleHooks(worldName: string, seeds: string[]): { hook: VulnHook; template: string }[] {
  const w = world(worldName);
  const shared = new Set(w.hosts.map((h) => h.name));
  const out = new Map<string, { hook: VulnHook; template: string }>();
  for (const t of VULN_TEMPLATES) {
    for (const seed of seeds) {
      const v = buildVulnScenario({ worldSeed: w.seed, templateId: t.id, seed, world: w });
      const f = v.corpus.tables.VulnFindings;
      const col = (n: string) => f.columns.indexOf(n);
      const byRecord = new Map(f.rows.map((r) => [String(r[col('RecordId')]), r]));
      for (const fi of v.case.findings) {
        const row = byRecord.get(fi.recordId)!;
        const host = String(row[col('DeviceName')]);
        const vulnId = String(row[col('VulnId')]);
        const real = fi.mustNotMiss && fi.truth.decision !== 'false-positive' && fi.truth.decision !== 'mitigate' && !fi.truth.mitigation?.length;
        if (!real || !shared.has(host) || !SIMVULN_ID_PATTERN.test(vulnId)) continue;
        const hook = { ...makeHook(host, vulnId, `${t.id}~${seed}`), ledgerId: `${t.id}~${seed}/${fi.findingId}@1` };
        out.set(`${host}|${vulnId}`, { hook, template: t.id });
      }
    }
  }
  return [...out.values()];
}

// Text a learner can read before submitting.
function beforeSubmit(c: ResolvedCase): string {
  return [c.alert.rule, c.alert.product, c.alert.summary, c.briefing, ...c.hints, ...c.alert.entities.map((e) => e.value)].join('\n');
}

describe('endpoint-known-vuln-exploit template', () => {
  it('is a linked template: resolvable by id, outside ALL_TEMPLATES, never random', () => {
    expect(LINKED_TEMPLATES.map((t) => t.id)).toContain(ID);
    expect(templateById(ID)).toBeDefined();
    expect(ALL_TEMPLATES.some((t) => t.id === ID)).toBe(false);
    const t = templateById(ID)!;
    expect(t.kind).toBe('incident');
    expect(t.twin).toBeUndefined();
    expect(t.cysaDomains.length).toBeGreaterThan(0);
  });

  it('builds without a hook (fallback host and id), stays synthetic and is solvable', async () => {
    await checkTemplate(ID, standardRuns());
  });

  it('the fallback names a world server and a SIMVULN id, deterministically', () => {
    for (const worldName of WORLDS) {
      const w = world(worldName);
      const a = buildHooked(w, undefined);
      const b = buildHooked(w, undefined);
      expect(JSON.stringify(a)).toBe(JSON.stringify(b));
      const alerts = rows(a, 'SecurityAlert').filter((r) => String(r.Description).includes('SIMVULN'));
      expect(alerts.length).toBeGreaterThanOrEqual(2);
      const hosts = new Set(w.hosts.map((h) => h.name));
      for (const r of alerts) {
        expect(hosts.has(String(r.CompromisedEntity))).toBe(true);
        expect(String(r.Description).match(/SIMVULN-[^\s.]*/g)!.every((m) => SIMVULN_ID_PATTERN.test(m))).toBe(true);
      }
    }
  });

  it('real eligible findings of every registered vuln template give hooks that build, name the host and the id, and are deterministic', async () => {
    let n = 0;
    const hostsSeen = new Set<string>();
    let dbRuns = 0;
    for (const worldName of WORLDS) {
      const w = world(worldName);
      const hooks = eligibleHooks(worldName, SEEDS);
      expect(hooks.length, `${worldName}: eligible hooks`).toBeGreaterThan(0);
      for (const { hook } of hooks) {
        const dbOnce = !hostsSeen.has(`${worldName}|${hook.host}`);
        hostsSeen.add(`${worldName}|${hook.host}`);
        if (dbOnce) dbRuns++;
        const s = await checkHooked(w, hook, dbOnce);
        const c = s.cases[0];
        const label = `${worldName} ${hook.host} ${hook.vulnId}`;
        expect(JSON.stringify(buildHooked(w, hook)), `${label}: deterministic`).toBe(JSON.stringify(s));
        // A row of the corpus names the host and the id.
        const alerts = rows(s, 'SecurityAlert').filter((r) => String(r.Description).includes(hook.vulnId));
        expect(alerts.some((r) => r.CompromisedEntity === hook.host), `${label}: a SecurityAlert on the host names the id`).toBe(true);
        expect(c.alert.entities.some((e) => e.value === hook.host), `${label}: alert entity`).toBe(true);
        expect(c.alert.fields.some(([, v]) => v === hook.vulnId), `${label}: alert field`).toBe(true);
        // Every vuln id string in the output is a SIMVULN id, and it is the hook's.
        const text = JSON.stringify(c) + JSON.stringify(s.corpus);
        const ids = new Set(text.match(/SIMVULN-[\w-]*/g) ?? []);
        expect([...ids], label).toEqual([hook.vulnId]);
        n++;
      }
    }
    expect(n).toBeGreaterThanOrEqual(WORLDS.length * 2);
    expect(dbRuns).toBeGreaterThanOrEqual(2);
    // The two host classes the shipped vuln templates actually produce.
    expect([...hostsSeen].some((k) => k.endsWith('|WEB01'))).toBe(true);
    expect([...hostsSeen].some((k) => k.endsWith('|APP01'))).toBe(true);
  }, 300_000);

  it('every non-mobile host of the world works as a target: structure, grading, synthetic, deterministic', async () => {
    for (const worldName of WORLDS) {
      const w = world(worldName);
      const targets = w.hosts.filter((h) => h.ip !== '' && h.kind !== 'mobile');
      const perOs = new Map<string, number>();
      for (const h of targets) {
        // All servers and appliances, and two workstations per OS.
        if (h.kind === 'laptop' || h.kind === 'desktop') {
          if ((perOs.get(h.os) ?? 0) >= 2) continue;
          perOs.set(h.os, (perOs.get(h.os) ?? 0) + 1);
        }
        const hook = makeHook(h.name, 'SIMVULN-2026-12345', `sweep-${h.name}`);
        const s = await checkHooked(w, hook, false);
        expect(JSON.stringify(buildHooked(w, hook))).toBe(JSON.stringify(s));
        expect(rows(s, 'SecurityAlert').some((r) => r.CompromisedEntity === h.name && String(r.Description).includes(hook.vulnId)), `${worldName}/${h.name}`).toBe(true);
      }
    }
  }, 300_000);

  it('the telemetry fits the host: an exposed host has network rows only, an internal Windows host has process rows', async () => {
    const w = world(WORLDS[0]);
    const web = w.hosts.find((h) => h.name === 'WEB01')!;
    const app = w.hosts.find((h) => h.name === 'APP01')!;
    expect(web.exposed).toBe(true);
    expect(app.exposed).toBe(false);
    expect(app.os.startsWith('Windows')).toBe(true);

    const sWeb = buildHooked(w, makeHook('WEB01', 'SIMVULN-2026-20001', 'fit-web'));
    expect(rows(sWeb, 'DeviceProcessEvents').filter((r) => r.DeviceName === 'WEB01')).toEqual([]);
    expect(rows(sWeb, 'DeviceNetworkEvents').filter((r) => r.DeviceName === 'WEB01')).toEqual([]);
    expect(rows(sWeb, 'DeviceFileEvents').filter((r) => r.DeviceName === 'WEB01')).toEqual([]);
    const inbound = rows(sWeb, 'FirewallLogs').filter((r) => r.Direction === 'Inbound' && r.DestinationIP === w.publicIps.web && r.DestinationPort === 443);
    expect(inbound.length).toBeGreaterThan(0);
    expect(rows(sWeb, 'SecurityAlert').some((r) => String(r.ProductName).includes('firewall') && r.CompromisedEntity === 'WEB01')).toBe(true);
    const out = rows(sWeb, 'FirewallLogs').filter((r) => r.SourceIP === web.ip && r.Direction === 'Outbound');
    expect(new Set(out.map((r) => r.DestinationIP)).size, 'known service plus one new address').toBeGreaterThanOrEqual(2);

    const sApp = buildHooked(w, makeHook('APP01', 'SIMVULN-2026-20002', 'fit-app'));
    const procs = rows(sApp, 'DeviceProcessEvents').filter((r) => r.DeviceName === 'APP01');
    expect(procs.some((r) => r.FileName === 'cmd.exe' && r.InitiatingProcessFileName === 'w3wp.exe')).toBe(true);
    expect(rows(sApp, 'SecurityAlert').some((r) => r.ProductName === 'Microsoft Defender for Endpoint' && r.CompromisedEntity === 'APP01')).toBe(true);
    const net = rows(sApp, 'DeviceNetworkEvents').filter((r) => r.DeviceName === 'APP01' && r.RemotePort === 443);
    expect(net.length).toBeGreaterThan(0);
    // The source of the real hit is an internal address no device owns.
    const real = rows(sApp, 'SecurityAlert').filter((r) => r.CompromisedEntity === 'APP01' && r.Status === 'New');
    expect(real.length).toBeGreaterThan(0);
    for (const r of real) {
      const src = String(r.Entities);
      expect(w.hosts.some((h) => h.ip === src), 'unmanaged source').toBe(false);
      expect(src.startsWith(w.sites[0].prefix)).toBe(true);
    }
  });

  it('look-alikes: the scanner trips the same signature on the host and other servers, resolved, with no follow-on', () => {
    for (const worldName of WORLDS) {
      const w = world(worldName);
      const scan = w.hosts.find((h) => h.name === 'SCAN01')!;
      for (const host of ['WEB01', 'APP01']) {
        const hook = makeHook(host, 'SIMVULN-2026-20003', `look-${host}`);
        const s = buildHooked(w, hook);
        const c = s.cases[0];
        const hits = rows(s, 'SecurityAlert').filter((r) => String(r.Description).includes(hook.vulnId));
        const fromScanner = hits.filter((r) => r.Entities === scan.ip);
        const others = hits.filter((r) => r.Entities !== scan.ip);
        expect(fromScanner.length, `${host}: scanner hits (host plus one or two servers)`).toBeGreaterThanOrEqual(2);
        expect(fromScanner.length).toBeLessThanOrEqual(3);
        expect(fromScanner.some((r) => r.CompromisedEntity === host)).toBe(true);
        expect(new Set(fromScanner.map((r) => r.CompromisedEntity)).size).toBe(fromScanner.length);
        for (const r of fromScanner) expect(r.Status).toBe('Resolved');
        expect(others.length).toBeGreaterThan(0);
        for (const r of others) {
          expect(r.CompromisedEntity).toBe(host);
          expect(r.Status).toBe('New');
        }
        // A search for the id alone does not decide it: it returns the scanner and the real source.
        expect(new Set(hits.map((r) => r.Entities)).size).toBeGreaterThanOrEqual(2);
        // No follow-on from the scanner: nothing it did on the host leaves the host.
        const hostIp = w.hosts.find((h) => h.name === host)!.ip;
        expect(rows(s, 'FirewallLogs').filter((r) => r.SourceIP === hostIp && r.DestinationIP === scan.ip)).toEqual([]);
        expect(rows(s, 'DeviceProcessEvents').filter((r) => r.DeviceName === host && String(r.AccountName).includes('svc-scan'))).toEqual([]);
        // mustNot covers the scanner; the scanner is never in block or scope.
        const must = c.indicators.mustNot.map((i) => i.value);
        expect(must).toContain('SCAN01');
        expect(must).toContain(scan.ip);
        const flagged = new Set([...c.indicators.block, ...c.indicators.scope].map((i) => i.value));
        for (const v of must) expect(flagged.has(v), `${host}: ${v} is both mustNot and flagged`).toBe(false);
      }
    }
  });

  it('the deciding clue is in the tables: nothing readable before submitting names the id, the decision or the vuln case', () => {
    const w = world(WORLDS[0]);
    for (const host of ['WEB01', 'APP01']) {
      const hook = makeHook(host, 'SIMVULN-2026-20004', `neutral-${host}`);
      const c = buildHooked(w, hook).cases[0];
      const text = beforeSubmit(c);
      expect(text).not.toContain(hook.vulnId);
      expect(text).not.toContain('SIMVULN');
      expect(text).not.toContain(hook.caseRef);
      expect(text).not.toMatch(/vulnerability (management )?case|ledger|false positive|accepted the risk|marked/i);
      expect(c.alert.rule).not.toMatch(/SIMVULN|vuln/i);
      // The follow-on that decides it is not stated in the alert or the briefing.
      expect(`${c.alert.summary}\n${c.briefing}`).not.toMatch(/beacon|callback|call out|outbound|compromis|exploited/i);
    }
  });

  it('adds no DomainIntel row and no attacker-role domain', () => {
    for (const worldName of WORLDS) {
      const w = world(worldName);
      for (const host of ['WEB01', 'APP01', 'BUILD01']) {
        const hook = makeHook(host, 'SIMVULN-2026-20005', `dom-${host}`);
        const withItem = buildHooked(w, hook);
        const without = buildHooked(w, hook, false);
        expect(rows(withItem, 'DomainIntel').map((r) => r.Domain)).toEqual(rows(without, 'DomainIntel').map((r) => r.Domain));
        // Remote urls written by the template are empty: attackers are addressed by IP only.
        const c2 = withItem.infra.A1.ips.c2!;
        expect(rows(withItem, 'DeviceNetworkEvents').filter((r) => r.RemoteIP === c2).every((r) => r.RemoteUrl === '')).toBe(true);
        expect(rows(withItem, 'DnsEvents').filter((r) => String(r.IPAddresses).includes(c2))).toEqual([]);
        expect(rows(withItem, 'WebProxy').filter((r) => r.DestinationIP === c2)).toEqual([]);
        expect(withItem.infra.A1.domains).toEqual({});
      }
    }
  });

  it('no CVE-shaped string in the template source or in anything it builds (DESIGN section 9)', () => {
    const src = readFileSync('src/core/cases/templates/vuln-link.ts', 'utf8');
    expect(cveViolations({ label: 'vuln-link.ts', text: src })).toEqual([]);
    const w = world(WORLDS[0]);
    const built: Scenario[] = [buildHooked(w, undefined)];
    for (const host of ['WEB01', 'APP01', 'BUILD01', 'SQL01']) built.push(buildHooked(w, makeHook(host, 'SIMVULN-2026-20006', `cve-${host}`)));
    for (const [i, s] of built.entries()) {
      const text = JSON.stringify(s.cases, null, 1) + '\n' + JSON.stringify(s.corpus, null, 1);
      expect(cveViolations({ label: `built-${i}`, text })).toEqual([]);
      expect(syntheticViolations(s.corpus, w)).toEqual([]);
      const strays = (text.match(/SIMVULN[0-9A-Za-z-]*/g) ?? []).filter((m) => !SIMVULN_ID_PATTERN.test(m));
      expect(strays).toEqual([]);
    }
  });

  it('is solvable on a shared database for every class, with every evidence point surfaced', async () => {
    const w = world(WORLDS[1]);
    for (const host of ['WEB01', 'APP01', 'BUILD01']) {
      const s = buildHooked(w, makeHook(host, 'SIMVULN-2026-20007', `solve-${host}`));
      const db = new SiemDatabase(await sqljs(), s.corpus);
      try {
        await checkSolvable(s, s.cases[0], db);
      } finally {
        db.close();
      }
    }
  });

  // ---- fix round 1 (WP5 A1-A6)
  const ms = (v: unknown) => Date.parse(String(v));

  it('A1: the ATT&CK key fits the host class: T1190 on the edge, T1210 from an internal source (T1190 accepted), tactics a subset of the template union', () => {
    const w = world(WORLDS[0]);
    const t = templateById(ID)!;
    expect(t.tactics).toEqual(['initial-access', 'lateral-movement', 'command-and-control']);
    for (const [host, edge] of [['WEB01', true], ['VPN01', true], ['APP01', false], ['BUILD01', false], ['SQL01', false]] as const) {
      const c = buildHooked(w, makeHook(host, 'SIMVULN-2026-30001', `a1-${host}`)).cases[0];
      const label = `${host}`;
      if (edge) {
        expect(c.truth.techniques, label).toEqual(['T1190', 'T1071.001']);
        expect(c.truth.tactics, label).toEqual(['initial-access', 'command-and-control']);
        expect(c.truth.alsoAccept ?? [], label).not.toContain('T1190');
        expect(c.references.map((r) => r.label), label).toContain('ATT&CK T1190');
      } else {
        expect(c.truth.techniques, label).toEqual(['T1210', 'T1071.001']);
        expect(c.truth.alsoAccept, label).toContain('T1190');
        expect(c.truth.tactics, label).toEqual(['lateral-movement', 'command-and-control']);
        expect(c.references.map((r) => r.label), label).toContain('ATT&CK T1210');
        expect(c.references.map((r) => r.label), label).not.toContain('ATT&CK T1190');
        // the attacker is already inside: the source device must be found and contained too
        const text = [...c.explanation, ...c.pitfalls, ...c.rubric.map((x) => x.text)].join('\n');
        expect(text, label).toMatch(/already inside/i);
        expect(c.explanation.join('\n'), label).toMatch(/find that source device and contain it/i);
        expect(c.rubric.find((x) => x.id === 'contain')!.text, label).toMatch(/internal source device/i);
      }
      for (const tac of c.truth.tactics) expect(t.tactics, label).toContain(tac);
    }
  });

  // A hooked item at a given local hour of a weekday, with an optional second item.
  function buildAtHour(w: World, hook: VulnHook, hour: number, extra: { templateId: string; offsetMin: number }[] = [], context?: (b: Parameters<NonNullable<Parameters<typeof buildScenario>[0]['context']>>[0], now: number) => void): Scenario {
    const { at: base } = practiceTiming(ID, hook.seed, 'business', w.org.utcOffset);
    const at = atLocalHour(base + 12 * HOUR, hour, w.org.utcOffset);
    const now = at + 6 * HOUR;
    return buildScenario({
      world: w,
      seed: `hooked-hour:${hook.seed}:${hour}`,
      now,
      windowHours: 30,
      items: [...extra.map((x, i) => ({ alertId: `X${i}`, templateId: x.templateId, seed: `x-${hook.seed}`, at: at + x.offsetMin * MIN })), { alertId: 'A1', templateId: ID, seed: hook.seed, at, vulnHook: hook }],
      historyFiller: true,
      context: context ? (b) => context(b, now) : undefined,
    });
  }
  const scannerTicket = (s: Scenario) => rows(s, 'Tickets').filter((r) => r.Type === 'Change' && r.AssignedTo === 'svc-scan');
  const scanRows = (s: Scenario, w: World, hostName: string) => {
    const scan = w.hosts.find((h) => h.name === 'SCAN01')!;
    const ip = w.hosts.find((h) => h.name === hostName)!.ip;
    return rows(s, 'FirewallLogs').filter((r) => r.SourceIP === scan.ip && r.DestinationIP === ip && r.RuleName === 'allow-scanner');
  };

  it('A2: the template is a business-hours item and the scan starts inside the window the ticket states, from the earliest to the latest planned alert', () => {
    expect(templateById(ID)!.when).toBe('business');
    for (const worldName of WORLDS) {
      const w = world(worldName);
      for (const hour of [9.2, 10.5, 13, 16.9]) {
        for (const host of ['WEB01', 'APP01']) {
          const hook = makeHook(host, 'SIMVULN-2026-30002', `a2-${host}-${hour}`);
          const s = buildAtHour(w, hook, hour);
          const label = `${worldName}/${host}/${hour}`;
          const tickets = scannerTicket(s);
          expect(tickets.length, label).toBe(1);
          const ws = ms(tickets[0].WindowStart);
          const we = ms(tickets[0].WindowEnd);
          expect(localHour(ws, w.org.utcOffset), label).toBeGreaterThanOrEqual(8);
          expect(localHour(we, w.org.utcOffset), label).toBeLessThanOrEqual(18.001);
          const first = Math.min(...scanRows(s, w, host).map((r) => ms(r.TimeGenerated)));
          expect(first, label).toBeGreaterThanOrEqual(ws);
          expect(first, label).toBeLessThan(we);
          expect(localHour(first, w.org.utcOffset), label).toBeGreaterThanOrEqual(8);
          expect(localHour(first, w.org.utcOffset), label).toBeLessThan(18);
          // and before the real exploitation
          const real = rows(s, 'SecurityAlert').filter((r) => r.CompromisedEntity === host && r.Status === 'New');
          expect(first, label).toBeLessThan(Math.min(...real.map((r) => ms(r.TimeGenerated))));
        }
      }
    }
  });

  it('A3: three ticket paths: reuse the standing approval when its window holds the scan, a one-off change when it cannot, its own standing approval when none exists; never two standing approvals', async () => {
    const standing = (s: Scenario) => scannerTicket(s).filter((r) => String(r.Title).toLowerCase().includes('standing approval'));
    const w = world(WORLDS[0]);
    const twinId = 'network-authorized-vulnscan';
    for (const host of ['WEB01', 'APP01']) {
      const hook = makeHook(host, 'SIMVULN-2026-30003', `a3-${host}`);
      // reuse path: the scheduled scan's approval opens before this alert
      const shared = buildAtHour(w, hook, 12, [{ templateId: twinId, offsetMin: -20 }]);
      const tickets = scannerTicket(shared);
      expect(tickets.map((r) => r.TicketId), `${host}: one svc-scan change`).toEqual(['CHG-STD-0007']);
      expect(standing(shared), `${host}: one standing approval`).toHaveLength(1);
      const c = shared.cases.find((x) => x.alertId === 'A1')!;
      const scannerEvidence = c.evidence.find((e) => e.id === 'scanner')!;
      expect(scannerEvidence.recordIds).toContain(String(tickets[0].RecordId));
      const ws = ms(tickets[0].WindowStart);
      const we = ms(tickets[0].WindowEnd);
      const times = scanRows(shared, w, host).map((r) => ms(r.TimeGenerated));
      expect(times.length).toBeGreaterThan(0);
      for (const t of times) {
        expect(t, host).toBeGreaterThanOrEqual(ws);
        expect(t, host).toBeLessThanOrEqual(we);
      }
      checkStructure(c);
      checkGrading(c);
      const db = new SiemDatabase(await sqljs(), shared.corpus);
      try {
        await checkSolvable(shared, c, db);
      } finally {
        db.close();
      }

      // own path: no other scanner ticket in the shift, and the item writes its own
      const alone = buildAtHour(w, hook, 12);
      const own = scannerTicket(alone);
      expect(own, host).toHaveLength(1);
      expect(own[0].TicketId).not.toBe('CHG-STD-0007');
      expect(standing(alone), `${host}: own standing approval`).toHaveLength(1);
      expect(alone.cases[0].evidence.find((e) => e.id === 'scanner')!.recordIds).toContain(String(own[0].RecordId));

      // one-off path: the existing approval opens after this alert, so its window cannot hold this scan
      const late = buildAtHour(w, hook, 10, [{ templateId: twinId, offsetMin: 300 }]);
      const lateTickets = scannerTicket(late);
      expect(lateTickets, `${host}: the late approval cannot hold the earlier scan`).toHaveLength(2);
      expect(standing(late), `${host}: still one standing approval`).toHaveLength(1);
      expect(standing(late)[0].TicketId).toBe('CHG-STD-0007');
      const mine = late.cases.find((x) => x.alertId === 'A1')!.evidence.find((e) => e.id === 'scanner')!.recordIds;
      const ownRow = lateTickets.find((r) => r.TicketId !== 'CHG-STD-0007')!;
      expect(mine).toContain(String(ownRow.RecordId));
      expect(mine).not.toContain(String(standing(late)[0].RecordId));
      expect(String(ownRow.Title), host).toMatch(/one-off/i);
      expect(String(ownRow.Details), host).not.toMatch(/standing approval|weekly/i);
      const lateCase = late.cases.find((x) => x.alertId === 'A1')!;
      for (const name of [host, ...lateCase.indicators.mustNot.filter((i) => i.kind === 'host' && i.value !== 'SCAN01').map((i) => i.value)]) expect(String(ownRow.Scope), `${host}: scope names ${name}`).toContain(name);
      const firstReal = Math.min(...rows(late, 'SecurityAlert').filter((r) => r.CompromisedEntity === host && r.Status === 'New').map((r) => ms(r.TimeGenerated)));
      // only this item's own scan: the late approval's scheduled scan runs after it
      const early = scanRows(late, w, host).map((r) => ms(r.TimeGenerated)).filter((t) => t < firstReal);
      expect(early.length, host).toBeGreaterThan(0);
      for (const t of early) {
        expect(t).toBeGreaterThanOrEqual(ms(ownRow.WindowStart));
        expect(t).toBeLessThanOrEqual(ms(ownRow.WindowEnd));
      }
      // the solution step does not claim a scope or a standing approval the ticket lacks
      const approvalStep = lateCase.solution.find((x) => x.title === 'Is the scan approved?')!;
      expect(approvalStep.why, host).not.toMatch(/standing|all server VLANs/i);
      expect(approvalStep.why, host).toMatch(/one-off/i);
      const reuseStep = shared.cases.find((x) => x.alertId === 'A1')!.solution.find((x) => x.title === 'Is the scan approved?')!;
      expect(reuseStep.why, host).not.toMatch(/all server VLANs|DMZ/i);
      const ownStep = alone.cases[0].solution.find((x) => x.title === 'Is the scan approved?')!;
      expect(ownStep.why, host).toMatch(/standing approval/i);
    }
  }, 120_000);

  it('A8/A9: network-class text is true for every host; with SCAN01 as the target there is no scanner and no two-source wording', () => {
    for (const worldName of WORLDS) {
      const w = world(worldName);
      for (const h of w.hosts.filter((x) => x.kind !== 'mobile' && x.ip !== '')) {
        const s = buildHooked(w, makeHook(h.name, 'SIMVULN-2026-30008', `a8-${h.name}`));
        const c = s.cases[0];
        const label = `${worldName}/${h.name}`;
        const text = [...c.explanation, ...c.pitfalls, ...c.rubric.map((x) => x.text), ...c.hints, ...c.solution.map((x) => x.why)].join('\n');
        expect(text, label).not.toMatch(/no process telemetry/i);
        if (h.name === 'SCAN01') {
          expect(c.hints.join('\n'), label).not.toMatch(/more than one source/i);
          expect(text, label).not.toMatch(/two (different )?sources|scanner's earlier hits/i);
          expect(c.alert.summary, label).toMatch(/from 1 different source address\./);
        }
      }
    }
  });

  it('A4: scanner look-alikes carry their own host class and stay on web ports unless the finding itself is on another port', () => {
    const productFor = (h: { exposed: boolean; name: string }) => (h.exposed ? 'Perimeter firewall (intrusion prevention)' : h.name === 'APP01' ? 'Microsoft Defender for Endpoint' : 'Network Detection & Response');
    for (const worldName of WORLDS) {
      const w = world(worldName);
      const scan = w.hosts.find((h) => h.name === 'SCAN01')!;
      for (const host of ['WEB01', 'APP01', 'SQL01', 'FS01', 'JUMP01', 'BUILD01']) {
        const hook = makeHook(host, 'SIMVULN-2026-30004', `a4-${host}`);
        const s = buildHooked(w, hook);
        const hits = rows(s, 'SecurityAlert').filter((r) => String(r.Description).includes(hook.vulnId));
        const targetPort = Number(/to \S+?:(\d+)/.exec(String(hits.find((r) => r.CompromisedEntity === host && r.Status === 'New')!.Description))![1]);
        const scanned = hits.filter((r) => r.Entities === scan.ip);
        expect(scanned.some((r) => r.CompromisedEntity === host), `${worldName}/${host}`).toBe(true);
        for (const r of hits) {
          const on = w.hosts.find((h) => h.name === r.CompromisedEntity)!;
          const label = `${worldName}/${host}: ${on.name}`;
          expect(r.ProductName, label).toBe(productFor(on));
          const m = /to (\S+?):(\d+)/.exec(String(r.Description))!;
          const p = Number(m[2]);
          if ([445, 1433, 3389].includes(p)) expect(p, `${label}: an SMB, SQL or RDP signature only where the finding is`).toBe(targetPort);
          expect(String(r.Description).includes('Detect mode'), label).toBe(productFor(on) !== 'Microsoft Defender for Endpoint');
          // real and scanner hits on one host read the same, apart from the source
          expect(r.Tactics, label).toBe(on.exposed ? 'InitialAccess' : 'LateralMovement');
        }
        // a finding on SMB, SQL or RDP gets no web look-alikes; a web finding gets web ones only
        const ports = new Set(hits.map((r) => Number(/to \S+?:(\d+)/.exec(String(r.Description))![1])));
        if ([445, 1433, 3389].includes(targetPort)) expect([...ports]).toEqual([targetPort]);
        else for (const p of ports) expect([443, 8443]).toContain(p);
      }
    }
  });

  it('A4/A5: only the IIS application server gets the w3wp and monitoring story; edge wording follows the role', () => {
    const w = world(WORLDS[0]);
    const iis = (s: Scenario, host: string) => rows(s, 'DeviceProcessEvents').filter((r) => r.DeviceName === host && (r.InitiatingProcessFileName === 'w3wp.exe' || r.AccountName === 'svc-monitor'));
    const targets = w.hosts.filter((h) => h.ip !== '' && h.kind !== 'mobile' && h.name !== 'APP01' && !h.exposed);
    expect(targets.length).toBeGreaterThan(3);
    for (const h of targets) {
      const s = buildHooked(w, makeHook(h.name, 'SIMVULN-2026-30005', `a5-${h.name}`));
      expect(iis(s, h.name), `${h.name}: no IIS story`).toEqual([]);
      expect(rows(s, 'DeviceProcessEvents').filter((r) => r.DeviceName === h.name && /whoami|DownloadFile/.test(String(r.ProcessCommandLine))), `${h.name}: network-level only`).toEqual([]);
      expect(s.cases[0].evidence.some((e) => e.id === 'followon'), h.name).toBe(true);
      expect(s.cases[0].evidence.some((e) => e.id === 'chain'), h.name).toBe(false);
    }
    expect(iis(buildHooked(w, makeHook('APP01', 'SIMVULN-2026-30005', 'a5-app')), 'APP01').length).toBeGreaterThan(0);

    const web = buildHooked(w, makeHook('WEB01', 'SIMVULN-2026-30006', 'a5-web')).cases[0];
    const vpn = buildHooked(w, makeHook('VPN01', 'SIMVULN-2026-30006', 'a5-vpn')).cases[0];
    const text = (c: ResolvedCase) => [...c.evidence.map((e) => e.why), ...c.explanation].join('\n');
    expect(text(web)).toMatch(/public web server/i);
    expect(text(vpn)).toMatch(/VPN concentrator/i);
    expect(text(vpn)).not.toMatch(/web server/i);
  });

  it('A6: the unmanaged internal source never reuses an address another alert of the shift already has in its rows', () => {
    const w = world(WORLDS[0]);
    const hook = makeHook('APP01', 'SIMVULN-2026-30007', 'a6');
    const sourceOf = (s: Scenario) => String(rows(s, 'SecurityAlert').find((r) => r.CompromisedEntity === 'APP01' && r.Status === 'New')!.Entities);
    const base = buildAtHour(w, hook, 12);
    const taken = sourceOf(base);
    const seed = (kind: 'fw-src' | 'fw-dst' | 'sec' | 'net-local' | 'net-remote') => (b: Parameters<NonNullable<Parameters<typeof buildScenario>[0]['context']>>[0], now: number) => {
      const t = now - 7 * HOUR;
      const fw = (src: string, dst: string) => b.fw({ TimeGenerated: t, Direction: 'Internal', Action: 'Allow', Protocol: 'TCP', SourceIP: src, SourcePort: 50000, DestinationIP: dst, DestinationPort: 8080, RuleName: 'allow-internal-https', BytesSent: 500, BytesReceived: 900, SessionDurationSec: 1 });
      if (kind === 'fw-src') fw(taken, w.hosts.find((h) => h.name === 'FS01')!.ip);
      if (kind === 'fw-dst') fw(w.hosts.find((h) => h.name === 'FS01')!.ip, taken);
      if (kind === 'sec') b.sec({ TimeGenerated: t, Computer: 'FS01', EventID: 4625, Account: 'nobody', TargetAccount: 'nobody', LogonType: 3, IpAddress: taken, WorkstationName: 'X', AuthenticationPackage: 'NTLM', ElevatedToken: 'No' });
      if (kind === 'net-local' || kind === 'net-remote') b.net({ TimeGenerated: t, DeviceName: 'FS01', LocalIP: kind === 'net-local' ? taken : w.hosts.find((h) => h.name === 'FS01')!.ip, RemoteIP: kind === 'net-remote' ? taken : '203.0.113.9', RemotePort: 443, RemoteUrl: '', InitiatingProcessFileName: 'x.exe', InitiatingProcessAccountName: 'SYSTEM' });
    };
    for (const kind of ['fw-src', 'fw-dst', 'sec', 'net-local', 'net-remote'] as const) {
      const s = buildAtHour(w, hook, 12, [], seed(kind));
      const src = sourceOf(s);
      expect(src, kind).not.toBe(taken);
      // the new address is not in any row of another alert either
      const inRows = (table: keyof Scenario['corpus']['tables'], cols: string[]) => rows(s, table).filter((r) => cols.some((c) => r[c] === src));
      const own = inRows('FirewallLogs', ['SourceIP', 'DestinationIP']).every((r) => r.DestinationPort === 8443 || r.SourceIP === src);
      expect(own, kind).toBe(true);
      expect(inRows('SecurityEvent', ['IpAddress']), kind).toEqual([]);
      expect(inRows('DeviceNetworkEvents', ['LocalIP', 'RemoteIP']), kind).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------------------
// End to end: planned and built shifts with the real template and hooks taken from real vuln
// builds, over several worlds and shift numbers, with and without an active campaign (WP5 W5, W7, W8).

describe('a hooked shift, end to end', () => {
  const SHIFT_WORLDS = ['shift-plan', 'shift-world-1', 'hook-world-0'];
  const SHIFTS = [0, 1, 2, 5];

  // Real ledger entries: a real attempt's caseRef is the template its seed resolves to, so a (template, seed)
  // pair the seed would not resolve to is not a case a learner can have played.
  const resolves = (caseRef: string) => {
    const [templateId, ...rest] = caseRef.split('~');
    const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.templates.some((x) => x.id === templateId));
    return !!type && resolveVulnTemplate(type, rest.join('~')).id === templateId;
  };
  const entries = (worldName: string) =>
    eligibleHooks(worldName, ['e0', 'e1', 'e2', 'e3', 'e4', 'e5']).filter(({ hook }) => resolves(hook.ledgerId.split('/')[0])).map(({ hook }) => ({
      id: hook.ledgerId,
      vulnId: hook.vulnId,
      host: hook.host,
      decision: hook.decision,
      schedule: hook.schedule,
      decidedDay: hook.decidedDay,
      caseRef: hook.ledgerId.split('/')[0],
    }));

  const key = (it: { templateId: string; seed: string; at: number }) => `${it.templateId}|${it.seed}|${it.at}`;

  // Rows as content, because RecordIds are positions in the whole corpus.
  function content(s: Scenario, c: ResolvedCase): { id: string; rows: string[] }[] {
    const byId = new Map<string, string>();
    for (const [table, t] of Object.entries(s.corpus.tables)) {
      const at = t.columns.indexOf('RecordId');
      if (at < 0) continue;
      for (const r of t.rows) byId.set(String(r[at]), `${table}|${JSON.stringify(r.filter((_, i) => i !== at))}`);
    }
    return c.evidence.map((e) => ({ id: e.id, rows: e.recordIds.map((id) => byId.get(id) ?? `missing:${id}`).sort() }));
  }

  it('W5 and W8: the same shift plus one hook item; every other case identical; the link on the hook case only', () => {
    let hooked = 0;
    for (const [wi, ws] of SHIFT_WORLDS.entries()) {
      const w = world(ws);
      const ledger = entries(ws);
      expect(ledger.length, ws).toBeGreaterThan(0);
      for (const n of SHIFTS) {
        for (const campaign of [false, true]) {
          const seed = `e2e-${wi}-${n}-${campaign}`;
          const state = campaign ? startCampaign(w, `e2e-c-${wi}`) : null;
          const slot = state ? campaignSlot(state, w, n) : undefined;
          const ctx = state ? campaignContext(state, w, n) : undefined;
          // one different entry per shift, so the sweep reaches different hosts and ids
          const entry = ledger[(wi * 7 + n * 3 + (campaign ? 1 : 0)) % ledger.length];
          const hook = selectVulnFollowUp([entry], shiftSeedFor(seed, n))!;
          const base = { world: w, seed, number: n, campaign: slot };
          const label = `${ws}/${n}/${campaign}/${entry.host}`;

          const without = planShift(base);
          const withHook = planShift({ ...base, vulnHook: hook });
          const hookItems = withHook.items.filter((x) => x.vulnHook);
          expect(hookItems, label).toHaveLength(1);
          expect(hookItems[0].templateId).toBe(VULN_LINK_TEMPLATE_ID);
          expect(hookItems[0].campaign).toBeUndefined();
          expect(withHook.items.filter((x) => !x.vulnHook).map(key).sort(), label).toEqual(without.items.map(key).sort());
          expect(withHook.campaignAlertId === undefined, label).toBe(without.campaignAlertId === undefined);

          const a = buildShift(w, without, ctx);
          const b = buildShift(w, withHook, ctx);
          expect(b.cases.map((c) => c.alertId), label).toEqual(withHook.items.map((x) => x.alertId));
          expect(b.cases).toHaveLength(a.cases.length + 1);

          // W8: the link is on exactly the hook case, and it is the hook's
          const linked = b.cases.filter((c) => c.vulnLink);
          expect(linked, label).toHaveLength(1);
          expect(linked[0].alertId).toBe(hookItems[0].alertId);
          expect(linked[0].templateId).toBe(VULN_LINK_TEMPLATE_ID);
          expect(linked[0].vulnLink).toEqual({ caseRef: hook.caseRef, vulnId: hook.vulnId, host: hook.host, decision: hook.decision, schedule: hook.schedule });
          expect(a.cases.some((c) => c.vulnLink)).toBe(false);

          // W5: every other case, its infrastructure and its evidence rows, as without the hook
          const others = b.cases.filter((x) => !x.vulnLink);
          expect(others.map((c) => c.templateId).sort(), label).toEqual(a.cases.map((c) => c.templateId).sort());
          for (const c of others) {
            const mate = a.cases.find((x) => x.templateId === c.templateId)!;
            expect(b.infra[c.alertId], `${label}/${c.templateId}`).toEqual(a.infra[mate.alertId]);
            expect(c.alert, `${label}/${c.templateId}`).toEqual(mate.alert);
            expect(c.truth).toEqual(mate.truth);
            expect(c.indicators).toEqual(mate.indicators);
            expect(content(b, c), `${label}/${c.templateId}`).toEqual(content(a, mate));
          }

          // the hook case: the host and the id are in its rows, and nothing before submit mentions the vuln case
          const rowText = JSON.stringify(content(b, linked[0]));
          expect(rowText, label).toContain(hook.host);
          expect(rowText, label).toContain(hook.vulnId);
          expect(beforeSubmit(linked[0]), label).not.toMatch(/vulnerability case|ledger|SIMVULN/i);

          // W8: the debrief link resolves and round-trips to the registered vuln template
          const r = resolveVulnLink(linked[0].vulnLink!)!;
          expect(r, label).not.toBeNull();
          const [templateId, ...rest] = hook.caseRef.split('~');
          const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.templates.some((x) => x.id === templateId))!;
          expect(resolveVulnTemplate(type, rest.join('~')).id).toBe(templateId);
          expect(r.href).toContain(type.slug);
          expect(r.href.endsWith(rest.join('~'))).toBe(true);

          // deterministic
          expect(JSON.stringify(buildShift(w, planShift({ ...base, vulnHook: hook }), ctx))).toBe(JSON.stringify(b));
          hooked++;
        }
      }
    }
    expect(hooked).toBe(SHIFT_WORLDS.length * SHIFTS.length * 2);
  });

  it('is solvable and gradeable, with every other alert as background, on a campaign shift', async () => {
    const w = world(SHIFT_WORLDS[0]);
    const ledger = entries(SHIFT_WORLDS[0]);
    const state = startCampaign(w, 'e2e-solve');
    const n = 1;
    const hook = selectVulnFollowUp([ledger[0]], shiftSeedFor('e2e-solve', n))!;
    const plan = planShift({ world: w, seed: 'e2e-solve', number: n, campaign: campaignSlot(state, w, n)!, vulnHook: hook });
    const s = buildShift(w, plan, campaignContext(state, w, n));
    expect(syntheticViolations(s.corpus, w)).toEqual([]);
    const db = new SiemDatabase(await sqljs(), s.corpus);
    try {
      for (const c of s.cases) {
        checkStructure(c);
        checkGrading(c);
        await checkSolvable(s, c, db);
      }
    } finally {
      db.close();
    }
  });

  // W7: alert ids are positions in a shift's queue, so they are read through the template behind each id.
  const named = (state: CampaignState, built: Record<number, Scenario>): string => {
    const label = (e: { shift: number }) => {
      const tpl = new Map(built[e.shift].cases.map((c) => [c.alertId, c.templateId]));
      return JSON.stringify(e).replace(/\bA\d+\b/g, (id) => `<${tpl.get(id) ?? id}>`);
    };
    return JSON.stringify({ ...state, log: state.log.map(label), intel: state.intel.map(label) });
  };

  for (const policy of ['catch', 'miss'] as const) {
    it(`W7: a campaign played with a hook alert every shift ends deep-equal to one played without (${policy})`, () => {
      const w = world('shift-plan');
      const ledger = entries('shift-plan');
      const miss = (c: ResolvedCase): Verdict => ({ ...perfectVerdict(c), disposition: 'benign', action: 'close', techniques: [], indicators: [] });
      const verdict = (c: ResolvedCase, campaignAlertId?: string): Verdict => (c.vulnLink ? miss(c) : policy === 'miss' && c.alertId === campaignAlertId ? miss(c) : perfectVerdict(c));
      const seed = `e2e-w7-${policy}`;
      let a = startCampaign(w, seed);
      let b = a;
      const seenA: Record<number, Scenario> = {};
      const seenB: Record<number, Scenario> = {};
      let turns = 0;
      for (let n = 0; n < 6 && a.status === 'active'; n++) {
        expect(b.status).toBe('active');
        const slot = campaignSlot(a, w, n)!;
        const hook = selectVulnFollowUp([ledger[n % ledger.length]], shiftSeedFor(seed, n))!;
        const base = { world: w, seed, number: n, campaign: slot };
        const planA = planShift(base);
        const planB = planShift({ ...base, vulnHook: hook });
        const ctx = campaignContext(a, w, n);
        const sa = buildShift(w, planA, ctx);
        const sb = buildShift(w, planB, ctx);
        const subs = (s: Scenario, campaignAlertId?: string): Submission[] => s.cases.map((c, i) => ({ alertId: c.alertId, verdict: verdict(c, campaignAlertId), atSec: 60 * (i + 1) }));
        const ra = scoreShift(sa.cases, subs(sa, planA.campaignAlertId));
        const rb = scoreShift(sb.cases, subs(sb, planB.campaignAlertId));
        const nextA = recordShift(a, w, n, sa.infra, ra, planA.campaignAlertId);
        const nextB = recordShift(b, w, n, sb.infra, rb, planB.campaignAlertId);
        seenA[n] = sa;
        seenB[n] = sb;
        expect(named(nextB, seenB), `shift ${n}`).toBe(named(nextA, seenA));
        expect(nextB.history.map((h) => h.id)).toEqual(nextA.history.map((h) => h.id));
        a = nextA;
        b = nextB;
        turns++;
      }
      expect(turns).toBeGreaterThan(1);
    });
  }
});
