import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { resolveVulnTemplate, vulnCaseTypes } from '../src/core/vuln/worklist.ts';
import { buildVulnScenario } from '../src/core/vuln/scenario.ts';
import { generateWorld } from '../src/core/world/world.ts';

// WP7 accessibility instrument: the FULL axe rule set (no tag filter: best practice rules included) on every vuln-related
// screen and state, in light and dark, at 1280, 360 and 320 px, plus "no horizontal page scroll" at 360 and 320 px.
// Each state is swept by `sweep`, which collects problems instead of stopping at the first one, so a single run lists
// every violation. A test ends with `expect(problems).toEqual([])`.

const PROFILE = { version: 2, worldSeed: 'e2e-world', analystName: 'E2E', attempts: [] };
const WORLD = generateWorld(PROFILE.worldSeed);
const CASE_T1 = '#/vuln/scan-review-internal-servers/e2e';
const CASE_T2 = '#/vuln/scan-review-web-servers/e2e';
const CASE_T3 = '#/vuln/scan-review-shared-services-and-payment-systems/e2e';
const CASE_CONTROLS = '#/vuln/scan-review-edge-and-internal-servers/e2e-ctl';
const CASE_UNUSED = '#/vuln/scan-review-optional-admin-consoles-and-internal-servers/e2e-x';

const SCHEMES = ['light', 'dark'] as const;
const WIDTHS = [1280, 360, 320] as const;

async function withProfile(page: Page, profile: object | null = PROFILE): Promise<void> {
  await page.addInitScript((p) => {
    if (p && !localStorage.getItem('soc-triage-sim:v2')) localStorage.setItem('soc-triage-sim:v2', JSON.stringify(p));
  }, profile);
}

function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console: ${m.text()}`);
  });
  return errors;
}

const still = (page: Page) => page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
const overflow = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
// The widest elements that stick out of the viewport, to name the cause of a sideways scroll.
const culprits = (page: Page) =>
  page.evaluate(() => {
    const w = document.documentElement.clientWidth;
    const name = (e: Element) => `${e.tagName.toLowerCase()}${e.id ? '#' + e.id : ''}${e.classList.length ? '.' + [...e.classList].join('.') : ''}`;
    return [...document.body.querySelectorAll('*')]
      .filter((e) => e.getBoundingClientRect().right > w + 0.5 && e.getBoundingClientRect().width > 0)
      .sort((a, b) => b.getBoundingClientRect().right - a.getBoundingClientRect().right)
      .slice(0, 4)
      .map((e) => `${name(e)} right=${Math.round(e.getBoundingClientRect().right)}`)
      .join('; ') +
    ' | wide content: ' +
    [...document.body.querySelectorAll('*')]
      .filter((e) => e.scrollWidth > e.clientWidth + 0.5 && e.clientWidth > 0 && getComputedStyle(e).overflowX === 'visible')
      .slice(-5)
      .map((e) => `${name(e)} scroll=${e.scrollWidth} client=${e.clientWidth}`)
      .join('; ');
  });
const heightFor = (w: number) => (w === 1280 ? 900 : 740);

// One sweep of the current state: every width x theme. A problem is a violation (any impact, full rule set) or a page
// that scrolls sideways at 360/320 px. The page is left at 1280 px in light, the state it was in for interaction.
async function sweep(page: Page, problems: string[], label: string): Promise<void> {
  const seen = new Map<string, string[]>();
  const note = (key: string, where: string) => seen.set(key, [...(seen.get(key) ?? []), where]);
  for (const width of WIDTHS) {
    await page.setViewportSize({ width, height: heightFor(width) });
    for (const scheme of SCHEMES) {
      await page.emulateMedia({ colorScheme: scheme });
      await still(page);
      const where = `${width}/${scheme}`;
      const r = await new AxeBuilder({ page }).analyze();
      for (const v of r.violations) note(`${v.id} (${v.impact}) ${v.help}: ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')}`, where);
      if (width < 1280 && scheme === 'light') {
        const o = await overflow(page);
        if (o > 0) note(`page scrolls sideways by ${o}px (${await culprits(page)})`, where);
      }
    }
  }
  for (const [k, w] of seen) problems.push(`${label}: ${k} [${w.join(', ')}]`);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.emulateMedia({ colorScheme: 'light' });
  await still(page);
}

const rowIds = (page: Page): Promise<string[]> => page.locator('tbody.wl-finding, li.wl-card').evaluateAll((els) => els.map((e) => e.getAttribute('data-finding-id')!));

async function openCase(page: Page, hash: string): Promise<void> {
  await page.goto(`/${hash}`);
  await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('main h1')).toBeFocused();
}

// The built case behind a hash (the same world and seed the page uses), for the right answers.
function built(hash: string) {
  const [, slug, seed] = hash.match(/#\/vuln\/([^/]+)\/([^/]+)$/)!;
  const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.slug === slug)!;
  const t = resolveVulnTemplate(type, seed);
  return buildVulnScenario({ worldSeed: PROFILE.worldSeed, templateId: t.id, seed, world: WORLD }).case;
}

// The submit button is aria-disabled while answers are missing, so Playwright's click waits for it: focus it and press Enter.
async function pressSubmit(page: Page): Promise<void> {
  await page.locator('#vc-submit-btn').focus();
  await page.keyboard.press('Enter');
}

async function runQuery(page: Page, q: string): Promise<void> {
  await page.locator('.cm-content').click();
  await page.keyboard.press('Control+A');
  await page.keyboard.press('Delete');
  await page.keyboard.insertText(q);
  await page.keyboard.press('Control+Enter');
  await expect(page.locator('.results-meta')).toBeVisible();
}

async function pinOne(page: Page): Promise<void> {
  await page.locator('#vc-tab-console').click();
  await runQuery(page, 'VulnIntel\n| take 5');
  await page.getByRole('button', { name: 'Pin row 1 as evidence' }).click();
  await expect(page.locator('.vc-submit .pins li')).toHaveCount(1);
}

type Case = ReturnType<typeof built>;
type Finding = Case['findings'][number];

// Answers one finding from its truth: decision, control (when asked), schedule, reasons (checked in the open panel).
async function answer(page: Page, f: Finding, schedule = f.truth.schedule): Promise<void> {
  const id = `#wl-${f.findingId}`;
  await page.locator(`${id}-decision`).selectOption(f.truth.decision);
  if (f.truth.decision === 'mitigate' && f.truth.mitigation?.length && (await page.locator(`${id}-control`).count()) > 0) {
    await page.locator(`${id}-control`).selectOption(f.truth.mitigation[0]);
  }
  await page.locator(`${id}-schedule`).selectOption(schedule);
  const reasons = f.truth.reasons.slice(0, 3);
  if (reasons.length > 0) {
    const toggle = page.locator(`${id}-reasons`);
    await toggle.click();
    for (const code of reasons) await page.locator(`${id}-reason-${code}`).setChecked(true);
    await toggle.click();
  }
}

// Every finding right and in the ideal order (a lesson finding may be scheduled too late), evidence pinned, submitted.
async function solveAndSubmit(page: Page, c: Case, lateLesson = false): Promise<string | null> {
  const lesson = c.findings.find((f) => f.lesson && f.truth.slaLatest && f.truth.slaLatest !== 'none') ?? null;
  for (const f of c.findings) await answer(page, f, lateLesson && f === lesson ? 'none' : f.truth.schedule);
  for (const [k, id] of c.idealOrder.entries()) {
    await page.locator(`#wl-${id}-prio`).click();
    await page.keyboard.press('Control+A');
    await page.keyboard.type(String(k + 1));
    await page.keyboard.press('Tab');
  }
  await pinOne(page);
  await pressSubmit(page);
  await expect(page.locator('#debrief-h')).toBeVisible();
  return lesson?.findingId ?? null;
}

// The states of an open case: worklist with answers and reasons, a hint, the console with a result and a pin, the note, the gate.
async function caseStates(page: Page, problems: string[], hash: string, tag: string): Promise<void> {
  const c = built(hash);
  await openCase(page, hash);
  await sweep(page, problems, `${tag} case, fresh`);

  const ids = await rowIds(page);
  const first = c.findings.find((f) => f.findingId === ids[0])!;
  const second = c.findings.find((f) => f.findingId === ids[1])!;
  await answer(page, first);
  await page.locator(`#wl-${second.findingId}-decision`).selectOption('avoid');
  await page.locator(`#wl-${first.findingId}-reasons`).click();
  await sweep(page, problems, `${tag} case, decision, schedule and reasons set, reasons panel open`);
  await page.locator(`#wl-${first.findingId}-reasons`).click();
  await sweep(page, problems, `${tag} case, decision, schedule and reasons set, panel closed, avoid chosen`);

  await page.getByRole('button', { name: /^Reveal hint/ }).click();
  await expect(page.locator('#vc-hint-0')).toBeFocused();
  await sweep(page, problems, `${tag} case, hint 1 revealed`);

  await pinOne(page);
  await sweep(page, problems, `${tag} case, console with a query result and a pin`);

  await page.locator('#vc-tab-note').click();
  await page.locator('#vc-note').fill('Patch the exposed host first; the rest follows the next window. Owner: platform team.');
  await sweep(page, problems, `${tag} case, note tab`);

  await pressSubmit(page);
  await expect(page.locator('.vc-needed')).toBeVisible();
  await sweep(page, problems, `${tag} case, submit gate with missing answers`);
}

test.describe('vulnerability accessibility sweep (full axe rule set, light and dark, 1280/360/320 px)', () => {
  // The SOC workspace shares its code with the follow-up alert's: its hidden "Query language" legend once pushed the page
  // sideways (fixed by `.lang-toggle { position: relative }`). A plain SOC case page must not scroll sideways at any width.
  test('a plain SOC case page does not scroll sideways (1280, 360, 320 px), axe clean', async ({ page }) => {
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);
    await page.goto('/#/case/failed-sign-ins-across-many-accounts/e2e');
    await expect(page.locator('.ws-grid')).toBeVisible({ timeout: 30_000 });
    for (const width of WIDTHS) {
      await page.setViewportSize({ width, height: heightFor(width) });
      await still(page);
      const o = await overflow(page);
      if (o > 0) problems.push(`SOC case at ${width}px: page scrolls sideways by ${o}px (${await culprits(page)})`);
    }
    await sweep(page, problems, 'plain SOC case');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('worklist: distinct visible placeholders, the table fits its region from 1200 px, the Simulated data badge', async ({ page }) => {
    await withProfile(page);
    await openCase(page, CASE_T1);
    const [first] = await rowIds(page);
    const decision = page.locator(`#wl-${first}-decision`);
    const schedule = page.locator(`#wl-${first}-schedule`);
    await expect(decision.locator('option').first()).toHaveText('Decision…');
    await expect(schedule.locator('option').first()).toHaveText('Schedule…');
    // The accessible names are unchanged.
    await expect(decision).toHaveAccessibleName(new RegExp(`^Decision for ${first} on `));
    await expect(schedule).toHaveAccessibleName(new RegExp(`^Schedule for ${first} on `));
    await expect(page.locator('.vc-bar [data-simulated]')).toHaveText('Simulated data');
    for (const width of [1200, 1280, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      const fit = await page.locator('.wl-table').evaluate((t) => {
        const region = t.closest('.table-wrap')!;
        return { table: region.scrollWidth, region: region.clientWidth };
      });
      expect(fit.table, `table fits its region at ${width}px`).toBeLessThanOrEqual(fit.region);
    }
    // Below 1200 px the page is a single column and the table has the whole width.
    await page.setViewportSize({ width: 1101, height: 900 });
    const fit = await page.locator('.wl-table').evaluate((t) => ({ table: t.closest('.table-wrap')!.scrollWidth, region: t.closest('.table-wrap')!.clientWidth }));
    expect(fit.table).toBeLessThanOrEqual(fit.region);
  });

  test('Home with a recent vuln attempt, the open mobile menu, the library (every tier, no match)', async ({ page }) => {
    test.setTimeout(240_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page, STATS_PROFILE);
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Vulnerability management' })).toBeVisible();
    await sweep(page, problems, 'home with a recent vuln attempt');

    // the collapsed nav, open (it only collapses below 901 px)
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 740 });
      await page.goto('/#/');
      await page.reload();
      const toggle = page.getByRole('button', { name: 'Menu' });
      await toggle.click();
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      await expect(page.locator('#primary-nav a', { hasText: 'Vulns' })).toBeVisible();
      for (const scheme of SCHEMES) {
        await page.emulateMedia({ colorScheme: scheme });
        await still(page);
        const r = await new AxeBuilder({ page }).analyze();
        for (const v of r.violations) problems.push(`open menu ${width}/${scheme}: ${v.id} (${v.impact}) ${v.help}: ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')}`);
        const o = await overflow(page);
        if (o > 0) problems.push(`open menu ${width}/${scheme}: page scrolls sideways by ${o}px (${await culprits(page)})`);
      }
    }
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.emulateMedia({ colorScheme: 'light' });

    await page.goto('/#/vuln');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await sweep(page, problems, 'library, all tiers');
    for (const tier of ['tier1', 'tier2', 'tier3']) {
      await page.locator('#vlib-diff').selectOption(tier);
      await expect(page.locator('.lib-card').first()).toBeVisible();
      await sweep(page, problems, `library, ${tier}`);
    }
    await page.locator('#vlib-diff').selectOption('all');
    await page.getByLabel('Search').fill('zzzzz');
    await expect(page.getByText('No case type matches "zzzzz".')).toBeVisible();
    await sweep(page, problems, 'library, a search with no match');

    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('Help glossary, Stats with vuln attempts, Study objectives card', async ({ page }) => {
    test.setTimeout(240_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page, { ...STATS_PROFILE, attempts: [SOC_ATTEMPT, ...STATS_ATTEMPTS], cards: { 'vm-needed-service': { templateId: 'vm-needed-service', ef: 2.5, interval: 1, reps: 1, lapses: 0, due: 0, last: 0, lastPercent: 40 } } });
    await page.goto('/#/help/vuln');
    await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();
    await sweep(page, problems, 'help/vuln');
    await page.goto('/#/stats');
    await expect(page.locator('section[aria-labelledby="vuln-h"]')).toBeVisible();
    await sweep(page, problems, 'stats with vuln attempts (domain 2.0, objectives, confusion matrix)');
    await page.goto('/#/study');
    await expect(page.getByRole('heading', { level: 2, name: 'CySA+ objectives' })).toBeVisible();
    await sweep(page, problems, 'study with the objectives card');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('tier 1 case states', async ({ page }) => {
    test.setTimeout(300_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);
    await caseStates(page, problems, CASE_T1, 'tier 1');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('tier 2 case states', async ({ page }) => {
    test.setTimeout(300_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);
    await caseStates(page, problems, CASE_T2, 'tier 2');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('tier 3 case states and a debrief with a closed duplicate', async ({ page }) => {
    test.setTimeout(420_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);
    await caseStates(page, problems, CASE_T3, 'tier 3');

    const c = built(CASE_T3);
    const dups = c.findings.filter((f) => f.truth.decision === 'false-positive' && f.truth.reasons.includes('duplicate-root-cause'));
    expect(dups.length).toBeGreaterThan(0);
    // The learner who patches every row does not see the duplicates.
    for (const id of await rowIds(page)) {
      await page.locator(`#wl-${id}-decision`).selectOption('patch');
      await page.locator(`#wl-${id}-schedule`).selectOption('standard-cycle');
    }
    await pressSubmit(page);
    await expect(page.locator('#debrief-h')).toBeVisible();
    await expect(page.locator(`li.vd-finding[data-finding-id="${dups[0].findingId}"]`)).toContainText('a duplicate: closed with the reason Duplicate root cause');
    await sweep(page, problems, 'tier 3 debrief with closed duplicates');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('tier 1 debrief: capped by a missed key finding, then passed', async ({ page }) => {
    test.setTimeout(420_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);
    await openCase(page, CASE_T1);
    const c = built(CASE_T1);
    const lessonId = await solveAndSubmit(page, c, true);
    expect(lessonId, 'a lesson finding with an SLA').not.toBeNull();
    await expect(page.locator('.vd-gate')).toBeVisible();
    await sweep(page, problems, 'debrief, capped');

    await page.getByRole('button', { name: 'Work it again' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible();
    await solveAndSubmit(page, c, false);
    await expect(page.locator('strong.text-ok', { hasText: 'Passed.' })).toBeVisible();
    await expect(page.locator('.vd-gate')).toHaveCount(0);
    await sweep(page, problems, 'debrief, passed');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('the control picker case and an avoid decision, with their debriefs', async ({ page }) => {
    test.setTimeout(420_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    await withProfile(page);

    // Control picker: mitigate on the headline, no control chosen yet, the gate open.
    const cc = built(CASE_CONTROLS);
    const mit = cc.findings.find((f) => f.truth.decision === 'mitigate' && f.truth.mitigation?.length)!;
    expect(mit, 'a mitigate finding with a control').toBeTruthy();
    await openCase(page, CASE_CONTROLS);
    await page.locator(`#wl-${mit.findingId}-decision`).selectOption('mitigate');
    await expect(page.locator(`#wl-${mit.findingId}-control`)).toBeVisible();
    await sweep(page, problems, 'control picker open, nothing chosen');
    await page.locator(`#wl-${mit.findingId}-schedule`).selectOption(mit.truth.schedule);
    await pressSubmit(page);
    await expect(page.locator('.vc-needed')).toBeVisible();
    await sweep(page, problems, 'control picker, submit gate asks for the control');
    await solveAndSubmit(page, cc);
    await sweep(page, problems, 'debrief with a mitigating control');

    // Avoid: the console that is not used.
    const cu = built(CASE_UNUSED);
    const avoid = cu.findings.find((f) => f.truth.decision === 'avoid')!;
    expect(avoid, 'an avoid finding').toBeTruthy();
    await openCase(page, CASE_UNUSED);
    await page.locator(`#wl-${avoid.findingId}-decision`).selectOption('avoid');
    await sweep(page, problems, 'avoid decision chosen');
    await solveAndSubmit(page, cu);
    await sweep(page, problems, 'debrief with an avoid decision');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });

  test('a SOC shift with a vuln follow-up alert, and that alert\'s debrief link back', async ({ page }) => {
    test.setTimeout(300_000);
    const errors = watchErrors(page);
    const problems: string[] = [];
    const HOOK_RULE = 'Exploit signature match on a monitored service';
    let entry: object | null = null;
    outer: for (const type of vulnCaseTypes(VULN_TEMPLATES)) {
      for (const seed of ['e2e', 'e2e-a', 'e2e-b', 'e2e-c']) {
        const t = resolveVulnTemplate(type, seed);
        const v = buildVulnScenario({ worldSeed: PROFILE.worldSeed, templateId: t.id, seed, world: WORLD });
        const f = v.case.findings.find((x) => x.mustNotMiss && x.sharedHost && x.truth.decision !== 'false-positive' && x.truth.decision !== 'mitigate' && !x.truth.mitigation?.length && /^SIMVULN-/.test(x.vulnId));
        if (!f) continue;
        entry = { id: `${t.id}~${seed}/${f.findingId}@1700000000000`, vulnId: f.vulnId, host: f.host, decision: 'false-positive', schedule: 'none', decidedDay: 20000, caseRef: `${t.id}~${seed}` };
        break outer;
      }
    }
    expect(entry, 'an eligible finding').not.toBeNull();
    await withProfile(page, { ...PROFILE, vulnLedger: [entry] });
    await page.goto('/#/');
    await page.getByRole('radio', { name: 'Untimed' }).check();
    await page.getByRole('button', { name: 'Start shift' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 30_000 });
    const hook = page.locator('.queue-item').filter({ hasText: HOOK_RULE });
    await expect(hook).toHaveCount(1);
    const alertId = (await hook.locator('.mono').first().textContent())!.trim();
    await sweep(page, problems, 'shift queue with the vuln follow-up alert');

    await hook.click();
    await expect(page.locator('.ws-grid')).toBeVisible();
    await sweep(page, problems, 'workspace of the vuln follow-up alert');
    await page.getByRole('radio', { name: 'Benign / expected' }).check();
    await page.getByRole('radio', { name: 'Informational' }).check();
    await page.getByRole('radio', { name: 'Close' }).check();
    await page.getByRole('button', { name: 'Submit & back to queue' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible();
    await page.getByRole('button', { name: 'Hand over' }).click();
    await page.getByRole('button', { name: 'Hand over now' }).click();
    await expect(page.getByText('Shift 1 handover')).toBeVisible();
    await page.getByRole('button', { name: `Review ${alertId}` }).click();
    await expect(page.locator('.vuln-link-back a')).toHaveCount(1, { timeout: 30_000 });
    await sweep(page, problems, 'debrief of the vuln follow-up alert, with the link back');
    expect(errors).toEqual([]);
    expect(problems).toEqual([]);
  });
});

// ---- seeded profile data (the same shapes e2e/vuln.spec.ts uses for Stats and Study)
type SeedDecision = { findingId: string; truth: string; given: string | null; mustNotMiss: boolean; verdict?: string };
const vulnRecord = (n: number, templateId: string, percent: number, objectives: string[], decisions: SeedDecision[], day = 20_000 + n) => ({
  id: `${templateId}~s${n}`,
  templateId,
  seed: `s${n}`,
  mode: 'vuln',
  completedAt: 1_780_000_000_000 + n * 60_000,
  day,
  percent,
  score: percent,
  dispositionCorrect: percent >= 70,
  xp: 50,
  hintsUsed: 0,
  durationSec: 300,
  components: {},
  matchedTechniques: [],
  missedTechniques: [],
  evidenceFound: 0,
  evidenceTotal: 0,
  category: 'vulnmgmt',
  difficulty: 'tier1',
  tactics: [],
  cysaDomains: ['2.0', '4.0'],
  vuln: { objectives, evidenceFound: 2, evidenceTotal: 3, decisions },
});
const fd = (i: number, truth: string, given: string | null, verdict?: string): SeedDecision => ({ findingId: `VF-0000${i}`, truth, given, mustNotMiss: false, ...(verdict ? { verdict } : {}) });
const STATS_ATTEMPTS = [
  vulnRecord(1, 'vm-kev-internal', 90, ['2.3', '2.5', '4.1'], [fd(1, 'patch', 'patch', 'exact'), fd(2, 'false-positive', 'patch', 'wrong'), fd(3, 'accept', 'transfer', 'wrong')]),
  vulnRecord(2, 'vm-stale-scan', 50, ['2.1', '2.2', '2.3', '2.5', '4.1'], [fd(1, 'false-positive', 'patch', 'wrong'), fd(2, 'false-positive', 'patch', 'wrong'), fd(3, 'mitigate', null, 'missing')]),
  vulnRecord(3, 'vm-fresh-scan', 80, ['2.1', '2.2', '2.3', '2.5', '4.1'], [fd(1, 'patch', 'patch', 'exact'), fd(2, 'false-positive', 'false-positive', 'exact')]),
];
const STATS_PROFILE = { ...PROFILE, xp: 150, attempts: STATS_ATTEMPTS };
const SOC_ATTEMPT = {
  id: 'identity-password-spray~a1',
  templateId: 'identity-password-spray',
  seed: 'a1',
  mode: 'practice',
  completedAt: 1_780_000_000_000,
  day: 20_000,
  percent: 80,
  score: 80,
  dispositionCorrect: true,
  xp: 90,
  hintsUsed: 0,
  durationSec: 200,
  components: {},
  matchedTechniques: [],
  missedTechniques: [],
  evidenceFound: 1,
  evidenceTotal: 1,
  category: 'identity',
  difficulty: 'tier1',
  tactics: ['credential-access'],
  cysaDomains: ['1.0'],
};
