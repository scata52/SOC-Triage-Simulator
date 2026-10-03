import { test, expect, type Locator, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { VULN_TEMPLATES } from '../src/core/vuln/registry.ts';
import { resolveVulnTemplate, vulnCaseTypes } from '../src/core/vuln/worklist.ts';
import { buildVulnScenario } from '../src/core/vuln/scenario.ts';
import { generateWorld } from '../src/core/world/world.ts';

// Vulnerability-management mode: acceptance criteria (1)-(10) of WP1e.
// A fixed profile so every run works in the same fictional organisation.
const PROFILE = { version: 2, worldSeed: 'e2e-world', analystName: 'E2E', attempts: [] };
const PROFILE_XP = { ...PROFILE, xp: 100 };
const PROFILE_RUBRIC = { ...PROFILE, settings: { showRubricLive: true } };
const CASE = '#/vuln/scan-review-internal-servers/e2e';
// Its template (spec) order is not FindingId-ascending; tests/vuln-worklist.test.ts pins that.
const CASE_UNSORTED = '#/vuln/scan-review-web-servers/e2e';
const TEMPLATE_IDS = [
  'vm-kev-internal', 'vm-nokev-internal', 'vm-stale-scan', 'vm-fresh-scan', 'vm-backport-fp',
  'vm-backport-real', 'vm-exposed-edge', 'vm-segmented', 'vm-waf-covers', 'vm-waf-bypass',
  'vm-legacy-accept', 'vm-legacy-isolate', 'vm-noncred-low', 'vm-cred-high', 'vm-saas-transfer', 'vm-self-hosted',
  'vm-unused-service', 'vm-needed-service', 'vm-dup-plugins', 'vm-distinct',
];
const LIVE = '[role="status"][aria-live="polite"][aria-atomic="true"]';
// A case whose seed picks a twin that writes ControlInventory rows: here `vm-segmented` (truth mitigate on the headline,
// an ACL in block mode covers it). The case page does not name the twin; the test asserts it from the data.
const CASE_CONTROLS = '#/vuln/scan-review-edge-and-internal-servers/e2e-ctl';
// Tier 3 (the first tier-3 case type): the seed `e2e` picks `vm-dup-plugins`. The test asserts the twin from the data.
const CASE_TIER3 = '#/vuln/scan-review-shared-services-and-payment-systems/e2e';
// A case whose seed picks `vm-unused-service` (truth avoid on the headline); the test asserts the twin from the data.
const CASE_UNUSED = '#/vuln/scan-review-optional-admin-consoles-and-internal-servers/e2e-x';

// Decision and schedule answers cycle so that every row of a solved case differs.
const DECISION_TYPE = ['Patch', 'Mitigate', 'Accept', 'False'];
const DECISION_VALUE = ['patch', 'mitigate', 'accept', 'false-positive'];
const DECISION_SHOWN = ['Patch', 'Mitigate', 'Accept', 'False positive'];
const SCHEDULE_TYPE = ['Standard', 'Next', 'Emergency', 'No'];
const SCHEDULE_VALUE = ['standard-cycle', 'next-window', 'emergency', 'none'];
const SCHEDULE_SHOWN = ['Standard patch cycle', 'Next maintenance window', 'Emergency change', 'No change'];

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

// Stricter than app.spec's axe(): zero violations of any impact (WP1e sign-off).
// Waits first until no transition or animation is running (a theme switch starts 160 ms colour transitions
// that axe would otherwise read half way). `include` limits the scan to one element, e.g. a moved card.
async function axeStrict(page: Page, label: string, include?: string): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  let b = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']);
  if (include) b = b.include(include);
  const r = await b.analyze();
  expect(r.violations.map((v) => `${label}: ${v.id} (${v.impact}) ${v.help} (${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')})`)).toEqual([]);
}

// Full rule set (best practice and experimental included, no tag filter), zero violations of any impact.
// A second helper: the WCAG-tag axeStrict above is shared by the other tests and stays as it is.
async function axeFull(page: Page, label: string): Promise<void> {
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
  const r = await new AxeBuilder({ page }).analyze();
  expect(r.violations.map((v) => `${label}: ${v.id} (${v.impact}) ${v.help} (${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')})`)).toEqual([]);
}

async function openCase(page: Page, hash = CASE): Promise<void> {
  await page.goto(`/${hash}`);
  await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('main h1')).toBeFocused();
}

async function overflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

async function tabTo(page: Page, target: Locator, key = 'Tab'): Promise<void> {
  for (let i = 0; i < 400; i++) {
    if (await target.evaluate((el) => el === document.activeElement, undefined, { timeout: 5000 })) return;
    await page.keyboard.press(key);
  }
  throw new Error(`tabTo: never reached ${target}`);
}

const rowIds = (page: Page): Promise<string[]> => page.locator('tbody.wl-finding, li.wl-card').evaluateAll((els) => els.map((e) => e.getAttribute('data-finding-id')!));

const live = (page: Page): Locator => page.locator(LIVE);

async function hostOf(page: Page, id: string): Promise<string> {
  return page.evaluate((fid) => {
    const unit = document.querySelector(`[data-finding-id="${fid}"]`)!;
    const cell = unit.querySelector('tr.wl-row td:nth-child(3)');
    if (cell) return cell.textContent!.trim();
    return unit.querySelector('.wl-card-h')!.textContent!.split('·')[1].trim();
  }, id);
}

// Uses selectOption on every row (non-keyboard tests only).
async function answerAll(page: Page, skip?: string): Promise<void> {
  const ids = await rowIds(page);
  for (const [k, id] of ids.entries()) {
    if (id === skip) continue;
    await page.locator(`#wl-${id}-decision`).selectOption(DECISION_VALUE[k % 4]);
    await page.locator(`#wl-${id}-schedule`).selectOption(SCHEDULE_VALUE[k % 4]);
  }
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

async function solveAndSubmit(page: Page): Promise<void> {
  await answerAll(page);
  await pinOne(page);
  await page.locator('#vc-submit-btn').click();
  await expect(page.locator('#debrief-h')).toBeVisible();
}

const watchLive = (page: Page) =>
  page.evaluate((sel) => {
    const w = window as unknown as { __live: string[] };
    w.__live = [];
    const el = document.querySelector(sel)!;
    new MutationObserver(() => {
      if (el.textContent) w.__live.push(el.textContent);
    }).observe(el, { childList: true, characterData: true, subtree: true });
  }, LIVE);

const liveCount = (page: Page, text: string) => page.evaluate((t) => (window as unknown as { __live: string[] }).__live.filter((x) => x === t).length, text);

// Domains in vuln data are never links (human decision 2026-10-02). Every rendered a[href] is an in-app route (#...)
// or a documentation-citation host; no anchor's href or text contains a domain that appears in the page data.
const CITATION_HOSTS = ['www.first.org', 'www.cisa.gov', 'www.comptia.org'];
async function noDataLinks(page: Page, label: string): Promise<number> {
  const r = await page.evaluate((cites) => {
    const anchors = [...document.querySelectorAll('a')].map((a) => ({ href: a.getAttribute('href'), text: (a.textContent ?? '').toLowerCase() }));
    const hostRe = /(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?![\w-])/gi;
    // Domain-like tokens in the data on the page (everything outside anchors), minus the citation hosts.
    const clone = document.body.cloneNode(true) as HTMLElement;
    clone.querySelectorAll('a').forEach((a) => a.remove());
    const data = [...new Set((clone.textContent ?? '').toLowerCase().match(hostRe) ?? [])].filter((t) => !cites.includes(t));
    const bad: string[] = [];
    for (const a of anchors) {
      const href = a.href ?? '';
      if (!href.startsWith('#')) {
        let host = '';
        try {
          host = new URL(href).host;
        } catch {
          /* not a URL */
        }
        if (!cites.includes(host)) bad.push(`href ${href}`);
      }
      for (const d of data) if (href.toLowerCase().includes(d) || a.text.includes(d)) bad.push(`data domain ${d} in anchor ${href} "${a.text.trim()}"`);
    }
    return { bad, anchors: anchors.length, data: data.length };
  }, CITATION_HOSTS);
  expect(r.bad, `${label}: links`).toEqual([]);
  expect(r.anchors, `${label}: has anchors`).toBeGreaterThan(0);
  return r.data;
}

test.describe('vulnerability mode', () => {
  test('no data domain is ever a link: library, case with query results, debrief', async ({ page }) => {
    test.setTimeout(120_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await page.goto('/#/vuln');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await noDataLinks(page, 'library');

    await openCase(page);
    await runQuery(page, 'DeviceInfo\n| take 20');
    await expect(page.locator('.results-meta')).toBeVisible();
    // The results show asset owners as user principal names, so the data really carries a domain here.
    expect(await noDataLinks(page, 'case with results'), 'the case page shows domains in its data').toBeGreaterThan(0);

    await solveAndSubmit(page);
    await page.locator('.vd-finding').first().getByRole('button', { name: /Show the/ }).click();
    await page.locator('.steps li').first().getByRole('button', { name: 'Run it' }).click();
    await expect(page.locator('.steps li').first().locator('.step-result')).toBeVisible();
    await noDataLinks(page, 'debrief');
    expect(errors).toEqual([]);
  });

  test('library: a fresh profile reaches the Home card and every tier; tier filter and labels match the SOC library', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page, null);
    await page.goto('/#/practice');
    await expect(page.locator('.lib-card').first()).toBeVisible();
    const socOptions = await page.locator('#lib-diff option').allInnerTexts();
    const socLabels = new Set(await page.locator('.lib-card .diff').allInnerTexts());

    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Vulnerability management' })).toBeVisible();
    await page.getByRole('link', { name: 'Browse vulnerability cases' }).click();
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    expect(await page.locator('#vlib-diff option').allInnerTexts()).toEqual(socOptions);
    const vulnLabels = await page.locator('.lib-card .diff').allInnerTexts();
    expect(vulnLabels.length).toBeGreaterThan(0);
    for (const l of vulnLabels) expect(socLabels.has(l), l).toBe(true);
    await axeStrict(page, 'library');

    await page.locator('#vlib-diff').selectOption('tier2');
    await expect(page.locator('.lib-card h2')).toHaveText(['Scan review: public web applications and servers', 'Scan review: web servers'].sort());
    await page.getByRole('button', { name: 'Start: Scan review: web servers' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    await page.goto('/#/vuln');
    await page.locator('#vlib-diff').selectOption('tier1');
    await expect(page.locator('.lib-card h2')).toHaveText(
      [
        'Scan review: edge and internal servers',
        'Scan review: file servers',
        'Scan review: internal servers',
        'Scan review: intranet application servers',
        'Scan review: laboratory controller and internal servers',
        'Scan review: optional admin consoles and internal servers',
        'Scan review: third-party ticketing service and internal servers',
      ].sort(),
    );
    await page.locator('.lib-card').first().getByRole('button', { name: /^Start:/ }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    await page.goto('/#/vuln');
    await page.locator('#vlib-diff').selectOption('tier3');
    await expect(page.locator('.lib-card h2')).toHaveText(['Scan review: shared services and payment systems']);
    await expect(page.getByText('No vulnerability cases at this tier yet.')).toHaveCount(0);
    await page.getByRole('button', { name: 'Start: Scan review: shared services and payment systems' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    await page.goto('/#/vuln/no-such-case/x');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Unknown case');
    expect(errors).toEqual([]);
  });

  test('keyboard only: reorder, answer every row distinctly, query, pin, note, submit, debrief', async ({ page }) => {
    test.setTimeout(240_000);
    const errors = watchErrors(page);
    await withProfile(page, PROFILE_XP);
    await openCase(page);
    const n = (await rowIds(page)).length;
    expect(n).toBeGreaterThanOrEqual(4);

    // Tab order follows the visual order: brief, worklist, tools, submit.
    const seq: string[] = [];
    const submit = page.locator('#vc-submit-btn');
    for (let i = 0; i < 500; i++) {
      await page.keyboard.press('Tab');
      const where = await page.evaluate(() => {
        const a = document.activeElement as HTMLElement;
        const c = a.closest('.vc-bar,.vc-brief,.vc-worklist,.vc-tools,.vc-submit');
        return { id: a.id, cls: c ? [...c.classList].find((x) => x.startsWith('vc-'))! : 'other' };
      });
      if (seq[seq.length - 1] !== where.cls) seq.push(where.cls);
      if (where.id === 'vc-submit-btn') break;
    }
    await expect(submit).toBeFocused();
    expect(seq).toEqual(['vc-brief', 'vc-worklist', 'vc-tools', 'vc-submit']);

    // Reload (drafts survive) to start from the heading again.
    await page.reload();
    await expect(page.locator('main h1')).toBeFocused();

    // Reorder first.
    let ids = await rowIds(page);
    const first = ids[0];
    await tabTo(page, page.locator(`#wl-${first}-down`));
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${first} moved to position 2 of ${n}.`);
    await expect(page.locator(`#wl-${first}-down`)).toBeFocused();
    await page.keyboard.press('Alt+ArrowUp');
    await expect(live(page)).toHaveText(`${first} moved to position 1 of ${n}.`);
    expect((await rowIds(page))[0]).toBe(first);
    const last = ids[n - 1];
    await tabTo(page, page.locator(`#wl-${last}-prio`));
    await page.keyboard.press('Control+A');
    await page.keyboard.type('1');
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${last} moved to position 1 of ${n}.`);
    ids = await rowIds(page);
    expect(ids[0]).toBe(last);

    // Answer in the final order, distinct on every row.
    for (const [k, id] of ids.entries()) {
      await tabTo(page, page.locator(`#wl-${id}-decision`));
      await page.keyboard.type(DECISION_TYPE[k % 4]);
      await expect(page.locator(`#wl-${id}-decision`)).toHaveValue(DECISION_VALUE[k % 4]);
      if (k % 4 === 1) {
        await expect(page.locator(`#wl-${id}-control-none`)).toBeVisible();
        await expect(page.locator(`#wl-${id}-control`)).toHaveCount(0);
      }
      await tabTo(page, page.locator(`#wl-${id}-schedule`));
      await page.keyboard.type(SCHEDULE_TYPE[k % 4]);
      await expect(page.locator(`#wl-${id}-schedule`)).toHaveValue(SCHEDULE_VALUE[k % 4]);
      if (k === 0) {
        await tabTo(page, page.locator(`#wl-${id}-reasons`));
        await page.keyboard.press('Enter');
        await expect(page.locator(`#wl-${id}-reasons`)).toHaveAttribute('aria-expanded', 'true');
        await page.keyboard.press('Tab');
        await page.keyboard.press('Space');
        await expect(page.locator(`#wl-${id}-reasons`)).toHaveAttribute('aria-label', new RegExp(`^Reasons \\(1 of 3\\) for ${id}`));
      }
    }
    expect(await rowIds(page)).toEqual(ids);

    // Tablist: arrow keys switch, the note is typed, then back to the console.
    const tabConsole = page.locator('#vc-tab-console');
    const tabNote = page.locator('#vc-tab-note');
    await tabTo(page, tabConsole);
    await page.keyboard.press('ArrowRight');
    await expect(tabNote).toHaveAttribute('aria-selected', 'true');
    await tabTo(page, page.locator('#vc-note'));
    await page.keyboard.type('The owner must patch before the deadline.');
    await tabTo(page, tabNote, 'Shift+Tab');
    await page.keyboard.press('ArrowLeft');
    await expect(tabConsole).toHaveAttribute('aria-selected', 'true');

    // Query, pin.
    await tabTo(page, page.locator('.cm-content'));
    await page.keyboard.press('Control+A');
    await page.keyboard.press('Delete');
    await page.keyboard.insertText('VulnIntel\n| take 5');
    await page.keyboard.press('Control+Enter');
    await expect(page.locator('.results-meta')).toBeVisible();
    await tabTo(page, page.getByRole('button', { name: 'Pin row 1 as evidence' }));
    await page.keyboard.press('Enter');
    await expect(page.getByRole('button', { name: 'Unpin row 1 as evidence' })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.vc-submit .pins li')).toHaveCount(1);

    await tabTo(page, submit);
    await expect(submit).not.toHaveAttribute('aria-disabled', 'true');
    await page.keyboard.press('Enter');

    // Debrief.
    await expect(page.locator('#debrief-h')).toBeVisible();
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.getByRole('heading', { name: 'Score breakdown' })).toBeVisible();
    await expect(page.locator('.grade-table tbody tr')).toHaveCount(5);
    await expect(page.locator('.vd-finding')).toHaveCount(n);
    for (const [k, id] of ids.entries()) {
      const li = page.locator(`li.vd-finding[data-finding-id="${id}"]`);
      await expect(li.locator('dd[data-field="decision"]')).toContainText(`Yours: ${DECISION_SHOWN[k % 4]}`);
      await expect(li.locator('dd[data-field="schedule"]')).toContainText(`Yours: ${SCHEDULE_SHOWN[k % 4]}`);
      await expect(li.locator('dd[data-field="priority"]')).toContainText(`Your position: ${k + 1} of ${n}`);
    }
    await tabTo(page, page.getByRole('button', { name: 'Run it' }).first());
    await page.keyboard.press('Enter');
    await expect(page.locator('.step-result').first()).toBeVisible();

    // XP goes into the shared total.
    const xpText = await page.locator('.vd-xp').innerText();
    const xp = Number(/\+(\d+) XP/.exec(xpText)![1]);
    expect(xp).toBeGreaterThan(0);
    await expect(page.locator('.rank-chip')).toHaveAttribute('title', `${100 + xp} XP`);
    await page.goto('/#/');
    await expect(page.locator('.recent-list')).toContainText('Scan review: internal servers');
    expect(errors).toEqual([]);
  });

  test('default order is scanner order, every data column sorts the worklist, and the sorted order is what is submitted', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page, CASE_UNSORTED);
    const def = await rowIds(page);
    const n = def.length;
    expect(def).toEqual([...def].sort());

    const sortButtons = page.locator('button.th-sort');
    await expect(sortButtons).toHaveCount(6);
    expect(await page.locator('thead th').evaluateAll((ths) => ths.filter((t) => !t.querySelector('button')).map((t) => t.textContent!.trim()))).toEqual(['Priority', 'Pins', 'Your call', 'Reasons']);
    const pairs = await sortButtons.evaluateAll((bs) => bs.map((b) => [b.getAttribute('aria-label')!, b.querySelector('.th-label')!.textContent!]));
    expect(pairs.map((p) => p[1])).toEqual(['Finding', 'Host', 'Vulnerability', 'Severity (scanner)', 'CVSS', 'First seen']);
    for (const [label, visible] of pairs) expect(label.startsWith(visible), label).toBe(true);
    const sevs = await page.locator('.wl-row .sev').allTextContents();
    for (const s of sevs) expect(['Critical', 'High', 'Medium', 'Low', 'Info']).toContain(s);

    const cvss = async () => (await page.locator('tbody.wl-finding tr.wl-row td:nth-child(6)').allTextContents()).map(Number.parseFloat).filter((x) => Number.isFinite(x));
    const prios = () => page.locator('input.wl-prio').evaluateAll((els) => els.map((e) => (e as HTMLInputElement).value));
    const ranks = async () => (await page.locator('.wl-row .sev').evaluateAll((els) => els.map((e) => Number(e.getAttribute('data-rank')))));

    await page.getByRole('button', { name: 'CVSS: sort highest first' }).click();
    await expect(page.locator('th[aria-sort="descending"]')).toHaveCount(1);
    await expect(live(page)).toHaveText('Worklist sorted by CVSS, highest first. Undo sort restores your previous order.');
    const desc = await cvss();
    for (let i = 1; i < desc.length; i++) expect(desc[i]).toBeLessThanOrEqual(desc[i - 1]);
    expect(await prios()).toEqual(def.map((_, i) => String(i + 1)));
    await page.getByRole('button', { name: 'CVSS: sort lowest first' }).click();
    await expect(page.locator('th[aria-sort="ascending"]')).toHaveCount(1);
    const asc = await cvss();
    for (let i = 1; i < asc.length; i++) expect(asc[i]).toBeGreaterThanOrEqual(asc[i - 1]);

    await page.getByRole('button', { name: 'Severity (scanner): sort most severe first' }).click();
    await expect(page.locator('th[aria-sort="descending"]')).toHaveCount(1);
    const rk = await ranks();
    for (let i = 1; i < rk.length; i++) expect(rk[i]).toBeLessThanOrEqual(rk[i - 1]);

    await page.locator('#wl-undo-sort').click();
    expect(await rowIds(page)).toEqual(def);
    await expect(page.locator('th[aria-sort]')).toHaveCount(0);
    await expect(live(page)).toHaveText('Sort undone. Your previous order is back.');
    await expect(page.locator('#wl-sort-severity')).toBeFocused();

    await page.locator('#wl-sort-cvss').click();
    await expect(page.locator('th[aria-sort="descending"]')).toHaveCount(1);
    const sorted = await rowIds(page);
    await page.reload();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
    expect(await rowIds(page)).toEqual(sorted);
    await expect(page.locator('th[aria-sort="descending"]')).toHaveCount(1);

    await page.locator(`#wl-${sorted[0]}-down`).click();
    await expect(page.locator('th[aria-sort]')).toHaveCount(0);
    await expect(page.locator('#wl-undo-sort')).toHaveCount(0);

    // Sort once more so the submitted order is a sorted one.
    await page.locator('#wl-sort-host').click();
    const submitted = await rowIds(page);
    expect(submitted.length).toBe(n);
    await solveAndSubmit(page);
    for (const [k, id] of submitted.entries()) {
      await expect(page.locator(`li.vd-finding[data-finding-id="${id}"] dd[data-field="priority"]`)).toContainText(`Your position: ${k + 1} of ${n}`);
    }
    expect(errors).toEqual([]);
  });

  test('reorder, sort, reason cap and focus are announced and kept', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    const ids0 = await rowIds(page);
    const n = ids0.length;
    expect(n).toBeGreaterThanOrEqual(4);
    const [a, b] = ids0;
    const last = ids0[n - 1];
    await watchLive(page);

    await page.locator(`#wl-${a}-down`).click();
    await expect(live(page)).toHaveText(`${a} moved to position 2 of ${n}.`);
    await page.locator(`#wl-${a}-up`).click();
    await expect(live(page)).toHaveText(`${a} moved to position 1 of ${n}.`);
    await page.locator(`#wl-${a}-up`).focus();
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${a} is already first.`);
    await page.keyboard.press('Enter');
    await expect.poll(() => liveCount(page, `${a} is already first.`)).toBe(2);
    await page.locator(`#wl-${last}-down`).focus();
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${last} is already last.`);

    await page.locator(`#wl-${b}-prio`).fill('3');
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${b} moved to position 3 of ${n}.`);
    await page.keyboard.press('Alt+ArrowDown');
    await expect(live(page)).toHaveText(`${b} moved to position 4 of ${n}.`);
    await page.locator('#wl-sort-cvss').click();
    await expect(live(page)).toHaveText('Worklist sorted by CVSS, highest first. Undo sort restores your previous order.');
    await page.locator('#wl-sort-cvss').click();
    await expect(live(page)).toHaveText('Worklist sorted by CVSS, lowest first. Undo sort restores your previous order.');

    // Priority blur: the commit must not pull focus back into the input.
    const r3 = (await rowIds(page))[2];
    await page.locator(`#wl-${r3}-prio`).click();
    await page.keyboard.press('Control+A');
    await page.keyboard.type('1');
    await page.keyboard.press('Tab');
    await expect(live(page)).toHaveText(`${r3} moved to position 1 of ${n}.`);
    // Tab continues to the next control of the same finding (its decision select), not back into the input.
    await expect(page.locator(`#wl-${r3}-decision`)).toBeFocused();

    // Alt+Arrow from a reason checkbox.
    const c = (await rowIds(page))[0];
    const host = await hostOf(page, c);
    await page.locator(`#wl-${c}-reasons`).click();
    const box = (code: string) => page.locator(`#wl-${c}-reason-${code}`);
    await tabTo(page, box('known-exploited'));
    await page.keyboard.press('Alt+ArrowDown');
    await expect(live(page)).toHaveText(`${c} moved to position 2 of ${n}.`);
    await expect(box('known-exploited')).toBeFocused();
    expect((await rowIds(page))[1]).toBe(c);
    await expect(page.locator(`tbody[data-finding-id="${c}"] tr.wl-reasons-row`)).toBeVisible();

    // The cap of three reasons.
    await box('known-exploited').check();
    await box('high-exploit-probability').check();
    await box('internet-exposed').check();
    const cap = `Three reasons chosen for ${c}. Uncheck one to choose another.`;
    await expect(live(page)).toHaveText(cap);
    await expect(box('critical-asset')).toHaveAttribute('aria-disabled', 'true');
    await expect(page.locator(`#wl-${c}-reasons-panel`)).toHaveAttribute('aria-describedby', `wl-${c}-reasons-status`);
    await expect(page.locator(`#wl-${c}-reasons-status`)).toHaveText('3 of 3 chosen. Uncheck one to choose another.');
    await expect(page.locator(`#wl-${c}-reasons`)).toHaveAttribute('aria-label', `Reasons (3 of 3) for ${c} on ${host}`);
    const before = await liveCount(page, cap);
    await tabTo(page, box('critical-asset'));
    await page.keyboard.press('Space');
    await expect(box('critical-asset')).not.toBeChecked();
    await expect.poll(() => liveCount(page, cap)).toBeGreaterThan(before);
    await box('known-exploited').uncheck();
    await expect(box('critical-asset')).not.toHaveAttribute('aria-disabled', 'true');
    await expect(page.locator(`#wl-${c}-reasons`)).toHaveAttribute('aria-label', `Reasons (2 of 3) for ${c} on ${host}`);

    // Mitigate with an empty ControlInventory.
    await page.locator(`#wl-${c}-decision`).selectOption('mitigate');
    await expect(page.locator(`#wl-${c}-control`)).toHaveCount(0);
    await expect(page.locator(`#wl-${c}-control-none`)).toBeVisible();
    expect(await page.locator(`#wl-${c}-decision`).getAttribute('aria-describedby')).toContain(`wl-${c}-control-none`);
    expect(errors).toEqual([]);
  });

  test('submit gate: a missing answer is focused and announced; mitigate needs no control without an inventory', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    const ids = await rowIds(page);
    const last = ids[ids.length - 1];
    const host = await hostOf(page, last);
    await answerAll(page, last);
    await page.locator(`#wl-${ids[0]}-decision`).selectOption('mitigate');
    await pinOne(page);
    const submit = page.locator('#vc-submit-btn');
    await expect(submit).toHaveAttribute('aria-disabled', 'true');
    await tabTo(page, submit);
    await page.keyboard.press('Enter');
    await expect(page.locator(`#wl-${last}-decision`)).toBeFocused();
    await expect(live(page)).toHaveText(`Still needed: decision for ${last} on ${host}, schedule for ${last} on ${host}.`);
    await expect(page.locator('.vc-needed button')).toHaveCount(2);
    await expect(page.locator('.vc-needed')).not.toContainText(ids[0]);
    await expect(page.locator('#debrief-h')).toHaveCount(0);

    await page.locator(`#wl-${last}-decision`).selectOption('patch');
    await page.locator(`#wl-${last}-schedule`).selectOption('standard-cycle');
    await expect(page.locator('.vc-needed')).toHaveCount(0);
    await expect(submit).not.toHaveAttribute('aria-disabled', 'true');
    await tabTo(page, submit);
    await page.keyboard.press('Enter');
    await expect(page.locator('#debrief-h')).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('control picker with a non-empty ControlInventory: listed with names, gated until chosen, the covering control is credited, axe clean', async ({ page }) => {
    test.setTimeout(180_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page, CASE_CONTROLS);

    // The twin is asserted from the data the analyst sees: exactly one ACL in block mode covers a vulnerability.
    await page.locator('#vc-tab-console').click();
    await runQuery(page, "ControlInventory\n| where Mode == 'block' and isnotempty(CoversVulnId)\n| project ControlId, Target");
    await expect(page.locator('.results-table tbody tr')).toHaveCount(1);
    const cells = page.locator('.results-table tbody tr td:not(.col-pin):not(.col-n)');
    const cover = (await cells.nth(0).innerText()).trim();
    expect(cover).toMatch(/^CTL-ACL-\d{4}$/);
    expect(await cells.nth(1).innerText()).toContain('EDGE01');

    // The headline is the finding on the edge appliance; every other row gets a decision that needs no control.
    const ids = await rowIds(page);
    const hosts = await Promise.all(ids.map((id) => hostOf(page, id)));
    const k = hosts.findIndex((h) => h.toUpperCase().startsWith('EDGE01'));
    expect(k, `a worklist row on EDGE01 in ${hosts.join(', ')}`).toBeGreaterThanOrEqual(0);
    const head = ids[k];
    const label = `${head} on ${hosts[k]}`;
    for (const id of ids) {
      if (id === head) continue;
      await page.locator(`#wl-${id}-decision`).selectOption('patch');
      await page.locator(`#wl-${id}-schedule`).selectOption('standard-cycle');
    }
    await pinOne(page);
    await watchLive(page);

    // Mitigate on the headline by keyboard: the picker appears, named, listing every control of the case.
    await tabTo(page, page.locator(`#wl-${head}-decision`));
    await page.keyboard.type('Mitigate');
    await expect(page.locator(`#wl-${head}-decision`)).toHaveValue('mitigate');
    await expect(live(page)).toHaveText(`Choose a control for ${label} in the next field.`);
    await expect(page.locator(`#wl-${head}-control-none`)).toHaveCount(0);
    const picker = page.getByRole('combobox', { name: `Control for ${label}` });
    await expect(picker).toBeVisible();
    await expect(picker).toHaveId(`wl-${head}-control`);
    await expect(picker).toHaveValue('');
    const options = await picker.locator('option').allInnerTexts();
    expect(options[0]).toBe('Choose a control…');
    expect(options.length, options.join(' | ')).toBe(4);
    for (const o of options.slice(1)) expect(o).toMatch(/^CTL-ACL-\d{4} \(ACL\)$/);
    expect(options.some((o) => o.startsWith(`${cover} `)), `${cover} is offered`).toBe(true);

    // The submit gate asks for the control, focuses the picker and announces it, until one is chosen.
    await tabTo(page, page.locator(`#wl-${head}-schedule`));
    await page.keyboard.type('Next');
    await expect(page.locator(`#wl-${head}-schedule`)).toHaveValue('next-window');
    const submit = page.locator('#vc-submit-btn');
    await expect(submit).toHaveAttribute('aria-disabled', 'true');
    await tabTo(page, submit);
    await page.keyboard.press('Enter');
    await expect(picker).toBeFocused();
    await expect(live(page)).toHaveText(`Still needed: control for ${label}.`);
    await expect(page.locator('.vc-needed button')).toHaveCount(1);
    await expect(page.locator('#debrief-h')).toHaveCount(0);

    // Before submit, no template id is on the page or in storage, on a twin that writes ControlInventory rows too.
    const before =
      (await page.content()) +
      (await page.evaluate(() => JSON.stringify([Object.entries(sessionStorage), Object.entries(localStorage)])));
    for (const id of TEMPLATE_IDS) expect(before, id).not.toContain(id);

    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await axeStrict(page, `case with the control picker open ${scheme}`);
    }

    // Choose the covering control by keyboard: the gate clears and the submit works.
    await picker.focus();
    await page.keyboard.type(cover);
    await expect(picker).toHaveValue(cover);
    await expect(page.locator('.vc-needed')).toHaveCount(0);
    await expect(submit).not.toHaveAttribute('aria-disabled', 'true');
    await tabTo(page, submit);
    await page.keyboard.press('Enter');
    await expect(page.locator('#debrief-h')).toBeVisible();

    // The headline's decision is credited, with the control that covers it.
    const card = page.locator(`li.vd-finding[data-finding-id="${head}"]`);
    const decision = (await card.locator('dd[data-field="decision"]').innerText()).replace(/\s+/g, ' ');
    expect(decision).toContain('Yours: Mitigate · Right: Mitigate · Right ');
    expect(decision).toContain(`Controls that cover it: ${cover} · Yours: ${cover}`);
    expect(decision).not.toContain('Half');
    expect((await card.locator('dd[data-field="schedule"]').innerText()).replace(/\s+/g, ' ')).toContain('Yours: Next maintenance window · Right: Next maintenance window · Right');
    await expect(card.locator('.badge:text-is("missed key finding")')).toHaveCount(0);

    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await axeStrict(page, `control debrief ${scheme}`);
    }
    expect(errors).toEqual([]);
  });

  test('tier 3 case: every finding renders, a keyboard reorder is announced, axe clean in both themes, card layout at 360 and 320 px', async ({ page }) => {
    test.setTimeout(240_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page, CASE_TIER3);

    // Tier 3 (DESIGN 2.3): 15 to 25 worklist findings, all rendered.
    const ids = await rowIds(page);
    const n = ids.length;
    expect(n).toBeGreaterThanOrEqual(15);
    expect(n).toBeLessThanOrEqual(25);
    await expect(page.locator('tbody.wl-finding')).toHaveCount(n);
    await expect(page.locator('table.worklist')).toBeVisible();

    // One keyboard reorder with its live-region announcement.
    const first = ids[0];
    await tabTo(page, page.locator(`#wl-${first}-down`));
    await page.keyboard.press('Enter');
    await expect(live(page)).toHaveText(`${first} moved to position 2 of ${n}.`);
    await expect(page.locator(`#wl-${first}-down`)).toBeFocused();
    expect((await rowIds(page))[1]).toBe(first);

    // The twin is asserted from the data the analyst sees: in `vm-dup-plugins` no service bundles its own copy of the
    // portal's library (SoftwareInventory says the portal links the system package), so no row says "bundled with Larkspur Portal".
    await page.locator('#vc-tab-console').click();
    await runQuery(page, "SoftwareInventory\n| where Product has 'bundled with Larkspur Portal'\n| summarize n = count()");
    await expect(page.locator('.results-table tbody tr')).toHaveCount(1);
    expect((await page.locator('.results-table tbody tr td:not(.col-pin):not(.col-n)').first().innerText()).trim()).toBe('0');

    // The focused editor's caret blinks for ever (an infinite animation); leave it before the scans wait for stillness.
    await page.evaluate(() => (document.activeElement as HTMLElement).blur());
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await axeStrict(page, `tier 3 case ${scheme}`);
    }
    await page.emulateMedia({ colorScheme: 'light' });

    // The card layout: no table, one card per finding, no sideways scroll.
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 740 });
      await page.reload();
      await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
      await expect(page.locator('table.worklist')).toHaveCount(0);
      await expect(page.locator('.wl-cards > li')).toHaveCount(n);
      expect(await overflow(page), `${width}px`).toBeLessThanOrEqual(0);
      for (const id of await rowIds(page)) {
        const box = (await page.locator(`li.wl-card[data-finding-id="${id}"]`).boundingBox())!;
        expect(box.x, `${id} at ${width}px`).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width, `${id} at ${width}px`).toBeLessThanOrEqual(width + 0.5);
      }
      for (const scheme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: scheme });
        await axeStrict(page, `tier 3 case ${width}px ${scheme}`);
      }
      await page.emulateMedia({ colorScheme: 'light' });
      expect(await overflow(page), `${width}px after axe`).toBeLessThanOrEqual(0);
    }
    expect(errors).toEqual([]);
  });

  test('the decision control offers avoid; avoid on a case whose truth is avoid is credited in the debrief', async ({ page }) => {
    test.setTimeout(180_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page, CASE_UNUSED);

    // The twin is asserted from the data: in `vm-unused-service` the export job reaches APP01 on the API port
    // (rule allow-app-api, four sessions), not on the console port.
    await page.locator('#vc-tab-console').click();
    await runQuery(page, "FirewallLogs\n| where RuleName == 'allow-app-api'\n| summarize n = count()");
    await expect(page.locator('.results-table tbody tr')).toHaveCount(1);
    expect((await page.locator('.results-table tbody tr td:not(.col-pin):not(.col-n)').first().innerText()).trim()).toBe('4');

    // The headline is the console on APP01; every other row gets a decision that needs no control.
    const ids = await rowIds(page);
    const hosts = await Promise.all(ids.map((id) => hostOf(page, id)));
    const k = hosts.findIndex((h) => h.toUpperCase().startsWith('APP01'));
    expect(k, `a worklist row on APP01 in ${hosts.join(', ')}`).toBeGreaterThanOrEqual(0);
    const head = ids[k];
    for (const id of ids) {
      if (id === head) continue;
      await page.locator(`#wl-${id}-decision`).selectOption('patch');
      await page.locator(`#wl-${id}-schedule`).selectOption('standard-cycle');
    }

    // The decision control offers avoid, with its description; choosing it by keyboard needs no control and no further field.
    const decision = page.locator(`#wl-${head}-decision`);
    expect(await decision.locator('option').allInnerTexts()).toContain('Avoid: remove or disable the component');
    await expect(decision.locator('option[value="avoid"]')).toHaveCount(1);
    await tabTo(page, decision);
    await page.keyboard.type('Avoid');
    await expect(decision).toHaveValue('avoid');
    await expect(page.locator(`#wl-${head}-control`)).toHaveCount(0);
    await expect(page.locator(`#wl-${head}-control-none`)).toHaveCount(0);
    await tabTo(page, page.locator(`#wl-${head}-schedule`));
    await page.keyboard.type('Next');
    await expect(page.locator(`#wl-${head}-schedule`)).toHaveValue('next-window');

    await pinOne(page);
    await page.locator('#vc-submit-btn').click();
    await expect(page.locator('#debrief-h')).toBeVisible();

    // The headline's decision is credited in full.
    const card = page.locator(`li.vd-finding[data-finding-id="${head}"]`);
    const shown = (await card.locator('dd[data-field="decision"]').innerText()).replace(/\s+/g, ' ');
    expect(shown).toMatch(/Yours: Avoid · Right: Avoid · Right(\s|$)/);
    expect(shown).not.toContain('Half');
    expect((await card.locator('dd[data-field="schedule"]').innerText()).replace(/\s+/g, ' ')).toContain('Yours: Next maintenance window · Right: Next maintenance window · Right');
    await expect(card.locator('.badge:text-is("missed key finding")')).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test('no answer key before submit', async ({ page }) => {
    await withProfile(page, PROFILE_RUBRIC);
    await openCase(page);
    await page.getByRole('tab', { name: 'Note' }).click();
    await expect(page.locator('.rubric-live')).toHaveCount(0);
    await expect(page.getByText('Your note is checked in the debrief')).toBeVisible();
    const note = 'owner deadline patch rescan exploited';
    await page.locator('#vc-note').fill(note);
    await expect(page.locator('.rubric-live')).toHaveCount(0);

    const snapshot = async () =>
      (await page.content()) +
      (await page.evaluate(() => JSON.stringify([Object.entries(sessionStorage), Object.entries(localStorage)])));
    const S = await snapshot();
    expect(S).toContain(note);
    await solveAndSubmit(page);
    const L = (await page.locator('#debrief-h').innerText()).trim();
    const R = (await page.locator('h3:has-text("A strong stakeholder note covers") + ul li').allInnerTexts()).map((t) => t.replace(/^✓\s*/, '').trim());
    expect(L.length).toBeGreaterThan(10);
    expect(R.length).toBeGreaterThan(0);
    for (const id of TEMPLATE_IDS) expect(S, id).not.toContain(id);
    expect(S).not.toContain('must-not-miss');
    expect(S).not.toContain('urgency tier');
    expect(S).not.toContain(L);
    for (const r of R) expect(S, r).not.toContain(r);
  });

  test('schema browser, autocomplete and Help per mode', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    const VULN_TABLES = ['VulnFindings', 'ScanRuns', 'VulnIntel', 'SoftwareInventory', 'PatchHistory', 'ControlInventory'];
    const complete = async (text: string): Promise<string[]> => {
      await page.locator('.cm-content').click();
      await page.keyboard.press('Control+A');
      await page.keyboard.press('Delete');
      await page.keyboard.insertText(text);
      await page.keyboard.press('Control+Space');
      await page.waitForTimeout(700);
      const options = await page.locator('.cm-tooltip-autocomplete li').allInnerTexts();
      // A lingering tooltip can cover the editor and stall the next click.
      await page.keyboard.press('Escape');
      return options;
    };

    // SOC case: none of the vulnerability tables.
    await page.goto('/#/case/failed-sign-ins-across-many-accounts/e2e');
    await expect(page.locator('.ws-grid')).toBeVisible({ timeout: 30_000 });
    await page.getByRole('tab', { name: 'Schema' }).click();
    await expect(page.locator('.schema')).toContainText('SigninLogs');
    await expect(page.locator('.schema section[aria-label="Vulnerability tables"]')).toHaveCount(0);
    const schemaText = await page.locator('.schema').innerText();
    expect(schemaText).not.toContain('VulnFindings');
    expect(schemaText).not.toContain('VulnIntel');
    expect(await complete('Sign')).toEqual(expect.arrayContaining([expect.stringContaining('SigninLogs')]));
    expect((await complete('Vuln')).join('|')).not.toContain('VulnFindings');
    expect((await complete('SigninLogs\n| union Vuln')).join('|')).not.toContain('VulnFindings');

    // Vulnerability case: all six, offered in KQL.
    await openCase(page);
    await page.getByRole('tab', { name: 'Schema' }).click();
    const group = page.locator('section[aria-label="Vulnerability tables"]');
    await expect(group).toBeVisible();
    const names = (await group.locator('summary .mono, summary').allInnerTexts()).join(' ');
    for (const t of VULN_TABLES) expect(names, t).toContain(t);
    await expect(group.locator('details')).toHaveCount(6);
    await expect.poll(async () => (await complete('Vuln')).join('|')).toContain('VulnFindings');
    expect((await complete('SigninLogs\n| union Vuln')).join('|')).toContain('VulnFindings');
    // SQL mode has no completion popup in either mode (the editor only installs autocompletion for KQL); see PROGRESS.

    // Help.
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto('/#/help/tables');
      await expect(page.getByRole('heading', { name: 'Vulnerability-management tables' })).toBeVisible();
      await expect(page.locator('details.disclosure')).toHaveCount(24);
      await expect(page.locator('details.disclosure:has(.badge-accent:text-is("vuln cases only"))')).toHaveCount(6);
      await expect(page.locator('details.disclosure:not(:has(.badge-accent))')).toHaveCount(18);
      await axeStrict(page, `help tables ${scheme}`);
      await page.goto('/#/help/keys');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Keyboard');
      await expect(page.getByText('Alt + ↑ / Alt + ↓')).toBeVisible();
      await expect(page.getByText(/drop-down list/)).toBeVisible();
      await axeStrict(page, `help keys ${scheme}`);
    }
    expect(errors).toEqual([]);
  });

  test('axe: library, case and debrief in light and dark', async ({ page }) => {
    test.setTimeout(120_000);
    const errors = watchErrors(page);
    await withProfile(page);
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto('/#/vuln');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
      await axeStrict(page, `library ${scheme}`);

      await openCase(page);
      const ids = await rowIds(page);
      await page.locator(`#wl-${ids[0]}-reasons`).click();
      await page.locator(`#wl-${ids[0]}-decision`).selectOption('mitigate');
      await runQuery(page, 'VulnFindings\n| take 20');
      await page.locator(`#wl-${ids[0]}-down`).click();
      await expect(page.locator('tbody.wl-finding.is-moved')).toHaveCount(1);
      await axeStrict(page, `moved row ${scheme}`, 'tbody.wl-finding.is-moved');
      await expect(page.locator('tbody.wl-finding.is-moved')).toHaveCount(0, { timeout: 6000 });
      await axeStrict(page, `case ${scheme}`);

      await solveAndSubmit(page);
      await page.locator('.vd-finding').first().getByRole('button', { name: /Show the/ }).click();
      await page.locator('.steps li').first().getByRole('button', { name: 'Run it' }).click();
      await expect(page.locator('.steps li').first().locator('.step-result')).toBeVisible();
      await axeStrict(page, `debrief ${scheme}`);
      await page.evaluate(() => sessionStorage.clear());
    }
    expect(errors).toEqual([]);
  });

  test('a missed lesson finding caps the debrief: a binding cap leads with the gate line, names the finding and why, axe clean', async ({ page }) => {
    test.setTimeout(180_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    // First pass: accept every risk. Only the debrief matters: it shows the right answers.
    for (const id of await rowIds(page)) {
      await page.locator(`#wl-${id}-decision`).selectOption('accept');
      await page.locator(`#wl-${id}-schedule`).selectOption('none');
    }
    await pinOne(page);
    await page.locator('#vc-submit-btn').click();
    await expect(page.locator('#debrief-h')).toBeVisible();

    const DECISION_BY_LABEL: Record<string, string> = { Patch: 'patch', Mitigate: 'mitigate', Avoid: 'avoid', Accept: 'accept', Transfer: 'transfer', 'False positive': 'false-positive' };
    const cards = page.locator('li.vd-finding');
    const order = await cards.evaluateAll((els) => els.map((e) => e.getAttribute('data-finding-id')!));
    const right: Record<string, { decision: string; schedule: string; reasons: string[] }> = {};
    for (const id of order) {
      const card = page.locator(`li.vd-finding[data-finding-id="${id}"]`);
      const decision = (await card.locator('dd[data-field="decision"]').innerText()).match(/Right: ([^·]+?) ·/)![1].trim();
      const schedule = (await card.locator('dd[data-field="schedule"]').innerText()).match(/Right: ([^·]+?) ·/)![1].trim();
      const because = (await card.locator('dd[data-field="why"]').innerText()).replace(/^Right because:\s*/, '').trim();
      right[id] = {
        decision: DECISION_BY_LABEL[decision],
        schedule: SCHEDULE_VALUE[SCHEDULE_SHOWN.indexOf(schedule)],
        reasons: because === 'none' ? [] : because.split(', ').slice(0, 3),
      };
      expect(right[id].decision, `${id} decision "${decision}"`).toBeTruthy();
      expect(right[id].schedule, `${id} schedule "${schedule}"`).toBeTruthy();
    }
    // The lesson finding to get wrong: right decision, a schedule later than its SLA allows.
    const lessonCard = page.locator('li.vd-finding:has(.badge:text-is("Lesson finding"))').first();
    const lessonId = (await lessonCard.getAttribute('data-finding-id'))!;
    expect(await lessonCard.locator('dd[data-field="schedule"]').innerText(), `${lessonId} has an SLA that "No change" is later than`).toMatch(/Latest schedule within the SLA: (Emergency change|Next maintenance window|Standard patch cycle)/);

    // Second pass: every finding right and in the debrief's order, but the lesson finding scheduled too late.
    await page.getByRole('button', { name: 'Work it again' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible();
    for (const id of await rowIds(page)) {
      const a = right[id];
      await page.locator(`#wl-${id}-decision`).selectOption(a.decision);
      await page.locator(`#wl-${id}-schedule`).selectOption(id === lessonId ? 'none' : a.schedule);
      if (a.reasons.length > 0) {
        await page.locator(`#wl-${id}-reasons`).click();
        for (const label of a.reasons) await page.locator(`#wl-${id}-reasons-panel`).getByLabel(label, { exact: true }).check();
        await page.locator(`#wl-${id}-reasons`).click();
      }
    }
    for (const [k, id] of order.entries()) {
      await page.locator(`#wl-${id}-prio`).click();
      await page.keyboard.press('Control+A');
      await page.keyboard.type(String(k + 1));
      await page.keyboard.press('Tab');
    }
    expect(await rowIds(page)).toEqual(order);
    await pinOne(page);
    await watchLive(page);
    await page.locator('#vc-submit-btn').click();
    await expect(page.locator('#debrief-h')).toBeVisible();

    // The announcement names the cap, so a screen-reader user hears what the debrief leads with.
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { __live: string[] }).__live.find((x) => x.startsWith('Scored')) ?? ''))
      .toMatch(/Capped at 60: \d+ key findings? missed\./);

    // The cap binds: the sum before the cap is above 60.
    const gate = page.locator('.vd-gate');
    await expect(gate).toHaveCount(1);
    await expect(gate).toBeVisible();
    const text = (await gate.innerText()).replace(/\s+/g, ' ');
    const bound = text.match(/^Capped at 60 \(pass 70; (\d+(?:\.\d+)?) before the cap\)/);
    expect(bound, text).not.toBeNull();
    expect(Number(bound![1]), 'the uncapped sum is above the cap').toBeGreaterThan(60);
    expect(text).toContain(`${lessonId} on `);
    expect(text).toContain('a finding this case turns on, was given a schedule later than its SLA allows');
    await expect(page.locator(`li.vd-finding[data-finding-id="${lessonId}"] .badge:text-is("missed key finding")`)).toBeVisible();

    // The gate line comes before the below-pass line, and "What mattered most" lists the finding once.
    await expect(page.getByText('Below the pass mark.')).toBeVisible();
    const gateFirst = await page.evaluate(() => {
      const g = document.querySelector('.vd-gate')!;
      const p = [...document.querySelectorAll('.debrief-hero-text p')].find((x) => x.textContent!.startsWith('Below the pass mark.') || x.textContent!.startsWith('Passed.'))!;
      return Boolean(g.compareDocumentPosition(p) & Node.DOCUMENT_POSITION_FOLLOWING);
    });
    expect(gateFirst).toBe(true);
    await expect(page.locator(`.vd-lead li[data-miss="${lessonId}"]`)).toHaveCount(1);
    const lead = await page.locator('.vd-lead li').allInnerTexts();
    for (const id of await cards.evaluateAll((els) => els.map((e) => e.getAttribute('data-finding-id')!))) {
      expect(lead.filter((t) => t.includes(`${id} `) || t.includes(`${id},`)).length, `${id} bullets`).toBeLessThanOrEqual(1);
    }

    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await axeStrict(page, `capped debrief ${scheme}`);
    }
    expect(errors).toEqual([]);
  });

  for (const vp of [
    { width: 360, height: 740 },
    { width: 320, height: 640 },
  ]) {
    test(`phone width ${vp.width}: card layout, reflow, no horizontal scroll`, async ({ page }) => {
      test.setTimeout(120_000);
      const errors = watchErrors(page);
      await page.setViewportSize(vp);
      await withProfile(page);
      await page.goto('/#/vuln');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
      expect(await overflow(page)).toBeLessThanOrEqual(0);

      await openCase(page, CASE_UNSORTED);
      const ids = await rowIds(page);
      const n = ids.length;
      expect(ids).toEqual([...ids].sort());
      await expect(page.locator('table.worklist')).toHaveCount(0);
      await expect(page.locator('.wl-cards > li')).toHaveCount(n);
      for (const id of ids) {
        const card = page.locator(`li.wl-card[data-finding-id="${id}"]`);
        for (const f of ['decision', 'schedule', 'reasons', 'up', 'down', 'prio']) await expect(card.locator(`#wl-${id}-${f}`)).toBeVisible();
      }
      const vw = vp.width;
      const bar = await page.locator('.wl-sortbar').boundingBox();
      expect(bar!.x + bar!.width).toBeLessThanOrEqual(vw + 0.5);
      for (const b of await page.locator('.wl-sortbar button').all()) {
        const r = (await b.boundingBox())!;
        expect(r.x).toBeGreaterThanOrEqual(0);
        expect(r.x + r.width).toBeLessThanOrEqual(vw + 0.5);
      }
      const wlBox = (await page.locator('.vc-worklist').boundingBox())!;
      const toolsBox = (await page.locator('.vc-tools').boundingBox())!;
      expect(wlBox.y + wlBox.height).toBeLessThanOrEqual(toolsBox.y + 1);

      await page.locator(`#wl-${ids[0]}-reasons`).click();
      await page.locator(`#wl-${ids[1]}-decision`).selectOption('mitigate');
      expect(await overflow(page)).toBeLessThanOrEqual(0);

      // Keyboard move from a checkbox inside a card.
      const cb = page.locator(`#wl-${ids[0]}-reason-known-exploited`);
      await tabTo(page, cb);
      await page.keyboard.press('Alt+ArrowDown');
      await expect(cb).toBeFocused();
      expect((await rowIds(page))[1]).toBe(ids[0]);
      expect(await overflow(page)).toBeLessThanOrEqual(0);

      if (vp.width === 360) {
        // Deterministic: the moved card is scanned while `.is-moved` is present (scoped, so the scan is quick),
        // the whole page once the highlight is gone; axeStrict waits for transitions to settle first.
        let up = true;
        for (const scheme of ['light', 'dark'] as const) {
          await page.emulateMedia({ colorScheme: scheme });
          await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'));
          await cb.focus();
          await page.keyboard.press(up ? 'Alt+ArrowUp' : 'Alt+ArrowDown');
          up = !up;
          await expect(page.locator('li.wl-card.is-moved')).toHaveCount(1);
          await axeStrict(page, `phone moved card ${scheme}`, 'li.wl-card.is-moved');
          await expect(page.locator('li.wl-card.is-moved')).toHaveCount(0, { timeout: 6000 });
          await axeStrict(page, `phone case ${scheme}`);
        }
        await page.emulateMedia({ colorScheme: 'light' });
      }
      await solveAndSubmit(page);
      expect(await overflow(page)).toBeLessThanOrEqual(0);
      expect(errors).toEqual([]);
    });
  }

  for (const vp of [
    { width: 360, height: 740 },
    { width: 320, height: 640 },
  ]) {
    test(`phone width ${vp.width}: control picker open on every card, no horizontal scroll`, async ({ page }) => {
      test.setTimeout(120_000);
      const errors = watchErrors(page);
      await page.setViewportSize(vp);
      await withProfile(page);
      await openCase(page, CASE_CONTROLS);
      await expect(page.locator('table.worklist')).toHaveCount(0);
      const ids = await rowIds(page);
      expect(ids.length).toBeGreaterThan(0);
      for (const id of ids) await page.locator(`#wl-${id}-decision`).selectOption('mitigate');
      for (const id of ids) {
        const picker = page.locator(`#wl-${id}-control`);
        await expect(picker).toBeVisible();
        const r = (await picker.boundingBox())!;
        expect(r.x).toBeGreaterThanOrEqual(0);
        expect(r.x + r.width).toBeLessThanOrEqual(vp.width + 0.5);
      }
      expect(await overflow(page)).toBeLessThanOrEqual(0);
      for (const scheme of ['light', 'dark'] as const) {
        await page.emulateMedia({ colorScheme: scheme });
        await axeStrict(page, `phone ${vp.width} control pickers open ${scheme}`);
      }
      await page.emulateMedia({ colorScheme: 'light' });
      expect(await overflow(page)).toBeLessThanOrEqual(0);
      expect(errors).toEqual([]);
    });
  }

  for (const w of [360, 320]) {
    test(`help pages do not scroll sideways at ${w}px`, async ({ page }) => {
      await page.setViewportSize({ width: w, height: 740 });
      await withProfile(page);
      for (const hash of ['#/help/tables', '#/help/keys']) {
        await page.goto(`/${hash}`);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        expect(await overflow(page), hash).toBeLessThanOrEqual(0);
      }
    });
  }

  test('a priority typed within 2 s of a move survives the highlight timer and commits afterwards', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    const ids = await rowIds(page);
    const n = ids.length;
    await page.locator(`#wl-${ids[0]}-down`).click();
    await expect(page.locator('tbody.wl-finding.is-moved')).toHaveCount(1);
    const prio = page.locator(`#wl-${ids[0]}-prio`);
    await prio.focus();
    await page.keyboard.press('Control+A');
    await page.keyboard.type(String(n));
    await expect(page.locator('tbody.wl-finding.is-moved')).toHaveCount(0, { timeout: 6000 }); // the timer re-rendered the list
    await page.waitForTimeout(300);
    await expect(prio).toHaveValue(String(n));
    await page.keyboard.press('Enter');
    expect((await rowIds(page))[n - 1]).toBe(ids[0]);
    await expect(live(page)).toHaveText(`${ids[0]} moved to position ${n} of ${n}.`);
    expect(errors).toEqual([]);
  });

  test('revealing hints moves focus to the new hint and announces it; unpinning announces and keeps focus', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    const reveal = page.getByRole('button', { name: /^Reveal hint/ });
    for (let i = 0; ; i++) {
      if ((await reveal.count()) === 0) break;
      await reveal.click();
      await expect(page.locator(`#vc-hint-${i}`)).toBeFocused();
      await expect(live(page)).toContainText(`Hint ${i + 1} of `);
    }
    await expect(page.locator('.hint').last()).toBeFocused();

    await page.locator('#vc-tab-console').click();
    await runQuery(page, 'VulnIntel\n| take 5');
    for (const r of [1, 2, 3]) await page.getByRole('button', { name: `Pin row ${r} as evidence` }).click();
    const unpins = page.locator('.vc-submit .pins .pin-unpin');
    await expect(unpins).toHaveCount(3);
    await unpins.nth(1).focus();
    await page.keyboard.press('Enter'); // the next one takes focus
    await expect(live(page)).toHaveText('Unpinned.');
    await expect(unpins).toHaveCount(2);
    await expect(unpins.nth(1)).toBeFocused();
    await page.keyboard.press('Enter'); // the last one: the previous one takes focus
    await expect(unpins).toHaveCount(1);
    await expect(unpins.nth(0)).toBeFocused();
    await page.keyboard.press('Enter'); // none left: the list heading
    await expect(page.locator('#vc-pins-h')).toBeFocused();
    expect(errors).toEqual([]);
  });

  for (const mode of ['emulated', 'setting'] as const) {
    test(`reduced motion (${mode}): reordering and sorting do not animate`, async ({ page }) => {
      const errors = watchErrors(page);
      if (mode === 'emulated') {
        await page.emulateMedia({ reducedMotion: 'reduce' });
        await withProfile(page);
      } else {
        await withProfile(page, { ...PROFILE, settings: { motion: 'reduce' } });
      }
      for (const vp of [
        { width: 1280, height: 800 },
        { width: 360, height: 740 },
      ]) {
        await page.setViewportSize(vp);
        await page.goto('/#/');
        await openCase(page);
        if (mode === 'setting') await expect(page.locator('html')).toHaveAttribute('data-motion', 'reduce');
        expect(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--dur').trim())).toMatch(/^0m?s$/);
        const still = async (label: string) => {
          await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
          for (let pass = 0; pass < 2; pass++) {
            expect(await page.evaluate(() => document.getAnimations().length), `${label} animations`).toBe(0);
            const t = await page.locator('tbody.wl-finding tr, li.wl-card').evaluateAll((els) => els.map((e) => getComputedStyle(e).transform));
            expect(t.every((x) => x === 'none'), `${label} transform`).toBe(true);
            if (pass === 0) await page.waitForTimeout(300);
          }
        };
        const first = (await rowIds(page))[0];
        await page.locator(`#wl-${first}-down`).click();
        await still(`${mode} ${vp.width} move`);
        await expect(page.locator(`[data-finding-id="${first}"]`)).toHaveClass(/is-moved/);
        await page.locator('#wl-sort-cvss').click();
        await still(`${mode} ${vp.width} sort`);
      }
      expect(errors).toEqual([]);
    });
  }
});

// ---------------------------------------------------------------- WP4: Stats and Study

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
// Objective 2.4 has no case; the false-positive row is the most common mix-up (three findings chose patch).
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

test.describe('vulnerability stats and study integration', () => {
  test('stats of a vuln-only profile: section, objective table, decision matrix, mix-up sentence, no empty state', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page, STATS_PROFILE);
    await page.goto('/#/stats');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('E2E');
    await expect(page.getByText('No graded cases yet')).toHaveCount(0);
    await expect(page.getByText('No SOC cases yet.')).toBeVisible();
    await expect(page.getByRole('heading', { level: 2, name: 'Vulnerability management' })).toBeVisible();
    const section = page.locator('section[aria-labelledby="vuln-h"]');
    await expect(section).toContainText('cases graded');
    await expect(section).toContainText('passed (2 of 3)');
    await expect(section).toContainText('73'); // average score of 90, 50, 80

    // objectives 2.1-2.5, no 4.1 row; a row without cases says so
    const objectives = section.getByRole('table', { name: /each CySA\+ vulnerability objective/ });
    await expect(objectives.getByRole('rowheader')).toHaveCount(5);
    await expect(objectives.getByRole('rowheader').nth(0)).toContainText('2.1 Vulnerability scanning methods');
    await expect(objectives.getByRole('rowheader').nth(2)).toContainText('2.3 Prioritizing vulnerabilities');
    await expect(objectives.getByRole('rowheader').nth(2)).toContainText('Given a scenario, analyze data to prioritize vulnerabilities.');
    await expect(objectives.getByRole('rowheader').filter({ hasText: '4.1' })).toHaveCount(0);
    await expect(objectives.getByRole('row', { name: /2\.4 Mitigating controls/ })).toContainText('No cases yet');
    await expect(objectives.getByRole('row', { name: /2\.3 Prioritizing/ })).toContainText('67%'); // 3 cases: 90, 50, 80 -> 2 of 3 passed
    await expect(objectives.getByRole('row', { name: /2\.3 Prioritizing/ }).getByRole('progressbar')).toHaveAttribute('aria-valuenow', '67');

    // the matrix: a real table with a caption, headers on both axes, the diagonal marked by text
    const matrix = section.locator('table.matrix');
    await expect(matrix.locator('caption')).toContainText('Number of findings by the right decision (rows)');
    await expect(matrix.locator('thead th[scope="col"]')).toHaveText(['Right decision', 'Patch', 'Mitigate', 'Avoid', 'Accept', 'Transfer', 'False positive', 'No decision']);
    await expect(matrix.locator('tbody th[scope="row"]')).toHaveText(['Patch', 'Mitigate', 'Avoid', 'Accept', 'Transfer', 'False positive']);
    const fpRow = matrix.getByRole('row', { name: /^False positive/ });
    await expect(fpRow.getByRole('cell').first()).toHaveText('3'); // chose patch when the answer was false positive: 3 findings
    await expect(fpRow.locator('td.matrix-diag')).toContainText('(matched the right decision)');
    await expect(matrix.locator('td.matrix-diag')).toHaveCount(6);
    await expect(matrix.locator('td.matrix-diag').first()).toContainText('2'); // patch -> patch twice
    await expect(section).toContainText('Most common mix-up: you chose Patch when the answer was False positive (3 findings).');

    // the scrollable regions are focusable and labelled
    for (const name of [/Results by CySA\+ objective/, /Decision matrix/]) {
      await expect(section.getByRole('region', { name })).toHaveAttribute('tabindex', '0');
    }
    expect(errors).toEqual([]);
  });

  test('stats with SOC and vuln attempts keep the SOC sections on SOC attempts only', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page, { ...STATS_PROFILE, attempts: [SOC_ATTEMPT, ...STATS_ATTEMPTS] });
    await page.goto('/#/stats');
    await expect(page.locator('.grid-4 .stat').first().locator('.stat-value')).toHaveText('1'); // SOC cases graded
    await expect(page.getByText('No SOC cases yet.')).toHaveCount(0);
    await expect(page.getByRole('heading', { level: 2, name: 'By category' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Results by category' })).not.toContainText('Vulnerability Management');
    await expect(page.getByRole('heading', { level: 2, name: 'Vulnerability management' })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('a profile with nothing graded shows the empty state and no vuln section', async ({ page }) => {
    await withProfile(page);
    await page.goto('/#/stats');
    await expect(page.getByText('No graded cases yet')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Vulnerability management' })).toHaveCount(0);
  });

  test('stats: axe clean (any impact) in light and dark, no page scroll at 360 and 320 px, the matrix scrolls inside its region', async ({ page }) => {
    test.setTimeout(90_000);
    const errors = watchErrors(page);
    await withProfile(page, { ...STATS_PROFILE, attempts: [SOC_ATTEMPT, ...STATS_ATTEMPTS] });
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.goto('/#/stats');
      await expect(page.locator('section[aria-labelledby="vuln-h"]')).toBeVisible();
      await axeStrict(page, `stats ${scheme}`);
      await axeFull(page, `stats full rule set, mixed profile ${scheme}`);
    }
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 740 });
      await page.goto('/#/stats');
      await expect(page.locator('section[aria-labelledby="vuln-h"]')).toBeVisible();
      expect(await overflow(page), `page scroll at ${width}`).toBeLessThanOrEqual(0);
      const region = page.getByRole('region', { name: /Decision matrix/ });
      const box = await region.evaluate((el) => ({ scroll: el.scrollWidth, client: el.clientWidth }));
      expect(box.scroll, `matrix scrolls inside its region at ${width}`).toBeGreaterThan(box.client);
      await region.focus();
      await expect(region).toBeFocused();
      await axeStrict(page, `stats ${width}px`);
    }
    expect(errors).toEqual([]);
  });

  test('stats: full axe rule set (best practice included) on a vuln-only profile, light and dark', async ({ page }) => {
    test.setTimeout(60_000);
    await withProfile(page, STATS_PROFILE);
    await page.setViewportSize({ width: 1280, height: 900 });
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto('/#/stats');
      await expect(page.locator('section[aria-labelledby="vuln-h"]')).toBeVisible();
      await axeFull(page, `stats full rule set, vuln-only profile ${scheme}`);
    }
  });

  test('study: the objectives card renders, vulnerability is not an alert category, a due vuln card starts the suggested twin', async ({ page }) => {
    const errors = watchErrors(page);
    const card = { templateId: 'vm-needed-service', ef: 2.5, interval: 1, reps: 1, lapses: 0, due: 0, last: 0, lastPercent: 40 };
    await withProfile(page, { ...PROFILE, cards: { 'vm-needed-service': card }, attempts: [vulnRecord(1, 'vm-needed-service', 40, ['2.3', '2.5', '4.1'], [fd(1, 'patch', 'accept', 'wrong')])] });
    await page.goto('/#/study');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Your study plan');
    await expect(page.getByRole('heading', { level: 2, name: 'CySA+ objectives' })).toBeVisible();
    const items = page.getByRole('list', { name: 'Mastery by CySA+ objective' }).getByRole('listitem');
    await expect(items).toHaveCount(6);
    await expect(items.nth(2)).toContainText('2.3 Prioritizing vulnerabilities');
    await expect(items.nth(5)).toContainText('4.1 Vulnerability management reporting');
    await expect(page.getByRole('list', { name: 'Mastery by category' })).not.toContainText('Vulnerability');
    await expect(page.getByRole('list', { name: 'Mastery by CySA+ domain' })).toContainText('2.0 Vulnerability Management');
    // the only due card is the vuln one: it is the suggestion, and the due list names it
    await expect(page.locator('section[aria-labelledby="next-h"]')).toContainText('Scan review: optional admin consoles and internal servers');
    await expect(page.locator('section[aria-labelledby="up-h"]')).toContainText('Scan review: optional admin consoles and internal servers');
    await axeStrict(page, 'study');

    await page.getByRole('button', { name: /^Start/ }).click();
    await expect(page).toHaveURL(/#\/vuln\/[^/]+\/[^/]+$/);
    const [, slug, seed] = new URL(page.url()).hash.match(/#\/vuln\/([^/]+)\/([^/]+)$/)!;
    const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.slug === decodeURIComponent(slug))!;
    expect(resolveVulnTemplate(type, decodeURIComponent(seed)).id).toBe('vm-needed-service');
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
    expect(errors).toEqual([]);
  });
});

// WP5: a finding left open in a vulnerability case becomes one extra alert in the next shift (DESIGN section 8),
// and its debrief links back to that case. A ledger entry is seeded, taken from a real build of the e2e world.
test.describe('continuity: vulnerability case to SOC shift', () => {
  const HOOK_RULE = 'Exploit signature match on a monitored service';
  const WORLD_SEED = PROFILE.worldSeed;

  function seededEntry() {
    const w = generateWorld(WORLD_SEED);
    for (const type of vulnCaseTypes(VULN_TEMPLATES)) {
      for (const seed of ['e2e', 'e2e-a', 'e2e-b', 'e2e-c']) {
        const t = resolveVulnTemplate(type, seed);
        const v = buildVulnScenario({ worldSeed: WORLD_SEED, templateId: t.id, seed, world: w });
        const f = v.case.findings.find((x) => x.mustNotMiss && x.sharedHost && x.truth.decision !== 'false-positive' && x.truth.decision !== 'mitigate' && !x.truth.mitigation?.length && /^SIMVULN-/.test(x.vulnId));
        if (!f) continue;
        const caseRef = `${t.id}~${seed}`;
        const entry = { id: `${caseRef}/${f.findingId}@1700000000000`, vulnId: f.vulnId, host: f.host, decision: 'false-positive', schedule: 'none', decidedDay: 20000, caseRef };
        return { entry, type, seed };
      }
    }
    throw new Error('no eligible finding');
  }

  const stored = (page: Page) => page.evaluate(() => JSON.parse(localStorage.getItem('soc-triage-sim:v2')!));

  async function startShift(page: Page): Promise<void> {
    await page.goto('/#/');
    await page.getByRole('radio', { name: 'Untimed' }).check();
    await page.getByRole('button', { name: 'Start shift' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 30_000 });
  }

  test('a pending ledger entry adds one alert, survives a reload, and the debrief links back; axe clean in both themes', async ({ page }) => {
    const errors = watchErrors(page);
    const { entry, type, seed } = seededEntry();
    await withProfile(page, { ...PROFILE, vulnLedger: [entry] });
    await startShift(page);
    const items = page.locator('.queue-item');
    const n = await items.count();
    // exactly one hook alert in the queue, and the ledger entry is consumed
    const hookItem = items.filter({ hasText: HOOK_RULE });
    await expect(hookItem).toHaveCount(1);
    const alertId = (await hookItem.locator('.mono').first().textContent())!.trim();
    // the profile is saved a moment after it changes
    await expect.poll(async () => (await stored(page)).vulnLedger?.[0]?.consumed).toBe(true);
    let p = await stored(page);
    expect(p.vulnLedger).toHaveLength(1);
    expect(p.activeShift.vulnHook.ledgerId).toBe(entry.id);
    // nothing before submit points at the vulnerability case
    await hookItem.click();
    await expect(page.locator('.ws-grid')).toBeVisible();
    await expect(page.locator('main')).not.toContainText(/vulnerability case|ledger/i);
    await page.goto('/#/shift');
    await expect(items).toHaveCount(n, { timeout: 30_000 });

    // a reload rebuilds the same queue; the entry is not given back and not taken twice
    await page.reload();
    await expect(items).toHaveCount(n, { timeout: 30_000 });
    await expect(items.filter({ hasText: HOOK_RULE })).toHaveCount(1);
    expect((await items.filter({ hasText: HOOK_RULE }).locator('.mono').first().textContent())!.trim()).toBe(alertId);
    p = await stored(page);
    expect(p.vulnLedger).toHaveLength(1);
    expect(p.vulnLedger[0].consumed).toBe(true);

    // work the hook alert, hand over, review it
    await items.filter({ hasText: HOOK_RULE }).click();
    await expect(page.locator('.ws-grid')).toBeVisible();
    await page.getByRole('radio', { name: 'Benign / expected' }).check();
    await page.getByRole('radio', { name: 'Informational' }).check();
    await page.getByRole('radio', { name: 'Close' }).check();
    await page.getByRole('button', { name: 'Submit & back to queue' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible();
    await page.getByRole('button', { name: 'Hand over' }).click();
    await page.getByRole('button', { name: 'Hand over now' }).click();
    await expect(page.getByText('Shift 1 handover')).toBeVisible();
    await page.getByRole('button', { name: `Review ${alertId}` }).click();
    const para = page.locator('.vuln-link-back');
    const link = para.locator('a');
    await expect(link).toHaveCount(1, { timeout: 30_000 });
    await expect(para).toContainText(entry.vulnId);
    await expect(para).toContainText('false positive');
    await expect(para).toContainText(type.title);
    await expect(link).toHaveAttribute('href', `#/vuln/${type.slug}/${seed}`);

    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await axeStrict(page, `hook debrief ${scheme}`);
    }
    await page.emulateMedia({ colorScheme: 'light' });

    // keyboard: the link takes focus and Enter opens the case
    await link.focus();
    await expect(link).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
    expect(errors).toEqual([]);
  });

  test('no ledger entry, no extra alert and no ledger written', async ({ page }) => {
    await withProfile(page);
    await startShift(page);
    await expect(page.locator('.queue-item').filter({ hasText: HOOK_RULE })).toHaveCount(0);
    expect((await stored(page)).vulnLedger).toBeUndefined();
  });

  test('phone width: the hook debrief does not scroll the page', async ({ page }) => {
    const { entry } = seededEntry();
    await page.setViewportSize({ width: 360, height: 740 });
    await withProfile(page, { ...PROFILE, vulnLedger: [entry] });
    await startShift(page);
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    const alertId = (await page.locator('.queue-item').filter({ hasText: HOOK_RULE }).locator('.mono').first().textContent())!.trim();
    await page.getByRole('button', { name: 'Hand over' }).click();
    await page.getByRole('button', { name: 'Hand over now' }).click();
    await expect(page.getByText('Shift 1 handover')).toBeVisible();
    await page.getByRole('button', { name: `Review ${alertId}` }).click();
    await expect(page.locator('.vuln-link-back a')).toBeVisible({ timeout: 30_000 });
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await axeStrict(page, 'hook debrief 360');
  });
});

// WP6 (polish): the nav item, the Help section for the mode and its keyboard routes, the closed-duplicate debrief line.
test.describe('polish: nav, Help glossary, debrief wording', () => {
  const NAV_LABELS = ['Console', 'Shift', 'Practice', 'Vulns', 'Study', 'Intel', 'Stats', 'Help'];

  test('nav: Vulns sits between Practice and Study, is current on the library and a case, and the keyboard reaches it', async ({ page }) => {
    test.setTimeout(90_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto('/#/practice');
    await expect(page.locator('.lib-card').first()).toBeVisible();
    await expect(page.locator('#primary-nav a')).toHaveText(NAV_LABELS);
    await expect(page.locator('#primary-nav a[aria-current="page"]')).toHaveText('Practice');

    // Keyboard only: from the Practice link, Tab to Vulns, Enter.
    const practice = page.locator('#primary-nav a', { hasText: 'Practice' });
    const vulns = page.locator('#primary-nav a', { hasText: 'Vulns' });
    await tabTo(page, practice);
    await page.keyboard.press('Tab');
    await expect(vulns).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/vuln$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.locator('#primary-nav a[aria-current="page"]')).toHaveText('Vulns');

    await openCase(page);
    await expect(page.locator('#primary-nav a[aria-current="page"]')).toHaveText('Vulns');
    expect(errors).toEqual([]);
  });

  // The header must fit at every width the menu is not collapsed: no page scroll, no overlap of the nav and the right-hand block.
  const HEADER_WIDTHS = [901, 920, 938, 1000, 1024, 1041, 1060, 1080, 1100, 1140, 1280];
  async function headerFits(page: Page): Promise<void> {
    for (const width of HEADER_WIDTHS) {
      await page.setViewportSize({ width, height: 800 });
      await page.goto('/#/vuln');
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
      expect(await overflow(page), `page scroll at ${width}`).toBeLessThanOrEqual(0);
      const gap = await page.evaluate(() => {
        const last = document.querySelector('#primary-nav a:last-child')!.getBoundingClientRect();
        const right = document.querySelector('.shell-right')!.getBoundingClientRect();
        const header = document.querySelector('.shell-header')!.getBoundingClientRect();
        return { overlap: last.right - right.left, wraps: last.bottom > header.bottom };
      });
      expect(gap.overlap, `nav overlaps the right side of the header at ${width}`).toBeLessThanOrEqual(0);
      expect(gap.wraps, `nav wraps at ${width}`).toBe(false);
    }
  }

  test('nav: the header does not overflow with a 3,800+ XP rank and a shift in progress, from 901 px up', async ({ page }) => {
    test.setTimeout(90_000);
    await withProfile(page, { ...PROFILE, xp: 4000, activeShift: { number: 1, budget: 30, startedAt: Date.now(), elapsedSec: 0, drafts: {}, submissions: [] } });
    await headerFits(page);
    await expect(page.locator('.rank-chip')).toContainText('Incident Responder');
  });

  test('nav: the header does not overflow with eight items, from 901 px up; the collapsed menu reaches Vulns by keyboard at 360 and 320 px', async ({ page }) => {
    test.setTimeout(90_000);
    await withProfile(page);
    await headerFits(page);
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 740 });
      await page.goto('/#/practice');
      await expect(page.locator('.lib-card').first()).toBeVisible();
      const toggle = page.getByRole('button', { name: 'Menu' });
      await expect(page.locator('#primary-nav')).toBeHidden();
      await tabTo(page, toggle);
      await page.keyboard.press('Enter');
      await expect(toggle).toHaveAttribute('aria-expanded', 'true');
      await expect(page.locator('#primary-nav a')).toHaveText(NAV_LABELS);
      const box = (await page.locator('#primary-nav').boundingBox())!;
      expect(box.x + box.width, `menu width at ${width}`).toBeLessThanOrEqual(width + 0.5);
      expect(await overflow(page), `page scroll with the menu open at ${width}`).toBeLessThanOrEqual(0);
      if (width === 360) await axeStrict(page, 'open menu 360');
      await tabTo(page, page.locator('#primary-nav a', { hasText: 'Vulns' }));
      await page.keyboard.press('Enter');
      await expect(page).toHaveURL(/#\/vuln$/);
      await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
      await expect(page.locator('#primary-nav')).toBeHidden();
    }
  });

  test('Help: the library, the case and the debrief link to the glossary; Tab and Enter reach it with no mouse', async ({ page }) => {
    test.setTimeout(180_000);
    const errors = watchErrors(page);
    await withProfile(page);
    const helpLink = page.getByRole('link', { name: 'Vulnerability terms (Help)' });

    // Library.
    await page.goto('/#/vuln');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await tabTo(page, helpLink);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.locator('main h1')).toHaveText('Vulnerability management');
    await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();

    // Case screen: from the brief area, no mouse.
    await openCase(page);
    await tabTo(page, helpLink);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();
    await page.goBack();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    // Debrief: the link keeps the debrief, so Back returns to the same review, and the attempt is not recorded again.
    await solveAndSubmit(page);
    const hero = page.locator('.debrief-hero-text');
    const heroText = await hero.innerText();
    const attempts = async () => (await page.evaluate(() => JSON.parse(localStorage.getItem('soc-triage-sim:v2')!))).attempts.length;
    await expect.poll(attempts).toBe(1);
    await tabTo(page, helpLink);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();
    await page.goBack();
    await expect(page.locator('#debrief-h')).toBeVisible({ timeout: 30_000 });
    expect(await hero.innerText()).toBe(heroText);
    await expect(page.locator('.vc-worklist')).toHaveCount(0);

    // Debrief to the nav and back: the debrief is still there, the attempt still counts once.
    await tabTo(page, page.locator('#primary-nav a', { hasText: 'Vulns' }), 'Shift+Tab');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/vuln$/);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await page.goBack();
    await expect(page.locator('#debrief-h')).toBeVisible({ timeout: 30_000 });
    expect(await hero.innerText()).toBe(heroText);
    expect(await attempts()).toBe(1);

    // Reopening the same case URL in this tab (a reload, or a link such as the SOC alert debrief's) shows the stored debrief, not an empty worklist.
    await page.reload();
    await expect(page.locator('#debrief-h')).toBeVisible({ timeout: 30_000 });
    expect(await attempts()).toBe(1);

    // "Work it again" forgets the finished debrief: Help and Back then show the empty worklist.
    await page.getByRole('button', { name: 'Work it again' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible();
    await tabTo(page, helpLink);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await page.goBack();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('#debrief-h')).toHaveCount(0);

    // The Help sections list names the section and marks it current.
    await page.goto('/#/help/start');
    await tabTo(page, page.locator('.help-nav a', { hasText: 'Vulnerability management' }));
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.locator('.help-nav a[aria-current="page"]')).toHaveText('Vulnerability management');

    // The nav: Help item, then the section entry, keyboard only.
    await page.goto('/#/vuln');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability cases');
    await tabTo(page, page.locator('#primary-nav a', { hasText: 'Help' }), 'Shift+Tab');
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help/);
    await tabTo(page, page.locator('.help-nav a', { hasText: 'Vulnerability management' }));
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/help\/vuln$/);
    await expect(page.locator('main h1')).toBeFocused();
    await expect(page.locator('.help-nav a[aria-current="page"]')).toHaveText('Vulnerability management');
    expect(errors).toEqual([]);
  });

  test('Help glossary: the terms, both feed explainers verbatim with their sources, links open in a new tab safely, no real CVE id', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await page.goto('/#/help/vuln');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Vulnerability management');
    const main = page.locator('main');
    for (const term of [
      'Credentialed vs unauthenticated scan', 'Backport', 'Stale result', 'Duplicate finding', 'CVSS base vs environmental', 'Sim-KEV', 'Sim-EPSS', 'Compensating control',
      'Patch', 'Mitigate', 'Avoid', 'Accept', 'Transfer', 'False positive', 'Schedule', 'SLA by severity class', 'Change freeze', 'Must-not-miss finding', 'Lesson finding and key finding', 'Urgency tier',
    ]) {
      await expect(main.locator('dt', { hasText: term }).first(), term).toBeVisible();
    }
    const text = (await main.innerText()).replace(/\s+/g, ' ');
    expect(text).toContain('Simulated list modeled on the CISA Known Exploited Vulnerabilities (KEV) catalog: vulnerabilities with evidence of exploitation in the wild. Entries here are fictional.');
    expect(text).toContain("Simulated score modeled on FIRST's Exploit Prediction Scoring System (EPSS): estimated probability that a vulnerability is exploited in the wild in the next 30 days, with its percentile rank. Values here are fictional but follow the real distribution.");
    expect(text).toContain('Ties inside a tier are free');
    expect(text).toContain('MAV:A');
    expect(text).not.toMatch(/\bCVE-\d{4}-\d{4,}/i);
    const kev = main.locator('a[href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]');
    const epss = main.locator('a[href="https://www.first.org/epss/"]');
    for (const a of [kev, epss]) {
      await expect(a).toHaveCount(1);
      await expect(a).toHaveAttribute('target', '_blank');
      await expect(a).toHaveAttribute('rel', 'noopener noreferrer');
      await expect(a).toContainText('(opens in a new tab)');
    }
    // Every external link in the section follows the same rule.
    const external = await main.locator('a[href^="http"]').evaluateAll((els) => els.map((a) => ({ href: a.getAttribute('href'), rel: a.getAttribute('rel'), target: a.getAttribute('target') })));
    expect(external).toHaveLength(2);
    for (const l of external) expect(l, l.href ?? '').toMatchObject({ rel: 'noopener noreferrer', target: '_blank' });
    // In-app cross links from the other sections.
    for (const section of ['start', 'tables', 'grading']) {
      await page.goto(`/#/help/${section}`);
      await expect(page.locator('main a[href="#/help/vuln"]').first(), section).toBeVisible();
    }
    expect(errors).toEqual([]);
  });

  test('Help glossary: axe clean (full rule set) in both themes, no page scroll at 360 and 320 px', async ({ page }) => {
    test.setTimeout(90_000);
    const errors = watchErrors(page);
    await withProfile(page);
    await page.setViewportSize({ width: 1280, height: 900 });
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto('/#/help/vuln');
      await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();
      await axeStrict(page, `help vuln ${scheme}`);
      await axeFull(page, `help vuln full rule set ${scheme}`);
    }
    await page.emulateMedia({ colorScheme: 'light' });
    for (const width of [360, 320]) {
      await page.setViewportSize({ width, height: 740 });
      await page.goto('/#/help/vuln');
      await expect(page.getByRole('heading', { level: 2, name: 'Glossary' })).toBeVisible();
      expect(await overflow(page), `page scroll at ${width}`).toBeLessThanOrEqual(0);
      // Each term sits above its definition: no definition is squeezed into a narrow column.
      const widths = await page.evaluate(() => {
        const article = document.querySelector('article.prose')!.getBoundingClientRect().width;
        return { article, dd: [...document.querySelectorAll('.vuln-glossary dd')].map((d) => d.getBoundingClientRect().width) };
      });
      expect(widths.dd.length).toBeGreaterThan(15);
      for (const w of widths.dd) expect(w, `a glossary definition at ${width}px`).toBeGreaterThanOrEqual(widths.article * 0.8);
      await axeFull(page, `help vuln full rule set ${width}px`);
    }
    expect(errors).toEqual([]);
  });

  test('Help links on the library, the case and the debrief: no page scroll at 360 px, axe clean', async ({ page }) => {
    test.setTimeout(120_000);
    await withProfile(page);
    await page.setViewportSize({ width: 360, height: 740 });
    await page.goto('/#/vuln');
    await expect(page.getByRole('link', { name: 'Vulnerability terms (Help)' })).toBeVisible();
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await axeStrict(page, 'library help link 360');
    await openCase(page);
    await expect(page.getByRole('link', { name: 'Vulnerability terms (Help)' })).toBeVisible();
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await solveAndSubmit(page);
    await expect(page.getByRole('link', { name: 'Vulnerability terms (Help)' })).toBeVisible();
    expect(await overflow(page)).toBeLessThanOrEqual(0);
    await page.evaluate(() => (document.activeElement as HTMLElement).blur());
    await axeStrict(page, 'debrief 360');
  });

  test('library: a search with no match says so, not that the tier is empty', async ({ page }) => {
    await withProfile(page);
    await page.goto('/#/vuln');
    await page.getByLabel('Search').fill('zzzzz');
    await expect(page.getByText('No case type matches "zzzzz".')).toBeVisible();
    await expect(page.getByText('No vulnerability cases at this tier yet.')).toHaveCount(0);
    await page.getByLabel('Search').fill('');
    await expect(page.locator('.lib-card').first()).toBeVisible();
  });

  test('a closed duplicate reads as one in the debrief, not as a plain false positive; each finding has a heading', async ({ page }) => {
    test.setTimeout(240_000);
    const errors = watchErrors(page);
    await withProfile(page);
    // The twin and its duplicates come from the data: seed `e2e` of the tier-3 case type.
    const type = vulnCaseTypes(VULN_TEMPLATES).find((t) => t.slug === 'scan-review-shared-services-and-payment-systems')!;
    const template = resolveVulnTemplate(type, 'e2e');
    const built = buildVulnScenario({ worldSeed: PROFILE.worldSeed, templateId: template.id, seed: 'e2e', world: generateWorld(PROFILE.worldSeed) });
    const dups = built.case.findings.filter((f) => f.truth.decision === 'false-positive' && f.truth.reasons.includes('duplicate-root-cause'));
    expect(dups.length, `closed duplicates in ${template.id}`).toBeGreaterThan(0);
    const lessonDup = dups.find((f) => f.lesson);

    await openCase(page, CASE_TIER3);
    // Patch every row (the learner who does not see the duplicates), then submit.
    for (const id of await rowIds(page)) {
      await page.locator(`#wl-${id}-decision`).selectOption('patch');
      await page.locator(`#wl-${id}-schedule`).selectOption('standard-cycle');
    }
    await pinOne(page);
    await page.locator('#vc-submit-btn').click();
    await expect(page.locator('#debrief-h')).toBeVisible();

    for (const f of dups) {
      const card = page.locator(`li.vd-finding[data-finding-id="${f.findingId}"]`);
      const shown = (await card.locator('dd[data-field="decision"]').innerText()).replace(/\s+/g, ' ');
      expect(shown, f.findingId).toContain('Yours: Patch · Right: False positive (a duplicate: closed with the reason Duplicate root cause) ·');
      // Each card has a heading that names the finding.
      await expect(card.getByRole('heading', { level: 3 }).first()).toContainText(f.findingId);
    }
    if (lessonDup) {
      const lead = page.locator(`.vd-lead li[data-miss="${lessonDup.findingId}"]`);
      await expect(lead).toHaveCount(1);
      await expect(lead).toContainText('The right call was False positive (closed as a duplicate)');
    }
    expect(await page.locator('li.vd-finding > .finding-head > h3').count()).toBe(built.case.findings.length);
    expect(errors).toEqual([]);
  });
});
