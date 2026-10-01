import { test, expect, type Locator, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// Vulnerability-management mode: acceptance criteria (1)-(10) of WP1e.
// A fixed profile so every run works in the same fictional organisation.
const PROFILE = { version: 2, worldSeed: 'e2e-world', analystName: 'E2E', attempts: [] };
const PROFILE_XP = { ...PROFILE, xp: 100 };
const PROFILE_RUBRIC = { ...PROFILE, settings: { showRubricLive: true } };
const CASE = '#/vuln/scan-review-internal-servers/e2e';
// Its template (spec) order is not FindingId-ascending; tests/vuln-worklist.test.ts pins that.
const CASE_UNSORTED = '#/vuln/scan-review-web-servers/e2e';
const TEMPLATE_IDS = ['vm-kev-internal', 'vm-nokev-internal', 'vm-stale-scan', 'vm-backport-fp'];
const LIVE = '[role="status"][aria-live="polite"][aria-atomic="true"]';

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

test.describe('vulnerability mode', () => {
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
    await expect(page.locator('.lib-card')).toHaveCount(1);
    await expect(page.locator('.lib-card h2')).toHaveText('Scan review: web servers');
    await page.getByRole('button', { name: 'Start: Scan review: web servers' }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    await page.goto('/#/vuln');
    await page.locator('#vlib-diff').selectOption('tier1');
    await expect(page.locator('.lib-card h2')).toHaveText(['Scan review: file servers', 'Scan review: internal servers'].sort());
    await page.locator('.lib-card').first().getByRole('button', { name: /^Start:/ }).click();
    await expect(page.locator('.vc-worklist')).toBeVisible({ timeout: 30_000 });

    await page.goto('/#/vuln');
    await page.locator('#vlib-diff').selectOption('tier3');
    await expect(page.getByText('No vulnerability cases at this tier yet.')).toBeVisible();

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
