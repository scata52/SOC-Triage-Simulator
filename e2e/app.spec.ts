import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// A fixed profile so every run works in the same fictional organisation.
const PROFILE = { version: 2, worldSeed: 'e2e-world', analystName: 'E2E', attempts: [] };
const CASE = '#/case/failed-sign-ins-across-many-accounts/e2e';

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

async function axe(page: Page, label: string): Promise<void> {
  const r = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
  const bad = r.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
  expect(bad.map((v) => `${label}: ${v.id} — ${v.help} (${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(' | ')})`)).toEqual([]);
}

async function openCase(page: Page): Promise<void> {
  await page.goto(`/${CASE}`);
  await expect(page.locator('.ws-grid')).toBeVisible({ timeout: 30_000 });
}

async function runQuery(page: Page, kql: string): Promise<void> {
  await page.locator('.cm-content').click();
  await page.keyboard.press('Control+A');
  await page.keyboard.press('Delete');
  await page.keyboard.insertText(kql);
  await page.keyboard.press('Control+Enter');
  await expect(page.locator('.results-meta')).toBeVisible();
}

test.describe('pages', () => {
  test('every page renders without errors and passes axe', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    for (const [hash, heading] of [
      ['#/', /Good (morning|afternoon|evening)|Late one/],
      ['#/practice', 'Alert library'],
      ['#/study', 'Your study plan'],
      ['#/intel', 'What IR knows'],
      ['#/stats', 'Stats'],
      ['#/help', 'How it works'],
      ['#/help/kql', 'KQL in five minutes'],
      ['#/help/reference', 'Query reference'],
      ['#/settings', 'Settings'],
      ['#/shift', 'No shift in progress'],
    ] as const) {
      await page.goto(`/${hash}`);
      await expect(page.getByRole('heading', { level: 1 })).toHaveText(heading);
      await axe(page, hash);
    }
    expect(errors).toEqual([]);
  });

  test('dark theme passes axe too', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await withProfile(page);
    await page.goto('/#/');
    await axe(page, 'home dark');
    await openCase(page);
    await runQuery(page, 'SigninLogs\n| take 20');
    await axe(page, 'case dark');
  });
});

test.describe('investigation', () => {
  test('query, pin, report, submit, debrief', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await openCase(page);
    await expect(page.getByRole('heading', { name: 'Failed sign-ins across many accounts' })).toBeVisible();

    // A KQL error is reported and highlighted, not thrown.
    await runQuery(page, 'SigninLogs | where NoSuchColumn == 1').catch(() => {});
    await expect(page.locator('.query-error')).toContainText('NoSuchColumn');

    await runQuery(page, 'SigninLogs\n| where ResultType != 0\n| summarize Failures = count(), Users = dcount(UserPrincipalName) by IPAddress\n| sort by Users desc');
    await expect(page.locator('.results-meta')).toContainText('aggregated rows cannot be pinned');
    await runQuery(page, 'SigninLogs\n| where ResultType == 0\n| take 20');
    const pin = page.getByRole('button', { name: 'Pin row 1 as evidence' });
    await pin.click();
    await expect(page.getByRole('button', { name: 'Unpin row 1 as evidence' })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.pins li')).toHaveCount(1);

    // Row inspector → add a value as an indicator.
    await page.getByRole('button', { name: 'Inspect row 1', exact: true }).click();
    await page.getByRole('button', { name: 'Add IPAddress value as an indicator' }).click();
    await expect(page.locator('.indicators li')).toHaveCount(1);

    // Free-typed, defanged indicator.
    await page.getByLabel('Indicator value').fill('198.51.100[.]99');
    await page.getByLabel('Indicator value').press('Enter');
    await expect(page.locator('.indicators li')).toHaveCount(2);

    await page.getByRole('radio', { name: 'True positive' }).check();
    await page.getByRole('radio', { name: 'High' }).check();
    await page.getByRole('radio', { name: 'Escalate to IR' }).check();
    const combo = page.getByRole('combobox', { name: 'MITRE ATT&CK' });
    await combo.fill('T1110.003');
    await combo.press('Enter');
    await expect(page.locator('.tech-chips li')).toHaveCount(1);
    await page.getByLabel('Handover note').fill('Password spray via legacy auth; one account compromised. Reset and enforce MFA, block legacy authentication.');
    await axe(page, 'workspace');
    await page.getByRole('button', { name: 'Submit verdict' }).click();

    await expect(page.getByRole('heading', { name: 'Score breakdown' })).toBeVisible();
    await expect(page.locator('.debrief-hero h1')).not.toBeEmpty();
    await expect(page.locator('.grade-table tbody tr')).toHaveCount(6);
    // The reference investigation runs against the same logs.
    await page.locator('.steps li').first().getByRole('button', { name: 'Run it' }).click();
    await expect(page.locator('.steps li').first().locator('.step-result')).toBeVisible();
    // Evidence rows can be revealed.
    await page.locator('.findings li').first().getByRole('button', { name: /Show the/ }).click();
    await expect(page.locator('.findings li').first().locator('.evidence-rows table').first()).toBeVisible();
    await axe(page, 'debrief');

    // Progress persisted.
    await page.goto('/#/stats');
    await expect(page.locator('.stat-value').first()).toHaveText('1');
    await page.reload();
    await expect(page.locator('.stat-value').first()).toHaveText('1');
    expect(errors).toEqual([]);
  });

  test('results sort, and a runaway query is stopped without losing the case', async ({ page }) => {
    await page.addInitScript(() => ((window as unknown as { __SOC_QUERY_TIMEOUT__: number }).__SOC_QUERY_TIMEOUT__ = 1500));
    await withProfile(page);
    await openCase(page);
    await runQuery(page, 'SigninLogs\n| project TimeGenerated, UserPrincipalName, ResultType\n| take 40');
    await page.getByRole('button', { name: 'ResultType: sort ascending' }).click();
    await expect(page.locator('th[aria-sort="ascending"]')).toHaveCount(1);
    const first = await page.locator('.results-table tbody tr').first().locator('td').last().innerText();
    await page.getByRole('button', { name: 'ResultType: sort descending' }).click();
    await expect(page.locator('th[aria-sort="descending"]')).toHaveCount(1);
    expect(Number(await page.locator('.results-table tbody tr').first().locator('td').last().innerText())).toBeGreaterThanOrEqual(Number(first));
    await expect(page.getByText('SQL generated from your KQL')).toBeVisible();

    // Catastrophic backtracking: the worker is killed and respawned.
    await runQuery(page, 'DeviceProcessEvents\n| extend s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n| where s matches regex "(a|aa)+b"').catch(() => {});
    await expect(page.locator('.query-error')).toContainText('was stopped', { timeout: 15_000 });
    await runQuery(page, 'SigninLogs\n| take 3');
    await expect(page.locator('.results-table tbody tr')).toHaveCount(3);
  });

  test('the editor never traps Tab, and the skip link works', async ({ page }) => {
    await withProfile(page);
    await page.goto('/#/');
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('main')).toBeFocused();

    await openCase(page);
    await page.locator('.cm-content').click();
    await page.keyboard.press('Tab');
    await expect(page.locator('.cm-content')).not.toBeFocused();
  });
});

test.describe('shift', () => {
  test('start, work an alert, hand over, see consequences', async ({ page }) => {
    const errors = watchErrors(page);
    await withProfile(page);
    await page.goto('/#/');
    await page.getByRole('radio', { name: 'Untimed' }).check();
    await page.getByRole('button', { name: 'Start shift' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 30_000 });
    const items = page.locator('.queue-item');
    const n = await items.count();
    expect(n).toBeGreaterThanOrEqual(6);
    expect(n).toBeLessThanOrEqual(9);
    await axe(page, 'shift queue');

    await items.first().click();
    await expect(page.locator('.ws-grid')).toBeVisible();
    await page.getByRole('radio', { name: 'Benign / expected' }).check();
    await page.getByRole('radio', { name: 'Informational' }).check();
    await page.getByRole('radio', { name: 'Close' }).check();
    await page.getByRole('button', { name: 'Submit & back to queue' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible();
    await expect(items.first().locator('.badge')).toHaveText('Benign / expected');

    // Resume after reload: same queue, submission kept.
    await page.reload();
    await expect(items).toHaveCount(n, { timeout: 30_000 });
    await expect(items.first().locator('.badge')).toHaveText('Benign / expected');

    await page.getByRole('button', { name: 'Hand over' }).click();
    await page.getByRole('button', { name: 'Hand over now' }).click();
    await expect(page.getByText('Shift 1 handover')).toBeVisible();
    await expect(page.locator('table tbody tr')).toHaveCount(n);
    await axe(page, 'handover');

    await page.goto('/#/intel');
    await expect(page.getByRole('heading', { name: 'Your incident history' })).toBeVisible();
    await expect(page.locator('section[aria-labelledby="ih-h"] tbody tr')).toHaveCount(n);

    // The next shift; coming back to the old handover must not wipe it.
    await page.goto('/#/handover');
    await page.getByRole('button', { name: 'Next shift' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 30_000 });
    await items.first().click();
    await page.getByRole('radio', { name: 'Benign / expected' }).check();
    await page.getByRole('radio', { name: 'Low' }).check();
    await page.getByRole('radio', { name: 'Close' }).check();
    await page.getByRole('button', { name: 'Submit & back to queue' }).click();
    await page.goto('/#/handover');
    await page.getByRole('link', { name: 'Resume shift 2' }).click();
    await expect(items.first().locator('.badge')).toHaveText('Benign / expected');
    expect(errors).toEqual([]);
  });
});

test.describe('platform', () => {
  test('phone width: no horizontal scroll, panels switch', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await withProfile(page);
    for (const hash of ['#/', '#/practice', '#/help/reference', '#/settings']) {
      await page.goto(`/${hash}`);
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow, hash).toBeLessThanOrEqual(0);
    }
    await openCase(page);
    await expect(page.locator('.ws-query')).toBeVisible();
    await expect(page.locator('.ws-verdict')).toBeHidden();
    await page.getByRole('button', { name: 'Verdict' }).click();
    await expect(page.locator('.ws-verdict')).toBeVisible();
    await page.getByRole('button', { name: 'Alert', exact: true }).click();
    await expect(page.locator('.ws-alert')).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    // The menu opens and navigates.
    await page.getByRole('button', { name: 'Menu' }).click();
    await page.getByRole('link', { name: 'Help' }).click();
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('How it works');

    // Data-heavy pages: a handed-over shift, the intel board and stats.
    await page.goto('/#/');
    await page.getByRole('radio', { name: 'Untimed' }).check();
    await page.getByRole('button', { name: 'Start shift' }).click();
    await expect(page.getByRole('heading', { name: 'Alert queue' })).toBeVisible({ timeout: 30_000 });
    await page.getByRole('button', { name: 'Hand over' }).click();
    await page.getByRole('button', { name: 'Hand over now' }).click();
    await expect(page.getByText('Shift 1 handover')).toBeVisible();
    for (const hash of ['#/handover', '#/intel', '#/stats', '#/shift']) {
      await page.goto(`/${hash}`);
      await page.waitForTimeout(300);
      const o = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(o, hash).toBeLessThanOrEqual(0);
    }
  });

  test('reduced motion is respected', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await withProfile(page);
    await page.goto('/#/');
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--dur').trim())).toMatch(/^0m?s$/);
  });

  test('a v1 profile is migrated on first load', async ({ page }) => {
    await page.addInitScript(() => {
      if (localStorage.getItem('soc-triage-sim:v1')) return;
      localStorage.setItem(
        'soc-triage-sim:v1',
        JSON.stringify({
          version: 1,
          analystName: 'Legacy',
          xp: 420,
          streak: 2,
          bestStreak: 5,
          records: [{ caseId: 'identity-password-spray#x', templateId: 'identity-password-spray', completedAt: Date.now() - 86_400_000, percent: 88, dispositionCorrect: true, xp: 130 }],
          recentTemplateIds: [],
          dailyDone: [],
          settings: { timerEnabled: false, showRubricLive: false },
        }),
      );
    });
    await page.goto('/#/settings');
    await expect(page.getByText('Your progress from the previous version was carried over: 1 cases')).toBeVisible();
    await expect(page.getByLabel('Analyst name')).toHaveValue('Legacy');
    await page.goto('/#/stats');
    await expect(page.getByText('420 XP')).toBeVisible();
    // The v1 save is left untouched as a backup.
    expect(await page.evaluate(() => JSON.parse(localStorage.getItem('soc-triage-sim:v1')!).xp)).toBe(420);
  });

  test('works offline after the first visit', async ({ page, context }) => {
    await withProfile(page);
    await page.goto('/#/');
    await page.evaluate(() => navigator.serviceWorker.ready.then(() => true));
    await expect
      .poll(() =>
        page.evaluate(async () => {
          const keys = await caches.keys();
          return keys.length ? (await (await caches.open(keys[0])).keys()).length : 0;
        }),
      )
      .toBeGreaterThan(10);
    await context.setOffline(true);
    await page.reload();
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await page.goto(`/${CASE}`);
    await expect(page.locator('.ws-grid')).toBeVisible({ timeout: 30_000 });
    await runQuery(page, 'SigninLogs\n| take 5');
    await expect(page.locator('.results-table tbody tr')).toHaveCount(5);
    await context.setOffline(false);
  });

  test('works with storage blocked (session-only)', async ({ page }) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', {
        get() {
          throw new DOMException('blocked', 'SecurityError');
        },
      });
    });
    await page.goto('/#/');
    await expect(page.getByText('This browser is blocking local storage')).toBeVisible();
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  });
});
