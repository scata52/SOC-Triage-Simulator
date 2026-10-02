import { profile, update, world, today } from '../store/app.ts';
import { navigate } from '../router.ts';
import { Icon } from '../components/Icon.tsx';
import { Bar } from '../components/ui.tsx';
import { rankFor, nextShiftNumber, startShift, asStudyAttempts } from '../../state/profile.ts';
import { BUDGETS, shiftSeedFor, type Budget } from '../../core/shift/plan.ts';
import { selectVulnFollowUp } from '../../core/shift/vuln-hook.ts';
import { FULL_STUDY_POOL, studyPlan } from '../../core/study/scheduler.ts';
import { campaignSummary, nextCampaign } from '../../core/campaign/campaign.ts';
import { ago, clock, dailySeed, plural, randomSeed } from '../lib/format.ts';
import { ALERT_TYPES, dailyCase } from '../lib/cases.ts';
import { templateById } from '../../core/cases/templates/index.ts';
import { useState } from 'preact/hooks';
import { VULN_TEMPLATES } from '../../core/vuln/registry.ts';
import { vulnCaseTypes } from '../../core/vuln/worklist.ts';

const VULN_TYPES = vulnCaseTypes(VULN_TEMPLATES);
const VULN_TIERS = [...new Set(VULN_TYPES.map((t) => t.difficulty.replace('tier', '')))].sort();

function greeting(): string {
  const h = new Date().getHours();
  return h < 5 ? 'Late one' : h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

export function BudgetPicker({ value, onChange }: { value: Budget; onChange: (b: Budget) => void }) {
  return (
    <fieldset class="segmented">
      <legend>Shift clock</legend>
      {BUDGETS.map((b) => (
        <label>
          <input type="radio" name="budget" value={b} checked={value === b} onChange={() => onChange(b)} />
          {b === 0 ? 'Untimed' : `${b} min`}
        </label>
      ))}
    </fieldset>
  );
}

export function beginShift(budget: Budget): void {
  update((p) => {
    // Never replace a shift in progress (e.g. "Next shift" on a stale
    // handover page reached with Back): just return to it.
    if (p.activeShift) return p;
    // A campaign runs across shifts; a new one starts when the last has ended.
    const campaign = p.campaign && p.campaign.status === 'active' ? p.campaign : nextCampaign(p.campaign, world.peek(), `${p.worldSeed}:c${p.campaignsFinished.length}`);
    // A vulnerability finding left open earlier becomes one extra alert (DESIGN section 8); its ledger entry is consumed here.
    const number = nextShiftNumber(p);
    const vulnHook = selectVulnFollowUp(p.vulnLedger, shiftSeedFor(p.worldSeed, number));
    return startShift({ ...p, campaign, settings: { ...p.settings, defaultBudget: budget } }, number, budget, Date.now(), { vulnHook });
  });
  navigate({ name: 'shift' });
}

export function Home() {
  const p = profile.value;
  const w = world.value;
  const rank = rankFor(p.xp);
  const [budget, setBudget] = useState<Budget>(p.settings.defaultBudget);
  const plan = studyPlan(p.cards, asStudyAttempts(p), today(), { pool: FULL_STUDY_POOL });
  const recent = [...p.attempts].reverse().slice(0, 6);
  // Vulnerability attempts are listed under Recent, but the SOC first-run card and accuracy chip stay SOC-only.
  const socAttempts = p.attempts.filter((a) => a.mode !== 'vuln');
  const last20 = socAttempts.slice(-20);
  const accuracy = last20.length ? Math.round((last20.filter((a) => a.dispositionCorrect).length / last20.length) * 100) : null;
  const daily = dailySeed();
  const dailyDone = p.dailyDone.includes(daily);
  const shiftNo = nextShiftNumber(p);
  const s = p.activeShift;
  const camp = p.campaign ? campaignSummary(p.campaign) : null;
  const firstRun = socAttempts.length === 0 && p.shifts.length === 0;

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <p class="eyebrow">{w.org.name} · Security Operations</p>
          <h1>
            {greeting()}, {p.analystName}.
          </h1>
          <p>
            {rank.current.name} · {p.xp.toLocaleString()} XP{rank.next ? ` · ${(rank.next.minXp - p.xp).toLocaleString()} to ${rank.next.name}` : ''}
          </p>
        </div>
      </div>

      {firstRun && (
        <section class="card intro" aria-labelledby="intro-h" style={{ marginBottom: 'var(--space-5)' }}>
          <h2 id="intro-h">How this works</h2>
          <ol class="intro-steps">
            <li>
              <strong>An alert lands.</strong> Every case sits on a full day of logs from {w.org.name} — sign-ins, endpoints, email, proxy, DNS, firewall —
              with the attack (or the innocent explanation) buried in ordinary noise.
            </li>
            <li>
              <strong>Investigate with real queries.</strong> A SIEM console answers KQL (or SQL) against those logs. Pin the rows that prove your case and
              note the indicators worth blocking.
            </li>
            <li>
              <strong>Call it.</strong> Disposition, severity, action, ATT&CK. The grade covers what you <em>found</em> as well as what you concluded.
            </li>
          </ol>
          <div class="btn-row">
            <a class="btn btn-primary" href={`#/case/${dailyCase(daily).slug}/${daily}`}>
              <Icon name="play" /> Try today's case
            </a>
            <a class="btn" href="#/help/kql">
              <Icon name="book" /> KQL in five minutes
            </a>
          </div>
        </section>
      )}

      <div class="grid home-grid">
        <section class="card hero-card" aria-labelledby="shift-h">
          <div class="card-head">
            <h2 id="shift-h">
              <Icon name="bolt" /> {s ? `Shift ${s.number + 1} in progress` : `Shift ${shiftNo + 1}`}
            </h2>
            {s && s.budget > 0 && <span class="badge badge-warn mono">{clock(s.budget * 60 - s.elapsedSec)} left</span>}
          </div>
          {s ? (
            <>
              <p class="muted">
                {plural(s.submissions.length ? new Set(s.submissions.map((x) => x.alertId)).size : 0, 'alert')} handled so far. The queue is waiting.
              </p>
              <a class="btn btn-primary btn-lg" href="#/shift">
                Resume shift <Icon name="right" />
              </a>
            </>
          ) : (
            <>
              <p class="muted">
                You're on the late shift. Six to nine alerts from today and last night share one set of logs; some are real, most are not. Work the ones
                that matter first — the clock is part of the job.
              </p>
              <BudgetPicker value={budget} onChange={setBudget} />
              <div class="btn-row" style={{ marginTop: 'var(--space-3)' }}>
                <button type="button" class="btn btn-primary btn-lg" onClick={() => beginShift(budget)}>
                  Start shift <Icon name="right" />
                </button>
              </div>
            </>
          )}
          {camp && camp.status === 'active' && camp.contained > 0 && (
            <p class="faint small" style={{ marginTop: 'var(--space-3)' }}>
              Intel: {camp.actor} is still active against {w.org.short}.
            </p>
          )}
        </section>

        <section class="card" aria-labelledby="study-h">
          <div class="card-head">
            <h2 id="study-h">
              <Icon name="cap" /> Study
            </h2>
            {plan.dueToday.length > 0 && <span class="badge badge-accent">{plural(plan.dueToday.length, 'review')} due</span>}
          </div>
          <p class="muted">
            Spaced repetition over every case type, weighted toward your weakest areas
            {plan.weakest.tactic[0] && plan.weakest.tactic[0].attempts > 0 ? ` — currently ${plan.weakest.tactic[0].label}` : ''}.
          </p>
          <div class="row" style={{ marginBottom: 'var(--space-3)' }}>
            <div class="stat">
              <span class="stat-value">
                {plan.seen}/{plan.total}
              </span>
              <span class="stat-label">case types seen</span>
            </div>
            <div class="stat" style={{ marginLeft: 'var(--space-5)' }}>
              <span class="stat-value">{plan.streak}</span>
              <span class="stat-label">day streak</span>
            </div>
          </div>
          <a class="btn btn-primary" href="#/study">
            Open study plan <Icon name="right" />
          </a>
        </section>

        <section class="card" aria-labelledby="daily-h">
          <div class="card-head">
            <h2 id="daily-h">
              <Icon name="spark" /> Case of the day
            </h2>
            {dailyDone && <span class="badge badge-ok">done</span>}
          </div>
          <p class="muted">The same case for everyone today, in a shared fictional company. Compare notes with a study partner.</p>
          <a class="btn" href="#/daily">
            {dailyDone ? 'Review it again' : "Open today's case"} <Icon name="right" />
          </a>
        </section>

        <section class="card" aria-labelledby="practice-h">
          <div class="card-head">
            <h2 id="practice-h">
              <Icon name="target" /> Practice
            </h2>
          </div>
          <p class="muted">{ALERT_TYPES.length} alert types, each with endless variations. Pick one or take whatever the queue throws at you.</p>
          <div class="btn-row">
            <button
              type="button"
              class="btn"
              onClick={() => {
                const pool = ALERT_TYPES.filter((a) => !a.hunt);
                const a = pool[Math.floor(Math.random() * pool.length)];
                navigate({ name: 'case', slug: a.slug, seed: randomSeed() });
              }}
            >
              <Icon name="play" /> Random case
            </button>
            <a class="btn btn-ghost" href="#/practice">
              Browse library
            </a>
          </div>
        </section>

        <section class="card home-vuln" aria-labelledby="vuln-h">
          <div class="card-head">
            <h2 id="vuln-h">
              <Icon name="shield" /> Vulnerability management
            </h2>
          </div>
          <p class="muted">
            {VULN_TYPES.length} scan reviews across tier{VULN_TIERS.length === 1 ? '' : 's'} {VULN_TIERS.join(', ')}, each with endless variations. Decide, schedule and justify remediation for a scanner
            worklist.
          </p>
          <div class="btn-row">
            <button
              type="button"
              class="btn"
              onClick={() => {
                const t = VULN_TYPES[Math.floor(Math.random() * VULN_TYPES.length)];
                navigate({ name: 'vuln-case', slug: t.slug, seed: randomSeed() });
              }}
            >
              <Icon name="play" /> Random scan review
            </button>
            <a class="btn btn-ghost" href="#/vuln">
              Browse vulnerability cases
            </a>
          </div>
        </section>
      </div>

      <div class="grid grid-2" style={{ marginTop: 'var(--space-4)' }}>
        <section class="card" aria-labelledby="recent-h">
          <div class="card-head">
            <h2 id="recent-h">Recent</h2>
            {accuracy !== null && <span class="chip">{accuracy}% correct calls (last {last20.length})</span>}
          </div>
          {recent.length === 0 ? (
            <p class="muted">Nothing yet. Your cases and shifts will show up here.</p>
          ) : (
            <ul class="recent-list">
              {recent.map((a) =>
                a.mode === 'vuln' ? (
                  <li>
                    <Icon name={a.dispositionCorrect ? 'check' : 'x'} class={a.dispositionCorrect ? 'text-ok' : 'text-bad'} label={a.dispositionCorrect ? 'Passed' : 'Below the pass mark'} />
                    <span class="recent-title">{VULN_TYPES.find((t) => t.templates.some((x) => x.id === a.templateId))?.title ?? a.templateId}</span>
                    <span class="mono faint">{a.percent}%</span>
                    <span class="faint small">{ago(a.completedAt)}</span>
                  </li>
                ) : (
                <li>
                  <Icon name={a.dispositionCorrect ? 'check' : 'x'} class={a.dispositionCorrect ? 'text-ok' : 'text-bad'} label={a.dispositionCorrect ? 'Right call' : 'Wrong call'} />
                  <span class="recent-title">{ALERT_TYPES.find((t) => t.templates.some((x) => x.id === a.templateId))?.title ?? templateById(a.templateId)?.title ?? a.templateId}</span>
                  <span class="mono faint">{a.percent}%</span>
                  <span class="faint small">{ago(a.completedAt)}</span>
                </li>
                ),
              )}
            </ul>
          )}
        </section>

        <section class="card" aria-labelledby="org-h">
          <div class="card-head">
            <h2 id="org-h">Your organisation</h2>
            <span class="chip">fictional</span>
          </div>
          <p>
            <strong>{w.org.name}</strong> — {w.org.industry.toLowerCase()}, {w.people.length} staff across {w.sites.map((x) => x.city.city).join(' and ')},{' '}
            {w.hosts.length} managed hosts, tenant <code>{w.org.domain}</code>.
          </p>
          <p class="muted small">
            The same company every time you play: its people, laptops, servers, VPN and partners persist, so you get to know what normal looks like. Its
            addresses come from documentation ranges and its name from a list of fictitious companies.
          </p>
          <Bar value={Math.min(1, p.shifts.length / 20)} label="Shifts worked" />
          <p class="faint small" style={{ marginTop: 6 }}>
            {plural(p.shifts.length, 'shift')} worked here
          </p>
        </section>
      </div>
    </div>
  );
}
