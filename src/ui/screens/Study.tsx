import { useMemo } from 'preact/hooks';
import { profile, today } from '../store/app.ts';
import { navigate } from '../router.ts';
import { Icon } from '../components/Icon.tsx';
import { Bar } from '../components/ui.tsx';
import { asStudyAttempts } from '../../state/profile.ts';
import { nextStudyCase, studyPlan, type Skill } from '../../core/study/scheduler.ts';
import { templateById } from '../../core/cases/templates/index.ts';
import { createRng } from '../../core/rng.ts';
import { seedFor, slugOf } from '../lib/cases.ts';
import { plural, randomSeed } from '../lib/format.ts';

function SkillList({ skills, label }: { skills: Skill[]; label: string }) {
  return (
    <ul class="skill-list" aria-label={label}>
      {skills.map((s) => (
        <li>
          <span>
            {s.label}
            {s.attempts === 0 && <span class="faint small"> · new</span>}
          </span>
          <Bar value={s.mastery} label={`${s.label} mastery${s.attempts === 0 ? ' (not tried yet)' : ''}`} color={s.attempts === 0 ? 'var(--border-strong)' : s.mastery >= 0.8 ? 'var(--ok)' : s.mastery >= 0.55 ? 'var(--warn)' : 'var(--bad)'} />
          <span class="mono small">{Math.round(s.mastery * 100)}%</span>
        </li>
      ))}
    </ul>
  );
}

export function Study() {
  const p = profile.value;
  const day = today();
  const attempts = asStudyAttempts(p);
  const plan = studyPlan(p.cards, attempts, day);
  // Stable suggestion for the page; a fresh one is drawn when you start.
  const suggestion = useMemo(() => nextStudyCase(p.cards, attempts, day, createRng(`study-view:${day}:${attempts.length}`)), [p.attempts.length, day]);
  const start = () => {
    navigate({ name: 'case', slug: slugOf(suggestion.templateId), seed: seedFor(suggestion.templateId, randomSeed()), study: true });
  };
  const byKind = (k: Skill['kind']) => plan.skills.filter((s) => s.kind === k).sort((a, b) => a.mastery - b.mastery);
  const dayLabel = (d: number) => {
    const diff = d - day;
    return diff === 1 ? 'Tomorrow' : new Date((d + 0.5) * 86_400_000).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
  };

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <p class="eyebrow">Study</p>
          <h1>Your study plan</h1>
          <p>Cases come back on a spaced-repetition schedule — sooner when you struggled, later when you nailed them — and new picks lean toward your weakest areas.</p>
        </div>
      </div>

      <div class="grid grid-2">
        <section class="card hero-card" aria-labelledby="next-h">
          <h2 id="next-h">
            <Icon name="cap" /> Next up
          </h2>
          <p class="lede">
            <strong>{templateById(suggestion.templateId)?.title}</strong>
          </p>
          <p class="muted small">{suggestion.detail}</p>
          <button type="button" class="btn btn-primary btn-lg" onClick={start}>
            Start <Icon name="right" />
          </button>
          <div class="row" style={{ marginTop: 'var(--space-4)', gap: 'var(--space-5)' }}>
            <div class="stat">
              <span class="stat-value">{plan.dueToday.length}</span>
              <span class="stat-label">due today{plan.overdue ? ` (${plan.overdue} overdue)` : ''}</span>
            </div>
            <div class="stat">
              <span class="stat-value">
                {plan.seen}/{plan.total}
              </span>
              <span class="stat-label">case types seen</span>
            </div>
            <div class="stat">
              <span class="stat-value">{plan.streak}</span>
              <span class="stat-label">day streak</span>
            </div>
          </div>
        </section>

        <section class="card" aria-labelledby="up-h">
          <h2 id="up-h">Coming up</h2>
          {plan.upcoming.length === 0 ? (
            <p class="muted small">Nothing scheduled in the next two weeks yet. Every case you grade becomes a card here.</p>
          ) : (
            <ul class="skill-list" aria-label="Reviews in the next two weeks">
              {plan.upcoming.map((u) => (
                <li>
                  <span>{dayLabel(u.day)}</span>
                  <Bar value={Math.min(1, u.count / 6)} label={`${u.count} reviews`} />
                  <span class="mono small">{u.count}</span>
                </li>
              ))}
            </ul>
          )}
          {plan.dueToday.length > 0 && (
            <>
              <h3 class="section-label">Due now</h3>
              <ul class="small">
                {plan.dueToday.slice(0, 8).map((id) => (
                  <li>{templateById(id)?.title}</li>
                ))}
              </ul>
              {plan.dueToday.length > 8 && <p class="faint small">and {plural(plan.dueToday.length - 8, 'more')}</p>}
            </>
          )}
        </section>
      </div>

      <div class="grid grid-3" style={{ marginTop: 'var(--space-4)' }}>
        <section class="card" aria-labelledby="sk-t">
          <h2 id="sk-t">ATT&CK tactics</h2>
          <SkillList skills={byKind('tactic')} label="Mastery by tactic" />
        </section>
        <section class="card" aria-labelledby="sk-c">
          <h2 id="sk-c">Alert categories</h2>
          <SkillList skills={byKind('category')} label="Mastery by category" />
        </section>
        <section class="card" aria-labelledby="sk-d">
          <h2 id="sk-d">CySA+ domains</h2>
          <SkillList skills={byKind('domain')} label="Mastery by CySA+ domain" />
          <p class="faint small">Mastery is a recency-weighted average of your grades, starting from 40% for anything you haven't tried.</p>
        </section>
      </div>
    </div>
  );
}
