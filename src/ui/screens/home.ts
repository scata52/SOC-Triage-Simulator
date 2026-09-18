import type { App } from '../app.ts';
import type { Category, Difficulty } from '../../types.ts';
import { ALL_CATEGORIES, ALL_TEMPLATES, CATEGORY_LABELS } from '../../data/templates/index.ts';
import { DIFFICULTY_LABELS } from '../../engine/generator.ts';
import { dailySeed } from '../../engine/rng.ts';
import { getProfile, rankFor, setAnalystName, updateSettings } from '../../state/store.ts';
import { summarise } from '../../state/stats.ts';
import { h } from '../dom.ts';

export function renderHome(app: App): HTMLElement {
  const p = getProfile();
  const rank = rankFor(p.xp);
  const sum = summarise(p.records);
  const dailyDone = p.dailyDone.includes(dailySeed());

  let category: Category | 'any' = 'any';
  let difficulty: Difficulty | 'any' = 'any';

  const categorySelect = h(
    'select',
    {
      id: 'f-category',
      class: 'select',
      onchange: (e: Event) => {
        category = (e.target as HTMLSelectElement).value as Category | 'any';
      },
    },
    h('option', { value: 'any' }, 'Any category'),
    ...ALL_CATEGORIES.map((c) => h('option', { value: c }, CATEGORY_LABELS[c])),
  );

  const difficultySelect = h(
    'select',
    {
      id: 'f-difficulty',
      class: 'select',
      onchange: (e: Event) => {
        difficulty = (e.target as HTMLSelectElement).value as Difficulty | 'any';
      },
    },
    h('option', { value: 'any' }, 'Any tier'),
    ...(['tier1', 'tier2', 'tier3'] as Difficulty[]).map((d) =>
      h('option', { value: d }, `${DIFFICULTY_LABELS[d]}${d === 'tier1' ? ' — foundational' : d === 'tier3' ? ' — advanced' : ''}`),
    ),
  );

  const startBtn = (label: string, sub: string, onclick: () => void, primary = false, disabled = false) =>
    h(
      'button',
      { class: `start-card${primary ? ' primary' : ''}`, type: 'button', onclick, disabled },
      h('span', { class: 'start-label' }, label),
      h('span', { class: 'start-sub' }, sub),
    );

  const counts = ALL_CATEGORIES.map((c) => ({
    c,
    n: ALL_TEMPLATES.filter((t) => t.category === c).length,
  })).filter((x) => x.n > 0);

  return h(
    'div',
    { class: 'home' },
    h(
      'section',
      { class: 'hero' },
      h('p', { class: 'eyebrow' }, 'Alert queue'),
      h('h1', null, 'Triage like it\'s your shift.'),
      h(
        'p',
        { class: 'lede' },
        'Each case hands you a realistic alert with the logs behind it. Decide what it is, how bad it is, what to do, and which ATT&CK technique you\'re looking at — then see the answer key.',
      ),
    ),

    h(
      'section',
      { class: 'grid-2' },
      // ------------------------------------------------------------ start
      h(
        'div',
        { class: 'card' },
        h('h2', null, 'Start'),
        h(
          'div',
          { class: 'filters' },
          h('label', { for: 'f-category' }, 'Category'),
          categorySelect,
          h('label', { for: 'f-difficulty' }, 'Difficulty'),
          difficultySelect,
        ),
        h(
          'div',
          { class: 'start-grid' },
          startBtn('Next case', 'One alert, graded immediately', () => app.start({ mode: 'single', category, difficulty }), true),
          startBtn(
            dailyDone ? 'Case of the Day — done' : 'Case of the Day',
            dailyDone ? 'Come back tomorrow for a new one' : 'Same case for everyone today',
            () => app.start({ mode: 'daily' }),
            false,
            dailyDone,
          ),
          startBtn('Shift · 5 cases', 'Short run with a summary', () => app.start({ mode: 'shift', total: 5, category, difficulty })),
          startBtn('Shift · 10 cases', 'Full rotation of the queue', () => app.start({ mode: 'shift', total: 10, category, difficulty })),
        ),
      ),

      // ------------------------------------------------------------ profile
      h(
        'div',
        { class: 'card' },
        h('h2', null, 'Analyst profile'),
        h(
          'div',
          { class: 'rank-row' },
          h('div', { class: 'rank-name' }, rank.current.name),
          h('div', { class: 'rank-xp' }, `${p.xp.toLocaleString()} XP`),
        ),
        h(
          'div',
          { class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(rank.progress * 100) },
          h('div', { class: 'progress-fill', style: `width:${Math.round(rank.progress * 100)}%` }),
        ),
        h(
          'p',
          { class: 'muted small' },
          rank.next
            ? `${(rank.next.minXp - p.xp).toLocaleString()} XP to ${rank.next.name}`
            : 'Top rank reached.',
        ),
        h(
          'dl',
          { class: 'stat-grid' },
          stat('Cases', String(sum.total)),
          stat('Avg score', sum.total ? `${sum.avgPercent}%` : '—'),
          stat('Disposition acc.', sum.total ? `${sum.dispositionAccuracy}%` : '—'),
          stat('Best streak', String(p.bestStreak)),
        ),
        h(
          'div',
          { class: 'settings' },
          h(
            'label',
            { class: 'toggle' },
            h('input', {
              type: 'checkbox',
              checked: p.settings.timerEnabled,
              onchange: (e: Event) => updateSettings({ timerEnabled: (e.target as HTMLInputElement).checked }),
            }),
            ' Show a timer while triaging',
          ),
          h(
            'label',
            { class: 'toggle' },
            h('input', {
              type: 'checkbox',
              checked: p.settings.showRubricLive,
              onchange: (e: Event) => updateSettings({ showRubricLive: (e.target as HTMLInputElement).checked }),
            }),
            ' Show note-quality hints while typing (easier)',
          ),
          h(
            'label',
            { class: 'name-field' },
            'Name ',
            h('input', {
              type: 'text',
              class: 'input',
              value: p.analystName,
              maxlength: 24,
              onchange: (e: Event) => setAnalystName((e.target as HTMLInputElement).value),
            }),
          ),
        ),
      ),
    ),

    // ------------------------------------------------------------ bank
    h(
      'section',
      { class: 'card' },
      h('h2', null, `Case bank — ${ALL_TEMPLATES.length} scenarios`),
      h(
        'p',
        { class: 'muted' },
        'Every scenario is regenerated with fresh identities, hosts, IPs, hashes and timings each time, so the same lesson never looks identical twice. Roughly a third are false positives or benign — closing those correctly is half the job.',
      ),
      h(
        'ul',
        { class: 'chips' },
        ...counts.map((x) => h('li', { class: 'chip' }, `${CATEGORY_LABELS[x.c]} `, h('span', { class: 'chip-count' }, String(x.n)))),
      ),
    ),
  );
}

function stat(label: string, value: string): HTMLElement {
  return h('div', { class: 'stat' }, h('dt', null, label), h('dd', null, value));
}
