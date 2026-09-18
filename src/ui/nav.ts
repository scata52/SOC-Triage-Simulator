import type { App, Screen } from './app.ts';
import { getProfile, rankFor } from '../state/store.ts';
import { h } from './dom.ts';

export function renderNav(app: App): HTMLElement {
  const p = getProfile();
  const rank = rankFor(p.xp);

  const go = (screen: Screen) => (e: Event) => {
    e.preventDefault();
    if (app.screen === 'triage' && app.currentCase && !app.grade) {
      if (!confirm('Leave this case? Your triage will not be recorded.')) return;
      app.abandonCase();
    }
    app.navigate(screen);
  };

  const link = (screen: Screen, label: string) =>
    h(
      'a',
      {
        href: `#/${screen}`,
        class: `nav-link${app.screen === screen ? ' active' : ''}`,
        onclick: go(screen),
      },
      label,
    );

  return h(
    'header',
    { class: 'nav' },
    h(
      'div',
      { class: 'container nav-inner' },
      h(
        'a',
        { href: '#/home', class: 'brand', onclick: go('home') },
        h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '◆'),
        h('span', { class: 'brand-text' }, 'SOC Triage Simulator'),
      ),
      h(
        'nav',
        { class: 'nav-links', 'aria-label': 'Primary' },
        link('home', 'Queue'),
        link('stats', 'Stats'),
        link('about', 'About'),
      ),
      h(
        'div',
        { class: 'profile-chip', title: `${p.xp} XP · streak ${p.streak} · best ${p.bestStreak}` },
        h('span', { class: 'chip-rank' }, rank.current.name),
        h('span', { class: 'chip-sep', 'aria-hidden': 'true' }, '·'),
        h('span', { class: 'chip-xp' }, `${p.xp.toLocaleString()} XP`),
        p.streak > 1 ? h('span', { class: 'chip-streak' }, `streak ${p.streak}`) : null,
      ),
    ),
  );
}
