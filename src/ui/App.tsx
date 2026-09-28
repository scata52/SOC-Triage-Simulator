import { useEffect, useRef, useState } from 'preact/hooks';
import { route, href, type Route } from './router.ts';
import { profile, saveFailed, persistent } from './store/app.ts';
import { rankFor } from '../state/profile.ts';
import { Icon, type IconName } from './components/Icon.tsx';
import { Bar, Toasts } from './components/ui.tsx';
import { Home } from './screens/Home.tsx';
import { Library } from './screens/Library.tsx';
import { Settings } from './screens/Settings.tsx';
import { CaseScreen, DailyScreen } from './screens/CaseScreen.tsx';
import { ShiftScreen, HandoverScreen } from './screens/Shift.tsx';
import { Intel } from './screens/Intel.tsx';
import { Study } from './screens/Study.tsx';
import { Stats } from './screens/Stats.tsx';
import { Help } from './screens/Help.tsx';

const NAV: { to: Route; label: string; icon: IconName; match: Route['name'][] }[] = [
  { to: { name: 'home' }, label: 'Console', icon: 'terminal', match: ['home'] },
  { to: { name: 'shift' }, label: 'Shift', icon: 'bolt', match: ['shift', 'shift-alert', 'handover'] },
  { to: { name: 'practice' }, label: 'Practice', icon: 'target', match: ['practice', 'case', 'daily'] },
  { to: { name: 'study' }, label: 'Study', icon: 'cap', match: ['study'] },
  { to: { name: 'intel' }, label: 'Intel', icon: 'globe', match: ['intel'] },
  { to: { name: 'stats' }, label: 'Stats', icon: 'chart', match: ['stats'] },
  { to: { name: 'help' }, label: 'Help', icon: 'book', match: ['help'] },
];

const TITLES: Record<Route['name'], string> = {
  home: 'Console',
  practice: 'Practice',
  case: 'Investigation',
  daily: 'Case of the day',
  study: 'Study',
  shift: 'Shift',
  'shift-alert': 'Shift — investigation',
  handover: 'Shift handover',
  intel: 'Threat intel',
  stats: 'Stats',
  help: 'Help',
  settings: 'Settings',
  'not-found': 'Not found',
};

function Screen({ r }: { r: Route }) {
  switch (r.name) {
    case 'home':
      return <Home />;
    case 'practice':
      return <Library />;
    case 'case':
      return <CaseScreen slug={r.slug} seed={r.seed} mode={r.study ? 'study' : 'practice'} key={`${r.slug}/${r.seed}/${r.study ? 's' : 'p'}`} />;
    case 'daily':
      return <DailyScreen />;
    case 'study':
      return <Study />;
    case 'shift':
      return <ShiftScreen />;
    case 'shift-alert':
      return <ShiftScreen alertId={r.alertId} />;
    case 'handover':
      return <HandoverScreen />;
    case 'intel':
      return <Intel />;
    case 'stats':
      return <Stats />;
    case 'help':
      return <Help section={r.section} />;
    case 'settings':
      return <Settings />;
    case 'not-found':
      return (
        <div class="page page-narrow">
          <h1 tabIndex={-1}>Nothing at this address</h1>
          <p>
            <code>#{r.path}</code> is not a page. <a href="#/">Back to the console</a>.
          </p>
        </div>
      );
  }
}

export function App() {
  const r = route.value;
  const p = profile.value;
  const rank = rankFor(p.xp);
  const [menuOpen, setMenuOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  const first = useRef(true);
  const activeShift = p.activeShift;

  // New page: close the menu, set the title, and move focus to the page
  // heading so screen-reader and keyboard users start at the content.
  useEffect(() => {
    setMenuOpen(false);
    document.title = `${TITLES[r.name]} · SOC Triage Simulator`;
    if (first.current) {
      first.current = false;
      return;
    }
    requestAnimationFrame(() => {
      // Pages that load first (a case, a shift) have no heading yet: focus
      // <main>, and they move focus to their heading when it appears.
      const h = mainRef.current?.querySelector<HTMLElement>('h1');
      if (h) {
        if (!h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
        h.focus({ preventScroll: true });
      } else mainRef.current?.focus({ preventScroll: true });
      window.scrollTo({ top: 0 });
    });
  }, [r]);

  return (
    <>
      <a class="skip-link" href="#main" onClick={(e) => (e.preventDefault(), mainRef.current?.focus())}>
        Skip to content
      </a>
      <header class="shell-header">
        <a class="brand" href="#/" aria-label="SOC Triage Simulator — console">
          <svg class="brand-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true">
            <path d="M12 2.5l8.5 3.7v6c0 4.6-3.6 8-8.5 9.3-4.9-1.3-8.5-4.7-8.5-9.3v-6z" />
            <path d="M7.5 12.5h2l1.5-3 2 6 1.5-3h2" stroke-linecap="round" />
          </svg>
          <span>
            SOC<span class="brand-sub">//triage</span>
          </span>
        </a>
        <button type="button" class="btn btn-ghost btn-icon menu-toggle" aria-expanded={menuOpen} aria-controls="primary-nav" onClick={() => setMenuOpen(!menuOpen)}>
          <Icon name={menuOpen ? 'x' : 'menu'} />
          <span class="visually-hidden">Menu</span>
        </button>
        <nav class="nav" id="primary-nav" aria-label="Primary" data-open={menuOpen ? 'true' : 'false'}>
          {NAV.map((n) => (
            <a href={href(n.to)} aria-current={n.match.includes(r.name) ? 'page' : undefined}>
              <Icon name={n.icon} />
              {n.label}
              {n.to.name === 'shift' && activeShift && (
                <span class="badge badge-warn">
                  <span aria-hidden="true">live</span>
                  <span class="visually-hidden">(shift in progress)</span>
                </span>
              )}
            </a>
          ))}
        </nav>
        <div class="shell-right">
          <a class="rank-chip" href="#/stats" title={`${p.xp.toLocaleString()} XP`}>
            <span class="rank-name">{rank.current.name}</span>
            <span class="xpbar">
              <Bar value={rank.progress} label={rank.next ? `Progress to ${rank.next.name}` : 'Top rank'} />
            </span>
          </a>
          <a class="btn btn-ghost btn-icon" href="#/settings" aria-label="Settings" aria-current={r.name === 'settings' ? 'page' : undefined}>
            <Icon name="sliders" />
          </a>
        </div>
      </header>
      {(!persistent || saveFailed.value) && (
        <div class="notice notice-warn" style={{ borderRadius: 0, borderLeft: 0, borderRight: 0 }}>
          <Icon name="alert" />
          <div>{!persistent ? 'This browser is blocking local storage, so progress lasts only until you close the tab. Export it from Settings to keep a copy.' : 'Progress could not be saved (storage full?). Export it from Settings to keep a copy.'}</div>
        </div>
      )}
      <main id="main" ref={mainRef} tabIndex={-1}>
        <Screen r={r} />
      </main>
      {!['case', 'shift-alert', 'daily'].includes(r.name) && (
        <footer class="site-footer">
          Every person, organisation, host, address, domain and hash here is synthetic — generated in your browser from documentation-reserved ranges and
          fictitious names. Nothing is sent anywhere; progress stays in this browser.
        </footer>
      )}
      <Toasts />
    </>
  );
}
