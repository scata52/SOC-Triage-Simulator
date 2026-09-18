import type { Category, Difficulty, GradeResult, TriageCase, TriageResponse } from '../types.ts';
import { generateCase, generateDailyCase } from '../engine/generator.ts';
import { gradeResponse } from '../engine/grading.ts';
import { dailySeed } from '../engine/rng.ts';
import { getProfile, recordResult, subscribe } from '../state/store.ts';
import { clear, h } from './dom.ts';
import { renderHome } from './screens/home.ts';
import { renderTriage } from './screens/triage.ts';
import { renderResult } from './screens/result.ts';
import { renderStats } from './screens/stats.ts';
import { renderAbout } from './screens/about.ts';
import { renderNav } from './nav.ts';

export type Screen = 'home' | 'triage' | 'result' | 'stats' | 'about';

export type SessionMode = 'single' | 'shift' | 'daily';

export interface SessionResult {
  title: string;
  percent: number;
  xp: number;
  dispositionCorrect: boolean;
}

export interface Session {
  mode: SessionMode;
  total: number; // 1 for single/daily; N for shift
  completed: number;
  results: SessionResult[];
  category: Category | 'any';
  difficulty: Difficulty | 'any';
  dailySeed?: string;
}

export interface StartOptions {
  mode: SessionMode;
  total?: number;
  category?: Category | 'any';
  difficulty?: Difficulty | 'any';
}

function emptyResponse(): TriageResponse {
  return { disposition: null, severity: null, action: null, techniques: [], notes: '' };
}

export class App {
  root: HTMLElement;
  screen: Screen = 'home';
  session: Session | null = null;
  currentCase: TriageCase | null = null;
  response: TriageResponse = emptyResponse();
  grade: GradeResult | null = null;
  startedAt: number | null = null;
  lastDurationSec: number | null = null;

  constructor(root: HTMLElement) {
    this.root = root;
    subscribe(() => {
      // Profile changes that happen outside a screen transition (settings)
      // re-render the nav only, to keep form state intact.
      this.renderNavOnly();
    });
    window.addEventListener('hashchange', () => this.routeFromHash());
    this.routeFromHash();
  }

  // ------------------------------------------------------------------ routing
  navigate(screen: Screen): void {
    this.screen = screen;
    const hash = `#/${screen}`;
    if (location.hash !== hash) history.replaceState(null, '', hash);
    this.render();
    window.scrollTo({ top: 0 });
  }

  private routeFromHash(): void {
    const target = location.hash.replace(/^#\/?/, '') as Screen;
    const known: Screen[] = ['home', 'stats', 'about'];
    // Triage/result require live state; deep links to them fall back home.
    if (known.includes(target)) {
      this.screen = target;
    } else if (target === 'triage' && this.currentCase && !this.grade) {
      this.screen = 'triage';
    } else if (target === 'result' && this.grade) {
      this.screen = 'result';
    } else {
      this.screen = 'home';
    }
    this.render();
  }

  // ------------------------------------------------------------------ session
  start(opts: StartOptions): void {
    this.session = {
      mode: opts.mode,
      total: opts.mode === 'shift' ? opts.total ?? 5 : 1,
      completed: 0,
      results: [],
      category: opts.category ?? 'any',
      difficulty: opts.difficulty ?? 'any',
      dailySeed: opts.mode === 'daily' ? dailySeed() : undefined,
    };
    this.loadNextCase();
  }

  loadNextCase(): void {
    const s = this.session;
    if (!s) return;
    const profile = getProfile();
    this.currentCase =
      s.mode === 'daily'
        ? generateDailyCase()
        : generateCase({
            category: s.category,
            difficulty: s.difficulty,
            avoidTemplateIds: profile.recentTemplateIds,
          });
    this.response = emptyResponse();
    this.grade = null;
    this.startedAt = Date.now();
    this.lastDurationSec = null;
    this.navigate('triage');
  }

  submit(): void {
    const c = this.currentCase;
    const s = this.session;
    if (!c || !s) return;
    const durationSec = this.startedAt ? Math.round((Date.now() - this.startedAt) / 1000) : null;
    this.lastDurationSec = durationSec;
    this.grade = gradeResponse(c, this.response);
    recordResult(c, this.grade, durationSec, s.dailySeed);
    s.completed += 1;
    s.results.push({
      title: c.title,
      percent: this.grade.percent,
      xp: this.grade.xpAwarded,
      dispositionCorrect: this.grade.dispositionCorrect,
    });
    this.navigate('result');
  }

  sessionFinished(): boolean {
    const s = this.session;
    return !!s && s.completed >= s.total;
  }

  endSession(): void {
    this.session = null;
    this.currentCase = null;
    this.grade = null;
    this.response = emptyResponse();
    this.navigate('home');
  }

  // Skip the current case without recording (counts as abandoning).
  abandonCase(): void {
    this.endSession();
  }

  // ------------------------------------------------------------------ render
  render(): void {
    clear(this.root);
    const main = h('main', { class: 'container', id: 'main' });
    switch (this.screen) {
      case 'home':
        main.appendChild(renderHome(this));
        break;
      case 'triage':
        if (this.currentCase) main.appendChild(renderTriage(this, this.currentCase));
        else main.appendChild(renderHome(this));
        break;
      case 'result':
        if (this.currentCase && this.grade) main.appendChild(renderResult(this, this.currentCase, this.grade));
        else main.appendChild(renderHome(this));
        break;
      case 'stats':
        main.appendChild(renderStats(this));
        break;
      case 'about':
        main.appendChild(renderAbout(this));
        break;
    }
    this.root.appendChild(renderNav(this));
    this.root.appendChild(main);
    this.root.appendChild(
      h(
        'footer',
        { class: 'footer' },
        'SOC Triage Simulator — synthetic training data only. No real systems, people or indicators.',
      ),
    );
  }

  private renderNavOnly(): void {
    const existing = this.root.querySelector('header.nav');
    if (!existing) return;
    existing.replaceWith(renderNav(this));
  }
}
