import type { App } from '../app.ts';
import type { GradeResult, TriageCase } from '../../types.ts';
import { technique, techniqueName } from '../../data/mitre.ts';
import { cysaLabel } from '../../data/cysa.ts';
import { CATEGORY_LABELS } from '../../data/templates/index.ts';
import { DIFFICULTY_LABELS } from '../../engine/generator.ts';
import { ACTION_LABELS, DISPOSITION_LABELS, SEVERITY_LABELS } from '../../engine/grading.ts';
import { getProfile } from '../../state/store.ts';
import { fmtDuration, h } from '../dom.ts';

export function renderResult(app: App, c: TriageCase, g: GradeResult): HTMLElement {
  const p = getProfile();
  const s = app.session;
  const truth = c.groundTruth;
  const r = app.response;
  const finished = app.sessionFinished();

  const tone = g.percent >= 85 ? 'good' : g.percent >= 60 ? 'ok' : 'bad';

  // --------------------------------------------------------------- header
  const header = h(
    'section',
    { class: `result-header tone-${tone}` },
    h(
      'div',
      { class: 'result-score' },
      h('div', { class: 'score-big' }, `${g.percent}%`),
      h('div', { class: 'score-sub' }, `${g.score} / ${g.maxScore} points`),
    ),
    h(
      'div',
      { class: 'result-verdict' },
      h(
        'p',
        { class: 'verdict-line' },
        g.dispositionCorrect ? 'Disposition correct. ' : 'Disposition missed. ',
        h('strong', null, VERDICT_SENTENCE[truth.disposition]),
      ),
      h(
        'p',
        { class: 'muted' },
        `+${g.xpAwarded} XP`,
        app.lastDurationSec !== null ? ` · ${fmtDuration(app.lastDurationSec)}` : '',
        p.streak > 1 ? ` · streak ${p.streak}` : '',
        ` · ${CATEGORY_LABELS[c.category]} · ${DIFFICULTY_LABELS[c.difficulty]}`,
      ),
    ),
  );

  // ------------------------------------------------------------ breakdown
  const breakdown = h(
    'section',
    { class: 'card' },
    h('h2', { class: 'section-title' }, 'Score breakdown'),
    h(
      'table',
      { class: 'breakdown' },
      h('tbody', null, ...g.breakdown.map((b) =>
        h(
          'tr',
          { class: b.ok ? 'ok' : b.earned > 0 ? 'partial' : 'miss' },
          h('th', { scope: 'row' }, b.label),
          h('td', { class: 'mono pts' }, `${b.earned}/${b.possible}`),
          h('td', null, b.detail),
        ),
      )),
    ),
  );

  // ------------------------------------------------------- your vs answer
  const cmp = (label: string, yours: string, answer: string, ok: boolean) =>
    h(
      'tr',
      { class: ok ? 'ok' : 'miss' },
      h('th', { scope: 'row' }, label),
      h('td', null, yours),
      h('td', null, answer),
    );

  const techLink = (id: string) => {
    const t = technique(id);
    return h(
      'a',
      { href: t?.url ?? '#', target: '_blank', rel: 'noopener', class: 'tech-link' },
      h('span', { class: 'mono' }, id),
      ' ',
      techniqueName(id),
    );
  };

  const yoursTechs = r.techniques.length ? h('ul', { class: 'plain' }, ...r.techniques.map((id) => h('li', { class: g.matchedTechniques.includes(id) ? 'ok' : 'miss' }, techLink(id)))) : h('span', { class: 'muted' }, 'None');
  const truthTechs = truth.techniques.length ? h('ul', { class: 'plain' }, ...truth.techniques.map((id) => h('li', { class: g.missedTechniques.includes(id) ? 'miss' : 'ok' }, techLink(id)))) : h('span', { class: 'muted' }, 'None — no adversary technique');

  const comparison = h(
    'section',
    { class: 'card' },
    h('h2', { class: 'section-title' }, 'Your call vs. answer key'),
    h(
      'table',
      { class: 'compare' },
      h('thead', null, h('tr', null, h('th', null, ''), h('th', null, 'You'), h('th', null, 'Answer key'))),
      h(
        'tbody',
        null,
        cmp('Disposition', r.disposition ? DISPOSITION_LABELS[r.disposition] : '—', DISPOSITION_LABELS[truth.disposition], g.dispositionCorrect),
        cmp('Severity', r.severity ? SEVERITY_LABELS[r.severity] : '—', SEVERITY_LABELS[truth.severity], r.severity === truth.severity),
        cmp('Action', r.action ? ACTION_LABELS[r.action] : '—', ACTION_LABELS[truth.action], r.action === truth.action),
        h('tr', { class: g.missedTechniques.length === 0 && g.extraTechniques.length === 0 ? 'ok' : 'miss' }, h('th', { scope: 'row' }, 'ATT&CK'), h('td', null, yoursTechs), h('td', null, truthTechs)),
      ),
    ),
  );

  // ---------------------------------------------------------------- notes
  const hits = new Set(g.rubricAutoHits);
  const notesSection = h(
    'section',
    { class: 'card' },
    h('h2', { class: 'section-title' }, `Notes coverage — ${hits.size} of ${c.rubric.length} key points`),
    h(
      'ul',
      { class: 'rubric' },
      ...c.rubric.map((item) => h('li', { class: hits.has(item.id) ? 'hit' : 'missed' }, h('span', { class: 'rubric-mark', 'aria-hidden': 'true' }, hits.has(item.id) ? '✓' : '○'), item.text)),
    ),
    r.notes.trim()
      ? h('blockquote', { class: 'notes-quote' }, r.notes)
      : h('p', { class: 'muted small' }, 'You left the notes empty. In a real ticket, the write-up is what the next shift reads.'),
    h('p', { class: 'muted small' }, 'Coverage is detected by keywords, so it is a nudge, not a judgement — the checklist is what a strong ticket would contain.'),
  );

  // ----------------------------------------------------------- explanation
  const explanation = h(
    'section',
    { class: 'card explanation' },
    h('h2', { class: 'section-title' }, 'What was actually going on'),
    ...c.explanation.map((para) => h('p', null, para)),
    c.pitfalls.length
      ? h('div', { class: 'pitfalls' }, h('h3', null, 'Common pitfalls'), h('ul', null, ...c.pitfalls.map((x) => h('li', null, x))))
      : null,
    h(
      'div',
      { class: 'refs' },
      h('h3', null, 'Maps to'),
      h('ul', { class: 'chips' }, ...c.cysaDomains.map((d) => h('li', { class: 'chip' }, `CySA+ ${cysaLabel(d)}`))),
      c.references.length
        ? h('ul', { class: 'plain' }, ...c.references.map((ref) => h('li', null, h('a', { href: ref.url, target: '_blank', rel: 'noopener' }, ref.label))))
        : null,
    ),
  );

  // ------------------------------------------------------------- session
  let sessionBlock: HTMLElement;
  if (s && s.mode === 'shift' && finished) {
    const avg = Math.round(s.results.reduce((a, x) => a + x.percent, 0) / s.results.length);
    const xp = s.results.reduce((a, x) => a + x.xp, 0);
    const correct = s.results.filter((x) => x.dispositionCorrect).length;
    sessionBlock = h(
      'section',
      { class: 'card shift-summary' },
      h('h2', { class: 'section-title' }, 'Shift complete'),
      h(
        'dl',
        { class: 'stat-grid' },
        stat('Cases', String(s.results.length)),
        stat('Average', `${avg}%`),
        stat('Dispositions', `${correct}/${s.results.length}`),
        stat('XP earned', `+${xp}`),
      ),
      h(
        'ol',
        { class: 'shift-list' },
        ...s.results.map((x) => h('li', { class: x.dispositionCorrect ? 'ok' : 'miss' }, h('span', { class: 'mono pts' }, `${x.percent}%`), ' ', x.title)),
      ),
      h('div', { class: 'form-actions' }, h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.endSession() }, 'Back to queue'), h('button', { class: 'btn', type: 'button', onclick: () => app.navigate('stats') }, 'View stats')),
    );
  } else if (s && s.mode === 'shift') {
    sessionBlock = h(
      'section',
      { class: 'form-actions sticky-actions' },
      h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.loadNextCase() }, `Next case (${s.completed + 1} of ${s.total})`),
      h('span', { class: 'muted small' }, 'Press N'),
      h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => app.endSession() }, 'End shift early'),
    );
  } else if (s && s.mode === 'daily') {
    sessionBlock = h(
      'section',
      { class: 'form-actions sticky-actions' },
      h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.endSession() }, 'Back to queue'),
      h('button', { class: 'btn', type: 'button', onclick: () => app.start({ mode: 'single' }) }, 'Another case'),
    );
  } else {
    sessionBlock = h(
      'section',
      { class: 'form-actions sticky-actions' },
      h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.loadNextCase() }, 'Next case'),
      h('span', { class: 'muted small' }, 'Press N'),
      h('button', { class: 'btn btn-ghost', type: 'button', onclick: () => app.endSession() }, 'Back to queue'),
    );
  }

  const onKey = (e: KeyboardEvent) => {
    if (e.key.toLowerCase() === 'n' && !finished && s && s.mode !== 'daily') {
      const tag = (e.target as HTMLElement | null)?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA') return;
      app.loadNextCase();
    }
  };
  window.addEventListener('keydown', onKey);
  const observer = new MutationObserver(() => {
    if (!document.body.contains(header)) {
      window.removeEventListener('keydown', onKey);
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  return h('div', { class: 'result' }, header, sessionBlock, breakdown, comparison, notesSection, explanation);
}

function stat(label: string, value: string): HTMLElement {
  return h('div', { class: 'stat' }, h('dt', null, label), h('dd', null, value));
}

const VERDICT_SENTENCE = {
  'true-positive': 'This was a true positive.',
  'false-positive': 'This was a false positive.',
  benign: 'This was benign, expected activity.',
} as const;
