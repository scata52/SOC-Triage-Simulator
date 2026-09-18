import type { App } from '../app.ts';
import { CATEGORY_LABELS } from '../../data/templates/index.ts';
import { TACTIC_LABELS } from '../../data/mitre.ts';
import { DIFFICULTY_LABELS } from '../../engine/generator.ts';
import { exportProfileJson, getProfile, importProfileJson, rankFor, resetProfile } from '../../state/store.ts';
import {
  byCategory,
  byCysaDomain,
  byDifficulty,
  summarise,
  tacticCoverage,
  trend,
  weakSpots,
} from '../../state/stats.ts';
import type { Bucket } from '../../state/stats.ts';
import { fmtDate, fmtDuration, h, svg } from '../dom.ts';

export function renderStats(app: App): HTMLElement {
  const p = getProfile();
  const sum = summarise(p.records);
  const rank = rankFor(p.xp);
  const cats = byCategory(p.records, CATEGORY_LABELS);
  const diffs = byDifficulty(p.records, DIFFICULTY_LABELS);
  const domains = byCysaDomain(p.records);
  const tactics = tacticCoverage(p.records);
  const weak = weakSpots(cats);
  const series = trend(p.records, 12);

  if (p.records.length === 0) {
    return h(
      'div',
      { class: 'stats' },
      h('h1', null, 'Stats'),
      h(
        'div',
        { class: 'card empty' },
        h('p', null, 'No cases triaged yet. Your accuracy by category, difficulty, CySA+ domain and ATT&CK tactic will show up here.'),
        h('button', { class: 'btn btn-primary', type: 'button', onclick: () => app.start({ mode: 'single' }) }, 'Start the first case'),
      ),
    );
  }

  return h(
    'div',
    { class: 'stats viz-root' },
    h(
      'div',
      { class: 'stats-head' },
      h('h1', null, 'Stats'),
      h('p', { class: 'muted' }, `${p.analystName} · ${rank.current.name} · ${p.xp.toLocaleString()} XP`),
    ),

    // ---------------------------------------------------------- hero + tiles
    h(
      'section',
      { class: 'tiles' },
      h(
        'div',
        { class: 'tile hero-tile' },
        h('div', { class: 'tile-label' }, 'Average score'),
        h('div', { class: 'hero-figure' }, `${sum.avgPercent}%`),
        h('div', { class: 'tile-sub muted' }, `across ${sum.total} case${sum.total === 1 ? '' : 's'}`),
      ),
      tile('Last 10 cases', `${sum.last10Percent}%`, sparkline(series)),
      tile('Disposition accuracy', `${sum.dispositionAccuracy}%`),
      tile('Best streak', String(p.bestStreak)),
      tile('Avg time per case', sum.avgDurationSec !== null ? fmtDuration(sum.avgDurationSec) : '—'),
    ),

    weak.length
      ? h(
          'section',
          { class: 'card weak' },
          h('h2', { class: 'section-title' }, 'Focus next'),
          h('p', { class: 'muted' }, 'Lowest average score with at least two cases played. Use the category filter on the queue to drill these.'),
          h('ul', { class: 'chips' }, ...weak.map((b) => h('li', { class: 'chip' }, `${b.label} `, h('span', { class: 'chip-count' }, `${b.avgPercent}%`)))),
        )
      : null,

    h(
      'section',
      { class: 'grid-2' },
      barCard('Score by category', 'Average score per case category. Bars show mean %, tooltip has count and disposition accuracy.', cats),
      barCard('Score by difficulty', 'Tier 1 is foundational, Tier 3 is the hard stuff.', diffs),
    ),

    h(
      'section',
      { class: 'grid-2' },
      barCard('CySA+ domain coverage', 'Average score on cases mapped to each CS0-003 exam domain.', domains),
      tacticCard(tactics),
    ),

    // ------------------------------------------------------------- history
    h(
      'section',
      { class: 'card' },
      h('h2', { class: 'section-title' }, 'Recent cases'),
      h(
        'table',
        { class: 'history' },
        h('thead', null, h('tr', null, h('th', null, 'When'), h('th', null, 'Case'), h('th', null, 'Category'), h('th', { class: 'num' }, 'Score'), h('th', null, 'Disp.'), h('th', { class: 'num' }, 'Time'))),
        h(
          'tbody',
          null,
          ...p.records
            .slice(-15)
            .reverse()
            .map((r) =>
              h(
                'tr',
                null,
                h('td', { class: 'muted small' }, fmtDate(r.completedAt)),
                h('td', null, r.title),
                h('td', { class: 'muted small' }, CATEGORY_LABELS[r.category]),
                h('td', { class: 'num mono' }, `${r.percent}%`),
                h('td', { class: r.dispositionCorrect ? 'status-good' : 'status-critical' }, r.dispositionCorrect ? '✓ correct' : '✗ missed'),
                h('td', { class: 'num mono muted' }, r.durationSec !== null ? fmtDuration(r.durationSec) : '—'),
              ),
            ),
        ),
      ),
    ),

    // --------------------------------------------------------------- data
    h(
      'section',
      { class: 'card' },
      h('h2', { class: 'section-title' }, 'Your data'),
      h('p', { class: 'muted' }, 'Everything is stored only in this browser. Export to keep a copy or move it to another machine.'),
      h(
        'div',
        { class: 'form-actions' },
        h('button', { class: 'btn', type: 'button', onclick: downloadExport }, 'Export JSON'),
        h('label', { class: 'btn file-btn' }, 'Import JSON', h('input', { type: 'file', accept: 'application/json', onchange: (e: Event) => importFile(e, app) })),
        h(
          'button',
          {
            class: 'btn btn-danger',
            type: 'button',
            onclick: () => {
              if (confirm('Reset all progress? This cannot be undone.')) {
                resetProfile();
                app.navigate('stats');
              }
            },
          },
          'Reset progress',
        ),
      ),
    ),
  );
}

// ---------------------------------------------------------------------------
function tile(label: string, value: string, extra?: Node, sub?: string): HTMLElement {
  return h(
    'div',
    { class: 'tile' },
    h('div', { class: 'tile-label' }, label),
    h('div', { class: 'tile-value' }, value),
    extra ?? null,
    sub ? h('div', { class: 'tile-sub muted' }, sub) : null,
  );
}

// 12-point sparkline: 2px line, round caps, >=8px end marker in the accent.
function sparkline(values: number[]): Node {
  if (values.length < 2) return h('div', { class: 'tile-sub muted' }, 'play more cases for a trend');
  const w = 120;
  const hgt = 32;
  const pad = 4;
  const n = values.length;
  const x = (i: number) => pad + (i * (w - pad * 2)) / (n - 1);
  const y = (v: number) => pad + (1 - v / 100) * (hgt - pad * 2);
  const d = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const last = values[n - 1];
  return svg(
    'svg',
    { class: 'sparkline', viewBox: `0 0 ${w} ${hgt}`, width: w, height: hgt, role: 'img', 'aria-label': `Score trend over the last ${n} cases, most recent ${last}%` },
    svg('path', { d, fill: 'none', stroke: 'var(--viz-muted)', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }),
    svg('circle', { cx: x(n - 1).toFixed(1), cy: y(last).toFixed(1), r: 4, fill: 'var(--viz-accent)', stroke: 'var(--surface)', 'stroke-width': 2 }),
  );
}

// Horizontal bar chart: single series (blue), value at the tip, hairline baseline.
function barCard(title: string, blurb: string, buckets: Bucket[]): HTMLElement {
  const rows = buckets.filter((b) => b.count > 0);
  return h(
    'div',
    { class: 'card chart-card' },
    h('h2', { class: 'section-title' }, title),
    h('p', { class: 'muted small' }, blurb),
    rows.length === 0
      ? h('p', { class: 'muted' }, 'No data yet.')
      : h(
          'div',
          { class: 'bars', role: 'img', 'aria-label': `${title}: ${rows.map((b) => `${b.label} ${b.avgPercent}%`).join(', ')}` },
          ...rows.map((b) =>
            h(
              'div',
              { class: 'bar-row', title: `${b.label}: ${b.avgPercent}% average over ${b.count} case${b.count === 1 ? '' : 's'} · disposition accuracy ${b.dispositionAccuracy}%` },
              h('div', { class: 'bar-label' }, b.label),
              h(
                'div',
                { class: 'bar-track' },
                h('div', { class: 'bar-fill', style: `width:${b.avgPercent}%` }),
                h('span', { class: 'bar-value mono' }, `${b.avgPercent}%`),
              ),
              h('div', { class: 'bar-count muted small' }, `n=${b.count}`),
            ),
          ),
        ),
    // Table view for accessibility / exact numbers.
    rows.length
      ? h(
          'details',
          { class: 'table-view' },
          h('summary', null, 'Table view'),
          h(
            'table',
            null,
            h('thead', null, h('tr', null, h('th', null, ''), h('th', { class: 'num' }, 'Cases'), h('th', { class: 'num' }, 'Avg %'), h('th', { class: 'num' }, 'Disp. acc.'))),
            h('tbody', null, ...rows.map((b) => h('tr', null, h('th', { scope: 'row' }, b.label), h('td', { class: 'num mono' }, String(b.count)), h('td', { class: 'num mono' }, `${b.avgPercent}%`), h('td', { class: 'num mono' }, `${b.dispositionAccuracy}%`)))),
          ),
        )
      : null,
  );
}

// ATT&CK tactic coverage: one meter per tactic. Fill = technique hit-rate
// (sequential blue), track = a deeper step of the same ramp.
function tacticCard(tactics: ReturnType<typeof tacticCoverage>): HTMLElement {
  const played = tactics.filter((t) => t.cases > 0);
  return h(
    'div',
    { class: 'card chart-card' },
    h('h2', { class: 'section-title' }, 'ATT&CK tactic coverage'),
    h('p', { class: 'muted small' }, 'For cases involving each tactic: how often you tagged the right technique. Tactics you have not met yet are dimmed.'),
    h(
      'ul',
      { class: 'meters' },
      ...tactics.map((t) =>
        h(
          'li',
          { class: `meter-row${t.cases === 0 ? ' unplayed' : ''}`, title: t.cases ? `${TACTIC_LABELS[t.tactic]}: ${t.techniqueHitRate}% technique hit-rate over ${t.cases} case${t.cases === 1 ? '' : 's'}` : `${TACTIC_LABELS[t.tactic]}: not yet encountered` },
          h('span', { class: 'meter-label' }, TACTIC_LABELS[t.tactic]),
          h('span', { class: 'meter', role: 'meter', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': t.techniqueHitRate, 'aria-label': `${TACTIC_LABELS[t.tactic]} technique hit-rate` }, h('span', { class: 'meter-fill', style: `width:${t.techniqueHitRate}%` })),
          h('span', { class: 'meter-value mono' }, t.cases ? `${t.techniqueHitRate}%` : '—'),
          h('span', { class: 'meter-count muted small' }, t.cases ? `n=${t.cases}` : ''),
        ),
      ),
    ),
    played.length === 0 ? h('p', { class: 'muted small' }, 'Play a few true-positive cases to populate this.') : null,
  );
}

// ---------------------------------------------------------------------------
function downloadExport(): void {
  const blob = new Blob([exportProfileJson()], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `soc-triage-progress-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function importFile(e: Event, app: App): void {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  file.text().then((text) => {
    if (importProfileJson(text)) {
      app.navigate('stats');
    } else {
      alert('That file does not look like an exported profile.');
    }
    input.value = '';
  });
}
