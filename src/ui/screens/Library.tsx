import { useState } from 'preact/hooks';
import { profile } from '../store/app.ts';
import { navigate } from '../router.ts';
import { Icon } from '../components/Icon.tsx';
import { ALERT_TYPES, type AlertType } from '../lib/cases.ts';
import { randomSeed } from '../lib/format.ts';
import { CATEGORY_LABELS } from '../../core/cases/templates/index.ts';
import { cysaLabel } from '../../core/taxonomy/cysa.ts';
import type { Category, Difficulty } from '../../core/types.ts';

const DIFF_LABEL: Record<Difficulty, string> = { tier1: 'Tier 1', tier2: 'Tier 2', tier3: 'Tier 3' };

function stats(a: AlertType) {
  const ids = new Set(a.templates.map((t) => t.id));
  const tries = profile.value.attempts.filter((x) => ids.has(x.templateId));
  return { n: tries.length, best: tries.length ? Math.max(...tries.map((x) => x.percent)) : null };
}

export function Library() {
  const [q, setQ] = useState('');
  const [cat, setCat] = useState<Category | 'all'>('all');
  const [diff, setDiff] = useState<Difficulty | 'all'>('all');
  const cats = [...new Set(ALERT_TYPES.map((a) => a.category))];
  const list = ALERT_TYPES.filter(
    (a) => (cat === 'all' || a.category === cat) && (diff === 'all' || a.difficulty === diff) && (!q.trim() || a.title.toLowerCase().includes(q.trim().toLowerCase())),
  );

  return (
    <div class="page">
      <div class="page-head">
        <div>
          <p class="eyebrow">Practice</p>
          <h1>Alert library</h1>
          <p>
            Each card is a detection. Some fire on real attacks, some on perfectly ordinary activity — often the same detection with opposite answers. Every
            start is a fresh variation.
          </p>
        </div>
      </div>

      <div class="filters" role="search">
        <div class="field">
          <label for="lib-q">Search</label>
          <input id="lib-q" class="input" type="search" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} placeholder="e.g. PowerShell" />
        </div>
        <div class="field">
          <label for="lib-cat">Category</label>
          <select id="lib-cat" class="select" value={cat} onChange={(e) => setCat((e.target as HTMLSelectElement).value as Category | 'all')}>
            <option value="all">All categories</option>
            {cats.map((c) => (
              <option value={c}>{CATEGORY_LABELS[c]}</option>
            ))}
          </select>
        </div>
        <div class="field">
          <label for="lib-diff">Difficulty</label>
          <select id="lib-diff" class="select" value={diff} onChange={(e) => setDiff((e.target as HTMLSelectElement).value as Difficulty | 'all')}>
            <option value="all">All tiers</option>
            <option value="tier1">Tier 1</option>
            <option value="tier2">Tier 2</option>
            <option value="tier3">Tier 3</option>
          </select>
        </div>
      </div>

      <p class="visually-hidden" role="status">
        {list.length} alert types shown
      </p>
      <ul class="lib-grid" aria-label="Alert types">
        {list.map((a) => {
          const s = stats(a);
          return (
            <li class="card lib-card">
              <div class="row">
                <span class="chip">{CATEGORY_LABELS[a.category]}</span>
                <span class="diff">{DIFF_LABEL[a.difficulty]}</span>
                {a.hunt && <span class="badge badge-accent">hunt</span>}
              </div>
              <h2 class="lib-title">{a.title}</h2>
              <p class="faint small">{a.cysaDomains.map(cysaLabel).join(' · ')}</p>
              <div class="row lib-foot">
                <span class="faint small">{s.n ? `${s.n} attempt${s.n === 1 ? '' : 's'} · best ${s.best}%` : 'Not attempted'}</span>
                <span class="spacer" />
                <button type="button" class="btn btn-sm btn-primary" onClick={() => navigate({ name: 'case', slug: a.slug, seed: randomSeed() })} aria-label={`Start: ${a.title}`}>
                  <Icon name="play" /> Start
                </button>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
