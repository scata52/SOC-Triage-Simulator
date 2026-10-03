// The vulnerability case library: one card per case type. Twin templates share
// a title and so one card; which one a start gets is decided by the seed.

import { useState } from 'preact/hooks';
import { profile } from '../store/app.ts';
import { navigate } from '../router.ts';
import { Icon } from '../components/Icon.tsx';
import { randomSeed } from '../lib/format.ts';
import { CATEGORY_LABELS } from '../../core/cases/templates/index.ts';
import { cysaLabel } from '../../core/taxonomy/cysa.ts';
import type { Difficulty } from '../../core/types.ts';
import { VULN_TEMPLATES } from '../../core/vuln/registry.ts';
import { vulnCaseTypes, type VulnCaseType } from '../../core/vuln/worklist.ts';

const DIFF_LABEL: Record<Difficulty, string> = { tier1: 'Tier 1', tier2: 'Tier 2', tier3: 'Tier 3' };
const TYPES = vulnCaseTypes(VULN_TEMPLATES);

function stats(t: VulnCaseType) {
  const ids = new Set(t.templates.map((x) => x.id));
  const tries = profile.value.attempts.filter((x) => ids.has(x.templateId));
  return { n: tries.length, best: tries.length ? Math.max(...tries.map((x) => x.percent)) : null };
}

export function VulnLibrary() {
  const [q, setQ] = useState('');
  const [diff, setDiff] = useState<Difficulty | 'all'>('all');
  const list = TYPES.filter((t) => (diff === 'all' || t.difficulty === diff) && (!q.trim() || t.title.toLowerCase().includes(q.trim().toLowerCase())));

  return (
    <div class="page vl">
      <div class="page-head">
        <div>
          <p class="eyebrow">Vulnerability management</p>
          <h1>Vulnerability cases</h1>
          <p>
            Each card is a scan review. Many hold two variations that look alike and differ in the one clue that decides them; which one you get is random, and every start
            is a fresh variation.
          </p>
          <p class="small">
            New to the terms? Read <a href="#/help/vuln">Vulnerability terms (Help)</a>: scan types, backports, Sim-KEV, Sim-EPSS and the six decisions.
          </p>
        </div>
      </div>

      <div class="filters" role="search">
        <div class="field">
          <label for="vlib-q">Search</label>
          <input id="vlib-q" class="input" type="search" value={q} onInput={(e) => setQ((e.target as HTMLInputElement).value)} placeholder="e.g. internal" />
        </div>
        <div class="field">
          <label for="vlib-diff">Difficulty</label>
          <select id="vlib-diff" class="select" value={diff} onChange={(e) => setDiff((e.target as HTMLSelectElement).value as Difficulty | 'all')}>
            <option value="all">All tiers</option>
            <option value="tier1">Tier 1</option>
            <option value="tier2">Tier 2</option>
            <option value="tier3">Tier 3</option>
          </select>
        </div>
      </div>

      <p class="visually-hidden" role="status">
        {list.length} {list.length === 1 ? 'case type' : 'case types'} shown
      </p>
      {list.length === 0 ? (
        <p class="muted">{q.trim() ? `No case type matches "${q.trim()}".` : 'No vulnerability cases at this tier yet.'}</p>
      ) : (
        <ul class="lib-grid" aria-label="Vulnerability case types">
          {list.map((t) => {
            const s = stats(t);
            return (
              <li class="card lib-card">
                <div class="row">
                  <span class="chip">{CATEGORY_LABELS.vulnmgmt}</span>
                  <span class="diff">{DIFF_LABEL[t.difficulty]}</span>
                </div>
                <h2 class="lib-title">{t.title}</h2>
                <p class="faint small">{t.cysaDomains.map(cysaLabel).join(' · ')}</p>
                <div class="row lib-foot">
                  <span class="faint small">{s.n ? `${s.n} attempt${s.n === 1 ? '' : 's'} · best ${s.best}%` : 'Not attempted'}</span>
                  <span class="spacer" />
                  <button type="button" class="btn btn-sm btn-primary" onClick={() => navigate({ name: 'vuln-case', slug: t.slug, seed: randomSeed() })} aria-label={`Start: ${t.title}`}>
                    <Icon name="play" /> Start
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
