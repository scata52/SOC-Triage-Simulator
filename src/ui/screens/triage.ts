import type { App } from '../app.ts';
import type { Disposition, LogArtifact, Severity, TriageAction, TriageCase } from '../../types.ts';
import { CATEGORY_LABELS } from '../../data/templates/index.ts';
import { DIFFICULTY_LABELS } from '../../engine/generator.ts';
import { MITRE_TECHNIQUES, TACTIC_LABELS, techniqueName } from '../../data/mitre.ts';
import {
  ACTION_LABELS,
  ACTION_ORDER,
  DISPOSITION_LABELS,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  detectRubricHits,
} from '../../engine/grading.ts';
import { getProfile } from '../../state/store.ts';
import { clear, fmtDuration, h } from '../dom.ts';

export function renderTriage(app: App, c: TriageCase): HTMLElement {
  const settings = getProfile().settings;
  const s = app.session;

  // ------------------------------------------------------------------ header
  const header = h(
    'section',
    { class: 'case-header' },
    h(
      'div',
      { class: 'case-meta' },
      h('span', { class: `chip cat-${c.category}` }, CATEGORY_LABELS[c.category]),
      h('span', { class: `chip tier-${c.difficulty}` }, DIFFICULTY_LABELS[c.difficulty]),
      s && s.mode === 'shift' ? h('span', { class: 'chip' }, `Case ${s.completed + 1} of ${s.total}`) : null,
      s && s.mode === 'daily' ? h('span', { class: 'chip' }, 'Case of the Day') : null,
      settings.timerEnabled ? timerEl(app) : null,
    ),
    h('h1', { class: 'case-title' }, c.title),
    h('div', { class: 'alert-box', role: 'note' }, h('span', { class: 'alert-label' }, 'ALERT'), h('p', null, c.alert)),
    h('p', { class: 'context muted' }, c.context),
  );

  // --------------------------------------------------------------- artifacts
  const artifacts = h(
    'section',
    { class: 'artifacts' },
    h('h2', { class: 'section-title' }, 'Evidence'),
    ...c.artifacts.map(renderArtifact),
  );

  // -------------------------------------------------------------------- form
  const submitBtn = h(
    'button',
    { class: 'btn btn-primary', type: 'button', disabled: true, onclick: () => app.submit() },
    'Submit triage',
  );

  const refreshSubmit = () => {
    const r = app.response;
    const ready = r.disposition !== null && r.severity !== null && r.action !== null;
    if (ready) submitBtn.removeAttribute('disabled');
    else submitBtn.setAttribute('disabled', '');
  };

  const dispositionCtl = segmented<Disposition>(
    'Disposition',
    'What is this?',
    (['true-positive', 'false-positive', 'benign'] as Disposition[]).map((d) => ({
      value: d,
      label: DISPOSITION_LABELS[d],
      className: `disp-${d}`,
    })),
    () => app.response.disposition,
    (v) => {
      app.response.disposition = v;
      refreshSubmit();
    },
  );

  const severityCtl = segmented<Severity>(
    'Severity',
    'How bad, if real?',
    SEVERITY_ORDER.map((sv) => ({ value: sv, label: SEVERITY_LABELS[sv], className: `sev-${sv}` })),
    () => app.response.severity,
    (v) => {
      app.response.severity = v;
      refreshSubmit();
    },
  );

  const actionCtl = segmented<TriageAction>(
    'Action',
    'What happens next?',
    ACTION_ORDER.map((a) => ({ value: a, label: ACTION_LABELS[a], className: `act-${a}` })),
    () => app.response.action,
    (v) => {
      app.response.action = v;
      refreshSubmit();
    },
  );

  const techniquePicker = renderTechniquePicker(app);

  // Notes + optional live rubric
  const rubricLive = h('ul', { class: 'rubric-live' });
  const refreshRubric = () => {
    clear(rubricLive);
    if (!settings.showRubricLive) return;
    const hits = new Set(detectRubricHits(c, app.response.notes));
    for (const item of c.rubric) {
      rubricLive.appendChild(
        h('li', { class: hits.has(item.id) ? 'hit' : '' }, hits.has(item.id) ? '✓ ' : '○ ', item.text),
      );
    }
  };

  const notes = h('textarea', {
    class: 'textarea',
    id: 'notes',
    rows: 6,
    placeholder:
      'Analyst notes — what happened, which evidence supports it, and what should happen next. Write it the way you would in the ticket.',
    oninput: (e: Event) => {
      app.response.notes = (e.target as HTMLTextAreaElement).value;
      refreshRubric();
    },
  }) as HTMLTextAreaElement;
  notes.value = app.response.notes;
  refreshRubric();

  const form = h(
    'section',
    { class: 'triage-form card' },
    h('h2', { class: 'section-title' }, 'Your triage'),
    dispositionCtl,
    severityCtl,
    actionCtl,
    techniquePicker,
    h(
      'div',
      { class: 'field' },
      h('label', { for: 'notes', class: 'field-label' }, 'Notes'),
      h('p', { class: 'field-hint muted' }, 'Free text. Graded lightly for coverage of the key points — the objective fields carry the score.'),
      notes,
      settings.showRubricLive ? rubricLive : null,
    ),
    h(
      'div',
      { class: 'form-actions' },
      submitBtn,
      h('span', { class: 'muted small' }, 'Ctrl/⌘ + Enter to submit'),
      h(
        'button',
        {
          class: 'btn btn-ghost',
          type: 'button',
          onclick: () => {
            if (confirm('Abandon this case? It will not be recorded.')) app.abandonCase();
          },
        },
        'Abandon',
      ),
    ),
  );

  const onKey = (e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !submitBtn.hasAttribute('disabled')) {
      e.preventDefault();
      app.submit();
    }
  };
  window.addEventListener('keydown', onKey, { once: false });
  // Remove the handler when the screen is torn down.
  const observer = new MutationObserver(() => {
    if (!document.body.contains(form)) {
      window.removeEventListener('keydown', onKey);
      observer.disconnect();
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });

  refreshSubmit();

  return h('div', { class: 'triage' }, header, h('div', { class: 'triage-layout' }, artifacts, form));
}

// ---------------------------------------------------------------------------
function renderArtifact(a: LogArtifact): HTMLElement {
  return h(
    'section',
    { class: `artifact fmt-${a.format}` },
    h(
      'header',
      { class: 'artifact-head' },
      h('span', { class: 'artifact-source' }, a.source),
      a.caption ? h('span', { class: 'artifact-caption muted' }, a.caption) : null,
    ),
    h('pre', { class: 'artifact-body', tabindex: 0 }, a.lines.join('\n')),
  );
}

interface Option<T> {
  value: T;
  label: string;
  className?: string;
}

function segmented<T extends string>(
  title: string,
  hint: string,
  options: Option<T>[],
  get: () => T | null,
  set: (v: T) => void,
): HTMLElement {
  const group = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': title });
  const buttons = options.map((o) =>
    h(
      'button',
      {
        type: 'button',
        role: 'radio',
        class: `seg ${o.className ?? ''}`,
        'aria-checked': 'false',
        onclick: () => {
          set(o.value);
          refresh();
        },
      },
      o.label,
    ),
  );
  const refresh = () => {
    const cur = get();
    buttons.forEach((b, i) => {
      const on = options[i].value === cur;
      b.classList.toggle('active', on);
      b.setAttribute('aria-checked', on ? 'true' : 'false');
    });
  };
  buttons.forEach((b) => group.appendChild(b));
  refresh();
  return h(
    'div',
    { class: 'field' },
    h('div', { class: 'field-label' }, title, h('span', { class: 'field-hint muted' }, ' ', hint)),
    group,
  );
}

// ---------------------------------------------------------------------------
function renderTechniquePicker(app: App): HTMLElement {
  let query = '';
  const chips = h('ul', { class: 'chips technique-chips', 'aria-live': 'polite' });
  const list = h('ul', { class: 'technique-list', role: 'listbox', 'aria-multiselectable': 'true' });

  const selected = () => app.response.techniques;

  const toggle = (id: string) => {
    const cur = selected();
    app.response.techniques = cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id];
    refreshChips();
    refreshList();
  };

  const refreshChips = () => {
    clear(chips);
    if (selected().length === 0) {
      chips.appendChild(h('li', { class: 'muted small' }, 'None selected — leave empty for benign / false-positive cases.'));
      return;
    }
    for (const id of selected()) {
      chips.appendChild(
        h(
          'li',
          { class: 'chip chip-removable' },
          h('span', { class: 'mono' }, id),
          ' ',
          techniqueName(id),
          h('button', { type: 'button', class: 'chip-x', 'aria-label': `Remove ${id}`, onclick: () => toggle(id) }, '×'),
        ),
      );
    }
  };

  const refreshList = () => {
    clear(list);
    const q = query.trim().toLowerCase();
    const matches = MITRE_TECHNIQUES.filter((t) => {
      if (!q) return true;
      return (
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.tactics.some((tc) => TACTIC_LABELS[tc].toLowerCase().includes(q))
      );
    });
    const sel = new Set(selected());
    for (const t of matches.slice(0, 60)) {
      const on = sel.has(t.id);
      list.appendChild(
        h(
          'li',
          { role: 'option', 'aria-selected': on ? 'true' : 'false', class: on ? 'selected' : '' },
          h(
            'label',
            { class: 'technique-row' },
            h('input', { type: 'checkbox', checked: on, onchange: () => toggle(t.id) }),
            h('span', { class: 'mono technique-id' }, t.id),
            h('span', { class: 'technique-name' }, t.name),
            h('span', { class: 'technique-tactic muted' }, t.tactics.map((tc) => TACTIC_LABELS[tc]).join(' · ')),
          ),
        ),
      );
    }
    if (matches.length === 0) list.appendChild(h('li', { class: 'muted small' }, 'No techniques match.'));
  };

  const search = h('input', {
    type: 'search',
    class: 'input',
    placeholder: 'Filter by ID, name or tactic — e.g. "T1110", "phishing", "lateral"',
    'aria-label': 'Filter techniques',
    oninput: (e: Event) => {
      query = (e.target as HTMLInputElement).value;
      refreshList();
    },
  });

  refreshChips();
  refreshList();

  return h(
    'div',
    { class: 'field' },
    h('div', { class: 'field-label' }, 'MITRE ATT&CK technique(s)', h('span', { class: 'field-hint muted' }, ' Tag what the adversary did. Sub-techniques preferred.')),
    chips,
    search,
    h('div', { class: 'technique-scroll' }, list),
  );
}

// ---------------------------------------------------------------------------
function timerEl(app: App): HTMLElement {
  const el = h('span', { class: 'chip chip-timer mono', 'aria-live': 'off' }, '0s');
  const tick = () => {
    if (!document.body.contains(el)) {
      clearInterval(iv);
      return;
    }
    if (app.startedAt) el.textContent = fmtDuration(Math.round((Date.now() - app.startedAt) / 1000));
  };
  const iv = setInterval(tick, 1000);
  return el;
}
