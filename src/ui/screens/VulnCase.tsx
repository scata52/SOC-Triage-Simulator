// A vulnerability case: brief, worklist, console and note, submit, debrief.
//
// Leak boundary: this container holds the resolved case, but before submitting
// it hands the screens below only `VulnCaseView` (six copied fields), the
// worklist rows (scanner columns) and the learner's draft. Only the debrief
// receives the case itself. Ids use the constant prefixes wl-, vc- and vcq-.

import { useEffect, useRef, useState } from 'preact/hooks';
import { profile, update, today, announcement } from '../store/app.ts';
import { navigate } from '../router.ts';
import { siem } from '../lib/siem.ts';
import type { LookupRow } from '../lib/protocol.ts';
import { clock, randomSeed } from '../lib/format.ts';
import { play } from '../lib/sound.ts';
import { focusHeading } from '../lib/focus.ts';
import { recordVulnAttempt } from '../../state/profile.ts';
import { gradeVulnCase, type VulnFindingAnswer, type VulnGrade, type VulnSubmission } from '../../core/vuln/grade.ts';
import type { ResolvedVulnCase } from '../../core/vuln/scenario.ts';
import { VULN_TEMPLATES } from '../../core/vuln/registry.ts';
import type { ReasonCode } from '../../core/vuln/model.ts';
import type { TableName } from '../../core/logs/schema.ts';
import type { Difficulty } from '../../core/types.ts';
import {
  MAX_REASONS,
  UNDO_SORT_MESSAGE,
  VULN_PASS_PERCENT,
  applySort,
  boundsMessage,
  buildSubmission,
  capMessage,
  caseView,
  defaultOrder,
  emptyDraft,
  missingForSubmit,
  moveBy,
  moveTo,
  pinCount,
  positionMessage,
  restoreDraft,
  resolveVulnTemplate,
  stayMessage,
  stillNeededMessage,
  toggleReason,
  undoSort,
  vulnCaseTypes,
  worklistRows,
  type SortKey,
  type SortUndo,
  type VulnCaseView,
  type VulnDraft,
  type WorklistRow,
} from '../../core/vuln/worklist.ts';
import { summarise, type PinMeta } from '../components/Results.tsx';
import { Worklist, type MoveTarget } from '../components/Worklist.tsx';
import { Icon } from '../components/Icon.tsx';
import { Loading, Notice, Tabs } from '../components/ui.tsx';
import { VulnBrief } from './VulnBrief.tsx';
import { VulnConsole, VULN_STARTER } from './VulnConsole.tsx';
import { VulnNote } from './VulnNote.tsx';
import { VulnDebrief } from './VulnDebrief.tsx';

const DIFF_LABEL: Record<Difficulty, string> = { tier1: 'Tier 1', tier2: 'Tier 2', tier3: 'Tier 3' };
const TYPES = vulnCaseTypes(VULN_TEMPLATES);

// ---- session storage (try/catch, as the SOC case screen) ---------------------

function loadVulnDraft(k: string): unknown {
  try {
    const raw = sessionStorage.getItem(`vdraft:${k}`);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function saveVulnDraft(k: string, d: VulnDraft | null): void {
  try {
    if (d) sessionStorage.setItem(`vdraft:${k}`, JSON.stringify(d));
    else sessionStorage.removeItem(`vdraft:${k}`);
  } catch {
    /* ignore */
  }
}
// The finished debrief survives leaving the screen (the Help link, the nav, Back): the submission is kept per case, the
// grade is recomputed from it on return and must match the stored score, else the case renders normally.
function saveVulnDone(k: string, templateId: string, percent: number, submission: VulnSubmission): void {
  try {
    sessionStorage.setItem(`vdone:${k}`, JSON.stringify({ v: 1, templateId, percent, submission }));
  } catch {
    /* ignore */
  }
}
function clearVulnDone(k: string): void {
  try {
    sessionStorage.removeItem(`vdone:${k}`);
  } catch {
    /* ignore */
  }
}
function loadVulnDone(k: string, c: ResolvedVulnCase, templateId: string): { grade: VulnGrade; submission: VulnSubmission } | null {
  try {
    const raw = sessionStorage.getItem(`vdone:${k}`);
    if (!raw) return null;
    const o = JSON.parse(raw) as { v?: unknown; templateId?: unknown; percent?: unknown; submission?: Partial<VulnSubmission> | null };
    const sub = o.submission;
    if (o.v !== 1 || o.templateId !== templateId || typeof o.percent !== 'number' || !sub || typeof sub !== 'object') return null;
    if (!sub.answers || typeof sub.answers !== 'object' || Array.isArray(sub.answers)) return null;
    if (!Array.isArray(sub.order) || !sub.order.every((x) => typeof x === 'string')) return null;
    if (!Array.isArray(sub.pins) || !sub.pins.every((x) => typeof x === 'string')) return null;
    if (typeof sub.notes !== 'string' || typeof sub.hintsUsed !== 'number') return null;
    const submission = sub as VulnSubmission;
    const grade = gradeVulnCase(c, submission);
    return grade.percent === o.percent ? { grade, submission } : null;
  } catch {
    return null;
  }
}
function loadVulnQuery(k: string): string | null {
  try {
    return sessionStorage.getItem(`vq:${k}`);
  } catch {
    return null;
  }
}
function saveVulnQuery(k: string, t: string): void {
  try {
    sessionStorage.setItem(`vq:${k}`, t);
  } catch {
    /* ignore */
  }
}

// ---- announcements: clear, then set, so an identical repeat is spoken again ---

let sayTimer: ReturnType<typeof setTimeout> | undefined;
function say(text: string): void {
  clearTimeout(sayTimer);
  announcement.value = '';
  sayTimer = setTimeout(() => (announcement.value = text), 50);
}

function useMedia(q: string): boolean {
  const [m, setM] = useState(() => typeof matchMedia !== 'undefined' && matchMedia(q).matches);
  useEffect(() => {
    const mq = matchMedia(q);
    const on = () => setM(mq.matches);
    on();
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, [q]);
  return m;
}

function Timer({ since }: { since: number }) {
  const [, tick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => tick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span class="chip chip-mono" aria-label="Time on this case" role="timer">
      <Icon name="clock" /> {clock((Date.now() - since) / 1000)}
    </span>
  );
}

interface Bundle {
  c: ResolvedVulnCase;
  view: VulnCaseView;
  rows: ReadonlyMap<string, WorklistRow>;
  controls: { id: string; kind: string }[];
  rowsByTable: Record<TableName, number>;
  ids: string[];
}

export function VulnCase({ slug, seed }: { slug: string; seed: string }) {
  const type = TYPES.find((t) => t.slug === slug);
  const template = type ? resolveVulnTemplate(type, seed) : undefined;
  const worldSeed = profile.value.worldSeed;
  const key = `vuln:${worldSeed}:${slug}:${seed}`;

  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [draft, setDraft] = useState<VulnDraft | null>(null);
  const [pinRows, setPinRows] = useState<ReadonlyMap<string, LookupRow>>(new Map());
  const [tab, setTab] = useState<'console' | 'note'>('console');
  const [movedId, setMovedId] = useState<string | null>(null);
  const [sortUndo, setSortUndo] = useState<SortUndo | null>(null);
  const [gateShown, setGateShown] = useState(false);
  const [done, setDone] = useState<{ grade: VulnGrade; submission: VulnSubmission } | null>(null);
  const started = useRef(Date.now());
  const consoleApi = useRef<{ load(q: string): void } | null>(null);
  const draftRef = useRef<VulnDraft | null>(null);
  const movedTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const narrow = useMedia('(max-width: 760px)');

  useEffect(() => {
    if (!template) return;
    let live = true;
    (async () => {
      try {
        const s = await siem.open({ kind: 'vuln', worldSeed, templateId: template.id, seed });
        const c = s.vulnCase;
        if (!c) throw new Error('The case could not be built.');
        const pairs = c.findings.map(({ findingId, recordId }) => ({ findingId, recordId }));
        const [lookup, inv] = await Promise.all([siem.lookup(pairs.map((x) => x.recordId)), siem.run('ControlInventory\n| project ControlId, Kind\n| sort by ControlId asc', 'kql', 500)]);
        if (!live) return;
        const ids = defaultOrder(pairs.map((x) => x.findingId));
        const d = restoreDraft(loadVulnDraft(key), ids, c.hints.length);
        draftRef.current = d;
        setDraft(d);
        // Back from Help or the nav: show the debrief again (never records the attempt a second time).
        setDone(loadVulnDone(key, c, template.id));
        setBundle({
          c,
          view: caseView(c),
          rows: worklistRows(pairs, lookup),
          controls: inv.rows.map((r) => ({ id: String(r[0] ?? ''), kind: String(r[1] ?? '') })),
          rowsByTable: s.rowsByTable,
          ids,
        });
      } catch (e) {
        if (live) setFailed((e as Error).message);
      }
    })();
    return () => {
      live = false;
    };
  }, [key]);

  useEffect(() => {
    if (bundle) focusHeading();
  }, [bundle, done]);

  // Pinned rows restored from a draft (or just pinned) need their cells.
  const pinKey = draft ? draft.pins.join(',') : '';
  useEffect(() => {
    if (!draft) return;
    const missing = draft.pins.filter((id) => !pinRows.has(id));
    if (!missing.length) return;
    let live = true;
    siem.lookup(missing).then((rows) => {
      if (!live) return;
      setPinRows((m) => {
        const next = new Map(m);
        for (const r of rows) next.set(summarise(r.columns, r.row, r.table).recordId, r);
        return next;
      });
    });
    return () => {
      live = false;
    };
  }, [pinKey]);

  useEffect(() => () => clearTimeout(movedTimer.current), []);

  if (!template || !type) {
    return (
      <div class="page page-narrow">
        <h1>Unknown case</h1>
        <p>
          There is no vulnerability case called <code>{slug}</code>. <a href="#/vuln">Browse the vulnerability cases</a>.
        </p>
      </div>
    );
  }
  if (failed) {
    return (
      <div class="page page-narrow">
        <h1>The case could not be built</h1>
        <Notice tone="bad">
          <p>{failed}</p>
        </Notice>
      </div>
    );
  }
  if (!bundle || !draft) return <Loading text="Generating the scan results…" />;
  const { c, view, rows, controls } = bundle;

  const commit = (next: VulnDraft) => {
    draftRef.current = next;
    setDraft(next);
    saveVulnDraft(key, next);
  };
  const cur = () => draftRef.current ?? draft;
  const label = (id: string) => {
    const host = rows.get(id)?.host;
    return host ? `${id} on ${host}` : id;
  };

  // ---- worklist callbacks -----------------------------------------------------

  const onAnswer = (id: string, a: VulnFindingAnswer) => {
    const d = cur();
    const prev = d.answers[id];
    commit({ ...d, answers: { ...d.answers, [id]: a } });
    if (a.decision === 'mitigate' && prev?.decision !== 'mitigate' && controls.length > 0) say(`Choose a control for ${label(id)} in the next field.`);
  };

  const onReason = (id: string, code: ReasonCode) => {
    const d = cur();
    const a = d.answers[id] ?? { decision: null, control: null, schedule: null, reasons: [] };
    const t = toggleReason(a.reasons, code, MAX_REASONS);
    if (t.capped) return say(capMessage(id));
    commit({ ...d, answers: { ...d.answers, [id]: { ...a, reasons: t.reasons } } });
    if (t.reasons.length === MAX_REASONS && a.reasons.length < MAX_REASONS) say(capMessage(id));
  };

  const onSort = (k: SortKey) => {
    const r = applySort(cur(), rows, k, sortUndo);
    commit(r.draft);
    setSortUndo(r.undo);
    setMovedId(null);
    say(r.message);
  };

  const onUndoSort = () => {
    if (!sortUndo) return;
    const d = cur();
    const was = d.sort?.key;
    commit(undoSort(d, sortUndo));
    setSortUndo(null);
    say(UNDO_SORT_MESSAGE);
    if (was) requestAnimationFrame(() => document.getElementById(`wl-sort-${was}`)?.focus());
  };

  const onMove = (id: string, target: MoveTarget) => {
    const d = cur();
    const res = 'by' in target ? moveBy(d.order, id, target.by) : moveTo(d.order, id, target.to);
    if (res.from < 0) return;
    if (res.to === res.from) return say('by' in target ? boundsMessage(id, target.by < 0 ? 'first' : 'last') : stayMessage(id, res.from, d.order.length));
    commit({ ...d, order: res.order, sort: null });
    setSortUndo(null);
    setMovedId(id);
    clearTimeout(movedTimer.current);
    movedTimer.current = setTimeout(() => setMovedId(null), 2000);
    say(positionMessage(id, res.to, d.order.length));
  };

  // ---- evidence and hints -----------------------------------------------------

  const togglePin = (meta: PinMeta) => {
    const d = cur();
    const pinned = d.pins.includes(meta.recordId);
    commit({ ...d, pins: pinned ? d.pins.filter((x) => x !== meta.recordId) : [...d.pins, meta.recordId] });
    if (!pinned) play('pin');
    say(pinned ? 'Unpinned.' : `Pinned as evidence (${d.pins.length + 1}).`);
  };

  const pinned = draft.pins.map((id) => {
    const r = pinRows.get(id);
    return r ? summarise(r.columns, r.row, r.table) : ({ recordId: id, time: '', text: 'Loading…' } as PinMeta);
  });
  const pinSet = new Set(draft.pins);
  const pinLookups = draft.pins.map((id) => pinRows.get(id)).filter((r): r is LookupRow => !!r);
  const pinCounts: Record<string, number> = {};
  for (const id of draft.order) {
    const r = rows.get(id);
    if (r) pinCounts[id] = pinCount(r, pinLookups);
  }

  const revealHint = () => {
    const d = cur();
    const n = Math.min(view.hints.length, d.hintsUsed + 1);
    if (n === d.hintsUsed) return;
    commit({ ...d, hintsUsed: n });
    say(`Hint ${n} of ${view.hints.length}: ${view.hints[n - 1]}`);
    requestAnimationFrame(() => document.getElementById(`vc-hint-${n - 1}`)?.focus());
  };

  const unpin = (recordId: string) => {
    const d = cur();
    const at = d.pins.indexOf(recordId);
    if (at < 0) return;
    commit({ ...d, pins: d.pins.filter((x) => x !== recordId) });
    say('Unpinned.');
    // The next Unpin button takes this one's place, else the previous one, else the list heading.
    requestAnimationFrame(() => {
      const btns = document.querySelectorAll<HTMLElement>('.vc-submit .pins .pin-unpin');
      (btns[Math.min(at, btns.length - 1)] ?? document.getElementById('vc-pins-h'))?.focus();
    });
  };

  // ---- submit -----------------------------------------------------------------

  const missing = missingForSubmit(draft, controls.length);
  const ready = draft.order.length - new Set(missing.map((m) => m.findingId)).size;
  const fieldId = (m: { findingId: string; field: string }) => `wl-${m.findingId}-${m.field}`;
  const describe = (m: { findingId: string; field: string }) => `${m.field} for ${label(m.findingId)}`;

  const submit = () => {
    if (missing.length) {
      setGateShown(true);
      document.getElementById(fieldId(missing[0]))?.focus();
      say(stillNeededMessage(missing, rows));
      return;
    }
    const d = cur();
    if (!d.pins.length && !confirm('You have not pinned any evidence. Submit anyway?')) return;
    const submission = buildSubmission(d);
    const grade = gradeVulnCase(c, submission);
    update((p) => recordVulnAttempt(p, { c, grade, submission, now: Date.now(), day: today(), durationSec: Math.round((Date.now() - started.current) / 1000) }).profile);
    saveVulnDraft(key, null);
    saveVulnDone(key, template.id, grade.percent, submission);
    setDone({ grade, submission });
    const passed = grade.percent >= VULN_PASS_PERCENT;
    play(passed ? 'good' : 'bad');
    const { gate } = grade;
    const capSay =
      gate.cap === null ? '' : ` ${gate.uncapped > gate.cap ? `Capped at ${gate.cap}` : `A missed key finding caps the score at ${gate.cap}`}: ${gate.missed.length} key finding${gate.missed.length === 1 ? '' : 's'} missed.`;
    say(`Scored ${grade.percent} out of 100. ${passed ? 'Passed.' : `Below the pass mark of ${VULN_PASS_PERCENT}.`}${capSay}${grade.mustNotMiss.dismissed.length ? ' You dismissed a must-not-miss finding.' : ''}`);
    window.scrollTo({ top: 0 });
  };

  if (done) {
    const again = () => {
      commit(emptyDraft(bundle.ids));
      saveVulnDraft(key, null);
      clearVulnDone(key);
      setSortUndo(null);
      setGateShown(false);
      setMovedId(null);
      setDone(null);
      started.current = Date.now();
    };
    return (
      <div class="page">
        <VulnDebrief
          c={c}
          grade={done.grade}
          submission={done.submission}
          rows={rows}
          actions={
            <>
              <button
                type="button"
                class="btn btn-primary"
                onClick={() => {
                  const pool = TYPES.filter((t) => t.slug !== slug);
                  const t = pool.length ? pool[Math.floor(Math.random() * pool.length)] : type;
                  navigate({ name: 'vuln-case', slug: t.slug, seed: randomSeed() });
                }}
              >
                Next vulnerability case <Icon name="right" />
              </button>
              <button type="button" class="btn" onClick={again}>
                <Icon name="history" /> Work it again
              </button>
              <button type="button" class="btn btn-ghost" onClick={() => navigate({ name: 'vuln-case', slug, seed: randomSeed() })}>
                Same case type, new variation
              </button>
              <a class="btn btn-ghost" href="#/vuln">
                Back to the library
              </a>
            </>
          }
        />
      </div>
    );
  }

  return (
    <div class="vc">
      <header class="vc-bar">
        <a class="btn btn-ghost btn-sm" href="#/vuln">
          <Icon name="left" /> Library
        </a>
        <h1 class="vc-h1">{view.title}</h1>
        <span class="diff">{DIFF_LABEL[view.difficulty]}</span>
        <span class="badge badge-accent">vulnerability case</span>
        <span class="badge" data-simulated="true">
          Simulated data
        </span>
        {profile.value.settings.timerEnabled && <Timer since={started.current} />}
      </header>

      <aside class="vc-brief card" aria-labelledby="vc-brief-h">
        <VulnBrief
          view={view}
          hintsUsed={draft.hintsUsed}
          narrow={narrow}
          onRevealHint={revealHint}
          onLoadQuery={(q) => {
            setTab('console');
            consoleApi.current?.load(q);
          }}
        />
        <p class="small vc-help-link">
          <Icon name="book" /> <a href="#/help/vuln">Vulnerability terms (Help)</a>
          <span class="faint"> — your answers are kept in this tab if you leave (unless your browser blocks storage).</span>
        </p>
      </aside>

      <Worklist
        rows={rows}
        draft={draft}
        controls={controls}
        pinCounts={pinCounts}
        movedId={movedId}
        canUndoSort={sortUndo !== null}
        narrow={narrow}
        onAnswer={onAnswer}
        onReason={onReason}
        onSort={onSort}
        onUndoSort={onUndoSort}
        onMove={onMove}
      />

      <section class="vc-tools card" aria-label="Investigation tools">
        <Tabs
          tabs={[
            { id: 'console' as const, label: 'Console' },
            { id: 'note' as const, label: 'Note' },
          ]}
          value={tab}
          onChange={setTab}
          label="Investigation tools"
          idPrefix="vc"
        />
        <div role="tabpanel" id="vc-panel-console" aria-labelledby="vc-tab-console" hidden={tab !== 'console'}>
          <VulnConsole
            initial={loadVulnQuery(key) ?? VULN_STARTER}
            onText={(t) => saveVulnQuery(key, t)}
            rowsByTable={bundle.rowsByTable}
            pins={pinSet}
            onTogglePin={togglePin}
            say={say}
            api={consoleApi}
            nameKey="vc"
          />
        </div>
        <div role="tabpanel" id="vc-panel-note" aria-labelledby="vc-tab-note" hidden={tab !== 'note'}>
          <VulnNote notes={draft.notes} onChange={(notes) => commit({ ...cur(), notes })} />
        </div>
      </section>

      <section class="vc-submit card" aria-labelledby="vc-submit-h">
        <h2 id="vc-submit-h" class="section-label">
          Evidence and submit
        </h2>
        <p class="small" id="vc-progress">
          {ready} of {draft.order.length} findings ready.
        </p>
        <h3 class="section-label" id="vc-pins-h" tabIndex={-1}>
          Pinned evidence <span class="badge">{pinned.length}</span>
        </h3>
        {pinned.length === 0 ? (
          <p class="faint small">
            Pin the log rows that back your calls with <Icon name="pin" /> in the console results.
          </p>
        ) : (
          <ul class="pins">
            {pinned.map((p) => (
              <li class="pin-item" key={p.recordId}>
                <div class="pin-text">
                  <span class="mono small">
                    {p.table ? `${p.table} · ` : ''}
                    {p.time}
                  </span>
                  <span class="small break">{p.text}</span>
                </div>
                <button type="button" class="btn btn-ghost btn-icon btn-sm pin-unpin" aria-label={['Unpin', p.table, p.time, p.text].filter(Boolean).join(' ')} onClick={() => unpin(p.recordId)}>
                  <Icon name="x" />
                </button>
              </li>
            ))}
          </ul>
        )}
        {gateShown && missing.length > 0 && (
          <div class="vc-needed">
            <h3 class="section-label">Still needed</h3>
            <ul>
              {missing.map((m) => (
                <li>
                  <button type="button" class="btn btn-ghost btn-sm" onClick={() => document.getElementById(fieldId(m))?.focus()}>
                    {describe(m)}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        <button type="button" id="vc-submit-btn" class="btn btn-primary btn-lg submit-btn" aria-disabled={missing.length > 0 ? 'true' : undefined} onClick={submit}>
          Submit worklist
        </button>
      </section>
    </div>
  );
}
