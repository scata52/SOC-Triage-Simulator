import { useRef, useState } from 'preact/hooks';
import { profile, update, replaceProfile, toast, world, loadSource } from '../store/app.ts';
import { Icon } from '../components/Icon.tsx';
import { Dialog, Notice } from '../components/ui.tsx';
import { BudgetPicker } from './Home.tsx';
import { defaultProfile, type MotionPref, type Settings as S, type ThemePref } from '../../state/profile.ts';
import { exportProfile, importProfile, newWorldSeed } from '../../state/storage.ts';
import { play } from '../lib/sound.ts';

function set<K extends keyof S>(k: K, v: S[K]): void {
  update((p) => ({ ...p, settings: { ...p.settings, [k]: v } }));
}

export function Settings() {
  const p = profile.value;
  const s = p.settings;
  const w = world.value;
  const [confirm, setConfirm] = useState<'reset' | 'world' | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const download = () => {
    const blob = new Blob([exportProfile(p)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `soc-triage-profile-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  const onImport = async (e: Event) => {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    const parsed = importProfile(await f.text(), { now: Date.now(), tzOffsetMinutes: new Date().getTimezoneOffset(), newWorldSeed });
    if (parsed) {
      replaceProfile(parsed);
      toast('Profile imported.');
    } else toast('That file is not a SOC Triage Simulator profile.');
    (e.target as HTMLInputElement).value = '';
  };

  return (
    <div class="page page-narrow">
      <div class="page-head">
        <div>
          <p class="eyebrow">Settings</p>
          <h1>Settings</h1>
        </div>
      </div>

      {loadSource === 'v1-migrated' && p.migratedFromV1 && (
        <Notice tone="ok">
          <p>
            Your progress from the previous version was carried over: {p.migratedFromV1.records} cases, your XP and your streaks. The old save is kept
            untouched in this browser as a backup.
          </p>
        </Notice>
      )}

      <section class="card settings-section" aria-labelledby="set-you">
        <h2 id="set-you">You</h2>
        <div class="field">
          <label for="set-name">Analyst name</label>
          <input id="set-name" class="input" value={p.analystName} maxLength={40} onChange={(e) => update((x) => ({ ...x, analystName: (e.target as HTMLInputElement).value.trim() || 'Analyst' }))} />
        </div>
      </section>

      <section class="card settings-section" aria-labelledby="set-look">
        <h2 id="set-look">Display</h2>
        <fieldset class="segmented" style={{ marginBottom: 'var(--space-4)' }}>
          <legend>Theme</legend>
          {(['system', 'dark', 'light'] as ThemePref[]).map((t) => (
            <label>
              <input type="radio" name="theme" checked={s.theme === t} onChange={() => set('theme', t)} />
              {t === 'system' ? 'Match system' : t === 'dark' ? 'Dark' : 'Light'}
            </label>
          ))}
        </fieldset>
        <fieldset class="segmented" style={{ marginBottom: 'var(--space-4)' }}>
          <legend>Motion</legend>
          {(['system', 'reduce', 'full'] as MotionPref[]).map((m) => (
            <label>
              <input type="radio" name="motion" checked={s.motion === m} onChange={() => set('motion', m)} />
              {m === 'system' ? 'Match system' : m === 'reduce' ? 'Reduce' : 'Full'}
            </label>
          ))}
        </fieldset>
        <div class="field">
          <label for="set-font">Query editor font size: {s.editorFontSize}px</label>
          <input id="set-font" type="range" min={12} max={20} step={1} value={s.editorFontSize} onInput={(e) => set('editorFontSize', Number((e.target as HTMLInputElement).value))} />
        </div>
      </section>

      <section class="card settings-section" aria-labelledby="set-sound">
        <h2 id="set-sound">Sound</h2>
        <label class="switch">
          <input type="checkbox" checked={s.sound} onChange={(e) => set('sound', (e.target as HTMLInputElement).checked)} />
          Play short sounds for alerts, pins and results
        </label>
        {s.sound && (
          <div class="field" style={{ marginTop: 'var(--space-3)' }}>
            <label for="set-vol">Volume</label>
            <div class="row">
              <input id="set-vol" type="range" min={0} max={1} step={0.05} value={s.volume} onInput={(e) => set('volume', Number((e.target as HTMLInputElement).value))} />
              <button type="button" class="btn btn-sm" onClick={() => play('good')}>
                <Icon name="sound" /> Test
              </button>
            </div>
          </div>
        )}
      </section>

      <section class="card settings-section" aria-labelledby="set-practice">
        <h2 id="set-practice">Practice</h2>
        <label class="switch">
          <input type="checkbox" checked={s.timerEnabled} onChange={(e) => set('timerEnabled', (e.target as HTMLInputElement).checked)} />
          Show a timer on practice cases
        </label>
        <br />
        <label class="switch" style={{ marginTop: 'var(--space-2)' }}>
          <input type="checkbox" checked={s.showRubricLive} onChange={(e) => set('showRubricLive', (e.target as HTMLInputElement).checked)} />
          Show the note checklist while writing (study aid)
        </label>
        <div style={{ marginTop: 'var(--space-4)' }}>
          <BudgetPicker value={s.defaultBudget} onChange={(b) => set('defaultBudget', b)} />
        </div>
      </section>

      <section class="card settings-section" aria-labelledby="set-data">
        <h2 id="set-data">Your data</h2>
        <p class="muted">Progress lives only in this browser. Export it to keep a copy or move it to another device.</p>
        <div class="btn-row">
          <button type="button" class="btn" onClick={download}>
            <Icon name="download" /> Export profile
          </button>
          <button type="button" class="btn" onClick={() => fileRef.current?.click()}>
            <Icon name="upload" /> Import profile
          </button>
          <input ref={fileRef} type="file" accept="application/json,.json" class="visually-hidden" tabIndex={-1} aria-hidden="true" onChange={onImport} />
        </div>
        <hr />
        <h3>Organisation</h3>
        <p class="muted">
          You work at <strong>{w.org.name}</strong> (world <code>{p.worldSeed}</code>). A new organisation means new people, hosts and network — and ends any
          running campaign. Your XP and history stay.
        </p>
        <div class="btn-row">
          <button type="button" class="btn" onClick={() => setConfirm('world')} disabled={!!p.activeShift}>
            <Icon name="globe" /> Move to a new organisation
          </button>
          <button type="button" class="btn btn-danger" onClick={() => setConfirm('reset')}>
            <Icon name="trash" /> Reset all progress
          </button>
        </div>
        {p.activeShift && <p class="faint small">Finish or abandon the current shift first.</p>}
      </section>

      <Dialog
        open={confirm !== null}
        title={confirm === 'reset' ? 'Reset all progress?' : 'Move to a new organisation?'}
        onClose={() => setConfirm(null)}
        footer={
          <>
            <button type="button" class="btn" onClick={() => setConfirm(null)}>
              Cancel
            </button>
            <button
              type="button"
              class={confirm === 'reset' ? 'btn btn-danger' : 'btn btn-primary'}
              onClick={() => {
                if (confirm === 'reset') {
                  replaceProfile({ ...defaultProfile(Date.now(), newWorldSeed()), settings: p.settings });
                  toast('Progress reset.');
                } else {
                  update((x) => ({ ...x, worldSeed: newWorldSeed(), campaign: null, activeShift: null }));
                  toast('Welcome to your new organisation.');
                }
                setConfirm(null);
              }}
            >
              {confirm === 'reset' ? 'Reset everything' : 'Move'}
            </button>
          </>
        }
      >
        {confirm === 'reset' ? (
          <p>This deletes your XP, history, study cards, shifts and campaign from this browser. Export first if you might want it back.</p>
        ) : (
          <p>You will start at a different fictional company. The current campaign ends; your XP, history and study cards are kept.</p>
        )}
      </Dialog>
    </div>
  );
}
