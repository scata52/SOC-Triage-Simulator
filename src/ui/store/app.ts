// App-wide state: the persisted profile, derived world, settings applied to
// the document, and a toast queue. Components read signals directly.

import { computed, effect, signal } from '@preact/signals';
import { generateWorld } from '../../core/world/world.ts';
import { WorldIndex } from '../../core/world/index.ts';
import { dayNumber, type Profile } from '../../state/profile.ts';
import { browserStorage, loadProfile, newWorldSeed, saveProfile, type LoadSource } from '../../state/storage.ts';

const kv = browserStorage();
const loaded = loadProfile(kv, { now: Date.now(), tzOffsetMinutes: new Date().getTimezoneOffset(), newWorldSeed });

export const profile = signal<Profile>(loaded.profile);
export const loadSource: LoadSource = loaded.source;
export const persistent = kv !== null;
export const saveFailed = signal(false);

let saveTimer: ReturnType<typeof setTimeout> | null = null;
function flush(): void {
  saveTimer = null;
  const ok = saveProfile(kv, profile.peek());
  if (persistent) saveFailed.value = !ok;
}
effect(() => {
  void profile.value;
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(flush, 300);
});
if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => {
    if (saveTimer) {
      clearTimeout(saveTimer);
      flush();
    }
  });
}

export function update(fn: (p: Profile) => Profile): void {
  profile.value = fn(profile.value);
}

export function replaceProfile(p: Profile): void {
  profile.value = p;
}

const worldSeed = computed(() => profile.value.worldSeed);
export const world = computed(() => generateWorld(worldSeed.value));
export const worldIndex = computed(() => new WorldIndex(world.value));

export function today(): number {
  return dayNumber(Date.now(), new Date().getTimezoneOffset());
}

// Theme and motion preferences on <html>.
const settings = computed(() => profile.value.settings);
effect(() => {
  const s = settings.value;
  const root = document.documentElement;
  if (s.theme === 'system') delete root.dataset.theme;
  else root.dataset.theme = s.theme;
  if (s.motion === 'system') delete root.dataset.motion;
  else root.dataset.motion = s.motion;
  root.style.setProperty('--editor-font-size', `${s.editorFontSize}px`);
});

export const reducedMotion = computed(() => {
  const m = settings.value.motion;
  if (m !== 'system') return m === 'reduce';
  return typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;
});

// ---------------------------------------------------------------- toasts
export interface Toast {
  id: number;
  text: string;
}
export const toasts = signal<Toast[]>([]);
let toastSeq = 0;
export function toast(text: string, ms = 4000): void {
  const id = ++toastSeq;
  toasts.value = [...toasts.value, { id, text }];
  setTimeout(() => (toasts.value = toasts.value.filter((t) => t.id !== id)), ms);
}

// Polite announcements for screen readers (separate from visual toasts).
export const announcement = signal('');
export function announce(text: string): void {
  announcement.value = '';
  queueMicrotask(() => (announcement.value = text));
}
