// Synthesised UI sounds (no audio files). Off unless enabled in settings.

import { profile } from '../store/app.ts';

type Cue = 'submit' | 'good' | 'bad' | 'alert' | 'tick' | 'pin';

const CUES: Record<Cue, { f: number[]; d: number; type: OscillatorType }> = {
  submit: { f: [520, 660], d: 0.07, type: 'sine' },
  good: { f: [523, 659, 784], d: 0.09, type: 'triangle' },
  bad: { f: [330, 262], d: 0.14, type: 'sine' },
  alert: { f: [880, 660, 880], d: 0.08, type: 'square' },
  tick: { f: [1200], d: 0.03, type: 'sine' },
  pin: { f: [740], d: 0.04, type: 'triangle' },
};

let ctx: AudioContext | null = null;

export function play(cue: Cue): void {
  const s = profile.peek().settings;
  if (!s.sound || s.volume <= 0) return;
  try {
    ctx ??= new AudioContext();
    const c = CUES[cue];
    let t = ctx.currentTime;
    for (const f of c.f) {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = c.type;
      osc.frequency.value = f;
      gain.gain.setValueAtTime(0, t);
      gain.gain.linearRampToValueAtTime(0.12 * s.volume, t + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + c.d);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + c.d + 0.02);
      t += c.d * 0.9;
    }
  } catch {
    /* audio unavailable */
  }
}
