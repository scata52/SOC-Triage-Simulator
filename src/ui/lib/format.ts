// Display formatting. Log times are shown in UTC, as a SIEM would.

export function utcTime(isoText: string): string {
  return isoText.slice(11, 19);
}

export function utcDateTime(isoText: string): string {
  return `${isoText.slice(0, 10)} ${isoText.slice(11, 19)}Z`;
}

export function clock(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

export function duration(sec: number | null): string {
  if (sec === null) return '—';
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${Math.round(sec % 60)}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function num(n: number): string {
  return n.toLocaleString('en-US');
}

export function pct(n: number): string {
  return `${Math.round(n)}%`;
}

export function ago(ms: number, now = Date.now()): string {
  const s = Math.round((now - ms) / 1000);
  if (s < 60) return 'just now';
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return d === 1 ? 'yesterday' : `${d} days ago`;
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

// "daily-2026-09-28": same for everyone, by local calendar date.
export function dailySeed(d = new Date()): string {
  return `daily-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

export function randomSeed(): string {
  const b = new Uint8Array(5);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(36).padStart(2, '0')).join('').slice(0, 8);
}
