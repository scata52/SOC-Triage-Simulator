// Time helpers. Inside core/ times are epoch milliseconds (UTC); they become
// ISO-8601 strings only when a corpus is finalised.

export const SEC = 1000;
export const MIN = 60 * SEC;
export const HOUR = 60 * MIN;
export const DAY = 24 * HOUR;

export function iso(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function isoDate(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

// Start of the UTC day containing ms.
export function utcDayStart(ms: number): number {
  return Math.floor(ms / DAY) * DAY;
}

// Local hour (fractional) at a UTC instant, for a fixed UTC offset in hours.
export function localHour(ms: number, utcOffset: number): number {
  const h = ((ms + utcOffset * HOUR) % DAY) / HOUR;
  return h < 0 ? h + 24 : h;
}

// UTC instant for a local wall-clock hour on the local day containing dayRef.
export function atLocalHour(dayRef: number, hour: number, utcOffset: number): number {
  const localMidnight = Math.floor((dayRef + utcOffset * HOUR) / DAY) * DAY;
  return localMidnight + hour * HOUR - utcOffset * HOUR;
}

// 0 = Sunday … 6 = Saturday, in local time.
export function localWeekday(ms: number, utcOffset: number): number {
  return new Date(ms + utcOffset * HOUR).getUTCDay();
}

export function isWeekend(ms: number, utcOffset: number): boolean {
  const d = localWeekday(ms, utcOffset);
  return d === 0 || d === 6;
}

export function fmtClock(ms: number): string {
  return iso(ms).slice(11, 19);
}

export function fmtDateTime(ms: number): string {
  return `${iso(ms).slice(0, 10)} ${iso(ms).slice(11, 19)} UTC`;
}
