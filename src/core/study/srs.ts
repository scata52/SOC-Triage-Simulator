// SM-2 spaced repetition, one card per case template. "Days" are integer day
// numbers supplied by the caller (core never reads the clock).

export interface Card {
  templateId: string;
  ef: number; // easiness factor, >= 1.3
  interval: number; // days until the next review
  reps: number; // consecutive successful reviews
  lapses: number;
  due: number; // day number
  last: number; // day number of the last review
  lastPercent: number;
}

export const MIN_EF = 1.3;

// Grade → SM-2 quality (0–5). 70% is the pass mark: below it the card lapses.
export function quality(percent: number): number {
  if (percent >= 95) return 5;
  if (percent >= 85) return 4;
  if (percent >= 70) return 3;
  if (percent >= 50) return 2;
  if (percent >= 30) return 1;
  return 0;
}

export function review(card: Card | undefined, templateId: string, percent: number, today: number): Card {
  const c: Card = card ? { ...card } : { templateId, ef: 2.5, interval: 0, reps: 0, lapses: 0, due: today, last: today, lastPercent: 0 };
  const q = quality(percent);
  // A pass before the card is due ("work it again", an early pick) is just
  // practice: it must not stretch the interval, or three quick repeats would
  // schedule the next review weeks out. A fail always counts as a lapse.
  if (card && today < card.due && q >= 3) {
    c.last = today;
    c.lastPercent = percent;
    return c;
  }
  if (q >= 3) {
    c.interval = c.reps === 0 ? 1 : c.reps === 1 ? 6 : Math.max(1, Math.round(c.interval * c.ef));
    c.reps += 1;
  } else {
    if (card) c.lapses += 1;
    c.reps = 0;
    c.interval = 1;
  }
  c.ef = Math.max(MIN_EF, Math.round((c.ef + 0.1 - (5 - q) * (0.08 + (5 - q) * 0.02)) * 1000) / 1000);
  c.due = today + c.interval;
  c.last = today;
  c.lastPercent = percent;
  return c;
}

export function isDue(card: Card, today: number): boolean {
  return card.due <= today;
}
