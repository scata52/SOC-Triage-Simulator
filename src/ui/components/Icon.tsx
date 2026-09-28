// A small stroke icon set, drawn for this app. Decorative by default
// (aria-hidden); pass `label` when an icon carries meaning on its own.

const PATHS = {
  shield: 'M12 3l8 3.5V12c0 4.4-3.4 7.6-8 9-4.6-1.4-8-4.6-8-9V6.5L12 3z M8.5 12.2l2.4 2.4 4.6-4.8',
  play: 'M8 5.5v13l10.5-6.5z',
  pin: 'M12 16.5V21 M8.5 3.5h7l-1 5.5 3 3H6.5l3-3z',
  pinned: 'M12 16.5V21 M8.5 3.5h7l-1 5.5 3 3H6.5l3-3z',
  search: 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13z M15.5 15.5L20 20',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 7.5V12l3 2',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  x: 'M6.5 6.5l11 11 M17.5 6.5l-11 11',
  alert: 'M12 3.5l9 16H3z M12 10v4 M12 17v.3',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 11v5 M12 8v.3',
  book: 'M5 4.5h10.5A3.5 3.5 0 0 1 19 8v12H8.5A3.5 3.5 0 0 1 5 16.5z M5 16.5A3.5 3.5 0 0 1 8.5 13H19',
  chart: 'M4 20h16 M7 16v-4 M12 16V7 M17 16v-7',
  sliders: 'M4 7h9 M17 7h3 M4 17h3 M11 17h9 M15 9a2 2 0 1 0 0-4 2 2 0 0 0 0 4z M9 19a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  terminal: 'M4 5h16v14H4z M8 10l3 2-3 2 M13 15h3',
  target: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9z M12 12.5v-1',
  copy: 'M9 9h10v11H9z M5 15V4h10',
  filter: 'M4 5h16l-6 7.5V18l-4 2v-7.5z',
  plus: 'M12 5v14 M5 12h14',
  minus: 'M5 12h14',
  trash: 'M5 7h14 M10 11v6 M14 11v6 M6.5 7l1 13h9l1-13 M9 7V4h6v3',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  menu: 'M4 7h16 M4 12h16 M4 17h16',
  right: 'M9.5 6l6 6-6 6',
  left: 'M14.5 6l-6 6 6 6',
  down: 'M6 9.5l6 6 6-6',
  flag: 'M5.5 21V4 M5.5 4.5h11l-2.5 4 2.5 4h-11',
  queue: 'M9 6.5h11 M9 12h11 M9 17.5h11 M4.5 6.5h.5 M4.5 12h.5 M4.5 17.5h.5',
  bolt: 'M13 3L5 13.5h6L10 21l8-10.5h-6z',
  globe: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z M3 12h18 M12 3c2.4 2.6 3.5 5.6 3.5 9s-1.1 6.4-3.5 9c-2.4-2.6-3.5-5.6-3.5-9S9.6 5.6 12 3z',
  cap: 'M2.5 9.5L12 5l9.5 4.5L12 14z M6.5 11.5v4.5c3 2 8 2 11 0v-4.5 M21.5 9.5v5',
  bulb: 'M9.5 18h5 M10.5 21h3 M12 3.5a5.5 5.5 0 0 0-3.6 9.7c.7.6 1.1 1.5 1.1 2.3v.5h5v-.5c0-.8.4-1.7 1.1-2.3A5.5 5.5 0 0 0 12 3.5z',
  code: 'M8 8l-4 4 4 4 M16 8l4 4-4 4 M14 5l-4 14',
  download: 'M12 4v11 M7 10.5l5 5 5-5 M5 20h14',
  upload: 'M12 16V5 M7 9.5l5-5 5 5 M5 20h14',
  sound: 'M4 9.5v5h4l5 4v-13l-5 4z M16.5 9a4.5 4.5 0 0 1 0 6',
  external: 'M14 4h6v6 M20 4l-8.5 8.5 M18 14v6H4V6h6',
  history: 'M4.5 12a7.5 7.5 0 1 0 2.2-5.3 M4.5 4.5v4h4 M12 8v4.5l3 1.5',
  hand: 'M8 13V6.5a1.5 1.5 0 0 1 3 0V12 M11 11.5V5a1.5 1.5 0 0 1 3 0v6.5 M14 11V6.5a1.5 1.5 0 0 1 3 0V14c0 4-2.5 7-6.5 7-2.5 0-4-1-5.5-3l-2.2-3.4a1.5 1.5 0 0 1 2.4-1.7L8 13.5',
  keyboard: 'M3 6.5h18v11H3z M6.5 10h.5 M10 10h.5 M13.5 10h.5 M17 10h.5 M7 14h10',
  db: 'M12 8c4.1 0 7.5-1.3 7.5-3S16.1 2 12 2 4.5 3.3 4.5 5 7.9 8 12 8z M4.5 5v14c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V5 M4.5 12c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3',
  spark: 'M12 3v4 M12 17v4 M3 12h4 M17 12h4 M5.6 5.6l2.8 2.8 M15.6 15.6l2.8 2.8 M5.6 18.4l2.8-2.8 M15.6 8.4l2.8-2.8',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, label, class: cls }: { name: IconName; label?: string; class?: string }) {
  const filled = name === 'play' || name === 'pinned';
  return (
    <svg
      class={`icon${cls ? ` ${cls}` : ''}`}
      viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      stroke={filled && name === 'play' ? 'none' : 'currentColor'}
      stroke-width="1.8"
      stroke-linecap="round"
      stroke-linejoin="round"
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : 'true'}
      focusable="false"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
