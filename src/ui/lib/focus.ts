// Focus management for content that appears after a load or a view change.
// Moves focus to the page heading only when focus has nowhere better to be
// (the document body or <main>) — never steals it from where the user is.

export function focusHeading(): void {
  requestAnimationFrame(() => {
    const a = document.activeElement;
    if (a && a !== document.body && a.tagName !== 'MAIN') return;
    const h = document.querySelector<HTMLElement>('main h1');
    if (!h) return;
    if (!h.hasAttribute('tabindex')) h.setAttribute('tabindex', '-1');
    h.focus({ preventScroll: true });
  });
}

// Focus an element once it exists (after a re-render).
export function focusWhenReady(selector: string): void {
  requestAnimationFrame(() => document.querySelector<HTMLElement>(selector)?.focus());
}

let seq = 0;
export function uniqueId(prefix: string): string {
  return `${prefix}-${++seq}`;
}
