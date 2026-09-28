// Small shared components.

import type { ComponentChildren } from 'preact';
import { useEffect, useRef } from 'preact/hooks';
import type { Severity } from '../../core/types.ts';
import { SEVERITY_LABELS } from '../../core/grading/grade.ts';
import { announcement, toasts } from '../store/app.ts';
import { Icon, type IconName } from './Icon.tsx';

export function Sev({ s }: { s: Severity }) {
  return <span class={`sev sev-${s}`}>{SEVERITY_LABELS[s]}</span>;
}

export function Bar({ value, label, color }: { value: number; label: string; color?: string }) {
  const v = Math.max(0, Math.min(1, value));
  return (
    <div class="bar" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(v * 100)} style={color ? { '--bar-color': color } : undefined}>
      <span style={{ width: `${v * 100}%` }} />
    </div>
  );
}

export function Ring({ value, label, sub, size = 120, color }: { value: number; label: string; sub?: string; size?: number; color?: string }) {
  const r = 50 - 6;
  const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(1, value));
  return (
    <div class="ring" style={{ '--size': `${size}px`, '--ring-color': color }} role="img" aria-label={`${label}${sub ? ` ${sub}` : ''}`}>
      <svg viewBox="0 0 100 100" aria-hidden="true">
        <circle class="track" cx="50" cy="50" r={r} />
        <circle class="value" cx="50" cy="50" r={r} stroke-dasharray={c} stroke-dashoffset={c * (1 - v)} />
      </svg>
      <div class="ring-label" aria-hidden="true">
        <strong>{label}</strong>
        {sub && <span>{sub}</span>}
      </div>
    </div>
  );
}

export function Loading({ text = 'Loading…' }: { text?: string }) {
  return (
    <div class="loading" role="status">
      <div class="spinner" aria-hidden="true" />
      <span>{text}</span>
    </div>
  );
}

export function Empty({ icon = 'info', children }: { icon?: IconName; children: ComponentChildren }) {
  return (
    <div class="empty">
      <Icon name={icon} />
      <div>{children}</div>
    </div>
  );
}

export function Notice({ tone, icon, children }: { tone?: 'warn' | 'bad' | 'ok'; icon?: IconName; children: ComponentChildren }) {
  return (
    <div class={`notice${tone ? ` notice-${tone}` : ''}`} role={tone === 'bad' ? 'alert' : undefined}>
      <Icon name={icon ?? (tone === 'ok' ? 'check' : tone ? 'alert' : 'info')} />
      <div>{children}</div>
    </div>
  );
}

// Accessible tabs with roving focus (arrow keys, Home/End).
export function Tabs<T extends string>({ tabs, value, onChange, label, idPrefix }: { tabs: { id: T; label: ComponentChildren }[]; value: T; onChange: (id: T) => void; label: string; idPrefix: string }) {
  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.id === value);
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') n = 0;
    else if (e.key === 'End') n = tabs.length - 1;
    if (n < 0) return;
    e.preventDefault();
    onChange(tabs[n].id);
    document.getElementById(`${idPrefix}-tab-${tabs[n].id}`)?.focus();
  };
  return (
    <div class="tabs" role="tablist" aria-label={label} onKeyDown={onKey}>
      {tabs.map((t) => (
        <button
          type="button"
          role="tab"
          id={`${idPrefix}-tab-${t.id}`}
          aria-selected={t.id === value}
          aria-controls={`${idPrefix}-panel-${t.id}`}
          tabIndex={t.id === value ? 0 : -1}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function TabPanel({ idPrefix, id, active, children, class: cls }: { idPrefix: string; id: string; active: boolean; children: ComponentChildren; class?: string }) {
  return (
    <div role="tabpanel" id={`${idPrefix}-panel-${id}`} aria-labelledby={`${idPrefix}-tab-${id}`} hidden={!active} class={cls} tabIndex={0}>
      {active && children}
    </div>
  );
}

// Native <dialog>: focus trap, Esc and focus restore come from the platform.
export function Dialog({ open, title, onClose, children, footer, wide }: { open: boolean; title: string; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} class="dialog" style={wide ? { width: 'min(860px, calc(100vw - 24px))' } : undefined} aria-labelledby="dialog-title" onClose={onClose} onCancel={(e) => (e.preventDefault(), onClose())}>
      {open && (
        <>
          <div class="dialog-head">
            <h2 id="dialog-title">{title}</h2>
            <button type="button" class="btn btn-ghost btn-icon btn-sm" onClick={onClose} aria-label="Close dialog">
              <Icon name="x" />
            </button>
          </div>
          <div class="dialog-body">{children}</div>
          {footer && <div class="dialog-foot">{footer}</div>}
        </>
      )}
    </dialog>
  );
}

export function Toasts() {
  return (
    <>
      <div class="toast-region" aria-hidden="true">
        {toasts.value.map((t) => (
          <div class="toast" key={t.id}>
            {t.text}
          </div>
        ))}
      </div>
      <div class="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {announcement.value}
      </div>
      <div class="visually-hidden" role="log" aria-live="polite">
        {toasts.value.map((t) => (
          <p key={t.id}>{t.text}</p>
        ))}
      </div>
    </>
  );
}
