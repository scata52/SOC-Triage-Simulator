// ATT&CK technique picker: an ARIA 1.2 combobox over the catalogue, with the
// chosen techniques as removable chips.

import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { announce } from '../store/app.ts';
import { MITRE_TECHNIQUES, TACTIC_LABELS, technique } from '../../core/taxonomy/mitre.ts';
import { Icon } from './Icon.tsx';

export function TechniquePicker({ value, onChange, idPrefix }: { value: string[]; onChange: (v: string[]) => void; idPrefix: string }) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const listId = `${idPrefix}-tech-list`;
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const matches = useMemo(() => {
    const s = q.trim().toLowerCase();
    const pool = MITRE_TECHNIQUES.filter((t) => !value.includes(t.id));
    if (!s) return pool.slice(0, 40);
    const scored = pool
      .map((t) => {
        const id = t.id.toLowerCase();
        const name = t.name.toLowerCase();
        const score = id === s ? 0 : id.startsWith(s) ? 1 : name.startsWith(s) ? 2 : name.includes(s) ? 3 : t.tactics.some((x) => TACTIC_LABELS[x].toLowerCase().includes(s)) ? 4 : 9;
        return { t, score };
      })
      .filter((x) => x.score < 9)
      .sort((a, b) => a.score - b.score || (a.t.id < b.t.id ? -1 : 1));
    return scored.slice(0, 40).map((x) => x.t);
  }, [q, value]);

  // Keep the highlighted option in view as the arrow keys move it.
  useEffect(() => {
    if (open) list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [active, open]);

  const remove = (id: string) => {
    onChange(value.filter((x) => x !== id));
    announce(`Removed ${id} ${technique(id)?.name ?? ''}.`);
  };

  const choose = (id: string) => {
    if (!value.includes(id)) onChange([...value, id]);
    setQ('');
    setActive(0);
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setOpen(true);
      setActive((a) => Math.min(matches.length - 1, a + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(0, a - 1));
    } else if (e.key === 'Enter') {
      if (open && matches[active]) {
        e.preventDefault();
        choose(matches[active].id);
      }
    } else if (e.key === 'Escape') {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
      }
    } else if (e.key === 'Backspace' && !q && value.length) {
      remove(value[value.length - 1]);
    }
  };

  return (
    <div class="techpicker">
      {value.length > 0 && (
        <ul class="tech-chips" aria-label="Selected techniques">
          {value.map((id) => (
            <li class="chip chip-mono">
              <span>
                {id} <span class="faint">{technique(id)?.name ?? ''}</span>
              </span>
              <button
                type="button"
                class="chip-x"
                aria-label={`Remove ${id} ${technique(id)?.name ?? ''}`}
                onClick={() => {
                  remove(id);
                  input.current?.focus();
                }}
              >
                <Icon name="x" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div class="combo">
        <input
          ref={input}
          id={`${idPrefix}-tech`}
          class="input"
          role="combobox"
          aria-expanded={open && matches.length > 0}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={open && matches[active] ? `${idPrefix}-opt-${matches[active].id}` : undefined}
          placeholder="Search by ID, name or tactic…"
          value={q}
          autocomplete="off"
          onInput={(e) => {
            setQ((e.target as HTMLInputElement).value);
            setOpen(true);
            setActive(0);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          onKeyDown={onKey}
        />
        {open && matches.length > 0 && (
          <ul id={listId} ref={list} role="listbox" class="combo-list" aria-label="ATT&CK techniques">
            {matches.map((t, i) => (
              <li
                id={`${idPrefix}-opt-${t.id}`}
                role="option"
                aria-selected={i === active}
                class={i === active ? 'is-active' : undefined}
                onMouseDown={(e) => (e.preventDefault(), choose(t.id))}
                onMouseEnter={() => setActive(i)}
              >
                <span class="mono">{t.id}</span> {t.name}
                <span class="faint small"> · {t.tactics.map((x) => TACTIC_LABELS[x]).join(', ')}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
