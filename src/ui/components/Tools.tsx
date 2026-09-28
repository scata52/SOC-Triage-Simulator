// Investigation side tools: schema browser, decoder, query history.

import { useState } from 'preact/hooks';
import { TABLES, type TableName } from '../../core/logs/schema.ts';
import { base32ToBytes, decodeUtf8, defang, entropy, refang, smartBase64Decode } from '../../core/synth/encoding.ts';
import { Icon } from './Icon.tsx';
import { num } from '../lib/format.ts';

export function SchemaBrowser({ rowsByTable, onPreview, onInsert }: { rowsByTable: Record<TableName, number>; onPreview: (table: string) => void; onInsert: (text: string) => void }) {
  const [filter, setFilter] = useState('');
  const f = filter.trim().toLowerCase();
  const groups: { title: string; kind: 'log' | 'context' }[] = [
    { title: 'Log tables', kind: 'log' },
    { title: 'Context tables', kind: 'context' },
  ];
  return (
    <div class="schema">
      <div class="field" style={{ marginBottom: 'var(--space-3)' }}>
        <label for="schema-q" class="visually-hidden">
          Filter tables and columns
        </label>
        <input id="schema-q" class="input" type="search" placeholder="Filter tables and columns…" value={filter} onInput={(e) => setFilter((e.target as HTMLInputElement).value)} />
      </div>
      {groups.map((g) => (
        <section aria-label={g.title}>
          <h4 class="schema-group">{g.title}</h4>
          {TABLES.filter((t) => t.kind === g.kind)
            .filter((t) => !f || t.name.toLowerCase().includes(f) || t.columns.some((c) => c.name.toLowerCase().includes(f)))
            .map((t) => (
              <details class="disclosure schema-table" open={!!f}>
                <summary>
                  <span class="mono">{t.name}</span>
                  <span class="faint small mono">{num(rowsByTable[t.name] ?? 0)}</span>
                </summary>
                <div class="disclosure-body">
                  <p class="faint small">{t.doc}</p>
                  <div class="btn-row" style={{ marginBottom: 'var(--space-2)' }}>
                    <button type="button" class="btn btn-sm" onClick={() => onPreview(t.name)}>
                      <Icon name="play" /> Preview rows
                    </button>
                    <button type="button" class="btn btn-sm btn-ghost" onClick={() => onInsert(t.name)}>
                      Insert name
                    </button>
                  </div>
                  <ul class="schema-cols">
                    {t.columns
                      .filter((c) => !f || t.name.toLowerCase().includes(f) || c.name.toLowerCase().includes(f))
                      .map((c) => (
                        <li>
                          <button type="button" class="link-btn mono" onClick={() => onInsert(c.name)} aria-label={`Insert column ${c.name}`}>
                            {c.name}
                          </button>
                          <span class="faint small mono"> {c.type}</span>
                          <div class="faint small">{c.doc}</div>
                        </li>
                      ))}
                  </ul>
                </div>
              </details>
            ))}
        </section>
      ))}
    </div>
  );
}

type Mode = 'base64' | 'base32' | 'url' | 'refang' | 'defang';

function hex(bytes: Uint8Array): string {
  return [...bytes.slice(0, 96)].map((b) => b.toString(16).padStart(2, '0')).join(' ') + (bytes.length > 96 ? ' …' : '');
}

function printable(s: string): number {
  if (!s) return 0;
  let ok = 0;
  for (const ch of s) if (/[\x20-\x7e\t\r\n]/.test(ch)) ok++;
  return ok / s.length;
}

export function decode(input: string, mode: Mode): { out: string; note: string } {
  const v = input.trim();
  if (!v) return { out: '', note: '' };
  try {
    if (mode === 'base64') {
      const r = smartBase64Decode(v.replace(/\s+/g, ''));
      if (!r) return { out: '', note: 'Not valid Base64.' };
      return { out: r.text, note: `Decoded as ${r.encoding === 'utf-16le' ? 'UTF-16LE (what PowerShell -EncodedCommand uses)' : 'UTF-8'}.` };
    }
    if (mode === 'base32') {
      const label = v.split('.')[0];
      const bytes = base32ToBytes(label);
      if (!bytes) return { out: '', note: 'Not valid Base32 (a–z, 2–7). For a DNS name, paste the long label.' };
      const text = decodeUtf8(bytes);
      return printable(text) > 0.9 ? { out: text, note: 'Decoded Base32 as text.' } : { out: hex(bytes), note: `Binary data (${bytes.length} bytes, shown as hex) — typical of encrypted or compressed tunnel traffic.` };
    }
    if (mode === 'url') return { out: decodeURIComponent(v.replace(/\+/g, ' ')), note: 'URL-decoded.' };
    if (mode === 'refang') return { out: refang(v), note: 'Refanged — careful, this is clickable now.' };
    return { out: defang(v), note: 'Defanged — safe to paste into tickets and chat.' };
  } catch (e) {
    return { out: '', note: (e as Error).message };
  }
}

export function Decoder() {
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<Mode>('base64');
  const r = decode(input, mode);
  const h = input.trim() ? entropy(input.trim().split('.')[0]) : 0;
  return (
    <div class="decoder">
      <div class="field">
        <label for="dec-in">Input</label>
        <textarea id="dec-in" class="textarea mono" rows={4} value={input} onInput={(e) => setInput((e.target as HTMLTextAreaElement).value)} placeholder="Paste an encoded command, a DNS label, a URL…" />
      </div>
      <fieldset class="segmented" style={{ marginBottom: 'var(--space-3)' }}>
        <legend>Transform</legend>
        {(
          [
            ['base64', 'Base64'],
            ['base32', 'Base32'],
            ['url', 'URL decode'],
            ['refang', 'Refang'],
            ['defang', 'Defang'],
          ] as [Mode, string][]
        ).map(([m, l]) => (
          <label>
            <input type="radio" name="dec-mode" checked={mode === m} onChange={() => setMode(m)} />
            {l}
          </label>
        ))}
      </fieldset>
      {input.trim() && (
        <p class="faint small">
          Entropy of the first label: <span class="mono">{h.toFixed(2)}</span> bits/char {h >= 4.2 ? '— random-looking (encoded or generated)' : h >= 3.5 ? '— mixed' : '— word-like'}
        </p>
      )}
      <div class="field">
        <span class="field-label" id="dec-out-l">
          Output
        </span>
        <pre class="decoder-out mono" aria-labelledby="dec-out-l" aria-live="polite">
          {r.out || <span class="faint">—</span>}
        </pre>
        {r.note && <span class="field-hint">{r.note}</span>}
      </div>
    </div>
  );
}

export function QueryHistory({ items, onLoad }: { items: string[]; onLoad: (q: string) => void }) {
  if (!items.length) return <p class="muted">Queries you run appear here.</p>;
  return (
    <ul class="qhistory">
      {items.map((q) => (
        <li>
          <button type="button" class="qhistory-item mono" onClick={() => onLoad(q)} title="Load into the editor">
            {q.length > 220 ? `${q.slice(0, 220)}…` : q}
          </button>
        </li>
      ))}
    </ul>
  );
}
