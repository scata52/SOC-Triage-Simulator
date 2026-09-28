// Small helpers shared by templates.

import type { RubricItem } from '../../types.ts';
import type { IndicatorSpec } from '../model.ts';
import type { Person } from '../../world/world.ts';
import { iso } from '../../logs/time.ts';

export function rubric(items: [string, string, string[]][]): RubricItem[] {
  return items.map(([id, text, keywords]) => ({ id, text, keywords }));
}

// KQL datetime literal for a moment.
export function kdt(ms: number): string {
  return `datetime(${iso(ms)})`;
}

// "14:03 UTC"
export function hm(ms: number): string {
  return `${iso(ms).slice(11, 16)} UTC`;
}

export function user(p: Person): IndicatorSpec {
  return { kind: 'user', value: p.upn, aliases: [p.sam, p.display] };
}

export function host(name: string): IndicatorSpec {
  return { kind: 'host', value: name };
}

export function ip(value: string, note?: string): IndicatorSpec {
  return { kind: 'ip', value, note };
}

export function domain(value: string, note?: string): IndicatorSpec {
  return { kind: 'domain', value, note };
}

export function sha(value: string, note?: string): IndicatorSpec {
  return { kind: 'sha256', value, note };
}

export function km(n: number): string {
  return n.toLocaleString('en-US');
}

export function technique(id: string): { label: string; url: string } {
  return { label: `ATT&CK ${id}`, url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` };
}
