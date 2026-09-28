// Indicator normalisation and matching. Analysts write indicators many ways —
// defanged, as URLs instead of domains, DOMAIN\user instead of a UPN, FQDNs
// instead of host names — and all of those should count.

import type { IndicatorKind, IndicatorSpec } from '../cases/model.ts';
import { refang } from '../synth/encoding.ts';
import { GENERIC_TLDS, registeredDomain, SUSPICIOUS_TLDS } from '../synth/domains.ts';

export interface GivenIndicator {
  kind: IndicatorKind;
  value: string;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const SHA256 = /^[a-f0-9]{64}$/i;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const TLDS = new Set<string>([...GENERIC_TLDS, ...SUSPICIOUS_TLDS, 'co', 'info', 'biz', 'dev', 'me', 'us', 'uk', 'de', 'eu', 'fr', 'nl', 'ru', 'cn', 'local', 'test', 'example', 'invalid']);

export function normalise(value: string): string {
  return refang(value.trim()).replace(/^["'<]+|["'>]+$/g, '').replace(/\.$/, '').toLowerCase();
}

// Best-effort type detection for free-typed indicators.
export function detectKind(raw: string): IndicatorKind {
  const v = normalise(raw);
  if (IPV4.test(v) || v.startsWith('2001:db8:')) return 'ip';
  if (SHA256.test(v)) return 'sha256';
  if (/^[a-z]+:\/\//.test(v)) return 'url';
  if (EMAIL.test(v)) return 'email';
  if (/\\/.test(v) && !v.includes('.')) return 'user';
  if (/\.(exe|dll|ps1|bat|iso|lnk|html|js|vbs|7z|zip|docm)$/.test(v)) return 'file';
  // first.last looks like a domain; only call it one if it ends in a TLD.
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v) && TLDS.has(v.split('.').pop()!)) return 'domain';
  if (/^[a-z]{2,4}-[a-z]{2,4}-\d{2,4}$|^(dc|fs|srv|sql|app|web|scan|jump|bkp|build|sccm|print|adconnect)\d*/.test(v)) return 'host';
  return 'user';
}

function hostOf(url: string): string {
  const m = /^[a-z]+:\/\/([^/:?#]+)/.exec(url);
  return m ? m[1] : url;
}

function userForms(v: string): string[] {
  const out = new Set([v]);
  const noDomain = v.includes('\\') ? v.split('\\').pop()! : v;
  out.add(noDomain);
  if (noDomain.includes('@')) out.add(noDomain.split('@')[0]);
  return [...out];
}

function hostForms(v: string): string[] {
  const out = new Set([v]);
  out.add(v.split('.')[0]);
  return [...out];
}

// Does a given indicator match a specified one?
export function matches(given: GivenIndicator, spec: IndicatorSpec): boolean {
  const g = normalise(given.value);
  const values = [spec.value, ...(spec.aliases ?? [])].map(normalise);
  switch (spec.kind) {
    case 'ip': {
      const host = /^[a-z]+:\/\//.test(g) ? hostOf(g) : g;
      const bare = /^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(host) ? host.split(':')[0] : host;
      return values.includes(g) || values.includes(bare);
    }
    case 'sha256':
    case 'email':
    case 'file':
      return values.includes(g) || values.includes(g.split(/[\\/]/).pop() ?? g);
    case 'domain': {
      const candidate = /^[a-z]+:\/\//.test(g) ? hostOf(g) : g.includes('@') ? g.split('@')[1] : g;
      return values.some((v) => candidate === v || candidate.endsWith(`.${v}`) || registeredDomain(candidate) === registeredDomain(v) && registeredDomain(v) === v);
    }
    case 'url': {
      return values.some((v) => g === v || hostOf(g) === hostOf(v));
    }
    case 'user': {
      const gf = userForms(g);
      return values.some((v) => userForms(v).some((f) => gf.includes(f)));
    }
    case 'host': {
      const gf = hostForms(g);
      return values.some((v) => hostForms(v).some((f) => gf.includes(f)));
    }
  }
}

export function findMatch(given: GivenIndicator, specs: IndicatorSpec[]): IndicatorSpec | undefined {
  return specs.find((s) => matches(given, s));
}

// Like findMatch, but when several specs match (an email address matches both
// the address and its domain) prefer the one written exactly as given, then
// one not already claimed by an earlier indicator.
export function bestMatch(given: GivenIndicator, specs: IndicatorSpec[], taken: ReadonlySet<IndicatorSpec>): IndicatorSpec | undefined {
  const candidates = specs.filter((s) => matches(given, s));
  const g = normalise(given.value);
  return (
    candidates.find((s) => [s.value, ...(s.aliases ?? [])].some((v) => normalise(v) === g)) ??
    candidates.find((s) => !taken.has(s)) ??
    candidates[0]
  );
}
