// CVSS v3.1 calculator: vector parsing and validation, base, temporal and
// environmental scores. Formulas are those of the FIRST CVSS v3.1
// specification, section 7; Roundup is the integer method of its Appendix A,
// which avoids floating-point artefacts such as 4.000000000000001 rounding to
// 4.1. Pure functions, no randomness, no clock.

export type CvssSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';
export const CVSS_SEVERITIES: readonly CvssSeverity[] = ['none', 'low', 'medium', 'high', 'critical'];

export const CVSS_PREFIX = 'CVSS:3.1';

// Metric groups, in the canonical order of a vector string.
export const BASE_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;
export const TEMPORAL_METRICS = ['E', 'RL', 'RC'] as const;
export const ENVIRONMENTAL_METRICS = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'] as const;

export type BaseMetric = (typeof BASE_METRICS)[number];
export type TemporalMetric = (typeof TEMPORAL_METRICS)[number];
export type EnvironmentalMetric = (typeof ENVIRONMENTAL_METRICS)[number];
export type CvssMetric = BaseMetric | TemporalMetric | EnvironmentalMetric;

const VALUES: Record<CvssMetric, string> = {
  AV: 'NALP',
  AC: 'LH',
  PR: 'NLH',
  UI: 'NR',
  S: 'UC',
  C: 'HLN',
  I: 'HLN',
  A: 'HLN',
  E: 'XUPFH',
  RL: 'XOTWU',
  RC: 'XURC',
  CR: 'XLMH',
  IR: 'XLMH',
  AR: 'XLMH',
  MAV: 'XNALP',
  MAC: 'XLH',
  MPR: 'XNLH',
  MUI: 'XNR',
  MS: 'XUC',
  MC: 'XHLN',
  MI: 'XHLN',
  MA: 'XHLN',
};

// A parsed vector: every base metric is present; temporal and environmental
// metrics that were omitted are absent (equivalent to "X", not defined).
export type CvssMetrics = Record<BaseMetric, string> & Partial<Record<TemporalMetric | EnvironmentalMetric, string>>;

export type CvssParseResult = { ok: true; metrics: CvssMetrics } | { ok: false; error: string };

const ALL_METRICS: readonly CvssMetric[] = [...BASE_METRICS, ...TEMPORAL_METRICS, ...ENVIRONMENTAL_METRICS];

export function parseVector(vector: string): CvssParseResult {
  const parts = vector.split('/');
  if (parts[0] !== CVSS_PREFIX) return { ok: false, error: `vector must start with "${CVSS_PREFIX}"` };
  const found = new Map<string, string>();
  for (const part of parts.slice(1)) {
    const colon = part.indexOf(':');
    if (colon <= 0) return { ok: false, error: `malformed metric "${part}"` };
    const key = part.slice(0, colon);
    const value = part.slice(colon + 1);
    if (!(ALL_METRICS as readonly string[]).includes(key)) return { ok: false, error: `unknown metric "${key}"` };
    if (found.has(key)) return { ok: false, error: `duplicate metric "${key}"` };
    const allowed = VALUES[key as CvssMetric];
    if (value.length !== 1 || !allowed.includes(value)) return { ok: false, error: `invalid value "${value}" for metric "${key}"` };
    found.set(key, value);
  }
  for (const key of BASE_METRICS) if (!found.has(key)) return { ok: false, error: `missing base metric "${key}"` };
  return { ok: true, metrics: Object.fromEntries(found) as CvssMetrics };
}

export function isValidVector(vector: string): boolean {
  return parseVector(vector).ok;
}

// The vector string with metrics in canonical order and "X" values dropped.
export function canonicalVector(metrics: CvssMetrics): string {
  const parts: string[] = [CVSS_PREFIX];
  for (const key of ALL_METRICS) {
    const value = metrics[key as keyof CvssMetrics];
    if (value === undefined) continue;
    if (value === 'X' && !(BASE_METRICS as readonly string[]).includes(key)) continue;
    parts.push(`${key}:${value}`);
  }
  return parts.join('/');
}

// Spec Appendix A. Smallest one-decimal number >= input, computed on integers.
export function roundUp1(input: number): number {
  const i = Math.round(input * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

// Spec Table 14.
export function severityOf(score: number): CvssSeverity {
  if (score <= 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const REQUIREMENT: Record<string, number> = { X: 1, L: 0.5, M: 1, H: 1.5 };
const EXPLOIT_MATURITY: Record<string, number> = { X: 1, U: 0.91, P: 0.94, F: 0.97, H: 1 };
const REMEDIATION_LEVEL: Record<string, number> = { X: 1, O: 0.95, T: 0.96, W: 0.97, U: 1 };
const REPORT_CONFIDENCE: Record<string, number> = { X: 1, U: 0.92, R: 0.96, C: 1 };

function privilegesRequired(pr: string, scopeChanged: boolean): number {
  if (pr === 'N') return 0.85;
  if (pr === 'L') return scopeChanged ? 0.68 : 0.62;
  return scopeChanged ? 0.5 : 0.27;
}

function toMetrics(v: string | CvssMetrics): CvssMetrics {
  if (typeof v !== 'string') return v;
  const parsed = parseVector(v);
  if (!parsed.ok) throw new Error(`invalid CVSS 3.1 vector: ${parsed.error}`);
  return parsed.metrics;
}

export function baseScore(input: string | CvssMetrics): number {
  const m = toMetrics(input);
  const changed = m.S === 'C';
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * privilegesRequired(m.PR, changed) * UI[m.UI];
  if (impact <= 0) return 0;
  return changed ? roundUp1(Math.min(1.08 * (impact + exploitability), 10)) : roundUp1(Math.min(impact + exploitability, 10));
}

function temporalMultiplier(m: CvssMetrics): number {
  return EXPLOIT_MATURITY[m.E ?? 'X'] * REMEDIATION_LEVEL[m.RL ?? 'X'] * REPORT_CONFIDENCE[m.RC ?? 'X'];
}

export function temporalScore(input: string | CvssMetrics): number {
  const m = toMetrics(input);
  return roundUp1(baseScore(m) * temporalMultiplier(m));
}

export function environmentalScore(input: string | CvssMetrics): number {
  const m = toMetrics(input);
  // "X" (or absent) on a modified metric means: use the base value.
  const mod = (key: 'MAV' | 'MAC' | 'MPR' | 'MUI' | 'MS' | 'MC' | 'MI' | 'MA', base: string): string => {
    const v = m[key];
    return v === undefined || v === 'X' ? base : v;
  };
  const mav = mod('MAV', m.AV);
  const mac = mod('MAC', m.AC);
  const mpr = mod('MPR', m.PR);
  const mui = mod('MUI', m.UI);
  const ms = mod('MS', m.S);
  const mc = mod('MC', m.C);
  const mi = mod('MI', m.I);
  const ma = mod('MA', m.A);
  const changed = ms === 'C';

  const miss = Math.min(
    1 -
      (1 - REQUIREMENT[m.CR ?? 'X'] * CIA[mc]) *
        (1 - REQUIREMENT[m.IR ?? 'X'] * CIA[mi]) *
        (1 - REQUIREMENT[m.AR ?? 'X'] * CIA[ma]),
    0.915,
  );
  const modifiedImpact = changed ? 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13 : 6.42 * miss;
  const modifiedExploitability = 8.22 * AV[mav] * AC[mac] * privilegesRequired(mpr, changed) * UI[mui];
  if (modifiedImpact <= 0) return 0;
  const inner = changed
    ? roundUp1(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10))
    : roundUp1(Math.min(modifiedImpact + modifiedExploitability, 10));
  return roundUp1(inner * temporalMultiplier(m));
}

export interface CvssScores {
  base: number;
  temporal: number;
  environmental: number;
  severity: CvssSeverity; // band of the base score
}

// All three scores for a vector; throws on an invalid vector.
export function scoreVector(vector: string): CvssScores {
  const m = toMetrics(vector);
  const base = baseScore(m);
  return { base, temporal: temporalScore(m), environmental: environmentalScore(m), severity: severityOf(base) };
}
