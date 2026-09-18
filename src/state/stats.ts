// Aggregations over the record history for the dashboard.

import type { Category, Difficulty, Tactic } from '../types.ts';
import type { CaseRecord } from './store.ts';
import { ALL_CATEGORIES } from '../data/templates/index.ts';
import { TACTIC_ORDER } from '../data/mitre.ts';
import { CYSA_DOMAINS } from '../data/cysa.ts';

export interface Bucket {
  key: string;
  label: string;
  count: number;
  avgPercent: number; // 0-100
  dispositionAccuracy: number; // 0-100
}

function bucketise<K extends string>(
  records: CaseRecord[],
  keys: readonly K[],
  keyOf: (r: CaseRecord) => K[],
  labelOf: (k: K) => string,
): Bucket[] {
  return keys.map((k) => {
    const rs = records.filter((r) => keyOf(r).includes(k));
    const count = rs.length;
    const avgPercent = count ? Math.round(rs.reduce((s, r) => s + r.percent, 0) / count) : 0;
    const correct = rs.filter((r) => r.dispositionCorrect).length;
    return {
      key: k,
      label: labelOf(k),
      count,
      avgPercent,
      dispositionAccuracy: count ? Math.round((correct / count) * 100) : 0,
    };
  });
}

export interface Summary {
  total: number;
  avgPercent: number;
  dispositionAccuracy: number;
  avgDurationSec: number | null;
  last10Percent: number;
}

export function summarise(records: CaseRecord[]): Summary {
  const total = records.length;
  if (total === 0) {
    return { total: 0, avgPercent: 0, dispositionAccuracy: 0, avgDurationSec: null, last10Percent: 0 };
  }
  const avgPercent = Math.round(records.reduce((s, r) => s + r.percent, 0) / total);
  const correct = records.filter((r) => r.dispositionCorrect).length;
  const timed = records.filter((r) => r.durationSec !== null) as (CaseRecord & { durationSec: number })[];
  const avgDurationSec = timed.length
    ? Math.round(timed.reduce((s, r) => s + r.durationSec, 0) / timed.length)
    : null;
  const last10 = records.slice(-10);
  const last10Percent = Math.round(last10.reduce((s, r) => s + r.percent, 0) / last10.length);
  return {
    total,
    avgPercent,
    dispositionAccuracy: Math.round((correct / total) * 100),
    avgDurationSec,
    last10Percent,
  };
}

export function byCategory(records: CaseRecord[], labels: Record<Category, string>): Bucket[] {
  return bucketise(records, ALL_CATEGORIES, (r) => [r.category], (k) => labels[k]);
}

export function byDifficulty(records: CaseRecord[], labels: Record<Difficulty, string>): Bucket[] {
  const keys: Difficulty[] = ['tier1', 'tier2', 'tier3'];
  return bucketise(records, keys, (r) => [r.difficulty], (k) => labels[k]);
}

export function byCysaDomain(records: CaseRecord[]): Bucket[] {
  return bucketise(
    records,
    CYSA_DOMAINS.map((d) => d.id),
    (r) => r.cysaDomains,
    (k) => {
      const d = CYSA_DOMAINS.find((x) => x.id === k);
      return d ? `${d.id} ${d.name}` : k;
    },
  );
}

export interface TacticCoverage {
  tactic: Tactic;
  cases: number; // cases whose ground truth involved this tactic
  techniqueHitRate: number; // 0-100, share of truth techniques matched in those cases
}

export function tacticCoverage(records: CaseRecord[]): TacticCoverage[] {
  return TACTIC_ORDER.map((tactic) => {
    const rs = records.filter((r) => r.tactics.includes(tactic));
    const truthCount = rs.reduce((s, r) => s + r.truthTechniques.length, 0);
    const matched = rs.reduce((s, r) => s + r.matchedTechniques.length, 0);
    return {
      tactic,
      cases: rs.length,
      techniqueHitRate: truthCount ? Math.round((Math.min(matched, truthCount) / truthCount) * 100) : 0,
    };
  });
}

// Weakest categories with enough data to be meaningful.
export function weakSpots(buckets: Bucket[], minCount = 2, limit = 3): Bucket[] {
  return buckets
    .filter((b) => b.count >= minCount)
    .sort((a, b) => a.avgPercent - b.avgPercent)
    .slice(0, limit);
}

// Percent trend for a sparkline: last N results.
export function trend(records: CaseRecord[], n = 20): number[] {
  return records.slice(-n).map((r) => r.percent);
}
