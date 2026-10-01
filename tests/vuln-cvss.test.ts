// CVSS v3.1 calculator against the oracle table in DESIGN section 6.2
// (verified 2026-09-28 against the FIRST specification examples and reference
// calculator). Every row is asserted, both scores where a row gives both.
import { describe, expect, it } from 'vitest';
import {
  baseScore,
  canonicalVector,
  environmentalScore,
  isValidVector,
  parseVector,
  roundUp1,
  scoreVector,
  severityOf,
  temporalScore,
} from '../src/core/vuln/cvss31.ts';

const P = 'CVSS:3.1/';
const V98 = `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`;
const V75 = `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`;
const V99 = `${P}AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`;

interface OracleRow {
  name: string;
  vector: string;
  base?: number;
  severity?: string;
  temporal?: number;
  environmental?: number;
}

const ORACLE: OracleRow[] = [
  { name: 'T1/T4 headline', vector: V98, base: 9.8, severity: 'critical' },
  { name: 'T3 headline', vector: V75, base: 7.5, severity: 'high' },
  { name: 'scope changed, PR:L = 0.68', vector: V99, base: 9.9 },
  { name: 'scope changed, low impacts', vector: `${P}AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N`, base: 6.4 },
  { name: 'AC:H, UI:R', vector: `${P}AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`, base: 3.1, severity: 'low' },
  { name: 'AV:L, PR:H unchanged', vector: `${P}AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L`, base: 4.2, severity: 'medium' },
  { name: 'PR:H = 0.5 when changed', vector: `${P}AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`, base: 8.2 },
  { name: 'AV:A', vector: `${P}AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H`, base: 9.3 },
  { name: 'AV:P', vector: `${P}AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`, base: 7.6 },
  { name: '1.08 multiplier path', vector: `${P}AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`, base: 6.1 },
  { name: 'impact <= 0 branch', vector: `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N`, base: 0, severity: 'none' },
  { name: 'T4 B segmented interface', vector: `${V98}/MAV:A`, environmental: 8.8 },
  { name: 'modified AV', vector: `${V98}/MAV:L`, environmental: 8.4 },
  { name: 'requirement raises score', vector: `${V75}/CR:H`, environmental: 9.3 },
  { name: 'requirement lowers score', vector: `${V75}/CR:L`, environmental: 5.7 },
  { name: 'MISS cap 0.915, exponent 13 path', vector: `${V99}/CR:H/IR:H/AR:H`, environmental: 10.0 },
  { name: 'temporal factors (9.8)', vector: `${V98}/E:F/RL:O/RC:C`, temporal: 9.1, environmental: 9.1 },
  { name: 'temporal factors (7.5)', vector: `${V75}/E:U/RL:O/RC:C`, temporal: 6.5 },
];

describe('CVSS 3.1 oracle table (DESIGN 6.2)', () => {
  for (const row of ORACLE) {
    it(row.name, () => {
      if (row.base !== undefined) expect(baseScore(row.vector)).toBe(row.base);
      if (row.severity !== undefined) expect(severityOf(baseScore(row.vector))).toBe(row.severity);
      if (row.temporal !== undefined) expect(temporalScore(row.vector)).toBe(row.temporal);
      if (row.environmental !== undefined) expect(environmentalScore(row.vector)).toBe(row.environmental);
    });
  }

  it('covers all 18 rows of the table', () => {
    expect(ORACLE).toHaveLength(18);
  });

  it('scoreVector returns base, temporal, environmental and the base band together', () => {
    expect(scoreVector(`${V98}/E:F/RL:O/RC:C`)).toEqual({ base: 9.8, temporal: 9.1, environmental: 9.1, severity: 'critical' });
    expect(scoreVector(V75)).toEqual({ base: 7.5, temporal: 7.5, environmental: 7.5, severity: 'high' });
  });

  it('temporal equals the base score when no temporal metrics are given', () => {
    for (const v of [V98, V75, V99, `${P}AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`, `${P}AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N`]) {
      const s = scoreVector(v);
      expect(s.temporal).toBe(s.base);
    }
  });

  it('environmental equals the base score with no environmental metrics, up to the spec 3.1 scope-changed quirk', () => {
    // Section 7 uses (ISS - 0.02)^15 for the base impact but (MISS * 0.9731 - 0.02)^13 for the
    // modified impact, so a scope-changed vector may differ by one tenth; scope-unchanged never does.
    for (const v of [V98, V75, `${P}AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N`]) expect(scoreVector(v).environmental).toBe(scoreVector(v).base);
    expect(scoreVector(V99).environmental).toBe(10.0);
    expect(scoreVector(V99).base).toBe(9.9);
  });

  it('explicit X values equal omitted metrics', () => {
    expect(environmentalScore(`${V98}/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X`)).toBe(9.8);
  });
});

describe('Roundup (spec Appendix A integer method)', () => {
  it('rounds up to one decimal', () => {
    expect(roundUp1(4.02)).toBe(4.1);
    expect(roundUp1(4.0)).toBe(4.0);
    expect(roundUp1(4.01)).toBe(4.1);
    expect(roundUp1(9.81)).toBe(9.9);
    expect(roundUp1(0)).toBe(0);
    expect(roundUp1(10)).toBe(10);
  });
  it('is not fooled by floating-point noise just above or below a tenth', () => {
    expect(roundUp1(4.000000000000001)).toBe(4.0);
    expect(roundUp1(3.9999999999999996)).toBe(4.0);
    expect(roundUp1(0.1 + 0.2 + 3.7)).toBe(4.0); // 4.000000000000001 in doubles
    expect(roundUp1(4.0000101)).toBe(4.1); // a real excess of 1e-5 still rounds up
  });
});

describe('severity bands (spec Table 14)', () => {
  it('maps band boundaries', () => {
    const cases: [number, string][] = [
      [0, 'none'],
      [0.1, 'low'],
      [3.9, 'low'],
      [4.0, 'medium'],
      [6.9, 'medium'],
      [7.0, 'high'],
      [8.9, 'high'],
      [9.0, 'critical'],
      [10.0, 'critical'],
    ];
    for (const [score, band] of cases) expect(severityOf(score), String(score)).toBe(band);
  });
});

describe('vector parsing and validation', () => {
  it('parses a full vector including temporal and environmental metrics', () => {
    const r = parseVector(`${V98}/E:F/RL:O/RC:C/CR:H/MAV:A`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.metrics.AV).toBe('N');
      expect(r.metrics.E).toBe('F');
      expect(r.metrics.MAV).toBe('A');
      expect(r.metrics.MPR).toBeUndefined();
    }
  });

  it('accepts base metrics in any order and canonicalises them', () => {
    const r = parseVector(`${P}A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N`);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(canonicalVector(r.metrics)).toBe(V98);
      expect(baseScore(r.metrics)).toBe(9.8);
    }
  });

  it('canonical form drops X values and orders metric groups base, temporal, environmental', () => {
    const r = parseVector(`${V98}/MAV:A/CR:H/RC:C/E:X/RL:O`);
    expect(r.ok).toBe(true);
    if (r.ok) expect(canonicalVector(r.metrics)).toBe(`${V98}/RL:O/RC:C/CR:H/MAV:A`);
  });

  it('rejects malformed vectors', () => {
    const bad = [
      '',
      'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // no prefix
      'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // wrong version
      'CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H`, // missing A
      `${V98}/AV:L`, // duplicate
      `${P}AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, // X not allowed on base metrics
      `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z`, // bad value
      `${P}AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:HH`, // too long
      `${V98}/ZZ:H`, // unknown metric
      `${V98}/E`, // no value
      `${V98}//E:F`, // empty segment
      `${V98}/E:F/`, // trailing slash
      `${V98}/CR:N`, // N is not a requirement value
    ];
    for (const v of bad) {
      expect(isValidVector(v), v).toBe(false);
      const r = parseVector(v);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.error.length).toBeGreaterThan(0);
    }
  });

  it('scoring an invalid vector throws', () => {
    expect(() => baseScore('nonsense')).toThrow(/invalid CVSS 3.1 vector/);
    expect(() => scoreVector(`${P}AV:N`)).toThrow();
  });
});

describe('score sanity over the whole base metric space', () => {
  const AV = ['N', 'A', 'L', 'P'];
  const AC = ['L', 'H'];
  const PR = ['N', 'L', 'H'];
  const UI = ['N', 'R'];
  const S = ['U', 'C'];
  const CIA = ['H', 'L', 'N'];

  it('every base score is in 0..10 with one decimal, and 0 exactly when C, I and A are all N', () => {
    for (const av of AV)
      for (const ac of AC)
        for (const pr of PR)
          for (const ui of UI)
            for (const s of S)
              for (const c of CIA)
                for (const i of CIA)
                  for (const a of CIA) {
                    const v = `${P}AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;
                    const score = baseScore(v);
                    expect(score).toBeGreaterThanOrEqual(0);
                    expect(score).toBeLessThanOrEqual(10);
                    expect(Math.round(score * 10) / 10).toBe(score);
                    expect(score === 0).toBe(c === 'N' && i === 'N' && a === 'N');
                    // Temporal factors never raise a score.
                    expect(temporalScore(`${v}/E:P/RL:W/RC:R`)).toBeLessThanOrEqual(score);
                    // A requirement of M (weight 1) is the same as omitting it; see the scope-changed quirk above.
                    expect(environmentalScore(`${v}/CR:M/IR:M/AR:M`)).toBe(environmentalScore(v));
                    expect(Math.abs(environmentalScore(v) - score)).toBeLessThan(s === 'C' ? 0.15 : 0.05);
                  }
  });

  it('is monotonic in attack vector reach', () => {
    const at = (av: string) => baseScore(`${P}AV:${av}/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`);
    expect(at('N')).toBeGreaterThan(at('A'));
    expect(at('A')).toBeGreaterThan(at('L'));
    expect(at('L')).toBeGreaterThan(at('P'));
  });
});
