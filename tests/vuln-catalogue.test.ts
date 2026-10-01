// The fictional vulnerability catalogue (DESIGN section 6.2): determinism, size,
// id shape, the calibrated CVSS mix, Sim-KEV constraints and Sim-EPSS sampling.
import { describe, expect, it } from 'vitest';
import { createRng } from '../src/core/rng.ts';
import { DAY } from '../src/core/logs/time.ts';
import { baseScore, parseVector, severityOf } from '../src/core/vuln/cvss31.ts';
import { formatSimVulnId, isSimVulnId, parseSimVulnId, SIMVULN_ID_PATTERN } from '../src/core/vuln/ids.ts';
import {
  CATALOGUE_SIZE,
  KEV_LAUNCH,
  MIN_REFERENCE_DATE,
  NEWLY_PUBLISHED_DAYS,
  SIM_EPSS_ALL,
  SIM_EPSS_LISTED,
  SIM_KEV_COUNT,
  VULN_CLASSES,
  findEntry,
  generateCatalogue,
  isNewlyPublished,
  sampleSimEpss,
  simEpssPercentile,
  simEpssPercentileRank,
  simEpssScoreAt,
  type CatalogueBand,
  type VulnCatalogue,
} from '../src/core/vuln/catalogue.ts';

const REF = Date.UTC(2026, 8, 28);
const SEEDS = Array.from({ length: 24 }, (_, i) => `cat-seed-${i}`);
const catalogues: VulnCatalogue[] = SEEDS.map((s) => generateCatalogue(s, REF));

describe('SIMVULN ids', () => {
  it('formats and validates SIMVULN-YYYY-NNNNN', () => {
    expect(formatSimVulnId(2026, 10421)).toBe('SIMVULN-2026-10421');
    expect(formatSimVulnId(2014, 7)).toBe('SIMVULN-2014-00007');
    expect(SIMVULN_ID_PATTERN.source).toBe('^SIMVULN-\\d{4}-\\d{5}$');
    expect(isSimVulnId('SIMVULN-2026-10421')).toBe(true);
    expect(parseSimVulnId('SIMVULN-2019-00042')).toEqual({ year: 2019, serial: 42 });
  });
  it('rejects anything else', () => {
    for (const bad of ['SIMVULN-26-10421', 'SIMVULN-2026-1042', 'SIMVULN-2026-104211', 'simvuln-2026-10421', ' SIMVULN-2026-10421', 'SIMVULN-2026-10421\n', 'SIMVULN2026-10421', '']) {
      expect(isSimVulnId(bad), JSON.stringify(bad)).toBe(false);
      expect(parseSimVulnId(bad)).toBeNull();
    }
    expect(() => formatSimVulnId(26, 1)).toThrow(RangeError);
    expect(() => formatSimVulnId(2026, 100000)).toThrow(RangeError);
    expect(() => formatSimVulnId(2026, -1)).toThrow(RangeError);
    expect(() => formatSimVulnId(2026.5, 1)).toThrow(RangeError);
  });
});

describe('catalogue determinism', () => {
  it('the same seed and reference date give an identical catalogue, however many others were built in between', () => {
    const a = generateCatalogue('determinism', REF);
    generateCatalogue('something-else', REF);
    const b = generateCatalogue('determinism', REF);
    expect(b).toEqual(a);
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
  });

  it('a numeric seed and its string form are the same seed', () => {
    expect(generateCatalogue(7, REF)).toEqual(generateCatalogue('7', REF));
  });

  it('different seeds give different catalogues', () => {
    const serialised = new Set(catalogues.map((c) => JSON.stringify(c.entries)));
    expect(serialised.size).toBe(catalogues.length);
    const idSets = new Set(catalogues.map((c) => c.entries.map((e) => e.id).join(',')));
    expect(idSets.size).toBe(catalogues.length);
  });

  it('rejects a reference date before 2021-11-04', () => {
    expect(() => generateCatalogue('x', MIN_REFERENCE_DATE - 1)).toThrow(RangeError);
    expect(() => generateCatalogue('x', Number.NaN)).toThrow(RangeError);
    expect(() => generateCatalogue('x', MIN_REFERENCE_DATE)).not.toThrow();
  });
});

describe('Sim-KEV listing dates and vendor names', () => {
  const refs = [MIN_REFERENCE_DATE, Date.UTC(2022, 5, 15), Date.UTC(2024, 1, 29), REF, Date.UTC(2026, 9, 30)];
  it('pins the launch of the real KEV catalogue (BOD 22-01, 2021-11-03) and the earliest reference date', () => {
    expect(new Date(KEV_LAUNCH).toISOString()).toBe('2021-11-03T00:00:00.000Z');
    expect(new Date(MIN_REFERENCE_DATE).toISOString()).toBe('2021-11-04T00:00:00.000Z');
  });
  it('never list before the KEV launch, the publish date, or on/after the reference date', () => {
    for (const ref of refs)
      for (let i = 0; i < 60; i++) {
        for (const e of generateCatalogue(`kev-date-${i}`, ref).entries) {
          if (!e.knownExploited) continue;
          expect(e.knownExploitedAdded).not.toBeNull();
          const added = e.knownExploitedAdded as number;
          expect(added).toBeGreaterThanOrEqual(KEV_LAUNCH);
          expect(added).toBeGreaterThanOrEqual(e.published);
          expect(added).toBeLessThan(ref);
        }
      }
  });
  it('uses none of the names that collide with real vendors (fact-check 2026-09-29)', () => {
    for (const c of catalogues)
      for (const e of c.entries) expect(`${e.vendor} ${e.product} ${e.title}`).not.toMatch(/fenwick|northmere/i);
  });
});

describe('catalogue shape', () => {
  it('has at least 60 entries', () => {
    expect(CATALOGUE_SIZE).toBeGreaterThanOrEqual(60);
    for (const c of catalogues) expect(c.entries).toHaveLength(CATALOGUE_SIZE);
  });

  it('every id matches the SIMVULN pattern, is unique, and the list is sorted by id', () => {
    for (const c of catalogues) {
      const ids = c.entries.map((e) => e.id);
      for (const id of ids) expect(id).toMatch(/^SIMVULN-\d{4}-\d{5}$/);
      expect(new Set(ids).size).toBe(ids.length);
      expect([...ids].sort()).toEqual(ids);
    }
  });

  it('the id year is the UTC year of the publication date', () => {
    for (const c of catalogues)
      for (const e of c.entries) {
        expect(parseSimVulnId(e.id)?.year).toBe(e.year);
        expect(new Date(e.published).getUTCFullYear()).toBe(e.year);
        expect(e.published).toBeLessThanOrEqual(c.referenceDate);
      }
  });

  it('titles are unique and entries use fictional vendors and products, all six classes', () => {
    for (const c of catalogues) {
      expect(new Set(c.entries.map((e) => e.title)).size).toBe(c.entries.length);
      expect(new Set(c.entries.map((e) => e.vulnClass))).toEqual(new Set(VULN_CLASSES));
      for (const e of c.entries) {
        expect(e.vendor.length).toBeGreaterThan(0);
        expect(e.title).toContain(e.product);
        expect(e.fixedVersion).toMatch(/^\d+\.\d+\.\d+$/);
      }
    }
  });

  it('findEntry looks entries up by id', () => {
    const c = catalogues[0];
    expect(findEntry(c, c.entries[10].id)).toBe(c.entries[10]);
    expect(findEntry(c, 'SIMVULN-1999-00000')).toBeUndefined();
  });
});

describe('CVSS in the catalogue', () => {
  it('every base score is our calculator applied to the entry vector', () => {
    for (const c of catalogues)
      for (const e of c.entries) {
        expect(parseVector(e.vector).ok, e.vector).toBe(true);
        expect(e.vector.startsWith('CVSS:3.1/')).toBe(true);
        expect(e.base).toBe(baseScore(e.vector));
        expect(e.severity).toBe(severityOf(e.base));
        expect(e.base).toBeGreaterThan(0);
      }
  });

  it('the severity mix holds within 5 points of Critical 15 / High 40 / Medium 40 / Low 5 for every seed', () => {
    const target: Record<CatalogueBand, number> = { critical: 15, high: 40, medium: 40, low: 5 };
    expect(catalogues.length).toBeGreaterThanOrEqual(20);
    for (const c of catalogues)
      for (const band of Object.keys(target) as CatalogueBand[]) {
        const pct = (100 * c.entries.filter((e) => e.severity === band).length) / c.entries.length;
        expect(Math.abs(pct - target[band]), `${c.seed} ${band} ${pct}`).toBeLessThanOrEqual(5);
      }
  });

  it('vectors favour the common shapes (base 7.5, 6.5, 8.8, 7.8, 9.8, 5.3)', () => {
    const common = new Set([7.5, 6.5, 8.8, 7.8, 9.8, 5.3]);
    const shares = catalogues.map((c) => c.entries.filter((e) => common.has(e.base)).length / c.entries.length);
    expect(shares.reduce((a, b) => a + b, 0) / shares.length).toBeGreaterThanOrEqual(0.55);
    // 7.5 is the single most frequent base score across seeds.
    const counts = new Map<number, number>();
    for (const c of catalogues) for (const e of c.entries) counts.set(e.base, (counts.get(e.base) ?? 0) + 1);
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
    expect(top).toBe(7.5);
  });

  it('spans every severity band', () => {
    for (const c of catalogues) expect(new Set(c.entries.map((e) => e.severity))).toEqual(new Set(['critical', 'high', 'medium', 'low']));
  });
});

describe('Sim-KEV', () => {
  it('lists exactly six entries, at least one Medium, about a third with an id year of 2019 or earlier', () => {
    expect(SIM_KEV_COUNT).toBe(6);
    for (const c of catalogues) {
      const listed = c.entries.filter((e) => e.knownExploited);
      expect(listed, c.seed).toHaveLength(6);
      expect(listed.some((e) => e.severity === 'medium'), c.seed).toBe(true);
      const old = listed.filter((e) => e.year <= 2019);
      expect(old.length, c.seed).toBeGreaterThanOrEqual(1);
      expect(old.length, c.seed).toBeLessThanOrEqual(3);
    }
  });

  it('listing dates fall between publication and the reference date; unlisted entries have none', () => {
    for (const c of catalogues)
      for (const e of c.entries) {
        if (e.knownExploited) {
          expect(e.knownExploitedAdded).not.toBeNull();
          expect(e.knownExploitedAdded!).toBeGreaterThan(e.published);
          expect(e.knownExploitedAdded!).toBeLessThanOrEqual(c.referenceDate);
        } else {
          expect(e.knownExploitedAdded).toBeNull();
        }
      }
  });

  it('listed entries are never newly published, and span more than one severity band', () => {
    for (const c of catalogues) {
      const listed = c.entries.filter((e) => e.knownExploited);
      for (const e of listed) expect(isNewlyPublished(e, c.referenceDate)).toBe(false);
      expect(new Set(listed.map((e) => e.severity)).size).toBeGreaterThanOrEqual(2);
    }
  });
});

describe('Sim-EPSS tables and sampling', () => {
  it('anchor tables are increasing in percentile and score and span 0..1', () => {
    for (const table of [SIM_EPSS_ALL, SIM_EPSS_LISTED]) {
      expect(table[0][0]).toBe(0);
      expect(table[table.length - 1][0]).toBe(1);
      for (let i = 1; i < table.length; i++) {
        expect(table[i][0]).toBeGreaterThan(table[i - 1][0]);
        expect(table[i][1]).toBeGreaterThan(table[i - 1][1]);
      }
    }
  });

  it('the inverse CDF hits every anchor and interpolates log-linearly between them', () => {
    for (const table of [SIM_EPSS_ALL, SIM_EPSS_LISTED]) for (const [p, s] of table) expect(simEpssScoreAt(table, p)).toBe(s);
    // Midway between the 0.50 and 0.75 anchors of the first table: geometric mean of 0.0067 and 0.016.
    expect(simEpssScoreAt(SIM_EPSS_ALL, 0.625)).toBeCloseTo(Math.sqrt(0.0067 * 0.016), 12);
    expect(simEpssScoreAt(SIM_EPSS_ALL, -1)).toBe(0.0005);
    expect(simEpssScoreAt(SIM_EPSS_ALL, 2)).toBe(0.98);
  });

  it('the displayed percentile comes from the all-CVE table: 0.004 is the 31st', () => {
    expect(simEpssPercentileRank(0.004)).toBe(31);
    for (const [p, s] of SIM_EPSS_ALL) expect(simEpssPercentile(s)).toBeCloseTo(p, 12);
    expect(simEpssPercentile(0.00001)).toBe(0);
    expect(simEpssPercentile(0.999)).toBe(1);
    // A score that is the median of the listed table is far above the median of all vulnerabilities.
    expect(simEpssPercentileRank(0.49)).toBeGreaterThan(95);
    // The percentile function inverts the inverse CDF of the first table.
    for (let u = 0.02; u < 1; u += 0.04) expect(simEpssPercentile(simEpssScoreAt(SIM_EPSS_ALL, u))).toBeCloseTo(u, 9);
  });

  it('unlisted draws follow the first table: median near 0.0067, one in ten above 0.039', () => {
    const rng = createRng('epss-unlisted');
    const draws = Array.from({ length: 20000 }, () => sampleSimEpss(rng));
    const below = (x: number) => draws.filter((d) => d < x).length / draws.length;
    expect(below(0.0067)).toBeGreaterThan(0.47);
    expect(below(0.0067)).toBeLessThan(0.53);
    expect(below(0.039)).toBeGreaterThan(0.88);
    expect(below(0.039)).toBeLessThan(0.92);
    for (const d of draws) {
      expect(d).toBeGreaterThanOrEqual(0.0005);
      expect(d).toBeLessThanOrEqual(0.98);
    }
  });

  it('listed draws follow the second table: about one in four is below 0.1, none below 0.0023', () => {
    const rng = createRng('epss-listed');
    const draws = Array.from({ length: 20000 }, () => sampleSimEpss(rng, { listed: true }));
    const lowShare = draws.filter((d) => d < 0.1).length / draws.length;
    expect(lowShare).toBeGreaterThan(0.21);
    expect(lowShare).toBeLessThan(0.29);
    for (const d of draws) {
      expect(d).toBeGreaterThanOrEqual(0.0023);
      expect(d).toBeLessThanOrEqual(0.997);
    }
    const median = [...draws].sort((a, b) => a - b)[draws.length / 2];
    expect(median).toBeGreaterThan(0.44);
    expect(median).toBeLessThan(0.54);
  });

  it('newly published draws come from the lower half of the first table, even for listed entries', () => {
    const rng = createRng('epss-new');
    for (let i = 0; i < 5000; i++) {
      const fresh = sampleSimEpss(rng, { newlyPublished: true });
      expect(fresh).toBeGreaterThanOrEqual(0.0005);
      expect(fresh).toBeLessThanOrEqual(0.0067);
      expect(sampleSimEpss(rng, { newlyPublished: true, listed: true })).toBeLessThanOrEqual(0.0067);
    }
  });

  it('every catalogue entry has an EPSS value in its table range and its percentile from the first table', () => {
    for (const c of catalogues)
      for (const e of c.entries) {
        const fresh = isNewlyPublished(e, c.referenceDate);
        if (fresh) {
          expect(e.epss).toBeGreaterThanOrEqual(0.0005);
          expect(e.epss).toBeLessThanOrEqual(0.0067);
        } else if (e.knownExploited) {
          expect(e.epss).toBeGreaterThanOrEqual(0.0023);
          expect(e.epss).toBeLessThanOrEqual(0.997);
        } else {
          expect(e.epss).toBeGreaterThanOrEqual(0.0005);
          expect(e.epss).toBeLessThanOrEqual(0.98);
        }
        expect(e.epssPercentile).toBeGreaterThanOrEqual(0);
        expect(e.epssPercentile).toBeLessThanOrEqual(1);
        expect(e.epssPercentile).toBe(Math.round(simEpssPercentile(e.epss) * 100) / 100);
      }
  });

  it('newly published entries (under 30 days old) exist in every catalogue and sit in the lower half; the rest are older', () => {
    for (const c of catalogues) {
      const fresh = c.entries.filter((e) => isNewlyPublished(e, c.referenceDate));
      expect(fresh.length, c.seed).toBeGreaterThanOrEqual(1);
      for (const e of fresh) {
        expect(c.referenceDate - e.published).toBeLessThan(NEWLY_PUBLISHED_DAYS * DAY);
        expect(e.epssPercentile).toBeLessThanOrEqual(0.5);
        expect(e.knownExploited).toBe(false);
      }
      for (const e of c.entries.filter((x) => !fresh.includes(x))) expect(c.referenceDate - e.published).toBeGreaterThanOrEqual(NEWLY_PUBLISHED_DAYS * DAY);
    }
  });

  it('about one Sim-KEV entry in four shows a modest probability (under 0.1) across seeds', () => {
    const listed = catalogues.flatMap((c) => c.entries.filter((e) => e.knownExploited));
    const share = listed.filter((e) => e.epss < 0.1).length / listed.length;
    expect(share).toBeGreaterThan(0.1);
    expect(share).toBeLessThan(0.45);
  });
});

describe('reference date', () => {
  it('moves the newly-published window with it', () => {
    const early = generateCatalogue('ref-shift', Date.UTC(2024, 2, 1));
    const late = generateCatalogue('ref-shift', Date.UTC(2026, 10, 1));
    for (const c of [early, late]) {
      expect(c.entries.filter((e) => isNewlyPublished(e, c.referenceDate)).length).toBeGreaterThanOrEqual(1);
      for (const e of c.entries) expect(e.published).toBeLessThanOrEqual(c.referenceDate);
    }
    expect(Math.max(...early.entries.map((e) => e.published))).toBeLessThan(Math.max(...late.entries.map((e) => e.published)));
  });
});
