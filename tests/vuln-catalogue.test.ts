// The fictional vulnerability catalogue (DESIGN section 6.2): determinism, size,
// id shape, the calibrated CVSS mix, Sim-KEV constraints and Sim-EPSS sampling.
import { describe, expect, it } from 'vitest';
import { createRng } from '../src/core/rng.ts';
import { DAY } from '../src/core/logs/time.ts';
import { baseScore, parseVector, severityOf } from '../src/core/vuln/cvss31.ts';
import { isCoherent, vectorFits, vectorProblem } from '../src/core/vuln/coherence.ts';
import { formatSimVulnId, isSimVulnId, parseSimVulnId, SIMVULN_ID_PATTERN } from '../src/core/vuln/ids.ts';
import {
  CATALOGUE_SIZE,
  KEV_LAUNCH,
  MIN_REFERENCE_DATE,
  NEWLY_PUBLISHED_DAYS,
  SIM_EPSS_ALL,
  SIM_EPSS_LISTED,
  SIM_KEV_COUNT,
  COMPONENTS,
  PRODUCTS,
  SHAPE_DEFS,
  VULN_CLASSES,
  VULN_CLASS_LABELS,
  componentText,
  findEntry,
  generateCatalogue,
  isNewlyPublished,
  sampleSimEpss,
  simEpssPercentile,
  simEpssPercentileRank,
  simEpssScoreAt,
  type CatalogueBand,
  type CatalogueEntry,
  type VulnCatalogue,
} from '../src/core/vuln/catalogue.ts';
import { placedOn } from '../src/core/vuln/templates/common.ts';

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
      for (const e of c.entries) expect(`${e.vendor} ${e.product} ${e.title}`).not.toMatch(/fenwick|northmere|quillon|larkfield/i);
  });
  it('a re-branded (placed) entry carries the vendor the catalogue gives that product, so a rename in one list cannot drift from the other', () => {
    const entries = catalogues[0].entries;
    for (const { product, vendor } of PRODUCTS) {
      const source = entries.find((e) => e.product !== product);
      expect(source).toBeDefined();
      const placed = placedOn(source as CatalogueEntry, 'ANY-HOST', createRng('vendor-agreement'), new Set(), [product]);
      expect(placed, product).not.toBeNull();
      expect(placed?.product).toBe(product);
      expect(placed?.vendor, product).toBe(vendor);
    }
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

// Class and vector coherence (WP1f): no entry's class or component contradicts its CVSS vector, as the
// coherence predicate (src/core/vuln/coherence.ts) defines it. The sweep fails the build on any contradiction.
describe('class and vector coherence', () => {
  const SWEEP = 2000;

  it(`every entry of ${SWEEP} (seed, referenceDate) catalogues is coherent`, () => {
    let checked = 0;
    const contradictions: string[] = [];
    for (let i = 0; i < SWEEP; i++) {
      const referenceDate = MIN_REFERENCE_DATE + ((i * 7919) % 1500) * DAY;
      const c = generateCatalogue(`coherence-${i}`, referenceDate);
      for (const e of c.entries) {
        checked++;
        if (!isCoherent(e)) contradictions.push(`coherence-${i} ${e.id} ${e.title} ${e.vector}: ${vectorProblem(e.vector, e.vulnClass, `${e.component} ${e.title}`)}`);
      }
    }
    expect(contradictions.slice(0, 5)).toEqual([]);
    expect(checked).toBe(SWEEP * CATALOGUE_SIZE);
  }, 120_000);

  it('every entry keeps its band, class label in the title and a component of its class', () => {
    for (const c of catalogues)
      for (const e of c.entries) {
        expect(COMPONENTS[e.vulnClass]).toContain(e.component);
        expect(e.title.startsWith(VULN_CLASS_LABELS[e.vulnClass])).toBe(true);
        expect(severityOf(e.base)).toBe(e.severity);
      }
  });

  it('every SHAPE_DEFS (shape, class) pair admits at least one component of that class', () => {
    for (const [body, classes] of SHAPE_DEFS)
      for (const cls of classes) {
        const fits = PRODUCTS.flatMap((p) => COMPONENTS[cls].filter((comp) => vectorFits(`CVSS:3.1/${body}`, cls, componentText(cls, p, comp))));
        expect(fits.length, `${body} ${cls}`).toBeGreaterThan(0);
      }
  });

  it('no SHAPE_DEFS pair is incoherent for all components, and every shape keeps a class', () => {
    for (const [body, classes] of SHAPE_DEFS) {
      expect(classes.length, body).toBeGreaterThan(0);
      for (const cls of classes) {
        const bad = COMPONENTS[cls].filter((comp) => !PRODUCTS.some((p) => vectorFits(`CVSS:3.1/${body}`, cls, componentText(cls, p, comp))));
        expect(bad.length, `${body} ${cls} has components that never fit: ${bad.join(', ')}`).toBeLessThan(COMPONENTS[cls].length);
      }
    }
  });

  describe('hardened rules (fact-check round)', () => {
    const V = (body: string): string => `CVSS:3.1/${body}`;
    const tls = (cls: 'misconfig' | 'info-leak', body: string): boolean => vectorFits(V(body), cls, 'TLS settings Insecure default configuration in Larkspur Portal TLS settings');

    it('a TLS flaw never has an availability impact, high integrity impact or user interaction', () => {
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(false); // 9.8
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L')).toBe(false); // 7.3
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(false); // 6.1 XSS shape
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N')).toBe(false);
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(true); // 7.5
      expect(tls('misconfig', 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(true); // 5.9
      expect(tls('misconfig', 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N')).toBe(true); // 5.3
    });

    it('a file share or remote shell misconfiguration needs no user interaction and no scope change; a remote shell is network-bound', () => {
      const cfg = (comp: string, body: string): boolean => vectorFits(V(body), 'misconfig', `${comp} Insecure default configuration in Larkspur Portal ${comp}`);
      for (const comp of ['file share permissions', 'remote shell settings']) {
        expect(cfg(comp, 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N'), `${comp} UI:R`).toBe(false); // 6.5
        expect(cfg(comp, 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), `${comp} UI:R/S:C`).toBe(false); // 6.1 XSS shape
        expect(cfg(comp, 'AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H'), `${comp} S:C`).toBe(false);
        expect(cfg(comp, 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), `${comp} plain`).toBe(true);
      }
      expect(cfg('remote shell settings', 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')).toBe(false);
      expect(cfg('remote shell settings', 'AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(false);
    });

    it('file share permissions need a network vector and a confidentiality or integrity impact', () => {
      const fs = (body: string): boolean => vectorFits(V(body), 'misconfig', 'file share permissions Insecure default configuration in Larkspur Portal file share permissions');
      expect(fs('AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')).toBe(false); // 5.5 local
      expect(fs('AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(false);
      expect(fs('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L')).toBe(false); // 5.3 availability only
      expect(fs('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H')).toBe(false);
      for (const body of [
        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // 9.8
        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', // 7.5
        'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', // 6.5
        'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', // 7.3
        'AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', // 4.3
        'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', // 5.3
        'AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', // 4.7
      ]) expect(fs(body), body).toBe(true);
    });

    it('remote shell settings need at least two of C, I, A impacts', () => {
      const rs = (body: string): boolean => vectorFits(V(body), 'misconfig', 'remote shell settings Insecure default configuration in Larkspur Portal remote shell settings');
      for (const body of [
        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', // 7.5
        'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', // 6.5
        'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', // 5.3
        'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', // 5.3
        'AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', // 4.3
      ]) expect(rs(body), body).toBe(false);
      for (const body of [
        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', // 9.8
        'AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', // 7.2
        'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', // 7.3
        'AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', // 4.7
      ]) expect(rs(body), body).toBe(true);
    });

    it('a database listener is network-bound and needs no user interaction and no scope change; the catalogue lists it instead of remote shell settings', () => {
      const dl = (body: string): boolean => vectorFits(V(body), 'misconfig', 'database listener settings Insecure default configuration in Larkspur Portal database listener settings');
      expect(dl('AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N')).toBe(false);
      expect(dl('AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')).toBe(false);
      expect(dl('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBe(true);
      expect(COMPONENTS.misconfig).toContain('database listener settings');
      expect(COMPONENTS.misconfig).not.toContain('remote shell settings');
    });

    it('rce needs no user interaction unless a user loads or opens attacker content', () => {
      const ui = 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H';
      for (const comp of ['deserialization endpoint', 'template engine', 'file-upload handler', 'update service', 'request parser'])
        expect(vectorFits(V(ui), 'rce', `${comp} Remote code execution in Larkspur Portal ${comp}`), comp).toBe(false);
      for (const comp of ['plugin loader', 'scripting console', 'document preview handler', 'project file importer'])
        expect(vectorFits(V(ui), 'rce', `${comp} Remote code execution in Larkspur Portal ${comp}`), comp).toBe(true);
      expect(vectorFits(V('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 'rce', 'template engine Remote code execution in Larkspur Portal template engine')).toBe(true);
    });

    it('rce may be local where a user opens attacker content: a console, a document preview handler, a project file importer', () => {
      const local = 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H';
      for (const comp of ['scripting console', 'document preview handler', 'project file importer'])
        expect(vectorFits(V(local), 'rce', `${comp} Remote code execution in Larkspur Portal ${comp}`), comp).toBe(true);
      for (const comp of ['template engine', 'file-upload handler', 'update service', 'deserialization endpoint'])
        expect(vectorFits(V(local), 'rce', `${comp} Remote code execution in Larkspur Portal ${comp}`), comp).toBe(false);
      expect(COMPONENTS.rce).toEqual(expect.arrayContaining(['document preview handler', 'project file importer']));
    });

    it('an info-leak never changes scope on an error handler or a log viewer, and no catalogue shape pairs them', () => {
      const sc = 'AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N';
      for (const comp of ['error handler', 'log viewer'])
        expect(vectorFits(V(sc), 'info-leak', `${comp} Information disclosure in Larkspur Portal ${comp}`), comp).toBe(false);
      for (const [body, classes] of SHAPE_DEFS) if (body.includes('/S:C/')) expect(classes, body).not.toContain('info-leak');
    });
  });

  it('no single (class, component) pair exceeds about twice the mean share of its class over the sweep', () => {
    const SHARE_SWEEP = 600;
    const pairs = new Map<string, number>();
    const perClass = new Map<string, number>();
    for (let i = 0; i < SHARE_SWEEP; i++) {
      const c = generateCatalogue(`share-${i}`, MIN_REFERENCE_DATE + ((i * 7919) % 1500) * DAY);
      for (const e of c.entries) {
        pairs.set(`${e.vulnClass}/${e.component}`, (pairs.get(`${e.vulnClass}/${e.component}`) ?? 0) + 1);
        perClass.set(e.vulnClass, (perClass.get(e.vulnClass) ?? 0) + 1);
      }
    }
    const heavy: string[] = [];
    for (const [cls, list] of Object.entries(COMPONENTS)) {
      const mean = (perClass.get(cls) ?? 0) / list.length; // the class's mean count per component
      for (const comp of list) {
        const ratio = (pairs.get(`${cls}/${comp}`) ?? 0) / mean;
        if (ratio > 2.25) heavy.push(`${cls}/${comp} ${ratio.toFixed(2)}x`);
      }
    }
    expect(heavy).toEqual([]);
  }, 120_000);
});
