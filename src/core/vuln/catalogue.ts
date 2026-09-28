// Seeded fictional vulnerability catalogue (DESIGN section 6.2). Everything
// here is invented: SIMVULN ids, fictional vendors and products, CVSS 3.1
// vectors scored by our own calculator, and exploitation signals drawn from the
// simulated feeds Sim-KEV and Sim-EPSS. No real vulnerability record appears
// in this file or in anything it generates.
//
// Deterministic per (seed, referenceDate): all randomness flows from
// core/rng.ts, one fork per purpose so changing one stage does not shift the
// others.

import { createRng, type Rng } from '../rng.ts';
import { DAY } from '../logs/time.ts';
import { baseScore, severityOf, type CvssSeverity } from './cvss31.ts';
import { formatSimVulnId } from './ids.ts';

export type VulnClass = 'rce' | 'sqli' | 'auth-bypass' | 'info-leak' | 'dos' | 'misconfig';
export const VULN_CLASSES: readonly VulnClass[] = ['rce', 'sqli', 'auth-bypass', 'info-leak', 'dos', 'misconfig'];

export const VULN_CLASS_LABELS: Record<VulnClass, string> = {
  rce: 'Remote code execution',
  sqli: 'SQL injection',
  'auth-bypass': 'Authentication bypass',
  'info-leak': 'Information disclosure',
  dos: 'Denial of service',
  misconfig: 'Insecure default configuration',
};

// CVSS severity band of an entry (the catalogue has no "none" entries).
export type CatalogueBand = Exclude<CvssSeverity, 'none'>;

export interface CatalogueEntry {
  id: string; // SIMVULN-YYYY-NNNNN
  year: number; // the id's year; the entry was published in this UTC year
  vulnClass: VulnClass;
  vendor: string; // fictional
  product: string; // fictional
  component: string;
  title: string;
  vector: string; // CVSS:3.1/...
  base: number; // cvss31.baseScore(vector)
  severity: CatalogueBand;
  published: number; // epoch ms (UTC day start)
  knownExploited: boolean; // Sim-KEV listing
  knownExploitedAdded: number | null; // epoch ms, when listed
  epss: number; // Sim-EPSS probability, 0..1
  epssPercentile: number; // 0..1, always from the all-CVE anchor table
  publicExploit: boolean;
  vendorFix: boolean;
  fixedVersion: string; // first fixed version of the product
}

export interface VulnCatalogue {
  seed: string;
  referenceDate: number; // epoch ms: "today" for the newly-published rule
  entries: readonly CatalogueEntry[]; // sorted by id
}

// ---- Sim-EPSS -------------------------------------------------------------

// [percentile, score] anchors, percentile ascending. Scores are interpolated
// log-linearly between anchors (calibration in DESIGN sections 6.2 and 11).
export type EpssAnchor = readonly [percentile: number, score: number];

// First table: all vulnerabilities (and the one every displayed percentile uses).
export const SIM_EPSS_ALL: readonly EpssAnchor[] = [
  [0, 0.0005],
  [0.1, 0.0021],
  [0.25, 0.0034],
  [0.5, 0.0067],
  [0.75, 0.016],
  [0.9, 0.039],
  [0.95, 0.088],
  [0.99, 0.55],
  [1, 0.98],
];

// Second table: entries on the Sim-KEV list.
export const SIM_EPSS_LISTED: readonly EpssAnchor[] = [
  [0, 0.0023],
  [0.1, 0.023],
  [0.25, 0.09],
  [0.5, 0.49],
  [0.75, 0.92],
  [1, 0.997],
];

// Inverse CDF: the score at percentile u (0..1) of a table.
export function simEpssScoreAt(table: readonly EpssAnchor[], u: number): number {
  const p = Math.min(Math.max(u, 0), 1);
  for (let i = 0; i < table.length - 1; i++) {
    const [p0, s0] = table[i];
    const [p1, s1] = table[i + 1];
    if (p <= p1) {
      const t = (p - p0) / (p1 - p0);
      if (t <= 0) return s0; // exact at the anchors
      if (t >= 1) return s1;
      return Math.exp(Math.log(s0) + t * (Math.log(s1) - Math.log(s0)));
    }
  }
  return table[table.length - 1][1];
}

// CDF of the all-CVE table: the percentile (0..1) of a score.
export function simEpssPercentile(score: number): number {
  const table = SIM_EPSS_ALL;
  if (score <= table[0][1]) return 0;
  if (score >= table[table.length - 1][1]) return 1;
  for (let i = 0; i < table.length - 1; i++) {
    const [p0, s0] = table[i];
    const [p1, s1] = table[i + 1];
    if (score < s1) {
      const t = (Math.log(score) - Math.log(s0)) / (Math.log(s1) - Math.log(s0));
      return p0 + t * (p1 - p0);
    }
  }
  return 1;
}

// The percentile as shown to the learner ("31st"): a whole number 0..100.
export function simEpssPercentileRank(score: number): number {
  return Math.round(simEpssPercentile(score) * 100);
}

const round4 = (x: number): number => Math.round(x * 10000) / 10000;
const round2 = (x: number): number => Math.round(x * 100) / 100;

export interface SimEpssOptions {
  listed?: boolean; // on the Sim-KEV list: draw from the second table
  newlyPublished?: boolean; // < 30 days old: lower half of the first table, whatever the listing
}

export function sampleSimEpss(rng: Rng, options: SimEpssOptions = {}): number {
  const u = rng.next();
  if (options.newlyPublished) return round4(simEpssScoreAt(SIM_EPSS_ALL, u * 0.5));
  return round4(simEpssScoreAt(options.listed ? SIM_EPSS_LISTED : SIM_EPSS_ALL, u));
}

// ---- Vector shapes --------------------------------------------------------

// Vector shapes by impact profile. Weights favour the shapes most common among
// real-world scores (base 7.5, 6.5, 8.8, 7.8, 9.8, 5.3). The severity band of
// each shape comes from the calculator, never from a hand-typed label.
type ShapeDef = readonly [body: string, classes: readonly VulnClass[], weight: number];

const SHAPE_DEFS: readonly ShapeDef[] = [
  // 9.0-10.0
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', ['rce', 'sqli', 'auth-bypass', 'misconfig'], 8], // 9.8
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', ['rce', 'auth-bypass'], 1], // 9.9
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', ['sqli', 'auth-bypass'], 2], // 9.1
  ['AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', ['rce'], 1], // 9.6
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N', ['sqli', 'auth-bypass'], 1], // 9.6
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', ['rce'], 1], // 10.0
  // 7.0-8.9
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', ['info-leak', 'sqli', 'misconfig'], 5], // 7.5
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', ['dos'], 6], // 7.5
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', ['rce', 'sqli', 'auth-bypass'], 5], // 8.8
  ['AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', ['rce'], 3], // 8.8
  ['AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', ['rce'], 3], // 7.8
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', ['rce', 'auth-bypass', 'misconfig'], 3], // 7.8
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', ['rce', 'auth-bypass'], 1], // 8.1
  ['AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', ['rce', 'misconfig'], 1], // 7.2
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N', ['info-leak', 'sqli'], 1], // 7.7
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N', ['sqli', 'auth-bypass'], 1], // 8.2
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L', ['auth-bypass', 'misconfig'], 1], // 7.3
  // 4.0-6.9
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', ['info-leak', 'sqli', 'misconfig'], 5], // 6.5
  ['AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N', ['info-leak', 'misconfig'], 3], // 6.5
  ['AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', ['info-leak', 'misconfig', 'auth-bypass'], 2], // 6.1
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', ['dos', 'misconfig'], 5], // 5.3
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', ['info-leak', 'misconfig'], 5], // 5.3
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', ['auth-bypass', 'misconfig'], 2], // 4.3
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', ['dos'], 3], // 5.5
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', ['info-leak', 'misconfig'], 2], // 5.5
  ['AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', ['rce', 'misconfig'], 1], // 4.2
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', ['sqli', 'auth-bypass'], 1], // 6.4
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', ['dos'], 1], // 5.9
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N', ['auth-bypass', 'sqli'], 2], // 5.4
  ['AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H', ['rce'], 1], // 6.7
  ['AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', ['rce', 'misconfig'], 1], // 4.7
  // 0.1-3.9
  ['AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', ['info-leak', 'misconfig'], 3], // 3.1
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', ['info-leak', 'misconfig'], 3], // 3.3
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L', ['dos'], 2], // 3.3
  ['AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N', ['info-leak'], 1], // 2.2
  ['AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', ['info-leak', 'misconfig'], 1], // 2.4
  ['AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:L/A:N', ['auth-bypass', 'misconfig'], 1], // 2.3
  ['AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N', ['auth-bypass', 'sqli'], 1], // 3.0
];

interface Shape {
  vector: string;
  classes: readonly VulnClass[];
  weight: number;
  band: CatalogueBand;
}

const SHAPES: readonly Shape[] = SHAPE_DEFS.map(([body, classes, weight]) => {
  const vector = `CVSS:3.1/${body}`;
  const band = severityOf(baseScore(vector));
  if (band === 'none') throw new Error(`catalogue shape scores 0: ${vector}`);
  return { vector, classes, weight, band };
});

function shapesFor(band: CatalogueBand, vulnClass: VulnClass): Shape[] {
  return SHAPES.filter((s) => s.band === band && s.classes.includes(vulnClass));
}

// Classes that have at least one vector shape in a band.
function feasibleClasses(band: CatalogueBand): VulnClass[] {
  return VULN_CLASSES.filter((c) => shapesFor(band, c).length > 0);
}

// ---- Fictional names ------------------------------------------------------

interface ProductDef {
  vendor: string;
  product: string;
}

const PRODUCTS: readonly ProductDef[] = [
  { vendor: 'Quillon Software', product: 'Larkspur Portal' },
  { vendor: 'Ashgrove Labs', product: 'Ironbark Wiki' },
  { vendor: 'Northmere Systems', product: 'Wrenwick Relay' },
  { vendor: 'Larkfield Software', product: 'Foxglove Helpdesk' },
  { vendor: 'Tallowfield Networks', product: 'Sablecrest Gateway' },
  { vendor: 'Brackenridge Data', product: 'Tamarind Backup' },
  { vendor: 'Ferrowick Industries', product: 'Copperfield Print Server' },
  { vendor: 'Tallowfield Networks', product: 'Marrowgate Proxy' },
  { vendor: 'Quillon Software', product: 'Quillon Forms' },
  { vendor: 'Ombrelune Digital', product: 'Ombrelune Files' },
  { vendor: 'Harrowgate Tech', product: 'Harrowgate Directory Sync' },
  { vendor: 'Pinecrest Analytics', product: 'Pinecrest Dashboards' },
  { vendor: 'Vantorn Corp', product: 'Vantorn Build Runner' },
  { vendor: 'Wexcombe Cloud', product: 'Wexcombe Object Store' },
  { vendor: 'Brackenridge Data', product: 'Brackenridge DB Console' },
  { vendor: 'Larkfield Software', product: 'Thistledown CMS' },
  { vendor: 'Ferrowick Industries', product: 'Cinderpath Scheduler' },
  { vendor: 'Harrowgate Tech', product: 'Dunmore Badge Manager' },
  { vendor: 'Northmere Systems', product: 'Elderfen Chat Server' },
  { vendor: 'Ashgrove Labs', product: 'Fenwick Inventory Agent' },
  { vendor: 'Tallowfield Networks', product: 'Gallowglass Firewall Manager' },
  { vendor: 'Pinecrest Analytics', product: 'Hollowmere Reporting' },
  { vendor: 'Vantorn Corp', product: 'Ivorygate Payments Adapter' },
  { vendor: 'Wexcombe Cloud', product: 'Kestrelmoor Telemetry Agent' },
];

const COMPONENTS: Record<VulnClass, readonly string[]> = {
  rce: ['template engine', 'file-upload handler', 'update service', 'plugin loader', 'deserialization endpoint', 'scripting console'],
  sqli: ['search endpoint', 'report filter', 'login form', 'export module', 'API query parameter', 'audit viewer'],
  'auth-bypass': ['session handler', 'SSO callback', 'password reset flow', 'API token check', 'admin console', 'license service'],
  'info-leak': ['debug endpoint', 'backup file exposure', 'error handler', 'directory listing', 'metrics endpoint', 'log viewer'],
  dos: ['request parser', 'certificate handler', 'compression module', 'queue worker', 'protocol negotiator', 'image renderer'],
  misconfig: ['default credentials', 'TLS settings', 'permissions template', 'management interface', 'cross-origin policy', 'installer profile'],
};

const CLASS_WEIGHT: Record<VulnClass, number> = { rce: 3, sqli: 2, 'auth-bypass': 2, 'info-leak': 2, dos: 2, misconfig: 2 };

// ---- Catalogue parameters (DESIGN section 6.2) ----------------------------

export const CATALOGUE_SIZE = 60;
export const SIM_KEV_COUNT = 6;
export const NEWLY_PUBLISHED_DAYS = 30;

// Whole-percent shares of the CVSS mix, assigned by quota (largest remainder),
// so the mix holds for every seed rather than on average.
export const BAND_MIX_PERCENT: Readonly<Record<CatalogueBand, number>> = { critical: 15, high: 40, medium: 40, low: 5 };

// How the six Sim-KEV entries spread over severity bands (each has a Medium).
const KEV_PATTERNS: readonly Readonly<Record<CatalogueBand, number>>[] = [
  { critical: 2, high: 3, medium: 1, low: 0 },
  { critical: 3, high: 2, medium: 1, low: 0 },
  { critical: 2, high: 2, medium: 2, low: 0 },
];
const KEV_LEGACY = 2; // a third of the Sim-KEV entries carry an id year <= 2019
const OTHER_LEGACY = 13; // further old ids among the rest (15 of 60 in all)
const NEWLY_PUBLISHED = 5;
const LEGACY_YEARS: readonly [number, number] = [2012, 2019];
const FIRST_RECENT_YEAR = 2020;
// 2021-01-01: keeps the "recent" date range (2020-01-01 .. reference - 30 days) non-empty.
export const MIN_REFERENCE_DATE = Date.UTC(2021, 0, 1);

const BAND_ORDER: readonly CatalogueBand[] = ['critical', 'high', 'medium', 'low'];

function quotaCounts(total: number): Record<CatalogueBand, number> {
  const counts = {} as Record<CatalogueBand, number>;
  const remainders: { band: CatalogueBand; rem: number }[] = [];
  let assigned = 0;
  for (const band of BAND_ORDER) {
    const exact = (BAND_MIX_PERCENT[band] * total) / 100;
    counts[band] = Math.floor(exact);
    assigned += counts[band];
    remainders.push({ band, rem: exact - counts[band] });
  }
  remainders.sort((a, b) => b.rem - a.rem); // stable: ties keep BAND_ORDER
  for (let i = 0; assigned < total; i = (i + 1) % remainders.length, assigned++) counts[remainders[i].band]++;
  return counts;
}

type AgeGroup = 'legacy' | 'recent' | 'new';

export function generateCatalogue(seed: string | number, referenceDate: number): VulnCatalogue {
  if (!Number.isFinite(referenceDate) || referenceDate < MIN_REFERENCE_DATE) {
    throw new RangeError('referenceDate must be an epoch-ms instant on or after 2021-01-01');
  }
  const root = createRng(`vuln-catalogue/${seed}`);
  const n = CATALOGUE_SIZE;
  const refDay = Math.floor(referenceDate / DAY) * DAY;

  // 1. Severity bands by quota, shuffled over the slots.
  const quota = quotaCounts(n);
  const bandList: CatalogueBand[] = BAND_ORDER.flatMap((b) => Array<CatalogueBand>(quota[b]).fill(b));
  const bands = root.fork('bands').shuffle(bandList);
  const slotsOf = (band: CatalogueBand): number[] => bands.flatMap((b, i) => (b === band ? [i] : []));

  // 2. Sim-KEV listings: exactly six, spread over bands by a per-seed pattern.
  const kevRng = root.fork('kev');
  const pattern = kevRng.pick(KEV_PATTERNS);
  const kevSlots = new Set<number>();
  for (const band of BAND_ORDER) for (const slot of kevRng.sample(slotsOf(band), pattern[band])) kevSlots.add(slot);
  const kevList = [...kevSlots].sort((a, b) => a - b);

  // 3. Age groups: legacy (id year <= 2019), newly published (< 30 days), recent.
  const groupRng = root.fork('groups');
  const group: AgeGroup[] = Array<AgeGroup>(n).fill('recent');
  for (const slot of groupRng.sample(kevList, KEV_LEGACY)) group[slot] = 'legacy';
  const others = Array.from({ length: n }, (_, i) => i).filter((i) => !kevSlots.has(i));
  const legacyOthers = groupRng.sample(others, OTHER_LEGACY);
  for (const slot of legacyOthers) group[slot] = 'legacy';
  const legacySet = new Set(legacyOthers);
  for (const slot of groupRng.sample(
    others.filter((i) => !legacySet.has(i)),
    NEWLY_PUBLISHED,
  ))
    group[slot] = 'new';

  // 4. Vulnerability class per slot: within a band, first one of each feasible
  // class (so all six classes appear), then weighted draws.
  const classRng = root.fork('class');
  const classes: VulnClass[] = Array<VulnClass>(n);
  for (const band of BAND_ORDER) {
    const slots = slotsOf(band);
    const feasible = feasibleClasses(band);
    const cover = classRng.shuffle(feasible);
    slots.forEach((slot, k) => {
      classes[slot] =
        k < cover.length ? cover[k] : classRng.pickWeighted(feasible.map((c) => ({ value: c, weight: CLASS_WEIGHT[c] })));
    });
  }

  // 5. Vector per slot, favouring the common shapes; base from the calculator.
  const vectorRng = root.fork('vectors');
  const vectors = classes.map((cls, slot) =>
    vectorRng.pickWeighted(shapesFor(bands[slot], cls).map((s) => ({ value: s.vector, weight: s.weight }))),
  );

  // 6. Names: a unique (product, component) per class, so titles are unique.
  const nameRng = root.fork('names');
  const usedNames = new Set<string>();
  const names = classes.map((cls) => {
    const candidates: { product: ProductDef; component: string }[] = [];
    for (const product of PRODUCTS)
      for (const component of COMPONENTS[cls]) if (!usedNames.has(`${cls}/${product.product}/${component}`)) candidates.push({ product, component });
    const pick = nameRng.pick(candidates);
    usedNames.add(`${cls}/${pick.product.product}/${pick.component}`);
    return pick;
  });

  // 7. Dates, ids and feed values, in slot order.
  const dateRng = root.fork('dates');
  const idRng = root.fork('ids');
  const feedRng = root.fork('feeds');
  const maxRecentAge = Math.floor((refDay - Date.UTC(FIRST_RECENT_YEAR, 0, 1)) / DAY);
  const usedIds = new Set<string>();
  const entries: CatalogueEntry[] = [];

  for (let slot = 0; slot < n; slot++) {
    let published: number;
    if (group[slot] === 'legacy') {
      published = Date.UTC(dateRng.int(LEGACY_YEARS[0], LEGACY_YEARS[1]), 0, 1) + dateRng.int(0, 364) * DAY;
    } else if (group[slot] === 'new') {
      published = refDay - dateRng.int(1, NEWLY_PUBLISHED_DAYS - 1) * DAY;
    } else {
      published = refDay - dateRng.int(NEWLY_PUBLISHED_DAYS + 1, maxRecentAge) * DAY;
    }
    const year = new Date(published).getUTCFullYear();
    let id: string;
    do id = formatSimVulnId(year, idRng.int(10000, 59999));
    while (usedIds.has(id));
    usedIds.add(id);

    const listed = kevSlots.has(slot);
    const isNew = group[slot] === 'new';
    const epss = sampleSimEpss(feedRng, { listed, newlyPublished: isNew });
    const ageDays = Math.floor((refDay - published) / DAY);
    const addedAfter = feedRng.int(1, Math.min(365, ageDays - 1));
    const exploitRoll = feedRng.next();
    const fixRoll = feedRng.next();
    const publicExploit = exploitRoll < (listed ? 0.85 : epss >= 0.05 ? 0.5 : 0.06);
    const noFixOdds = group[slot] === 'legacy' ? 0.2 : isNew ? 0.3 : 0.05;
    const fixedVersion = `${feedRng.int(1, 9)}.${feedRng.int(0, 12)}.${feedRng.int(0, 9)}`;
    const base = baseScore(vectors[slot]);
    const { product, component } = names[slot];

    entries.push({
      id,
      year,
      vulnClass: classes[slot],
      vendor: product.vendor,
      product: product.product,
      component,
      title: `${VULN_CLASS_LABELS[classes[slot]]} in ${product.product} ${component}`,
      vector: vectors[slot],
      base,
      severity: bands[slot],
      published,
      knownExploited: listed,
      knownExploitedAdded: listed ? published + addedAfter * DAY : null,
      epss,
      epssPercentile: round2(simEpssPercentile(epss)),
      publicExploit,
      vendorFix: fixRoll >= noFixOdds,
      fixedVersion,
    });
  }

  entries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { seed: String(seed), referenceDate, entries };
}

// ---- Lookups --------------------------------------------------------------

export function findEntry(catalogue: VulnCatalogue, id: string): CatalogueEntry | undefined {
  return catalogue.entries.find((e) => e.id === id);
}

export function isNewlyPublished(entry: CatalogueEntry, referenceDate: number): boolean {
  return referenceDate - entry.published < NEWLY_PUBLISHED_DAYS * DAY;
}
