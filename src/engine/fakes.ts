// Realistic synthetic data generators. Everything is seeded via the Rng so a
// given case is reproducible. A Faker holds one generated "environment" so all
// artifacts inside a single case agree (same company, AD domain, subnet, user).

import type { Rng } from './rng.ts';

export interface GeoCity {
  city: string;
  country: string;
  cc: string; // ISO country code
  lat: number;
  lon: number;
}

export interface Identity {
  first: string;
  last: string;
  username: string; // sAMAccountName style
  upn: string; // user principal name / email
  display: string;
}

export interface Environment {
  company: string;
  adDomain: string; // CORP.ACME.LOCAL
  emailDomain: string; // acme.com
  internalCidr: string; // 10.20.0.0/16
  internalPrefix: string; // "10.20"
  hqCity: GeoCity;
}

const FIRST_NAMES = [
  'James', 'Mary', 'Robert', 'Patricia', 'John', 'Jennifer', 'Michael', 'Linda',
  'David', 'Elizabeth', 'Sarah', 'Daniel', 'Laura', 'Thomas', 'Anna', 'Mark',
  'Julia', 'Peter', 'Sophie', 'Lukas', 'Emma', 'Noah', 'Mia', 'Leon', 'Hannah',
  'Priya', 'Arjun', 'Wei', 'Yuki', 'Omar', 'Fatima', 'Carlos', 'Sofia',
];

const LAST_NAMES = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis',
  'Martinez', 'Lopez', 'Wilson', 'Anderson', 'Taylor', 'Thomas', 'Moore', 'Lee',
  'Mueller', 'Schmidt', 'Fischer', 'Weber', 'Wagner', 'Becker', 'Hoffmann',
  'Nguyen', 'Patel', 'Kumar', 'Chen', 'Wang', 'Ali', 'Khan', 'Rossi', 'Novak',
];

const COMPANY_NAMES = [
  'Acme', 'Northwind', 'Contoso', 'Globex', 'Initech', 'Umbra', 'Meridian',
  'Vertex', 'Ironclad', 'Bluewave', 'Cinder', 'Halcyon', 'Kestrel', 'Lattice',
];

const COMPANY_SUFFIX = ['Corp', 'Industries', 'Systems', 'Logistics', 'Financial', 'Health', 'Retail', 'Labs'];

const SERVICE_ACCOUNTS = [
  'svc-backup', 'svc-sql', 'svc-sccm', 'svc-scan', 'svc-monitor', 'svc-iis',
  'svc-vault', 'svc-jenkins', 'svc-ldap', 'svc-veeam', 'svc-print',
];

const CITIES: GeoCity[] = [
  { city: 'Berlin', country: 'Germany', cc: 'DE', lat: 52.52, lon: 13.405 },
  { city: 'Munich', country: 'Germany', cc: 'DE', lat: 48.137, lon: 11.575 },
  { city: 'Frankfurt', country: 'Germany', cc: 'DE', lat: 50.11, lon: 8.682 },
  { city: 'London', country: 'United Kingdom', cc: 'GB', lat: 51.507, lon: -0.127 },
  { city: 'Amsterdam', country: 'Netherlands', cc: 'NL', lat: 52.37, lon: 4.895 },
  { city: 'Paris', country: 'France', cc: 'FR', lat: 48.857, lon: 2.352 },
  { city: 'Madrid', country: 'Spain', cc: 'ES', lat: 40.417, lon: -3.703 },
  { city: 'Warsaw', country: 'Poland', cc: 'PL', lat: 52.23, lon: 21.011 },
  { city: 'New York', country: 'United States', cc: 'US', lat: 40.713, lon: -74.006 },
  { city: 'Ashburn', country: 'United States', cc: 'US', lat: 39.043, lon: -77.487 },
  { city: 'San Francisco', country: 'United States', cc: 'US', lat: 37.775, lon: -122.419 },
  { city: 'Toronto', country: 'Canada', cc: 'CA', lat: 43.651, lon: -79.347 },
  { city: 'São Paulo', country: 'Brazil', cc: 'BR', lat: -23.55, lon: -46.633 },
  { city: 'Lagos', country: 'Nigeria', cc: 'NG', lat: 6.524, lon: 3.379 },
  { city: 'Moscow', country: 'Russia', cc: 'RU', lat: 55.755, lon: 37.617 },
  { city: 'Kyiv', country: 'Ukraine', cc: 'UA', lat: 50.45, lon: 30.523 },
  { city: 'Dubai', country: 'United Arab Emirates', cc: 'AE', lat: 25.205, lon: 55.271 },
  { city: 'Mumbai', country: 'India', cc: 'IN', lat: 19.076, lon: 72.877 },
  { city: 'Singapore', country: 'Singapore', cc: 'SG', lat: 1.352, lon: 103.82 },
  { city: 'Hong Kong', country: 'Hong Kong', cc: 'HK', lat: 22.319, lon: 114.17 },
  { city: 'Manila', country: 'Philippines', cc: 'PH', lat: 14.6, lon: 120.98 },
  { city: 'Sydney', country: 'Australia', cc: 'AU', lat: -33.868, lon: 151.209 },
  { city: 'Tokyo', country: 'Japan', cc: 'JP', lat: 35.689, lon: 139.692 },
  { city: 'Seoul', country: 'South Korea', cc: 'KR', lat: 37.566, lon: 126.978 },
];

// TLDs / patterns that read as suspicious for typosquat + newly-registered domains.
const SUSPICIOUS_TLDS = ['top', 'xyz', 'shop', 'live', 'click', 'zip', 'cam', 'support', 'help'];
const BRAND_LURES = ['microsoft', 'office365', 'docusign', 'sharepoint', 'onedrive', 'okta', 'paypal', 'dhl', 'ups'];

const LEGIT_PROCESSES = [
  'chrome.exe', 'msedge.exe', 'outlook.exe', 'teams.exe', 'explorer.exe',
  'svchost.exe', 'OneDrive.exe', 'excel.exe', 'winword.exe', 'code.exe',
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
  'python-requests/2.32.3',
  'curl/8.7.1',
  'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
];

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

export function haversineKm(a: GeoCity, b: GeoCity): number {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const la1 = (a.lat * Math.PI) / 180;
  const la2 = (b.lat * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return Math.round(2 * R * Math.asin(Math.min(1, Math.sqrt(h))));
}

export interface Faker {
  env: Environment;
  identity(): Identity;
  serviceAccount(): string;
  privateIp(): string;
  publicIp(): string;
  cityElsewhere(not: GeoCity): GeoCity;
  city(): GeoCity;
  workstation(): string;
  laptop(): string;
  server(role?: string): string;
  domainController(): string;
  legitProcess(): string;
  maliciousDomain(): string;
  legitExternalDomain(): string;
  md5(): string;
  sha256(): string;
  hex(length: number): string;
  guid(): string;
  mac(): string;
  userAgent(): string;
  port(): number;
  // Timestamp helpers around a per-case anchor time.
  anchorTime: Date;
  iso(offsetSec?: number): string; // 2026-09-18T14:03:22Z
  syslog(offsetSec?: number): string; // Sep 18 14:03:22
  winTime(offsetSec?: number): string; // 9/18/2026 2:03:22 PM
  clock(offsetSec?: number): string; // 14:03:22
}

export function createFaker(rng: Rng): Faker {
  const companyBase = rng.pick(COMPANY_NAMES);
  const company = `${companyBase} ${rng.pick(COMPANY_SUFFIX)}`;
  const emailDomain = `${slug(companyBase)}.com`;
  const adDomain = `CORP.${companyBase.toUpperCase()}.LOCAL`;
  const octet2 = rng.int(16, 60);
  const internalPrefix = `10.${octet2}`;
  const hqCity = rng.pick(CITIES.filter((c) => ['DE', 'GB', 'US', 'NL', 'FR'].includes(c.cc)));

  const env: Environment = {
    company,
    adDomain,
    emailDomain,
    internalCidr: `10.${octet2}.0.0/16`,
    internalPrefix,
    hqCity,
  };

  // Anchor "now" for the case: a plausible recent weekday time.
  const anchor = new Date(Date.UTC(2026, 8, rng.int(1, 26), rng.int(6, 20), rng.int(0, 59), rng.int(0, 59)));

  function shift(offsetSec: number): Date {
    return new Date(anchor.getTime() + offsetSec * 1000);
  }

  function identity(): Identity {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const username = `${first.toLowerCase()}.${last.toLowerCase()}`;
    return {
      first,
      last,
      username,
      upn: `${username}@${emailDomain}`,
      display: `${first} ${last}`,
    };
  }

  function privateIp(): string {
    return `${internalPrefix}.${rng.int(1, 250)}.${rng.int(2, 250)}`;
  }

  function publicIp(): string {
    // Avoid private/reserved ranges; keep first octet in routable public space.
    const a = rng.pickWeighted([
      { value: rng.int(11, 126), weight: 3 },
      { value: rng.int(128, 171), weight: 3 },
      { value: rng.int(173, 191), weight: 2 },
      { value: rng.int(193, 223), weight: 3 },
    ]);
    return `${a}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`;
  }

  const faker: Faker = {
    env,
    anchorTime: anchor,
    identity,
    serviceAccount: () => rng.pick(SERVICE_ACCOUNTS),
    privateIp,
    publicIp,
    city: () => rng.pick(CITIES),
    cityElsewhere: (not) => rng.pick(CITIES.filter((c) => c.city !== not.city && c.cc !== not.cc)),
    workstation: () => `WKS-${rng.hex(2).toUpperCase()}${rng.int(100, 999)}`,
    laptop: () => `LT-${rng.pick(['FIN', 'HR', 'ENG', 'SAL', 'OPS', 'MKT'])}-${rng.int(10, 99)}`,
    server: (role) => `SRV-${(role ?? rng.pick(['APP', 'FILE', 'WEB', 'DB', 'PRINT'])).toUpperCase()}${rng.int(1, 9).toString().padStart(2, '0')}`,
    domainController: () => `DC${rng.int(1, 3).toString().padStart(2, '0')}`,
    legitProcess: () => rng.pick(LEGIT_PROCESSES),
    legitExternalDomain: () =>
      rng.pick(['github.com', 'update.microsoft.com', 'slack.com', 'zoom.us', 'dropbox.com', 'salesforce.com', 'atlassian.net']),
    maliciousDomain: () => {
      const style = rng.int(0, 2);
      if (style === 0) {
        // brand lure + suspicious TLD
        return `${rng.pick(BRAND_LURES)}-${rng.pick(['secure', 'login', 'verify', 'account'])}.${rng.pick(SUSPICIOUS_TLDS)}`;
      }
      if (style === 1) {
        // DGA-ish random label
        return `${rng.hex(rng.int(10, 16))}.${rng.pick(SUSPICIOUS_TLDS)}`;
      }
      // typosquat of the company or a brand
      const base = rng.bool() ? slug(companyBase) : rng.pick(BRAND_LURES);
      const typo = base.length > 3 ? base.slice(0, -1) + base.slice(-1) + rng.pick(['s', 'i', '1', 'o']) : base + 'x';
      return `${typo}.${rng.pick(SUSPICIOUS_TLDS)}`;
    },
    md5: () => rng.hex(32),
    sha256: () => rng.hex(64),
    hex: (length) => rng.hex(length),
    guid: () =>
      `${rng.hex(8)}-${rng.hex(4)}-${rng.hex(4)}-${rng.hex(4)}-${rng.hex(12)}`,
    mac: () => Array.from({ length: 6 }, () => rng.hex(2)).join(':').toUpperCase(),
    userAgent: () => rng.pick(USER_AGENTS),
    port: () => rng.pick([22, 23, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5985, 5986, 8080, 8443]),
    iso: (offsetSec = 0) => shift(offsetSec).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    syslog: (offsetSec = 0) => {
      const d = shift(offsetSec);
      const mon = d.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
      const day = String(d.getUTCDate()).padStart(2, ' ');
      return `${mon} ${day} ${faker.clock(offsetSec)}`;
    },
    winTime: (offsetSec = 0) => {
      const d = shift(offsetSec);
      let h = d.getUTCHours();
      const ampm = h >= 12 ? 'PM' : 'AM';
      h = h % 12 || 12;
      const mm = String(d.getUTCMinutes()).padStart(2, '0');
      const ss = String(d.getUTCSeconds()).padStart(2, '0');
      return `${d.getUTCMonth() + 1}/${d.getUTCDate()}/${d.getUTCFullYear()} ${h}:${mm}:${ss} ${ampm}`;
    },
    clock: (offsetSec = 0) => {
      const d = shift(offsetSec);
      return [d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
        .map((n) => String(n).padStart(2, '0'))
        .join(':');
    },
  } as Faker;

  return faker;
}
