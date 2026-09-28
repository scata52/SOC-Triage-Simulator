// Cities and a synthetic GeoIP registry. The registry maps each allocated
// documentation-range address to a city, country and a private-use ASN with an
// invented network name — enough for sign-in logs to carry believable location
// data without describing any real network.

import type { Rng } from '../rng.ts';
import { privateAsn } from './addresses.ts';

export interface GeoCity {
  city: string;
  country: string;
  cc: string;
  lat: number;
  lon: number;
  utcOffset: number; // hours, in the simulated season
}

export const CITIES: readonly GeoCity[] = [
  { city: 'Munich', country: 'Germany', cc: 'DE', lat: 48.137, lon: 11.575, utcOffset: 2 },
  { city: 'Berlin', country: 'Germany', cc: 'DE', lat: 52.52, lon: 13.405, utcOffset: 2 },
  { city: 'Frankfurt', country: 'Germany', cc: 'DE', lat: 50.11, lon: 8.682, utcOffset: 2 },
  { city: 'Hamburg', country: 'Germany', cc: 'DE', lat: 53.551, lon: 9.994, utcOffset: 2 },
  { city: 'Vienna', country: 'Austria', cc: 'AT', lat: 48.208, lon: 16.373, utcOffset: 2 },
  { city: 'Zurich', country: 'Switzerland', cc: 'CH', lat: 47.377, lon: 8.542, utcOffset: 2 },
  { city: 'London', country: 'United Kingdom', cc: 'GB', lat: 51.507, lon: -0.127, utcOffset: 1 },
  { city: 'Manchester', country: 'United Kingdom', cc: 'GB', lat: 53.481, lon: -2.243, utcOffset: 1 },
  { city: 'Dublin', country: 'Ireland', cc: 'IE', lat: 53.349, lon: -6.26, utcOffset: 1 },
  { city: 'Amsterdam', country: 'Netherlands', cc: 'NL', lat: 52.37, lon: 4.895, utcOffset: 2 },
  { city: 'Paris', country: 'France', cc: 'FR', lat: 48.857, lon: 2.352, utcOffset: 2 },
  { city: 'Lyon', country: 'France', cc: 'FR', lat: 45.764, lon: 4.835, utcOffset: 2 },
  { city: 'Madrid', country: 'Spain', cc: 'ES', lat: 40.417, lon: -3.703, utcOffset: 2 },
  { city: 'Barcelona', country: 'Spain', cc: 'ES', lat: 41.385, lon: 2.173, utcOffset: 2 },
  { city: 'Milan', country: 'Italy', cc: 'IT', lat: 45.464, lon: 9.19, utcOffset: 2 },
  { city: 'Warsaw', country: 'Poland', cc: 'PL', lat: 52.23, lon: 21.011, utcOffset: 2 },
  { city: 'Prague', country: 'Czechia', cc: 'CZ', lat: 50.075, lon: 14.437, utcOffset: 2 },
  { city: 'Stockholm', country: 'Sweden', cc: 'SE', lat: 59.329, lon: 18.068, utcOffset: 2 },
  { city: 'Copenhagen', country: 'Denmark', cc: 'DK', lat: 55.676, lon: 12.568, utcOffset: 2 },
  { city: 'Lisbon', country: 'Portugal', cc: 'PT', lat: 38.722, lon: -9.139, utcOffset: 1 },
  { city: 'New York', country: 'United States', cc: 'US', lat: 40.713, lon: -74.006, utcOffset: -4 },
  { city: 'Ashburn', country: 'United States', cc: 'US', lat: 39.043, lon: -77.487, utcOffset: -4 },
  { city: 'Chicago', country: 'United States', cc: 'US', lat: 41.878, lon: -87.63, utcOffset: -5 },
  { city: 'San Francisco', country: 'United States', cc: 'US', lat: 37.775, lon: -122.419, utcOffset: -7 },
  { city: 'Toronto', country: 'Canada', cc: 'CA', lat: 43.651, lon: -79.347, utcOffset: -4 },
  { city: 'São Paulo', country: 'Brazil', cc: 'BR', lat: -23.55, lon: -46.633, utcOffset: -3 },
  { city: 'Lagos', country: 'Nigeria', cc: 'NG', lat: 6.524, lon: 3.379, utcOffset: 1 },
  { city: 'Johannesburg', country: 'South Africa', cc: 'ZA', lat: -26.204, lon: 28.047, utcOffset: 2 },
  { city: 'Istanbul', country: 'Türkiye', cc: 'TR', lat: 41.008, lon: 28.978, utcOffset: 3 },
  { city: 'Moscow', country: 'Russia', cc: 'RU', lat: 55.755, lon: 37.617, utcOffset: 3 },
  { city: 'Kyiv', country: 'Ukraine', cc: 'UA', lat: 50.45, lon: 30.523, utcOffset: 3 },
  { city: 'Dubai', country: 'United Arab Emirates', cc: 'AE', lat: 25.205, lon: 55.271, utcOffset: 4 },
  { city: 'Mumbai', country: 'India', cc: 'IN', lat: 19.076, lon: 72.877, utcOffset: 5.5 },
  { city: 'Singapore', country: 'Singapore', cc: 'SG', lat: 1.352, lon: 103.82, utcOffset: 8 },
  { city: 'Hong Kong', country: 'Hong Kong', cc: 'HK', lat: 22.319, lon: 114.17, utcOffset: 8 },
  { city: 'Manila', country: 'Philippines', cc: 'PH', lat: 14.6, lon: 120.98, utcOffset: 8 },
  { city: 'Tokyo', country: 'Japan', cc: 'JP', lat: 35.689, lon: 139.692, utcOffset: 9 },
  { city: 'Seoul', country: 'South Korea', cc: 'KR', lat: 37.566, lon: 126.978, utcOffset: 9 },
  { city: 'Sydney', country: 'Australia', cc: 'AU', lat: -33.868, lon: 151.209, utcOffset: 10 },
];

export const EUROPEAN_HQ_CODES = ['DE', 'AT', 'CH', 'GB', 'IE', 'NL', 'FR', 'ES', 'IT', 'PL', 'CZ', 'SE', 'DK', 'PT'];

export function cityByName(name: string): GeoCity {
  const c = CITIES.find((x) => x.city === name);
  if (!c) throw new Error(`Unknown city ${name}`);
  return c;
}

export function haversineKm(a: GeoCity, b: GeoCity): number {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const la1 = (a.lat * Math.PI) / 180;
  const la2 = (b.lat * Math.PI) / 180;
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin(dLon / 2) ** 2;
  return Math.round(2 * R * Math.asin(Math.min(1, Math.sqrt(h))));
}

export type NetworkKind = 'residential' | 'mobile' | 'hosting' | 'corporate' | 'anonymizer';

export interface GeoEntry {
  city: string;
  country: string;
  cc: string;
  asn: number;
  network: string; // invented network operator name
  kind: NetworkKind;
}

const NET_WORDS_A = ['Northgate', 'Bluefield', 'Silverline', 'Brightwave', 'Keystone', 'Harbor', 'Summit', 'Redstone', 'Lakeside', 'Cobalt', 'Granite', 'Evergreen', 'Beacon', 'Cedar', 'Ironbridge'];
const NET_WORDS_B: Record<NetworkKind, readonly string[]> = {
  residential: ['Broadband', 'Fiber', 'Cable', 'Telecom'],
  mobile: ['Mobile', 'Wireless', 'Cellular'],
  hosting: ['Hosting', 'Cloud', 'Datacenter', 'VPS'],
  corporate: ['Enterprise Networks'],
  anonymizer: ['Privacy Relay', 'Anon Transit'],
};

export function networkName(rng: Rng, kind: NetworkKind): string {
  return `${rng.pick(NET_WORDS_A)} ${rng.pick(NET_WORDS_B[kind])}`;
}

export function geoEntry(rng: Rng, city: GeoCity, kind: NetworkKind, network?: string, asn?: number): GeoEntry {
  return {
    city: city.city,
    country: city.country,
    cc: city.cc,
    asn: asn ?? privateAsn(rng),
    network: network ?? networkName(rng, kind),
    kind,
  };
}
