// Fictional vulnerability identifiers: SIMVULN-<4-digit year>-<5-digit serial>.
// The shape is deliberately different from the public identifier scheme used
// for real vulnerabilities, so a scenario id can never be mistaken for a real
// record (DESIGN section 9).

export const SIMVULN_PREFIX = 'SIMVULN';
export const SIMVULN_ID_PATTERN = /^SIMVULN-\d{4}-\d{5}$/;

export interface ParsedSimVulnId {
  year: number;
  serial: number;
}

export function formatSimVulnId(year: number, serial: number): string {
  if (!Number.isInteger(year) || year < 1000 || year > 9999) throw new RangeError(`SIMVULN year must be 4 digits, got ${year}`);
  if (!Number.isInteger(serial) || serial < 0 || serial > 99999) throw new RangeError(`SIMVULN serial must be 0..99999, got ${serial}`);
  return `${SIMVULN_PREFIX}-${year}-${String(serial).padStart(5, '0')}`;
}

export function isSimVulnId(value: string): boolean {
  return SIMVULN_ID_PATTERN.test(value);
}

export function parseSimVulnId(value: string): ParsedSimVulnId | null {
  if (!SIMVULN_ID_PATTERN.test(value)) return null;
  return { year: Number(value.slice(8, 12)), serial: Number(value.slice(13)) };
}
