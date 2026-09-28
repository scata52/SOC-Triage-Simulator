import type { CysaDomain } from '../types.ts';

// CompTIA CySA+ (CS0-003) exam domains and their exam weightings.
export const CYSA_DOMAINS: CysaDomain[] = [
  {
    id: '1.0',
    name: 'Security Operations',
    blurb: 'System/network architecture concepts, threat intelligence, and analysis of malicious activity — the day-to-day of monitoring and triage.',
  },
  {
    id: '2.0',
    name: 'Vulnerability Management',
    blurb: 'Implementing and analysing vulnerability assessment tools, prioritising vulnerabilities, and controls to mitigate them.',
  },
  {
    id: '3.0',
    name: 'Incident Response and Management',
    blurb: 'Attack methodology frameworks, performing incident response, and the incident management lifecycle.',
  },
  {
    id: '4.0',
    name: 'Reporting and Communication',
    blurb: 'Communicating vulnerability and incident findings to stakeholders, metrics, and reporting.',
  },
];

const DOMAIN_MAP = new Map(CYSA_DOMAINS.map((d) => [d.id, d]));

export function cysaDomain(id: string): CysaDomain | undefined {
  return DOMAIN_MAP.get(id);
}

export function cysaLabel(id: string): string {
  const d = DOMAIN_MAP.get(id);
  return d ? `${d.id} ${d.name}` : id;
}
