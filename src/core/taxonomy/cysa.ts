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

// The CS0-003 objectives the vulnerability-management mode trains. `title` is the
// official wording, verbatim (DESIGN §1); `short` is the label for bars and tables.
export interface CysaObjective {
  id: string;
  domain: string;
  title: string;
  short: string;
}

export const CYSA_OBJECTIVES: CysaObjective[] = [
  { id: '2.1', domain: '2.0', title: 'Given a scenario, implement vulnerability scanning methods and concepts.', short: 'Vulnerability scanning methods' },
  { id: '2.2', domain: '2.0', title: 'Given a scenario, analyze output from vulnerability assessment tools.', short: 'Assessment tool output' },
  { id: '2.3', domain: '2.0', title: 'Given a scenario, analyze data to prioritize vulnerabilities.', short: 'Prioritizing vulnerabilities' },
  { id: '2.4', domain: '2.0', title: 'Given a scenario, recommend controls to mitigate attacks and software vulnerabilities.', short: 'Mitigating controls' },
  { id: '2.5', domain: '2.0', title: 'Explain concepts related to vulnerability response, handling, and management.', short: 'Vulnerability response and management' },
  { id: '4.1', domain: '4.0', title: 'Explain the importance of vulnerability management reporting and communication.', short: 'Vulnerability management reporting' },
];

const OBJECTIVE_MAP = new Map(CYSA_OBJECTIVES.map((o) => [o.id, o]));

export function cysaObjective(id: string): CysaObjective | undefined {
  return OBJECTIVE_MAP.get(id);
}

// "2.3 Prioritizing vulnerabilities"
export function objectiveLabel(id: string): string {
  const o = OBJECTIVE_MAP.get(id);
  return o ? `${o.id} ${o.short}` : id;
}

const DOMAIN_MAP = new Map(CYSA_DOMAINS.map((d) => [d.id, d]));

export function cysaDomain(id: string): CysaDomain | undefined {
  return DOMAIN_MAP.get(id);
}

export function cysaLabel(id: string): string {
  const d = DOMAIN_MAP.get(id);
  return d ? `${d.id} ${d.name}` : id;
}
