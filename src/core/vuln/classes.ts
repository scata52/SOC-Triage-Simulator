// Vulnerability classes and their labels. Kept in their own module so coherence.ts
// and catalogue.ts can both import them without importing each other.

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
