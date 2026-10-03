// The stakeholder-note rubric of every vulnerability template (WP6). The vulnerability matcher (vulnRubricHits) lowercases the note,
// turns every run of characters outside a-z0-9 into one space and tests each keyword, normalised the same way, as a substring of the
// note padded with a space at each end (a keyword with a space at its edge demands a word boundary there). What keeps the checklist
// honest is the keywords: a model note ticks all four items, a note without content ticks at most one, the other twin's model note
// ticks neither the risk nor the action item, the wrong-twin and negated notes of a reviewer's probes tick nothing they should not,
// the honest phrasings of the right answer tick their item (also in other word order, with possessive host names and with the clue stated
// as a negation), no keyword of one twin is contained in a keyword of the other, and a date ticks only when it is a date of the case.
import { describe, expect, it } from 'vitest';
import { vulnRubricHits } from '../../src/core/vuln/grade.ts';
import { VULN_CASE_TEMPLATES } from '../../src/core/vuln/templates/index.ts';
import type { VulnTemplate } from '../../src/core/vuln/model.ts';
import type { Corpus } from '../../src/core/logs/corpus.ts';
import { world } from '../helpers/scenario-check.ts';
import { buildFor, vulnRuns } from '../helpers/vuln-scenario-check.ts';

// VULN_RUBRIC_RUNS=200 sweeps more seeds (slow); the default is the 20 seeds every template is held to.
const RUNS = vulnRuns(Number(process.env.VULN_RUBRIC_RUNS ?? 20), 0);
const TEMPLATES: readonly VulnTemplate[] = VULN_CASE_TEMPLATES;
const ITEMS = ['owner', 'risk', 'action', 'date'] as const;

type RowObject = Record<string, unknown>;
function rows(corpus: Corpus, table: keyof Corpus['tables']): RowObject[] {
  const t = corpus.tables[table];
  return t.rows.map((r) => Object.fromEntries(t.columns.map((c, i) => [c, r[i]])) as RowObject);
}
const day = (ms: number | string): string => new Date(ms).toISOString().slice(0, 10);

// What a note can say about the case without the rubric's words: the teams that own the affected hosts and the change tickets, the
// dates of the calendar and the expiry of an approved exception that is still in force.
interface Facts {
  teams: string;
  next: string;
  cycle: string;
  expiry: string | null;
}
type Case = { facts: Facts; rubric: { id: string; text: string; keywords: string[] }[] };
const cache = new Map<string, Case>();
function factsOf(t: VulnTemplate, seed: { world: string; seed: string }): Case {
  const key = `${t.id}|${seed.world}|${seed.seed}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const built = buildFor(t, world(seed.world), seed.seed);
  const work = new Set(built.case.findings.map((f) => f.recordId));
  const hosts = new Set(rows(built.corpus, 'VulnFindings').filter((r) => work.has(String(r.RecordId))).map((r) => String(r.DeviceName)));
  const devices = rows(built.corpus, 'DeviceInfo').filter((d) => hosts.has(String(d.DeviceName)));
  const teams = [...new Set([...devices.map((d) => String(d.Owner)), 'IT Infrastructure'])].join(', ');
  const windows = [...built.case.constraints.windows].sort((a, b) => a.start - b.start);
  const now = Date.parse(String(built.now));
  const exceptions = rows(built.corpus, 'Tickets').filter((x) => /risk exception/i.test(String(x.Title)) && Date.parse(String(x.WindowEnd)) > now);
  const out: Case = {
    facts: { teams, next: day(windows[0].start), cycle: day(windows[1].start), expiry: exceptions.length > 0 ? day(Date.parse(String(exceptions[0].WindowEnd))) : null },
    rubric: built.case.rubric.map((r) => ({ id: r.id, text: r.text, keywords: r.keywords })),
  };
  cache.set(key, out);
  return out;
}
// Fails with every offender listed (a toEqual diff truncates).
const none = (list: readonly string[], label: string): void => {
  if (list.length > 0) throw new Error([label, ...list].join('\n'));
};
const hits = (rubric: { id: string; keywords: string[] }[], note: string): string[] => vulnRubricHits(rubric.map((r) => ({ id: r.id, text: '', keywords: r.keywords })), note);

// A model note per template: the risk and the action in a competent analyst's own words. The teams and dates come from the case.
// Each pair of twins words the one thing that differs between them (the control, the clue, the host) and nothing else.
const RISK_ACTION: Record<string, { risk: string; action: string }> = {
  'vm-kev-internal': {
    risk: 'The headline is on Sim-KEV: a known exploited flaw, and exploitation has been observed. Anyone on the network can read data without logging in.',
    action: 'Raise an emergency change for the listed finding on the application server. The developer server goes in the next window and the TLS update in the standard cycle. Rescan the file server.',
  },
  'vm-nokev-internal': {
    risk: 'The same 7.5 is not exploited: Sim-EPSS is low and there is no public exploit.',
    action: 'No emergency. The developer server goes first in the next window; the 7.5 headline goes in the standard cycle with the TLS update. Rescan the file server.',
  },
  'vm-stale-scan': {
    risk: 'The scanner result on FS01 is out of date. FS02 is still vulnerable: its only later update was an operating system rollup, so its package is below the fix.',
    action: 'Dismiss FS01 and rescan it. Patch FS02 in the next window and the others in the emergency or standard cycle. Accept the print server finding.',
  },
  'vm-fresh-scan': {
    risk: 'FS01 has the update installed but it is not in effect until the restart: the service still has the old library loaded, so that finding is current. The FS02 result is out of date.',
    action: 'Schedule the reboot of FS01 in the next window. Dismiss FS02 and rescan it. Patch the others in the emergency or standard cycle and accept the print server finding.',
  },
  'vm-backport-fp': {
    risk: 'The banner shows only the upstream version. The fix was backported on WEBLX01, so the banner is wrong there; WEBLX02 has the old package. The public website flaw is known exploited (Sim-KEV) and unpatched, and the FS01 result is stale.',
    action: 'Dismiss WEBLX01 and FS01 and rescan them. Patch WEBLX02 and the public website by emergency change. Accept the print server exception.',
  },
  'vm-backport-real': {
    risk: 'The banner shows only the upstream version. WEBLX01 is built from source, so nothing was backported on WEBLX01 and its banner is accurate; WEBLX02 is the distro package and is already fixed. The public website flaw is known exploited (Sim-KEV) and unpatched, and the FS01 result is stale.',
    action: 'Dismiss WEBLX02 and FS01 and rescan them. Patch WEBLX01 and the public website by emergency change. Accept the print server exception.',
  },
  'vm-exposed-edge': {
    risk: "The edge appliance's management interface is internet-facing, with an unauthenticated remote code execution flaw and nothing blocking it.",
    action: 'Raise an emergency change to patch EDGE01, and a compromise check on the sources that reached its management port. APP01 goes in the next window, the Medium in the standard cycle. Rescan FS01.',
  },
  'vm-segmented': {
    risk: 'The management interface is reachable only from the management VLAN, and a verified blocking ACL is compensating for the missing patch for now.',
    action: 'Mitigate with the ACL now; the permanent fix goes in the next window and the ACL has to stay in effect until then. Rescan FS01.',
  },
  'vm-waf-covers': {
    risk: "The portal's SQL injection is covered for now by a WAF rule in block mode, a virtual patch that is only temporary until the code release.",
    action: 'Mitigate with the WAF rule now and keep the rule in place. The code release goes in the next window after the freeze; the public website in the next window, the rest in the standard cycle. Rescan FS01.',
  },
  'vm-waf-bypass': {
    risk: "The portal's SQL injection has a WAF rule in detect mode that only detects: nothing blocks the attack, so the fix cannot wait for the release.",
    action: 'Raise an emergency change to deploy the fix through the freeze. The public website goes in the next window, the rest in the standard cycle. Rescan FS01 and hand the requests that reached the page to the SOC for a compromise check.',
  },
  'vm-legacy-accept': {
    risk: 'The vendor has ended support and no fix will come. The controller is already reachable only from the OT management hosts and the authorised scanner, which is the condition of the approved exception.',
    action: 'Accept the controller finding under the approved exception and re-assess it at expiry. Patch the print server, whose exception expired, and put the rest in the standard cycle.',
  },
  'vm-legacy-isolate': {
    risk: 'The vendor has ended support and no fix will come. Corporate workstations can reach the controller and there is no approved exception.',
    action: 'Move the controller behind the OT controller VLAN ACL in the next window and raise a risk exception once it is in effect. Patch the print server, whose exception expired, and put the rest in the standard cycle.',
  },
  'vm-noncred-low': {
    risk: 'The sweep read only the banner. The credentialed run tested INTRA01, whose inventory is above the fix, so the banner was wrong; the login failed on INTRA02, so its banner is right.',
    action: 'Dismiss INTRA01 and ask for a credentialed rescan. Patch INTRA02 by emergency change, the others in the next window and the standard cycle.',
  },
  'vm-cred-high': {
    risk: 'The sweep read only the banner. The credentialed run tested INTRA02, whose inventory is above the fix, so the banner was wrong; the login failed on INTRA01, so its banner is right.',
    action: 'Dismiss INTRA02 and ask for a credentialed rescan. Patch INTRA01 by emergency change, the others in the next window and the standard cycle.',
  },
  'vm-saas-transfer': {
    risk: "The ticketing service is vendor-hosted and operated by the vendor, whose advisory commits to a fix date. The fix is the vendor's, but accountability for our data stays with us until the vendor confirms.",
    action: "Record transfer for the hosted ticketing service HELPDESK01 and for the dashboards service: track the vendor's date and get its written confirmation, with no testing of its platform. Patch the contract-covered server on APP01 in the next window.",
  },
  'vm-self-hosted': {
    risk: 'This ticketing server is self-managed: IT installed and runs it, and the vendor will not update it. It is a Critical reachable from the internet.',
    action: 'Raise an emergency change to patch the ticketing server. Record transfer for the hosted dashboards service and patch the contract-covered server on APP01 in the next window.',
  },
  'vm-unused-service': {
    risk: 'Nobody uses the admin console on APP01, and removing the console on APP01 removes the attack surface.',
    action: 'Avoid the console on APP01 and on DEVBOX01 (disable it, then rescan). Patch the console on SQL01, which is used, and dismiss the banner-only Medium on BUILD01.',
  },
  'vm-needed-service': {
    risk: 'The stock export needs the console on APP01, so it cannot simply be switched off.',
    action: 'Patch the console on APP01 and on SQL01, which are used. Avoid the unused one on DEVBOX01 and dismiss the banner-only Medium on BUILD01.',
  },
  'vm-dup-plugins': {
    risk: 'One flaw in a shared library, reported six times: one update fixes it, because the portal links the system package as well; two other services bundle their own copies. The payments database comes before the developer test server.',
    action: 'Patch the system package once and close the portal, forms and directory detections as duplicates. Patch the two bundled copies, the payments database in the next window and the Sim-KEV Critical by emergency change. Dismiss the stale result and rescan; accept the print server exception.',
  },
  'vm-distinct': {
    risk: 'One flaw in a shared library, but the portal bundles its own copy, as do two other services, so there are separate fixes besides the system package. The payments database comes before the developer test server.',
    action: 'Patch the system package and each bundled copy (the portal, the mail relay and the chat service); close the forms and directory detections as duplicates. Patch the payments database in the next window and the Sim-KEV Critical by emergency change. Dismiss the stale result and rescan; accept the print server exception.',
  },
};

const noteOf = (id: string, f: Facts): string => {
  const m = RISK_ACTION[id];
  const expiry = f.expiry === null ? '' : ` The print server exception expires on ${f.expiry}.`;
  return `${f.teams} make the changes. ${m.risk} ${m.action} The next maintenance window is ${f.next} and the standard patch cycle ${f.cycle}.${expiry}`;
};

// Generic verbs and risk words, with no host, team, product, date or schedule term.
const CONTENT_FREE = [
  'Owner: the server owner. Risk: the host is vulnerable and exposed. Action: patch it as soon as possible. Deadline per the SLA.',
  'Severity is high and the risk is serious: attackers could exploit it. We need to patch, update and remediate quickly; the owner of the system is responsible. Please prioritise by risk and fix promptly.',
  'Vulnerabilities were found by the scan. Critical items first, then high, then medium. Apply patches, update software, fix the issues and report back when it is done on time.',
];

// Honest phrasings of the right answer and the wrong-twin or negated notes that must not tick it, one probe each from the reviewers'
// findings (RUB-1 to RUB-12). `ticks` are items the note must tick on the template; `not` items it must not. A host name is the
// case's own (the worlds share them).
interface Probe {
  note: string;
  ticks?: ('risk' | 'action')[];
  not?: ('risk' | 'action')[];
}
const PROBES: Record<string, Probe[]> = {
  'vm-kev-internal': [
    { note: 'The headline on APP01 is on Sim-KEV, so exploitation has been observed in the wild. Raise an emergency change to patch it.', ticks: ['risk', 'action'] },
    { note: 'No emergency change is needed. The headline is not on Sim-KEV and it is not known exploited.', not: ['risk', 'action'] },
  ],
  'vm-nokev-internal': [
    { note: 'The headline can go in the regular monthly patch cycle: the headline is not on Sim-KEV and its Sim-EPSS is low.', ticks: ['risk', 'action'] },
    { note: 'No emergency change is needed. The headline is not on Sim-KEV and it is not known exploited.', ticks: ['risk'] },
    { note: 'The headline on APP01 is on Sim-KEV, so exploitation has been observed in the wild. Raise an emergency change to patch it.', not: ['risk', 'action'] },
  ],
  'vm-stale-scan': [
    { note: 'FS01 was updated after the scan with no reboot pending, so its result is stale: dismiss FS01.', ticks: ['risk', 'action'] },
    { note: 'The FS01 finding is out of date. FS02 is still unpatched.', ticks: ['risk'] },
    { note: 'Mark FS01 as a false positive and rescan it.', ticks: ['action'] },
  ],
  'vm-fresh-scan': [
    { note: 'FS01 was updated after the scan with no reboot pending, so its result is stale: dismiss FS01.', not: ['risk', 'action'] },
    { note: 'FS01 needs a reboot: the update is installed but the reboot is pending. Reboot FS01 in the next window.', ticks: ['risk', 'action'] },
  ],
  'vm-backport-fp': [
    { note: 'The distro backported the security fix on WEBLX01, so the banner is wrong there. Mark WEBLX01 as a false positive.', ticks: ['risk', 'action'] },
    { note: 'WEBLX02 has a backported fix in its distro package, and the banner is right on WEBLX01.', not: ['risk'] },
  ],
  'vm-backport-real': [
    { note: 'WEBLX02 has a backported fix in its distro package.', not: ['risk'] },
    { note: 'WEBLX01 is compiled from source, so no backport applies and the banner version is the real version. Patch WEBLX01.', ticks: ['risk', 'action'] },
  ],
  'vm-exposed-edge': [
    { note: 'EDGE01 is exposed to the internet with no ACL in front of the management interface.', ticks: ['risk'] },
    { note: 'There is no compensating control and it is not a mitigation: raise an emergency change to patch EDGE01.', ticks: ['action'], not: ['risk'] },
  ],
  'vm-segmented': [
    { note: 'There is no compensating control and it is not a mitigation: raise an emergency change to patch EDGE01.', not: ['risk', 'action'] },
    { note: 'The ACL is compensating for the missing patch. Mitigate with the ACL and keep it in effect until the permanent fix in the next window.', ticks: ['risk', 'action'] },
  ],
  'vm-waf-covers': [
    { note: 'The WAF rule is blocking the attack, so the code release can wait.', ticks: ['risk'] },
    { note: 'Nothing blocks the attack: the WAF rule only detects. There is no compensating control and it is not a mitigation.', not: ['risk', 'action'] },
  ],
  'vm-waf-bypass': [
    { note: 'Nothing blocks the attack: the WAF rule only detects. Raise an emergency change through the freeze.', ticks: ['risk', 'action'] },
    { note: 'The WAF rule is blocking the attack, so the code release can wait. Mitigate with the WAF rule.', not: ['risk', 'action'] },
  ],
  'vm-legacy-accept': [
    { note: 'The controller sits behind the block-mode ACL on the OT VLAN and has an approved exception: accept the risk.', not: ['action'] },
    { note: 'File a risk acceptance once the ACL is in effect. There is no risk acceptance today.', not: ['risk', 'action'] },
    { note: 'Accept the controller under the approved exception and re-assess it at expiry.', ticks: ['action'] },
  ],
  'vm-legacy-isolate': [
    { note: 'The controller sits behind the block-mode ACL on the OT VLAN and has an approved exception: accept the risk.', not: ['action'] },
    { note: 'File a risk acceptance once the ACL is in effect. There is no risk acceptance today.', not: ['risk'] },
    { note: 'The controller is reachable from user workstations and there is no waiver.', ticks: ['risk'] },
    { note: 'Put the controller behind the OT controller VLAN ACL, then raise a risk exception.', ticks: ['action'] },
  ],
  'vm-noncred-low': [
    { note: 'The credentialed scan could not log in to INTRA02.', ticks: ['risk'] },
    { note: 'INTRA02: authentication failed during the credentialed run.', ticks: ['risk'] },
    { note: 'INTRA01 false positive (package above fix).', ticks: ['action'] },
    { note: 'The credentialed scan could not log in to INTRA01.', not: ['risk'] },
    { note: 'There was no credentialed check of INTRA02.', ticks: ['risk'] },
    { note: 'The credentialed run never tested INTRA02.', ticks: ['risk'] },
    { note: 'The credentialed run reached INTRA02 but the login failed.', ticks: ['risk'] },
    { note: 'There was no credentialed check of INTRA01.', not: ['risk'] },
    { note: 'The credentialed run never tested INTRA01.', not: ['risk'] },
    { note: 'The credentialed run reached INTRA01 but the login failed.', not: ['risk'] },
    { note: 'The credentialed run tested INTRA01 and the package is above the fix.', ticks: ['risk'] },
    { note: 'The credentialed check of INTRA01 showed the package above the fix.', ticks: ['risk'] },
  ],
  'vm-cred-high': [
    { note: 'The credentialed scan could not log in to INTRA01.', ticks: ['risk'] },
    { note: 'INTRA02 false positive (package above fix).', ticks: ['action'] },
    { note: 'The credentialed scan could not log in to INTRA02.', not: ['risk'] },
    { note: 'There was no credentialed check of INTRA01.', ticks: ['risk'] },
    { note: 'The credentialed run never tested INTRA01.', ticks: ['risk'] },
    { note: 'The credentialed run reached INTRA01 but the login failed.', ticks: ['risk'] },
    { note: 'There was no credentialed check of INTRA02.', not: ['risk'] },
    { note: 'The credentialed run never tested INTRA02.', not: ['risk'] },
    { note: 'The credentialed run reached INTRA02 but the login failed.', not: ['risk'] },
    { note: 'The credentialed run tested INTRA02 and the package is above the fix.', ticks: ['risk'] },
    { note: 'The credentialed check of INTRA02 showed the package above the fix.', ticks: ['risk'] },
  ],
  'vm-saas-transfer': [
    { note: 'Raise an emergency change for the ticketing server. The dashboards service is vendor-hosted: transfer it and track the vendor date.', not: ['risk', 'action'] },
    { note: 'The dashboards service is SaaS, hosted by the vendor. We run the ticketing server ourselves.', not: ['risk'] },
    { note: 'Monitor the vendor fix for the ticketing service and wait for its written confirmation.', ticks: ['action'] },
    { note: 'Record transfer for HELPDESK01 and do not test the vendor platform.', ticks: ['action'] },
    { note: 'HELPDESK01 is vendor-hosted, so record transfer for it.', ticks: ['risk'] },
  ],
  'vm-self-hosted': [
    { note: 'The dashboards service is vendor-hosted: record transfer and track the vendor date. No emergency change is needed.', not: ['risk', 'action'] },
    { note: 'We run this instance ourselves, and the vendor will not update it.', ticks: ['risk'] },
    { note: 'Raise an emergency change for the ticketing server.', ticks: ['action'] },
  ],
  'vm-unused-service': [
    { note: 'Patch the APP01 console.', not: ['action'] },
    { note: 'Disable the unused console on DEVBOX01.', not: ['risk'] },
    { note: 'The APP01 admin console is unused: avoid by turning it off.', ticks: ['risk', 'action'] },
    { note: 'Unused console on APP01: uninstall it (avoid).', ticks: ['action'] },
  ],
  'vm-needed-service': [
    { note: 'Patch the APP01 console.', ticks: ['action'] },
    { note: 'Disable the unused console on DEVBOX01.', not: ['risk'] },
    { note: 'The APP01 console is in use, so patch it.', ticks: ['action'] },
    { note: 'The APP01 admin console is unused: avoid by turning it off.', not: ['risk', 'action'] },
  ],
  'vm-dup-plugins': [
    { note: 'The portal links the system package, a duplicate. The mail relay and the chat service each bundle their own copy of the library and need a separate update.', ticks: ['risk'] },
    { note: 'Patch the system package once and the portal separately.', not: ['action'] },
    { note: 'The portal is a duplicate of the package-level finding.', ticks: ['risk'] },
  ],
  'vm-distinct': [
    { note: 'The portal links the system package, a duplicate. The mail relay and the chat service each bundle their own copy of the library and need a separate update.', not: ['risk', 'action'] },
    { note: 'Patch the system package once and the portal separately.', ticks: ['action'] },
    { note: 'The portal bundles its own copy, so it is not a duplicate.', ticks: ['risk'] },
  ],
};

// Probes of the second review round: a note about a fact that both twins share (the DEVBOX01 console, SQL01's used console, the print
// server exception, the APP01 contract, the freeze, a reboot after patching FS02) or a negation that a cheap keyword would tick.
const NO_EMERGENCY: Probe = { note: 'No emergency patching is needed, and no emergency deployment either.', not: ['action'] };
const NO_COMPENSATING: Probe = { note: 'There is no compensating control in place.', not: ['action'] };
const SHARED_FACT_PROBES: Record<string, Probe[]> = {
  'vm-kev-internal': [
    { note: 'No exploitation observed on the headline, and no exploitation has been observed anywhere.', not: ['risk'] },
    { note: 'No emergency patching is needed. No emergency window is needed either.', not: ['action'] },
    { note: 'The file server finding is on Sim-KEV and actively exploited, but the headline is not.', not: ['risk'] },
    { note: 'The APP01 finding is on Sim-KEV and is being exploited.', ticks: ['risk'] },
  ],
  'vm-nokev-internal': [
    { note: 'No exploitation observed on the headline.', ticks: ['risk'] },
    { note: 'The developer server finding is not on Sim-KEV, so it goes in the next window.', not: ['risk'] },
    { note: 'The developer server finding is not listed and not exploited, and its EPSS is low with no public exploit.', not: ['risk'] },
    { note: 'The TLS finding on the print server has a low EPSS, is not exploited and is not urgent: standard cycle.', not: ['risk'] },
    { note: 'The file server result is not listed anywhere and there is no sign of exploitation.', not: ['risk'] },
  ],
  'vm-stale-scan': [
    { note: 'Patch FS02 in the next window and reboot it afterwards.', not: ['action'] },
    { note: 'FS01 was updated after the scan and no reboot is pending, so the result is out of date: dismiss FS01.', ticks: ['risk', 'action'] },
    { note: 'FS01 was updated after the scan and no restart is pending.', ticks: ['risk'] },
    { note: 'FS02 still runs the old library: its update was only an operating system rollup.', ticks: ['risk'] },
  ],
  'vm-fresh-scan': [
    { note: 'FS01 was updated after the scan and no reboot is pending, so the result is out of date. Dismiss FS01.', not: ['risk', 'action'] },
    { note: 'FS01 was updated after the scan and no restart is pending, so dismiss it.', not: ['risk'] },
    { note: 'FS02 still runs the old library: its update was only an operating system rollup.', not: ['risk'] },
    { note: 'FS01 needs a reboot: the update is installed but the service still loads the old library.', ticks: ['risk'] },
    { note: 'The update on FS01 is not in effect until the host restarts.', ticks: ['risk'] },
    { note: 'FS01 has no pending reboot, so the update is in effect.', not: ['risk'] },
    { note: 'Patch FS02 in the next window and reboot it afterwards.', not: ['action'] },
    { note: 'FS01 is still pending a reboot, so reboot FS01 in the next window.', ticks: ['risk', 'action'] },
  ],
  'vm-exposed-edge': [NO_EMERGENCY],
  'vm-segmented': [NO_COMPENSATING],
  'vm-waf-covers': [
    { note: 'Nothing protects the portal until the release: raise an emergency change.', not: ['risk'] },
    { note: 'Nothing protects the code until the code release, so deploy the fix.', not: ['risk'] },
    { note: 'The WAF rule only logs: nothing is blocking the attack.', not: ['risk'] },
    { note: 'The WAF rule blocks nothing: it only logs.', not: ['risk'] },
    NO_COMPENSATING,
  ],
  'vm-waf-bypass': [
    { note: 'Nothing can be deployed during the freeze, so the code release goes in the next window after the freeze.', not: ['action'] },
    { note: 'Deploy the fix now despite the freeze.', ticks: ['action'] },
    NO_EMERGENCY,
  ],
  'vm-legacy-accept': [
    { note: 'Move it behind the ACL so that it is only reachable from the OT management hosts.', not: ['risk', 'action'] },
    { note: 'Raise a risk exception once the ACL is in effect, and re-assess it at expiry.', not: ['action'] },
    { note: 'Corporate workstations can reach the controller as well as the OT management hosts and the authorised scanner, and there is no approved exception.', not: ['risk'] },
    { note: 'The PRINT01 exception has expired and there is no approved exception for the print server, which is reachable only from the print VLAN.', not: ['risk'] },
    { note: 'The controller is already reachable only from the OT management hosts and the authorised scanner.', ticks: ['risk'] },
    { note: 'The controller has an approved exception.', ticks: ['risk'] },
  ],
  'vm-legacy-isolate': [
    { note: 'Move it behind the ACL so that it is only reachable from the OT management hosts, and raise a risk exception once the ACL is in effect and re-assess it at expiry.', ticks: ['action'] },
    { note: 'The ACL denies the corporate workstations, and the controller is reachable only from the OT management hosts.', not: ['risk'] },
    { note: 'The PRINT01 exception has expired: there is no approved exception for the print server.', not: ['risk'] },
    { note: 'There is no approved exception for the controller and corporate workstations are allowed through.', ticks: ['risk'] },
  ],
  'vm-saas-transfer': [
    { note: 'APP01 is installed and run by IT under a support contract: patch it in the next window.', not: ['risk'] },
    { note: 'Record transfer for DASHSVC01, wait for the confirmation notice and the vendor written confirmation, monitor the vendor and do not test its platform.', not: ['action'] },
  ],
  'vm-self-hosted': [
    { note: 'Record transfer for DASHSVC01, wait for the confirmation notice and the vendor written confirmation, monitor the vendor and do not test its platform.', not: ['action'] },
    { note: 'APP01 is installed and run by IT under a support contract: patch it in the next window.', not: ['risk'] },
    { note: 'The ticketing server is installed and run by IT, and the vendor will not update it.', ticks: ['risk'] },
    NO_EMERGENCY,
  ],
  'vm-unused-service': [
    { note: 'Disable the unused console on DEVBOX01, which removes the attack surface; there is no business process on it.', not: ['risk'] },
    { note: 'Nobody uses the console on DEVBOX01.', not: ['risk'] },
    { note: 'The SQL01 console is needed by the database team, so patch it.', not: ['risk'] },
    { note: 'The stock export needs the console on APP01.', not: ['risk'] },
    { note: 'No one uses the console on APP01, so removing the console on APP01 removes the attack surface.', ticks: ['risk'] },
  ],
  'vm-needed-service': [
    { note: 'Disable the unused console on DEVBOX01, which removes the attack surface; there is no business process on it.', not: ['risk'] },
    { note: 'The SQL01 console is needed by the database team, so patch it.', not: ['risk'] },
    { note: 'Nobody uses the console on APP01, so removing the console on APP01 removes the attack surface.', not: ['risk'] },
    { note: 'The stock export needs the console on APP01.', ticks: ['risk'] },
    { note: 'The APP01 console cannot be switched off: the stock export uses it.', ticks: ['risk'] },
  ],
};

// Honest variants of each model note: other word order, possessive host names ("APP01's"), a clue that is stated as a negation ("there
// is no approved exception"). Each variant is a competent analyst's note for this twin, so it ticks this twin's risk (risk sentence)
// and action (action sentence), and the other twin's risk and action items stay unticked by it.
interface Variant { risk: string; action: string }
const VARIANTS: Record<string, Variant[]> = {
  'vm-kev-internal': [
    { risk: "APP01's headline is listed on Sim-KEV: it is being exploited in the wild, and no login is needed.", action: "APP01's headline goes through an emergency change. The developer server goes in the next window, the TLS update in the standard cycle, and FS01 gets a rescan." },
    { risk: 'There is no doubt about it: the headline is on Sim-KEV and has been exploited.', action: "An emergency change is raised for the headline today. The developer server is not an emergency: it goes in the next window, and FS01's result needs a rescan." },
  ],
  'vm-nokev-internal': [
    { risk: "APP01's headline 7.5 is not on Sim-KEV and its Sim-EPSS is low, with no public exploit.", action: 'The headline goes in the standard cycle along with the TLS update; the developer server goes first, in the next window, and FS01 needs a rescan.' },
    { risk: 'There is no sign that the headline is exploited, and no sign of exploitation for it anywhere.', action: 'The headline is not an emergency, so it waits for the standard cycle. The developer server takes the next window and the file server is rescanned.' },
  ],
  'vm-stale-scan': [
    { risk: "FS01's scanner result is out of date: it was updated after the scan and no reboot is pending. FS02 is still below the fix, because its only update was an OS rollup.", action: "FS01's finding is dismissed and rescanned; FS02 is patched in the next window; the others go in the emergency or standard cycle, and the print server finding is accepted." },
    { risk: "FS01 no longer has the vulnerability: it was updated after the scan and there is no restart pending. FS02's later update was only a rollup, so the fix is missing there.", action: "Close FS01's result as a false positive and rescan it. Schedule FS02's patch for the next window. Accept the print server." },
  ],
  'vm-fresh-scan': [
    { risk: "FS01's update is installed but a reboot is pending, so the old library is still loaded and the finding stands. FS02's result is out of date: it was updated after the scan and no reboot is pending.", action: "Reboot FS01 in the next window. Dismiss FS02's finding and rescan it. Patch the rest in the emergency or standard cycle and accept the print server." },
    { risk: "There is no fix missing on FS01: the update is on the host, but it is not in effect until the restart, since the service still has the old library loaded. FS02's result is stale.", action: "FS01 is rebooted in the next window. FS02 is closed as a false positive and rescanned. The print server is accepted." },
  ],
  'vm-backport-fp': [
    { risk: "WEBLX01's banner is wrong: the distro backported the security fix there. WEBLX02 still has the old package. The public website flaw is on Sim-KEV and unpatched; the FS01 result is stale.", action: "WEBLX01's finding is dismissed as a false positive, WEBLX02 and the public website are patched by emergency change; FS01 is rescanned; the print server exception is accepted." },
    { risk: 'There is no vulnerability on WEBLX01, because the fix was backported there and the banner shows only the upstream version; WEBLX02 is still vulnerable.', action: 'Dismiss WEBLX01 as a false positive, rescan it, and patch WEBLX02 by emergency change. Accept the print server.' },
  ],
  'vm-backport-real': [
    { risk: "WEBLX01's banner is accurate: it is built from source, so nothing was backported there. WEBLX02 is the distro package and the fix is already in it.", action: "Patch WEBLX01 and the public website by emergency change. WEBLX02's finding is dismissed as a false positive. FS01 is rescanned; the print server exception is accepted." },
    { risk: "There is no backport on WEBLX01: it is compiled from source, so the banner version is the real version, and WEBLX02's distro package carries the fix.", action: 'Patch WEBLX01 by emergency change along with the public website; dismiss WEBLX02 and rescan FS01.' },
  ],
  'vm-exposed-edge': [
    { risk: "EDGE01's management interface faces the internet, with an unauthenticated remote code execution flaw and no ACL in front.", action: "EDGE01 is patched by emergency change, and the sources that reached its management port get a compromise check. APP01's finding goes in the next window and the Medium in the standard cycle; FS01 is rescanned." },
    { risk: 'There is no control in front of EDGE01: its management interface is open to the internet, and the flaw needs no login.', action: 'Raise an emergency change for EDGE01 and check the sources that reached it for compromise; APP01 waits for the next window.' },
  ],
  'vm-segmented': [
    { risk: "EDGE01's management interface is reachable only from the management VLAN, and a verified ACL in block mode is compensating for the missing patch.", action: "The ACL is the mitigation for now and has to stay in effect; EDGE01's patch goes in the next window; FS01 is rescanned." },
    { risk: 'Nothing from the internet can reach the EDGE01 management interface: a blocking ACL is compensating for the patch that is not yet applied.', action: 'Mitigate EDGE01 with the ACL now and patch it in the next window; the ACL is kept in effect until the patch.' },
  ],
  'vm-waf-covers': [
    { risk: "The portal's SQL injection is blocked by a WAF rule in block mode: a virtual patch that is temporary until the code release.", action: 'The WAF rule is the mitigation for now and stays in place; the code release goes in the next window after the freeze, the public website in the next window and the rest in the standard cycle; FS01 is rescanned.' },
    { risk: 'There is no gap in front of the portal: the WAF rule blocks the injection attempts, so the release can wait.', action: "Mitigate the portal with the WAF rule now. The portal's code release is scheduled for the next window after the freeze." },
  ],
  'vm-waf-bypass': [
    { risk: "The portal's WAF rule is in detect mode, so it only logs the injection: nothing is blocking the attack and the fix cannot wait for the release.", action: "The portal's fix goes out by emergency change, through the freeze; the public website goes in the next window; FS01 is rescanned and the requests that reached the page go to the SOC." },
    { risk: 'There is no blocking rule on the portal: the WAF only detects, so the attack gets through.', action: "Raise an emergency change for the portal's fix despite the freeze, and send the SOC the requests that reached the page." },
  ],
  'vm-legacy-accept': [
    { risk: "The controller's vendor has ended support, so no fix will come; it is already reachable only from the OT management hosts and the authorised scanner, which the approved exception requires.", action: "The controller's finding is accepted under the approved exception, and its expiry is re-assessed. The print server is patched since its exception expired; the rest goes in the standard cycle." },
    { risk: 'There is no fix from the vendor, which ended support. The approved exception for the controller is still valid, and the ACL blocks the corporate workstations.', action: 'Under the approved exception, accept the controller and review it at the expiry. Patch the print server, because its exception expired.' },
  ],
  'vm-legacy-isolate': [
    { risk: "The controller's vendor has ended support and no fix will come. Corporate workstations can still reach it, and the exception request is still open, not approved.", action: 'The controller goes behind the OT controller VLAN ACL in the next window, and then a risk exception is raised. The print server is patched since its exception expired; the rest goes in the standard cycle.' },
    { risk: 'There is no approved exception for the controller, and corporate workstations are allowed through, with no vendor fix to come.', action: 'Isolate the controller behind the ACL in the next window; once it is in effect, raise a risk exception. Patch the print server.' },
    { risk: 'Corporate workstations can reach the controller, and no exception has been approved for it.', action: 'Move the controller behind the OT controller VLAN ACL in the next window, then raise a risk exception to accept the remaining risk under it.' },
  ],
  'vm-noncred-low': [
    { risk: "INTRA01's credentialed check showed the package above the fix, so its banner was wrong. INTRA02's login failed, so its banner stands.", action: "INTRA01's finding is dismissed and a credentialed rescan is requested; INTRA02 is patched by emergency change and the others in the next window and the standard cycle." },
    { risk: 'The sweep was banner-only. There is no vulnerability on INTRA01, since its inventory is above the fix; the credentialed login to INTRA02 failed, so nobody checked it.', action: 'Close INTRA01 as a false positive and ask for a credentialed rescan. Patch INTRA02 by emergency change.' },
  ],
  'vm-cred-high': [
    { risk: "INTRA02's credentialed check showed the package above the fix, so its banner was wrong. INTRA01's login failed, so its banner stands.", action: "INTRA02's finding is dismissed and a credentialed rescan is requested; INTRA01 is patched by emergency change and the others in the next window and the standard cycle." },
    { risk: 'The sweep was banner-only. There is no vulnerability on INTRA02, since its inventory is above the fix; the credentialed login to INTRA01 failed, so nobody checked it.', action: 'Close INTRA02 as a false positive and ask for a credentialed rescan. Patch INTRA01 by emergency change.' },
  ],
  'vm-saas-transfer': [
    { risk: "HELPDESK01's ticketing service is vendor-hosted and vendor-operated; the vendor's advisory gives a fix date, so the fix is the vendor's, though we stay accountable for our data until the vendor confirms.", action: "HELPDESK01 is recorded as transfer, as is the dashboards service: follow the vendor's date, get its written confirmation, and do not test its platform. APP01 is patched in the next window." },
    { risk: 'We do not run the ticketing service: the vendor operates it and has committed to a fix date. There is no patch for us to apply.', action: "Record transfer for HELPDESK01, track the vendor's fix date and wait for the vendor's written confirmation without testing the platform. Patch APP01 in the next window." },
  ],
  'vm-self-hosted': [
    { risk: 'The ticketing server is self-managed: IT installed it and runs it, and the vendor will not update it. It is a Critical, reachable from the internet.', action: 'An emergency change patches the ticketing server; the dashboards service is recorded as transfer; APP01 is patched in the next window.' },
    { risk: 'Nobody at the vendor runs this ticketing server: we installed it ourselves and there is no vendor update, and it faces the internet.', action: 'Raise an emergency change for the ticketing server, mark the dashboards service as transfer, and patch APP01 in the next window.' },
  ],
  'vm-unused-service': [
    { risk: "Nobody uses APP01's admin console, so removing it removes the attack surface.", action: "APP01's console is switched off, as is DEVBOX01's, then rescanned. SQL01's console is patched, since it is used, and BUILD01's banner-only Medium is dismissed." },
    { risk: 'There is no business process on the APP01 console: no one uses it, and switching it off removes the exposure.', action: 'Disable the console on APP01 and DEVBOX01, and rescan. Patch the SQL01 console; dismiss the BUILD01 banner finding.' },
  ],
  'vm-needed-service': [
    { risk: "APP01's console is needed by the stock export, so it cannot just be turned off.", action: "Patch APP01's console and SQL01's console, which are used. The DEVBOX01 console is avoided and BUILD01's banner-only Medium is dismissed." },
    { risk: 'The APP01 console cannot be disabled: the stock export depends on it.', action: 'Update the console on APP01 and on SQL01, since they are in use; disable the unused one on DEVBOX01 and dismiss the BUILD01 Medium.' },
  ],
  'vm-dup-plugins': [
    { risk: "It is one flaw in a shared library reported six times. The portal's copy is the system package, so one update covers it; two other services ship their own copies, which need separate fixes.", action: 'The system package is patched once, and the portal, forms and directory detections are closed as duplicates. The two bundled copies are patched, the payments database in the next window and the Sim-KEV Critical by emergency change; the stale result is dismissed and rescanned; the print server exception is accepted.' },
    { risk: 'There is no separate fix for the portal: it uses the system package like the others, so these are duplicates; only two other services bundle their own copies.', action: 'Update the system package once and close the portal, forms and directory findings as duplicates; patch each of the two bundled copies, and dismiss the stale one.' },
  ],
  'vm-distinct': [
    { risk: "It is one library flaw, but the portal's own bundled copy needs its own update, as do the copies in the mail relay and the chat service: they are not duplicates of the system package.", action: "Patch the system package, then the portal's bundled copy, the mail relay and the chat service; close the forms and directory detections as duplicates; the payments database goes in the next window, the Sim-KEV Critical by emergency change; dismiss the stale result and rescan; accept the print server exception." },
    { risk: 'There is no duplicate for the portal: it bundles its own copy, separate from the system package.', action: 'Update each bundled copy as well as the system package: the portal, the mail relay and the chat service; close the forms and directory ones as duplicates.' },
  ],
};

// Probes of the fourth review round: possessive host names, shared facts that a generic keyword fits, and the isolate twin's own last step.
const ROUND4: Record<string, Probe[]> = {
  'vm-nokev-internal': [
    { note: 'The developer server is not an emergency: next window.', not: ['action'] },
    { note: 'The TLS update is not an emergency; it goes in the standard cycle.', not: ['action'] },
  ],
  'vm-kev-internal': [{ note: 'The developer server is not an emergency: next window.', not: ['action'] }],
  'vm-stale-scan': [
    { note: 'The APP01 critical is below the fix.', not: ['risk'] },
    { note: "FS02's package is below the fix.", ticks: ['risk'] },
    { note: "FS01's update needs a reboot.", not: ['risk'] },
  ],
  'vm-fresh-scan': [
    { note: 'The APP01 critical is below the fix.', not: ['risk'] },
    { note: 'FS01 has the fix installed but a reboot is pending.', ticks: ['risk'] },
    { note: "FS01's update needs a reboot.", ticks: ['risk'] },
  ],
  'vm-noncred-low': [
    { note: "INTRA02's credentialed login failed.", ticks: ['risk'] },
    { note: "INTRA01's banner was wrong.", ticks: ['risk'] },
    { note: "INTRA01's credentialed login failed.", not: ['risk'] },
  ],
  'vm-cred-high': [
    { note: "INTRA01's credentialed login failed.", ticks: ['risk'] },
    { note: "INTRA02's banner was wrong.", ticks: ['risk'] },
    { note: "INTRA02's credentialed login failed.", not: ['risk'] },
  ],
  'vm-backport-fp': [
    { note: "WEBLX01's banner is wrong.", ticks: ['risk'] },
    { note: "WEBLX01's banner is accurate.", not: ['risk'] },
  ],
  'vm-backport-real': [
    { note: "WEBLX01's banner is accurate.", ticks: ['risk'] },
    { note: "WEBLX01's banner is wrong.", not: ['risk'] },
  ],
  'vm-saas-transfer': [
    { note: 'Monitor the vendor fix date for HELPDESK01.', ticks: ['action'] },
    { note: "Track the vendor's fix date for HELPDESK01.", ticks: ['action'] },
  ],
  'vm-unused-service': [
    { note: "APP01's admin console is unused.", ticks: ['risk'] },
    { note: "Nobody uses APP01's console.", ticks: ['risk'] },
    { note: 'Unused console on APP01.', ticks: ['risk'] },
  ],
  'vm-needed-service': [
    { note: "APP01's admin console is unused.", not: ['risk'] },
    { note: "Nobody uses APP01's console.", not: ['risk'] },
    { note: 'Unused console on APP01.', not: ['risk'] },
  ],
  'vm-dup-plugins': [{ note: "The portal's detection is a duplicate: close it.", ticks: ['risk'] }],
  'vm-distinct': [{ note: "The portal's detection is a duplicate: close it.", not: ['risk'] }],
  'vm-waf-covers': [
    { note: 'The freeze is in effect until the next window; deploy the fix through the freeze by emergency change.', not: ['action'] },
    { note: 'The detect rule is in effect but it only logs.', not: ['action'] },
  ],
  'vm-legacy-accept': [
    { note: 'There is no approved exception for the controller.', not: ['risk'] },
    { note: 'Move the controller behind the OT controller VLAN ACL in the next window, then raise a risk exception to accept the finding.', not: ['action'] },
    { note: 'Raise a risk exception to accept the finding once it is isolated.', not: ['action'] },
    { note: 'The remaining risk is accepted under a new risk exception.', not: ['action'] },
    { note: "The controller's approved exception is still valid.", ticks: ['risk'] },
  ],
  'vm-legacy-isolate': [
    { note: 'There is no approved exception for the controller.', ticks: ['risk'] },
    { note: 'Move the controller behind the OT controller VLAN ACL in the next window, then raise a risk exception to accept the finding.', ticks: ['action'] },
    { note: 'The remaining risk is accepted under a new risk exception.', not: ['risk'] },
  ],
};

// Probes of the fifth review round: the honest last steps and notes of one twin that a keyword of the other twin's action item fitted
// ("accept it under a new exception", "stays in effect for logging", "can go in an emergency change"), and two of a twin's own phrasings.
const ROUND5: Record<string, Probe[]> = {
  'vm-legacy-accept': [
    { note: 'Once the ACL is in effect, accept the controller under a new risk exception.', not: ['risk', 'action'] },
    { note: "Accept LABCTL01's residual risk under a new risk exception.", not: ['risk', 'action'] },
    { note: 'Accept the risk on the controller under a new exception.', not: ['risk', 'action'] },
    { note: 'Once the ACL is in effect, accept the controller under a new risk exception, since there is no approved exception.', not: ['risk', 'action'] },
    { note: 'Accept the controller under the approved exception.', ticks: ['action'] },
    { note: "Accept LABCTL01's finding under the approved exception.", ticks: ['action'] },
    { note: 'The controller is reachable only from the OT management hosts.', ticks: ['risk'] },
    { note: "LABCTL01 is reachable only from the OT management hosts.", ticks: ['risk'] },
  ],
  'vm-legacy-isolate': [
    { note: 'Move LABCTL01 behind the ACL.', ticks: ['action'] },
    { note: "Move LABCTL01 behind the OT controller VLAN ACL in the next window.", ticks: ['action'] },
    { note: 'Once the ACL is in effect, accept the controller under a new risk exception.', ticks: ['action'], not: ['risk'] },
    { note: "Once the ACL is in effect, accept LABCTL01's residual risk under a new risk exception.", ticks: ['action'], not: ['risk'] },
    { note: 'Accept the risk on the controller under a new exception.', not: ['risk'] },
    { note: 'Accept the controller under the approved exception.', not: ['action'] },
  ],
  'vm-waf-covers': [
    { note: 'The detect rule stays in effect for logging, but it blocks nothing.', not: ['risk', 'action'] },
    { note: 'The detect rule stays in effect for logging.', not: ['risk', 'action'] },
    { note: 'The WAF rule stays in effect until the code release.', ticks: ['action'] },
  ],
  'vm-kev-internal': [
    { note: 'The headline is on Sim-KEV: the headline can go in an emergency change tonight.', ticks: ['risk', 'action'] },
    { note: 'The headline can go in an emergency change tonight.', ticks: ['action'] },
  ],
  'vm-nokev-internal': [
    { note: 'The headline is on Sim-KEV: the headline can go in an emergency change tonight.', not: ['risk', 'action'] },
    { note: 'The headline can go in an emergency change tonight.', not: ['action'] },
    { note: 'The headline can go in the standard cycle.', ticks: ['action'] },
    { note: 'The 7.5 goes in the standard cycle.', ticks: ['action'] },
    { note: 'The 7.5 goes in an emergency change.', not: ['action'] },
  ],
  'vm-exposed-edge': [{ note: 'Apply the permanent fix in the emergency change tonight.', ticks: ['action'] }],
  'vm-segmented': [
    { note: 'Apply the permanent fix in the emergency change tonight.', not: ['risk', 'action'] },
    { note: 'The permanent fix goes in the next window.', ticks: ['action'] },
    { note: 'The permanent fix in the next window.', ticks: ['action'] },
  ],
  'vm-saas-transfer': [
    { note: 'The advisory date is for the hosted tenants of the ticketing service, not for our install.', not: ['risk'] },
    { note: 'The vendor installs the update only for its hosted tenants; HELPDESK01 is ours.', not: ['risk'] },
  ],
  'vm-self-hosted': [{ note: 'The advisory date is for the hosted tenants of the ticketing service, not for our install.', not: ['risk'] }],
  'vm-stale-scan': [
    { note: "SQL01's monthly rollup fixes no application vulnerability; it is unrelated.", not: ['risk'] },
    { note: "FS02's later update was only a rollup.", ticks: ['risk'] },
  ],
  'vm-fresh-scan': [{ note: "SQL01's monthly rollup fixes no application vulnerability; it is unrelated.", not: ['risk'] }],
};

describe('every template has a rubric note for each twin', () => {
  it('covers every template', () => {
    expect(TEMPLATES.map((t) => t.id).sort()).toEqual(Object.keys(RISK_ACTION).sort());
    expect(Object.keys(PROBES).sort()).toEqual(Object.keys(RISK_ACTION).sort());
    for (const id of [...Object.keys(SHARED_FACT_PROBES), ...Object.keys(ROUND4), ...Object.keys(ROUND5)]) expect(Object.keys(RISK_ACTION), id).toContain(id);
  });
});

// ---- the date item ----------------------------------------------------------

const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const MONTH = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const ord = (n: number): string => (n % 100 >= 11 && n % 100 <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][n % 10] ?? 'th'));
const caseDates = (rubric: { id: string; keywords: string[] }[]): Set<string> =>
  new Set((rubric.find((r) => r.id === 'date')?.keywords ?? []).map((k) => /^ (\d{4}-\d{2}-\d{2}) $/.exec(k)?.[1]).filter((k): k is string => k !== undefined));

describe.each(TEMPLATES.map((t) => [t.id, t] as const))('%s stakeholder-note rubric', (id, t) => {
  it('has the four items, and a model note built from the case ticks all of them', () => {
    for (const run of RUNS) {
      const { facts, rubric } = factsOf(t, run);
      expect(rubric.map((r) => r.id), `${id} ${run.seed}: items`).toEqual([...ITEMS]);
      expect(hits(rubric, noteOf(id, facts)).sort(), `${id} ${run.world}/${run.seed}: model note`).toEqual([...ITEMS].sort());
    }
  });

  it('is not ticked by a note with no content: at most one item', () => {
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      for (const note of CONTENT_FREE) expect(hits(rubric, note).length, `${id} ${run.world}/${run.seed}: "${note.slice(0, 40)}" ticked ${hits(rubric, note).join(', ')}`).toBeLessThanOrEqual(1);
    }
  });

  it("is not ticked by the other twin's model note on the risk or the action item", () => {
    expect(t.twin, `${id} has a twin`).toBeTruthy();
    for (const run of RUNS) {
      const { facts, rubric } = factsOf(t, run);
      const got = hits(rubric, noteOf(t.twin!, facts));
      expect(got, `${id} ${run.world}/${run.seed}: twin note must not tick action`).not.toContain('action');
      expect(got, `${id} ${run.world}/${run.seed}: twin note must not tick risk`).not.toContain('risk');
    }
  });

  it("is not ticked by the other twin's honest variants (word order, possessive hosts, a negated clue) on the risk or the action item", () => {
    expect(VARIANTS[t.twin!]?.length, `${t.twin} has variants`).toBeGreaterThanOrEqual(2);
    const bad = new Set<string>();
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      for (const v of VARIANTS[t.twin!]) {
        for (const note of [`${v.risk} ${v.action}`, v.risk, v.action]) {
          for (const item of hits(rubric, note)) if (item === 'risk' || item === 'action') bad.add(`${item} <- "${note.slice(0, 70)}"`);
        }
      }
    }
    none([...bad], `${id}: the twin's variants tick this twin's items`);
  });

  it('honest variants of its own model note tick its risk and its action', () => {
    expect(VARIANTS[id]?.length, `${id} has variants`).toBeGreaterThanOrEqual(2);
    const bad = new Set<string>();
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      for (const v of VARIANTS[id]) {
        if (!hits(rubric, v.risk).includes('risk')) bad.add(`risk missed: "${v.risk.slice(0, 70)}"`);
        if (!hits(rubric, v.action).includes('action')) bad.add(`action missed: "${v.action.slice(0, 70)}"`);
        const both = hits(rubric, `${v.action} ${v.risk}`);
        if (!both.includes('risk') || !both.includes('action')) bad.add(`both orders missed: "${v.risk.slice(0, 50)}"`);
      }
    }
    none([...bad], `${id}: own variants`);
  });

  it('honest phrasings tick their item and wrong-twin or negated notes do not', () => {
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      for (const p of [...PROBES[id], ...(SHARED_FACT_PROBES[id] ?? []), ...(ROUND4[id] ?? []), ...(ROUND5[id] ?? [])]) {
        const got = hits(rubric, p.note);
        for (const item of p.ticks ?? []) expect(got, `${id} ${run.world}/${run.seed}: "${p.note}" must tick ${item}`).toContain(item);
        for (const item of p.not ?? []) expect(got, `${id} ${run.world}/${run.seed}: "${p.note}" must not tick ${item}`).not.toContain(item);
      }
    }
  });

  it('does not tick the date item on a word about an expiry or an end without a date', () => {
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      for (const note of ['The print server exception expires soon; patch it before the expiry.', 'The exception is valid until further notice and runs out eventually; expiration is near.']) expect(hits(rubric, note), `${id} ${run.world}/${run.seed}: "${note}"`).not.toContain('date');
    }
  });

  it('has only date keywords with a number: a word about an expiry or a deadline is never one', () => {
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      const bad = (rubric.find((r) => r.id === 'date')?.keywords ?? []).filter((k) => !/[0-9]|\b(three|seven|fourteen|thirty|ninety) (calendar )?days?\b/.test(k));
      expect(bad, `${id} ${run.world}/${run.seed}: date keywords without a number`).toEqual([]);
    }
  });

  it('ticks the date item on the right date alone, written in ISO form', () => {
    for (const run of RUNS) {
      const { facts, rubric } = factsOf(t, run);
      expect(hits(rubric, facts.next), `${id} ${run.world}/${run.seed}: next window date`).toContain('date');
      if (facts.expiry !== null) expect(hits(rubric, `valid to ${facts.expiry}`), `${id} ${run.world}/${run.seed}: exception expiry date`).toContain('date');
    }
  });

  it('ticks the date item on every way of writing it: at the start, in brackets, at the end, with an ordinal', () => {
    for (const run of RUNS) {
      const { facts, rubric } = factsOf(t, run);
      const d = new Date(`${facts.next}T00:00:00Z`);
      const n = d.getUTCDate();
      const m = d.getUTCMonth();
      const notes = [
        `${n} ${MON[m]} is the deadline.`,
        `${n} ${MONTH[m]}: patch the server.`,
        `Deadline (${n} ${MON[m]}).`,
        `Patch it by ${MON[m]} ${n}.`,
        `Patch it by ${MONTH[m]} ${n}`,
        `${MON[m]} ${n}: next window.`,
        `Due ${MONTH[m]} ${n}, 2026, in the next window.`,
        `The ${n}${ord(n)} of ${MONTH[m]}.`,
        `Next window on ${MON[m]} ${n}${ord(n)}.`,
        `${String(n).padStart(2, '0')}/${String(m + 1).padStart(2, '0')}/${d.getUTCFullYear()}`,
        `${n}-${MON[m]}-${d.getUTCFullYear()}`,
        `Fri ${n} ${MON[m]}`,
      ];
      for (const note of notes) expect(hits(rubric, note), `${id} ${run.world}/${run.seed}: "${note}"`).toContain('date');
    }
  });

  it('does not tick the date item on another day of the month, the month alone or a longer number', () => {
    for (const run of RUNS) {
      const { facts, rubric } = factsOf(t, run);
      const known = caseDates(rubric);
      const d = new Date(`${facts.next}T00:00:00Z`);
      const n = d.getUTCDate();
      const m = d.getUTCMonth();
      const wrongDays = [Number(`${n}1`), Number(`${n}0`), Number(`1${n}`)].filter((w) => w <= 31 && w !== n);
      const notes = [`${MONTH[m]} 2026, ${MONTH[(m + 1) % 12]} 2026 or ${MONTH[(m + 2) % 12]} 2026.`, `Sep 2026 / Oct 2026 / Nov 2026.`];
      const wrong: { note: string; w: number }[] = [];
      for (const w of wrongDays) {
        wrong.push({ note: `Patch it by ${MON[m]} ${w}.`, w }, { note: `Deadline: ${MONTH[m]} ${w}.`, w }, { note: `${w} ${MON[m]} is the deadline.`, w });
      }
      for (const note of notes) expect(hits(rubric, note), `${id} ${run.world}/${run.seed}: "${note}"`).not.toContain('date');
      for (const { note, w } of wrong) {
        if (known.has(`${d.getUTCFullYear()}-${String(m + 1).padStart(2, '0')}-${String(w).padStart(2, '0')}`)) continue; // that day is one of the case's own dates
        expect(hits(rubric, note), `${id} ${run.world}/${run.seed}: "${note}"`).not.toContain('date');
      }
    }
  });

  it('ticks the date item on a day count in brackets, at the start or hyphenated, and not on a longer count', () => {
    for (const run of RUNS) {
      const { rubric } = factsOf(t, run);
      const counts = (rubric.find((r) => r.id === 'date')?.keywords ?? []).map((k) => /^ (\d+) days $/.exec(k)?.[1]).filter((k): k is string => k !== undefined);
      expect(counts.length, `${id}: day counts`).toBeGreaterThan(0);
      for (const c of counts) {
        for (const note of [`SLA (${c} days).`, `${c}-day deadline.`, `${c} days from first detection.`]) expect(hits(rubric, note), `${id} ${run.world}/${run.seed}: "${note}"`).toContain('date');
        const longer = `1${c} days`;
        if (!counts.includes(`1${c}`)) expect(hits(rubric, `The window is ${longer} away.`), `${id}: "${longer}"`).not.toContain('date');
      }
    }
  });
});

// ---- containment guard -------------------------------------------------------

// No keyword of one twin's risk or action item may be contained in a keyword of the other twin's item of the same kind (it would match
// wherever the other twin's keyword does: "approved exception for X" in "no approved exception for X"), nor be equal to one. A keyword
// is allowed only when listed here with the pair, the item and the reason.
const CONTAINED_OK: { pair: [string, string]; item: 'risk' | 'action'; keyword: string; reason: string }[] = [];
const containedOk = (a: string, b: string, item: string, kw: string): boolean =>
  CONTAINED_OK.some((x) => x.item === item && x.keyword === kw && ((x.pair[0] === a && x.pair[1] === b) || (x.pair[0] === b && x.pair[1] === a)));

describe('no keyword of one twin is contained in a keyword of the other twin', () => {
  const pairs = TEMPLATES.filter((t) => t.id < t.twin!).map((t) => [t, TEMPLATES.find((x) => x.id === t.twin)!] as const);
  it.each(pairs.map(([a, b]) => [a.id, b.id, a, b] as const))('%s and %s', (idA, idB, a, b) => {
    const offences = new Set<string>();
    const inside = (small: string, big: string): boolean => vulnRubricHits([{ id: 'x', text: '', keywords: [small] }], big).length > 0;
    for (const run of RUNS) {
      const ra = factsOf(a, run).rubric;
      const rb = factsOf(b, run).rubric;
      for (const item of ['risk', 'action'] as const) {
        const ka = ra.find((r) => r.id === item)!.keywords;
        const kb = rb.find((r) => r.id === item)!.keywords;
        for (const x of ka) for (const y of kb) {
          if (inside(x, y) && !containedOk(idA, idB, item, x)) offences.add(`${item}: "${x}" (${idA}) is inside "${y}" (${idB})`);
          if (inside(y, x) && !containedOk(idA, idB, item, y)) offences.add(`${item}: "${y}" (${idB}) is inside "${x}" (${idA})`);
        }
      }
    }
    none([...offences].slice(0, 40), `${idA} / ${idB}`);
  });
});

describe('the legacy twin without an exception does not ask for an expiry', () => {
  it('asks for the date of the new exception, and holds no expiry date', () => {
    const isolate = VULN_CASE_TEMPLATES.find((x) => x.id === 'vm-legacy-isolate')!;
    const accept = VULN_CASE_TEMPLATES.find((x) => x.id === 'vm-legacy-accept')!;
    for (const run of RUNS) {
      const a = factsOf(accept, run).rubric.find((r) => r.id === 'date')!;
      const i = factsOf(isolate, run).rubric.find((r) => r.id === 'date')!;
      expect(i.text, `${run.seed}: isolate date text`).not.toMatch(/expir/i);
      expect(i.text, `${run.seed}: isolate date text holds no date`).not.toMatch(/\d{4}-\d{2}-\d{2}/);
      const expiry = factsOf(accept, run).facts.expiry!;
      const own = new Set([factsOf(isolate, run).facts.next, factsOf(isolate, run).facts.cycle]);
      if (!own.has(expiry)) {
        expect(i.keywords, `${run.seed}: the isolate twin must not ask for the accepted exception's expiry date ${expiry}`).not.toContain(` ${expiry} `);
        expect(vulnRubricHits([{ id: 'date', text: '', keywords: i.keywords }], `The exception is valid to ${expiry}.`), `${run.seed}: the expiry date alone does not tick the isolate date item`).toEqual([]);
      }
      expect(i.text).toMatch(/new risk exception/);
      expect(a.text).toMatch(/expires/);
      expect(a.keywords, `${run.seed}: the accepted exception's expiry date is a date keyword`).toContain(` ${factsOf(accept, run).facts.expiry} `);
      expect(i.keywords).not.toContain('expires');
      expect(a.keywords).not.toContain('expires');
      // the expiry date in the other forms a note writes it ticks the isolate item no more than the ISO form does
      if (!own.has(expiry)) {
        const d = new Date(`${expiry}T00:00:00Z`);
        const n = d.getUTCDate();
        const m = d.getUTCMonth();
        for (const note of [`The exception runs to ${n} ${MON[m]}.`, `Valid until ${MONTH[m]} ${n}.`, `Expiry: ${n}${ord(n)} of ${MONTH[m]}.`, `${String(n).padStart(2, '0')}/${String(m + 1).padStart(2, '0')}/${d.getUTCFullYear()}`]) {
          expect(vulnRubricHits([{ id: 'date', text: '', keywords: i.keywords }], note), `${run.seed}: "${note}"`).toEqual([]);
        }
      }
    }
  });
});
