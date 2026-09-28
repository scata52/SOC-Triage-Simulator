// Context-table noise: routine travel/HR tickets, a commercial threat-intel
// feed covering the internet background, and (for standalone practice cases)
// a little incident history so the table is never empty.

import { DAY, HOUR } from '../time.ts';
import type { NoiseCtx } from './context.ts';

export function contextNoise(n: NoiseCtx, opts: { historyFiller: boolean }): void {
  const { b, rng } = n;
  const w = b.world;

  // Travel for field staff who are on the road, plus a conference trip.
  const travellers = new Map<string, string>();
  for (const s of n.sessions) if (s.location === 'travel' && s.travelCity) travellers.set(s.person.id, s.travelCity);
  for (const [id, city] of travellers) {
    const p = b.idx.person(id);
    b.ticket({ TicketId: n.nextTicket('TRV'), Type: 'Travel', Title: `Client visits — ${city}`, Requester: p.upn, AssignedTo: 'Travel desk', Status: 'Approved', Created: b.windowStart - rng.int(4, 20) * DAY, WindowStart: b.windowStart - rng.int(1, 2) * DAY, WindowEnd: b.windowEnd + rng.int(1, 3) * DAY, Scope: p.sam, Details: `Hotel and flights booked. Laptop on always-on VPN.` });
  }
  const conf = rng.pick(w.people.filter((p) => ['Engineering', 'Marketing', 'Security'].includes(p.department)));
  b.ticket({ TicketId: n.nextTicket('TRV'), Type: 'Travel', Title: `Conference attendance — ${rng.pick(['Lisbon', 'Barcelona', 'Amsterdam'])}`, Requester: conf.upn, AssignedTo: 'Travel desk', Status: 'Approved', Created: b.windowStart - 30 * DAY, WindowStart: b.windowEnd + rng.int(8, 30) * DAY, WindowEnd: b.windowEnd + rng.int(31, 34) * DAY, Scope: conf.sam, Details: 'Registration and travel approved by manager.' });

  // HR notices.
  const starter = rng.pick(w.people);
  b.ticket({ TicketId: n.nextTicket('HR'), Type: 'HR', Title: `New starter next month — reporting to ${starter.display}`, Requester: rng.pick(w.people.filter((p) => p.department === 'HR')).upn, AssignedTo: 'Service Desk', Status: 'Open', Created: b.windowStart - rng.int(2, 9) * DAY, Scope: starter.department, Details: 'Provision laptop and accounts one week before start date.' });

  // Standing change for patching.
  b.ticket({ TicketId: n.nextTicket('CHG'), Type: 'Change', Title: 'Monthly server patching — Saturday window', Requester: 'IT Infrastructure', AssignedTo: 'IT Infrastructure', Status: 'Scheduled', Created: b.windowStart - 6 * DAY, WindowStart: b.windowEnd + rng.int(1, 5) * DAY, WindowEnd: b.windowEnd + rng.int(5, 6) * DAY, Scope: 'All Windows servers', Details: 'Reboots expected.' });

  // Commercial TI feed: scanners, anonymizers, some already-blocked phish.
  const feed = rng.pick(['Harbourlight Threat Feed', 'Northstar Intel', 'Crescent Reputation Service']);
  for (const ip of rng.sample(w.internet.scanners, rng.int(8, 14))) {
    b.intel({ Indicator: ip, IndicatorType: 'ipv4', ThreatType: 'Scanner', Confidence: rng.int(50, 80), Source: feed, FirstSeen: b.now - rng.int(20, 300) * DAY, LastSeen: b.now - rng.int(0, 5) * DAY, Description: 'Mass internet scanning (ports 22, 23, 445, 3389).', Actor: '' });
  }
  for (const ip of w.internet.tor) {
    b.intel({ Indicator: ip, IndicatorType: 'ipv4', ThreatType: 'Anonymizer', Confidence: 90, Source: feed, FirstSeen: b.now - rng.int(30, 600) * DAY, LastSeen: b.now - rng.int(0, 2) * DAY, Description: 'Anonymity network exit node.', Actor: '' });
  }
  for (const r of b.rowsOf('EmailEvents')) {
    if (r.ThreatTypes === 'Phish' && rng.bool(0.6)) {
      const d = String(r.SenderMailFromDomain);
      b.intel({ Indicator: d, IndicatorType: 'domain', ThreatType: 'Phishing', Confidence: rng.int(60, 90), Source: feed, FirstSeen: b.now - rng.int(1, 10) * DAY, LastSeen: b.now - rng.int(0, 1) * DAY, Description: 'Credential-phishing kit hosting.', Actor: '' });
    }
  }
  for (let i = 0; i < rng.int(4, 8); i++) {
    b.intel({ Indicator: rng.hex(64), IndicatorType: 'sha256', ThreatType: 'Malware', Confidence: rng.int(70, 95), Source: feed, FirstSeen: b.now - rng.int(5, 200) * DAY, LastSeen: b.now - rng.int(0, 20) * DAY, Description: rng.pick(['Commodity infostealer.', 'Loader delivered via malvertising.', 'Ransomware precursor tooling.']), Actor: '' });
  }

  if (opts.historyFiller) {
    const analysts = w.people.filter((p) => p.department === 'Security');
    const items = [
      ['User-reported phish — marketing newsletter', 'Informational', 'Benign', 'Closed', 'Newsletter from a known sender; reassured the user.'],
      ['Malware blocked on endpoint', 'Low', 'True positive', 'Closed', 'Adware installer quarantined by AV on download; no execution.'],
      ['Atypical travel — VPN cloud gateway', 'Informational', 'Benign', 'Closed', 'Sign-in via corporate VPN egress; same compliant device.'],
      ['Multiple failed sign-ins — internet background', 'Low', 'Benign', 'Closed', 'Legacy-auth guessing from scanners, all failed; no success.'],
    ];
    for (const [title, sev, disp, status, summary] of rng.sample(items, rng.int(2, 4))) {
      b.incident({ IncidentId: n.nextTicket('INC'), Opened: b.windowStart - rng.int(3, 60) * DAY - rng.int(0, 10) * HOUR, Title: title, Severity: sev, Disposition: disp, Status: status, Analyst: rng.pick(analysts).display, Entities: '', Summary: summary });
    }
  }
}

// Background security alerts: low-severity detections that were
// auto-remediated or resolved, so the alert table is never just the answers.
export function alertNoise(n: NoiseCtx): void {
  const { b, rng } = n;
  const w = b.world;
  const endpoints = b.idx.endpoints();
  const count = rng.int(4, 8);
  for (let i = 0; i < count; i++) {
    const t = rng.int(b.windowStart, b.windowEnd);
    const kind = rng.int(0, 4);
    if (kind === 0) {
      const h = rng.pick(endpoints);
      b.alert({ TimeGenerated: t, AlertName: 'Potentially unwanted application blocked', ProductName: 'Microsoft Defender for Endpoint', AlertSeverity: 'Low', CompromisedEntity: h.name, Entities: h.owner, Tactics: 'Execution', Status: 'Auto-remediated', Description: 'A bundled toolbar installer was quarantined on download. No execution.' });
    } else if (kind === 1) {
      const p = rng.pick(w.people);
      b.alert({ TimeGenerated: t, AlertName: 'Unfamiliar sign-in properties', ProductName: 'Microsoft Entra ID Protection', AlertSeverity: 'Low', CompromisedEntity: p.upn, Entities: rng.pick(w.internet.hotels), Tactics: 'InitialAccess', Status: 'Resolved', Description: 'Sign-in from a new network; MFA completed on the registered device. Risk dismissed by policy.' });
    } else if (kind === 2) {
      const p = rng.pick(w.people);
      b.alert({ TimeGenerated: t, AlertName: 'Email messages containing phish URLs removed after delivery', ProductName: 'Microsoft Defender for Office 365', AlertSeverity: 'Informational', CompromisedEntity: p.upn, Entities: '', Tactics: 'InitialAccess', Status: 'Auto-remediated', Description: 'One message moved to quarantine by zero-hour auto purge before it was opened.' });
    } else if (kind === 3) {
      const p = rng.pick(w.people);
      b.alert({ TimeGenerated: t, AlertName: 'Anonymous IP address', ProductName: 'Microsoft Entra ID Protection', AlertSeverity: 'Medium', CompromisedEntity: p.upn, Entities: rng.pick(w.internet.tor), Tactics: 'InitialAccess', Status: 'Resolved', Description: 'Sign-in attempt from an anonymizer; failed on password. Blocked by Conditional Access.' });
    } else {
      const h = rng.pick(endpoints);
      b.alert({ TimeGenerated: t, AlertName: 'Suspicious PowerShell command line', ProductName: 'Microsoft Defender for Endpoint', AlertSeverity: 'Low', CompromisedEntity: h.name, Entities: 'SYSTEM, ccmexec.exe', Tactics: 'Execution', Status: 'Resolved', Description: 'Encoded command launched by the SCCM client. Classified benign (software inventory).' });
    }
  }
}
