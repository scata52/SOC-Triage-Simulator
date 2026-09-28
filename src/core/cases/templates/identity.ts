// Identity & access scenarios. Two twin pairs live here:
//  - atypical travel: account takeover vs. the corporate VPN gateway
//  - failures ending in lockouts/success: password spray vs. a stale phone
import type { CaseTemplate } from '../model.ts';
import type { Person } from '../../world/world.ts';
import { DAY, HOUR, MIN, SEC, atLocalHour, localWeekday } from '../../logs/time.ts';
import { haversineKm } from '../../synth/geo.ts';
import { userAgentOf } from '../../logs/noise/presence.ts';
import { mfaDetail } from '../../logs/noise/identity.ts';
import { BIN, binaryHash, documentName } from '../../synth/software.ts';
import { host, hm, ip, kdt, km, rubric, technique, user } from './util.ts';

const ATTACKER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// ---------------------------------------------------------------------------
// Atypical travel — real account takeover (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const impossibleTravel: CaseTemplate = {
  id: 'identity-impossible-travel',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Atypical travel sign-in',
  lesson: 'Account takeover with a replayed session token',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  twin: 'identity-benign-vpn-travel',
  stages: ['execution'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ dept: ['Finance', 'Executive', 'Sales', 'Operations'] });
    const site = idx.siteOf(victim);
    const device = pick.device(victim);
    const tBad = at - rng.int(4, 11) * MIN;
    const gap = rng.int(12, 45);
    const tGood = tBad - gap * MIN;
    const here = pick.where(victim, tGood);
    const hereGeo = log.geo[here.cloudIp];
    const hereCity = { city: hereGeo?.city ?? site.city.city, cc: hereGeo?.cc ?? site.city.cc, country: hereGeo?.country ?? site.city.country };
    const foreign = pick.city({ farFrom: site.city, minKm: 700 });
    const attacker = ctx.infra.ip('login', foreign);
    const distance = haversineKm(site.city, foreign);
    const speed = Math.round(distance / (gap / 60));

    log.signin({
      TimeGenerated: tGood, UserPrincipalName: victim.upn, AppDisplayName: 'Office 365 Exchange Online', ClientAppUsed: 'Browser', IPAddress: here.cloudIp,
      ResultType: 0, AuthenticationRequirement: 'multiFactorAuthentication', MfaDetail: '', MfaResult: 'MFA requirement satisfied by claim in the token',
      ConditionalAccessStatus: 'success', IncomingTokenType: 'primaryRefreshToken', DeviceId: device.deviceId, DeviceName: device.name, IsCompliant: true, IsManaged: true,
      OperatingSystem: 'Windows 11', Browser: 'Edge 131.0.2903', UserAgent: userAgentOf(victim), RiskLevelDuringSignIn: 'none',
    });
    const badBase = {
      UserPrincipalName: victim.upn, ClientAppUsed: 'Browser', IPAddress: attacker, ResultType: 0, AuthenticationRequirement: 'multiFactorAuthentication',
      MfaDetail: '', MfaResult: 'MFA requirement satisfied by claim in the token', ConditionalAccessStatus: 'success', IncomingTokenType: 'refreshToken',
      DeviceId: '', DeviceName: '', IsCompliant: false, IsManaged: false, OperatingSystem: 'Windows 10', Browser: 'Chrome 124.0.0', UserAgent: ATTACKER_UA,
    } as const;
    const bad = log.signin({ ...badBase, TimeGenerated: tBad, AppDisplayName: 'Office 365 Exchange Online', RiskLevelDuringSignIn: 'medium' });
    const bad2 = log.signin({ ...badBase, TimeGenerated: tBad + rng.int(60, 150) * SEC, AppDisplayName: 'Office 365 SharePoint Online', RiskLevelDuringSignIn: 'low' });
    const rule = log.audit({
      TimeGenerated: tBad + rng.int(100, 200) * SEC, Workload: 'Exchange', OperationName: 'New-InboxRule', Category: 'Mailbox', InitiatedBy: victim.upn, TargetResource: victim.upn, ClientIP: attacker,
      Details: 'Name: ..; SubjectOrBodyContainsWords: invoice, payment, wire, remittance, bank details; MoveToFolder: RSS Subscriptions; MarkAsRead: True; StopProcessingRules: True',
    });
    const mail = log.audit({ TimeGenerated: tBad + rng.int(30, 90) * SEC, Workload: 'Exchange', OperationName: 'MailItemsAccessed', Category: 'Mailbox', InitiatedBy: victim.upn, TargetResource: victim.upn, ClientIP: attacker, Details: `Items: ${rng.int(80, 400)}; ClientInfoString: Client=OWA; Throttled: False` });
    const downloads = Array.from({ length: rng.int(2, 4) }, (_, i) =>
      log.audit({ TimeGenerated: tBad + (4 + i * 2) * MIN + rng.int(0, 50) * SEC, Workload: 'SharePoint', OperationName: 'FileDownloaded', Category: 'File', InitiatedBy: victim.upn, TargetResource: `https://${world.org.tenant}.sharepoint.com/sites/Finance/Shared Documents/${documentName(rng, 'Finance', 'xlsx')}`, ClientIP: attacker, Details: `UserAgent: Chrome 124; Site: Finance` }),
    );

    return {
      alert: {
        rule: 'Atypical travel',
        product: 'Microsoft Entra ID Protection',
        severity: 'medium',
        time: at,
        summary: `Sign-ins for ${victim.upn} from ${hereCity.city} (${hereCity.cc}) and ${foreign.city} (${foreign.cc}) ${gap} minutes apart.`,
        entities: [
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'ip', value: here.cloudIp, label: hereCity.city },
          { kind: 'ip', value: attacker, label: foreign.city },
        ],
        fields: [['Risk detection', 'Atypical travel (offline)'], ['Risk level', 'Medium'], ['First location', `${hereCity.city}, ${hereCity.country}`], ['Second location', `${foreign.city}, ${foreign.country}`]],
      },
      briefing: `${world.org.name} is a cloud-first Microsoft 365 tenant; Conditional Access requires MFA for every user. ${victim.display} is ${victim.title} in ${victim.department}.`,
      truth: {
        disposition: 'true-positive', severity: 'high', action: 'escalate',
        techniques: ['T1078.004', 'T1564.008'], tactics: ['initial-access', 'defense-evasion'],
        alsoAccept: ['T1114.002', 'T1114.003', 'T1539', 'T1528', 'T1550.004', 'T1078'],
      },
      evidence: [
        { id: 'token', label: `The ${foreign.city} sign-in used no registered or compliant device and rode an existing token`, why: 'Legitimate sessions for this user come from a compliant, registered laptop. A token replayed from an unmanaged machine satisfies MFA without anyone approving anything.', rows: [bad, bad2] },
        { id: 'rule', label: 'A hidden inbox rule for invoice/payment/wire mail, created from the same IP', why: 'Moving finance replies to RSS Subscriptions and marking them read is the opening move of business email compromise.', rows: [rule] },
        { id: 'access', label: 'Mail and finance documents accessed from the attacker IP', why: 'The session was used, not just established — scope what was read and downloaded.', rows: [mail, ...downloads] },
      ],
      indicators: {
        block: [ip(attacker, 'Attacker sign-in source')],
        scope: [user(victim)],
        mustNot: [ip(here.cloudIp, "The user's genuine location"), ...world.vpn.egress.map((v) => ip(v.ip, 'Corporate VPN egress')), ip(site.natIp, 'Office egress')],
      },
      hints: [
        `Two cities, one account. Which sign-in is really ${victim.first}? Compare the device and token details behind each, and check whether ${attacker} is one of the organisation's own egress points.`,
        `SigninLogs | where UserPrincipalName == "${victim.upn}" | project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType`,
        `What did that session do next? Search the audit trail for activity from ${attacker}.`,
      ],
      solution: [
        { title: "Line up the user's sign-ins", kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}"\n| project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType, MfaResult\n| sort by TimeGenerated asc`, why: 'The normal sessions come from a compliant, registered laptop. The foreign one has no device at all and a replayed refresh token.' },
        { title: 'Is the foreign IP ours?', kql: 'NamedLocations', why: `Only the office egress and VPN gateways are trusted. ${attacker} is not among them, so no VPN explanation exists.` },
        { title: "Follow the attacker's IP through the audit log", kql: `AuditLogs\n| where ClientIP == "${attacker}"\n| project TimeGenerated, Workload, OperationName, TargetResource, Details`, why: 'Mail access, a finance-hiding inbox rule and SharePoint downloads — the session was used for BEC preparation.' },
      ],
      rubric: rubric([
        ['distance', `~${km(distance)} km in ${gap} minutes (~${km(speed)} km/h) — physically impossible without a VPN explanation, and there isn't one.`, ['km', 'speed', 'impossible', 'distance', 'travel']],
        ['device', 'The foreign sign-in came from an unregistered, non-compliant device.', ['device', 'unmanaged', 'compliant', 'unregistered', 'new device']],
        ['token', 'MFA "satisfied by claim in the token" from a foreign device means token theft/replay — MFA passing is not exoneration.', ['token', 'replay', 'mfa', 'refresh', 'stolen']],
        ['rule', 'The inbox rule hides invoice/payment/wire mail — business email compromise preparation.', ['inbox rule', 'rule', 'bec', 'hide', 'rss']],
        ['contain', 'Revoke sessions and refresh tokens, reset the password, remove the rule, and scope what was accessed.', ['revoke', 'reset', 'remove', 'contain', 'session']],
      ]),
      explanation: [
        `Two successful sign-ins for ${victim.upn}, ${gap} minutes apart, from ${hereCity.city} and ${foreign.city} — about ${km(distance)} km, an implied ${km(speed)} km/h. The ${hereCity.city} session is ${victim.first}'s normal pattern: their registered, compliant laptop ${device.name}. The ${foreign.city} session has no device ID at all and arrived with a refresh token rather than a fresh login, and ${attacker} is not one of the organisation's named locations.`,
        `The confirmer is what that session did: it read mail, downloaded finance spreadsheets, and created an inbox rule named ".." that moves anything mentioning invoices, payments or wires into RSS Subscriptions and marks it read. That is the textbook opening of business email compromise — hide the finance conversation from the real user while the attacker takes it over.`,
        `MFA shows as satisfied, but only "by claim in the token": the attacker replayed a session stolen earlier (commonly via an adversary-in-the-middle phishing kit), so no prompt ever fired. Escalate as a confirmed account takeover: revoke sessions and refresh tokens, reset the password, remove the rule, and work out what was read or sent.`,
      ],
      pitfalls: [
        'Do not close this because MFA shows as satisfied — token theft bypasses the prompt entirely.',
        'The device and the inbox rule are what separate this from the VPN twin; the alert name is identical.',
        `Don't block ${here.cloudIp} — that is where the real user is working from.`,
      ],
      references: [technique('T1078.004'), technique('T1564.008'), { label: 'Entra ID Protection risk detections', url: 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Password spray against Entra ID over legacy auth (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const passwordSpray: CaseTemplate = {
  id: 'identity-password-spray',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Failed sign-ins across many accounts',
  lesson: 'Password spray with one success over legacy IMAP',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  stages: ['initial-access'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const hq = world.sites[0].city;
    const city = pick.city({ farFrom: hq, minKm: 1200 });
    const ip1 = ctx.infra.ip('bruteforce', city);
    const ip2 = ctx.infra.ip('bruteforce2', city);
    const targets = pick.people(rng.int(38, 54));
    const compromised = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : rng.pick(targets.filter((p) => !p.adminAccount));
    if (!targets.includes(compromised)) targets.push(compromised);
    const start = at - rng.int(24, 32) * MIN;
    const span = 18 * MIN;
    const base = {
      AppDisplayName: 'Office 365 Exchange Online', AuthenticationRequirement: 'singleFactorAuthentication', MfaDetail: '', MfaResult: '', ConditionalAccessStatus: 'notApplied',
      IncomingTokenType: 'none', DeviceId: '', DeviceName: '', IsCompliant: false, IsManaged: false, OperatingSystem: '', Browser: '', UserAgent: 'BAV2ROPC', RiskLevelDuringSignIn: 'none',
    } as const;
    const failures = [];
    const order = rng.shuffle(targets);
    const successAt = start + Math.floor(span * rng.float(0.45, 0.8));
    for (let i = 0; i < order.length; i++) {
      const p = order[i];
      const tries = p === compromised ? 1 : rng.int(1, 2);
      for (let k = 0; k < tries; k++) {
        const t = start + Math.floor((span * (i + k * 0.5)) / order.length) + rng.int(0, 40) * SEC;
        if (p === compromised) continue;
        failures.push(log.signin({ ...base, TimeGenerated: t, UserPrincipalName: p.upn, IPAddress: rng.bool() ? ip1 : ip2, ClientAppUsed: rng.bool(0.8) ? 'IMAP4' : 'Authenticated SMTP', ResultType: 50126, RiskLevelDuringSignIn: rng.pick(['none', 'low']) }));
      }
    }
    const success = log.signin({ ...base, TimeGenerated: successAt, UserPrincipalName: compromised.upn, IPAddress: ip1, ClientAppUsed: 'IMAP4', ResultType: 0 });
    const follow = [
      ...Array.from({ length: rng.int(3, 6) }, (_, i) => log.signin({ ...base, TimeGenerated: successAt + (i + 1) * rng.int(40, 90) * SEC, UserPrincipalName: compromised.upn, IPAddress: ip1, ClientAppUsed: 'IMAP4', ResultType: 0 })),
      log.audit({ TimeGenerated: successAt + rng.int(2, 5) * MIN, Workload: 'Exchange', OperationName: 'MailItemsAccessed', Category: 'Mailbox', InitiatedBy: compromised.upn, TargetResource: compromised.upn, ClientIP: ip1, Details: `Items: ${rng.int(300, 2400)}; ClientInfoString: Client=IMAP4; Throttled: False` }),
    ];
    const accounts = targets.length;
    const attempts = failures.length;

    return {
      alert: {
        rule: 'Password spray suspected',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${attempts} failed sign-ins against ${accounts - 1}+ distinct accounts from 2 IP addresses in ${Math.round(span / MIN)} minutes.`,
        entities: [
          { kind: 'ip', value: ip1, label: city.city },
          { kind: 'ip', value: ip2, label: city.city },
        ],
        fields: [['Analytics rule', 'Many accounts, few attempts each, shared sources'], ['Window', `${hm(start)} – ${hm(start + span)}`]],
      },
      briefing: `${world.org.name} still allows legacy authentication (IMAP, SMTP AUTH) for a few old integrations; disabling it tenant-wide is on the roadmap. The internet scans this tenant constantly.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1110.003'], tactics: ['credential-access'], alsoAccept: ['T1078.004', 'T1114.002', 'T1078'] },
      evidence: [
        { id: 'breadth', label: 'Failures spread across many accounts from the same two IPs, one or two attempts each', why: 'Breadth, not depth, is the spray signature — it stays under per-account lockout thresholds. That is what separates it from the internet background of scattered guesses.', rows: failures },
        { id: 'success', label: `One account — ${compromised.upn} — succeeded`, why: 'The spray found a valid password. That turns noise into an incident.', rows: [success] },
        { id: 'use', label: 'The attacker then pulled the mailbox over IMAP', why: 'Legacy IMAP skips MFA and Conditional Access; the mailbox was downloaded.', rows: follow },
      ],
      indicators: { block: [ip(ip1, 'Spray source'), ip(ip2, 'Spray source')], scope: [user(compromised)], mustNot: [ip(world.sites[0].natIp, 'Office egress')] },
      hints: [
        'Failed sign-ins arrive all day from the internet. What makes these different — how many accounts, how many sources, how many tries each? And did any attempt from these IPs succeed?',
        `SigninLogs | where IPAddress in ("${ip1}", "${ip2}") | summarize Attempts = count(), Accounts = dcount(UserPrincipalName) by IPAddress, ResultType`,
        `SigninLogs | where IPAddress in ("${ip1}", "${ip2}") and ResultType == 0`,
      ],
      solution: [
        { title: 'Profile the failures by source', kql: 'SigninLogs\n| where ResultType != 0\n| summarize Attempts = count(), Accounts = dcount(UserPrincipalName) by IPAddress, ClientAppUsed\n| sort by Accounts', why: `Two IPs stand out: dozens of distinct accounts with one or two tries each over IMAP. Everything else is scattered background guessing.` },
        { title: 'Sample the spray', kql: `SigninLogs\n| where IPAddress in ("${ip1}", "${ip2}") and ResultType != 0\n| project TimeGenerated, UserPrincipalName, IPAddress, ClientAppUsed, ResultType\n| take 25`, why: 'One password, many accounts, low and slow.' },
        { title: 'Did anything succeed?', kql: `SigninLogs\n| where IPAddress in ("${ip1}", "${ip2}") and ResultType == 0\n| project TimeGenerated, UserPrincipalName, ClientAppUsed, AuthenticationRequirement`, why: `${compromised.upn} authenticated over IMAP with single-factor authentication — legacy auth never asks for MFA.` },
        { title: 'What did the attacker do with it?', kql: `AuditLogs\n| where ClientIP == "${ip1}"`, why: 'MailItemsAccessed: the mailbox was synchronised out.' },
      ],
      rubric: rubric([
        ['pattern', 'Spray pattern: one password across many accounts, few attempts each — not many passwords against one account.', ['spray', 'many accounts', 'one password', 'low and slow', 'breadth']],
        ['legacy', 'Legacy/basic auth (IMAP) is abused because it skips MFA and Conditional Access.', ['legacy', 'imap', 'basic auth', 'smtp', 'single factor']],
        ['success', `One account succeeded (${compromised.sam}) — treat it as compromised.`, ['success', 'compromised', 'succeeded', compromised.sam]],
        ['contain', 'Reset the compromised account, revoke sessions, block the sources, and disable legacy auth.', ['reset', 'block', 'disable legacy', 'conditional access', 'revoke']],
      ]),
      explanation: [
        `The signature of a password spray is breadth, not depth: a single common password tried once or twice against a long list of accounts, staying under per-account lockout thresholds. Here ${accounts - 1}+ accounts saw one to three IMAP attempts each from two addresses in ${city.city} — error 50126, invalid credentials. The same table is full of scattered internet guessing; aggregation by source is what makes this pattern jump out.`,
        `One attempt did not fail: ${compromised.upn} returned ResultType 0 over IMAP with single-factor authentication. Legacy protocols ignore Conditional Access and MFA, which is exactly why sprays target them. Minutes later the same IP pulled the mailbox (MailItemsAccessed via IMAP).`,
        `Escalate: reset ${compromised.first}'s password and revoke sessions, review what the mailbox exposed, block both sources, and push the legacy-auth shutdown forward — it is the control gap this attack walked through.`,
      ],
      pitfalls: [
        'Volume alone can look like a misconfigured client or background noise — the tell is many distinct accounts with few attempts each from shared sources.',
        'Do not stop at "lots of failures, all blocked". The single success is the incident.',
      ],
      references: [technique('T1110.003'), { label: 'Block legacy authentication', url: 'https://learn.microsoft.com/entra/identity/conditional-access/policy-block-legacy-authentication' }],
    };
  },
};

// ---------------------------------------------------------------------------
// RDP brute force against an accidentally exposed jump host (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const rdpBruteForce: CaseTemplate = {
  id: 'identity-rdp-bruteforce',
  category: 'identity',
  difficulty: 'tier1',
  title: 'Failed RDP logons on the jump host',
  lesson: 'RDP brute force through a forgotten firewall exception',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  stages: ['initial-access'],
  when: 'off-hours',
  build(ctx) {
    const { rng, log, pick, at, world } = ctx;
    const nat = world.sites[0].natIp;
    const attacker = ctx.infra.ip('bruteforce', pick.city());
    const netEng = pick.person({ dept: 'IT', working: false });
    const chgDay = at - rng.int(5, 9) * DAY;
    const chg = log.ticket({
      TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: 'Temporary: allow RDP to JUMP01 from the internet for vendor support', Requester: netEng.upn, AssignedTo: netEng.upn,
      Status: 'Implemented — removal overdue', Created: chgDay - DAY, WindowStart: chgDay, WindowEnd: chgDay + 2 * DAY, Scope: 'FW01, JUMP01',
      Details: `NAT TCP/3389 on ${nat} to JUMP01 (rule tmp-rdp-jump01). To be removed after the vendor session on ${new Date(chgDay + DAY).toISOString().slice(0, 10)}.`,
    });
    const exposed = log.patchDevice('JUMP01', { ExposedToInternet: true });

    // The open port attracts the internet background too.
    for (const scanner of rng.sample(world.internet.scanners, rng.int(4, 8))) {
      const t = rng.int(ctx.log.windowStart + HOUR, at - HOUR);
      log.fw({ TimeGenerated: t, Direction: 'Inbound', Action: 'Allow', SourceIP: scanner, SourcePort: rng.int(20000, 65000), DestinationIP: nat, DestinationPort: 3389, RuleName: 'tmp-rdp-jump01', BytesSent: rng.int(900, 3000), BytesReceived: rng.int(1500, 5000), SessionDurationSec: rng.int(1, 6) });
      for (let k = 0; k < rng.int(1, 4); k++) {
        log.sec({ TimeGenerated: t + k * rng.int(2, 9) * SEC, Computer: 'JUMP01', EventID: 4625, Account: '-', TargetAccount: rng.pick(['administrator', 'admin', 'user', 'test', 'guest']), LogonType: 10, IpAddress: scanner, WorkstationName: '-', AuthenticationPackage: 'NTLM', Status: '0xC000006D', SubStatus: rng.pick(['0xC000006A', '0xC0000064']) });
      }
    }

    const failuresN = rng.int(160, 300);
    const start = at - rng.int(50, 70) * MIN;
    const tSuccess = start + 26 * MIN + rng.int(0, 60) * SEC;
    const failures = [];
    for (let i = 0; i < failuresN; i++) {
      const t = start + Math.floor((i / failuresN) * 25 * MIN) + rng.int(0, 4) * SEC;
      const target = rng.bool(0.85) ? 'JUMP01\\Administrator' : rng.pick(['admin', 'backup', 'scanner', 'rdpuser']);
      failures.push(log.sec({ TimeGenerated: t, Computer: 'JUMP01', EventID: 4625, Account: '-', TargetAccount: target, LogonType: 10, IpAddress: attacker, WorkstationName: rng.pick(['kali', '-', 'WIN-7N3KQ0']), AuthenticationPackage: 'NTLM', Status: '0xC000006D', SubStatus: target.includes('Administrator') ? '0xC000006A' : '0xC0000064' }));
      if (i % 12 === 0) log.fw({ TimeGenerated: t, Direction: 'Inbound', Action: 'Allow', SourceIP: attacker, SourcePort: rng.int(40000, 65000), DestinationIP: nat, DestinationPort: 3389, RuleName: 'tmp-rdp-jump01', BytesSent: rng.int(2000, 6000), BytesReceived: rng.int(3000, 9000), SessionDurationSec: rng.int(1, 4) });
    }
    const success = log.sec({ TimeGenerated: tSuccess, Computer: 'JUMP01', EventID: 4624, Account: '-', TargetAccount: 'JUMP01\\Administrator', LogonType: 10, IpAddress: attacker, WorkstationName: 'WIN-7N3KQ0', AuthenticationPackage: 'Negotiate', ElevatedToken: 'Yes' });
    const session = log.fw({ TimeGenerated: tSuccess - 2 * SEC, Direction: 'Inbound', Action: 'Allow', SourceIP: attacker, SourcePort: rng.int(40000, 65000), DestinationIP: nat, DestinationPort: 3389, RuleName: 'tmp-rdp-jump01', BytesSent: rng.int(8_000_000, 30_000_000), BytesReceived: rng.int(40_000_000, 90_000_000), SessionDurationSec: rng.int(2200, 2700) });
    const acct = 'administrator';
    const paths: Record<string, string> = { 'powershell.exe': BIN.powershell.path, 'cmd.exe': BIN.cmd.path, 'whoami.exe': BIN.whoami.path, 'net.exe': BIN.net.path, 'nltest.exe': 'C:\\Windows\\System32\\nltest.exe' };
    const cmd = (t: number, file: string, line: string, parent = 'cmd.exe') =>
      log.proc({ TimeGenerated: t, DeviceName: 'JUMP01', AccountName: acct, FileName: file, FolderPath: paths[file], ProcessCommandLine: line, SHA256: binaryHash(file), Signer: 'Microsoft Windows', ProcessIntegrityLevel: 'High', InitiatingProcessFileName: parent, InitiatingProcessCommandLine: parent === 'cmd.exe' ? '"C:\\Windows\\system32\\cmd.exe"' : parent });
    const hands = [
      cmd(tSuccess + 70 * SEC, 'cmd.exe', '"C:\\Windows\\system32\\cmd.exe"', 'explorer.exe'),
      cmd(tSuccess + 95 * SEC, 'whoami.exe', 'whoami /all'),
      cmd(tSuccess + 140 * SEC, 'net.exe', 'net group "Domain Admins" /domain'),
      cmd(tSuccess + 200 * SEC, 'nltest.exe', `nltest /dclist:${world.org.adFqdn}`),
      cmd(tSuccess + 330 * SEC, 'powershell.exe', 'powershell.exe -ep bypass -c "Get-ADComputer -Filter * | Select-Object -ExpandProperty Name"'),
    ];

    return {
      alert: {
        rule: 'Brute force against Windows host',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${failuresN} failed logons (event 4625, logon type 10) on JUMP01 from ${attacker} within 25 minutes.`,
        entities: [
          { kind: 'host', value: 'JUMP01' },
          { kind: 'ip', value: attacker },
        ],
        fields: [['Threshold', '> 50 failures per source per 30 min'], ['Logon type', '10 — RemoteInteractive (RDP)']],
      },
      briefing: `${world.org.name}: JUMP01 is the RDP jump host administrators use to reach servers. It is normally reachable only from the internal network and VPN.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1110.001', 'T1133'], tactics: ['credential-access', 'initial-access'], alsoAccept: ['T1021.001', 'T1078.003', 'T1087.002', 'T1482', 'T1033', 'T1059.001', 'T1078'] },
      evidence: [
        { id: 'success', label: 'After the failures, the same IP logged on successfully as Administrator (4624, type 10, elevated)', why: 'A wall of failures is an attempt. The success from the same source is the compromise.', rows: [success] },
        { id: 'hands', label: 'Hands-on-keyboard discovery on JUMP01 right after the logon', why: 'whoami, Domain Admins enumeration, nltest and AD computer listing: an operator orienting before moving laterally.', rows: hands },
        { id: 'exposure', label: 'Why it was reachable: a "temporary" firewall change that was never removed', why: `The change exposed 3389 on the office egress to JUMP01 and was due for removal days ago.`, rows: [chg, exposed, session] },
      ],
      indicators: { block: [ip(attacker, 'Brute-force source')], scope: [host('JUMP01'), { kind: 'user', value: 'JUMP01\\Administrator', aliases: ['Administrator', 'administrator'] }], mustNot: [ip(nat, 'Office egress — blocking it takes the office offline')] },
      hints: [
        'Failures are an attempt. Did any logon from that address succeed — and if so, what happened in that session?',
        `SecurityEvent | where Computer == "JUMP01" and IpAddress == "${attacker}" | summarize count() by EventID, TargetAccount`,
        'JUMP01 should not be reachable from the internet at all. Check its CMDB entry, the firewall and recent changes.',
      ],
      solution: [
        { title: 'Outcome of the attempts', kql: `SecurityEvent\n| where Computer == "JUMP01" and IpAddress == "${attacker}"\n| summarize Attempts = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by EventID, TargetAccount`, why: 'Hundreds of 4625s against Administrator — and one 4624.' },
        { title: 'The successful logon', kql: `SecurityEvent\n| where Computer == "JUMP01" and EventID == 4624 and IpAddress == "${attacker}"`, why: 'Type 10 (RDP), elevated token.' },
        { title: 'What ran in that session', kql: `DeviceProcessEvents\n| where DeviceName == "JUMP01" and TimeGenerated > ${kdt(tSuccess)}\n| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessFileName`, why: 'Discovery commands typed by a human operator.' },
        { title: 'Why was RDP open to the internet?', kql: 'Tickets\n| where Scope has "JUMP01"', why: 'A temporary vendor exception that was never rolled back.' },
      ],
      rubric: rubric([
        ['exposure', 'RDP/3389 was exposed to the internet by a change that was never reverted — the root cause.', ['3389', 'rdp', 'exposed', 'internet', 'change', 'firewall']],
        ['bruteforce', 'Hundreds of 4625 failures then a 4624 success from the same IP = successful brute force.', ['4625', '4624', 'brute', 'failed logon', 'success']],
        ['hands', 'Post-logon discovery (whoami, Domain Admins, nltest) = hands-on-keyboard operator.', ['whoami', 'domain admins', 'nltest', 'discovery', 'hands-on']],
        ['contain', 'Isolate JUMP01, kill the session, reset the local admin, remove the NAT rule, and scope for lateral movement.', ['isolate', 'block', 'reset', 'firewall', 'contain', 'remove']],
      ]),
      explanation: [
        `Logon type 10 is RemoteInteractive — RDP. ${failuresN} 4625 failures (0xC000006A, bad password) against the local Administrator from ${attacker}, then a 4624 success from that same address with an elevated token: a successful RDP brute force. A handful of scanner IPs also bounced off the port; the attacker is the one that stayed, and got in.`,
        `Why JUMP01 was reachable at all is in the change log: a "temporary" NAT of 3389 for a vendor session, due to be removed days ago and still live. The CMDB now shows the host as internet-exposed.`,
        `The ${Math.round(2400 / 60)}-minute session was not idle: whoami, Domain Admins enumeration, a domain-controller list and an AD computer dump — an operator mapping the domain from a jump host that has line of sight to every server. Escalate: isolate JUMP01, terminate the session, rotate the local Administrator password, remove the NAT rule, and hunt for onward logons from JUMP01.`,
      ],
      pitfalls: [
        'A few failures then a success is ordinary fat-fingering; hundreds from one external IP is not.',
        `Blocking ${nat} would take the office offline — it is your own egress address.`,
        "Don't just reset the password — the live session, the exposure and the operator's next hop all need handling.",
      ],
      references: [technique('T1110.001'), technique('T1133')],
    };
  },
};

// ---------------------------------------------------------------------------
// MFA fatigue / push bombing (TRUE POSITIVE, harder)
// ---------------------------------------------------------------------------
const mfaFatigue: CaseTemplate = {
  id: 'identity-mfa-fatigue',
  category: 'identity',
  difficulty: 'tier3',
  title: 'Burst of MFA push notifications',
  lesson: 'MFA fatigue ending in an approval and a new attacker authenticator',
  cysaDomains: ['1.0', '3.0'],
  kind: 'incident',
  stages: ['initial-access'],
  when: 'any',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const pushUsers = world.people.filter((p) => p.mfaMethod === 'Push notification' && !p.adminAccount);
    const victim: Person = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : rng.pick(pushUsers.filter((p) => pick.sessionAt(p, at)).length ? pushUsers.filter((p) => pick.sessionAt(p, at)) : pushUsers);
    const site = idx.siteOf(victim);
    const city = pick.city({ farFrom: site.city, minKm: 1500 });
    const attacker = ctx.infra.ip('login', city);
    const pushes = rng.int(14, 31);
    const t0 = at - rng.int(12, 18) * MIN;
    const base = {
      UserPrincipalName: victim.upn, AppDisplayName: 'OfficeHome', ClientAppUsed: 'Browser', IPAddress: attacker, AuthenticationRequirement: 'multiFactorAuthentication',
      ConditionalAccessStatus: 'notApplied', IncomingTokenType: 'none', DeviceId: '', DeviceName: '', IsCompliant: false, IsManaged: false, OperatingSystem: 'Windows 10', Browser: 'Chrome 124.0.0', UserAgent: ATTACKER_UA,
    } as const;
    const challenge = log.signin({ ...base, TimeGenerated: t0, ResultType: 50074, MfaDetail: mfaDetail('Push notification'), MfaResult: '', RiskLevelDuringSignIn: 'low' });
    const denials = [];
    let t = t0 + 15 * SEC;
    for (let i = 0; i < pushes; i++) {
      t += rng.int(9, 24) * SEC;
      denials.push(log.signin({ ...base, TimeGenerated: t, ResultType: 500121, MfaDetail: 'Mobile app notification', MfaResult: rng.bool(0.4) ? 'MFA denied; user declined the authentication' : 'MFA denied; user did not respond to mobile app notification', RiskLevelDuringSignIn: 'medium' }));
    }
    const approved = log.signin({ ...base, TimeGenerated: t + rng.int(10, 30) * SEC, ResultType: 0, MfaDetail: 'Mobile app notification', MfaResult: 'MFA completed in Azure AD', ConditionalAccessStatus: 'success', RiskLevelDuringSignIn: 'medium' });
    const tA = t + 40 * SEC;
    const regInfo = log.audit({ TimeGenerated: tA + rng.int(60, 150) * SEC, Workload: 'AzureActiveDirectory', OperationName: 'User registered security info', Category: 'UserManagement', InitiatedBy: victim.upn, TargetResource: victim.upn, ClientIP: attacker, Details: 'Method: Microsoft Authenticator (new device "Pixel 7 Pro"); Existing methods retained' });
    const regDevice = log.audit({ TimeGenerated: tA + rng.int(180, 300) * SEC, Workload: 'AzureActiveDirectory', OperationName: 'Register device', Category: 'Device', InitiatedBy: victim.upn, TargetResource: `DESKTOP-${rng.alnum(7).toUpperCase()}`, ClientIP: attacker, Details: 'Join type: Microsoft Entra registered; OS: Windows 10' });
    const identity = log.identityRef(victim.upn);

    return {
      alert: {
        rule: 'Excessive MFA push requests for one user',
        product: 'Microsoft Sentinel',
        severity: 'medium',
        time: at,
        summary: `${pushes + 1} MFA push challenges for ${victim.upn} from ${attacker} (${city.city}) within ${Math.round((t - t0) / MIN) + 1} minutes.`,
        entities: [
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'ip', value: attacker, label: city.city },
        ],
        fields: [['Analytics rule', '> 10 MFA challenges for one user in 10 minutes'], ['MFA method on file', victim.mfaMethod]],
      },
      briefing: `${world.org.name} is rolling out number-matching MFA in waves; some users are still on plain Approve/Deny push notifications.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1621', 'T1078.004'], tactics: ['credential-access', 'initial-access'], alsoAccept: ['T1098.005', 'T1556', 'T1098', 'T1078'] },
      evidence: [
        { id: 'burst', label: 'A burst of declined / unanswered pushes from one foreign IP — the password was already correct', why: 'Each MFA challenge means the password step passed. The attacker already had the credential and was trying to wear the user down.', rows: [challenge, ...denials] },
        { id: 'approved', label: 'The burst ended in an approval', why: 'One tired tap handed over a session.', rows: [approved] },
        { id: 'persist', label: 'The attacker immediately registered their own authenticator and a device', why: 'Durable access that survives a password reset unless it is removed.', rows: [regInfo, regDevice] },
        { id: 'gap', label: `The user was still on Approve/Deny push, not number matching`, why: 'The control gap that made blind approval possible.', rows: [identity] },
      ],
      indicators: { block: [ip(attacker, 'Attacker source')], scope: [user(victim)], mustNot: [ip(pick.where(victim).cloudIp, "User's genuine location")] },
      hints: [
        'A flood of MFA challenges means the password step already succeeded. How did the flood end?',
        `SigninLogs | where UserPrincipalName == "${victim.upn}" and IPAddress == "${attacker}" | summarize count() by ResultType, MfaResult`,
        `Look for what the new session changed: AuditLogs | where ClientIP == "${attacker}"`,
      ],
      solution: [
        { title: 'How did the challenges end?', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}" and IPAddress == "${attacker}"\n| project TimeGenerated, ResultType, MfaResult\n| sort by TimeGenerated asc`, why: 'Denials and timeouts, then "MFA completed" — approved.' },
        { title: 'What did the attacker add?', kql: `AuditLogs\n| where ClientIP == "${attacker}"\n| project TimeGenerated, OperationName, TargetResource, Details`, why: 'A new authenticator and a registered device: persistence.' },
        { title: 'Why could this work?', kql: `IdentityInfo\n| where AccountUpn == "${victim.upn}"\n| project AccountUpn, MfaMethod, Department`, why: 'Plain push notifications — no number matching to break the blind tap.' },
      ],
      rubric: rubric([
        ['knownpw', 'The attacker already had the correct password — every MFA challenge implies the first factor passed.', ['password', 'correct', 'stolen', 'phish', 'first factor']],
        ['bombing', 'Repeated pushes = MFA fatigue / push bombing to wear the user down.', ['fatigue', 'bombing', 'push', 'spam', 'mfa']],
        ['approval', 'One approval is all it takes — treat the account as compromised from that moment.', ['approved', 'compromised', 'session', 'token']],
        ['persist', 'The attacker registered their own authenticator/device — remove it or the reset is useless.', ['registered', 'authenticator', 'device', 'persistence', 'security info']],
        ['fix', 'Revoke sessions, reset the password, remove the new method, and move the user to number matching.', ['number match', 'revoke', 'reset', 'remove', 'conditional access']],
      ]),
      explanation: [
        `Every MFA challenge in this burst means the password was already right — ${victim.first}'s credential was stolen earlier. Without the second factor, the attacker fired ${pushes} Approve/Deny prompts from ${city.city} in a few minutes, betting the user would eventually tap Approve to make it stop. They did.`,
        `Within minutes the new session registered an attacker-controlled authenticator app and an Entra-registered device. That is persistence: a password reset alone would leave the attacker a working second factor.`,
        `Escalate as an account compromise: revoke sessions and refresh tokens, reset the password, remove the attacker's authenticator and device, and move ${victim.first} to number matching — which defeats blind approval. The report should flag the incomplete number-matching rollout as the control gap.`,
      ],
      pitfalls: [
        'The denials before the approval can read as "the user rejected the spam" — the final approval flips it to a compromise.',
        'Resetting the password without removing the newly registered MFA method leaves the attacker in.',
      ],
      references: [technique('T1621'), technique('T1098.005'), { label: 'Number matching in MFA push', url: 'https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-number-match' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: atypical travel that is the corporate VPN cloud gateway
// ---------------------------------------------------------------------------
const benignTravel: CaseTemplate = {
  id: 'identity-benign-vpn-travel',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Atypical travel sign-in',
  lesson: 'Corporate VPN cloud gateway in another city',
  cysaDomains: ['1.0', '4.0'],
  kind: 'benign',
  twin: 'identity-impossible-travel',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const vpn = world.vpn.egress[1];
    // Someone genuinely away from the office right now: on the road, or at
    // home over VPN. Their day in the logs then agrees with the story.
    const away = ctx.sessions.filter((x) => x.start <= at && x.end >= at && (x.location === 'travel' || (x.location === 'home' && x.onVpn)));
    const session = away.length ? rng.pick(away) : undefined;
    const victim = session?.person ?? pick.person({ fieldSales: true });
    const device = pick.device(victim);
    const firstIp = session?.location === 'travel' && session.hotelIp ? session.hotelIp : victim.homeIp;
    const firstGeo = log.geo[firstIp];
    const firstCity = { city: firstGeo?.city ?? idx.siteOf(victim).city.city, cc: firstGeo?.cc ?? idx.siteOf(victim).city.cc, country: firstGeo?.country ?? idx.siteOf(victim).city.country };
    const tVpn = at - rng.int(6, 14) * MIN;
    const tEarlier = tVpn - rng.int(15, 45) * MIN;
    const base = {
      UserPrincipalName: victim.upn, ClientAppUsed: 'Browser', ResultType: 0, AuthenticationRequirement: 'multiFactorAuthentication', ConditionalAccessStatus: 'success',
      DeviceId: device.deviceId, DeviceName: device.name, IsCompliant: true, IsManaged: true, OperatingSystem: 'Windows 11', Browser: 'Edge 131.0.2903', UserAgent: userAgentOf(victim), RiskLevelDuringSignIn: 'none',
    } as const;
    const early = log.signin({ ...base, TimeGenerated: tEarlier, AppDisplayName: 'Office 365 Exchange Online', IPAddress: firstIp, MfaDetail: mfaDetail(victim.mfaMethod), MfaResult: 'MFA completed in Azure AD', IncomingTokenType: 'none' });
    const flagged = log.signin({ ...base, TimeGenerated: tVpn, AppDisplayName: rng.pick(['Salesforce', 'Office 365 SharePoint Online', 'Microsoft Teams']), IPAddress: vpn.ip, MfaDetail: '', MfaResult: 'MFA requirement satisfied by claim in the token', IncomingTokenType: 'primaryRefreshToken', RiskLevelDuringSignIn: 'low' });
    for (let i = 0; i < rng.int(2, 3); i++) {
      log.audit({ TimeGenerated: tVpn + (i + 1) * rng.int(60, 180) * SEC, Workload: 'SharePoint', OperationName: 'FileAccessed', Category: 'File', InitiatedBy: victim.upn, TargetResource: `https://${world.org.tenant}.sharepoint.com/sites/${victim.department}/Shared Documents/${documentName(rng, victim.department, 'pptx')}`, ClientIP: vpn.ip, Details: `UserAgent: Edge; Site: ${victim.department}` });
    }
    // Cite the travel request the service desk already has, if any.
    const trip = log.find('Tickets', (r) => r.Type === 'Travel' && r.Requester === victim.upn);
    const named = log.namedLocationRef(vpn.ip);
    const minutes = Math.round((tVpn - tEarlier) / MIN);

    return {
      alert: {
        rule: 'Atypical travel',
        product: 'Microsoft Entra ID Protection',
        severity: 'medium',
        time: at,
        summary: `Sign-ins for ${victim.upn} from ${firstCity.city} (${firstCity.cc}) and ${vpn.city.city} (${vpn.city.cc}) ${minutes} minutes apart.`,
        entities: [
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'ip', value: firstIp, label: firstCity.city },
          { kind: 'ip', value: vpn.ip, label: vpn.city.city },
        ],
        fields: [['Risk detection', 'Atypical travel (offline)'], ['Risk level', 'Medium'], ['First location', `${firstCity.city}, ${firstCity.country}`], ['Second location', `${vpn.city.city}, ${vpn.city.country}`]],
      },
      briefing: `${world.org.name} is a cloud-first Microsoft 365 tenant; Conditional Access requires MFA for every user. ${victim.display} is ${victim.title} in ${victim.department}.`,
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'vpn', label: `${vpn.ip} is the organisation's own VPN cloud gateway in ${vpn.city.city}`, why: 'Geolocation shows where the VPN gateway is, not where the user is. The "second city" is infrastructure you own.', rows: [named] },
        { id: 'device', label: 'Both sign-ins come from the same registered, compliant laptop with a normal primary refresh token', why: 'Continuity of device and token is what the account-takeover twin lacks.', rows: [flagged, early] },
        ...(trip ? [{ id: 'travel', label: 'An approved travel request covers today', why: 'Corroboration: the user is on the road and connecting via always-on VPN.', rows: [trip] }] : []),
      ],
      indicators: { block: [], scope: [], mustNot: [ip(vpn.ip, 'Corporate VPN egress — blocking it cuts off every remote worker'), ip(firstIp, "The user's own connection")] },
      hints: [
        `Before deciding this is a takeover: is ${vpn.ip} someone else's, or yours? And is the device behind both sign-ins the same one?`,
        `NamedLocations | where IPAddress == "${vpn.ip}"`,
        `SigninLogs | where UserPrincipalName == "${victim.upn}" | project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType`,
      ],
      solution: [
        { title: 'Is the "foreign" IP ours?', kql: `NamedLocations\n| where IPAddress == "${vpn.ip}"`, why: `It is the corporate VPN cloud gateway in ${vpn.city.city}.` },
        { title: 'Same device on both sides?', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}"\n| project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType\n| sort by TimeGenerated asc`, why: `${device.name}, compliant, with a primary refresh token — the same laptop throughout.` },
        ...(trip ? [{ title: 'Any corroboration?', kql: `Tickets\n| where Requester == "${victim.upn}"`, why: 'Approved travel covering today.' }] : []),
      ],
      rubric: rubric([
        ['vpn', `The "foreign" IP is the company's VPN egress in ${vpn.city.city} (NamedLocations).`, ['vpn', 'egress', 'gateway', 'named location', 'corporate']],
        ['samedevice', 'Both sign-ins use the same registered, compliant device with a normal refresh token.', ['same device', 'device', 'compliant', 'managed', 'intune']],
        ['corroborate', 'Approved travel and normal follow-on activity, no inbox rules or new devices.', ['travel', 'ticket', 'approved', 'normal', 'corroborate']],
        ['close', 'Benign — document the VPN explanation, close, and propose tuning (trusted location excluded from atypical travel).', ['benign', 'close', 'tune', 'exclude', 'false positive']],
      ]),
      explanation: [
        `This fires the same rule as a real takeover, so you have to check rather than pattern-match on the alert name. ${vpn.ip} is the organisation's own VPN cloud gateway in ${vpn.city.city} — it is in NamedLocations. GeoIP reports where the gateway sits, not where the user is.`,
        `Device continuity seals it: both sign-ins come from ${device.name}, registered and compliant, with a primary refresh token — exactly the signals the account-takeover twin lacks. ${trip ? 'There is an approved travel request for today, and the' : 'The'} follow-on activity is ordinary SharePoint use. No inbox rules, no new devices, no new MFA methods.`,
        `Disposition benign. Close with a note on the VPN explanation, and recommend tuning: sign-ins from trusted named locations should not feed atypical-travel. That recommendation is the Domain 4 part of the job.`,
      ],
      pitfalls: [
        'Escalating on the alert title alone. Same managed device plus an owned VPN egress is what makes it benign.',
        `Never list ${vpn.ip} as a malicious indicator — blocking your own VPN gateway takes every remote worker offline.`,
      ],
      references: [{ label: 'Named locations in Conditional Access', url: 'https://learn.microsoft.com/entra/identity/conditional-access/concept-assignment-network' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: repeated lockouts from a phone with a stale password
// ---------------------------------------------------------------------------
const benignLockout: CaseTemplate = {
  id: 'identity-benign-lockout',
  category: 'identity',
  difficulty: 'tier1',
  title: 'Repeated account lockouts',
  lesson: 'A phone mail app with a stale password after leave',
  cysaDomains: ['1.0'],
  kind: 'benign',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const off = world.org.utcOffset;
    const victim = pick.person({ mobile: true, dept: ['Finance', 'Sales', 'Marketing', 'Operations', 'HR', 'Legal', 'Engineering'] });
    const phone = idx.mobileOf(victim)!;
    const carrier = rng.pick(world.internet.carriers);
    // The previous Friday, 16:12 local.
    let friday = at - DAY;
    while (localWeekday(friday, off) !== 5) friday -= DAY;
    const pwdChange = atLocalHour(friday, 16.2, off);
    const identity = log.patchIdentity(victim.upn, { EmploymentStatus: 'Active — returned from leave today', LastPasswordChange: pwdChange });
    const hd = pick.person({ dept: 'Helpdesk', working: false });
    const reset = log.ticket({
      TicketId: log.nextTicketId('REQ'), Type: 'Service request', Title: `Password reset — ${victim.display} (expired during leave)`, Requester: victim.upn, AssignedTo: hd.upn, Status: 'Closed',
      Created: pwdChange - 12 * MIN, Scope: victim.sam, Details: 'Password expired during three weeks of leave. Reset by phone; user reminded to update the password on their phone mail app.',
    });
    // The phone is not syncing: remove any successful phone sign-ins from noise.
    log.drop('SigninLogs', (r) => r.UserPrincipalName === victim.upn && r.DeviceName === phone.name);

    const whereNow = pick.where(victim, at);
    const dayStart = whereNow.session?.start ?? atLocalHour(at, 8, off);
    const laptopOk = log.signin({
      TimeGenerated: dayStart + rng.int(3, 9) * MIN, UserPrincipalName: victim.upn, AppDisplayName: 'Microsoft Teams', ClientAppUsed: 'Mobile Apps and Desktop clients', IPAddress: whereNow.cloudIp,
      ResultType: 0, AuthenticationRequirement: 'multiFactorAuthentication', MfaDetail: mfaDetail(victim.mfaMethod), MfaResult: 'MFA completed in Azure AD', ConditionalAccessStatus: 'success',
      IncomingTokenType: 'none', DeviceId: whereNow.device.deviceId, DeviceName: whereNow.device.name, IsCompliant: true, IsManaged: true, OperatingSystem: 'Windows 11', Browser: 'Teams', UserAgent: userAgentOf(victim), RiskLevelDuringSignIn: 'none',
    });
    const failures = [];
    let lockouts = 0;
    let streak = 0;
    const firstFail = Math.max(ctx.log.windowStart + 5 * MIN, atLocalHour(at, 6.5, off) + rng.int(0, 20) * MIN);
    for (let t = firstFail; t < at - MIN; t += 10 * MIN + rng.int(-50, 50) * SEC) {
      streak++;
      const locked = streak > 5;
      if (locked && streak === 6) lockouts++;
      if (streak >= 7) streak = 0;
      failures.push(
        log.signin({
          TimeGenerated: t, UserPrincipalName: victim.upn, AppDisplayName: 'Office 365 Exchange Online', ClientAppUsed: 'Exchange ActiveSync', IPAddress: t < dayStart ? victim.homeIp : carrier,
          ResultType: locked ? 50053 : 50126, AuthenticationRequirement: 'singleFactorAuthentication', MfaDetail: '', MfaResult: '', ConditionalAccessStatus: 'notApplied', IncomingTokenType: 'none',
          DeviceId: phone.deviceId, DeviceName: phone.name, IsCompliant: phone.managed, IsManaged: phone.managed, OperatingSystem: phone.os.startsWith('iOS') ? 'iOS 19.0' : 'Android 16',
          Browser: 'Native mail client', UserAgent: phone.os.startsWith('iOS') ? 'Apple-iPhone17C1/2201.100' : 'Android-Mail/2026.08', RiskLevelDuringSignIn: 'none',
        }),
      );
    }
    lockouts = Math.max(1, lockouts);

    return {
      alert: {
        rule: 'Repeated account lockouts',
        product: 'Microsoft Sentinel',
        severity: 'low',
        time: at,
        summary: `${victim.upn} has ${failures.length} failed sign-ins since ${new Date(firstFail).toISOString().slice(11, 16)} UTC and has been locked out by smart lockout ${lockouts}+ times.`,
        entities: [{ kind: 'user', value: victim.upn, label: victim.display }],
        fields: [['Analytics rule', 'Lockouts > 2 per account per 4 hours']],
      },
      briefing: `${world.org.name} — ${victim.display} (${victim.title}, ${victim.department}).`,
      truth: { disposition: 'benign', severity: 'low', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'source', label: `Every failure is ${victim.first}'s own phone (${phone.name}) via Exchange ActiveSync, roughly every ten minutes`, why: 'One known device retrying on a timer is a mail client with a saved password, not an attacker.', rows: failures },
        { id: 'timeline', label: 'The password was reset on Friday after it expired during leave', why: 'The phone still holds the old password; every sync attempt fails and trips smart lockout.', rows: [identity, reset] },
        { id: 'works', label: 'Interactive sign-in on the laptop with the new password succeeded this morning', why: 'The user knows the new password — only the stale client fails.', rows: [laptopOk] },
      ],
      indicators: { block: [], scope: [], mustNot: [ip(carrier, 'Mobile carrier NAT shared by thousands of subscribers'), host(phone.name), ip(victim.homeIp, "User's home connection")] },
      hints: [
        'Where are the failures coming from — how many distinct sources, devices and client types? Is there a rhythm to them?',
        `SigninLogs | where UserPrincipalName == "${victim.upn}" | summarize count() by DeviceName, ClientAppUsed, ResultType`,
        'What changed for this user recently? Check the directory entry and the service desk.',
      ],
      solution: [
        { title: 'Where do the failures come from?', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}" and ResultType != 0\n| summarize Failures = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by DeviceName, ClientAppUsed, IPAddress`, why: `One source: the user's own ${phone.name} over Exchange ActiveSync.` },
        { title: 'The rhythm', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}" and ClientAppUsed == "Exchange ActiveSync"\n| project TimeGenerated, ResultType, IPAddress\n| sort by TimeGenerated asc`, why: 'A retry every ~10 minutes: a sync timer, not a human or an attack tool.' },
        { title: 'Does the new password work?', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}" and ResultType == 0\n| project TimeGenerated, DeviceName, ClientAppUsed, MfaResult`, why: `Yes — the laptop signs in fine. Only the phone is stuck on the old password.` },
        { title: 'What changed?', kql: `IdentityInfo\n| where AccountUpn == "${victim.upn}"\n| project AccountUpn, EmploymentStatus, LastPasswordChange`, why: 'Back from leave; password changed Friday.' },
        { title: 'Service desk record', kql: `Tickets\n| where Scope == "${victim.sam}"`, why: 'The reset ticket even notes the phone needed updating.' },
      ],
      rubric: rubric([
        ['staleclient', "The failures come from the user's own phone still caching the old password (ActiveSync).", ['stale', 'cached', 'phone', 'activesync', 'mobile', 'old password']],
        ['pwchange', 'Timeline lines up with Friday’s password reset after leave.', ['password change', 'reset', 'friday', 'ticket', 'timeline', 'leave']],
        ['single', 'One known device, a fixed retry rhythm, no other sources; the laptop sign-in works.', ['single', 'one device', 'rhythm', 'every 10', 'benign']],
        ['fix', 'Fix: update or remove the saved credential on the phone mail profile; close.', ['update', 'remove', 'credential', 'reconfigure', 'mail app']],
      ]),
      explanation: [
        `A classic self-inflicted lockout. ${victim.first}'s password expired during leave and was reset on Friday. Their phone's native mail app still holds the old one, so every ActiveSync poll — about every ten minutes — fails with 50126 and trips Entra smart lockout (50053).`,
        `There is no breadth: one source device the user owns, one client type, a timer-like rhythm, and the user's interactive sign-in on their laptop succeeds with the new password. None of the account-takeover or spray markers are present.`,
        `Disposition benign, severity low. The fix is operational — update or remove the saved password on the phone. Close with that note (and let the service desk know their reset script works).`,
      ],
      pitfalls: [
        'Lockouts feel security-relevant, but one owned device retrying an old password is IT hygiene, not an incident.',
        'If the failures came from an unfamiliar IP or many accounts, the disposition would flip — always confirm the source.',
        `Don't block ${carrier} — it is a mobile carrier's NAT used by thousands of people.`,
      ],
      references: [{ label: 'Entra smart lockout', url: 'https://learn.microsoft.com/entra/identity/authentication/howto-password-smart-lockout' }],
    };
  },
};

export const identityTemplates: CaseTemplate[] = [impossibleTravel, passwordSpray, rdpBruteForce, mfaFatigue, benignTravel, benignLockout];
