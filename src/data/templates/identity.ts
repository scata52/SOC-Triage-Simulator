import type { CaseTemplate } from '../../types.ts';
import { artifact, kvBlock, table, rubric } from './util.ts';
import { haversineKm } from '../../engine/fakes.ts';

// ---------------------------------------------------------------------------
// Impossible travel — real account takeover (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const impossibleTravel: CaseTemplate = {
  id: 'identity-impossible-travel',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Atypical travel sign-in to Microsoft Entra ID',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const user = faker.identity();
    const home = faker.env.hqCity;
    let foreign = faker.cityElsewhere(home);
    for (let i = 0; i < 8 && haversineKm(home, foreign) < 4000; i++) {
      foreign = faker.cityElsewhere(home);
    }
    const homeIp = faker.publicIp();
    const foreignIp = faker.publicIp();
    const gapMin = rng.int(12, 35);
    const km = haversineKm(home, foreign);
    const impliedSpeed = Math.round(km / (gapMin / 60));
    const device = faker.guid();
    const foreignDevice = faker.guid();

    return {
      alert: `Entra ID Identity Protection raised "Atypical travel" (High) for ${user.upn}: two interactive sign-ins ${gapMin} minutes apart from ${home.city}, ${home.cc} and ${foreign.city}, ${foreign.cc}.`,
      context: `${faker.env.company} — cloud-first tenant, Conditional Access enforces MFA for all users.`,
      artifacts: [
        artifact(
          'Microsoft Entra ID — Sign-in logs',
          'table',
          table(
            ['Time (UTC)', 'User', 'IP', 'Location', 'Status', 'MFA', 'DeviceId'],
            [
              [faker.clock(0), user.username, homeIp, `${home.city}, ${home.cc}`, 'Success', 'Satisfied', device.slice(0, 8)],
              [faker.clock(gapMin * 60), user.username, foreignIp, `${foreign.city}, ${foreign.cc}`, 'Success', 'Satisfied', foreignDevice.slice(0, 8)],
            ],
          ),
          'Two successful interactive sign-ins for the same identity.',
        ),
        artifact(
          'Entra ID — Second sign-in detail',
          'kv',
          kvBlock([
            ['User', user.upn],
            ['Application', 'Office 365 Exchange Online'],
            ['IP address', foreignIp],
            ['Location', `${foreign.city}, ${foreign.country}`],
            ['Client app', 'Browser'],
            ['User agent', faker.userAgent()],
            ['Device ID', foreignDevice],
            ['Conditional Access', 'Success (MFA satisfied by token)'],
            ['Session', 'Reused primary refresh token'],
          ]),
        ),
        artifact(
          'Mailbox audit (post sign-in)',
          'raw',
          [
            `${faker.iso(gapMin * 60 + 90)}  New-InboxRule "..." created by ${user.upn}`,
            `  Rule: move messages containing "invoice","payment","wire" -> RSS Subscriptions; MarkAsRead=true`,
          ],
          'Activity seen minutes after the second sign-in.',
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1078.004'],
        tactics: ['initial-access', 'persistence', 'defense-evasion'],
      },
      rubric: rubric([
        ['distance', `Note the ~${km.toLocaleString()} km separation and ~${impliedSpeed.toLocaleString()} km/h implied speed — physically impossible.`, ['km', 'speed', 'impossible', 'distance', 'travel']],
        ['newdevice', 'The second sign-in used a different Device ID / unmanaged device.', ['device', 'deviceid', 'unmanaged', 'new device']],
        ['rule', 'A malicious inbox rule was created to hide finance-related replies (classic BEC).', ['inbox rule', 'rule', 'bec', 'forward', 'hide']],
        ['token', 'MFA showed "satisfied" via a reused/stolen token — MFA passing does not clear the account.', ['token', 'mfa', 'refresh', 'satisfied', 'stolen']],
        ['contain', 'Containment: revoke sessions/refresh tokens, force password reset, disable the inbox rule.', ['revoke', 'reset', 'disable', 'contain', 'session']],
      ]),
      explanation: [
        `Two successful sign-ins for ${user.upn} occurred ${gapMin} minutes apart from cities ~${km.toLocaleString()} km apart — an implied travel speed of ~${impliedSpeed.toLocaleString()} km/h. No human does that, and there is no VPN context that reconciles it here.`,
        `The confirmer is the follow-on activity: a new Device ID and an inbox rule that silently diverts and marks-as-read anything about invoices, payments or wires. That is the textbook opening move of Business Email Compromise — the attacker wants finance replies hidden from the real user.`,
        `Critically, MFA is "Satisfied". Attackers who steal a session/primary-refresh token ride the existing MFA claim, so a green MFA column is not exoneration. Treat this as a confirmed account takeover: revoke sessions and refresh tokens, force a password reset, remove the inbox rule, and hunt for what was accessed.`,
      ],
      pitfalls: [
        'Do not close this because "MFA was satisfied" — token theft bypasses the prompt entirely.',
        'The inbox rule is the tell that separates this from the benign-travel twin.',
      ],
      references: [
        { label: 'ATT&CK T1078.004 Cloud Accounts', url: 'https://attack.mitre.org/techniques/T1078/004/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Password spray against Entra ID (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const passwordSpray: CaseTemplate = {
  id: 'identity-password-spray',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Distributed failed sign-ins across many users',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const srcIp = faker.publicIp();
    const srcIp2 = faker.publicIp();
    const foreign = faker.cityElsewhere(faker.env.hqCity);
    const victims = Array.from({ length: 8 }, () => faker.identity());
    const compromised = rng.pick(victims);
    const rows = victims.map((v, i) => {
      const success = v.username === compromised.username;
      return [
        faker.clock(i * 7),
        v.username,
        rng.bool() ? srcIp : srcIp2,
        success ? 'Success' : 'Failure',
        success ? '0' : '50126',
        success ? '—' : 'Invalid username or password',
      ];
    });

    return {
      alert: `SIEM correlation "Password spray suspected": 220+ failed Entra ID sign-ins in 10 minutes spanning 60+ distinct accounts from 2 source IPs, followed by 1 success.`,
      context: `${faker.env.company} — legacy auth (IMAP/SMTP) not fully blocked; seamless SSO enabled.`,
      artifacts: [
        artifact(
          'Microsoft Entra ID — Sign-in logs (sample)',
          'table',
          table(['Time', 'User', 'Source IP', 'Result', 'Err', 'Reason'], rows),
          'Each account sees only 1–2 attempts; the pattern is one password tried broadly.',
        ),
        artifact(
          'Entra ID — Aggregates (last 10 min)',
          'kv',
          kvBlock([
            ['Distinct target accounts', 63],
            ['Total attempts', 224],
            ['Attempts per account', '1–3 (low & slow)'],
            ['Source IPs', `${srcIp}, ${srcIp2} (${foreign.country})`],
            ['Legacy auth protocol', 'IMAP4 / Basic'],
            ['Successful logons', `1 — ${compromised.username}`],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1110.003'],
        tactics: ['credential-access'],
      },
      rubric: rubric([
        ['pattern', 'Recognise the spray pattern: one password across many accounts (few attempts each) rather than many passwords against one.', ['spray', 'many accounts', 'one password', 'low and slow']],
        ['legacy', 'Legacy/basic auth (IMAP) is being abused to dodge modern controls.', ['legacy', 'imap', 'basic auth', 'smtp']],
        ['success', `One account succeeded (${compromised.username}) — treat it as compromised.`, ['success', 'compromised', 'succeeded', compromised.username]],
        ['contain', 'Reset the compromised account, block the source IPs, and disable legacy auth.', ['reset', 'block', 'disable legacy', 'conditional access']],
      ]),
      explanation: [
        `The signature of a password spray is breadth, not depth: a single common password (e.g. Season+Year) tried once or twice against a large list of accounts, staying under per-account lockout thresholds. Here 60+ accounts each saw only a handful of attempts — error 50126 (invalid credentials) — from two IPs.`,
        `One account, ${compromised.username}, returned error 0 (success). That is no longer just credential-access noise; it is a foothold. The legacy IMAP path matters because basic auth ignores Conditional Access/MFA, which is exactly why attackers target it.`,
        `Escalate: force-reset the successful account and audit its recent activity, block the source IPs, and accelerate disabling legacy authentication tenant-wide.`,
      ],
      pitfalls: [
        'Volume alone can look like a misconfigured client — the differentiator is many distinct accounts with few attempts each.',
        'Do not stop at "lots of failures". The single success is the incident.',
      ],
      references: [
        { label: 'ATT&CK T1110.003 Password Spraying', url: 'https://attack.mitre.org/techniques/T1110/003/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// RDP brute force from the internet (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const rdpBruteForce: CaseTemplate = {
  id: 'identity-rdp-bruteforce',
  category: 'identity',
  difficulty: 'tier1',
  title: 'Repeated RDP logon failures then a success',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const host = faker.server('RDP');
    const attacker = faker.publicIp();
    const local = rng.pick(['administrator', 'admin', 'backup', faker.identity().username]);
    const failures = rng.int(180, 640);

    return {
      alert: `EDR/Windows alert: ${failures} Event ID 4625 (failed logon, type 10/RemoteInteractive) on ${host} from a single external IP within 25 minutes, ending in a 4624 success.`,
      context: `${faker.env.company} — ${host} is a jump host with RDP (3389) exposed to the internet after a firewall change last week.`,
      artifacts: [
        artifact(
          'Windows Security — Event 4625 (sample)',
          'kv',
          kvBlock([
            ['Event ID', '4625 (An account failed to log on)'],
            ['Logon Type', '10 (RemoteInteractive / RDP)'],
            ['Target Account', local],
            ['Source Network Address', attacker],
            ['Failure Reason', '0xC000006A — bad password'],
            ['Count in window', `${failures} failures`],
            ['Workstation', host],
          ]),
        ),
        artifact(
          'Windows Security — Event 4624 (the success)',
          'kv',
          kvBlock([
            ['Time', faker.winTime(1500)],
            ['Event ID', '4624 (An account was successfully logged on)'],
            ['Logon Type', '10 (RemoteInteractive)'],
            ['Account', local],
            ['Source Network Address', attacker],
            ['Elevated Token', 'Yes'],
          ]),
        ),
        artifact(
          'Perimeter firewall',
          'raw',
          [
            `${faker.syslog(-60)} fw01 ALLOW tcp ${attacker}:${rng.int(40000, 61000)} -> ${host}:3389 (rule: rdp-jump-inbound)`,
            `${faker.syslog(1500)} fw01 ALLOW tcp ${attacker}:${rng.int(40000, 61000)} -> ${host}:3389 (rule: rdp-jump-inbound) session established 41m`,
          ],
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1110.001', 'T1021.001'],
        tactics: ['credential-access', 'lateral-movement'],
      },
      rubric: rubric([
        ['exposure', 'RDP/3389 is exposed to the internet — the root exposure enabling this.', ['3389', 'rdp', 'exposed', 'internet', 'perimeter']],
        ['bruteforce', `Hundreds of 4625 type-10 failures then a 4624 success = successful brute force.`, ['4625', '4624', 'brute', 'failed logon', 'success']],
        ['sameip', 'All failures and the success share one source IP — clear attribution.', ['same ip', 'source', attacker, 'single ip']],
        ['contain', 'Isolate the host, kill the RDP session, reset the account, and remove 3389 from the internet.', ['isolate', 'block', 'reset', 'firewall', 'contain']],
      ]),
      explanation: [
        `Logon type 10 is RemoteInteractive (RDP). A wall of 4625 failures (0xC000006A = bad password) against ${local} from one internet IP, terminating in a 4624 success from that same IP, is a successful RDP brute force — one of the most common initial-access vectors for ransomware crews.`,
        `The firewall log shows why it was reachable: 3389 was opened to the world by last week's change. The successful session then ran for ~40 minutes with an elevated token, so assume hands-on-keyboard access.`,
        `This is a clear escalation to incident response: isolate ${host}, terminate the session, reset ${local}, pull the 3389 exposure, and begin scoping what the attacker did during that session window.`,
      ],
      pitfalls: [
        'A few failures then a success is normal user fat-fingering; hundreds from an external IP is not.',
        "Don't just reset the password — the live session and the internet exposure must both be handled.",
      ],
      references: [
        { label: 'ATT&CK T1110.001 Password Guessing', url: 'https://attack.mitre.org/techniques/T1110/001/' },
      ],
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
  title: 'Burst of MFA push notifications, then an approval',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const user = faker.identity();
    const foreign = faker.cityElsewhere(faker.env.hqCity);
    const attackerIp = faker.publicIp();
    const pushes = rng.int(14, 31);

    return {
      alert: `Entra ID: ${pushes} MFA push requests for ${user.upn} in 6 minutes from IP ${attackerIp} (${foreign.country}); the ${pushes}th was Approved and a session was established.`,
      context: `${faker.env.company} — number-matching MFA was rolled out to only part of the org; ${user.username} is not yet in scope.`,
      artifacts: [
        artifact(
          'Entra ID — Authentication details',
          'table',
          table(
            ['Time', 'Method', 'Result', 'IP', 'Location'],
            [
              [faker.clock(0), 'Password', 'Correct', attackerIp, `${foreign.city}, ${foreign.cc}`],
              [faker.clock(20), 'Push', 'Denied', attackerIp, foreign.city],
              [faker.clock(45), 'Push', 'Denied', attackerIp, foreign.city],
              [faker.clock(80), 'Push', 'No response', attackerIp, foreign.city],
              ['...', `(${pushes - 4} more pushes)`, '...', attackerIp, foreign.city],
              [faker.clock(360), 'Push', 'Approved', attackerIp, foreign.city],
            ],
          ),
        ),
        artifact(
          'Entra ID — Context',
          'kv',
          kvBlock([
            ['User', user.upn],
            ['Password entered correctly', 'Yes — first attempt'],
            ['Push method', 'Approve/Deny (no number match)'],
            ['Registered device location', `${faker.env.hqCity.city}, ${faker.env.hqCity.cc}`],
            ['Requesting IP location', `${foreign.city}, ${foreign.country}`],
            ['Post-approval', 'Access token issued; device registration attempted'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1621', 'T1078.004'],
        tactics: ['credential-access', 'initial-access'],
      },
      rubric: rubric([
        ['knownpw', 'The attacker already has the correct password — first-attempt success means prior credential theft/phishing.', ['password', 'correct', 'stolen', 'phish']],
        ['bombing', 'Repeated pushes = MFA fatigue / push bombing to wear the user down.', ['fatigue', 'bombing', 'push', 'spam', 'mfa']],
        ['approval', 'One approval is all it takes — treat the account as compromised from that moment.', ['approved', 'compromised', 'session', 'token']],
        ['fix', 'Remediate and harden: revoke sessions, reset password, and enforce number-matching MFA.', ['number match', 'revoke', 'reset', 'harden', 'conditional access']],
      ]),
      explanation: [
        `The attacker already had ${user.username}'s valid password (correct on the first try), so this is post-credential-theft. Lacking the second factor, they generated a flood of Approve/Deny push prompts — MFA fatigue, aka push bombing — betting the user eventually taps Approve to make it stop. After ${pushes} prompts, someone did.`,
        `Because this tenant hadn't rolled number-matching to this user, a single careless tap handed over a session. The post-approval device-registration attempt is the attacker trying to plant durable access.`,
        `Escalate as an account compromise: revoke the session and refresh tokens, reset the password, remove any newly registered device/MFA method, and get this user into number-matching (which defeats blind-approve).`,
      ],
      pitfalls: [
        'The denials before the approval can look like the user rejecting spam — but the final Approve flips it to a compromise.',
        'Number-matching not being universal is the control gap to raise in your report.',
      ],
      references: [
        { label: 'ATT&CK T1621 MFA Request Generation', url: 'https://attack.mitre.org/techniques/T1621/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: atypical-travel that is actually the corporate VPN (BENIGN)
// ---------------------------------------------------------------------------
const benignTravel: CaseTemplate = {
  id: 'identity-benign-vpn-travel',
  category: 'identity',
  difficulty: 'tier2',
  title: 'Atypical travel alert on a sales user',
  cysaDomains: ['1.0'],
  build({ faker }) {
    const user = faker.identity();
    const home = faker.env.hqCity;
    const trip = faker.cityElsewhere(home);
    const device = faker.guid();
    const vpnEgress = faker.publicIp();

    return {
      alert: `Entra ID Identity Protection "Atypical travel" (Medium) for ${user.upn}: sign-ins from ${home.city}, ${home.cc} and ${trip.city}, ${trip.cc} on the same day.`,
      context: `${faker.env.company} — ${user.username} is on the field-sales team; company issues a split-tunnel VPN whose egress is in ${trip.city}.`,
      artifacts: [
        artifact(
          'Microsoft Entra ID — Sign-in logs',
          'table',
          table(
            ['Time', 'IP', 'Location', 'Status', 'MFA', 'DeviceId', 'Compliant'],
            [
              [faker.clock(0), faker.publicIp(), `${home.city}, ${home.cc}`, 'Success', 'Satisfied', device.slice(0, 8), 'Yes'],
              [faker.clock(3600 * 4), vpnEgress, `${trip.city}, ${trip.cc}`, 'Success', 'Satisfied', device.slice(0, 8), 'Yes'],
            ],
          ),
          'Same Device ID and compliant/managed device in both rows.',
        ),
        artifact(
          'Context enrichment',
          'kv',
          kvBlock([
            ['Device', 'Same Intune-managed, compliant laptop in both sign-ins'],
            ['Egress IP owner', `${faker.env.company} VPN concentrator (asset inventory)`],
            ['User travel', `Calendar shows an approved client trip to ${trip.city}`],
            ['Impossible speed?', 'No — 4-hour gap, and the "trip" IP is the corp VPN'],
            ['Post sign-in activity', 'Normal mailbox/SharePoint access, no rule changes'],
            ['Risk state', 'Identity Protection auto-lowered after device compliance'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'benign',
        severity: 'informational',
        action: 'close',
        techniques: [],
        tactics: [],
      },
      rubric: rubric([
        ['samedevice', 'Both sign-ins use the same managed, compliant Device ID.', ['same device', 'deviceid', 'managed', 'compliant', 'intune']],
        ['vpn', `The "foreign" IP belongs to the company VPN egress in ${trip.city}.`, ['vpn', 'egress', 'concentrator', 'corporate']],
        ['corroborate', 'Calendar/travel and normal follow-on activity corroborate legitimacy.', ['calendar', 'travel', 'approved', 'corroborate', 'normal']],
        ['close', 'Disposition benign; document why and close (optionally tune the rule).', ['benign', 'close', 'false positive', 'tune']],
      ]),
      explanation: [
        `This trips the same rule as a real takeover, so you must actually check rather than pattern-match on the alert name. Three things reconcile it: the same Intune-managed, compliant Device ID in both sign-ins; the "foreign" IP is the company's own VPN egress (confirmable in asset inventory); and the 4-hour gap is nowhere near impossible.`,
        `Enrichment seals it — an approved client trip on the calendar and completely normal follow-on activity, with none of the inbox-rule/new-device behaviour that marks account takeover.`,
        `Disposition benign. Close with a short note on the VPN-egress explanation. If this recurs for field-sales users, propose a named-location/rule exclusion so the tuning reduces future noise — that recommendation is the Domain 4 reporting piece.`,
      ],
      pitfalls: [
        'The trap is escalating on the alert title alone. Same managed device + owned VPN egress is what makes it benign.',
        'Still write it up — silent closes teach the SIEM nothing.',
      ],
      references: [
        { label: 'Entra ID Identity Protection risks', url: 'https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: account lockouts from a stale cached credential (BENIGN)
// ---------------------------------------------------------------------------
const benignLockout: CaseTemplate = {
  id: 'identity-benign-lockout',
  category: 'identity',
  difficulty: 'tier1',
  title: 'Repeated lockouts on a returning employee',
  cysaDomains: ['1.0'],
  build({ faker }) {
    const user = faker.identity();
    const phone = faker.laptop();
    const dc = faker.domainController();

    return {
      alert: `Account lockout alert: ${user.username} locked out (Event 4740) three times this morning; multiple 4625 failures across hosts.`,
      context: `${faker.env.company} — ${user.username} returned today from three weeks of leave and changed their password on Friday.`,
      artifacts: [
        artifact(
          'Windows Security — 4625 failures',
          'table',
          table(
            ['Time', 'Account', 'Caller Host', 'Logon Type', 'Status', 'Sub-status'],
            [
              [faker.clock(0), user.username, phone, '3 (Network)', '0xC000006A', '0xC0000064'],
              [faker.clock(600), user.username, phone, '3 (Network)', '0xC000006A', '—'],
              [faker.clock(1200), user.username, phone, '3 (Network)', '0xC000006A', '—'],
            ],
          ),
          'All failures originate from one device the user owns.',
        ),
        artifact(
          'Lockout source (Netlogon / DC)',
          'kv',
          kvBlock([
            ['Locking DC', dc],
            ['Bad password source', `${phone} (user's mobile — Exchange ActiveSync)`],
            ['Pattern', 'Every ~10 min = mail client retrying old password'],
            ['Password last set', 'Friday 16:12 (matches help-desk ticket)'],
            ['Other hosts affected', 'None — single stale client'],
            ['Interactive logon on workstation', 'Succeeded normally with new password'],
          ]),
        ),
      ],
      groundTruth: {
        disposition: 'benign',
        severity: 'low',
        action: 'close',
        techniques: [],
        tactics: [],
      },
      rubric: rubric([
        ['staleclient', "The failures come from the user's own phone still caching the old password (ActiveSync).", ['stale', 'cached', 'phone', 'activesync', 'mobile']],
        ['pwchange', 'Timeline lines up with a Friday password change and a help-desk ticket.', ['password change', 'friday', 'ticket', 'timeline']],
        ['single', 'One source device, no lateral spread, interactive logon works — not an attack.', ['single', 'one device', 'no spread', 'benign']],
        ['fix', 'Fix: update/remove the saved credential on the mobile mail profile.', ['update', 'remove', 'credential', 'reconfigure', 'mobile']],
      ]),
      explanation: [
        `Classic self-inflicted lockout. After a password change, any device still holding the old secret — most often a phone's ActiveSync mail profile — keeps retrying and burns through the lockout threshold every few minutes. Here every 4625 comes from one device the user owns, sub-status 0xC0000064/0xC000006A (bad user/bad password), and the timing matches a Friday reset with a help-desk ticket.`,
        `There's no breadth (one source, no other hosts), no external IP, and the user's interactive logon works fine with the new password. None of the account-takeover markers are present.`,
        `Disposition benign, severity low. Resolution is operational: update or remove the cached credential on the mobile mail client. Close with that note.`,
      ],
      pitfalls: [
        'Lockouts feel security-relevant, but a single owned device retrying an old password is an IT hygiene issue, not an incident.',
        'If the bad-password source were an unfamiliar host or external IP, the disposition would flip — always confirm the source.',
      ],
      references: [
        { label: 'Event 4740 account lockout', url: 'https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740' },
      ],
    };
  },
};

export const identityTemplates: CaseTemplate[] = [
  impossibleTravel,
  passwordSpray,
  rdpBruteForce,
  mfaFatigue,
  benignTravel,
  benignLockout,
];
