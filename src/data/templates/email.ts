import type { CaseTemplate } from '../../types.ts';
import { artifact, kvBlock, rubric } from './util.ts';

// ---------------------------------------------------------------------------
// Credential-harvesting phishing, user clicked and submitted (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const credentialPhish: CaseTemplate = {
  id: 'email-phish-credential',
  category: 'phishing',
  difficulty: 'tier1',
  title: 'Reported email with a credential-harvesting link',
  cysaDomains: ['1.0', '3.0'],
  build({ faker }) {
    const victim = faker.identity();
    const lureDomain = faker.maliciousDomain();
    const proxyIp = faker.publicIp();

    return {
      alert: `User ${victim.username} reported an email via the "Report Phish" button. Secure email gateway had delivered it (verdict: none). Proxy shows the user then browsed to the linked site.`,
      context: `${faker.env.company} — Microsoft 365 mail with a third-party email gateway; web proxy logs available.`,
      artifacts: [
        artifact(
          'Email gateway — Message headers',
          'kv',
          kvBlock([
            ['From (display)', `"Microsoft 365 Security" <no-reply@${lureDomain}>`],
            ['Return-Path', `bounce@${lureDomain}`],
            ['Reply-To', `security-team@${lureDomain}`],
            ['Subject', '[Action Required] Your password expires today'],
            ['SPF', `pass (envelope domain ${lureDomain})`],
            ['DKIM', `pass (d=${lureDomain})`],
            ['DMARC', 'pass for sender domain — but sender domain is NOT microsoft.com'],
            ['Domain age', '4 days (newly registered)'],
            ['Link', `hxxps://${lureDomain}/owa/login?u=${victim.username}`],
          ]),
        ),
        artifact(
          'Email body (rendered summary)',
          'raw',
          [
            'Your Microsoft 365 password expires in 2 hours. To keep the same',
            'password, verify your identity now, otherwise your mailbox will be',
            'suspended.  [ Keep My Password ]  <- links to the domain above',
            '',
            'Urgency + brand impersonation + a link to a look-alike login page.',
          ],
        ),
        artifact(
          'Web proxy — user browsing',
          'raw',
          [
            `${faker.syslog(300)} proxy ALLOW ${victim.username} ${faker.privateIp()} GET https://${lureDomain}/owa/login 200 text/html`,
            `${faker.syslog(342)} proxy ALLOW ${victim.username} ${faker.privateIp()} POST https://${lureDomain}/owa/auth 302 (form submit, 412 bytes) -> ${proxyIp}`,
          ],
          'A POST to /auth means the credentials were very likely submitted.',
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1566.002', 'T1204.001'],
        tactics: ['initial-access', 'execution'],
      },
      rubric: rubric([
        ['alignment', 'SPF/DKIM/DMARC "pass" for the attacker\'s own domain — not for microsoft.com. Alignment is to the wrong domain.', ['spf', 'dkim', 'dmarc', 'alignment', 'domain', 'not microsoft']],
        ['newdomain', 'The sender domain is newly registered and impersonates a brand.', ['newly registered', 'domain age', 'new domain', 'impersonat', 'lookalike']],
        ['submitted', 'The proxy POST to /auth indicates the user submitted credentials — assume compromise.', ['post', 'submitted', 'credentials', 'compromise', 'harvest']],
        ['contain', 'Reset the user, revoke sessions, block the domain, and purge the mail org-wide.', ['reset', 'revoke', 'block', 'purge', 'contain']],
      ]),
      explanation: [
        `Passing SPF/DKIM/DMARC does not mean "legitimate". Those checks pass for the domain that actually sent the mail — here the attacker's own ${lureDomain}, registered four days ago. Alignment to microsoft.com fails; the brand is only in the display name. This is the single most common way analysts wrongly clear phishing.`,
        `The lure is textbook: password-expiry urgency, brand impersonation, and a link to an Outlook-look-alike login. The web proxy then shows a GET to the fake login followed by a POST to /auth from ${victim.username} — a form submission, i.e. the credentials were entered.`,
        `Treat ${victim.username} as compromised: reset the password, revoke sessions/refresh tokens, block ${lureDomain} at proxy and mail, and purge the message from all mailboxes. Then hunt for anyone else who received or clicked it.`,
      ],
      pitfalls: [
        'SPF/DKIM/DMARC "pass" is about the sending domain, not the impersonated brand — check alignment.',
        'A GET to the phishing page is a click; a POST is a credential submission. The POST raises severity.',
      ],
      references: [
        { label: 'ATT&CK T1566.002 Spearphishing Link', url: 'https://attack.mitre.org/techniques/T1566/002/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Malicious attachment, partially delivered before block (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const attachmentPhish: CaseTemplate = {
  id: 'email-phish-attachment',
  category: 'phishing',
  difficulty: 'tier2',
  title: 'Malware attachment campaign to finance',
  cysaDomains: ['1.0', '3.0'],
  build({ rng, faker }) {
    const sender = faker.maliciousDomain();
    const recipients = rng.int(9, 24);
    const delivered = rng.int(2, 5);
    const sha = faker.sha256();

    return {
      alert: `Email gateway retro-detonation flipped an attachment to MALICIOUS ${rng.int(20, 55)} minutes after delivery. ${recipients} recipients targeted; ${delivered} messages were delivered before the verdict updated.`,
      context: `${faker.env.company} — finance distribution list targeted with a fake invoice; sandbox detonation is asynchronous.`,
      artifacts: [
        artifact(
          'Email gateway — Campaign summary',
          'kv',
          kvBlock([
            ['Subject', 'Overdue Invoice #' + rng.int(40000, 99000) + ' — please remit'],
            ['Sender', `accounts@${sender}`],
            ['Attachment', 'Invoice_' + rng.int(1000, 9999) + '.html (HTML smuggling)'],
            ['SHA-256', sha],
            ['Initial verdict', 'Clean (0/72)'],
            ['Retro verdict', 'Malicious — drops ISO -> LNK -> script'],
            ['Recipients', `${recipients} (finance DL)`],
            ['Delivered before block', `${delivered}`],
            ['Clicked/opened', 'Under investigation'],
          ]),
        ),
        artifact(
          'Sandbox detonation (excerpt)',
          'json',
          [
            '{',
            '  "verdict": "malicious",',
            '  "behaviours": [',
            '    "html_smuggling_blob_decoded",',
            '    "iso_mounted_from_downloads",',
            '    "lnk_executes_powershell -nop -w hidden",',
            `    "beacon_attempt: ${faker.maliciousDomain()}:443"`,
            '  ],',
            `  "sha256": "${sha}"`,
            '}',
          ],
        ),
      ],
      groundTruth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: ['T1566.001'],
        tactics: ['initial-access'],
      },
      rubric: rubric([
        ['retro', 'A clean-then-malicious retro verdict means detonation lagged delivery — some mail landed.', ['retro', 'detonation', 'delivered', 'lag', 'sandbox']],
        ['smuggling', 'HTML smuggling -> ISO -> LNK -> PowerShell is the delivery chain to explain.', ['html smuggling', 'iso', 'lnk', 'powershell', 'chain']],
        ['purge', `Purge the ${delivered} delivered messages and confirm whether any were opened.`, ['purge', 'remove', 'opened', 'clicked', 'delivered']],
        ['hunt', 'Hunt endpoints for the SHA-256 / ISO-mount / beacon indicators.', ['hunt', 'sha', 'ioc', 'beacon', 'endpoint']],
      ]),
      explanation: [
        `Asynchronous sandboxing creates a delivery window: the gateway first scored the attachment clean, then retro-detonation flipped it to malicious. So ${delivered} messages reached finance inboxes before the block. Those delivered copies are the risk.`,
        `The chain — HTML smuggling that decodes a blob to an ISO, which contains an LNK that launches hidden PowerShell and beacons out — is a common loader pattern (used by many commodity and access-broker crews). Even one opened attachment could mean a foothold.`,
        `Escalate: purge the delivered messages from all mailboxes, determine whether any recipient opened the attachment (EDR process telemetry for the ISO mount / powershell child of explorer), and push the SHA-256 and beacon domain as IOCs to endpoint and network blocking.`,
      ],
      pitfalls: [
        'An initial "clean" verdict is not final when the gateway does async detonation — always check for a retro update.',
        'Blocking future copies is not enough; the already-delivered messages must be purged and the endpoints checked.',
      ],
      references: [
        { label: 'ATT&CK T1566.001 Spearphishing Attachment', url: 'https://attack.mitre.org/techniques/T1566/001/' },
      ],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign: legitimate marketing mail reported as phishing (BENIGN)
// ---------------------------------------------------------------------------
const benignMarketing: CaseTemplate = {
  id: 'email-benign-marketing',
  category: 'phishing',
  difficulty: 'tier1',
  title: 'User-reported "phishing" newsletter',
  cysaDomains: ['1.0'],
  build({ rng, faker }) {
    const esp = rng.pick(['sendgrid.net', 'mailchimp.com', 'mktomail.com', 'salesforce.com']);
    const brand = rng.pick(['LinkedIn', 'Atlassian', 'Zoom', 'Adobe', 'GitHub']);
    const brandDomain = brand.toLowerCase() + '.com';

    return {
      alert: `${faker.identity().username} used "Report Phish" on a marketing email ("${brand} — new features this month"). Auto-triage asks you to confirm.`,
      context: `${faker.env.company} — users are (correctly) encouraged to report anything suspicious; most reports are false alarms.`,
      artifacts: [
        artifact(
          'Email gateway — Message headers',
          'kv',
          kvBlock([
            ['From', `news@marketing.${brandDomain}`],
            ['Return-Path', `bounces@${esp}`],
            ['Sending service', `${esp} (known ESP on tenant allow-context)`],
            ['SPF', `pass (aligned to ${brandDomain} via ESP)`],
            ['DKIM', `pass (d=${brandDomain}, selector s1)`],
            ['DMARC', `pass — aligned to ${brandDomain}`],
            ['Domain age', `${rng.int(9, 20)} years`],
            ['List-Unsubscribe', 'present (RFC 8058 one-click)'],
            ['Links', `all resolve to https://${brandDomain}/...`],
          ]),
        ),
        artifact(
          'Reputation enrichment',
          'kv',
          kvBlock([
            ['Sender domain reputation', 'Good / established'],
            ['URL reputation', `Clean — ${brandDomain} verified`],
            ['Prior campaigns', 'Same sender seen monthly for 2+ years'],
            ['Attachments', 'None'],
            ['Why user flagged it', 'Unexpected/promotional — not malicious'],
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
        ['authpass', `SPF/DKIM/DMARC all pass AND align to ${brandDomain} — the real brand.`, ['spf', 'dkim', 'dmarc', 'aligned', 'pass']],
        ['legitesp', 'Sent via a known ESP with a one-click List-Unsubscribe — marketing, not malware.', ['esp', 'unsubscribe', 'list-unsubscribe', 'marketing', 'sendgrid']],
        ['links', `Links resolve to ${brandDomain}, not a look-alike.`, ['links', 'resolve', 'domain', 'legit', 'clean']],
        ['close', 'Benign; reassure the user and close (report-phish culture is still good).', ['benign', 'close', 'false positive', 'reassure']],
      ]),
      explanation: [
        `Here every authentication check passes and aligns to the real ${brandDomain}: SPF, DKIM (d=${brandDomain}), and DMARC alignment. The mail went out through a mainstream ESP (${esp}), carries an RFC-8058 one-click unsubscribe, has no attachments, and every link resolves to the genuine brand domain. That is what legitimate bulk marketing looks like.`,
        `Contrast with the credential-phish twin, where the checks "pass" only for an attacker-owned, days-old domain and the brand lives solely in the display name. The differentiator is alignment to the real domain plus domain age and history.`,
        `Disposition benign, informational. Close it, and thank the user — you want people reporting, even when it's a false alarm. If this exact sender generates lots of reports, an allow/known-sender note is reasonable tuning.`,
      ],
      pitfalls: [
        'Do not reflexively treat every user-reported email as malicious — most are benign, and clearing them well is core T1 work.',
        'Never punish reporting; a good close reinforces the behaviour you want.',
      ],
      references: [
        { label: 'DMARC alignment overview', url: 'https://dmarc.org/overview/' },
      ],
    };
  },
};

export const emailTemplates: CaseTemplate[] = [
  credentialPhish,
  attachmentPhish,
  benignMarketing,
];
