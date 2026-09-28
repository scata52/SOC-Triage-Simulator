import { it } from 'vitest';
import { generateWorld } from '../src/core/world/world.ts';
import { buildPracticeCase } from '../src/core/cases/scenario.ts';
import { SiemDatabase } from '../src/core/query/engine.ts';
import { sqljs } from './helpers/sql.ts';

const WORLDS = ['review-a', 'review-b', 'review-c'];
const SEEDS = ['r1', 'r2', 'r3'];
const worlds = new Map(WORLDS.map((w) => [w, generateWorld(w)]));

function fmt(r: { columns: { name: string }[]; rows: unknown[][] }, max = 12): string {
  const cols = r.columns.map((c) => c.name);
  return [cols.join(' | '), ...r.rows.slice(0, max).map((row) => row.map((v) => String(v ?? '')).join(' | ')), r.rows.length > max ? `... (${r.rows.length} rows)` : ''].join('\n');
}

const TEMPLATE = process.env.PROBE ?? 'identity-impossible-travel';
const QUERIES: Record<string, (c: any) => string[]> = JSON.parse('{}');

it('probe', async () => {
  const out: string[] = [];
  const SQL = await sqljs();
  for (const wn of WORLDS) {
    for (const seed of SEEDS) {
      const w = worlds.get(wn)!;
      const s = buildPracticeCase(w, TEMPLATE, seed);
      const c = s.cases[0];
      const db = new SiemDatabase(SQL, s.corpus);
      const q = (kql: string, max = 12) => {
        try {
          return fmt(db.run(kql, 'kql', { maxRows: 5000 }), max);
        } catch (e) {
          return `ERR ${(e as Error).message}`;
        }
      };
      const byId = (ids: string[]) => ids.map((id) => `"${id}"`).join(',');
      out.push(`===== ${wn}/${seed} at=${c.alert.time} now=${s.now} offset=${w.org.utcOffset}`);
      out.push(`ALERT: ${c.alert.summary}`);
      out.push(`ENT: ${JSON.stringify(c.alert.entities)}`);
      out.push(`FIELDS: ${JSON.stringify(c.alert.fields)}`);
      const ctx = { c, s, w, q, byId };
      for (const line of (globalThis as any).PROBES[TEMPLATE](ctx)) out.push(line);
      db.close();
    }
  }
  throw new Error(out.join('\n'));
}, 600_000);

(globalThis as any).PROBES = {
  'identity-impossible-travel': ({ c, w, q }: any) => {
    const upn = c.alert.entities[0].value;
    return [
      `SITE/VPN: ${w.sites.map((x: any) => x.city.city + ' ' + x.natIp).join('; ')} VPN: ${w.vpn.egress.map((v: any) => v.city.city + ' ' + v.ip).join('; ')}`,
      q(`SigninLogs | where UserPrincipalName == "${upn}" | project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType, ResultType, AppDisplayName | sort by TimeGenerated asc`, 40),
    ];
  },
  'identity-benign-vpn-travel': ({ c, w, q }: any) => {
    const upn = c.alert.entities[0].value;
    return [
      `SITE/VPN: ${w.sites.map((x: any) => x.city.city + ' ' + x.natIp).join('; ')} VPN: ${w.vpn.egress.map((v: any) => v.city.city + ' ' + v.ip).join('; ')}`,
      q(`SigninLogs | where UserPrincipalName == "${upn}" | project TimeGenerated, IPAddress, City, DeviceName, IsCompliant, IncomingTokenType, AppDisplayName | sort by TimeGenerated asc`, 40),
      q(`Tickets | where Type == "Travel"`),
    ];
  },
  'identity-benign-lockout': ({ c, q }: any) => {
    const upn = c.alert.entities[0].value;
    const sam = upn.split('@')[0];
    return [
      q(`IdentityInfo | where AccountUpn == "${upn}" | project EmploymentStatus, LastPasswordChange, MfaMethod`),
      q(`SigninLogs | where UserPrincipalName == "${upn}" | summarize n = count(), first = min(TimeGenerated), last = max(TimeGenerated) by DeviceName, ClientAppUsed, ResultType, IPAddress`, 30),
      q(`DeviceProcessEvents | where AccountName == "${sam}" | summarize n = count(), first = min(TimeGenerated), last = max(TimeGenerated)`),
      q(`SecurityEvent | where TargetAccount has "${sam}" | summarize n = count(), first = min(TimeGenerated), last = max(TimeGenerated) by EventID`),
    ];
  },
  'identity-password-spray': ({ q }: any) => [
    q('SigninLogs\n| where ResultType != 0\n| summarize Attempts = count(), Accounts = dcount(UserPrincipalName) by IPAddress, ClientAppUsed\n| sort by Accounts', 8),
    q('SigninLogs | where ResultType == 50053 | summarize count() by UserPrincipalName | sort by count_', 5),
  ],
  'identity-rdp-bruteforce': ({ q }: any) => [
    q('DeviceProcessEvents | where FileName in ("powershell.exe","cmd.exe","whoami.exe","net.exe","nltest.exe") | summarize Hashes = dcount(SHA256), Paths = make_set(FolderPath) by FileName'),
    q('SecurityEvent | where Computer == "JUMP01" and EventID == 4624 | project TimeGenerated, TargetAccount, LogonType, IpAddress, WorkstationName', 10),
    q('DeviceProcessEvents | where DeviceName == "JUMP01" | project TimeGenerated, AccountName, ProcessCommandLine, SHA256', 10),
  ],
  'identity-mfa-fatigue': ({ c, q }: any) => {
    const upn = c.alert.entities[0].value;
    const ip = c.alert.entities[1].value;
    return [
      q(`SigninLogs | where UserPrincipalName == "${upn}" and IPAddress == "${ip}" | summarize n = count(), first = min(TimeGenerated), last = max(TimeGenerated) by ResultType`),
      q(`AuditLogs | where ClientIP == "${ip}" | project TimeGenerated, OperationName`),
      q('SigninLogs | where ResultType == 500121 | summarize count() by UserPrincipalName'),
      q('AuditLogs | where OperationName == "User registered security info" | project TimeGenerated, InitiatedBy, ClientIP, Details'),
    ];
  },
};
