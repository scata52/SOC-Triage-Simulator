import { describe, expect, it } from 'vitest';
import { generateWorld } from '../src/core/world/world.ts';
import { CorpusBuilder, type Corpus } from '../src/core/logs/corpus.ts';
import { generateNoise } from '../src/core/logs/noise/index.ts';
import { createRng } from '../src/core/rng.ts';
import { HOUR } from '../src/core/logs/time.ts';
import { TABLE_NAMES, hasTimeColumn } from '../src/core/logs/schema.ts';
import { SCCM_INVENTORY_B64 } from '../src/core/logs/noise/endpoint.ts';
import { smartBase64Decode } from '../src/core/synth/encoding.ts';
import { syntheticViolations } from './helpers/guardrails.ts';

function build(worldSeed: string, seed: string, nowIso = '2026-09-23T13:20:00Z') {
  const world = generateWorld(worldSeed);
  const now = Date.parse(nowIso);
  const b = new CorpusBuilder({ world, rng: createRng(seed), windowStart: now - 20 * HOUR, windowEnd: now, now });
  generateNoise(b, { historyFiller: true });
  return { world, corpus: b.finalize() };
}

function col(c: Corpus, table: keyof Corpus['tables'], column: string): unknown[] {
  const t = c.tables[table];
  const i = t.columns.indexOf(column);
  return t.rows.map((r) => r[i]);
}

describe('noise corpus', () => {
  it('is deterministic', () => {
    expect(JSON.stringify(build('w', 's').corpus)).toBe(JSON.stringify(build('w', 's').corpus));
  });

  const cases = [
    ['w1', 's1', '2026-09-23T13:20:00Z'],
    ['w2', 's2', '2026-09-24T08:05:00Z'],
    ['w3', 's3', '2026-09-26T15:40:00Z'], // Saturday: skeleton staff
    ['w4', 's4', '2026-09-29T21:10:00Z'],
    ['w5', 's5', '2026-10-01T10:00:00Z'],
  ] as const;

  for (const [ws, s, now] of cases) {
    it(`${ws}/${now}: sane, ordered, consistent and synthetic`, () => {
      const { world, corpus } = build(ws, s, now);

      // Volume: a realistic haystack without being unwieldy (weekends are quiet).
      const weekend = [0, 6].includes(new Date(now).getUTCDay());
      expect(corpus.rowCount).toBeGreaterThan(weekend ? 400 : 2000);
      expect(corpus.rowCount).toBeLessThan(20000);

      // RecordIds unique across the whole corpus.
      const ids = TABLE_NAMES.flatMap((t) => (corpus.tables[t].columns.includes('RecordId') ? col(corpus, t, 'RecordId') : []));
      expect(new Set(ids).size).toBe(ids.length);

      // Log tables are time-ordered and inside the window.
      for (const t of TABLE_NAMES) {
        if (!hasTimeColumn(t)) continue;
        const times = col(corpus, t, 'TimeGenerated') as string[];
        for (let i = 1; i < times.length; i++) expect(times[i] >= times[i - 1]).toBe(true);
        for (const x of times) {
          expect(x >= corpus.windowStart).toBe(true);
          expect(x <= corpus.windowEnd).toBe(true);
        }
      }

      // Every endpoint in EDR tables exists in the CMDB.
      const devices = new Set(col(corpus, 'DeviceInfo', 'DeviceName') as string[]);
      for (const t of ['DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents'] as const) {
        for (const d of col(corpus, t, 'DeviceName')) expect(devices.has(d as string), `${t} ${d}`).toBe(true);
      }
      for (const c of col(corpus, 'SecurityEvent', 'Computer')) expect(devices.has(c as string), `SecurityEvent ${c}`).toBe(true);

      // Sign-ins are for org accounts.
      for (const u of col(corpus, 'SigninLogs', 'UserPrincipalName')) expect(String(u).endsWith(`@${world.org.domain}`)).toBe(true);

      // Guardrails over every cell.
      expect(syntheticViolations(corpus, world)).toEqual([]);
    });
  }

  it('contains the decoys the templates rely on', () => {
    // Across a few corpora, the benign look-alikes must show up.
    let encodedPs = 0;
    let sevenZip = 0;
    let certutil = 0;
    let inboxRules = 0;
    let tasks = 0;
    let legacyAuthFailures = 0;
    for (let i = 0; i < 4; i++) {
      const { corpus } = build(`decoy-${i}`, `d${i}`);
      const cmd = col(corpus, 'DeviceProcessEvents', 'ProcessCommandLine') as string[];
      encodedPs += cmd.filter((c) => c.includes('-EncodedCommand')).length;
      sevenZip += cmd.filter((c) => c.includes('7z.exe')).length;
      certutil += cmd.filter((c) => c.startsWith('certutil')).length;
      inboxRules += (col(corpus, 'AuditLogs', 'OperationName') as string[]).filter((o) => o === 'New-InboxRule').length;
      tasks += (col(corpus, 'SecurityEvent', 'EventID') as number[]).filter((e) => e === 4698).length;
      legacyAuthFailures += (col(corpus, 'SigninLogs', 'ClientAppUsed') as string[]).filter((c) => c === 'IMAP4').length;
    }
    expect(encodedPs).toBeGreaterThan(5);
    expect(sevenZip).toBeGreaterThan(0);
    expect(certutil).toBeGreaterThan(0);
    expect(inboxRules).toBeGreaterThan(0);
    expect(tasks).toBeGreaterThan(4);
    expect(legacyAuthFailures).toBeGreaterThan(10);
  });

  it('SCCM encoded command decodes to the benign inventory script', () => {
    const d = smartBase64Decode(SCCM_INVENTORY_B64);
    expect(d?.encoding).toBe('utf-16le');
    expect(d?.text).toContain('Win32_InstalledWin32Program');
  });
});
