// Guards against the class of bugs that make the same seed produce different
// cases on different machines, and against case rows being recognisable by
// their position or number.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { generateWorld } from '../src/core/world/world.ts';
import { buildPracticeCase } from '../src/core/cases/scenario.ts';

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : p.endsWith('.ts') ? [p] : [];
  });
}

describe('determinism hygiene in src/core', () => {
  it('uses no locale-dependent ordering or formatting, and no ambient randomness or clock', () => {
    const offenders: string[] = [];
    for (const f of files('src/core')) {
      const text = readFileSync(f, 'utf8');
      text.split('\n').forEach((line, i) => {
        if (/^\s*\/\//.test(line) || line.includes('determinism-exempt')) return;
        if (/localeCompare\(|toLocale\w*String\(\s*\)|Math\.random\(|Date\.now\(|new Date\(\)/.test(line)) offenders.push(`${f}:${i + 1}: ${line.trim()}`);
      });
    }
    expect(offenders).toEqual([]);
  });
});

describe('case rows are not recognisable by position', () => {
  it('evidence tickets are not reliably the last or highest-numbered ticket', () => {
    const templates = ['identity-rdp-bruteforce', 'identity-benign-lockout', 'identity-benign-vpn-travel', 'endpoint-benign-admin-psexec'];
    let last = 0;
    let highest = 0;
    let total = 0;
    for (const t of templates) {
      for (let i = 0; i < 4; i++) {
        const s = buildPracticeCase(generateWorld(`pos-${i}`), t, `p${i}`);
        const tickets = s.corpus.tables.Tickets;
        const ridCol = tickets.columns.indexOf('RecordId');
        const idCol = tickets.columns.indexOf('TicketId');
        const evidenceIds = new Set(s.cases[0].evidence.flatMap((e) => e.recordIds));
        const idx = tickets.rows.findIndex((r) => evidenceIds.has(String(r[ridCol])));
        if (idx < 0) continue;
        total++;
        if (idx === tickets.rows.length - 1) last++;
        const same = tickets.rows.filter((r) => String(r[idCol]).slice(0, 3) === String(tickets.rows[idx][idCol]).slice(0, 3));
        const max = same.map((r) => String(r[idCol])).sort().at(-1);
        if (max === tickets.rows[idx][idCol] && same.length > 1) highest++;
      }
    }
    expect(total).toBeGreaterThan(8);
    expect(last).toBeLessThan(total * 0.6);
    expect(highest).toBeLessThan(total * 0.8);
  });
});
