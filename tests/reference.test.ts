import { beforeAll, describe, expect, it } from 'vitest';
import { KQL_REFERENCE, referenceNames } from '../src/core/query/kql/reference.ts';
import { TABULAR_OPERATORS } from '../src/core/query/kql/parser.ts';
import { SiemDatabase } from '../src/core/query/engine.ts';
import { buildPracticeCase, type Scenario } from '../src/core/cases/scenario.ts';
import { world } from './helpers/scenario-check.ts';
import { sqljs } from './helpers/sql.ts';

let db: SiemDatabase;
let s: Scenario;

beforeAll(async () => {
  s = buildPracticeCase(world('reference'), 'endpoint-encoded-powershell', 'ref');
  db = new SiemDatabase(await sqljs(), s.corpus);
});

describe('KQL reference', () => {
  for (const e of KQL_REFERENCE) {
    it(`${e.kind} ${e.name}: example runs`, () => {
      expect(() => db.run(e.example, 'kql', { maxRows: 50 })).not.toThrow();
    });
  }

  it('documents every tabular operator', () => {
    const documented = new Set(referenceNames('operator'));
    const aliases = new Set(['filter', 'order', 'limit']);
    for (const op of TABULAR_OPERATORS) if (!aliases.has(op)) expect(documented, op).toContain(op);
  });

  it('has unique entries per kind', () => {
    const keys = KQL_REFERENCE.map((e) => `${e.kind}:${e.name}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
});

describe('SQL helpers documented in Help', () => {
  it('run as documented', () => {
    const q = "SELECT TimeGenerated, DeviceName, ProcessCommandLine\nFROM DeviceProcessEvents\nWHERE kql_has(ProcessCommandLine, 'hidden', 0)\nORDER BY TimeGenerated DESC\nLIMIT 20";
    expect(() => db.run(q, 'sql')).not.toThrow();
    for (const f of ["kql_contains(FileName, 'exe', 0)", "kql_regex(FileName, '^p')", "kql_extract('(\\w+)', 1, FileName)", "kql_b64decode('aGk=')"]) {
      expect(() => db.run(`SELECT ${f} AS x FROM DeviceProcessEvents LIMIT 1`, 'sql'), f).not.toThrow();
    }
  });
});

describe('record lookup', () => {
  it('returns whole evidence rows by RecordId, in the order asked', () => {
    const c = s.cases[0];
    const ids = c.evidence.flatMap((e) => e.recordIds).slice(0, 6).reverse();
    const rows = db.lookup([...ids, 'nope', "x' OR 1=1 --"]);
    expect(rows.map((r) => String(r.row.at(-1)))).toEqual(ids);
    for (const r of rows) expect(r.columns.at(-1)).toBe('RecordId');
    expect(db.lookup([])).toEqual([]);
  });
});
