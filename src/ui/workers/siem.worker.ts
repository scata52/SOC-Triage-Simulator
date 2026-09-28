// The SIEM worker: builds the scenario (world + noise + cases) and hosts it in
// sql.js, off the main thread. One session at a time.

import initSqlJs, { type SqlJsStatic } from 'sql.js';
import wasmUrl from 'sql.js/dist/sql-wasm.wasm?url';
import { SiemDatabase, toQueryError } from '../../core/query/engine.ts';
import { generateWorld, type World } from '../../core/world/world.ts';
import { buildPracticeCase, type Scenario } from '../../core/cases/scenario.ts';
import { buildShift, planShift, type ShiftPlan } from '../../core/shift/plan.ts';
import { campaignContext, campaignSlot } from '../../core/campaign/campaign.ts';
import { TABLE_NAMES, type TableName } from '../../core/logs/schema.ts';
import { sessionKey, type OpenSpec, type Request, type Response, type SessionInfo } from '../lib/protocol.ts';

let sqlPromise: Promise<SqlJsStatic> | null = null;
const sql = () => (sqlPromise ??= initSqlJs({ locateFile: () => wasmUrl }));

let world: World | null = null;
let db: SiemDatabase | null = null;
let current: string | null = null;
let currentInfo: SessionInfo | null = null;

function worldFor(seed: string): World {
  if (!world || world.seed !== seed) world = generateWorld(seed);
  return world;
}

async function open(spec: OpenSpec): Promise<SessionInfo> {
  const key = sessionKey(spec);
  if (key === current && db && currentInfo) return currentInfo;
  const t0 = performance.now();
  const w = worldFor(spec.worldSeed);
  let scenario: Scenario;
  let plan: ShiftPlan | undefined;
  if (spec.kind === 'practice') {
    scenario = buildPracticeCase(w, spec.templateId, spec.seed);
  } else {
    const slot = spec.campaign ? campaignSlot(spec.campaign, w, spec.number) : undefined;
    plan = planShift({ world: w, seed: spec.worldSeed, number: spec.number, budget: spec.budget, campaign: slot, recent: spec.recent });
    scenario = buildShift(w, plan, spec.campaign ? campaignContext(spec.campaign, w, spec.number) : undefined);
  }
  const SQL = await sql();
  db?.close();
  db = new SiemDatabase(SQL, scenario.corpus);
  current = key;
  const rowsByTable = Object.fromEntries(TABLE_NAMES.map((t) => [t, scenario.corpus.tables[t].rows.length])) as Record<TableName, number>;
  currentInfo = {
    key,
    now: scenario.corpus.now,
    windowStart: scenario.corpus.windowStart,
    windowEnd: scenario.corpus.windowEnd,
    rowCount: scenario.corpus.rowCount,
    rowsByTable,
    cases: scenario.cases,
    infra: scenario.infra,
    plan,
    buildMs: Math.round(performance.now() - t0),
  };
  return currentInfo;
}

function reply(r: Response): void {
  self.postMessage(r);
}

self.addEventListener('message', async (ev: MessageEvent<Request>) => {
  const req = ev.data;
  try {
    if (req.type === 'open') {
      reply({ id: req.id, ok: true, type: 'open', data: await open(req.spec) });
    } else if (req.type === 'run') {
      if (!db) throw new Error('No case is open.');
      reply({ id: req.id, ok: true, type: 'run', data: db.run(req.text, req.lang, { maxRows: req.maxRows }) });
    } else if (req.type === 'lookup') {
      if (!db) throw new Error('No case is open.');
      reply({ id: req.id, ok: true, type: 'lookup', data: db.lookup(req.ids) });
    }
  } catch (e) {
    reply({ id: req.id, ok: false, error: toQueryError(e) });
  }
});
