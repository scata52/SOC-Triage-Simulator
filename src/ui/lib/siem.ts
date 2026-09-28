// Promise client for the SIEM worker. A query that runs past the time
// budget (a pathological regex, a cross join) terminates the worker; the next
// request respawns it and reopens the last session, which is deterministic
// from its spec, so the analyst loses nothing but the runaway query.

import type { QueryError, QueryLang, QueryResult } from '../../core/query/engine.ts';
import type { LookupRow, OpenSpec, Request, Response, SessionInfo } from './protocol.ts';

export const QUERY_TIMEOUT_MS = 15_000;
// Tests shorten the budget through this global.
const timeoutMs = () => (globalThis as { __SOC_QUERY_TIMEOUT__?: number }).__SOC_QUERY_TIMEOUT__ ?? QUERY_TIMEOUT_MS;

export class QueryFailure extends Error {
  readonly start: number;
  readonly end: number;
  constructor(e: QueryError) {
    super(e.message);
    this.start = e.start;
    this.end = e.end;
  }
}

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void; timer?: ReturnType<typeof setTimeout> };
type Payload<T extends Request['type']> = T extends Request['type'] ? Omit<Extract<Request, { type: T }>, 'id'> : never;

class SiemClient {
  private worker: Worker | null = null;
  private seq = 0;
  private pending = new Map<number, Pending>();
  private lastSpec: OpenSpec | null = null;
  private opened: Promise<SessionInfo> | null = null;

  private spawn(): Worker {
    const w = new Worker(new URL('../workers/siem.worker.ts', import.meta.url), { type: 'module', name: 'siem' });
    w.addEventListener('message', (ev: MessageEvent<Response>) => {
      const r = ev.data;
      const p = this.pending.get(r.id);
      if (!p) return;
      this.pending.delete(r.id);
      if (p.timer) clearTimeout(p.timer);
      if (r.ok) p.resolve(r.data);
      else p.reject(new QueryFailure(r.error));
    });
    w.addEventListener('error', (ev) => this.reset(new Error(ev.message || 'The query engine stopped unexpectedly.')));
    return w;
  }

  private reset(reason: Error): void {
    this.worker?.terminate();
    this.worker = null;
    this.opened = null;
    for (const p of this.pending.values()) {
      if (p.timer) clearTimeout(p.timer);
      p.reject(reason);
    }
    this.pending.clear();
  }

  private post<T>(msg: Payload<Request['type']>, timeoutMs?: number): Promise<T> {
    const id = ++this.seq;
    this.worker ??= this.spawn();
    const w = this.worker;
    return new Promise<T>((resolve, reject) => {
      const p: Pending = { resolve: resolve as (v: unknown) => void, reject };
      if (timeoutMs) {
        p.timer = setTimeout(() => {
          this.reset(new QueryFailure({ message: `The query ran for more than ${Math.round(timeoutMs / 1000)} s and was stopped. Narrow it with a time filter, a more specific where, or take.`, start: 0, end: 0 }));
        }, timeoutMs);
      }
      this.pending.set(id, p);
      w.postMessage({ ...msg, id } as Request);
    });
  }

  // After a respawn the new worker has no session: reopen the last one first.
  private async ready(): Promise<void> {
    if (this.worker && this.opened) {
      await this.opened;
      return;
    }
    if (this.lastSpec) await this.open(this.lastSpec);
  }

  open(spec: OpenSpec): Promise<SessionInfo> {
    this.lastSpec = spec;
    const p = this.post<SessionInfo>({ type: 'open', spec });
    this.opened = p;
    p.catch(() => {
      if (this.opened === p) this.opened = null;
    });
    return p;
  }

  async run(text: string, lang: QueryLang, maxRows = 500): Promise<QueryResult> {
    await this.ready();
    return this.post<QueryResult>({ type: 'run', text, lang, maxRows }, timeoutMs());
  }

  async lookup(ids: string[]): Promise<LookupRow[]> {
    await this.ready();
    return this.post<LookupRow[]>({ type: 'lookup', ids }, timeoutMs());
  }
}

export const siem = new SiemClient();
