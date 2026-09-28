// Promise client for the SIEM worker.

import type { QueryError, QueryLang, QueryResult } from '../../core/query/engine.ts';
import type { LookupRow, OpenSpec, Request, Response, SessionInfo } from './protocol.ts';

export class QueryFailure extends Error {
  readonly start: number;
  readonly end: number;
  constructor(e: QueryError) {
    super(e.message);
    this.start = e.start;
    this.end = e.end;
  }
}

type Pending = { resolve: (v: unknown) => void; reject: (e: unknown) => void };
type Payload<T extends Request['type']> = T extends Request['type'] ? Omit<Extract<Request, { type: T }>, 'id'> : never;

class SiemClient {
  private worker: Worker | null = null;
  private seq = 0;
  private pending = new Map<number, Pending>();

  private ensure(): Worker {
    if (this.worker) return this.worker;
    const w = new Worker(new URL('../workers/siem.worker.ts', import.meta.url), { type: 'module', name: 'siem' });
    w.addEventListener('message', (ev: MessageEvent<Response>) => {
      const r = ev.data;
      const p = this.pending.get(r.id);
      if (!p) return;
      this.pending.delete(r.id);
      if (r.ok) p.resolve(r.data);
      else p.reject(new QueryFailure(r.error));
    });
    w.addEventListener('error', (ev) => {
      for (const p of this.pending.values()) p.reject(new Error(ev.message || 'The query engine stopped unexpectedly.'));
      this.pending.clear();
      this.worker = null;
    });
    this.worker = w;
    return w;
  }

  private send<T>(msg: Payload<Request['type']>): Promise<T> {
    const id = ++this.seq;
    const w = this.ensure();
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
      w.postMessage({ ...msg, id } as Request);
    });
  }

  open(spec: OpenSpec): Promise<SessionInfo> {
    return this.send({ type: 'open', spec });
  }

  run(text: string, lang: QueryLang, maxRows = 500): Promise<QueryResult> {
    return this.send({ type: 'run', text, lang, maxRows });
  }

  lookup(ids: string[]): Promise<LookupRow[]> {
    return this.send({ type: 'lookup', ids });
  }
}

export const siem = new SiemClient();
