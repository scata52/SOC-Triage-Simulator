// Shared state for noise generators.

import type { Rng } from '../../rng.ts';
import type { CorpusBuilder } from '../corpus.ts';
import type { Session } from './presence.ts';

export interface NoiseCtx {
  b: CorpusBuilder;
  rng: Rng;
  sessions: Session[];
  off: number; // HQ utc offset
  nextTicket(prefix: 'CHG' | 'REQ' | 'TRV' | 'HR' | 'INC'): string;
}

export function createNoiseCtx(b: CorpusBuilder, rng: Rng, sessions: Session[]): NoiseCtx {
  return {
    b,
    rng,
    sessions,
    off: b.world.org.utcOffset,
    nextTicket: (prefix) => b.nextTicketId(prefix),
  };
}
