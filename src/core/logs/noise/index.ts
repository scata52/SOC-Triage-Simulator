// Baseline activity for a corpus window. Each generator gets its own forked
// RNG stream so changing one source never reshuffles another.

import type { CorpusBuilder } from '../corpus.ts';
import { createNoiseCtx, type NoiseCtx } from './context.ts';
import { planSessions, type Session } from './presence.ts';
import { auditNoise, internetAuthNoise, signinNoise } from './identity.ts';
import { endpointNoise } from './endpoint.ts';
import { perimeterNoise, webNoise } from './network.ts';
import { emailNoise } from './email.ts';
import { alertNoise, contextNoise } from './intel.ts';

export interface NoiseOptions {
  historyFiller?: boolean;
}

export function generateNoise(b: CorpusBuilder, opts: NoiseOptions = {}): Session[] {
  const rng = b.rng.fork('noise');
  const sessions = planSessions(b, rng.fork('presence'));
  const base = createNoiseCtx(b, rng.fork('tickets'), sessions);
  const withRng = (label: string): NoiseCtx => ({ ...base, rng: rng.fork(label) });

  signinNoise(withRng('signin'));
  internetAuthNoise(withRng('internet-auth'));
  auditNoise(withRng('audit'));
  endpointNoise(withRng('endpoint'));
  webNoise(withRng('web'));
  perimeterNoise(withRng('perimeter'));
  emailNoise(withRng('email'));
  contextNoise(withRng('context'), { historyFiller: opts.historyFiller ?? false });
  alertNoise(withRng('alerts'));
  return sessions;
}

export type { Session } from './presence.ts';
