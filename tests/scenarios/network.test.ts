import { describe, it } from 'vitest';
import { networkTemplates } from '../../src/core/cases/templates/network.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('network scenarios', () => {
  for (const t of networkTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
