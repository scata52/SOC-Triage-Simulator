import { describe, it } from 'vitest';
import { identityTemplates } from '../../src/core/cases/templates/identity.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('identity scenarios', () => {
  for (const t of identityTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
