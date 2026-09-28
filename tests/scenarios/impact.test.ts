import { describe, it } from 'vitest';
import { impactTemplates } from '../../src/core/cases/templates/impact.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('impact scenarios', () => {
  for (const t of impactTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
