import { describe, it } from 'vitest';
import { opsTemplates } from '../../src/core/cases/templates/ops.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('ops scenarios', () => {
  for (const t of opsTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
