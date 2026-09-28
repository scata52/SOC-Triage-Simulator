import { describe, it } from 'vitest';
import { endpointTemplates } from '../../src/core/cases/templates/endpoint.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('endpoint scenarios', () => {
  for (const t of endpointTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
