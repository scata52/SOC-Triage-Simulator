import { describe, it } from 'vitest';
import { emailTemplates } from '../../src/core/cases/templates/email.ts';
import { checkTemplate, standardRuns } from '../helpers/scenario-check.ts';

describe('email scenarios', () => {
  for (const t of emailTemplates) {
    it(`${t.id} builds, stays synthetic and is solvable`, async () => {
      await checkTemplate(t.id, standardRuns());
    });
  }
});
