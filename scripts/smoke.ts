// Deterministic smoke test: every template x many seeds must build without
// throwing, reference only catalogued techniques, and grade a perfect answer
// at 100%. Run with: npm test
import { ALL_TEMPLATES } from '../src/data/templates/index.ts';
import { generateCase, regenerateFromId } from '../src/engine/generator.ts';
import { gradeResponse, MAX_SCORE } from '../src/engine/grading.ts';
import { technique } from '../src/data/mitre.ts';
import { cysaDomain } from '../src/data/cysa.ts';

const SEEDS_PER_TEMPLATE = 40;
let failures = 0;

function fail(msg: string): void {
  failures++;
  console.error('FAIL:', msg);
}

for (const t of ALL_TEMPLATES) {
  for (let i = 0; i < SEEDS_PER_TEMPLATE; i++) {
    const seed = `smoke-${t.id}-${i}`;
    let c;
    try {
      c = generateCase({ seed, templateId: t.id });
    } catch (e) {
      fail(`${t.id} seed ${i} threw: ${(e as Error).message}`);
      continue;
    }

    if (c.templateId !== t.id) fail(`${t.id}: templateId mismatch`);
    if (!c.alert.trim()) fail(`${t.id}: empty alert`);
    if (c.artifacts.length === 0) fail(`${t.id}: no artifacts`);
    for (const a of c.artifacts) {
      if (a.lines.length === 0) fail(`${t.id}: artifact "${a.source}" has no lines`);
    }
    if (c.explanation.length === 0) fail(`${t.id}: no explanation`);
    if (c.rubric.length === 0) fail(`${t.id}: no rubric`);

    const rubricIds = new Set<string>();
    for (const r of c.rubric) {
      if (rubricIds.has(r.id)) fail(`${t.id}: duplicate rubric id ${r.id}`);
      rubricIds.add(r.id);
      if (r.keywords.length === 0) fail(`${t.id}: rubric ${r.id} has no keywords`);
    }

    for (const id of c.groundTruth.techniques) {
      if (!technique(id)) fail(`${t.id}: unknown technique ${id}`);
    }
    for (const d of c.cysaDomains) {
      if (!cysaDomain(d)) fail(`${t.id}: unknown CySA+ domain ${d}`);
    }

    // Benign/FP cases must not carry techniques; TP cases must.
    if (c.groundTruth.disposition === 'true-positive' && c.groundTruth.techniques.length === 0) {
      fail(`${t.id}: true-positive with no techniques`);
    }
    if (c.groundTruth.disposition !== 'true-positive' && c.groundTruth.techniques.length > 0) {
      fail(`${t.id}: non-malicious case carries techniques`);
    }

    // Perfect answer must score full marks.
    const perfect = gradeResponse(c, {
      disposition: c.groundTruth.disposition,
      severity: c.groundTruth.severity,
      action: c.groundTruth.action,
      techniques: c.groundTruth.techniques,
      notes: '',
    });
    if (perfect.score !== MAX_SCORE) {
      fail(`${t.id}: perfect answer scored ${perfect.score}/${MAX_SCORE}`);
    }

    // Empty answer must score zero on the objective parts (benign cases get
    // technique credit for tagging nothing, which is correct behaviour).
    const empty = gradeResponse(c, {
      disposition: null,
      severity: null,
      action: null,
      techniques: [],
      notes: '',
    });
    const expectedEmpty = c.groundTruth.techniques.length === 0 ? 25 : 0;
    if (empty.score !== expectedEmpty) {
      fail(`${t.id}: empty answer scored ${empty.score}, expected ${expectedEmpty}`);
    }

    // Reproducibility: regenerating from the id must yield identical content.
    const again = regenerateFromId(c.id);
    if (!again || JSON.stringify(again) !== JSON.stringify(c)) {
      fail(`${t.id} seed ${i}: regeneration from id is not deterministic`);
    }
  }
}

// Unfiltered generation should work and rotate across templates.
const seen = new Set<string>();
for (let i = 0; i < 300; i++) seen.add(generateCase({ seed: `rot-${i}` }).templateId);
if (seen.size < ALL_TEMPLATES.length * 0.8) {
  fail(`random generation only reached ${seen.size}/${ALL_TEMPLATES.length} templates in 300 draws`);
}

console.log(
  `${ALL_TEMPLATES.length} templates x ${SEEDS_PER_TEMPLATE} seeds; ${seen.size}/${ALL_TEMPLATES.length} reached by random draw.`,
);
if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log('smoke: OK');
