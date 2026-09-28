# PLAN — Vulnerability Management workstream

Rules: `CLAUDE.md` → "Vulnerability Management workstream". Spec: `DESIGN.md` (section refs as §n).
Every package: reviewer PASS, `npm run typecheck && npm test && npm run build` green, one commit, PROGRESS.md updated.
"CI changes" = none unless stated; the existing `check` and `e2e` jobs pick up new tests automatically.

---
## WP0 — Kickoff and progress file
- Goal: create `docs/vuln-mgmt/PROGRESS.md` from the template below; resolve open questions answered by the human; confirm baseline green.
- Owner: coordinator (inline). Files: `docs/vuln-mgmt/PROGRESS.md`. Deps: none.
- Acceptance: PROGRESS.md exists with sections Done / In progress / Next / Decisions / Known issues; baseline check results recorded.
- Tests: none.

## WP1a — Core types, fictional catalogue, CVSS 3.1 calculator
- Goal: `src/core/vuln/{model.ts,cvss31.ts,catalogue.ts,ids.ts}` per §2.2, §6.2; `SIMVULN-YYYY-NNNNN` id helper.
- Owner: implementer. Deps: WP0.
- Acceptance: (1) `VulnTemplate`, `VulnCaseSpec`, `FindingTruth`, `VulnDecision`, `ReasonCode` exported; (2) CVSS scores match every row of the oracle table in DESIGN §6.2 (verified 2026-09-28), Roundup uses the spec's Appendix A integer method; (3) catalogue deterministic by seed, ≥ 60 entries, ids match `/^SIMVULN-\d{4}-\d{5}$/`; (4) no real CVE strings in `src/core/vuln/**`.
- Tests: `tests/vuln-cvss.test.ts`, `tests/vuln-catalogue.test.ts`, guardrail `tests/vuln-guardrails.test.ts` (CVE regex over source + generated output).

## WP1b — Corpus tables and scan writer
- Goal: add `VulnFindings`, `ScanRuns`, `VulnIntel`, `SoftwareInventory`, `PatchHistory`, `ControlInventory` to `logs/schema.ts` (§6.1); `src/core/vuln/scan-writer.ts`; `buildVulnScenario` in `src/core/vuln/scenario.ts`; worker accepts a vuln spec.
- Owner: implementer. Files: `src/core/logs/schema.ts`, `src/core/logs/corpus.ts` (writers only), `src/core/vuln/*`, `src/ui/workers/siem.worker.ts`, `src/ui/lib/protocol.ts`. Deps: WP1a.
- Acceptance: (1) existing SOC scenario suite unchanged and green; (2) vuln scenario builds deterministically (same seed → identical rows); (3) KQL `VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited` runs; (4) addresses pass existing synthetic guardrails; (5) build < 1 s for tier-3 size in Node test.
- Tests: `tests/vuln-corpus.test.ts`; extend `kql/reference.ts` with 2 join examples (executed by existing reference test).

## WP1c — Grader
- Goal: `src/core/vuln/grade.ts` implementing §5 exactly; reuse ordinal helper, evidence scoring, hint penalty, nDCG from `shift/score.ts` (extract to a shared helper if needed, no behaviour change).
- Owner: implementer. Deps: WP1a.
- Acceptance: (1) §5.6 perfect (100) and sort-by-CVSS (57.3) examples reproduce to ±0.5, and the dismiss-F1 example's decisions (15) and must-not-miss (−4) parts reproduce exactly; (2) perfect = 100, empty = 0; (3) FP on must-not-miss applies −5 (cap −10); (4) capacity overflow rule; (5) near-miss matrix of §5.1 incl. the asymmetric `avoid` rule; (6) SOC grading tests unchanged.
- Tests: `tests/vuln-grading.test.ts` with fixtures from §5.6.

## WP1d — Slice content: 4 templates incl. twin T3
- Goal: `vm-kev-internal` / `vm-nokev-internal` (twin T3), plus `vm-stale-scan` and `vm-backport-fp` (T1/T2 A-sides) in `src/core/vuln/templates/`.
- Owner: scenario-author; fact-checker reviews. Deps: WP1b, WP1c.
- Acceptance: (1) `tests/helpers/vuln-scenario-check.ts` (implementer adds in WP1b or here via coordinator) runs every template × 20 seeds: builds, deterministic, perfect = 100, empty = 0, reference KQL returns every evidence row; (2) twins share `title` and headline base score; opposite schedule/decision; (3) fact-checker PASS.
- Tests: `tests/vuln-scenarios/slice.test.ts`.

## WP1e — UI slice + accessibility
- Goal: routes `#/vuln` and `#/vuln/<slug>/<seed>` (§7), Home card, worklist with decision/schedule/reason controls, move up/down, console tab reuse, note tab, submit → debrief; record attempt (`mode: 'vuln'`, `category: 'vulnmgmt'`) with additive type widening.
- Owner: implementer. Files: `src/ui/router.ts`, `src/ui/App.tsx`, `src/ui/screens/Vuln*.tsx`, `src/ui/components/Worklist.tsx`, `src/ui/styles/screens.css`, `src/state/profile.ts`, `src/core/types.ts`, `src/core/study/scheduler.ts` (AttemptMode), `src/core/cases/templates/index.ts` (label only), `e2e/vuln.spec.ts`. Deps: WP1d.
- Acceptance: (1) solve a case end-to-end by keyboard only (e2e); (2) axe clean on library, case, debrief in both themes; (3) 360 px: no horizontal scroll, card layout; (4) reduced motion: no reorder animation; (5) reorder announced via live region; (6) old profile fixture still coerces; (7) XP added to the shared total.
- Tests: `e2e/vuln.spec.ts`; `tests/profile.test.ts` new cases. CI: none (e2e job globs `e2e/`).
- **Slice exit**: coordinator + reviewer confirm architecture; record ADR adjustments before content batches.

## WP2 — Content batch A (twins T1, T2, T4, T5)
- Owner: scenario-author; fact-checker + scenario-reviewer. Deps: WP1e.
- Acceptance: 6 new templates (completing T1, T2; T4 both; T5 both), all harness checks, fact-checker PASS, each twin's `lesson` names the clue.
- Tests: `tests/vuln-scenarios/batch-a.test.ts`.

## WP3 — Content batch B (twins T6, T7, T8, T11) + tier 3 (T9, T10)
- Owner: scenario-author. Deps: WP2. Acceptance/tests as WP2 plus 2 tier-3 cases with ≥ 15 findings and capacity squeeze; T11 exercises the `avoid` decision; `tests/vuln-scenarios/batch-b.test.ts`.

## WP4 — Stats and study integration
- Goal: objective-level skill kind in `study/scheduler.ts`; Stats shows domain 2.0 / objectives 2.1–2.5 and decision confusion matrix; vuln templates in study pool with SRS cards.
- Owner: implementer. Deps: WP1e (content can grow in parallel only if files don't overlap).
- Acceptance: weak objective raises selection weight (unit test); Stats screen axe clean; existing study tests unchanged.
- Tests: `tests/study.test.ts` additions, `e2e/vuln.spec.ts` stats check.

## WP5 — Continuity hook (vuln → SOC)
- Goal: optional `profile.vulnLedger` (cap 50); new SOC template `endpoint-known-vuln-exploit` receiving `ctx.vulnHook`; shift planner injects it at most once per shift when a real must-not-miss was dismissed/deferred; debrief links back.
- Owner: implementer (engine) + scenario-author (template body, inside a new file coordinated by the coordinator since it lives under `src/core/cases/templates/`). Deps: WP4.
- Acceptance: (1) deterministic injection given ledger + seed; (2) no injection with empty ledger (existing shift tests unchanged); (3) template passes SOC scenario harness; (4) ledger coerces from old profiles.
- Tests: `tests/shift.test.ts`, new `tests/scenarios/vuln-link.test.ts`.

## WP6 — Polish
- Goal: Help section for the mode (terms: credentialed scan, backport, compensating control, avoid vs mitigate, Sim-KEV and Sim-EPSS with their real-world equivalents per DESIGN §3.1), hint ladders, debrief copy review, stakeholder-note rubric tuning.
- Owner: implementer + scenario-author (separate files). Deps: WP3.
- Acceptance: Help reachable by keyboard; every template has ≥ 2 hints; reviewer PASS.

## WP7 — Hardening
- Goal: full accessibility audit (all new screens, both themes, 360 px, keyboard, screen-reader names), fact-check sweep of all vuln content, guardrail-auditor run, update `ARCHITECTURE.md`, `README.md`, AS-BUILT.md, close PROGRESS.md.
- Owner: reviewer + fact-checker + guardrail-auditor; coordinator edits docs.
- Acceptance: zero axe violations; fact-checker PASS on every template; NEEDS-HUMAN-CHECK list resolved or explicitly deferred by a human; CI green on the branch.

## Optional WP8 — Real-data snapshot (human-run)
- Goal: `scripts/refresh-vuln-snapshot.mjs` (Node built-ins only) writing `data/vuln-snapshot/*.json` with source URL + retrieval date; debrief "real-world reference" panel. Only if a human runs it with network. Not required for release.

---
## PROGRESS.md template (for WP0)
```
# PROGRESS — Vulnerability Management
## Done
## In progress
## Next
## Decisions
## Known issues
```

## NEEDS-HUMAN-CHECK
Open:
1. **Target exam version.** CS0-003 (English) retires 2026-12-22; CS0-004 launched 2026-06-23 (DESIGN §1). The whole app (SOC side
   included) is mapped to CS0-003, so retargeting is an app-wide decision, not a vuln-mode one. Until decided, the mode maps to CS0-003.
2. **CS0-004 objective numbering and CVSS version.** The official CS0-004 objectives PDF was not retrievable on 2026-09-28; CompTIA's V4 page
   lists four unnumbered VM objectives and does not name a CVSS version. Needed only if item 1 goes to CS0-004.

Resolved 2026-09-28 (sources in DESIGN):
- CS0-003 objective numbers/titles 2.1–2.5, 4.1 confirmed verbatim; domain 2.0 is **30%**, not 22% (DESIGN §1). Mapping errors fixed.
- CVSS version: objectives name none; 2.3 lists Scope (v3.x-only) → v3.1 (DESIGN §10).
- CVSS v3.1 oracles recomputed from the FIRST spec and cross-checked with FIRST's calculator (DESIGN §6.2); §5.6 example 2 corrected.
- Feed names: SKEV/XPS replaced by Sim-KEV/Sim-EPSS with explainers (DESIGN §3.1).

## Decision log (ADR-style)
- **ADR-1 Sibling `VulnTemplate`, shared lower layers.** SOC `GroundTruth`/grader don't fit vuln decisions; sharing world/corpus/worker keeps one org and one console.
- **ADR-2 Fictional vuln ids (`SIMVULN-`) by default.** No network in build env; memory-sourced CVE facts are banned. Snapshot path is optional and human-run.
- **ADR-3 Structured reason codes graded; free-text note coaching only.** Keyword grading of prose rewards vocabulary, not judgment; codes with contradiction penalties are deterministic and testable.
- **ADR-4 CVSS v3.1 only.** Matches the exam (CS0-003 2.3 lists Scope, a v3.x-only metric; verified 2026-09-28) and keeps the calculator small; v4.0 is future work.
- **ADR-5 Tier-based nDCG for ordering.** Reuses shift scoring; ties within a tier are free so grading doesn't punish defensible orderings.
- **ADR-6 Vuln context lives in corpus tables.** Reference KQL stays runnable, so the existing harness proves solvability.
- **ADR-7 Profile stays v2; additive fields only.** Avoids a migration; coercion tests guard old data.
- **ADR-8 Reorder by buttons/number input, not drag.** Keyboard and screen-reader first; drag may be added later as enhancement.
- **ADR-9 Agent models:** haiku for explorer (cheap lookups), sonnet for author/implementer/fact-checker, opus for the gate reviewer (highest cost of a wrong PASS).
  Checked 2026-09-28 against https://code.claude.com/docs/en/sub-agents and https://code.claude.com/docs/en/model-config: `haiku`, `sonnet`,
  `opus` are valid `model:` aliases (as are `fable`, `inherit` and full model ids); on the Anthropic API `opus` → Opus 5.5, `sonnet` → Sonnet 5.5.
  No agent file needed a fix. The coordinator (main session) runs on Opus 5.5 (`/model opus`): it plans, integrates and decides, where
  mistakes cascade into every package. Frontmatter pins each subagent regardless of the main session's model; the three reviewers without
  `model:` follow `CLAUDE_CODE_SUBAGENT_MODEL` if set, else the main session's model.
- **ADR-10 Feed names Sim-KEV / Sim-EPSS (2026-09-28).** Replace invented "SKEV"/"XPS": learners must recognise the real KEV and EPSS names; the `Sim-` prefix, badge and explainer keep the fiction explicit (DESIGN §3.1).
- **ADR-11 Add `avoid` decision (2026-09-28).** CS0-003 2.5 lists accept/transfer/avoid/mitigate; without `avoid` the mode could not teach removing an unused component. Near-miss is asymmetric (avoid→patch 0.5, patch→avoid 0); twin T11 in WP3.
