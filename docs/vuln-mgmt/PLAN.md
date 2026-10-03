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
- Acceptance: (1) `VulnTemplate`, `VulnCaseSpec`, `FindingTruth`, `VulnDecision`, `ReasonCode` exported; (2) CVSS scores match every row of the oracle table in DESIGN §6.2 (verified 2026-09-28), Roundup uses the spec's Appendix A integer method; (3) catalogue deterministic by seed, ≥ 60 entries, ids match `/^SIMVULN-\d{4}-\d{5}$/`; (4) no real CVE strings in `src/core/vuln/**`; (5) catalogue follows the calibrated parameters in DESIGN §6.2 (CVSS mix within ±5 points per band, 6 Sim-KEV entries incl. ≥ 1 Medium and ≥ 1 old id, Sim-EPSS sampled from the two anchor tables, displayed percentile from the all-CVE table: 0.004 → 31st).
- Tests: `tests/vuln-cvss.test.ts`, `tests/vuln-catalogue.test.ts`, guardrail `tests/vuln-guardrails.test.ts` (CVE regex over all scenario data as defined in DESIGN §9 rule 2: `src/core/vuln/**` + generated case output; no exceptions).

## WP1b — Corpus tables and scan writer
- Goal: add `VulnFindings`, `ScanRuns`, `VulnIntel`, `SoftwareInventory`, `PatchHistory`, `ControlInventory` to `logs/schema.ts` (§6.1); `src/core/vuln/scan-writer.ts`; `buildVulnScenario` in `src/core/vuln/scenario.ts`; worker accepts a vuln spec.
- Owner: implementer. Files: `src/core/logs/schema.ts`, `src/core/logs/corpus.ts` (writers only), `src/core/vuln/*`, `src/ui/workers/siem.worker.ts`, `src/ui/lib/protocol.ts`; as built also `src/core/query/kql/parser.ts` (additive: bare table on the right of `join`, needed for acceptance 3). Deps: WP1a.
- Acceptance: (1) existing SOC scenario suite unchanged and green; (2) vuln scenario builds deterministically (same seed → identical rows); (3) KQL `VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited` runs; (4) addresses pass existing synthetic guardrails; (5) build < 1 s for tier-3 size in Node test.
- Tests: `tests/vuln-corpus.test.ts`; extend `kql/reference.ts` with 2 join examples (executed by existing reference test).

## WP1c — Grader
- Goal: `src/core/vuln/grade.ts` implementing §5 exactly; reuse ordinal helper, evidence scoring, hint penalty, nDCG from `shift/score.ts` (extract to a shared helper if needed, no behaviour change).
- Owner: implementer. Deps: WP1a. Files: `src/core/vuln/grade.ts`, `src/core/grading/shared.ts` (ordinal credit and evidence scoring
  moved out of `grading/grade.ts`, no behaviour change), `src/core/grading/grade.ts`, `tests/vuln-grading.test.ts`,
  `tests/helpers/vuln-scenario-check.ts` (perfect = 100 / empty = 0 checks); outside the original list, for ADR-19 and signed off by
  the reviewer on their own: `src/core/vuln/model.ts` (`tiers` required, `FindingTruth.slaLatest`), `src/core/vuln/scenario.ts`
  (build-time tier checks), `tests/vuln-corpus.test.ts` (tests for those checks).
- Acceptance: (1) §5.6 perfect (100) and sort-by-CVSS (57.3) examples reproduce to ±0.5, and the dismiss-F1 example's decisions (15) and must-not-miss (−4) parts reproduce exactly; (2) perfect = 100, empty = 0; (3) FP on must-not-miss applies −5 (cap −10); (4) capacity overflow rule; (5) near-miss matrix of §5.1 incl. the asymmetric `avoid` rule; (6) SOC grading tests unchanged.
- Tests: `tests/vuln-grading.test.ts` with fixtures from §5.6.

## WP1d — Slice content: 4 templates incl. twin T3
- Goal: `vm-kev-internal` / `vm-nokev-internal` (twin T3), plus `vm-stale-scan` and `vm-backport-fp` (T1/T2 A-sides) in `src/core/vuln/templates/`.
- Owner: scenario-author; fact-checker reviews. Deps: WP1b, WP1c.
- Files: `src/core/vuln/templates/**`, `tests/vuln-scenarios/slice.test.ts` (+ `data-rules.test.ts` for the generic data rules every
  template must meet, and `kev-internal.test.ts`, `stale-scan.test.ts`, `backport-fp.test.ts` for template-specific checks); coordinator inline: `tests/helpers/vuln-scenario-check.ts`
  (evidence per case + on every must-not-miss finding, FP ⇒ schedule `none`, determinism per run, `everyEvidenceRow`),
  `src/core/vuln/registry.ts` (imports `templates/index.ts`). Outside the list, signed off by the reviewer on its own:
  `src/core/vuln/catalogue.ts` + `tests/vuln-catalogue.test.ts` (Sim-KEV listing dates clamped to the real KEV launch, 2021-11-03,
  after all draws; `MIN_REFERENCE_DATE` → 2021-11-04; "Fenwick Inventory Agent" → "Tarnwick Inventory Agent", "Northmere Systems" →
  "Ravenmere Systems": real IT vendors per the fact-checker).
- Acceptance: (1) `tests/helpers/vuln-scenario-check.ts` (implementer adds in WP1b or here via coordinator) runs every template × 20 seeds: builds, deterministic, perfect = 100, empty = 0, reference KQL returns every evidence row; (2) twins share `title` and headline base score; opposite schedule/decision; (3) fact-checker PASS.
- Tests: `tests/vuln-scenarios/slice.test.ts`.

## WP1e — UI slice + accessibility
- Goal: routes `#/vuln` and `#/vuln/<slug>/<seed>` (§7), Home card, worklist with decision/schedule/reason controls, move up/down, console tab reuse, note tab, submit → debrief; record attempt (`mode: 'vuln'`, `category: 'vulnmgmt'`) with additive type widening. Also: SOC sessions stop listing the six vuln context tables, which WP1b added and which are empty there (schema browser, Help schema, editor autocomplete all read `TABLES`); deferred to here by the human 2026-09-28.
- Owner: implementer. Files: `src/ui/router.ts`, `src/ui/App.tsx`, `src/ui/screens/Vuln*.tsx`, `src/ui/components/Worklist.tsx`, `src/ui/styles/screens.css`, `src/state/profile.ts`, `src/core/types.ts`, `src/core/study/scheduler.ts` (AttemptMode), `src/core/cases/templates/index.ts` (label only), `src/ui/components/Tools.tsx`, `src/ui/components/Editor.tsx`, `src/ui/screens/Help.tsx` (vuln tables per mode), `e2e/vuln.spec.ts`. Deps: WP1d.
  As built, outside the list (coordinator-approved, reviewer sign-off on each): `src/core/vuln/worklist.ts` + `tests/vuln-worklist.test.ts`
  (pure worklist helpers, per-mode table list, case types; unit-testable because vitest has no DOM); `src/ui/screens/Home.tsx` (the Home
  card the goal names; vuln branch in Recent; first-run and accuracy chip from SOC attempts only, so SOC Home is unchanged);
  `src/ui/screens/Stats.tsx` (reads SOC attempts only until WP4, one filter); `src/ui/components/Debrief.tsx` (`export` on `scoreColor`,
  `EvidenceRows`, `StepRunner`, no behaviour change); `tests/profile.test.ts` (Tests line); `README.md` table count (coordinator).
- Acceptance: (1) solve a case end-to-end by keyboard only (e2e); (2) axe clean on library, case, debrief in both themes; (3) 360 px: no horizontal scroll, card layout; (4) reduced motion: no reorder animation; (5) reorder announced via live region; (6) old profile fixture still coerces; (7) XP added to the shared total; (8) no XP/rank gate: on a fresh profile the Home card and cases of every tier are reachable, and the vuln library has the SOC Library's tier filter (DESIGN §7); (9) a SOC session's schema browser and autocomplete don't offer the six vuln tables, a vuln session's do, and Help marks them as vuln-mode tables. README's table count ("18 tables") is updated by the coordinator with this package;
  (10) the worklist's default order is not derived from the answer key (not template/spec order, not truth, tiers or `idealOrder`), and
  its columns are sortable (added 2026-09-30, human).
- Tests: `e2e/vuln.spec.ts`; `tests/profile.test.ts` new cases. CI: none (e2e job globs `e2e/`).
- **Slice exit**: coordinator + reviewer confirm architecture; record ADR adjustments before content batches.

## WP1f — Grading and catalogue hardening (added 2026-09-30, human; ADR-20)
- Goal: close the grading headroom and the catalogue class/vector contradictions (PROGRESS.md Known issues) before content batches;
  rename "Quorvane"; reserved domains; verify CS0-003 objective titles against the official objectives.
- Owner: implementer (grader, catalogue, tests); scenario-author (template data, if the new rules need it); fact-checker (names,
  objectives); coordinator: DESIGN §5 and the §5.6 worked examples. Deps: WP1e.
- Files: `src/core/vuln/grade.ts`, `src/core/vuln/catalogue.ts`, `tests/vuln-grading.test.ts`, `tests/vuln-catalogue.test.ts`, a new
  hardening test over every template; template files only via the scenario-author; `docs/vuln-mgmt/DESIGN.md` §5 (coordinator).
  As built, outside the list (reviewer sign-off on each): implementer — `tests/vuln-hardening.test.ts` (the new test),
  `src/core/grading/shared.ts` (opt-in pin rule; SOC output byte-identical), `src/core/vuln/scenario.ts` (`lesson` on resolved
  findings; build errors: no lesson finding, real key finding without `slaLatest`, no evidence point), new
  `src/core/vuln/coherence.ts` (the class/vector predicate moved out of `templates/common.ts`, tightened after the fact-checker's
  veto) and `src/core/vuln/classes.ts` (class list and labels, so catalogue and coherence don't import each other),
  `src/ui/screens/VulnDebrief.tsx` (gate line), `src/ui/screens/Help.tsx` (grading table), `e2e/vuln.spec.ts` (binding-cap debrief
  test with axe), `tests/vuln-corpus.test.ts`,
  `tests/helpers/vuln-fixture.ts`, `tests/helpers/vuln-scenario-check.ts`, `tests/vuln-worklist.test.ts` (exemption removed),
  `tests/vuln-guardrails.test.ts` (reserved-domain scan); scenario-author — `templates/{common,kev-internal,stale-scan,backport-fp}.ts`
  and `tests/vuln-scenarios/{slice,data-rules,kev-internal,backport-fp}.test.ts`; coordinator inline — `src/core/vuln/model.ts`
  (`FindingSpec.lesson`) and the six `lesson: true` lines (four headlines, then the two decoys after the pre-gate review), the
  `Fragment` keys in `VulnDebrief.tsx` after the gate (reviewer note), DESIGN §2.2/§5/§5.8, PLAN, PROGRESS.
- Starting mechanism (the tests define done; adjust if needed): a missed schedule on a must-not-miss finding counts like a dismissal;
  free extra pins are capped at the number of evidence points (was 4); irrelevant reason codes never score positively.
- Acceptance, as tests run against every template: (1) the shotgun strategy (SLA-table schedule, every reason code, every row pinned)
  fails (< 70); (2) an answer that gets only the lesson finding wrong fails (< 70); (3) the ideal answer scores ≥ 90; (4) an answer
  that gets the lesson finding right with minor slips still passes (≥ 70); (5) the catalogue has no class/CVSS-vector contradiction and
  a test fails the build on any; (6) "Quorvane" renamed to a name with no real-world hits (fact-checker web sweep); every generated
  domain uses a reserved name (`.example`, `.test`, `.invalid`), fixed where not (a fix that would change SOC output goes to the human
  first: existing SOC content stays unchanged); (7) the fact-checker tries to fetch the official CS0-003 objectives and verifies the
  2.x/4.1 titles; if the download is gated, the item goes on the NEEDS-HUMAN-CHECK list; (8) DESIGN §5, §5.6 and the Help grading table match the grader;
  (9) twins present the same pre-submit surface (found in WP1e): the T3 twins' first hint is shared and neutral (today hint 1 and
  hint 3 differ per twin in `kev-internal.ts`, so revealing hint 1 tells the twin; later hints may stay twin-specific), and the twins
  write the same row count per table (today `VulnIntel` differs on some seeds, visible in the schema browser); the `it.fails` and
  `ROW_COUNT_GAPS` exemption in `tests/vuln-worklist.test.ts` are removed.
- Tests: `tests/vuln-grading.test.ts`, `tests/vuln-catalogue.test.ts`, new hardening test.

## WP2 — Content batch A (twins T1, T2, T4, T5)
- Owner: scenario-author; fact-checker + scenario-reviewer. Deps: WP1f.
- Acceptance: 6 new templates (completing T1, T2; T4 both; T5 both), all harness checks, fact-checker PASS, each twin's `lesson` names the clue.
- Tests: `tests/vuln-scenarios/batch-a.test.ts`.
- As built (2026-10-02): templates `exposed-edge.ts` (T4), `waf.ts` (T5), B sides in `backport-fp.ts` / `stale-scan.ts`, shared
  policy rows and the template-local `freezeFirst` calendar in `common.ts`; tests `batch-a`, `exposed-edge`, `waf` (+ updated
  `backport-fp`, `stale-scan`, `data-rules`: C4 holds mitigate truths to the compensating-control row, K5 exempts the T4 exposure
  clue and the T1/T2 mirrored sibling). Outside the list, reviewer sign-off on each: implementer — `e2e/vuln.spec.ts`
  (control picker with a non-empty ControlInventory, WP1e follow-up; library tier test) and `tests/vuln-worklist.test.ts` (the
  one-template case type is built from a one-element list now that every registered type is a twin pair); coordinator inline —
  vendor renames in `src/core/vuln/catalogue.ts` (+ `common.ts`, `waf.ts`) after the fact-checker found real companies:
  "Quillon Software" → "Velmarrow Software", "Quillon Forms" → "Velmarrow Forms", "Larkfield Software" → "Dravenholt Software",
  and the name guard in `tests/vuln-catalogue.test.ts`; the compensating-control row's recording sentence in `common.ts`.

## WP3 — Content batch B (twins T6, T7, T8, T11) + tier 3 (T9, T10)
- Owner: scenario-author. Deps: WP2. Acceptance/tests as WP2 plus 2 tier-3 cases with ≥ 15 findings and capacity squeeze; T11 exercises the `avoid` decision; `tests/vuln-scenarios/batch-b.test.ts`.
- Reading (human, 2026-10-02): the 2 tier-3 cases are the T10 twin pair, both containing T9's ordering pattern.
- As built (2026-10-02): templates `legacy.ts` (T6), `scan-method.ts` (T7), `saas.ts` (T8), `unused-service.ts` (T11),
  `tier3.ts` (T10 with T9); `common.ts` (`policyAttachments` takes template-local extra rows; new products in `PRODUCT_KINDS`);
  tests `batch-b`, `pair-helpers.ts` (the pair suite moved out of `batch-a`; logic unchanged except the lesson-count bound, which follows DESIGN §5.8 at tier 3), per-template tests, `data-rules`
  (C4 second mitigate form for a control to apply; C7 counts only an approved unexpired exception and a control whose target
  names the host; K5 exemptions for the T7 mirror and the T8 hosting columns; an asset-tier deadline hook for the T10 ids).
  Outside the list, reviewer sign-off on each: implementer — `e2e/vuln.spec.ts` (library tiers incl. Tier 3, a tier-3 case
  test, the avoid decision) and `tests/helpers/vuln-scenario-check.ts` (DeviceInfo addresses unique and never an egress
  address, additive); coordinator inline — `tests/vuln-hardening.test.ts` (the lesson-count bound follows DESIGN §5.8: 1–3 at
  tiers 1–2, at most half the case at tier 3).

## WP4 — Stats and study integration
- Goal: objective-level skill kind in `study/scheduler.ts`; Stats shows domain 2.0 / objectives 2.1–2.5 and decision confusion matrix; vuln templates in study pool with SRS cards.
- Owner: implementer. Deps: WP1e (content can grow in parallel only if files don't overlap).
- Acceptance: weak objective raises selection weight (unit test); Stats screen axe clean; existing study tests unchanged.
- Tests: `tests/study.test.ts` additions, `e2e/vuln.spec.ts` stats check.
- As built (2026-10-02): `study/scheduler.ts` (`SkillKind` `objective`, `StudyTemplate` view, `SOC_STUDY_POOL` default /
  `FULL_STUDY_POOL` passed by the UI through `StudyOptions.pool`, `studyTemplateById`, exported `studyWeight`), `taxonomy/cysa.ts`
  (`CYSA_OBJECTIVES`, titles verbatim from DESIGN §1), `vuln/worklist.ts` (`vulnSeedFor`), `state/profile.ts` (vuln SRS card,
  `verdict` per recorded decision, vuln attempts in study attempts), new `state/vuln-stats.ts`, `ui/lib/cases.ts` (`studyRoute`),
  `Stats.tsx` (Vulnerability management section: domain 2.0 summary, objectives 2.1–2.5, decision confusion matrix, most common
  mix-up), `Study.tsx` (objectives card), `Home.tsx`, `CaseScreen.tsx`; tests `study` (appended), `profile`, new `vuln-stats`,
  `study-route`, `e2e/vuln.spec.ts`. Outside the list, reviewer sign-off on each: `ui/styles/screens.css` (bars inside table rows get
  a width, which also makes the 0-px bars of the SOC "By category" table visible, display only); the SOC Stats scroll region
  "Latest cases" renamed "Table of the latest graded cases" (axe `landmark-unique`); three existing `profile` tests updated for
  the vuln card and `verdict`.

## WP5 — Continuity hook (vuln → SOC): one alert, upgradeable
- Goal: per DESIGN §8. Optional `profile.vulnLedger` (cap 50); pure `selectVulnFollowUp(ledger, shiftSeed) → VulnHook | null`; `planShift` takes the result as an optional slot parallel to `campaign` and adds **exactly one** alert from new SOC template `endpoint-known-vuln-exploit` (receives `ctx.vulnHook`); ledger entry marked consumed; debrief links back. No follow-on stages, no campaign state change.
- Owner: implementer (engine) + scenario-author (template body, inside a new file coordinated by the coordinator since it lives under `src/core/cases/templates/`). Deps: WP4.
- Acceptance: (1) deterministic injection given ledger + seed; (2) no injection with empty ledger (existing shift tests unchanged); (3) at most one injected alert per shift and a consumed entry never re-injects; (4) campaign state untouched by the injection; (5) template passes SOC scenario harness; (6) ledger coerces from old profiles.
- Tests: `tests/shift.test.ts`, new `tests/scenarios/vuln-link.test.ts`.
- As built (2026-10-02): new `src/core/shift/vuln-hook.ts` (ledger types, entry rule, cap/trim, coercion validators,
  `selectVulnFollowUp`, `markConsumed`); `shift/plan.ts` (`ShiftOptions.vulnHook`, one extra item on its own time stream,
  `shiftSeedFor`); `cases/scenario.ts` (hook items built last, `ResolvedCase.vulnLink`); `campaign/campaign.ts` (history skips the
  hook case); `vuln/scenario.ts` (`host`, `vulnId`, `sharedHost` on resolved findings); `state/profile.ts` (`vulnLedger`, entries
  written by `recordVulnAttempt`, `startShift` options with consumption, coercion of the ledger and `activeShift.vulnHook`,
  `moveToNewOrganisation`, recency window without linked templates); `study/scheduler.ts` (lookup resolves linked templates);
  UI: `Home`, `Shift`, `Settings`, `protocol.ts` (session key includes the hook), the worker, `Debrief.tsx` + new
  `ui/lib/vuln-link.ts` (link back after submit). Template (scenario-author, under PLAN's assignment):
  `src/core/cases/templates/vuln-link.ts` (`LINKED_TEMPLATES`, outside `ALL_TEMPLATES`). Tests: `shift`, `profile`, `campaign`,
  new `vuln-continuity`, new `tests/scenarios/vuln-link.test.ts`, `e2e/vuln.spec.ts` (3). Outside the list, reviewer sign-off on
  each: `taxonomy/mitre.ts` (T1210 Exploitation of Remote Services, one line, coordinator); `tests/helpers/scenario-check.ts`
  (linked templates only: truth tactics a non-empty subset of the template's); `tests/vuln-grading.test.ts` (fixture fields);
  the coordinator's contract edits (`cases/model.ts`, `cases/scenario.ts`, `templates/index.ts`); DESIGN §8 clarification.

## WP6 — Polish
- Goal: Help section for the mode (terms: credentialed scan, backport, compensating control, avoid vs mitigate, Sim-KEV and Sim-EPSS with their real-world equivalents per DESIGN §3.1), hint ladders, debrief copy review, stakeholder-note rubric tuning.
- Owner: implementer + scenario-author (separate files). Deps: WP3.
- Acceptance: Help reachable by keyboard; every template has ≥ 2 hints; reviewer PASS.
- Readings (coordinator, 2026-10-03; the criteria were thin as written, see PROGRESS): Help section `#/help/vuln` reached by
  Tab/Enter from library, case, debrief and nav, axe full rule set both themes, 360/320 px; hints ≥ 2, twins share hint 1,
  named tables exist; debrief copy display only (scores identical vs HEAD); rubric: model note ticks all four, content-free
  note ≤ 1, the other twin's notes never tick the action item; glossary fact-checked.
- As built (2026-10-03): implementer — `src/ui/App.tsx` (Vulns nav item), `src/ui/screens/Help.tsx` (section `vuln`,
  glossary, cross-links), `VulnDebrief.tsx`, `VulnCase.tsx` (Help link, debrief kept in sessionStorage, cap in the live
  region), `VulnLibrary.tsx`, `src/ui/styles/screens.css`, `src/core/vuln/worklist.ts` (glosses), `src/core/vuln/grade.ts`
  (display strings, one-decimal percent, `vulnRubricHits`), `tests/vuln-grading.test.ts`, `tests/vuln-worklist.test.ts`,
  `e2e/vuln.spec.ts`; scenario-author — `src/core/vuln/templates/**` (rubric keywords and date helpers in `common.ts`, T8
  wording and external run length, briefings, kev risk text, product placement in five pairs), new
  `tests/vuln-scenarios/rubric.test.ts`, `data-rules` (V1 version consistency, H1 hints), `batch-b`, `saas`, `waf`. Outside
  the vuln area, reviewer sign-off on each: `src/core/logs/schema.ts` (`ScanRuns.AuthFailures` doc text), the shared header
  CSS on SOC screens (ADR-24, display only), the shared Help page; coordinator inline — three glossary sentences after the
  fact-check, DESIGN §3.1/§4 (T8)/§5/§7.

## WP7 — Hardening
- Goal: full accessibility audit (all new screens, both themes, 360 px, keyboard, screen-reader names), fact-check sweep of all vuln content, guardrail-auditor run, update `ARCHITECTURE.md`, `README.md`, AS-BUILT.md, close PROGRESS.md.
- Owner: reviewer + fact-checker + guardrail-auditor; coordinator edits docs.
- Acceptance: zero axe violations; fact-checker PASS on every template; NEEDS-HUMAN-CHECK list resolved or explicitly deferred by a human; CI green on the branch.
- Readings (coordinator, 2026-10-03, PROGRESS): "zero axe violations" = full axe rule set on every vuln screen and state, both
  themes, 1280/360/320 px, as an e2e sweep plus a manual keyboard/screen-reader audit; "fact-checker PASS on every template" =
  one verdict per template (20) plus the Help glossary; "CI green on the branch" = the pull request's checks on the final commit.
- As built (2026-10-03): implementer — new `e2e/vuln-a11y.spec.ts` (42 states × 3 widths × 2 themes, full rule set, page
  scroll), fixes in `src/ui/screens/{VulnCase,VulnDebrief,VulnLibrary,Help,Settings}.tsx`, `src/ui/components/{Worklist,
  Workspace,Debrief}.tsx`, `src/ui/styles/{screens,components}.css`, `src/core/vuln/{worklist,scan-writer}.ts`,
  `src/state/storage.ts` (`clearTabSession`; `Shift.tsx` imports its handover key from there), `tests/helpers/{guardrails,cve-guard}.ts` and their callers, `tests/{profile,
  vuln-continuity,vuln-corpus,vuln-guardrails}.test.ts`, `e2e/vuln.spec.ts`; scenario-author — renames in
  `src/core/vuln/catalogue.ts` + `tests/vuln-catalogue.test.ts` (assigned by path, ADR-25) and the templates, the
  vm-unused-service lesson, T10 objectives, the exam reference label, `batch-b`; coordinator inline — SOC registrar names in
  `src/core/synth/domains.ts`, the KQL-guide link cue in `Workspace.tsx`, three wording fixes, DESIGN §1/§3.1/§9,
  `README.md`, `ARCHITECTURE.md`, `AS-BUILT.md`, PLAN, PROGRESS. SOC changes are display/test only (ADR-24), listed in
  PROGRESS. NEEDS-HUMAN-CHECK: none open.

## WP8 — Brief readability (added 2026-10-03, human request)
- Goal: the Brief panel of a vulnerability case (`src/ui/screens/VulnBrief.tsx`: briefing, the two key/value attachments,
  hints) reads well in the side column at ≥ 1200 px and on phones. Trigger (human, 2026-10-03): the open attachments
  "vulnerability remediation standard (excerpt)" and "Change calendar (UTC)" are "a couple of characters wide".
  Measured 2026-10-03 (coordinator, screenshots on the system Chrome): with the brief 320 px wide (1280–1920 px) the
  key/value grid (`.kv`, `max-content 1fr`) gives the key column 159 px (policy) and 231 px (calendar) and the values
  89 px and 17 px of monospace — 1 to 3 characters per line; the attachments are 4,813 px and 2,177 px tall. At 360 px:
  105 / 33 px and 4,020 / 1,600 px (closed by default there). The single-column layout (< 1200 px) reads fine.
- Owner: implementer — `src/ui/styles/screens.css` (and `components.css` only for a deliberate shared change),
  `src/ui/screens/VulnBrief.tsx`, `e2e/vuln.spec.ts` and/or `e2e/vuln-a11y.spec.ts`. Coordinator: design choice from a
  judged panel, before/after screenshots, PLAN/PROGRESS. Deps: WP7.
- Acceptance: at 1280, 1440, 1920, 1000, 760, 700, 640, 360 and 320 px in both themes, every value in both attachments
  gets at least 60 % of the list's width or sits on its own full-width line below its key; at 1280 px the policy
  attachment is at most 1,800 px tall and the calendar at most 400 px (from 4,813 / 2,177; the first draft said "a third",
  written before measuring, and the readability, not the height, is the complaint); no horizontal page scroll; full axe
  rule set clean on the case with both attachments open; tab order brief → worklist → tools → submit unchanged; the SOC
  case screen's attachments unchanged (an e2e assertion on a SOC case guards the shared `.kv` rules: two tracks, mono
  values); an e2e test pins every measurement; reviewer PASS.
- Design (coordinator, 2026-10-03, from a judged panel of three proposals — responsive CSS, typography, page layout — and
  two judges, reader and maintainer, who split; the grafts they agreed on make the design):
  1. `.vc-brief { container: vc-brief / inline-size }`; `@container vc-brief (width < 640px)` stacks `.vc-brief .kv`
     (`grid-template-columns: minmax(0, 1fr)`, no row gap inside a pair, `var(--space-2)` between pairs via `dd + dt`);
     above it the two-column list stays with the key column capped: `fit-content(40%) minmax(0, 1fr)`. The threshold is
     on the brief's content box (≈ 706 px viewport); every key today is ≤ 231 px, so the calendar's value share at the
     flip is ≥ 62 %. Note in a CSS comment that inline-size containment needs the grid track the brief has (fixed/fr, never
     `auto`).
  2. Values in the sans face: `VulnBrief.tsx` drops `class="mono"` on the `dd` (policy sentences and timestamps are not
     identifiers; monospace breaks the window dates after a hyphen at 296–336 px); `.vc-brief .kv dd { font-variant-numeric:
     tabular-nums }`; keys `.vc-brief .kv dt { font-weight: 500 }`. `Panels.tsx` keeps `mono` (SOC fields are identifiers).
     The boxed `details.disclosure` chrome stays (the flat-section variant broke the product idiom).
  3. Wrapped titles: `.vc-brief details.disclosure > summary { align-items: flex-start }` and `> summary > .icon
     { margin-top: calc((1lh - 1em) / 2) }` (the icon is 1em; identical to today for one-line titles).
  4. Grid at ≥ 1200 px: `grid-template-columns: clamp(320px, 25%, 480px) minmax(0, 1fr)` (320 at 1280, ≈ 352 at 1440,
     ≈ 472 at 1920; e2e asserts floors, never exact widths — the 25 % depends on the scrollbar) and a spare fifth row
     (`grid-template-rows: auto auto auto auto 1fr`, areas gain `'brief .'`) so the brief's height no longer stretches
     the worklist, tools and submit cards (today a 534 px table sits in a 2,685 px card). Both are deliberate scope
     additions to the right column, logged in PROGRESS; nothing changes below 1200 px.
  5. e2e (`e2e/vuln.spec.ts`, inside 'vulnerability mode', `withProfile` fixed world, `await document.fonts.ready` before
     measuring): at every width above, open both attachments and assert per value `share ≥ 0.6 || ownLine`, the used
     track count (`getComputedStyle(dl).gridTemplateColumns.split(' ').length`: 1 stacked at ≤ 640 and 360/320, 2 at
     760–1000), the icon's midpoint inside the title's first line rect, the height caps at 1280, brief width ≥ 340 at 1440
     and ≥ 440 at 1920, worklist card height − table height ≤ 130 px at 1280, overflow 0 at 640/360/320, the summary
     toggled by keyboard (Enter) at 360 px, and `axeFull` at 1280 and 360 in both themes with the attachments open; one
     SOC case assertion (two tracks, `dd.mono`). Timeout 240 s. Add the open-attachments state to the T1 case in
     `e2e/vuln-a11y.spec.ts` (the WP7 sweep covers the closed default only).
  Rejected: `max-width: 72ch` on values (full width in a table is fine); closing the policy by default at ≥ 1200 px;
  `line-height` tweaks to hit a height figure. Follow-ups logged in PROGRESS, not in this package: the calendar sits below
  the policy (≈ 1,500 px down at 1280) though it is used for every schedule decision — swapping the attachment order in
  `common.ts policyAttachments()` is a scenario-author change for a human to approve; the policy title repeats the org
  name and wraps to 2–3 lines; `open={!narrow}` leaves both attachments open in the 761–1199 px one-column band.
- As built (2026-10-03): implementer (opus) — `src/ui/styles/screens.css` (vuln section), `src/ui/screens/VulnBrief.tsx`,
  `e2e/vuln.spec.ts` (helpers `openAttachments`, `briefMetrics`, the "brief readability" test), `e2e/vuln-a11y.spec.ts`
  (`sweep` with a `prepare` callback, T1 open-attachments sweep); coordinator inline — the key cap subtracts the column
  gap with headroom (`fit-content(calc(38% - var(--space-3)))`: a value keeps ≥ 62 % by arithmetic at every width, not
  only at the listed ones; `40%` landed exactly on 60.0 % in the 706–711 px band, with no margin for rounding), the SOC
  guard also pins key weight and summary alignment, PLAN and PROGRESS. Measured after: values 260 px at a 320 px brief
  (276 at 360 px), policy 1,666 px and calendar 312 px at 1280 px.

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
Open: none.

Resolved 2026-10-02 by the human (raised in WP1f):
3. **CS0-003 objective titles 2.1–2.5 and 4.1**: checked by hand against the official PDF (which the fact-checker could not read: it
   is encrypted). They match DESIGN §1 word for word; no change.
4. **Reserved domain names**: the documented exception is accepted, with a rule (DESIGN §9 rule 10). Real registered domains (the
   shared world's Microsoft sample namespaces such as `contoso.com`) and real service domains appear only in benign or legitimate
   roles; a domain in an attacker or malicious role is a reserved name (`.example`, `.test`, `.invalid`) or otherwise guaranteed
   unregistered, and is never a clickable link; documentation citations are a second exception. Vuln-mode data is enforced by test;
   SOC data was only checked and the non-compliant attacker-role domains reported (PROGRESS Known issues), SOC output unchanged.

Resolved 2026-09-28 by the human:
1. **Target exam version: CS0-003, confirmed.** CS0-003 (English) retires 2026-12-22 and CS0-004 launched 2026-06-23 (DESIGN §1); the
   whole app stays mapped to CS0-003. CS0-004 is not investigated further.
2. **CS0-004 objective numbering and CVSS version**: moot, follows from item 1.

Resolved 2026-09-28 (sources in DESIGN):
- CS0-003 objective numbers/titles 2.1–2.5, 4.1 confirmed verbatim; domain 2.0 is **30%**, not 22% (DESIGN §1). Mapping errors fixed.
- CVSS version: objectives name none; 2.3 lists Scope (v3.x-only) → v3.1 (DESIGN §10).
- CVSS v3.1 oracles recomputed from the FIRST spec and cross-checked with FIRST's calculator (DESIGN §6.2); §5.6 example 2 corrected.
- Feed names: SKEV/XPS replaced by Sim-KEV/Sim-EPSS with explainers (DESIGN §3.1).

## Decision log (ADR-style)
- **ADR-1 Sibling `VulnTemplate`, shared lower layers.** SOC `GroundTruth`/grader don't fit vuln decisions; sharing world/corpus/worker keeps one org and one console.
- **ADR-2 Fictional vuln ids (`SIMVULN-`) by default.** No network in build env; memory-sourced CVE facts are banned. *Superseded by ADR-13: the optional snapshot path is gone.*
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
- **ADR-12 Calibrated simulated feeds (2026-09-28).** One-time calibration against CISA KEV, FIRST EPSS and NVD (DESIGN §11) sets the catalogue CVSS mix, Sim-KEV count and Sim-EPSS anchor tables (§6.2). Aggregates only; no raw data or real CVE ids in the repo; no runtime or build-time fetch.
- **ADR-13 Fact policy: fictional only for v1, no real-vulnerability dataset (2026-09-28).** Scenario data is fully fictional (`SIMVULN-` ids, fictional products, Sim-KEV/Sim-EPSS); the "no real CVE id" test covers scenario data only (`src/core/vuln/**` + generated case output) with no exceptions (DESIGN §9). Reason: keeps the project's "synthetic data only" guardrail unconditional, avoids stale data and re-verification in an offline static site, and calibrated feeds plus the Help explainer already teach the real-world names. Alternative rejected: a curated real-CVE lookup panel as a later package.
- **ADR-14 Continuity = one SOC alert, upgradeable (2026-09-28).** WP5 injects exactly one alert per qualifying ledger entry, with no campaign stages. The selection is one pure function feeding an optional `planShift` slot beside `campaign`, so attacker-driven behaviour can replace it later without changing the template or ledger (DESIGN §8). Reason: smallest change that proves the link; campaign coupling is riskier to existing shift scoring.
- **ADR-15 No XP gating; difficulty tiers inside the mode (2026-09-28).** Same as the SOC side: all cases open, Tier 1–3 labels and filter (DESIGN §7). Reason: gating hides cases exam learners need; consistency with the existing Library.
- **ADR-16 WP8 (real-data snapshot script) removed (2026-09-28).** Follows from ADR-13. It was the last package, so no other package is renumbered.
- **ADR-17 Keep the CS0-003 mapping (2026-09-28; confirmed by the human the same day, no longer provisional).** CS0-003 (English) retires 2026-12-22, but the whole app maps to CS0-003 and retargeting is app-wide (NEEDS-HUMAN-CHECK 1, resolved). Objective tags are template data, so a later CS0-004 remap would touch tags and labels only.
- **ADR-18 Subagents at max effort (2026-09-28, human decision).** Every agent file on a model with effort levels sets `effort: max`
  (overrides the session effort; https://code.claude.com/docs/en/sub-agents). `explorer` stays on haiku without `effort`: Haiku has no
  effort levels (https://code.claude.com/docs/en/model-config). The coordinator's own effort is set in the app, not in these files.
  *Reverted 2026-09-29 by the human: the `effort` lines are removed; subagents follow the session effort again (models unchanged).*
- **ADR-19 Ordering tiers and SLA limits are explicit template data (2026-09-29, WP1c, coordinator).** `VulnCaseSpec.tiers` becomes
  required (tiers 1–3 → relevance 3/2/1, unlisted → 0) and `FindingTruth` gains optional `slaLatest` (latest schedule within the
  finding's SLA). Reason: §5.2 grades on tiers but an optional `tiers` left relevance undefined beyond three ranked findings, and
  §5.3's "later than SLA allows" (needed for the §5.6 total of 57.3) cannot be derived from the row: the SLA is policy and "standard
  cycle" has no date. Alternatives rejected: inferring tiers from `truth.schedule` (breaks "noise = 0") or treating any
  later-than-truth schedule as an SLA breach (removes §5.3's half credit for one step late within SLA). No template existed yet;
  the builder fixture already gives `tiers`. Grading edge cases are recorded as "Clarified (WP1c)" notes in DESIGN §2.2 and §5.
- **ADR-20 Grading and catalogue hardening before content batches (2026-09-30, human).** New package WP1f between WP1e and WP2.
  Reason: under §5 as written, a table-blind shotgun answer passes `vm-nokev-internal` (72.2–72.8) and a learner who gets only the
  lesson finding wrong still passes (76–94); every WP2/WP3 template would inherit both, and 26 % of catalogue entries carry a class
  their vector contradicts. Acceptance is defined by strategy tests over every template, not by the mechanism.
- **ADR-21 Real OS names as platform context only (2026-09-30, human).** World OS strings (`Windows Server 2022`, `Ubuntu 24.04` in
  `DeviceInfo`) stay, on the condition that a fictional vulnerability only ever belongs to a fictional product, never to a real OS or
  vendor. Reason: the shared SOC world must stay unchanged; the vulnerable product carries the fiction.
- **ADR-22 Lesson gate (2026-10-01, WP1f, coordinator; the human set the acceptance tests, ADR-20).** Key findings (the lesson
  findings, `FindingSpec.lesson`, plus must-not-miss findings) gate the pass: a missed key finding caps the case at 60 (DESIGN §5.8).
  Also: a must-not-miss schedule miss counts like a dismissal (−5); a decision that earns 0 earns no schedule or reason credit; an
  unneeded reason code costs 0.25 and a contradicting one 0.5; vuln pins: free = number of evidence points, no penalty cap, own scan
  rows neutral. Reason: three mechanisms were built and measured on every template × 20 runs (probe harness of the strategy
  tests); all three met the bounds, and two judges compared them. Score arithmetic alone (lesson finding weighing half the case,
  per-finding composite) fails "only the lesson wrong" only by a structural 2.5 points, inflates naive answers that get the lesson
  right by accident (a synthetic T2-B failed the shotgun bound), and lets a late or dismissed Sim-KEV must-not-miss pass at tier-3
  size (82–89). The cap holds at any size and needs no per-template tuning. Cost: a score can drop from about 98 to 60, so the debrief
  leads with the gate and shows the uncapped sum. Alternatives rejected: A (lesson weight = all others, exact lesson answer
  required: fails honest one-step hedges at 66), C (per-finding composite with a fixed lesson share: weakest on future twins).
- **ADR-23 Subagents at high effort (2026-10-01, human decision, during WP1f).** Every agent file whose model has effort levels sets
  `effort: high` in its frontmatter: `implementer`, `scenario-author`, `fact-checker` (sonnet), `reviewer` (opus), and the three
  reviewers without `model:` that follow the main session's model (Opus 5.5: `code-reviewer`, `guardrail-auditor`,
  `scenario-reviewer`). `explorer` stays on haiku without `effort` (Haiku has no effort levels, as in ADR-18). Models are unchanged.
  Takes effect for agents started after the change; WP1f's earlier stages ran at the session effort.
- **ADR-24 SOC content may change for quality (2026-10-03, human decision).** The guardrail "existing SOC content and scores
  unchanged" is replaced (CLAUDE.md): SOC content and output may change when that raises the quality of the overall product. Each
  such change is deliberate (never a side effect of vuln work), reviewer-checked and logged in PROGRESS.md with its reason; one that
  moves existing SOC scores says so. Vuln packages still prove "no side effect" where they promise it (e.g. WP5's no-hook identity). The reviewer's
  guardrail list (`.claude/agents/reviewer.md`) and DESIGN §10's non-goal were updated to match.
  First use: the authorised-pentest case's claims about other sources (WP5 known issue), reworded the same day.
- **ADR-25 scenario-author scope covers package-assigned files (2026-10-03, human decision).** `.claude/agents/scenario-author.md`
  and CLAUDE.md: besides `src/core/vuln/templates/**` and `tests/vuln-scenarios/**`, the scenario-author writes any file the
  current package (PLAN.md) or the coordinator's brief assigns to it by path (e.g. a linked SOC template); never an unassigned SOC
  template. Reason: in WP5 it declined the two files PLAN assigned to it, once, because its definition named only the vuln area.
  Model and effort unchanged.
- **ADR-26 Vuln rubric matcher with word boundaries (2026-10-03, WP6, coordinator).** Vuln stakeholder notes are matched by
  `vulnRubricHits` (lowercase, possessives dropped, punctuation runs → one space, note padded; keywords may carry edge spaces as
  word boundaries); SOC keeps the substring `detectRubricHits`. Reason: substring matching cannot keep a date keyword such as
  'oct 3' from matching "Oct 31", and the rubric keyword audit showed generic words ticking content-free notes. Rubric
  quality is held by generic tests (model note, content-free note, twin cross-ticks, containment), not by single phrases.
  Keyword coaching stays approximate (negations), as ADR-3 accepts. Scores unchanged; only vuln rubric XP can move.
- **ADR-27 SOC attacker-role domains keep their generated names (2026-10-03, WP7, coordinator).** DESIGN §9 rule 10 is not
  applied to SOC data in this workstream: reserved TLDs on attacker domains alone would make the TLD a perfect tell (1,355 vs
  0 in 100 SOC builds) and empty the lessons that turn on telling a fictitious partner or vendor domain from an attacker's.
  The complete fix re-domains the shared world's fictitious partner and vendor namespaces too, a SOC content project of its
  own. Mitigations in place: no domain is rendered as a link (SOC and vuln e2e), Help tells learners not to visit them.
- **ADR-28 Vuln brief attachments follow the brief's width; values in the sans face (2026-10-03, WP8, coordinator).**
  `.vc-brief` is an inline-size container: its key/value attachments stack (key, then a full-width value) under a 640 px
  content box and show two columns above it, the key capped at 38 % minus the column gap so a value keeps ≥ 62 %; the
  values are set in the sans face with tabular figures (policy sentences and timestamps, not identifiers — the SOC panel
  keeps monospace); at ≥ 1200 px the vuln case grid gets a brief column of `clamp(320px, 25%, 480px)` and a spare `1fr`
  row so the brief's height no longer stretches the right-hand cards. Reason: with the shared `.kv` (`max-content 1fr`)
  in a 320 px column the values measured 89 / 17 px of monospace and the attachments 4,813 / 2,177 px tall. Chosen from a
  judged panel (responsive CSS, typography, page layout) by the grafts both judges agreed on. Vuln-only (every selector
  under `.vc-brief` or the `.vc` grid); an e2e guard pins the SOC `.kv` shape, key weight and summary alignment. First use
  of container queries and the `lh` unit (Chrome 109+, Firefox 120+, Safari 16.4+; degradation is the capped two-column
  list and an unshifted icon).
