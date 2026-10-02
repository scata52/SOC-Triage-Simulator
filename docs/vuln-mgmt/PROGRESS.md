# PROGRESS — Vulnerability Management

Branch: `feat/vuln-mgmt-wp1` (from `main` @ 849adce).

## Done
- **WP0 — Kickoff and progress file** (2026-09-28). Baseline on `main` @ 849adce: `npm run typecheck` ok, `npm test` 16 files / 233 tests
  passed, `npm run build` ok (Node 24.19.0).
- **WP1a — Core types, fictional catalogue, CVSS 3.1 calculator** (2026-09-28). `src/core/vuln/{model,cvss31,ids,catalogue}.ts`;
  tests `vuln-cvss` (all 18 §6.2 oracle rows), `vuln-catalogue`, `vuln-guardrails`. 19 files / 298 tests green; reviewer PASS.

- **WP1b — Corpus tables and scan writer** (2026-09-28). Six context tables in `logs/schema.ts` (appended after the existing 18) and thin
  writers in `corpus.ts`; `src/core/vuln/{scan-writer,scenario,registry}.ts`; `vuln` OpenSpec variant in worker/protocol; two join examples
  in `kql/reference.ts`; bare-table right side for `join` in the KQL parser. Tests `vuln-corpus` (+34), guardrail wired to generated
  cases; helpers `cve-guard`, `vuln-fixture` (tier-3 fixture), `vuln-scenario-check`. 20 files / 334 tests, build ok, e2e 11/11
  (system Chrome). SOC output verified byte-identical (25 templates + 3 shifts hashed before/after, ignoring the six new empty tables).
  Reviewer PASS (max effort): independent hash probe, 50 practice cases + 5 shifts identical vs HEAD; build ≈ 6 ms warm / 20 ms cold.
- **WP1c — Grader** (2026-09-29). `src/core/vuln/grade.ts` (`gradeVulnCase`, `emptyVulnSubmission`, `perfectVulnSubmission`, per-finding
  results for the debrief); ordinal credit and evidence scoring moved to `src/core/grading/shared.ts`; ADR-19 (`tiers` required,
  `FindingTruth.slaLatest`, five build-time tier checks). Tests `vuln-grading` (122), tier checks in `vuln-corpus`; `checkVulnGrading`
  (perfect = 100, empty = 0) runs in `checkVulnTemplate`. 21 files / 457 tests, build ok, e2e 11/11. SOC `gradeCase` byte-identical
  (3,000 grades + 30 shift scores hashed vs HEAD). Reviewer PASS twice: the gate, then a re-gate after a delta from the code review and
  the differential oracle (independent grader from the rules: 0 mismatches over 87,622 submissions). Surviving mutants now killed.

- **WP1d — Slice content** (2026-09-30). `src/core/vuln/templates/`: `vm-kev-internal` / `vm-nokev-internal` (twin T3, tier 1,
  §5.6 literally), `vm-stale-scan` (T2 A, tier 1), `vm-backport-fp` (T1 A, tier 2); shared `common.ts` (org policy + calendar
  attachments, one-row-per-finding scan model, `WORKLIST_SHAPES`: the curated class/component/vector table every worklist finding comes
  from, background noise within §6.3, login-failure rows, contradiction facts, twin-shared rng). Tests `tests/vuln-scenarios/`: slice
  (acceptance 1–2: every template × 20 seeds with the DB, per-seed determinism, 100/0, every evidence row returned; twins; §5.6 on
  the built case: 57.3 / 15 / −4), data-rules (generic rules every template inherits: class/vector coherence, §6.3 budget, dates,
  deadline derivation with ≥ 24 h margins, contradicting codes and true required codes, weights, run coverage, naive-strategy guard
  < 70), regressions (named seeds; opt-in 2,000-seed sweep), per-template checks. Outside the list, reviewer-signed: catalogue
  Sim-KEV dates ≥ 2021-11-03 and two renames (prep); helper and registry edits (coordinator). 27 files / 609 tests (+4 opt-in),
  build ok. Reviews: review #1 FAIL (4 blocking); fix rounds 1–5, each checked by an independent verifier; review #2 reviewer PASS
  and fact-checker PASS; content defects found by the other reviewers fixed afterwards; reviewer re-gate PASS; fact-checker FAIL on
  two shape-table triples, fixed, then confirmed (see Decisions).

- **WP1e — UI slice + accessibility** (2026-10-01). Routes `#/vuln` and `#/vuln/<slug>/<seed>`; `VulnLibrary` (the SOC Library's tier
  filter and labels; twins share one card, the seed picks the twin), `VulnCase` (brief, worklist, console, note, submit gate,
  debrief), `Worklist` (table above 760 px, cards at or below; sortable columns with Undo sort, Move up/down, priority input,
  Alt+Up/Down, up to 3 reason chips, live-region announcements), `VulnDebrief`; pure helpers in `src/core/vuln/worklist.ts`. Attempts
  are recorded as `mode: 'vuln'`, `category: 'vulnmgmt'`, with XP added to the shared total. SOC sessions no longer offer the six vuln
  tables (schema browser, KQL autocomplete); Help marks them as vuln-only. Tests: `tests/vuln-worklist.test.ts`, vuln cases in
  `tests/profile.test.ts`, `e2e/vuln.spec.ts` (16). 28 files / 655 tests (+1 expected fail, 4 opt-in), build ok, e2e 27/27, vuln e2e
  80/80 over 5 repeats. Process: design spec with 3 critics; pre-gate review (5 lenses, one skeptic per finding: 7 defects confirmed,
  fixed in one round); reviewer gate FAIL once (a Help near-miss example was reversed, fixed inline), re-gate PASS with sign-off on
  every outside-list file. README table count updated.

- **WP1f — Grading and catalogue hardening** (2026-10-01). Lesson gate (ADR-22, DESIGN §5.8): lesson findings
  (`FindingSpec.lesson`) and must-not-miss findings are key; a missed key finding caps the case at 60 and the debrief leads with it
  (uncapped sum shown); must-not-miss left open −5; a decision worth 0 earns no schedule or reason credit; unneeded code −0.25,
  contradicting −0.5; vuln pins: free = evidence points, no cap, own scan rows neutral (opt-in in `grading/shared.ts`, SOC output
  byte-identical: 3,200 graded SOC submissions vs HEAD). Build errors: no lesson finding, real key finding without `slaLatest`, no
  evidence point. Catalogue: only coherent class/component/vector entries (predicate moved to `coherence.ts`, tightened after
  three fact-checker vetoes; `classes.ts`); 2,000-catalogue sweep and a concentration test. "Quorvane" → "Dunmarrow"; T3 twins
  share a neutral hint 1 and write equal row counts (background noise on a shared rng); reserved-domain guardrail scan (world org
  domains and citation hosts exempt pending NEEDS-HUMAN-CHECK 4); CS0-003 titles NEEDS-HUMAN-CHECK 3 (PDF encrypted).
  `tests/vuln-hardening.test.ts`, every template × 20 runs (percent): shotgun max 53 / 57 / 55 / 40, only-the-lesson-wrong max 60
  for every lesson finding, ideal min 100, lesson right + slips min 88 / 88 / 90 / 94 (kev / nokev / stale / backport); before:
  shotgun up to 72.8 and lesson-wrong up to 97.2. 29 files / 728 tests (+5 opt-in), build ok, e2e 28/28 (system Chrome). Process:
  probe harness + three competing mechanisms + two judges; pre-gate review and two verified fix rounds; reviewer gate PASS (first
  attempt), fact-checker PASS.

## In progress
- None. Next session starts WP2.

## Next
- WP2 — Content batch A (twins T1, T2, T4, T5)
- WP3 — Content batch B (twins T6, T7, T8, T11) + tier 3 (T9, T10)
- WP4 — Stats and study integration
- WP5 — Continuity hook (vuln → SOC)
- WP6 — Polish
- WP7 — Hardening

## Decisions
- ADR-1 … ADR-17 live in PLAN.md "Decision log"; this file records only execution-time decisions.
- 2026-09-28: NEEDS-HUMAN-CHECK 1–2 (CS0-003 vs CS0-004) do not block WP1a/WP1b — they touch objective tags (template data, WP1d+)
  only; CVSS oracles are verified (DESIGN §6.2). Mode maps to CS0-003 per ADR-17.
- WP1a: `VulnContext = CaseContext & { vuln: { catalogue } }`; the scan writer is added additively in WP1b.
- WP1a: model adds optional `FindingTruth.contradicting` (§5.4 per-finding contradicting codes), `VulnCaseSpec.tiers`,
  `constraints.freezes`; the change-window type is `ChangeWindow` (DESIGN's `Window` clashes with the DOM global).
- WP1a: catalogue band mix is quota-based (exactly 9/24/24/3 of 60), so the ±5-point criterion holds for every seed.
  `generateCatalogue(seed, referenceDate)` needs an explicit reference date (no clock reads).
- WP1a: environmental score uses exponent 13 (base uses 15) as FIRST v3.1 §7.3 specifies; an unmodified scope-changed vector can
  therefore score 0.1 above its base score. Intended, tested.
- WP1a: fictional product "Juniperline" renamed "Kestrelmoor" (too close to a real vendor name).
- 2026-09-28 (human): subagents run at `effort: max` (ADR-18). WP1a and its review ran at session effort; WP1b's review onward at max.

- WP1b: the six tables are appended AFTER `IncidentHistory` in `SCHEMA`, so the RecordId sequence of every existing table is unchanged;
  `Corpus.tables` gains six empty keys in SOC scenarios (unavoidable: `Record<TableName, …>`). A test pins the table order.
- WP1b: columns added beyond §6.1 (which lists key columns): `VulnIntel.FixedVersion`, `PatchHistory.Description`. `VendorFix` is a bool.
- WP1b: vuln corpus has no SOC log noise (hundreds of rows: CMDB/identity context from the world plus what the template plants);
  `planSessions` still runs so `VulnContext extends CaseContext` is honest. Log window is 14 days (`VULN_WINDOW_DAYS`).
- WP1b: case date and catalogue depend on `(worldSeed, seed)` only, not on the template id, so twin templates built with the same seed
  share the date and the catalogue and can pair deciders. Template rng streams still depend on the template id.
- WP1b: `ctx.vuln.scan` (ScanWriter) API: `run`, `finding`, `background` (mostly medium/low, never Sim-KEV, plus `hygiene` findings with
  empty VulnId), `intel` (create/patch; pass a modified catalogue entry to override a decider), `software` (upsert), `scopeHost`
  (scenario-only device, inserted at a seeded CMDB position). Method rules enforced: unauthenticated = banner version and needs a port;
  credentialed/agent = package version; a failed login falls back to the banner for that device for the whole run and is counted in
  `ScanRuns.AuthFailures`; external scans are unauthenticated and see only exposed devices; findings cannot span more devices than
  `TargetsScanned`.
- WP1b: KQL parser now accepts a bare table on the right of `join` (real KQL: `| join kind=inner VulnIntel on VulnId`), additive; the
  parenthesised form is unchanged. Needed for the literal example in PLAN/DESIGN.
- WP1b: `registry.ts` (`VULN_TEMPLATES`, empty) is where WP1d wires `templates/index.ts`; `buildVulnScenario` also takes a `template` object.
  `SessionInfo.vulnCase` carries a vuln session; `cases` is `[]` and `infra` `{}` for it.

- 2026-09-28 (human): exam version is **CS0-003, confirmed**; CS0-004 is not investigated further. NEEDS-HUMAN-CHECK 1–2 closed in
  PLAN.md; ADR-17 is no longer provisional.
- 2026-09-28 (coordinator, left to it by the human): **`explorer` stays on haiku** without `effort`. Reason: it answers location lookups
  whose output (paths, symbols) the coordinator checks before acting on it, so a wrong answer is caught cheaply and deeper reasoning buys
  little; ADR-9's cost rationale still holds; no explorer error has been observed; agent models change only for a concrete reason.
- 2026-09-28 (coordinator, left to it by the human): **WP1a's review is re-run at max effort**, read-only against commit fbed98e, in
  parallel with WP1c. Reason: WP1a is what WP1c and WP1d build on (model types, CVSS calculator, catalogue: ≈ 780 source lines), it is
  the only package reviewed before ADR-18, and the calculator is pinned by 18 oracle rows but untested outside them. Findings that don't
  block WP1c go to Known issues for a separate fix, not into the WP1c commit.
- 2026-09-28 (human): the six vuln tables that show up empty in SOC sessions stay as they are until WP1e, as recommended. PLAN.md's WP1e
  entry did not say so; it now carries the goal, acceptance (9) and the three files (`Tools.tsx`, `Editor.tsx`, `Help.tsx`).

- 2026-09-29 (coordinator, before WP1c): session start found PLAN, PROGRESS and repo in agreement (WP0–WP1b committed, no WP1c file);
  the branch was 1 commit ahead of origin (8f8da53, unpushed). DESIGN §5 left gaps the grader must fill; resolved as ADR-19 (`tiers`
  required, `FindingTruth.slaLatest`) plus "Clarified (WP1c)" notes in DESIGN §2.2/§5: rounding, mitigate without control, penalty
  inside the 40 points, restraint rule for an untiered case and for findings without required codes, 3-code cap, capacity ties.
  §5.3 "emergency when not justified = half" is implemented as written, including truth `none`: on an FP, emergency then scores
  0.5 while next-window scores 0. Flagged for the human; a one-line DESIGN change would limit it to findings that need a fix.
  **Resolved 2026-09-29 (human): half credit only on real findings** (truth not FP, as for the must-not-miss penalty); an emergency
  on a false positive now follows the ordinal: 0 against its usual truth `none`. DESIGN §5.3 updated. Reviewer PASS (differential vs
  the previous grader: only FP + emergency findings changed, 0.5 → 0; 468 tests).
- WP1c: grade details WP1e's debrief relies on: `mustNotMiss.decisionPenalty` / `orderingPenalty` give the nominal charge (5 per
  dismissal, cap 10; 4 per miss) before the floor at 0; a finding zeroed by capacity keeps its own zero-credit verdict (`sla-breach`,
  `wrong`) and is listed in `overflow`, so the debrief must read that list; `slaLatest: null` counts as not set; out-of-enum
  decisions/schedules count as unanswered and negative or NaN `hintsUsed` as 0; required codes are a set (repeats ignored) and
  `perfectVulnSubmission` answers the first three distinct ones. The ordering sentence floors the nDCG percent (§5.6 sort-by-CVSS
  reads 69 %); WP6's copy review may switch to one decimal.
- WP1c: the WP1a re-review at max effort ran in parallel: PASS. An independent CVSS 3.1 implementation matched every one of 2,592 base
  vectors, 259,200 temporal and 16.6 M environmental combinations; 9,000 generated catalogues had 0 violations. Minor findings under
  Known issues.
- 2026-09-29 (human): ADR-18 reverted. `effort: max` is removed from the seven agent files; subagents follow the session effort again.
  Models are unchanged.

- 2026-09-29 (coordinator, before WP1d): session start found PLAN, PROGRESS and repo in agreement (WP0–WP1c committed incl. 09f8f50,
  no `templates/` yet); branch in sync with origin. Open items left for WP1d, resolved:
  - **Evidence is per case.** `checkVulnStructure` now requires ≥ 1 evidence point per case and one on every must-not-miss finding,
    not one per finding. Reason: §5.5 scores "every evidence spec of every finding" and §5.6 gives F2 none (3 points, "evidence
    1/3 → 5"); a point on F2 would break the worked example, and a medium TLS finding with no decider has nothing to prove. The
    must-not-miss rule keeps the costly mistake provable.
  - **False positive ⇒ schedule `none`** is a structure check (Known issues, WP1c).
  - **Acceptance 1 read literally:** every template × 20 seeds, each with the database; determinism per seed (was: first run only);
    the reference investigation must return *every* row of every evidence point (`checkVulnTemplate(..., { everyEvidenceRow })`).
    The WP1b tier-3 fixture keeps the SOC "any row" rule: its `backport` point lists alternative rows by design.
  - **Sim-KEV dates and "Fenwick"** are fixed in `catalogue.ts` (outside WP1d's list, logged in PLAN.md): a listing date is never
    before the real KEV catalogue's launch (fact-checker confirms the date), the product is renamed. Reason: Sim-KEV is "modeled on"
    KEV, so a 2012 listing date teaches something false; rule 1 forbids real company names. Clamp after the draws, so every other
    catalogue value stays byte-identical.
  - **T3 headline class.** §6.2 pins the T3 headline to `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5) but §5.6 calls F1 an "RCE"; a
    C:H-only vector is a remote information disclosure, not code execution. The vector wins (oracle row, twin headline); F1 is an
    unauthenticated remote information disclosure, §5.6 wording clarified.
  - **`vm-kev-internal` is §5.6 literally:** 4 findings with §5.6's truths, weights, tiers, required reasons and 3 evidence points;
    CVSS F3 > 7.5 > F4 (High) > F2 (Medium), so §5.6's sort-by-CVSS order holds; the slice test reproduces §5.6 on the built case.
  - **F4 next-window vs twin B's F1 standard-cycle** (both High, Sim-EPSS ≈ 0.004): the difference is the SLA clock. F4 was first
    seen early enough that the standard cycle breaches its High SLA (`slaLatest: 'next-window'`); B's F1 was first seen recently.
    §5.6's required reasons stay; `sla-deadline` is allowed, never contradicting.
  - **Worklist = the spec's findings** (tier 1: 4–6, §2.3). §6.3's "60–80 % background" is measured over the corpus `VulnFindings`
    rows (unscored scanner output in the console), not the worklist.
  - **Twin headline convention:** `findings[0]` is the headline finding in both twins; the slice test checks equal title, equal
    headline base score and a different headline decision or schedule.
  - Registry wiring (`registry.ts` imports `templates/index.ts`) and the stub index: coordinator, inline.
- WP1d prep (fact-checker on the authoring brief, no veto; reviewer PASS on the catalogue change and the inline edits above):
  - KEV launch 2021-11-03 (BOD 22-01); a web sweep of every catalogue/scan-writer name found two real IT vendors (Fenwick, Northmere),
    both renamed. Catalogue output otherwise byte-identical to HEAD (reviewer probe, 10,800 catalogues).
  - The org policy is the fictional org's own (never presented as CISA's; the fact-checker reports BOD 22-01 was revoked 2026-06-10 for
    BOD 26-04, so prose cites neither as current). The Sim-KEV 3-day clock runs from the later of first detection and the listing date.
  - Twin B tiers are `[[F4], [F1], [F2]]`, not a tie: F4's SLA deadline is earlier (next-window vs standard-cycle), so a tie would
    contradict the schedule truths.
  - Objectives: T3 twins `2.3, 2.5, 4.1`; `vm-stale-scan` `2.1, 2.2, 2.3, 2.5, 4.1` (2.5 added in review #2: it grades a risk
    exception and change windows); `vm-backport-fp` `2.1, 2.2, 2.3, 2.5, 4.1`;
    `cysaDomains ['2.0', '4.0']` (every template has a stakeholder-note rubric).
  - `vm-backport-fp` is tier 2 (8–12 findings, 2 deciders), so the slice gives WP1e's tier filter two tiers; the others are tier 1.
    T1/T2 A sides leave `twin` unset until their B side lands (WP2), so nothing links to a missing case.
- WP1d review #1 (reviewer FAIL; fact-checker FAIL, no veto; scenario-reviewer, red-team learner and code-reviewer FAIL). Blocking:
  backport's Sim-KEV decider had no decoy; re-vectored catalogue entries kept a class/title their vector contradicts; a table-blind
  strategy passed `vm-nokev-internal` (72.4); a template wrote a real OS name. All fixed in one round (see Done). Rulings:
  - **World OS strings** (`Windows Server 2022`, `Ubuntu 24.04` in DeviceInfo) come from the shared SOC world, which must stay
    unchanged; they are platform context, never the vulnerable product. Every vulnerable product and every template-authored host OS
    is fictional. Flagged for the human.
  - **Weights follow §5.1:** must-not-miss 3, deciders/decoys/tiered findings 1, worklist padding (low/info, standard-cycle noise,
    accepted risk) 0.5. §5.6 keeps F2 at 1 (literal).
  - **Contradicting codes** list every signal code that the data proves false for that finding (`stale-scan` on a real finding,
    `known-exploited` when not listed, `public-exploit` when none, `low-exploitability` when listed); §5.4 uses the first as its example.
  - **Background noise** (unscored rows) stays ≤ Medium with no exploitation signal (not listed, Sim-EPSS < 0.02, no public exploit,
    vendor fix available), per §6.3 "informational/low".
  - Deadlines are due by the end of the day (UTC), and every truth keeps ≥ 1 day between its deadline and the window that decides it.
  - Naive strategies (all-patch-by-CVSS, all-FP, SLA-by-class, reason spam) must stay below the 70 % pass mark on every template.
    The remaining headroom sits in the grader as specified (extra codes cost nothing, §5.4; FP scheduled standard-cycle earns 0.5,
    §5.3); left for the slice exit review, not changed in WP1d.

- 2026-09-30 (WP1d close-out): review #2 gave reviewer PASS and fact-checker PASS, but the scenario-reviewer, red-team and
  code-reviewer still found content that taught something false (a misconfiguration accepted "for lack of a vendor fix", a local-only
  vector on an internet-exposed must-not-miss, a false pitfall sentence). Rather than commit known-false content, three more rounds
  followed (each verifier-checked), ending in `WORKLIST_SHAPES`: worklist class, component and vector come only from a curated table,
  because fitting descriptions to arbitrary catalogue vectors kept producing oddities. Reviewer re-gate PASS; fact-checker FAIL on two
  triples ('local API' SQLi scored AV:N; web-app components in AV:L groups), fixed, then fact-checker PASS and reviewer PASS on the delta.
  The fact-checker notes "Quorvane" (the fictional web server) also names unrelated gambling domains and a hobby project: non-blocking.

- 2026-09-30 (coordinator, before WP1e): session start found PLAN, PROGRESS and repo in agreement (WP0–WP1d committed, no WP1e file:
  no `Vuln*.tsx`, `Worklist.tsx`, `e2e/vuln.spec.ts`); branch clean and in sync with origin. Human decisions on the open items, recorded:
  1. **Grading loophole: fix it** in a new package **WP1f** (after WP1e, before WP2; ADR-20). Done = strategy tests over every
     template: shotgun fails, only-the-lesson-wrong fails, ideal ≥ 90, lesson right with minor slips passes. Starting mechanism: a
     missed must-not-miss schedule counts like a dismissal, free pins = number of evidence points, irrelevant codes never score
     positively. DESIGN §5 and §5.6 follow in WP1f.
  2. **Real OS names as platform context: confirmed** (ADR-21), on the condition that fictional vulnerabilities only ever belong to
     fictional products, never to a real OS or vendor.
  3. **Catalogue class/vector contradictions** are fixed in WP1f, with a test that fails the build on any contradiction.
  4. **Worklist order** is WP1e acceptance (10): the default order is not derived from the answer key; columns are sortable.
  5. In WP1f: rename "Quorvane" (no real-world hits), reserved domains only (`.example`, `.test`, `.invalid`), fetch the official
     CS0-003 objectives to verify titles (NEEDS-HUMAN-CHECK if gated).
- WP1e (coordinator): the default worklist order is **FindingId ascending** (scanner export order). FindingIds are `VF-NNNNN` drawn
  from the scan writer's rng (`nextFindingId`), so the order carries no answer-key signal; sorting by severity or CVSS is one action
  away. Column sort reorders the worklist itself: the table order is the submitted priority order (§7 has one order, refined by Move
  up/down and the priority input), and each sort is announced in the live region.

- WP1e (coordinator sign-off on the design spec, 2026-09-30). Deviations from DESIGN: D1 `recordVulnAttempt` instead of
  `recordAttempt` (no SRS cards or disposition streak for vuln until WP4; `asStudyAttempts` skips vuln attempts); D2 components stored
  under `vuln-*` keys, top-level evidence 0/0, details in optional `AttemptRecord.vuln`, so SOC Stats math is untouched; D3 a vuln
  console (reusing `Results`, `SchemaBrowser`, `LazyEditor`, `Decoder`, `QueryHistory`, `Tabs`) instead of the SOC `Workspace`, which is
  typed to SOC cases; D4 no live rubric before submit, whatever `showRubricLive` says (rubric texts and keyword ticks reveal schedules
  and the twin); D5 Alt+Up/Down does not act from a `<select>` (Alt+Down opens it; Help says so); D6 a vuln-local `say()` so a
  repeated message is spoken again; D7 the submit gate asks for a decision and a schedule on every finding, and for a control only
  when ControlInventory has rows. Also: Stats reads SOC attempts only until WP4; Home's first-run state and accuracy chip count SOC
  attempts only; the vuln screens must have zero axe violations of any impact (stricter than the shared SOC helper); no nav item
  (WP6 decides); the submitted order is the table order, FP/accept rows included.
- WP1e acceptance readings: (1) keyboard-only from the library to the debrief, including a reorder, a query, a pin and a note;
  (3) no `<table>` at 760 px or less and no page scroll at 360 and 320 px; (4) no running animation after a move or sort, under the
  system setting and the app's MotionPref; (8) every tier that has a template (1 and 2 today) — Tier 3 shows an empty state until WP3;
  (10) default order = FindingId ascending, proven on a seed whose spec order is not ascending, and a column sort changes the
  submitted order.
- 2026-10-01: the session limit paused WP1e's pre-gate review on 2026-09-30; it resumed from the workflow cache and nothing was
  lost. While cleaning up, `git worktree remove --force` on a review agent's scratch worktree followed its `node_modules` junction
  and deleted part of the main `node_modules`; restored with `npm ci` from the unchanged lockfile (checks matched before and after).
  Agents are now told not to junction worktrees.
- 2026-10-01 (human, after WP1e): WP1e merged to `main` via PR #4 (merge commit 2782c3b, CI green); the branch is fast-forwarded to
  `main`. Decisions: (1) the GitHub Pages redeploy that every push to `main` triggers is fine as is, so the live site shows the
  vuln mode before WP1f; (2) the Claude Code Review workflow (added in PR #3) may read the PR: its `--allowedTools` now match the
  code-review plugin's own list (`gh pr view/diff/list`, `gh issue view/list`, `gh search`, `gh pr comment` for its summary, inline
  comments) and `pull-requests: write` as in the action's official example; before, it finished green in seconds without reading the
  diff; (3) WP1f starts in a fresh session.

- 2026-10-01 (coordinator, before WP1f): session start found PLAN, PROGRESS and repo in agreement (WP0–WP1e committed and merged,
  no hardening test); branch clean, in sync with origin and `main` (f13ec50); baseline 28 files / 655 tests (+1 expected fail,
  4 opt-in). The human's five WP1f decisions were already recorded (2026-09-30 entry above, ADR-20/21, PLAN WP1f/WP1e); no other
  open question was left for the coordinator.
- WP1f acceptance readings (the criteria do not define these terms; flagged here, not guessed silently): **lesson finding** =
  the finding(s) the template's `lesson` text is about, now explicit data (`FindingSpec.lesson`; in twins `findings[0]`, verified
  on every run; the stale-scan and backport-fp lesson texts also name the sibling decoy, so it is flagged too — pre-gate review);
  "only the lesson finding wrong" is tried for each lesson finding in turn; **targeted misconception** = the twin's truth for the
  headline (decision, schedule, reasons, place in the order), else a flip: a false positive trusted (patch at the SLA-table
  schedule), a real finding dismissed as a false positive; **every reason code** = only three count, so the shotgun is
  tried with the full vocabulary in order, the common-code spam set and the case's three most-required codes, and the bound holds
  for the best; **every row pinned** = all corpus rows, or the vuln tables plus DeviceInfo; **ideal** = the perfect answer pinning
  every row of every evidence point plus each finding's own scan row (perfect itself stays 100); **minor slips** = one other finding
  one step earlier, one required code dropped, one evidence point unpinned, one adjacent swap, one hint, two irrelevant pins, all at
  once; **fails** = below the 70 pass mark on every template × 20 runs. Written into DESIGN §5.8.
- WP1f mechanism (ADR-22): three candidates (A: arithmetic, the human's starting rules plus a lesson weight of half the case; B:
  lesson gate; C: per-finding composite) were built as scratch graders and measured with a shared probe harness on every template
  × 20 runs; all met the four bounds; two judges (learner fairness, robustness) split C vs B. Chosen: **B plus grafts** — a missed
  key finding (lesson or must-not-miss) caps the case at 60; must-not-miss left open (FP, unscheduled, past `slaLatest`) −5; a
  decision worth 0 earns no schedule or reason credit; unneeded code −0.25, contradicting −0.5; vuln pins: free = evidence points,
  no cap, own scan rows neutral. Baseline before WP1f: S1 max 70.4 / 72.8 / 70.4 / 59.0 and S2 max 95.9 / 97.2 / 88.0 / 87.8
  (kev / nokev / stale / backport). The human's starting mechanism alone left S2 at 70.9 / 97.2 / 88.0 / 87.8 (measured).
- WP1f inline (coordinator): `FindingSpec.lesson?` in `model.ts`; `lesson: true` on the four headline lesson findings (one line
  each in `kev-internal.ts` ×2, `stale-scan.ts`, `backport-fp.ts`), so the implementer and the scenario-author could start in
  parallel; after the pre-gate review two more on the stale-scan and backport-fp decoys (six in all); after the gate, `Fragment`
  keys in `VulnDebrief.tsx` (reviewer note).
- WP1f pre-gate review (5 lenses, a skeptic per finding; 22 confirmed ≈ 13 distinct, 5 refuted) and rulings: the decoys named by
  the stale-scan and backport-fp lesson texts are lesson findings (dismissing the real Critical decoy passed at 84–86); the lesson
  emergency clause is dropped (a draft capped a cautious emergency patch on a real next-window decoy; nokev's over-reaction is
  two steps and stays caught); left open applies only when the truth schedule is not `none`; hardening bounds use the percent
  the pass decision uses; S2 runs per lesson finding. Two fix rounds, each verified; the fact-checker vetoed new catalogue pairings
  three times (TLS with availability impact; misconfig components with UI:R, AV:L or single-impact shapes), each fixed and re-passed.
- WP1f facts: "Quorvane" → **"Dunmarrow"** (fact-checker web sweep: only fictional-world mentions, no company, product,
  trademark or domain; six other candidates rejected). The CS0-003 objectives PDF is encrypted (NEEDS-HUMAN-CHECK 3). The world's
  org domains are registered Microsoft fictitious-company domains, not reserved names, shared with SOC (NEEDS-HUMAN-CHECK 4).
- 2026-10-01 (human, during WP1f): subagents run at **`effort: high`** (ADR-23): seven agent files, `explorer` (haiku) excluded,
  models unchanged. WP1f's design, build, catalogue and content stages ran at the session effort; the pre-gate review (paused by
  the human) and everything after it run at high.

- 2026-10-02 (human, after WP1f): decisions on the open items, applied before WP2 (no work package started).
  1. **CS0-003 objective titles** checked by hand against the official PDF: identical to DESIGN §1; NEEDS-HUMAN-CHECK 3 closed.
  2. **Domains**: the documented exception is accepted with a rule (DESIGN §9 rule 10; NEEDS-HUMAN-CHECK 4 closed): real registered
     and service domains only in benign roles; attacker-role domains reserved (or guaranteed unregistered) and never clickable;
     citations a second exception. Vuln mode is enforced: `tests/vuln-guardrails.test.ts` allows a non-reserved domain only in four
     benign columns (`IdentityInfo.AccountUpn`, `IdentityInfo.Manager`, `DeviceInfo.Owner`, `Tickets.Requester`) or a citation
     host in case references, reserved names everywhere else, with a checker self-test; `e2e/vuln.spec.ts` checks that the vuln
     library, a case page with a query result and the debrief link only in-app routes and citation hosts. No auto-linkification
     exists in `src/ui`. SOC was checked only (see Known issues).
  3. **Cap confirmed** (keep the pre-cap score and the debrief lead). The human asked to confirm that it triggers only on
     must-not-miss findings: it does not — it triggers on every key finding, lesson findings included (DESIGN §5.8); in nokev,
     stale-scan and backport-fp the lesson findings are not must-not-miss, and a must-not-miss-only cap would let "only the lesson
     finding wrong" pass at 88–97 (WP1f acceptance 2). Lesson right with minor slips passes: 88 / 88 / 90 / 94 %. Raised with the
     human, who decided the same day: **keep it** (the cap covers lesson and must-not-miss findings, DESIGN §5.8).
  4. **Claude Code Review check**: it reviewed nothing because the code-review plugin's command runs every step through subagents
     and the job allowed no agent tool (PR #6 run: 2 turns, no tool call, no comment, green). Replaced with a direct review prompt
     and the gh tools (the action's own `pr-review-comprehensive` example), restricted to pull requests into `main`, and a final
     step that fails the job when no bot comment was posted. The action only runs a workflow identical to the default branch's, so
     the pull request carrying this change shows the check red; it is proven on the next pull request.

## Known issues
- SOC attacker-role domains do not meet DESIGN §9 rule 10 (checked 2026-10-02, reported, SOC output unchanged as the human asked):
  every one comes from `attackerDomain()` (`src/core/synth/domains.ts:120-142`; random labels under real TLDs: `SUSPICIOUS_TLDS`
  .top/.xyz/… at :80, `GENERIC_TLDS` .com/.net/.org/.io/… at :81, lookalike `.com/.net/.co`), called by `src/core/cases/infra.ts:83`
  and `src/core/logs/noise/email.ts:81,91`. In 300 practice builds (25 templates × 3 worlds × 4 seeds): 132 distinct truth domains
  and 4,020 logged ones, none reserved. No template hard-codes an attacker domain, and none is rendered as a link. Fixing it changes
  every SOC case: a human decision.
- Vuln domain test, minor (reviewer, 2026-10-02): its bare-token file-extension list includes real TLDs (`.zip`, `.sh`, `.py`, `.md`,
  `.so`), so a bare token such as `c2.zip` would pass; URL and e-mail hosts are checked without it, and no such token occurs today.
- WP1e follow-ups: Stats ignores vuln attempts until WP4; the control picker with a non-empty ControlInventory has no e2e test until a
  template writes controls (WP2, T5/T6; unit tests cover the gate branch); the query engine still knows the six vuln tables in SOC
  sessions (empty results, a did-you-mean could name one); a "Query this finding in the console" button was dropped (WP6
  candidate); devtools on one's own profile shows the template id of an earlier attempt of the same seed; SQL mode has no
  autocomplete popup in either mode (pre-existing; the SQL schema map is inert). (Help's mitigate sentence, the twin-telling first
  hint and the twin `VulnIntel` row counts were fixed in WP1f.)
- `tests/helpers/vuln-scenario-check.ts` covers build, structure, corpus integrity, synthetic guardrails, determinism (per run since
  WP1d), solvability (optionally every evidence row) and (since WP1c) grading: perfect = 100, empty = 0.
- The builder accepts templates whose perfect answer scores below 100: must-not-miss outside the top k of `idealOrder`; ideal
  emergency + next-window over capacity; truth schedule later than `slaLatest`; more than 3 distinct required codes; mitigate
  without a `mitigation` list. `checkVulnGrading` catches each of these for every template, and `checkVulnStructure` rejects a
  false positive whose schedule is not `none` (WP1d). Since WP1f the builder itself rejects a case with no lesson finding, a real
  key finding without `slaLatest`, or no evidence point.
- Minor, from the last verifier (not blocking): `vectorProblem` does not know the product kind (an AV:L "scripting console" RCE on a
  web app passes; only background rows can show it, worklist rows must match `WORKLIST_SHAPES`); some appliance low-band shapes are
  local DoS ("certificate handler", AV:L); the "3 shapes per band" test counts across kinds; the twins' FS01 login-failure row and
  APP01 certificate row differ beyond FindingId (outside the worklist).
- Twins share their worklist rows (VulnId, host, CVSS, FirstSeen, DetectedVersion) and, since WP1f, their background rows (host,
  vulnerability, run) and row counts per table; FindingId, DetectedVersion, Evidence and FirstSeen/LastSeen of background rows
  still differ (the scan writer's rng is seeded by template id, WP1b), which no single session can see. Accepted.
- WP1f, minor (not blocking): the fact-checker's shape notes — rce 9.6 (UI:R, S:C) on plugin loader / scripting console fits
  scope change poorly; the sqli S:C shapes (9.6, 7.7, 6.4) assume the database is a separate authority; the auth-bypass and
  misconfig 6.1 shape (UI:R, S:C) is XSS-shaped on session handler / password reset / management interface; misconfig 7.3
  (C:L/I:L/A:L) on default credentials understates the usual impact. `vectorProblem` still does not know the product kind.
- WP1f, accepted by the pre-gate review (not defects under §5): each T3 twin alone passes a blanket policy that matches its own
  truth (nokev: SLA table + `low-exploitability`, 74.8; kev: emergency for everything, 75.6) — the pair catches it (each policy is
  gated on the other twin); dismissing a real non-key finding still passes when the rest is right (stale-scan's Critical 9.8,
  73.7: −26 points, not Sim-KEV listed, so not must-not-miss). WP2/WP3 authors: make every finding whose dismissal must fail a
  key finding. nokev's shotgun margin is the thinnest (S1 57 %); more decoys would widen it.
- WP1f hardening S4: the "two irrelevant pins" slip costs nothing because free pins = evidence points (≥ 2 in every template); the
  test asserts the two pins are irrelevant, so a template with one evidence point would exercise the penalty.
- WP1a re-review (minor, non-blocking): CVSS tests check little beyond the 18 oracle rows (15/15 environmental, temporal and parser
  mutants survive; add about 40 golden vectors); catalogue tests don't pin the Sim-EPSS anchor tables or `KEV_LEGACY`; `toMetrics`
  doesn't validate metric objects (NaN → "critical"); `fixedVersion` is set when `vendorFix` is false (the scan writer blanks it).
- Pre-existing SOC bug, on `main` too and not vuln-related: `ops-hunt-repo-exfil` fails to build for world `diff-world`, seed `d1`
  ("evidence 'volume' row in WebProxy fell outside the corpus window"); other seeds build. The SOC suite doesn't cover that pair.
- Parser bare-table `join` lacks tests for the error path and for a join with no `kind` (reviewer note, non-blocking).
- `scan-writer.ts` hygiene findings report their basis without honouring a failed login (cosmetic).
- `query/engine.ts` column-type map now also types new column names (`Port`, `Started`, …); only affects type labels on aliased SQL
  result columns, no conflicts found.
