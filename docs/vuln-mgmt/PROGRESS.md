# PROGRESS — Vulnerability Management

Branch: `feat/vuln-mgmt-wp6-wp7` (from `main` @ eadf4b6; WP1 merged via PRs #4, #6, #7, WP2–WP3 via PR #8, WP4–WP5 via PR #9,
human decisions of 2026-10-03 via PR #10).

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

- **WP2 — Content batch A** (2026-10-02). Six templates complete T1, T2, T4 and T5: `vm-backport-real` (T1-B, tier 2, 9
  findings; the sibling web server mirrors, so each twin keeps one false positive), `vm-fresh-scan` (T2-B, tier 1, 5; update
  installed before the scan, reboot pending), `vm-exposed-edge` / `vm-segmented` (T4, tier 1, 4; detect-only ACL and allowed
  internet sessions vs block-mode ACL with management-VLAN-only traffic, environmental 8.8 in the explanation),
  `vm-waf-covers` / `vm-waf-bypass` (T5, tier 2, 8; same WAF rule in block vs detect mode, template-local freeze-first calendar).
  Shared policy rows: severity class from the base score; compensating control (record `mitigate` naming the control, the
  permanent fix in the next window). Tests: `batch-a` (per pair: registration, title/difficulty/headline, §5.8 difference,
  clue present A vs B, lesson names its clue, identical pre-submit surface incl. hint 1 and row counts), `exposed-edge`, `waf`,
  updated `backport-fp`, `stale-scan`, `data-rules` (C4 mitigate rule, K5 exemptions); e2e: control picker with a non-empty
  ControlInventory (keyboard, gate, axe in both themes, 360/320 px) and the library tier test. Vendor renames (real companies).
  32 files / 971 tests (+11 opt-in), build ok, e2e 32/32. Hardening over 200 seeds: S1 max 69.4 (exposed-edge; others ≤ 66),
  S2 max 60 for every lesson finding, S3 100, S4 min ≥ 88. Process: brief checked by the fact-checker; four sequential authors;
  pre-gate review 2 rounds × 5 lenses with a skeptic per finding (41 → 31 kept, 7 blocking; 20 → 11 kept, 3 blocking), every
  author/implementer fix verified; coordinator fixes (policy recording sentence, renames, a wording fix); reviewer gate PASS
  (first attempt), fact-checker PASS.

- **WP3 — Content batch B** (2026-10-02). Ten templates: `vm-legacy-accept` / `vm-legacy-isolate` (T6, tier 1, 5 findings;
  approved exception with isolation in effect vs no exception and corporate sessions reaching the controller → mitigate behind
  the OT isolation ACL), `vm-noncred-low` / `vm-cred-high` (T7, tier 1, 5; banner guess disproved by a credentialed run vs
  confirmed by inventory where the credentialed login failed; mirrored look-alike hosts), `vm-saas-transfer` / `vm-self-hosted`
  (T8, tier 1, 5; vendor-operated service → transfer vs IT-managed install → patch), `vm-unused-service` / `vm-needed-service`
  (T11, tier 1, 5; unused default admin console → avoid vs one a business process uses → patch), and the first tier-3 cases
  `vm-dup-plugins` / `vm-distinct` (T10 with T9 inside, 16 findings, 2 runs, stale-vs-fresh conflict, capacity squeeze with the
  ideal fitting exactly; per-service detections of a fictional shared library are duplicates closed once vs bundled copies;
  payments Medium ahead of the developer-box Critical by the Asset tier row). Template-local policy rows; `pair-helpers.ts`
  (shared pair suite), `batch-b`, per-template tests, `data-rules` hooks; e2e: library tiers incl. Tier 3, a tier-3 case
  (keyboard reorder, axe both themes, 360/320 px), the avoid decision. 38 files / 1,353 tests (+21 opt-in), build ok, e2e
  34/34. Hardening (WP3 templates): S1 max 60.2, S2 60 for every lesson finding, S3 100, S4 min 87.7; WP2 numbers unchanged.
  Process: brief checked by the fact-checker (PASS-WITH-CHANGES, applied); T6 author, then a workflow of four sequential
  authors, e2e, 2 review rounds × 5 lenses with skeptics (37 → 24 kept, 5 blocking; 25 → 16 kept, 2 blocking), verified fixes;
  coordinator ruling on T10 key findings with a verified fix; reviewer gate PASS (first attempt), fact-checker PASS.

- **WP4 — Stats and study integration** (2026-10-02). Objective skill kind (2.1–2.5, 4.1; titles verbatim from DESIGN §1) and an
  explicit study pool: `nextStudyCase` / `studyPlan` take `pool` (default the SOC pool, so existing callers and tests behave as
  before; the UI passes SOC + vuln). Vuln attempts review their own SRS card (keyed by template id, each twin its own card) and join
  the study attempts; a study pick of a vuln case opens the right twin (`vulnSeedFor`, `studyRoute`). Study shows an objectives card.
  Stats gains a "Vulnerability management" section: domain 2.0 summary (cases, passed at 70+, average), objectives 2.1–2.5, a
  decision confusion matrix (right decision × your decision, diagonal marked in text) and the most common mix-up (only decisions
  without full credit; a wrong control is reported separately). Tests: `study` (appended; existing tests byte-identical),
  `profile`, `vuln-stats`, `study-route`, e2e stats/study (full axe rule set, both themes, 360/320 px). 40 files / 1,380 tests
  (+21 opt-in), build ok, e2e 40/40. SOC identity vs HEAD: 7,200 suggestions + 80 plans, 0 mismatches (implementer and reviewer
  probes). Process: brief with rulings R1–R8; implementer; pre-gate review 5 lenses with a skeptic per finding (10 → 7 kept, none
  blocking); fix round (F1–F8) verified independently incl. mutations; coordinator fix (off-diagonal wrong-control); reviewer gate
  PASS (first attempt).

- **WP5 — Continuity hook (vuln → SOC)** (2026-10-02). A real must-not-miss finding the grader counts as left open (dismissed,
  unscheduled or past its SLA) writes a ledger entry (`profile.vulnLedger`, cap 50), unless a verified control covers it, its host is
  case-local or it has no SIMVULN id. The next shift takes the oldest entry at start (`selectVulnFollowUp`, stored on the active
  shift, entry consumed) and gets exactly one extra alert, `endpoint-known-vuln-exploit` (`LINKED_TEMPLATES`, never picked at
  random). The rest of the shift is unchanged: hook built last, campaign history skips it. The alert fits the host: an internet-facing
  web server gets perimeter IPS hits, then C2 on 443 (T1190); the internal application server gets an internal unmanaged source,
  then a w3wp → cmd → PowerShell chain and beacons (T1210, T1190 accepted). The authorised scanner trips the same signature on the
  host and its peers, so a signature hit alone is not the answer. The debrief links back to the vuln case after submit.
  Tests: `vuln-continuity`, `scenarios/vuln-link` (template harness with and without a hook over real hooks; end-to-end shift
  properties; campaign equality), `shift`, `profile`, `campaign`, e2e (queue, reload, consumed entry, debrief link, axe both
  themes, 360 px). 42 files / 1,453 tests (+21 opt-in), build ok, e2e 43/43. SOC identity vs f7c380c with no hook: 84
  (implementer) + 90 (reviewer) plan/scenario comparisons, 0 differences; `ALL_TEMPLATES` unchanged. Process: brief checked by
  three critics (3 blocking design defects fixed before building); author and implementer in parallel; integration; pre-gate
  review 6 lenses with a skeptic per finding (16 → 11 kept, 2 blocking); fix rounds (engine B1–B4; template A1–A6, round 2
  A3b/A7–A9), each verified on 250–750 real-hook shifts; coordinator wording fixes; reviewer gate PASS (first attempt);
  fact-checker PASS-WITH-CHANGES (three wording hedges applied, reviewer delta sign-off).

- **WP6 — Polish** (2026-10-03).
  - **Help:** new section `#/help/vuln`, linked from the vuln library, the case brief, the debrief and Start, Tables and
    Grading. It holds a glossary:
    - scans: credentialed vs unauthenticated, backport, stale result, duplicate;
    - CVSS base vs environmental;
    - Sim-KEV and Sim-EPSS: the §3.1 text verbatim, with CISA and FIRST sources;
    - compensating control; the six decisions with avoid vs mitigate; schedules, SLA and freeze;
    - must-not-miss, lesson finding, urgency tier.
  - **Nav:** a **Vulns** item between Practice and Study.
  - **Debrief copy:**
    - the ordering percent shows one decimal, rounded down;
    - a closed duplicate is named as one;
    - the deduction wording matches the grader;
    - the cap is in the live-region announcement;
    - finding cards have headings;
    - the debrief survives leaving the page (sessionStorage).
  - **Library copy:** fixes in the vuln library text.
  - **Rubric:**
    - every template's keywords were retuned; the new vuln-only matcher `vulnRubricHits` matches whole words and drops
      possessives; SOC is unchanged;
    - dates are generated from the case's own calendar;
    - generic guards in `tests/vuln-scenarios/rubric.test.ts`: the model note ticks all four items, a content-free note at
      most one, the other twin's honest notes tick neither the risk nor the action item, no containment between twins, a date
      keyword needs a number.
  - **Template text:**
    - T8 says "non-intrusive read" and has no vendor scanning;
    - every briefing has the same six-decision list;
    - the kev risk text reads correctly.
  - **Version realism:** worklist flaws on different hosts get different products. Data-rules V1 checks it; it failed on HEAD
    for 8 templates. Data-rules H1 checks the hints (≥ 2 each, every named table exists).
  - **Totals:** 43 files / 1,754 tests (+21 opt-in), build ok, e2e 52/52.
  - **Proofs:**
    - vuln truths byte-identical to HEAD (400 cases);
    - hardening unchanged;
    - scores and components identical to HEAD's grader (3,200 + 3,840 submissions; reviewer 2,400); only `rubricHits` and
      so XP differ.
  - **SOC UI change (ADR-24),** deliberate and display only, no SOC score moves:
    - the shared header gains the nav item;
    - nav icons are hidden at 901–1140 px and the XP bar at 901–1000 px, so eight items fit without sideways scroll at any
      rank, with or without a live shift;
    - the open mobile menu is capped at the viewport height and scrolls;
    - Help gains the section, and its XP line says "handover or stakeholder note".
  - **Process:**
    - copy audit with skeptics: 36 → 22 kept;
    - parallel build (implementer + scenario-author) with a T8 fact-check (PASS-WITH-CHANGES, applied);
    - pre-gate review, 5 lenses with skeptics: 45 → 40 kept, 6 blocking;
    - fix rounds, each verified independently, then rubric rounds 4–5 ending in test guards;
    - fact-checker PASS; reviewer gate PASS (first attempt).

## In progress
- WP7 — Hardening (next in this session).

## Next
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

- 2026-10-02 (coordinator, before WP2): session start found PLAN, PROGRESS and repo in agreement (WP0–WP1f committed and merged
  to `main` via PR #7, bae599d; no WP2 file: no `batch-a.test.ts`, templates T3 ×2, `vm-stale-scan`, `vm-backport-fp` only). Local
  `main` was behind `origin/main` and was fast-forwarded; work goes on `feat/vuln-mgmt-wp2-wp3` (human: a separate branch, not
  `main`). Baseline 29 files / 729 tests (+5 opt-in), build ok. No open question was left for the coordinator. This session does
  WP2 and WP3 only. Rulings in the WP2 authoring brief (fact-checker PASS-WITH-CHANGES on the brief, all changes applied):
  1. **Compensating-control policy row** (shared `policyAttachments`): DESIGN §4's T4-B / T5-A "mitigate → patch next-window"
     cannot be derived from the written policy today (twins share FirstSeen, so the A side's emergency deadline binds the B side
     too). New row: a control that blocks the vulnerable path (ControlInventory, block mode, covering this vulnerability on this
     host; FirewallLogs or WAF logs confirm it) satisfies the deadline only while in effect and ends when the permanent fix is
     deployed; the fix goes in the next maintenance window; no vendor fix → risk exception. No existing template writes
     ControlInventory rows, so no existing truth changes (attachment text gains rows). Second row (fact-checker): the severity
     class comes from the CVSS base score in the scan store, so an environmental score cannot be read into the class table.
  2. **T4-B truth** `mitigate` with the verified ACL, next-window; `patch` is not in `alsoAccept` (A's emergency patch would be a
     one-step slip on B and pass, failing hardening S2). Headline not Sim-KEV-listed (a listing puts B on the 3-day clock); B's
     host is not internet-exposed (fact-checker: else the clues contradict). Environmental 8.8 (`MAV:A`) is explanation only.
  3. **T5 calendar**: "fix needs code release after freeze" + "patch next-window" is read as: in both twins the freeze comes
     before the next window, which is the first window after it (template-local calendar variant; the shared calendar and the
     other templates are unchanged). B uses WAF detect mode (provable in ControlInventory); `avoid` only if the data shows the
     feature can be switched off.
  4. Tiers: T4 tier 1, T5 tier 2, T1-B tier 2 and T2-B tier 1 (as their A sides). Objectives: T4 `2.3, 2.5, 4.1` (no 2.1:
     segmentation is taught as a control), T5 `2.3, 2.4, 2.5, 4.1`, B sides as their A sides. The fact-checker could not re-read
     the CS0-003 PDF to confirm "compensating control" under 2.5; DESIGN §1 records that mapping as verified on 2026-09-28
     (rule 8), so it is not a new NEEDS-HUMAN-CHECK.
  5. Outside WP2's list: the control-picker e2e test with a non-empty ControlInventory (WP1e follow-up tied to the first template
     that writes controls) is added by the implementer in `e2e/vuln.spec.ts`; logged in PLAN.
- 2026-10-02 (human, asked during WP2): **WP3 tier-3 scope.** PLAN says "2 tier-3 cases (T9, T10)" while DESIGN §4 lists T9 as one
  ordering case and T10 as a twin pair (3 cases). Decision: the 2 tier-3 cases are the T10 twin pair (`vm-dup-plugins` /
  `vm-distinct`, same title and headline, one clue differs), and both contain T9's ordering pattern (Critical on a dev box vs
  Medium on the payments database, payments first). No separate `vm-dev-crit` / `vm-prod-med` templates.
- WP2 pre-gate (coordinator rulings on the items the review left to the coordinator; workflow: 4 sequential authors, e2e,
  2 review rounds × 5 lenses with a skeptic per finding: round 1 41 findings / 31 kept (7 blocking), round 2 20 / 11 (3 blocking),
  all author/implementer-owned ones fixed and verified):
  1. "patch, next-window" on the vm-segmented / vm-waf-covers headline is capped at 60 (near miss on a lesson finding). Fair only
     if the policy says how to record a verified control: the compensating-control row now says to record the finding as
     `mitigate` naming the control, scheduled for the permanent fix's window (DESIGN §4 clarification). Kept the cap.
  2. **T1-B / T2-B mirror the sibling host** (WEBLX02 / FS02 become the B side's false positive): accepted (DESIGN §4
     clarification); each twin keeps one false positive and one real finding on the look-alike hosts, so neither twin is a
     "patch everything" case; `data-rules` K5 exempts exactly those hosts (`MIRROR_CLUE`), and the T4 exposure flag
     (`EXPOSURE_CLUE`).
  3. T4/T5 exposure and FirewallLogs "never change an answer" (red team, minor): by the written policy the control's mode and
     its log confirmation decide; exposure corroborates (`internet-exposed` required in A). Recorded, not changed.
  4. Vendor names: the fact-checker found real companies named "Quillon" and "Larkfield Software"; renamed (PLAN WP2 as built).
     The SOC registrar list (`src/core/synth/domains.ts:155`, "Quillon Domains") is SOC content and stays unchanged (Known issues).

- 2026-10-02 (coordinator, before WP3 authoring): brief checked by the fact-checker (PASS-WITH-CHANGES), applied: T10's
  duplicates are true positives "closed as duplicate" (decision `false-positive` + `duplicate-root-cause`, worded honestly,
  bundled copies checked first, services restarted), fictional library name; T8 sourced from a vendor advisory / non-intrusive
  fingerprint of org-owned hostnames, no testing of vendor systems, reserved tenant host; T9's asset-tier row moves the
  deadline one class (Medium on payment systems → High deadline; Critical on isolated non-production → High deadline), not the
  class. Declined: dropping 4.1 from T7/T11 (every template has a graded note, WP1d ruling) and adding 2.4 to T11 (DESIGN §1
  maps avoid / attack surface to 2.5). Ultracode was switched off mid-session, so WP3 runs as individual agents (same steps).

- WP3 pre-gate (workflow: T6 author alone, then T7, T8, T11, T10 authors in sequence with earlier handoffs, e2e, 2 review
  rounds × 5 lenses with a skeptic per finding: round 1 37 findings / 24 kept (5 blocking), round 2 25 / 16 (2 blocking); all
  author/implementer-owned ones fixed and verified). Coordinator rulings:
  1. **T10 key findings**: a probe (every template × 20 runs, one real finding dismissed alone, the rest perfect) showed T10's
     package-level root, second bundled copy, developer-box Critical and still-valid rollup High passing at 94–95. They are now
     lesson findings (7 of 16 per twin), named in the lesson texts; DESIGN §5.8 clarified for tier 3 (every finding the lesson
     names and every decider whose lone dismissal must fail, at most half the case); the hardening count bound follows it. They
     also gate a two-step over-reaction (an emergency change for these standard-cycle findings), which on the developer-box
     Critical is T9's misconception. Verified: each scores 60 when dismissed; hardening S1 ≤ 60, S2 60, S3 100, S4 ≥ 88.
  2. T6: the scanner-session timing regression was already fixed in the tree (a test now covers 41 seeds); the "ticket alone"
     pitfall is scoped to this exception; objectives gain 2.1 (both explanations teach an OT scanning consideration; DESIGN §1).
  3. T7, T8, T11, T10 as-built deviations from DESIGN §4 / the brief are accepted and recorded in DESIGN §4 ("Clarified
     2026-10-02 (WP3)"): T7's internal sweep and inventory-plus-failed-login confirmation (ids kept), T8's clue in DeviceInfo
     plus Tickets, T11's scheduled `avoid`, T10's mixed design (only the headline flips).

- 2026-10-02 (coordinator, before WP4): session start found PLAN, PROGRESS and repo in agreement (WP0–WP3 committed and merged
  to `main` via PR #8, 78c9078; no WP4/WP5 file); `main` clean and in sync with origin; work goes on `feat/vuln-mgmt-wp4-wp5`.
  Baseline 38 files / 1,353 tests (+21 opt-in), build ok. No open question was left for the coordinator. This session does WP4
  and WP5 only. WP4 rulings (acceptance readings, no human input needed):
  1. **Study pool is an option, default SOC.** Acceptance 3 ("existing study tests unchanged") is read literally: those tests call
     the SOC `templateById` on every suggestion and expect `plan.total = ALL_TEMPLATES.length`, so a vuln id in the default pool
     would crash them. The UI passes the full pool everywhere (Study, Home, the SOC study "next case"), so vuln cases are in the
     learner's study pool as DESIGN §8 says; with the SOC pool, suggestions are identical to HEAD (probed).
  2. **Objective accuracy = share of passed cases** (70+), with the average score beside it; objectives are tagged per template,
     not per finding, so a decision accuracy per objective does not exist. 4.1 is a study skill but not a Stats row (every vuln case
     carries it; it would repeat the 2.0 summary).
  3. **The SOC disposition streak stays SOC-only** ("consecutive right calls" on alerts; a vuln pass is not a disposition); the
     study day streak counts vuln days (it counts days studied). SOC Stats sections keep reading SOC attempts only.
  4. **The confusion matrix counts every decided finding**; the mix-up sentence counts only decisions without full credit (an
     answer the case also accepts is not a mix-up; a mitigate with a non-covering control is reported as a control problem). Each
     recorded decision now stores the grader's `verdict` (additive; old records fall back to "off the diagonal = mix-up").

- WP5 (coordinator): the brief's first draft was checked by three critics (engine, template, DESIGN conformance) before any
  code. Changes they forced:
  - the hook item is built last: the builder's shared rng otherwise moved the campaign alert's attacker IPs;
  - campaign history skips the hook case;
  - host and vulnId reach `recordVulnAttempt` through the resolved findings: the corpus lives in the worker;
  - case-local hosts are excluded: no noise baseline possible without changing other alerts;
  - the trigger is the grader's own left-open set, minus findings a verified control covers. A mitigate truth followed by an
    exploitation alert would teach that controls don't matter;
  - entry ids are unique per attempt;
  - consumption is a pure `startShift` transition, and the hook is persisted on the active shift for reload;
  - the session key includes the hook;
  - coercion validates `activeShift.vulnHook`;
  - a world move clears the ledger.
  Recorded in DESIGN §8 ("Clarified 2026-10-02 (WP5)").
- WP5 acceptance (4) reading: campaign state is deep-equal with and without the hook except the alert-number labels in the log entry
  and intel notes (A-numbers name each alert's position in that shift's queue; numbering the hook out of time order would mark
  it as special).
- WP5 template ATT&CK: T1190 fits only internet-facing hosts; the internal variant (exploited from an internal address) is T1210
  Exploitation of Remote Services (lateral-movement), added to the taxonomy, with T1190 accepted. The harness's tactics equality
  check becomes "non-empty subset" for linked templates only (the template's tactics are the union of both variants).
- WP5 process note: in fix round 1 the scenario-author declined the two assigned files (its definition limits it to the vuln
  template area) although it had written them under PLAN's assignment in round 0; it accepted again when the prompt quoted
  PLAN WP5. If a later package assigns SOC-side content, quote that line.

- 2026-10-03 (human, after WP4–WP5 were merged via PR #9): two decisions, applied the same day on
  `chore/vuln-mgmt-decisions-2026-10-03`, without starting WP6.
  1. **SOC content and output may change when that raises the overall product's quality** (ADR-24; CLAUDE.md guardrail
     replaced). Such changes must be deliberate, reviewer-checked and logged here with the reason. A change that moves existing
     SOC scores must say so.
     - First use: `ops-authorized-pentest` (`src/core/cases/templates/ops.ts`). Four strings claimed that no other source
       touched the public web app: the external evidence label, the 'Anything from other sources?' step, the 'sources' rubric
       text and explanation paragraph 2.
     - They now say what is always true: the engagement covers its two named sources; any other source is outside it, normally
       background, and one that attacks gets its own alert and its own triage. That is also the better lesson.
     - Truth, evidence rows, indicators, hints and rubric keywords are unchanged, so SOC scores do not move. Only those case
       texts changed.
     - Fixes the WP5 known issue (a WEB01 hook in the same shift contradicted the case).
     - The other SOC items in Known issues (the "Quillon" registrar, attacker-role domains) are no longer blocked on a human
       decision. They are left for a package.
  2. **scenario-author scope** (ADR-25): `.claude/agents/scenario-author.md` and CLAUDE.md now let it write files a package
     assigns to it by path. Model and effort are unchanged.
  Reviewer check: FAIL once, because `.claude/agents/reviewer.md` and DESIGN §10 still stated the old rule. Both were updated, and
  a pentest sentence ("raises its own alert") that sat against the case's "attacker hiding in the noise" warning was reworded.
  Pentest grades vs `main`: 84 grades (3 worlds × 4 seeds × 7 verdicts), 0 differences.

- 2026-10-03 (coordinator, before WP6): session start found PLAN, PROGRESS and repo in agreement (WP0–WP5 merged via PR #9,
  the human decisions via PR #10, `main` @ eadf4b6; no WP6/WP7 file). `main` was clean and in sync with origin. Work goes on
  `feat/vuln-mgmt-wp6-wp7`. Baseline 42 files / 1,453 tests (+21 opt-in), build ok. The one discrepancy was this file's header,
  which still named the merged WP4–WP5 branch (fixed). This session does WP6 and WP7 only. Ultracode is on, so each stage runs as a
  workflow: an audit of hints, rubric and UI copy with one skeptic per audit (36 findings, 22 confirmed) and fact probes.
  Open items PROGRESS left to the coordinator for WP6, resolved:
  1. **Nav item** (WP1e: "WP6 decides"): add **Vulns** → `#/vuln`, between Practice and Study. Reason: the mode is a peer of
     Practice and Shift. Today only the Home card leads to it, so a keyboard user on any other screen has no direct route.
  2. **Ordering percent** (WP1c): **one decimal, still rounded down**, so §5.6's sort-by-CVSS reads 69.7 % (nDCG 0.6978). Reason: the copy
     audit found the whole percent disagreeing with the points beside it (14/20 next to 69 %). One decimal agrees with the points
     to within rounding and still never claims 100 % for a non-ideal order. Display only; scores are unchanged.
  3. **Tier skew** (WP3: "WP6 may promote pairs"): **no promotion.** Tiers are size classes (§2.3: 4–6, 8–12, ≥ 15 findings).
     Relabelling a pair without resizing it would misstate its difficulty. Resizing is new content, with new hardening and
     fact-check work, so it is not polish. Future work.
  4. **T8 "scan" → "version read"** (fact-checker, WP3): **reword** the vendor-operated-service policy row and the prose that
     relies on it. The new rule: no scanning or testing of a vendor platform; the only check on a vendor-hosted tenant is reading
     the version that the org's own hostname shows. Truths unchanged.
  5. **T10 closed duplicates shown as plain "False positive"** (WP3): the decision code and its label stay, because the grader,
     Stats and the e2e tests are keyed on them. Instead:
     - the false-positive option gloss names the three ways to close a row: not affected, already fixed, a duplicate;
     - the debrief calls a closed duplicate a duplicate;
     - Help explains it;
     - Transfer gets a gloss too.
  6. **"Query this finding in the console"** (WP1e candidate): **declined.** It is not in WP6's goal or DESIGN §7. One more
     control on every worklist row adds screen-reader verbosity and 360 px density, and the console's examples already show the
     query. Future work.
  7. **Version realism** (WP2/WP3: "WP6/WP7"): **fixed in WP6** by the scenario-author.
     - The problem: a host sits below another worklist flaw's fixed version on the same product, without that finding.
     - Probe over 200 seeds: 5 template pairs show it (seeds affected: backport 42, waf 49, noncred/cred 33, legacy 15,
       exposed-edge 13); none elsewhere.
     - Version strings alone cannot fix it: VulnIntel holds only a fixed-in version.
     - So worklist flaws on different hosts get different products unless the data explains the gap. No truth changes; a
       data-rules test guards it.
  WP6 acceptance readings. The criteria are thin as written ("Help reachable by keyboard; every template has ≥ 2 hints; reviewer
  PASS"), so they are flagged here, not guessed silently:
  1. **Help reachable by keyboard.**
     - A Help section for the mode (`#/help/vuln`) holds the glossary.
     - Tab + Enter reaches it from the vuln library, the case screen, the debrief and the nav (keyboard-only e2e).
     - axe is clean on it (full rule set, both themes), with no horizontal scroll at 360/320 px.
  2. **Hints.**
     - Every template ≥ 2 hints is already true (3 each); it stays a test.
     - Also tested: twins share hint 1 (exists), and every table a hint names exists.
     - The ladder audit found no blocking defect: hint 1 is shared and neutral in all 10 pairs. Later hints may stay
       twin-specific (WP1f).
  3. **Debrief copy.** The confirmed copy findings are fixed. They are display only, so a probe must show every vuln score and
     component identical before and after.
  4. **Rubric tuning.** Superseded by ruling I16 (WP6 pre-gate entry below): the vuln grade uses the word-boundary `vulnRubricHits`; the SOC
     `detectRubricHits` (substring) is unchanged. Only vuln keywords and the vuln matcher change, so vuln XP can move only
     through `rubricHits`. Per template:
     - a model note ticks all four items;
     - a content-free note (generic verbs and risk words; no host, team, product, date or schedule term) ticks at most one;
     - the other twin's model note misses this twin's action item;
     - the right date alone, in ISO form, ticks the date item.
     Today the content-free note ticks owner and date in 20/20.
  5. **Glossary content.**
     - Terms: the goal's terms, plus must-not-miss, urgency tier, lesson finding, duplicate, stale result, and CVSS base vs
       environmental.
     - The Sim-KEV and Sim-EPSS explainers are quoted verbatim from §3.1, with the real names and their sources.
     - Fact-checker PASS on the glossary and on the T8 wording.

- WP6 pre-gate (workflow: fact-checker on the built copy, PASS-WITH-CHANGES, applied; 5 review lenses with a skeptic per lens:
  45 findings, 40 kept, 6 blocking, many duplicated across lenses; fix rounds, each checked by an independent verifier).
  Coordinator rulings:
  - **I1, debrief kept across navigation** (blocking: the new Help link on the debrief threw the debrief away, as any nav link
    already did). Not a new tab: the debrief is stored in sessionStorage (`vdone:` per slug + seed + template, validated
    against the stored score) and shown whenever the same case URL opens again in that tab, so Back, a reload and the WP5
    continuity link from the SOC alert debrief land on the finished debrief. The attempt is never recorded twice; "Work it
    again" clears it.
  - **I16, vuln rubric matcher** (the substring matcher cannot keep 'oct 3' from matching 'oct 31'). Vuln notes are matched by
    `vulnRubricHits` (`src/core/vuln/grade.ts`), SOC keeps `detectRubricHits` unchanged:
    - both sides are lowercased; a possessive ('s or ’s at a word end) is dropped first, so 'app01 console' matches "APP01's
      console" ("it's" becomes "it", "its" is unchanged);
    - every run of non-[a-z0-9] becomes one space; the note is trimmed and padded with a space at each end;
    - a keyword keeps its edge spaces to demand a word boundary; one with no letter or digit never matches; an empty note
      hits nothing.
    Vuln scores and components are identical to before (3,840 random submissions vs HEAD's grader); only `rubricHits`
    (+3 XP each) can move vuln XP.
  - **"passive read" → "non-intrusive read"** (T8): CS0-003 2.1 calls scanning passive only when no traffic is sent; one
    ordinary request to our own hostname is active but non-intrusive (fact-checker PASS). The external run that reads the
    hosted aliases now lasts 1–10 minutes instead of 45–180 (same draw count; truths and evidence unchanged).
  - **Negations** ("not acceptable", "no sign that…") are a limitation of keyword coaching (ADR-3: the rubric gives coaching
    and XP only); cheap traps were avoided, no more.
  - **Rubric rounds stop at test guards.** Each round's fresh honest notes found new cross-ticks, so round 4 turned the
    classes into generic guards (pair cross-tick with honest variants, a containment guard with an empty exception list,
    dates must contain a number). Round 5 closed the last action-item leaks a verifier found with fresh notes.

## Known issues
- WP5 (not blocking): (fixed 2026-10-03, ADR-24: the authorised-pentest case no longer claims that no other attacker exists, so
  a WEB01 hook in the same shift no longer contradicts it). The hook's routine-client sessions can come from a laptop that
  another alert in the shift treats as a foothold (seen once in 756 shifts: one extra row in that case's query). The hook alert
  is always a true positive with no twin (ADR-14 v1). Additive effects on other cases' queries (an extra Change ticket, extra
  svc-scan logons, a one-off scan ticket next to the twin's standing approval) leave their answer keys true. A must-not-miss
  finding left with no decision writes no ledger entry (the submit gate asks for every decision, so it cannot happen in the app).
  CHG-STD-0007's own window can run past 18:00 although it says "business hours" (`network.ts`, pre-existing SOC content).
  The e2e link test runs the WCAG-tag axe; the reviewer's full-rule check was clean.
- WP4 (not blocking): at 360 px the Stats tables (objectives, matrix, SOC "By category") scroll sideways inside their focusable
  regions now that the bars have a width (the page itself does not scroll); the Study page's own e2e runs the WCAG-tag axe only
  (the reviewer's full-rule probe was clean); every existing vuln attempt recorded before WP4 has no card until the case is
  worked again.
- WP3 gate notes (not blocking): the avoid e2e test has no axe or 360 px pass (UI unchanged); `common.ts` classes the T10
  library product as 'server' in `PRODUCT_KINDS`; the T8 K5 exemption strips 5 DeviceInfo columns of the headline host; T8's
  passive version read of a vendor-hosted tenant is defensible, but some SaaS terms forbid any scanning, so WP6 may reword
  "scan" to "version read" (fact-checker; done in WP6: "non-intrusive read"); "Halbrenn" is one letter off a small UK firm (kept); the case library is skewed
  toward tier 1 (7 case types; tier 2: 2; tier 3: 1), WP6 may promote pairs (WP6 decided not to:
  tiers are size classes).
- WP3 (pre-gate, not blocking): dismissing one real non-key finding alone still passes in every template (probe, 20 runs):
  decoys 75–86 (T3 dev box, T4/T5 detect-only decoys, T6 expired-exception and detect-only decoys, T8 contract and second
  hosted service, T11 second console and console-in-use), padding about 89–97. WP1f accepted this; WP7 should decide whether
  lesson-named decoys become key findings at tiers 1–2 or a separate "must not dismiss" flag is worth a grader change. The
  generic UI and Help label T10's closed duplicates as plain "False positive" (fixed in WP6: gloss, debrief, Help). WP2
  templates can show one worklist product below another worklist flaw's fixed version on another host (about 57 of 200 seeds
  for backport-fp, scenario-author note): realism, WP6/WP7 (fixed in WP6: data-rules V1). Some T6 decider points also accept shared ScanRuns/ticket rows. The
  e2e tier-3 and avoid tests find their twin through `resolveVulnTemplate` and assert it from the data; a new template in either
  case type can change the pick (fails visibly). Hardening S4's "one step earlier" slip can land on a closed duplicate.
- WP2, minor (reviewer / pre-gate, not blocking): `vm-exposed-edge` shotgun S1 max is 69.4 (structural: the same over 200
  seeds; the naive emergency patch is right on A's headline, and the twin `vm-segmented` holds it to 47.9) — any reweight or new
  finding there needs a decoy to keep the margin; `data-rules` K5 exempts whole SoftwareInventory/PatchHistory rows of the two
  mirrored hosts (batch-a pins the specifics); the vuln-worklist assertion "every registered case type is a twin pair" must
  change if a single-template type is registered; `VulnDebrief.tsx:245` could guard the "Missed" codes line when enough codes
  matched (no template triggers it); T4's hint 2 names the three clue tables.
- SOC registrar list `src/core/synth/domains.ts:155` contains "Quillon Domains"; "Quillon" is a real company (fact-checker,
  2026-10-02). Since 2026-10-03 (ADR-24) the coordinator may rename it; not done yet (candidate for WP6/WP7).
- SOC attacker-role domains do not meet DESIGN §9 rule 10 (checked 2026-10-02, reported, SOC output unchanged as the human asked):
  every one comes from `attackerDomain()` (`src/core/synth/domains.ts:120-142`; random labels under real TLDs: `SUSPICIOUS_TLDS`
  .top/.xyz/… at :80, `GENERIC_TLDS` .com/.net/.org/.io/… at :81, lookalike `.com/.net/.co`), called by `src/core/cases/infra.ts:83`
  and `src/core/logs/noise/email.ts:81,91`. In 300 practice builds (25 templates × 3 worlds × 4 seeds): 132 distinct truth domains
  and 4,020 logged ones, none reserved. No template hard-codes an attacker domain, and none is rendered as a link. Fixing it changes
  every SOC case's generated domains; since 2026-10-03 (ADR-24) that is the coordinator's call, not a human decision. Not done yet
  (candidate for WP7, with a SOC test like the vuln one).
- Vuln domain test, minor (reviewer, 2026-10-02): its bare-token file-extension list includes real TLDs (`.zip`, `.sh`, `.py`, `.md`,
  `.so`), so a bare token such as `c2.zip` would pass; URL and e-mail hosts are checked without it, and no such token occurs today.
- WP1e follow-ups: (Stats and study include vuln attempts since WP4); (the control-picker e2e with a non-empty ControlInventory landed in WP2);
  the query engine still knows the six vuln tables in SOC
  sessions (empty results, a did-you-mean could name one); a "Query this finding in the console" button was dropped (WP6
  declined it: future work); devtools on one's own profile shows the template id of an earlier attempt of the same seed; SQL mode has no
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
