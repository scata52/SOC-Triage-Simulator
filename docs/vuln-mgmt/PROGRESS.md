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

## In progress
- WP1c — Grader.

## Next
- WP1d — Slice content: 4 templates incl. twin T3
- WP1e — UI slice + accessibility (slice exit review)
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

## Known issues
- SOC sessions now list six empty vuln tables in the schema browser, Help schema and editor autocomplete (they come from `TABLES`).
  Scheduled in WP1e (PLAN.md acceptance 9); README.md ("18 tables", lines 46 and 156) gets the new count with WP1e (coordinator).
- `tests/helpers/vuln-scenario-check.ts` covers build, structure, corpus integrity, synthetic guardrails, determinism and solvability;
  the grading checks (perfect = 100, empty = 0) join it in WP1c/WP1d.
- Parser bare-table `join` lacks tests for the error path and for a join with no `kind` (reviewer note, non-blocking).
- `scan-writer.ts` hygiene findings report their basis without honouring a failed login (cosmetic).
- `query/engine.ts` column-type map now also types new column names (`Port`, `Started`, …); only affects type labels on aliased SQL
  result columns, no conflicts found.
