# AS-BUILT — SOC Triage Simulator (state on 2026-09-28, before Vulnerability Management)

Read from the code, not from older briefs. `ARCHITECTURE.md` is broadly accurate
(it was the v2 plan and the code follows it); differences are noted below.

## Stack
- Vite 8 + TypeScript ~6 (strict, erasable syntax only: union types, no enums).
- UI: Preact 10 + `@preact/signals`, TSX. CodeMirror 6 editor (lazy-loaded).
- Query engine: sql.js (SQLite WASM) inside a Web Worker (`src/ui/workers/siem.worker.ts`).
- Fonts bundled via `@fontsource` (IBM Plex Sans/Mono). No runtime CDN.
- Static site: hash routing, service worker `public/sw.js`, PWA manifest. No backend.
- Node >= 22.12. Tests: Vitest; Playwright + `@axe-core/playwright` for e2e/a11y.

## Folder layout
```
src/core/            pure logic, no DOM
  rng.ts             seeded RNG (determinism is load-bearing)
  types.ts           Disposition, Severity, TriageAction, Tactic, Category, GroundTruth, RubricItem
  taxonomy/          cysa.ts (4 CS0-003 domains, ids '1.0'..'4.0'), mitre.ts
  synth/             synthetic names, orgs (MS fictitious companies), RFC 5737 addresses, domains, software
  world/             generateWorld(seed): people, hosts (criticality, exposed, managed), sites, VPN egress
  logs/              schema.ts (tables+columns docs), corpus.ts (single row writer, RowRef), noise/
  query/             engine.ts (sql.js wrapper), kql/ (lexer, Pratt parser, transpiler, reference), sql-guard.ts, udf.ts
  cases/             model.ts (CaseTemplate/CaseSpec), picker.ts, infra.ts, scenario.ts (buildScenario), templates/
  grading/           grade.ts (100-pt case grade), indicators.ts (normalising matcher)
  shift/             plan.ts (queue composition), score.ts (80% cases + 20% nDCG prioritisation)
  campaign/          campaign.ts (fictional actor, stages, ThreatIntel/IncidentHistory feedback)
  study/             srs.ts (SM-2), scheduler.ts (weak-skill weighted selection by domain/tactic/category)
src/state/           profile.ts (Profile v2, attempts, XP, ranks, v1 migration), storage.ts (localStorage, tolerant)
src/ui/              App.tsx, router.ts, screens/ (Home, Library, CaseScreen, Shift, Study, Intel, Stats, Help, Settings),
                     components/ (Workspace, Editor, Results, Debrief, TechniquePicker, Panels, Tools, ui), lib/, styles/ (tokens.css + 3)
tests/               10 unit suites + tests/scenarios/*.test.ts (one per template file) + helpers/ (scenario-check, guardrails, sql)
e2e/app.spec.ts      Playwright + axe
.claude/agents/      code-reviewer, guardrail-auditor, scenario-reviewer (read-only reviewers, no `model:` set)
```

## Data model (core)
- `World` (seeded): people, `Host {name, ip, kind, os, role, criticality: Low|Medium|High|Critical, owner, siteId, deviceId, exposed, managed}`, service accounts, VPN egress, partners. `WORLD_VERSION = 1`.
- Corpus: ~17 Sentinel/Defender-style tables (logs + context: `DeviceInfo`, `Tickets`, `ThreatIntel`, `DomainIntel`, `IncidentHistory`, ...). `DeviceInfo` already carries Role, Owner, Criticality, IsManaged, ExposedToInternet, OSPlatform.
- Every row has a random `RecordId`; signal rows are known only via `RowRef` handles held by the case spec.
- **No vulnerability, scan, CVE, patch or software-version tables exist.** "Vulnerability" appears only as the authorised-scanner benign twin in `templates/network.ts`.

## Case / template format (`src/core/cases/model.ts`)
- `CaseTemplate {id, category, difficulty tier1-3, title (neutral), lesson, cysaDomains, tactics, kind: incident|benign|ops, twin?, stages?, when?, build(ctx)}`.
- `build(ctx: CaseContext)` emits rows via `ctx.log` and returns `CaseSpec {alert, briefing, attachments?, truth: GroundTruth, evidence[] (RowRef-backed), indicators {block, scope, mustNot}, hints, solution (runnable KQL), rubric, explanation, pitfalls, references}`.
- Templates registered in `templates/index.ts` (`ALL_TEMPLATES`, `CATEGORY_LABELS`). 8 files, grouped by category.
- `Category` union is SOC-only (phishing, identity, malware, ...). `GroundTruth` is SOC-shaped (disposition/severity/action/techniques).

## Grading (`src/core/grading/grade.ts`)
- 100 points: disposition 30, severity 10, action 10, ATT&CK 15, evidence 20, indicators 15.
- Ordinal partial credit (one step off = half). Hints cost 20% of evidence each. 4 free extra pins, then penalties.
- Indicators: coverage + false-flag penalties + `mustNot` penalty (−5).
- Notes rubric: `detectRubricHits` keyword match → coaching + XP bonus, not points.
- `DIFFICULTY_MULTIPLIER` tier1 1 / tier2 1.5 / tier3 2 for XP. `perfectVerdict(c)` used by tests (must score 100).
- Shift prioritisation: nDCG of handling order vs. true urgency (`shift/score.ts`). Reusable for vuln ordering.

## Query console / SQL layer
- KQL subset → SQLite transpiler; raw SQL mode guarded read-only (`sql-guard.ts`, `query_only`).
- Worker builds the scenario from a spec (world seed + case or shift) and owns the DB; 15 s budget, respawn on timeout.
- Schema docs + autocomplete come from `logs/schema.ts`. Adding a table = schema entry + corpus writer + noise.

## Persistence
- `localStorage` via `state/storage.ts` (tolerates blocked storage). Profile `version: 2` with `coerceProfile` and v1 migration.
- `AttemptRecord` keyed `${templateId}~${seed}`; stores components (keyed by grade `ComponentId`), category, difficulty, tactics.
- XP total + `RANKS` / `rankFor(xp)`; SM-2 `cards` per template; shift records; campaign state; export/import.

## Org / continuity
- Persistent world per profile (`worldSeed`). Campaign: actor progresses one stage per shift; your verdicts feed `IncidentHistory`, reported indicators feed `ThreatIntel`; templates receive `foothold` + infra presets.
- Continuity is keyed on **campaign stages**, not on arbitrary prior cases. There is no hook for "state from a non-shift case changes a later corpus". A vuln→exploit hook needs a new, small profile field.

## i18n
- None. English only. UI and case prose kept separate from logic (ARCHITECTURE §11 defers EN/DE).

## Tests + CI
- `npm run typecheck` (app + node configs), `npm test` (Vitest, 16 files / 233 tests on this date), `npm run build` (typecheck + vite build), `npm run test:e2e`.
- Guardrail tests: all corpus addresses in RFC 5737/1918/2001:db8, org names on the fictitious list.
- Scenario suite: every template × many seeds builds deterministically, `perfectVerdict` = 100, empty verdict = 0, reference KQL finds the evidence against real sql.js.
- CI `.github/workflows/ci.yml`: job `check` (typecheck, test, build) + job `e2e` (Playwright chromium + axe). `deploy.yml` manual Pages deploy.
- Verified locally on this date: typecheck clean, 233/233 tests pass, build succeeds.

## Fragile / unfinished
- `Category`, `GroundTruth`, `ComponentId` and `AttemptRecord.components` are SOC-shaped unions; widening them touches stats, study and profile coercion — do it additively.
- `CYSA_DOMAINS` has domain-level ids only; no objective-level (2.1-2.5) taxonomy exists.
- Profile has no per-mode separation; adding a mode must not break `coerceProfile` (bump only if shape changes incompatibly).
- Route union in `ui/router.ts` is closed; new screens need both `parse` and `href` entries.
- Existing agents have no `model:` frontmatter (inherit).
- No network egress to CISA/NVD/FIRST from this build environment (proxy rejected `www.cisa.gov`), so real vuln data cannot be pulled here.
- No CLAUDE.md existed before this workstream.
