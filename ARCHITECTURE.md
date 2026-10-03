# Architecture — SOC Triage Simulator v2

This document is the plan for taking the simulator from "read curated evidence,
pick answers" to "investigate a live log corpus on shift, inside an organisation
that remembers". It was written before any files moved; the commit history
follows the migration order at the bottom.

## 1. What the product is

You are an analyst in the SOC of a fictional organisation. A queue of alerts is
waiting. Each alert is backed by a **SIEM you can actually query** — thousands
of synthetic log rows across a dozen tables, most of them irrelevant, exactly
like the real thing. You write KQL (or SQL) to pivot from the alert's entities,
pin the rows that prove your call, extract indicators, and file a verdict. The
answer key then shows what you found, what you missed, and how a senior analyst
would have run the investigation — as runnable queries.

Across sessions the organisation persists. A fictional threat actor works
through a campaign against it; the phishing domain you (hopefully) extracted
last shift is in your threat-intel table this shift, and the incident you
wrongly closed as benign is sitting in the incident history for a sharper
analyst to notice. What you practise next is chosen by spaced repetition,
weighted toward your weakest CySA+ domains and ATT&CK tactics.

The pedagogical core of v1 survives and deepens:

| v1 | v2 |
|---|---|
| Evidence pre-selected into 2–3 blocks | Evidence must be **found** in a noisy corpus; decoys that resemble every signal are deliberately present |
| Twins differ in a context line you are handed | Twins differ in context you must **look up** (change tickets, VPN egress, device compliance, asset roles) |
| Notes keyword-matched | Notes rubric kept as coaching, plus **graded evidence pins** and **indicator extraction** |
| One card at a time | **Shifts**: 6–9 alerts, mostly noise, on a clock; prioritisation is graded |
| Stateless cases | **Persistent world + campaign** with consequences across shifts |
| "Avoid last 6 templates" | **SM-2 spaced repetition**, weighted by weak domains/tactics |

## 2. Guiding constraints

- **Static-first.** The full experience runs from a static build (GitHub Pages
  or any file host) with no backend and no account. After first load it works
  offline (service worker). No CDN at runtime: WASM, fonts and editor are
  bundled.
- **Synthetic by construction** (enforced by tests, see §9):
  - External IPv4 addresses come only from the RFC 5737 documentation ranges
    (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), IPv6 from
    `2001:db8::/32`, internal from RFC 1918. Attacker, user, SaaS and scanner
    addresses are drawn from the *same* pools, so the range carries no signal.
  - The victim organisation is always one of Microsoft's documentation-reserved
    fictitious companies (Contoso, Fabrikam, Northwind Traders, …) — realistic,
    and owned for exactly this purpose.
  - Attacker domains are generated labels (look-alikes of the fictional org,
    DGA-style strings, lure words plus random tokens); threat actors have
    invented names; ASNs are private-use (RFC 6996); hashes are random.
  - Real products (Entra ID, Defender, Sysmon) and real benign services
    (github.com, zoom.us) appear only as the environment, never as bad actors.
- **Accessible.** Keyboard-complete, screen-reader labelled, usable at 360 px
  wide, `prefers-reduced-motion` respected, sound off by default.
- **Deterministic.** Every case, shift and corpus regenerates exactly from
  seeds. This is what makes "Case of the Day", replay, and exhaustive testing
  possible.

## 3. Stack

| Concern | Choice | Why |
|---|---|---|
| Build | Vite 8 + TypeScript (strict, erasable syntax) | Existing; fast |
| UI | **Preact + @preact/signals** (TSX) | The investigation workspace is stateful (editor, results, pins, timers). Vanilla `h()` was fine for forms; it isn't for this. Preact is ~4 kB and keeps the zero-framework spirit. |
| Query engine | **sql.js** (SQLite → WASM) in a **Web Worker** | Real SQL for free; worker keeps the UI responsive and lets a runaway query be killed (terminate + rebuild — the corpus is deterministic) |
| Query language | **KQL subset → SQL transpiler** (hand-written) + raw SQL mode | KQL is what Sentinel/Defender analysts actually write; SQL is universal. Both teach. |
| Editor | **CodeMirror 6** (bundled) | Syntax highlighting, schema-aware autocomplete, accessible |
| Fonts | IBM Plex Sans + Plex Mono via `@fontsource` (bundled) | Technical, terminal-adjacent identity; works offline |
| Tests | **Vitest** (unit + scenario suite), **Playwright + axe-core** (e2e + a11y) | Scenario suite runs every template's reference investigation against a real sql.js database |

No backend in this iteration. Cross-device sync is served by profile
export/import; a backend would be the one additive option later (§11).

## 4. Module layout

```
src/
  core/                       pure TypeScript — no DOM; runs in browser, worker and Node
    rng.ts                    seeded PRNG (xmur3 + mulberry32) with stable forks
    types.ts                  shared domain types
    taxonomy/                 mitre.ts, cysa.ts
    synth/                    the synthetic-data policy: address pools, domain
                              generators, names, geo registry, fictitious orgs,
                              encodings (Base64/UTF-16LE, Base32, entropy)
    world/                    World: org, sites, people, hosts, service accounts,
                              apps, network, VPN — generated once per profile
    logs/
      schema.ts               every SIEM table: columns, types, descriptions
      corpus.ts               CorpusBuilder: typed row emitters, record ids, finalise
      noise/                  baseline activity per source, with deliberate decoys
    query/
      kql/                    lexer, parser (Pratt), transpiler → SQLite, reference
      sql-guard.ts            read-only enforcement for SQL mode
      udf.ts                  JS functions registered into SQLite (has, regex, …)
      engine.ts               sql.js wrapper: load corpus, run, look up rows
    cases/
      model.ts                CaseTemplate v2, CaseContext, CaseSpec
      picker.ts, infra.ts     people/hosts from the world; attacker infrastructure
      scenario.ts             world + seed + items → corpus + resolved cases
      templates/              identity, email, endpoint, network, impact, ops
    grading/                  grade.ts (verdict, evidence, indicators), indicators.ts
    study/                    srs.ts (SM-2), scheduler.ts (due + weakness)
    shift/                    plan.ts (compose), score.ts (prioritisation),
                              vuln-hook.ts (vuln → SOC continuity, §13)
    campaign/                 actors.ts, campaign.ts (stages, consequences)
    vuln/                     vulnerability-management mode (§13): model, cvss31,
                              catalogue, coherence, scan-writer, scenario, grade,
                              worklist, registry, templates/
  state/                      profile v2 (pure transitions), storage, v1 migration,
                              vuln-stats.ts
  ui/                         Preact app
    App.tsx, router.ts, main.tsx
    store/app.ts              profile signal + persistence, settings, toasts
    lib/                      SIEM worker client and protocol, alert types, format, sound
    workers/siem.worker.ts    builds the scenario and hosts it in sql.js
    components/               workspace, editor, results, tools, panels, debrief, ui
    screens/                  home, library, case, shift + handover, intel, study,
                              stats, help, settings; vuln library, case, debrief
    styles/                   tokens, base, components, screens
public/                       service worker, web manifest, icon
tests/                        Vitest
e2e/                          Playwright + axe
```

`core/` never imports from `ui/` or `state/`. Everything that decides a grade
is in `core/` and covered by tests.

## 5. The world and the log corpus

### World

`generateWorld(seed)` produces a persistent organisation (stored as its seed):
~60–90 people across departments (finance, sales, engineering, HR, IT,
helpdesk, executive) with managers, titles, sites, primary devices and home
networks; workstations and servers with roles and criticality (domain
controllers, file servers, SCCM, vulnerability scanner, RDP jump host, VPN
concentrator); service accounts with owners; SaaS apps; office NAT and VPN
egress addresses; and a synthetic GeoIP/ASN registry for every external
address. Case of the Day uses a fixed public world seed so everyone gets the
same case.

### Tables

Names and columns follow Microsoft Sentinel / Defender conventions so the KQL
transfers to real work.

| Table | Kind | Carries |
|---|---|---|
| `SigninLogs` | log | Entra ID sign-ins: app, client, IP, geo, result codes, MFA detail, device, compliance, risk |
| `AuditLogs` | log | Directory + M365 audit: inbox rules, MFA registration, role changes, consent |
| `SecurityEvent` | log | Windows Security: 4624/4625/4634/4740/4698/4728/7045… |
| `DeviceProcessEvents` | log | EDR process creation with parent, command line, hash, signer |
| `DeviceNetworkEvents` | log | EDR connections by process |
| `DeviceFileEvents` | log | EDR file create/modify/rename |
| `EmailEvents` | log | Gateway: sender, auth results, verdicts (initial vs latest), URLs, attachments, user reports |
| `WebProxy` | log | Proxy: user, URL, method, status, bytes, category, action |
| `DnsEvents` | log | Resolver: client, query name, type, response, registered domain |
| `FirewallLogs` | log | Perimeter + east-west: 5-tuple, action, rule, bytes, direction |
| `IdentityInfo` | context | HR/AD: department, title, manager, employment status, groups, MFA method |
| `DeviceInfo` | context | CMDB: role, owner, criticality, exposure, IP |
| `NamedLocations` | context | Office NAT, VPN egress — "is this IP ours?" |
| `Tickets` | context | Change, service, travel, HR tickets — the twin-decider more often than not |
| `ThreatIntel` | context | Feed + **your own team's prior findings** (campaign) |
| `DomainIntel` | context | WHOIS/reputation: registration date, age, registrar, category |
| `IncidentHistory` | context | Prior incidents in this org, **with the verdicts you gave** |

A practice case spans ~20 hours ending shortly after the alert: typically
6–12k rows, weighted by a diurnal curve so off-hours activity stands out.

### Noise budget and decoys

Noise generators produce baseline activity *and* benign look-alikes of every
signal a template can emit: encoded PowerShell from the management agent,
`PSEXESVC` installed by SCCM under change control, `7z.exe` used by engineers,
legitimately-named scheduled tasks, benign inbox rules, fat-finger 4625s,
internet background IMAP/RDP noise against the perimeter, sales staff on the
VPN egress in another city. A query like `where ProcessCommandLine has "-enc"`
therefore returns several rows, and the analyst has to discriminate on parent,
host role, account and ticket — which is the skill.

### Record identity

Every row has a `RecordId` (random, table-agnostic). Signal rows are tracked
**outside** the database by the case spec; nothing queryable distinguishes
signal from noise.

## 6. Cases (template v2)

A template is still a generator, but it now *emits log rows* instead of
pre-rendered text blocks:

```ts
const template: CaseTemplate = {
  id, category, difficulty,
  title,            // neutral — shown before the case is solved; twins share it
  lesson,           // what it turned out to be — debrief and stats only
  cysaDomains, tactics, kind, twin?, stages?, when?,
  build(ctx) {
    const user = ctx.foothold?.personId ? ctx.idx.person(ctx.foothold.personId)
                                        : ctx.pick.person({ dept: 'Finance' });
    const c2 = ctx.infra.domain('c2');                      // campaign-aware
    const hit = ctx.log.proc({ ... });                      // → RowRef
    return {
      alert:   { rule, product, severity, time, summary, entities, fields },
      briefing, attachments?,                               // e.g. rendered email
      truth:   { disposition, severity, action, techniques, tactics, alsoAccept? },
      evidence: [{ id, label, why, rows: [hit, ...] }],     // pin any row → point
      indicators: { block: [...], scope: [...], mustNot: [...] },
      hints: [...],
      solution: [{ title, kql, why, expectEmpty? }],        // reference investigation
      rubric, explanation, pitfalls, references,
    };
  },
};
```

Alerts say what a detection would say — not the deciding fact. The deciding
context lives in the corpus and context tables. All 21 v1 scenarios are ported
with their explanations, pitfalls and rubrics intact; new templates add
nuance v1 couldn't express (true positive but already remediated → close;
the company's own phishing simulation; an authorised pentest).

Each template ships a **reference investigation** (`solution`) — KQL that a
senior analyst would run. The scenario test suite executes every solution
against a real sql.js database for many seeds and asserts it surfaces the
evidence rows and indicators. That guarantees every case is solvable through
the console, and the same queries become the debrief ("how it should have
been worked") and the hint ladder.

## 7. Query engine

- **Worker** builds the scenario from its spec (world seed + case or shift)
  and owns the sql.js database, so the corpus never crosses to the main
  thread. A query exceeding the time budget (15 s) terminates the worker; the
  client respawns it and reopens the last session — deterministic from its
  spec — before the next request.
- **KQL subset**, documented in-app from `kql/reference.ts` (whose every
  example is executed by the tests): `let`, `search`, `where`, `project`,
  `project-away/-rename/-reorder`, `extend`, `summarize … by` with ~15
  aggregates (incl. `arg_max`, `make_set`, `stdev`), `sort/order by`,
  `take/limit`, `top`, `distinct`, `count`, `join` (inner, leftouter,
  leftanti, leftsemi), `serialize`, `getschema`, `render`; comparison and
  string operators with negations and case-sensitive variants; ~40 scalar
  functions. Parsed with a Pratt parser, checked against the schema (with
  did-you-mean suggestions), compiled to nested SQLite `SELECT`s. The
  generated SQL is viewable under the results — a bridge between the two
  languages.
- **SQL mode** accepts a single read-only `SELECT`/`WITH` statement; SQLite
  itself runs with `query_only`.
- Results render in an accessible table with column sort, a row inspector
  whose values can be filtered on, excluded, searched everywhere, reported as
  indicators or copied, and per-row pinning whenever `RecordId` is present (the
  transpiler carries it, hidden, through row-preserving operators).

## 8. Grading

100 points: **disposition 30, severity 10, action 10, ATT&CK 15,
evidence 20, indicators 15**.

- Partial-credit rules from v1 carry over (severity ±1, adjacent action,
  parent technique, benign twins penalise tagged techniques).
- **Evidence**: each evidence point is satisfied by pinning any of its rows.
  Hints reduce the evidence component progressively.
- **Indicators**: coverage of the indicators to block (10) and of the
  affected users/hosts (5), matched however the analyst writes them
  (defanged, URL, `DOMAIN\user`, FQDN); −2 per indicator the evidence does
  not support (up to −6) and −5 for anything on the case's `mustNot` list —
  flagging your own VPN egress as malicious is the mistake that takes 400
  remote workers offline. Nothing to report + nothing reported = full marks.
- The scenario harness asserts that every template's reference verdict scores
  exactly 100 and an untouched alert 0.
- Notes rubric remains a coaching checklist and XP bonus.

## 9. Shifts, campaign, study

- **Shift** (`core/shift`): the late-shift analyst sits down at 17:30 local and
  inherits the day's queue plus whatever fired overnight — 6–9 alerts in one
  corpus (the noise of one is the background of another): one to three real
  incidents (the campaign's move when a campaign runs), usually their benign
  twins (same rule, same title), routine ops tickets, and benign alerts.
  Threat hunts stay out of the queue. A real-time budget (20/30/45 min or
  untimed) runs; unworked alerts score zero at handover. Shift score = 80%
  severity-weighted case scores + 20% **prioritisation** (nDCG of the
  handling order against the true urgency of each alert).
- **Campaign** (`core/campaign`): a fictional actor (invented names, avoiding
  real vendors' naming schemes) walks a kill-chain playbook, one stage per
  shift, on the same victim, laptop and infrastructure (templates receive
  them through `foothold` and infra presets). Consequences:
  escalate a stage as a true positive → IR contains it, the actor is
  identified, pivots to a new victim and starts over; after `tenacity`
  containments it is **evicted**. Miss it — or flag it without escalating —
  and it moves to the next stage; missing the objective is a **breach**.
  Reported block indicators land in `ThreatIntel` (attributed once the actor
  is identified) and are burned; unreported infrastructure is reused. Every
  verdict of every shift appears in `IncidentHistory` as analyst "You".
- **Study** (`core/study`): SM-2 cards per template (quality from the grade,
  70% pass mark); due reviews first, then new/early cases drawn with weights
  exponential in the analyst's weakness across the CySA+ domains, ATT&CK
  tactics (benign cases train their twin's) and category each case trains;
  tier-2/3 cases are gated for brand-new analysts.

## 10. Testing and CI

- `npm run typecheck` — tsc over app, tests and e2e.
- `npm test` — Vitest: RNG, world determinism, **synthetic-data guardrails**
  (every address in every generated corpus is in the allowed ranges; org
  domains are on the fictitious list), KQL lexer/parser/transpiler, SQL guard,
  grading, SRS, shift composition and scoring, campaign progression, profile
  migration, and the **scenario suite** (every template × many seeds: builds,
  deterministic, perfect answer scores 100, reference investigation finds the
  evidence against a real sql.js database).
- `npm run test:e2e` — Playwright against the production build: practice
  case end-to-end (query errors, pin, row inspector, indicators, verdict,
  debrief with runnable reference steps), column sort and runaway-query
  recovery, a full shift with resume and handover, keyboard access, 360 px
  viewport, reduced motion, v1 migration, blocked storage, offline play, and
  axe-core scans of every screen in both themes.
- Vulnerability-management tests are listed in §13.
- CI runs `check` (typecheck, test, build) and `e2e` jobs on pull requests and
  pushes to `main`. Deploying to Pages is a manual workflow.

## 11. Deliberately not in this iteration

- **Backend** (sync, leaderboards). Export/import covers the single-user case.
  If added later it would be one optional Cloudflare Worker + D1, never
  required.
- **EN/DE rendering.** Worth doing, but it doubles every content change while
  the content model is still settling. UI strings and case prose are kept
  separate from logic so this can follow.
- **Threat-intel content pipeline** (e.g. CISA KEV shapes). The
  vulnerability-management mode (§13) deliberately ships no real-vulnerability
  data: its feeds are simulated and calibrated once against aggregate public
  statistics (docs/vuln-mgmt/DESIGN.md §11, PLAN ADR-13).

## 12. Migration order (one commit or small group each)

1. This document.
2. Tooling: Preact, Vitest, sql.js, CodeMirror, fonts; v1 smoke test moves to
   Vitest unchanged.
3. `core/synth` + `core/world` with guardrail tests.
4. `core/logs`: schema, corpus builder, noise generators with decoys.
5. `core/query`: KQL transpiler, SQL guard, sql.js engine, tests.
6. `core/cases` v2 model; port identity templates.
7. Port email and endpoint templates.
8. Port network and impact templates; new ops/nuance templates.
9. Grading v2.
10. Study, shift and campaign engines.
11. Profile v2 with v1 migration.
12. New UI shell and design system (replaces v1 UI; v1 engine removed).
13. Investigation workspace.
14. Debrief screen.
15. Shift board and handover report.
16. Intel/campaign board, study plan, stats, help.
17. Polish: sound, shortcuts, offline.
18. E2E + accessibility tests; CI.
19. README and screenshots.

Every step keeps `typecheck`, tests and build green. The v1 engine and UI kept
working alongside the new core until step 12 swapped them.

**Status:** all steps are done. Deviations from the plan above are folded
into the sections: the worker builds the corpus itself (§7); shifts are the
late shift inheriting the day's queue (§9); indicator scoring is coverage plus
penalties rather than precision/recall (§8); offline support precaches from a
list the build writes (`precache.json`), since the build manifest omits the
worker and WebAssembly.

## 13. Vulnerability-management mode

Added 2026-09-28 → 2026-10-03 as a separate workstream; design, plan with its
decision log (ADR-1 onward), and execution record live in
[`docs/vuln-mgmt/`](docs/vuln-mgmt/) (`DESIGN.md`, `PLAN.md`, `PROGRESS.md`;
`AS-BUILT.md` is the baseline before it and the delta after it).

- **A sibling template type.** `VulnTemplate` (`core/vuln/model.ts`) sits beside
  `CaseTemplate`: SOC verdicts and vuln decisions are graded differently, but
  both share the world, the corpus builder, the worker and the console. Cases
  come as twin pairs: same title and headline finding, one clue that flips the
  answer.
- **Data.** Six context tables are appended after the SOC tables in
  `logs/schema.ts`: `VulnFindings`, `ScanRuns`, `VulnIntel`,
  `SoftwareInventory`, `PatchHistory`, `ControlInventory` (SOC sessions hide
  them). `catalogue.ts` generates a fictional catalogue per seed: `SIMVULN-`
  ids, fictional products, CVSS 3.1 vectors scored by `cvss31.ts` (pinned to
  FIRST oracle rows), and the simulated Sim-KEV / Sim-EPSS feeds;
  `coherence.ts` keeps each vulnerability class consistent with its vector.
  `scan-writer.ts` enforces how scanners see a host: banner versions without
  credentials, package versions with them, failed logins, external scope.
- **Builder.** `buildVulnScenario` (`vuln/scenario.ts`) derives the case date
  and catalogue from (world seed, seed) only, so twins pair, and rejects specs
  the grader could not score fairly (tiers, lesson finding, SLA limits,
  evidence).
- **Grading** (`vuln/grade.ts`, 100 points): decisions 40 (near-miss matrix),
  ordering 20 (urgency tiers, nDCG, must-not-miss in the top places), schedule
  10 (SLA-aware), reasons 15 (penalties for unneeded and contradicting codes),
  evidence 15 (the shared pin scoring). A missed key finding caps the case at
  60. The stakeholder note is coaching and XP only, matched by
  `vulnRubricHits` (word boundaries; the SOC matcher is unchanged).
- **UI.** `#/vuln` (library with tier filter), `#/vuln/<slug>/<seed>` (brief,
  worklist as a table or cards, console, note, debrief), `#/help/vuln`, and a
  Vulns nav item; pure worklist helpers live in `vuln/worklist.ts`.
- **Integration.** Vuln attempts join the shared profile and XP, the study
  pool (CySA+ objectives 2.1–2.5 and 4.1 as skills) and Stats (domain 2.0,
  objectives, decision confusion matrix: `state/vuln-stats.ts`). A
  must-not-miss finding left open writes a ledger entry; the next shift gets
  exactly one extra alert (`endpoint-known-vuln-exploit`, outside the random
  pool), built after every other item so the rest of the shift is unchanged
  (`shift/vuln-hook.ts`).
- **Tests.** `vuln-cvss`, `vuln-catalogue`, `vuln-corpus`, `vuln-grading`,
  `vuln-guardrails` (no CVE id in scenario data; domain rules), `vuln-hardening`
  (strategy bounds: naive answers and lesson misses fail, ideal and minor slips
  pass), `vuln-worklist`, `vuln-stats`, `vuln-continuity`,
  `scenarios/vuln-link`, and `vuln-scenarios/` (per template, the twin-pair
  suite, data rules, rubric); `e2e/vuln.spec.ts` and the accessibility sweep
  `e2e/vuln-a11y.spec.ts`.
