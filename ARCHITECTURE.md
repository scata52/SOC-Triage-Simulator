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
    rng.ts                    seeded PRNG (mulberry32/xmur3) — carried over from v1
    types.ts                  shared domain types
    taxonomy/                 mitre.ts, cysa.ts (carried over, extended)
    synth/                    the synthetic-data policy: address pools, domain
                              generators, names, geo registry, fictitious orgs
    world/                    World: org, sites, people, hosts, service accounts,
                              apps, network, VPN — generated once per profile
    logs/
      schema.ts               every SIEM table: columns, types, descriptions
      corpus.ts               CorpusBuilder: typed row emitters, record ids, finalise
      noise/                  baseline activity per source, with deliberate decoys
    query/
      kql/                    lexer, parser (Pratt), transpiler → SQLite SQL
      sql-guard.ts            read-only enforcement for SQL mode
      functions.ts            JS UDFs registered into SQLite (has, regex, …)
      engine.ts               sql.js wrapper: build DB from corpus, run, schema
    cases/
      model.ts                CaseTemplate v2, CaseContext, CaseSpec
      context.ts              builds a CaseContext (picker, infra, emitter, clock)
      generate.ts             template + seed + world → Case (spec + corpus)
      templates/              identity, email, endpoint, network, impact, ops
    grading/                  grade.ts (verdict, evidence, indicators), ioc.ts
    study/                    srs.ts (SM-2), scheduler.ts (due + weakness)
    shift/                    plan.ts (compose), score.ts (prioritisation, SLA)
    campaign/                 actors.ts, campaign.ts (stages, consequences)
  state/                      profile v2 (localStorage), v1 → v2 migration
  ui/                         Preact app
    app.tsx, router.ts, store/ (signals), components/, screens/, sound.ts
    workers/query.worker.ts   hosts sql.js
  styles/                     tokens, base, components, screens
tests/                        vitest
e2e/                          playwright + axe
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
  id, category, difficulty, title, cysaDomains, twin?, stage?,
  build(ctx) {
    const user = ctx.victim.person({ dept: 'Finance' });   // campaign-aware
    const c2 = ctx.infra.domain('c2');                      // campaign-aware
    const hit = ctx.log.process({ ... });                   // → RowRef
    return {
      alert:   { rule, product, severity, time, summary, entities, fields },
      briefing, attachments?,                               // e.g. rendered email
      truth:   { disposition, severity, action, techniques, tactics },
      evidence: [{ id, label, rows: [hit, ...] }],          // pin any row → point
      indicators: { report: [...], scope: [...], mustNot: [...] },
      investigation: { hints: [...], solution: [{ title, kql, why }] },
      rubric, explanation, pitfalls, references,            // carried from v1
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

- **Worker** owns the sql.js database. The main thread sends the corpus once,
  then queries. A query exceeding the time budget terminates the worker; the
  client respawns it and reloads the (deterministic) corpus.
- **KQL subset** (documented in-app on the Help screen): `where`, `project`,
  `project-away`, `project-rename`, `extend`, `summarize … by` (count, countif,
  dcount, sum, avg, min, max, make_set, make_list), `sort/order by`, `take/limit`,
  `top N by`, `distinct`, `count`, `search`, `serialize`, `render`; operators
  `== != =~ !~ < <= > >= contains has startswith endswith matches regex in in~
  between`, with negations; functions `ago now bin datetime tolower toupper
  strlen substring strcat isempty isnotempty iff case tostring toint
  datetime_diff hourofday extract prev next`. Parsed with a Pratt parser into
  an AST, type-checked against the schema (with did-you-mean suggestions), and
  compiled to nested SQLite `SELECT`s. The generated SQL is viewable — a
  deliberate bridge between the two languages.
- **SQL mode** accepts a single read-only `SELECT`/`WITH` statement.
- Results render in an accessible table with column sort, cell actions
  (filter to / exclude / add as indicator / search everywhere / copy) and
  per-row pinning whenever `RecordId` is present (the transpiler carries it
  through row-preserving operators).

## 8. Grading

100 points: **disposition 30, severity 10, action 10, ATT&CK 15,
evidence 20, indicators 15**.

- Partial-credit rules from v1 carry over (severity ±1, adjacent action,
  parent technique, benign twins penalise tagged techniques).
- **Evidence**: each evidence point is satisfied by pinning any of its rows.
  Hints reduce the evidence component progressively.
- **Indicators**: recall/precision over malicious indicators to block, recall
  over scope (affected users/hosts), and a heavy penalty for anything on the
  case's `mustNot` list — flagging your own VPN egress as malicious is the
  mistake that takes 400 remote workers offline.
- Notes rubric remains a coaching checklist and XP bonus.

## 9. Shifts, campaign, study

- **Shift**: 6–9 alerts land together — typically one campaign stage, zero or
  one other true positive, benign twins, and fast "ops" noise. All share one
  corpus (the noise of one alert is the background of another). A real-time
  budget (20/30/45 min or untimed) runs; verdicts are graded at handover.
  Shift score = severity-weighted case scores plus **prioritisation**: how
  early the real incidents were handled relative to the ideal order.
- **Campaign**: a fictional actor walks a kill-chain playbook (initial access
  → execution → persistence/C2 → discovery/lateral → objective), one stage per
  shift, reusing its infrastructure and victims. Your verdicts have
  consequences: catch a stage and IR contains it (the actor rotates
  infrastructure and pivots victims; your extracted indicators land in
  `ThreatIntel`); miss it and the actor progresses on the same foothold. Every
  prior incident appears in `IncidentHistory` with the verdict you gave. The
  campaign ends with eviction or with its objective.
- **Study**: SM-2 cards per template (quality from score), a scheduler that
  serves due cards first and weights new picks toward the weakest CySA+
  domains and ATT&CK tactics, and a study-plan screen.

## 10. Testing and CI

- `npm run typecheck` — tsc over app, tests and e2e.
- `npm test` — Vitest: RNG, world determinism, **synthetic-data guardrails**
  (every address in every generated corpus is in the allowed ranges; org
  domains are on the fictitious list), KQL lexer/parser/transpiler, SQL guard,
  grading, SRS, shift composition and scoring, campaign progression, profile
  migration, and the **scenario suite** (every template × many seeds: builds,
  deterministic, perfect answer scores 100, reference investigation finds the
  evidence against a real sql.js database).
- `npm run test:e2e` — Playwright: practice case end-to-end (query, pin,
  indicator, verdict, debrief), a shift, keyboard-only flow, mobile viewport
  (no horizontal scroll), and axe-core scans of every screen.
- CI runs `check` (typecheck, test, build) and `e2e` jobs on every push/PR.

## 11. Deliberately not in this iteration

- **Backend** (sync, leaderboards). Export/import covers the single-user case.
  If added later it would be one optional Cloudflare Worker + D1, never
  required.
- **EN/DE rendering.** Worth doing, but it doubles every content change while
  the content model is still settling. UI strings and case prose are kept
  separate from logic so this can follow.
- **Threat-intel content pipeline** (e.g. CISA KEV shapes). A later build-time
  script; the template model already accommodates it.

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

Every step keeps `typecheck`, tests and build green. The v1 engine and UI keep
working alongside the new core until step 12 swaps them.
