# DESIGN — Vulnerability Management mode

Status: design only. Builds on `docs/vuln-mgmt/AS-BUILT.md`. Decisions carry a one-line reason.
Work breakdown: `docs/vuln-mgmt/PLAN.md`. Items marked **NEEDS-HUMAN-CHECK** must be verified by a person.

## 0. One-paragraph pitch
The analyst opens a **vuln case**: a scan export for part of the same persistent fictional org, plus
asset inventory, patch history, change windows, SLA policy and a threat-intel feed. They must decide,
per finding, **patch / mitigate / accept / transfer / false positive**, order the work, fit it into the
change calendar, cite the rows that justify each call, and write a short stakeholder note. The answer key
explains why. Twins share the same headline finding and score but flip the right decision on context.

## 1. Learning goals → CS0-003 objectives
Domain 2.0 Vulnerability Management (22% of the exam per CompTIA's published weighting — **NEEDS-HUMAN-CHECK**).
Objective titles below are from memory of the public CS0-003 objectives PDF (version not confirmed) and were **not** fetched
(no network in the design environment) — **NEEDS-HUMAN-CHECK** wording and numbering against the official PDF.

| Obj | Title (paraphrased) | Goals in this mode | Where trained |
|---|---|---|---|
| 2.1 | Implement vulnerability scanning methods and concepts | credentialed vs non-credentialed; agent vs agentless; internal vs external; active vs passive; scan scope/segmentation; stale scans; asset discovery gaps | ScanRuns metadata, twins T1, T2, T7 |
| 2.2 | Analyze output from vulnerability assessment tools | read scanner rows; spot false positives (backported patch, version banner mismatch); dedupe plugins; tool families (network scanner, web app scanner, cloud posture, SCA) | Findings table, evidence pins, twins T1, T2, T8 |
| 2.3 | Analyze data to prioritize vulnerabilities | CVSS base vs environmental (CIA requirements, modified metrics); exploitability signals (known-exploited listing, exploit probability, public PoC); asset value, exposure, zero-day handling | Ordering score, twins T3–T6 |
| 2.4 | Recommend controls to mitigate attacks and software vulnerabilities | map finding class → control (e.g., injection → input validation/WAF; broken auth → MFA; misconfig → hardening baseline) | Mitigation picker, rubric |
| 2.5 | Explain concepts related to vulnerability response, handling, and management | compensating controls; control types; patching and configuration management; maintenance windows; exceptions/risk acceptance; risk transfer; SLAs; inhibitors to remediation (legacy, business process interruption, MOUs/SLAs, degraded functionality, proprietary systems) | Scheduling score, accept/transfer decisions, twins T4, T5, T6 |
| 4.1 (secondary) | Vulnerability management reporting and communication | stakeholder note, metrics (SLA breach, MTTR), action plans, inhibitors | Stakeholder note rubric |

Tagging: vuln templates set `cysaDomains: ['2.0']` (+ `'4.0'` when the note is graded) and a new
`objectives: string[]` field (`'2.1'..'2.5'`, `'4.1'`) used by stats and study. Reason: study scheduler
already weights by domain; objective-level tags give finer weak-skill targeting without breaking it.

## 2. Scenario model

### 2.1 What a vuln case is
```
VulnCase = {
  scope:     assets in scope (subset of World hosts + a few scenario-only hosts)
  scans:     ScanRun[]  (tool, method: credentialed|unauthenticated|agent, vantage: internal|external, started, coverage)
  findings:  Finding[]  (vulnId, asset, port/service, detectedVersion, evidence text, firstSeen, lastSeen, scanRunId, status)
  intel:     VulnIntel[] per vulnId (cvss vector+base, known-exploited flag+date-added, exploit probability, public exploit, vendor fix)
  context:   DeviceInfo (criticality, exposure, owner), SoftwareInventory, PatchHistory, Tickets (change windows, exceptions),
             ControlInventory (WAF rules, segmentation, EDR, MFA) and the org SLA policy
  constraints: change windows (dates), freeze periods, SLA per severity class, team capacity (slots per window)
  task:      decide per finding, order, schedule, cite, write note
}
```

### 2.2 Relation to the existing template format — decision
**New sibling type `VulnTemplate` in `src/core/vuln/`, reusing the world, RNG, synth, corpus builder, query
worker, picker and SRS; not a variant of `CaseTemplate`.** Reason: `CaseSpec.truth` is SOC-shaped
(disposition/ATT&CK) and the grader is 100 points over those components; forcing vuln truth into it would
either break the "perfect = 100" invariant or add meaningless components. Sharing lower layers keeps one world,
one corpus, one console.

```ts
interface VulnTemplate {
  id: string;                 // 'vm-<slug>'; namespace prevents collisions with SOC ids
  difficulty: Difficulty; title: string; lesson: string;
  cysaDomains: string[]; objectives: string[];
  twin?: string; kind: 'vuln';
  build(ctx: VulnContext): VulnCaseSpec;       // VulnContext = CaseContext + ctx.vuln (VulnCatalogue, ScanWriter)
}
interface VulnCaseSpec {
  briefing: string; attachments?: Attachment[];
  findings: FindingSpec[];    // each: findingId, row: RowRef, truth: FindingTruth, weight, mustNotMiss?, evidence: EvidenceSpec[]
  constraints: { windows: Window[]; slaDays: Record<SlaClass, number>; capacityPerWindow: number };
  idealOrder: string[];       // findingIds, most urgent first (ties allowed via `tiers: string[][]`)
  hints: string[]; solution: SolutionStep[];   // runnable KQL, same harness as SOC
  rubric: RubricItem[];       // stakeholder-note coaching (keywords), as today
  explanation: string[]; pitfalls: string[]; references: CaseReference[];
}
type VulnDecision = 'patch' | 'mitigate' | 'accept' | 'transfer' | 'false-positive';
interface FindingTruth {
  decision: VulnDecision; alsoAccept?: VulnDecision[];
  schedule: 'emergency' | 'next-window' | 'standard-cycle' | 'none';
  reasons: ReasonCode[];      // required justification codes (see §5.4)
  mitigation?: ControlId[];   // acceptable controls when decision = mitigate
}
```
Seeded generation as today: `buildVulnScenario({worldSeed, templateId, seed})` → deterministic spec + corpus.

### 2.3 Case sizes
Tier 1: 4–6 findings, 1 twin-decider. Tier 2: 8–12 findings, 2 deciders + noise. Tier 3: 15–25 findings across
2 scan runs, conflicting evidence (stale vs fresh scan), capacity squeeze. Reason: ordering only teaches with > 4 items;
> 25 becomes clerical.

## 3. Skills trained (each has ≥1 template and ≥1 twin, see §4)
1. **Reading scanner output**: credentialed vs unauthenticated confidence; banner-based version guesses; backported
   fixes (distro package version ≠ upstream version) → false positive; stale results (asset patched after scan per
   PatchHistory); duplicate plugins for one root cause; "potential" vs "confirmed" findings.
2. **CVSS base vs environmental**: read vectors; apply Confidentiality/Integrity/Availability requirements and modified
   attack vector (e.g., AV:N → effectively adjacent behind segmentation). The app shows base; the analyst derives context.
3. **Exploit likelihood**: known-exploited listing (fictional catalogue "SKEV"), exploit-probability score (fictional "XPS",
   EPSS-style 0–1 with percentile), public exploit / exploit-kit availability, vendor advisory "exploited in the wild".
4. **Asset criticality and exposure**: `DeviceInfo.Criticality`, `ExposedToInternet`, data classification, blast radius
   (domain controller, jump host, CI runner with secrets).
5. **Compensating controls**: WAF virtual patch, segmentation ACL, feature disabled via config, EDR prevention rule,
   MFA in front of the service — and whether the control actually covers the attack path (verify in ControlInventory +
   FirewallLogs).
6. **Remediation choice and sequencing**: five decisions; SLA per class; change windows and freezes; emergency change
   justification; capacity limits; dependencies (patch the library before the app restart; reboot groups).
7. **Communicating the decision**: short stakeholder note (owner, risk, action, date, exception expiry) graded by rubric.

## 4. Twin catalogue
Each pair: same `title`, same headline finding and base score; one clue differs. Ids are proposed template slugs.

| # | Pair (A / B) | Shared headline | Deciding clue (where) | A decision | B decision | Misconception exposed |
|---|---|---|---|---|---|---|
| T1 | `vm-backport-fp` / `vm-backport-real` | Critical 9.8 on Linux web server, unauthenticated scan | PatchHistory/SoftwareInventory show distro package with backported fix vs upstream vulnerable build compiled from source | false-positive | patch (emergency if exposed) | "Scanner said critical, so it is" |
| T2 | `vm-stale-scan` / `vm-fresh-scan` | High finding on file server, 21 days old | PatchHistory: KB installed after ScanRun.started (A) vs installed-but-pending-reboot, service still loads old DLL (B) | false-positive (stale; request rescan) | patch (schedule reboot) | "Installed = fixed"; ignoring scan timestamps |
| T3 | `vm-kev-internal` / `vm-nokev-internal` | CVSS 7.5 on internal app server | VulnIntel: on SKEV list + public exploit (A) vs XPS 0.4% no exploit (B) | patch, emergency | patch, standard-cycle | CVSS alone sets urgency |
| T4 | `vm-exposed-edge` / `vm-segmented` | CVSS 9.8 RCE on management interface | DeviceInfo exposed + FirewallLogs show internet hits (A) vs ControlInventory: interface on isolated mgmt VLAN, ACL verified in FirewallLogs (B) | patch, emergency | mitigate (already) → patch next-window | Base score = environmental score |
| T5 | `vm-waf-covers` / `vm-waf-bypass` | SQL injection in public web app, fix needs code release after freeze | WAF rule covers the vulnerable parameter (A) vs WAF in detect-only mode / endpoint not routed through WAF (B) | mitigate (virtual patch) + patch next-window | emergency change (patch/disable feature) | "We have a WAF" ≠ covered |
| T6 | `vm-legacy-accept` / `vm-legacy-isolate` | Unsupported OS on lab/OT controller, vendor won't patch | Tickets: approved, time-boxed risk exception with owner and isolation in place (A) vs no exception and host reachable from corp VLAN (B) | accept (verify expiry) | mitigate (segment) + raise exception | "Can't patch → nothing to do" |
| T7 | `vm-noncred-low` / `vm-cred-high` | Same host, same vuln family, different severity reported | ScanRuns: unauthenticated external scan saw banner only (A, informational) vs credentialed agent confirms vulnerable version (B) | false-positive for version guess → schedule credentialed rescan | patch | Trusting method-blind output; not knowing credentialed scans find more |
| T8 | `vm-saas-transfer` / `vm-self-hosted` | Critical vuln in a third-party ticketing product | SoftwareInventory/Contracts: vendor-hosted SaaS, vendor SLA/contract covers patching (A) vs self-hosted instance (B) | transfer (track vendor, verify) | patch | Every finding is ours to patch |
| T9 | `vm-dev-crit` / `vm-prod-med` | Two findings: Critical on a dev box, Medium on the payments DB | DeviceInfo criticality, data class, exposure | ordering: payments first | (same case, ordering twin) | Sort by severity column |
| T10 | `vm-dup-plugins` / `vm-distinct` | 6 findings on one host | same root cause (one OpenSSL-like library, one patch) vs six unrelated issues | patch once, 5 duplicates marked false-positive(dup) → decision "patch" on root, others `duplicate` reason | handle separately | Counting findings instead of fixes |

T1–T8 satisfy the "≥ 8 pairs" requirement; T9–T10 are ordering/triage twins for tier 2–3.
WP1 slice uses **T3** (cleanest signal, exercises the intel table and scheduling).

## 5. Grading model (100 points per vuln case)
Decision: **new grader `gradeVulnCase` in `src/core/vuln/grade.ts`**, reusing the ordinal-partial-credit helper,
evidence pin scoring (any row satisfies a point), hint penalty, `DIFFICULTY_MULTIPLIER`, and the shift nDCG function.
Reason: same philosophy and helpers, different components; keeps "perfect = 100, empty = 0" invariant testable.

| Component | Pts | What |
|---|---|---|
| decisions | 40 | per-finding decision, weighted by finding weight |
| ordering | 20 | weighted nDCG vs `idealOrder`, must-not-miss penalty |
| schedule | 10 | per-finding window vs truth, SLA-aware |
| justification | 15 | reason codes selected per finding (deterministic, not keywords) |
| evidence | 15 | pinned rows satisfying evidence points |
Free-text stakeholder note: rubric keyword hits → coaching + XP bonus only (as today). Reason: keyword grading of prose
is gameable; judgment is graded through structured choices + evidence.

### 5.1 Decisions (40)
- Finding weight `w` (default 1; must-not-miss 3; noise 0.5). Earned = 40 × Σ(w·credit)/Σw.
- credit: exact or in `alsoAccept` = 1. Near-miss matrix (row = truth, col = given) = 0.5:
  patch↔mitigate (when truth is patch and a real control is chosen that covers the path), accept↔mitigate,
  transfer↔accept. Everything else 0. **false-positive given on a real must-not-miss = 0 and −5 (cap −10)**:
  dismissing a real exploited vuln is the costly mistake (mirrors SOC `mustNot`).
- `mitigate` requires a control from the finding's acceptable list; wrong control → 0.5.

### 5.2 Ordering (20)
- Relevance per finding from its tier (tier 1 = 3, 2 = 2, 3 = 1, noise/FP = 0). Score = 20 × nDCG(given order).
  Ties inside a tier are free (graded on tiers, not total order). Findings marked FP/accept may be left unranked at no cost.
- Must-not-miss: each one not in the top `k` (k = number of must-not-miss items + 1) costs 4 points of ordering (floor 0).

### 5.3 Schedule (10)
- Choices: emergency change / next window / standard cycle / none. Ordinal with half credit one step off, but
  **later than SLA allows = 0** regardless of step distance; emergency when not justified = half (change fatigue is real).
- Capacity: if emergency+next-window assignments exceed `capacityPerWindow`, lowest-relevance overflow items score 0.

### 5.4 Justification reason codes (15)
Fixed vocabulary (checkbox chips per finding, ≤ 3): `known-exploited`, `high-exploit-probability`, `public-exploit`,
`internet-exposed`, `critical-asset`, `sensitive-data`, `compensating-control-verified`, `control-not-covering`,
`credentialed-confirmed`, `banner-only`, `backported-fix`, `stale-scan`, `pending-reboot`, `duplicate-root-cause`,
`vendor-responsibility`, `approved-exception`, `no-vendor-fix`, `low-exploitability`, `sla-deadline`, `change-freeze`.
Score per finding = |given ∩ required| / |required| − 0.25 × |given ∩ contradicting|, clamped 0..1; weighted like decisions.
Each template lists `required` and `contradicting` codes per finding (e.g., `stale-scan` contradicts a real finding).

### 5.5 Evidence (15)
Exactly the SOC mechanism: `EvidenceSpec` with RowRefs; pin any row → point; hints −20% of this component each;
4 free extra pins, then −1 per irrelevant pin (cap −5).

### 5.6 Worked examples (T3 case `vm-kev-internal`, 4 findings)
Findings: F1 SKEV-listed RCE on app server (must-not-miss, w3, tier1, emergency, reasons {known-exploited, public-exploit});
F2 medium TLS config (w1, tier3, standard, reasons {low-exploitability}); F3 stale high on file server already patched
(w1, FP, none, {stale-scan}); F4 high on dev box, XPS 0.4% (w1, tier2, next-window, {low-exploitability}).
Σw = 6. Evidence points: 3 (SKEV row, PatchHistory row for F3, DeviceInfo for F4).
- **Perfect**: 40 + 20 + 10 + 15 + 15 = **100**.
- **Sort-by-CVSS analyst**: decisions all "patch" → F1 1·3, F2 1, F3 0, F4 1 → 40×5/6 = 33.3. Order F3,F1,F4,F2 by score:
  nDCG ≈ 0.86 → 17.2; F1 in top 2 → no must-not-miss penalty. Schedule: F1 next-window (SLA 3 days breached → 0),
  F3 scheduled (should be none → 0) → 10×(0+1+0+1)/4 = 5. Reasons none → 0. Evidence 1/3 → 5. **Total ≈ 60.5.**
- **Dismisses F1 as FP**: decisions 40×3/6 = 20 − 5 = 15; ordering loses must-not-miss 4; typical **≈ 45**. Debrief leads with F1.
- **Empty submission**: 0 (grader must return 0; tested).

### 5.7 Pass mark and XP
Pass (SRS quality) 70% as SOC. XP = score × `DIFFICULTY_MULTIPLIER` + rubric bonus, identical formula to SOC so ranks stay comparable.

## 6. Data model and generator

### 6.1 New corpus tables (context kind, in `logs/schema.ts`, Sentinel/Defender-TVM-flavoured names)
| Table | Key columns |
|---|---|
| `VulnFindings` | FindingId, DeviceName, VulnId, Title, Severity (scanner), CvssBase, Port, Service, DetectedVersion, Evidence, ScanRunId, FirstSeen, LastSeen, Status, PluginFamily |
| `ScanRuns` | ScanRunId, Tool, Method (Credentialed/Unauthenticated/Agent), Vantage (Internal/External), Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures |
| `VulnIntel` | VulnId, CvssVector, CvssBase, KnownExploited (bool), KnownExploitedAdded, ExploitProbability, ExploitPercentile, PublicExploit, VendorFix, Published, Source ("fictional catalogue") |
| `SoftwareInventory` | DeviceName, Product, Vendor, Version, PackageSource (distro/vendor/source-built), InstalledOn |
| `PatchHistory` | DeviceName, PatchId, InstalledOn, RebootPending, Result |
| `ControlInventory` | ControlId, Kind (WAF/ACL/EDR/MFA/Config), Target, Mode (block/detect), CoversVulnId, Evidence |
| existing `DeviceInfo`, `Tickets` (change windows, freezes, risk exceptions with expiry), `FirewallLogs` (exposure proof) |
Reason for context tables in the corpus: the reference investigation stays runnable KQL and the existing scenario harness proves solvability.

### 6.2 Generator
- `src/core/vuln/catalogue.ts`: seeded fictional vuln catalogue (≈ 60 entries) — class (RCE, SQLi, auth bypass, info leak, DoS, misconfig),
  product family (fictional product names), CVSS 3.1 vector, base computed by our own calculator (`cvss31.ts`, formula from the public
  FIRST spec; tested against the spec's worked examples — **NEEDS-HUMAN-CHECK** the vectors used as test oracles).
- `scan-writer.ts`: emits ScanRuns + findings for in-scope hosts; applies method semantics (unauthenticated sees banner-derived versions only;
  credentialed/agent sees package versions).
- Templates plant deciders (signal rows) via `ctx.log` and keep RowRefs.

### 6.3 Noise budget (per case)
- 60–80% of findings are background: informational/low (TLS ciphers, self-signed certs, SSH banners), duplicates, accepted-risk items with valid exceptions.
- Every decider has a decoy: another SKEV-listed item already patched; another WAF rule in detect mode on an unrelated app; another stale scan that is still valid.
- ScanRuns: ≥ 2 runs, one with partial coverage or auth failures. Tickets: ≥ 3 unrelated change tickets and one freeze.
- Row counts small (hundreds, not thousands): vuln work is about joining context, not searching haystacks. Reason: keeps worker build < 1 s on mobile.

### 6.4 Query layer
Same worker, same KQL/SQL. Schema docs, autocomplete and did-you-mean come from `schema.ts` automatically. Add 2–3 KQL reference
examples for joins (`VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited`) to the in-app reference (executed by tests).

## 7. UI flow and accessibility
Routes (add to `router.ts`): `#/vuln` (library of vuln cases), `#/vuln/<slug>/<seed>` (case), debrief inline as SOC.
Home gets a "Vulnerability Management" card next to Practice/Shift.

Case screen layout (reuse `Workspace`, `Panels`, `Results`, `Debrief`, tokens.css):
1. **Brief** panel: scope, SLA policy table, change calendar (list, not a graphic-only calendar).
2. **Findings worklist** (primary): accessible `<table>` with one row per finding; per row a decision `<select>`, schedule `<select>`,
   reason-chip group (`role="group"`, checkboxes), pin count. Rows reorderable by **Move up/Move down buttons** and a numeric "priority"
   input (drag-and-drop optional enhancement only). Reason: drag is not keyboard/screen-reader friendly.
3. **Console** tab: existing query editor + results with pinning.
4. **Note** tab: stakeholder note textarea with live rubric hints off by default.
5. **Submit** → Debrief: per-component bars, per-finding truth vs yours, "why", reference queries runnable.

Keyboard: tab order Brief → worklist → console → submit; worklist rows use roving focus only if a grid is needed (default: plain table controls);
Alt+↑/↓ moves focused finding; all shortcuts listed in Help. Screen reader: each control labelled "Decision for FND-xxxx on HOST",
live region announces reorder ("FND-0004 moved to position 2 of 6"). Mobile 360 px: worklist collapses to cards per finding
(same controls, stacked), console below. Reduced motion: no animated reordering; honours existing `MotionPref`. Colour never the sole
carrier of severity (text label + icon). Axe scan in both themes for the new screens.

## 8. Integration
- **Profile/XP/ranks**: record attempts via `recordAttempt` with `mode: 'vuln'` (extend `AttemptMode`), `category: 'vulnmgmt'`
  (extend `Category` + `CATEGORY_LABELS`), components stored under vuln keys (widen `AttemptRecord.components` to
  `Partial<Record<string, number>>`). Profile stays version 2; `coerceProfile` must accept old and new records (test). XP feeds the same rank.
- **Stats**: domain 2.0 / objectives 2.1–2.5 accuracy; decision confusion matrix (e.g., "you patch things that are false positives").
- **Study/adaptive**: `VulnTemplate` registered in study pool; `skills()` extended with `objective` kind. SRS cards keyed by template id.
- **Continuity (supported, WP-C)**: profile gains `vulnLedger: {vulnId, host, decision, decidedDay}[]` (optional field, capped 50).
  When a *real* must-not-miss finding was marked FP/accept/standard-cycle, the shift planner may inject SOC template
  `endpoint-known-vuln-exploit` whose `build` receives `ctx.vulnHook {host, vulnId}` and emits exploitation telemetry referencing the
  same fictional VulnId; its debrief links back to the vuln case. Feasible because shift `plan.ts` composes templates and templates
  already receive optional context (`foothold`). Campaign actor may use the ledger as an initial-access option (future work).
- **Case of the Day**: future work.

## 9. Fact and safety policy (rules)
1. All organizations, hosts, users, IPs, hashes and credentials are synthetic. Nothing is presented as a real incident or real company.
2. Vulnerability facts (CVE IDs, CVSS scores/vectors, KEV status, EPSS, affected versions) must never come from model memory. Either
   (a) pull them at build time from a public source (NVD, CISA KEV, FIRST EPSS) into a pinned snapshot file recording source URL and
   retrieval date, or (b) make them clearly fictional with an ID scheme that cannot be mistaken for a real CVE.
3. **This build uses (b).** The design environment has no network access to NVD/CISA/FIRST. Fictional IDs use the scheme
   `SIMVULN-<4-digit year>-<5 digits>` (e.g., `SIMVULN-2026-10421`); product names are fictional; the listing is "SKEV (simulated
   known-exploited catalogue)"; exploit probability is "XPS (simulated, EPSS-style)". UI shows a "Simulated data" badge on intel panels.
4. A guardrail test fails the build if any string matching `/CVE-\d{4}-\d{4,}/i` appears in generated case output or `src/core/vuln/**`,
   except in `data/vuln-snapshot/*.json` reference metadata (rule 5).
5. Optional (a): `scripts/refresh-vuln-snapshot.mjs`, human-run with network, writes `data/vuln-snapshot/<source>-<date>.json` with
   `{sourceUrl, retrievedAt, license, records}`. Snapshot data may appear only as **reference metadata** in the debrief ("a real-world
   vulnerability with a similar profile"), never as something the fictional org suffered. Not required for the app to work.
6. Real CVEs may appear as reference metadata, but a fictional org is never claimed to have suffered a real incident.
7. Everything works offline as a static site. Any backend stays optional and additive.
8. CS0-003 objective mapping and CVSS test oracles are human-verified before release (NEEDS-HUMAN-CHECK list in PLAN.md).
9. fact-checker agent may veto any scenario violating rules 1–6.

## 10. Non-goals and risks
Non-goals: real scanner file import (Nessus/Qualys XML); CVSS v4 calculator (v3.1 only in this iteration — **NEEDS-HUMAN-CHECK** whether
CS0-003 expects v3.1); live feeds; i18n; backend; editing existing SOC templates (except adding one new continuity template).

| Risk | Mitigation |
|---|---|
| Fictional data feels unreal | Realistic vectors, plugin text shapes, version strings; scenario-reviewer + fact-checker gates |
| Reason codes become a checklist to game | contradicting-code penalty; codes differ per twin |
| Widening shared unions breaks profile/stats | additive widening, coercion tests with old fixtures |
| Worklist UI too heavy on mobile | card layout, no drag requirement, e2e at 360 px |
| Ordering grade feels arbitrary | tier-based relevance, ties free, debrief shows ideal tiers with reasons |
| Scope creep into CVSS v4 / real feeds | explicit non-goal; ADR-4 |
