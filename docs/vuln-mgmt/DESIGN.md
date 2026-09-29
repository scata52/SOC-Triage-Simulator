# DESIGN — Vulnerability Management mode

Status: design only. Builds on `docs/vuln-mgmt/AS-BUILT.md`. Decisions carry a one-line reason.
Work breakdown: `docs/vuln-mgmt/PLAN.md`. Items marked **NEEDS-HUMAN-CHECK** must be verified by a person.
Verified against primary sources on 2026-09-28 (exam objectives, CVSS oracles, feed naming); sources are cited inline.

## 0. One-paragraph pitch
The analyst opens a **vuln case**: a scan export for part of the same persistent fictional org, plus
asset inventory, patch history, change windows, SLA policy and a threat-intel feed. They must decide,
per finding, **patch / mitigate / avoid / accept / transfer / false positive**, order the work, fit it into the
change calendar, cite the rows that justify each call, and write a short stakeholder note. The answer key
explains why. Twins share the same headline finding and score but flip the right decision on context.

## 1. Learning goals → CS0-003 objectives
Source: *CompTIA CySA+ CS0-003 Certification Exam: Exam Objectives, Version 1.0*
(https://comptiacdn.azureedge.net/webcontent/docs/default-source/exam-objectives/comptia-cysa-cs0-003-exam-objectives-(1-0)-(2)-(002).pdf,
retrieved 2026-09-28) and the CompTIA CySA+ V3 page (https://www.comptia.org/en-us/certifications/cybersecurity-analyst/v3/, retrieved 2026-09-28).

Domain weightings (CS0-003): 1.0 Security Operations 33% · **2.0 Vulnerability Management 30%** · 3.0 Incident Response
Management 20% · 4.0 Reporting and Communication 17%. (The earlier "22%" was wrong.)

Exam lifecycle: CS0-003 (English) retires **2026-12-22** (Japanese, Portuguese, Spanish: 2027-03-23). Its successor **CS0-004** launched
2026-06-23 (https://www.comptia.org/en-us/certifications/cybersecurity-analyst/v4/, retrieved 2026-09-28): Security Operations 34%,
Vulnerability Management 26%, Incident Response and Management 24%, Reporting and Communication 16%. CS0-004 domain 2.0 has four
objectives (scanning methods; tool output; prioritize *and* mitigate; control types, risks and VM concepts). The official CS0-004
objectives PDF was not retrievable, so no CS0-004 numbering is used here (see PLAN NEEDS-HUMAN-CHECK). Objective tags are template data,
so a later remap changes tags and labels only.

Titles below are verbatim from the CS0-003 PDF. "Enrichment" marks goals the mode teaches beyond the objective's wording.

| Obj | Official title | Goals in this mode | Where trained |
|---|---|---|---|
| 2.1 | Given a scenario, implement vulnerability scanning methods and concepts. | asset discovery gaps; credentialed vs non-credentialed; agent vs agentless; internal vs external; passive vs active; special considerations (scheduling, segmentation, sensitivity levels); critical infrastructure (OT/ICS); stale scans (enrichment) | ScanRuns metadata, twins T1, T2, T6, T7 |
| 2.2 | Given a scenario, analyze output from vulnerability assessment tools. | read scanner rows; banner-derived vs package-derived versions; dedupe plugins; tool families named in the objective (vulnerability scanners, web application scanners, network scanning and mapping, cloud infrastructure assessment); SCA output (enrichment) | Findings table, evidence pins, twins T1, T7, T10 |
| 2.3 | Given a scenario, analyze data to prioritize vulnerabilities. | CVSS interpretation with the objective's metrics (attack vector, attack complexity, privileges required, user interaction, scope, C/I/A impact); validation (true/false positives and negatives: backported fix, stale scan, banner-only); context awareness (internal / external / isolated); exploitability/weaponization (Sim-KEV, Sim-EPSS, public exploit); asset value; zero-day. CVSS environmental metrics are enrichment, taught as the numeric form of "context awareness" | Ordering score, twins T1–T5, T9 |
| 2.4 | Given a scenario, recommend controls to mitigate attacks and software vulnerabilities. | map finding class → control, using the objective's class names (injection flaws → parameterized queries / input validation, WAF as virtual patch; identification and authentication failures → MFA; security misconfiguration → hardening baseline; end-of-life or outdated components → upgrade or isolate) | Mitigation picker, rubric, twins T5, T6 |
| 2.5 | Explain concepts related to vulnerability response, handling, and management. | compensating control; control types; patching and configuration management (testing, implementation, rollback, validation); maintenance windows; exceptions; risk management principles **accept / transfer / avoid / mitigate**; policies, governance and SLOs; prioritization and escalation | Decisions, scheduling score, twins T4, T5, T6, T8, T11 |
| 4.1 (secondary) | Explain the importance of vulnerability management reporting and communication. | stakeholder note; VM reporting (affected hosts, risk score, mitigation, recurrence, prioritization); action plans; inhibitors to remediation (MOU, SLA, organizational governance, business process interruption, degrading functionality, legacy systems, proprietary systems); metrics and KPIs (trends, top 10, critical vulnerabilities and zero-days, SLOs) | Stakeholder note rubric, twins T6, T8 |

Corrections vs the first draft: inhibitors to remediation belong to 4.1, not 2.5; MTTR is a 4.2 (incident response) metric, not 4.1;
false-positive validation is a 2.3 item; SCA is not in 2.2's tool list; 2.5 names **avoid** as a risk principle, so it is now a decision (§2.2, T11).

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
  idealOrder: string[];       // findingIds, most urgent first; lists every tiered finding, relevance never rising
  tiers: string[][];          // urgency tiers 1–3 in order (§5.2); a finding in no tier is noise/FP/accepted (relevance 0)
  hints: string[]; solution: SolutionStep[];   // runnable KQL, same harness as SOC
  rubric: RubricItem[];       // stakeholder-note coaching (keywords), as today
  explanation: string[]; pitfalls: string[]; references: CaseReference[];
}
// avoid = remove or disable the vulnerable component/service entirely; mitigate = keep it, put a control in front
type VulnDecision = 'patch' | 'mitigate' | 'avoid' | 'accept' | 'transfer' | 'false-positive';
interface FindingTruth {
  decision: VulnDecision; alsoAccept?: VulnDecision[];
  schedule: 'emergency' | 'next-window' | 'standard-cycle' | 'none';
  slaLatest?: FindingTruth['schedule']; // latest schedule that still meets this finding's SLA on the case calendar (§5.3)
  reasons: ReasonCode[];      // required justification codes (see §5.4)
  contradicting?: ReasonCode[]; // codes that count against the learner (§5.4)
  mitigation?: ControlId[];   // controls that cover the vulnerable path: credit for mitigate (§5.1)
}
```
Clarified 2026-09-29 (WP1c, coordinator): `tiers` is required because §5.2 grades on tiers and a strict `idealOrder` cannot
give relevance to more than three ranked findings; `slaLatest` exists because the SLA that applies is policy, not a function of
the finding row (the T3 decider scores CVSS 7.5, High, yet has the 3-day SLA), and the calendar has no fixed date for "standard
cycle". Build-time checks: at most 3 tiers, disjoint, FP/accept truths untiered, must-not-miss findings tiered.
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
   attack vector (e.g., AV:N → effectively adjacent behind segmentation: 9.8 base becomes 8.8 with `MAV:A`, see §6.2).
   The app shows base; the analyst derives context.
3. **Exploit likelihood**: known-exploited listing (**Sim-KEV**, simulated, modeled on the CISA KEV catalog), exploit-probability
   score (**Sim-EPSS**, simulated, modeled on FIRST EPSS: 0–1 probability of exploitation in the next 30 days, with percentile),
   public exploit / exploit-kit availability, vendor advisory "exploited in the wild". Naming rationale in §3.1.
4. **Asset criticality and exposure**: `DeviceInfo.Criticality`, `ExposedToInternet`, data classification, blast radius
   (domain controller, jump host, CI runner with secrets).
5. **Compensating controls**: WAF virtual patch, segmentation ACL, feature disabled via config, EDR prevention rule,
   MFA in front of the service — and whether the control actually covers the attack path (verify in ControlInventory +
   FirewallLogs).
6. **Remediation choice and sequencing**: six decisions; SLA per class; change windows and freezes; emergency change
   justification; capacity limits; dependencies (patch the library before the app restart; reboot groups).
7. **Communicating the decision**: short stakeholder note (owner, risk, action, date, exception expiry) graded by rubric.

### 3.1 Simulated feed names — decision
The first draft used invented acronyms "SKEV" and "XPS". Replaced by **Sim-KEV** and **Sim-EPSS**. Reason: the learner must recognise
KEV and EPSS at work; an invented acronym teaches a word that exists nowhere, and "XPS" already means other things (a document format,
a laptop line). The `Sim-` prefix plus the "Simulated data" badge keeps the fiction explicit. CS0-003 itself names neither feed
(2.3 says "exploitability/weaponization"), so the mode teaches the concept under the exam's term and the real-world names alongside it.
- Column/table names stay plain: `VulnIntel.KnownExploited`, `KnownExploitedAdded`, `ExploitProbability`, `ExploitPercentile`.
- Intel panel headings: "Known exploited (Sim-KEV)" and "Exploit probability, next 30 days (Sim-EPSS)", each with a one-line explainer:
  - Sim-KEV: "Simulated list modeled on the CISA Known Exploited Vulnerabilities (KEV) catalog: vulnerabilities with evidence of
    exploitation in the wild. Entries here are fictional."
  - Sim-EPSS: "Simulated score modeled on FIRST's Exploit Prediction Scoring System (EPSS): estimated probability that a vulnerability
    is exploited in the wild in the next 30 days, with its percentile rank. Values here are fictional but follow the real distribution (§11)."
- Help glossary (WP6) repeats both entries. Sources for the definitions: https://www.cisa.gov/known-exploited-vulnerabilities-catalog and
  https://www.first.org/epss/ (retrieved 2026-09-28).

## 4. Twin catalogue
Each pair: same `title`, same headline finding and base score; one clue differs. Ids are proposed template slugs.

| # | Pair (A / B) | Shared headline | Deciding clue (where) | A decision | B decision | Misconception exposed |
|---|---|---|---|---|---|---|
| T1 | `vm-backport-fp` / `vm-backport-real` | Critical 9.8 on Linux web server, unauthenticated scan | PatchHistory/SoftwareInventory show distro package with backported fix vs upstream vulnerable build compiled from source | false-positive | patch (emergency if exposed) | "Scanner said critical, so it is" |
| T2 | `vm-stale-scan` / `vm-fresh-scan` | High finding on file server, 21 days old | PatchHistory: KB installed after ScanRun.started (A) vs installed-but-pending-reboot, service still loads old DLL (B) | false-positive (stale; request rescan) | patch (schedule reboot) | "Installed = fixed"; ignoring scan timestamps |
| T3 | `vm-kev-internal` / `vm-nokev-internal` | CVSS 7.5 on internal app server | VulnIntel: on Sim-KEV + public exploit (A) vs Sim-EPSS 0.004 (≈ 31st percentile), no public exploit (B) | patch, emergency | patch, standard-cycle | CVSS alone sets urgency |
| T4 | `vm-exposed-edge` / `vm-segmented` | CVSS 9.8 RCE on management interface | DeviceInfo exposed + FirewallLogs show internet hits (A) vs ControlInventory: interface on isolated mgmt VLAN, ACL verified in FirewallLogs (B; environmental 8.8 with `MAV:A`) | patch, emergency | mitigate (already) → patch next-window | Base score = environmental score |
| T5 | `vm-waf-covers` / `vm-waf-bypass` | SQL injection in public web app, fix needs code release after freeze | WAF rule covers the vulnerable parameter (A) vs WAF in detect-only mode / endpoint not routed through WAF (B) | mitigate (virtual patch) + patch next-window | emergency change (patch/disable feature) | "We have a WAF" ≠ covered |
| T6 | `vm-legacy-accept` / `vm-legacy-isolate` | Unsupported OS on lab/OT controller, vendor won't patch | Tickets: approved, time-boxed risk exception with owner and isolation in place (A) vs no exception and host reachable from corp VLAN (B) | accept (verify expiry) | mitigate (segment) + raise exception | "Can't patch → nothing to do" |
| T7 | `vm-noncred-low` / `vm-cred-high` | Same host, same vuln family, different severity reported | ScanRuns: unauthenticated external scan saw banner only (A, informational) vs credentialed agent confirms vulnerable version (B) | false-positive for version guess → schedule credentialed rescan | patch | Trusting method-blind output; not knowing credentialed scans find more |
| T8 | `vm-saas-transfer` / `vm-self-hosted` | Critical vuln in a third-party ticketing product | SoftwareInventory/Contracts: vendor-hosted SaaS, vendor SLA/contract covers patching (A) vs self-hosted instance (B) | transfer (track vendor, verify) | patch | Every finding is ours to patch |
| T9 | `vm-dev-crit` / `vm-prod-med` | Two findings: Critical on a dev box, Medium on the payments DB | DeviceInfo criticality, data class, exposure | ordering: payments first | (same case, ordering twin) | Sort by severity column |
| T10 | `vm-dup-plugins` / `vm-distinct` | 6 findings on one host | same root cause (one OpenSSL-like library, one patch) vs six unrelated issues | patch once, 5 duplicates marked false-positive(dup) → decision "patch" on root, others `duplicate` reason | handle separately | Counting findings instead of fixes |
| T11 | `vm-unused-service` / `vm-needed-service` | High RCE in an optional admin console on an app server | SoftwareInventory: installed by default, FirewallLogs/app logs show no use, Tickets: owner confirms not needed (A) vs console used by a business process (B) | avoid (remove/disable the component) | patch | "Every vulnerability needs a patch"; attack-surface reduction |

T1–T8 satisfy the "≥ 8 pairs" requirement; T9–T10 are ordering/triage twins for tier 2–3; T11 covers the "avoid" principle of 2.5.
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
  transfer↔accept, and truth avoid → given patch (fixes this finding but keeps the attack surface). Truth patch → given avoid = 0
  (removes a component the business needs). Everything else 0. **false-positive given on a real must-not-miss = 0 and −5 (cap −10)**:
  dismissing a real exploited vuln is the costly mistake (mirrors SOC `mustNot`).
- `mitigate` requires a control from the finding's acceptable list; wrong control → 0.5.
- Clarified (WP1c): `mitigate` with no control counts as a wrong control. The patch→mitigate near miss needs a control from
  `mitigation` (on a patch finding the list names the controls that cover the path), else 0; accept↔mitigate needs none. The −5
  applies when `false-positive` is given on a must-not-miss finding whose truth is not FP; it is taken inside the 40 points
  (floor 0). Σw = 0 → 0.

### 5.2 Ordering (20)
- Relevance per finding from its tier (tier 1 = 3, 2 = 2, 3 = 1, noise/FP = 0). Score = 20 × nDCG(given order).
  Ties inside a tier are free (graded on tiers, not total order). Findings marked FP/accept may be left unranked at no cost.
- Must-not-miss: each one not in the top `k` (k = number of must-not-miss items + 1) costs 4 points of ordering (floor 0).
- Clarified (WP1c): tiers come from `tiers` (§2.2). A finding's position is its place in the submitted order (unknown and repeated
  ids ignored); an unranked finding earns no gain and is outside the top `k`. A case with no tiered finding scores the full 20
  once any of its findings has a decision, else 0 (SOC's restraint rule; keeps empty = 0).

### 5.3 Schedule (10)
- Choices: emergency change / next window / standard cycle / none. Ordinal with half credit one step off, but
  **later than SLA allows = 0** regardless of step distance; emergency when not justified = half on a real finding (change fatigue
  is real; human decision 2026-09-29: an emergency change for a false positive follows the ordinal, i.e. 0 against its truth `none`).
- Capacity: if emergency+next-window assignments exceed `capacityPerWindow`, lowest-relevance overflow items score 0.
- Clarified (WP1c): unweighted mean over all findings (§5.6 divides by 4). Rules per finding, first match wins: not set 0; later
  than `slaLatest` (when the template gives it) 0; exact 1; emergency on a real finding (truth not FP) whose truth is not
  emergency 0.5, also when that truth is `none` (accept, transfer); otherwise ordinal. Then capacity: among equal relevance the learner's lower-ranked assignment overflows
  first (unranked lowest), then the later finding in case order.

### 5.4 Justification reason codes (15)
Fixed vocabulary (checkbox chips per finding, ≤ 3): `known-exploited`, `high-exploit-probability`, `public-exploit`,
`internet-exposed`, `critical-asset`, `sensitive-data`, `compensating-control-verified`, `control-not-covering`,
`credentialed-confirmed`, `banner-only`, `backported-fix`, `stale-scan`, `pending-reboot`, `duplicate-root-cause`,
`vendor-responsibility`, `approved-exception`, `no-vendor-fix`, `low-exploitability`, `sla-deadline`, `change-freeze`,
`unused-component`.
Score per finding = |given ∩ required| / |required| − 0.25 × |given ∩ contradicting|, clamped 0..1; weighted like decisions.
Each template lists `required` and `contradicting` codes per finding (e.g., `stale-scan` contradicts a real finding).
Clarified (WP1c): only the first three distinct codes count. A finding with no required codes scores 1 when it has a decision
(SOC's restraint rule), else 0, before the contradiction penalty.

### 5.5 Evidence (15)
Exactly the SOC mechanism: `EvidenceSpec` with RowRefs; pin any row → point; hints −20% of this component each;
4 free extra pins, then −1 per irrelevant pin (cap −5). The points are every evidence spec of every finding.
Rounding (WP1c): components to one decimal (evidence to whole points, as SOC); score = their sum; percent = rounded score.

### 5.6 Worked examples (T3 case `vm-kev-internal`, 4 findings)
Findings: F1 Sim-KEV-listed RCE on app server (must-not-miss, w3, tier1, emergency, reasons {known-exploited, public-exploit});
F2 medium TLS config (w1, tier3, standard, reasons {low-exploitability}); F3 stale high on file server already patched
(w1, FP, none, {stale-scan}); F4 high on dev box, Sim-EPSS 0.004 (w1, tier2, next-window, {low-exploitability}).
Σw = 6. Evidence points: 3 (Sim-KEV row, PatchHistory row for F3, DeviceInfo for F4).
- **Perfect**: 40 + 20 + 10 + 15 + 15 = **100**.
- **Sort-by-CVSS analyst**: decisions all "patch" → F1 1·3, F2 1, F3 0, F4 1 → 40×5/6 = 33.3. Order F3,F1,F4,F2 by score:
  nDCG = 0.698 (linear gain / log2(pos+2), as `prioritisation()` in `shift/score.ts`) → 14.0; F1 in top 2 → no must-not-miss penalty.
  Schedule: F1 next-window (SLA 3 days breached → 0), F3 scheduled (should be none → 0) → 10×(0+1+0+1)/4 = 5. Reasons none → 0.
  Evidence 1/3 → 5. **Total = 57.3.** (First draft said nDCG ≈ 0.86 / total ≈ 60.5; recomputed 2026-09-28.)
- **Dismisses F1 as FP**: decisions 40×3/6 = 20 − 5 = 15; ordering loses must-not-miss 4; rest depends on the submission,
  typically **≈ 45**. Debrief leads with F1. (Only the decisions and must-not-miss parts are exact.)
- **Empty submission**: 0 (grader must return 0; tested).

### 5.7 Pass mark and XP
Pass (SRS quality) 70% as SOC. XP = score × `DIFFICULTY_MULTIPLIER` + rubric bonus, identical formula to SOC so ranks stay comparable.

## 6. Data model and generator

### 6.1 New corpus tables (context kind, in `logs/schema.ts`, Sentinel/Defender-TVM-flavoured names)
| Table | Key columns |
|---|---|
| `VulnFindings` | FindingId, DeviceName, VulnId, Title, Severity (scanner), CvssBase, Port, Service, DetectedVersion, Evidence, ScanRunId, FirstSeen, LastSeen, Status, PluginFamily |
| `ScanRuns` | ScanRunId, Tool, Method (Credentialed/Unauthenticated/Agent), Vantage (Internal/External), Started, Finished, TargetsPlanned, TargetsScanned, AuthFailures |
| `VulnIntel` | VulnId, CvssVector, CvssBase, KnownExploited (bool), KnownExploitedAdded, ExploitProbability, ExploitPercentile, PublicExploit, VendorFix, Published, Source ("Simulated (Sim-KEV / Sim-EPSS)") |
| `SoftwareInventory` | DeviceName, Product, Vendor, Version, PackageSource (distro/vendor/source-built), InstalledOn |
| `PatchHistory` | DeviceName, PatchId, InstalledOn, RebootPending, Result |
| `ControlInventory` | ControlId, Kind (WAF/ACL/EDR/MFA/Config), Target, Mode (block/detect), CoversVulnId, Evidence |
| existing `DeviceInfo`, `Tickets` (change windows, freezes, risk exceptions with expiry), `FirewallLogs` (exposure proof) |
Reason for context tables in the corpus: the reference investigation stays runnable KQL and the existing scenario harness proves solvability.

### 6.2 Generator
- `src/core/vuln/catalogue.ts`: seeded fictional vuln catalogue (≈ 60 entries) — class (RCE, SQLi, auth bypass, info leak, DoS, misconfig),
  product family (fictional product names), CVSS 3.1 vector, base computed by our own calculator (`cvss31.ts`, formulas from the
  FIRST v3.1 specification §7, Roundup per its Appendix A integer method; tested against the oracle table below).

**CVSS v3.1 test oracles (verified 2026-09-28).** A throwaway calculator written from the spec
(https://www.first.org/cvss/v3.1/specification-document, §7 and Appendix A) reproduced all 27 single-score examples on
https://www.first.org/cvss/v3.1/examples (0 mismatches; 2 examples print two scores for two products and were skipped), and matched
FIRST's reference calculator (https://www.first.org/cvss/calculator/cvsscalc31.js) on 20,000 random full vectors, base + temporal +
environmental, with 0 mismatches. Both headline scores used in §4 (9.8, 7.5) reproduce. The vectors below are metric strings only;
the source examples' CVE ids are deliberately not copied.

| Vector (prefix `CVSS:3.1/`) | Expected | Covers |
|---|---|---|
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | base 9.8 Critical | T1/T4 headline |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | base 7.5 High | T3 headline |
| `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | base 9.9 | scope changed, PR:L = 0.68 |
| `AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` | base 6.4 | scope changed, low impacts |
| `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` | base 3.1 Low | AC:H, UI:R |
| `AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L` | base 4.2 Medium | AV:L, PR:H unchanged |
| `AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` | base 8.2 | PR:H = 0.5 when changed |
| `AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H` | base 9.3 | AV:A |
| `AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | base 7.6 | AV:P |
| `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` | base 6.1 | 1.08 multiplier path |
| `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | base 0.0 None | impact ≤ 0 branch (computed, not a FIRST example) |
| 9.8 vector + `/MAV:A` | environmental 8.8 | T4 B segmented interface |
| 9.8 vector + `/MAV:L` | environmental 8.4 | modified AV |
| 7.5 vector + `/CR:H` | environmental 9.3 | requirement raises score |
| 7.5 vector + `/CR:L` | environmental 5.7 | requirement lowers score |
| 9.9 vector + `/CR:H/IR:H/AR:H` | environmental 10.0 | MISS cap 0.915, exponent 13 path |
| 9.8 vector + `/E:F/RL:O/RC:C` | temporal 9.1, environmental 9.1 | temporal factors |
| 7.5 vector + `/E:U/RL:O/RC:C` | temporal 6.5 | temporal factors |

Severity bands (spec Table 14): None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.
- `scan-writer.ts`: emits ScanRuns + findings for in-scope hosts; applies method semantics (unauthenticated sees banner-derived versions only;
  credentialed/agent sees package versions).
- Templates plant deciders (signal rows) via `ctx.log` and keep RowRefs.

**Catalogue and feed parameters (calibrated 2026-09-28, numbers in §11).** Deterministic per seed; a template may override values for its deciders.
- *CVSS mix* of the ≈ 60 catalogue entries: Critical 15% · High 40% · Medium 40% · Low 5% (NVD: 16/40/43/2% over all CVEs with a v3 score,
  14/46/37/4% over the last 90 days). Vectors favour the shapes most common in NVD (base 7.5, 6.5, 8.8, 7.8, 9.8, 5.3). Reason: a
  critical-heavy catalogue would teach that most findings are critical.
- *Sim-KEV*: 6 of ≈ 60 catalogue entries (10%), a deliberate teaching over-sample (real: 0.45% of all CVEs, 1.6% of Critical ones).
  Listed entries span severities as KEV does, so at least one is Medium; about a third carry an old id (SIMVULN year ≤ 2019) on a legacy
  host. Background (non-decider) findings are never Sim-KEV-listed except the planted decoys.
- *Sim-EPSS, not Sim-KEV-listed*: inverse-CDF sampling, log-linear between anchors (percentile → score): 0 → 0.0005, 0.10 → 0.0021,
  0.25 → 0.0034, 0.50 → 0.0067, 0.75 → 0.016, 0.90 → 0.039, 0.95 → 0.088, 0.99 → 0.55, 1.0 → 0.98.
- *Sim-EPSS, Sim-KEV-listed*: anchors 0 → 0.0023, 0.10 → 0.023, 0.25 → 0.090, 0.50 → 0.49, 0.75 → 0.92, 1.0 → 0.997. So about one
  Sim-KEV entry in four shows Sim-EPSS < 0.1, and at least one tier-2+ case uses such an item: "known exploited" outranks a modest probability.
- *Displayed percentile* always comes from the first (all-CVE) anchor table, so a score maps to one percentile everywhere (0.004 → 31st).
- *Newly published* entries (< 30 days before the case date) draw Sim-EPSS from the lower half of the first table: recent CVEs have not
  accrued exploitation evidence yet (recent Critical CVEs: median EPSS 0.0056). Supports the 2.3 "zero-day" discussion.

### 6.3 Noise budget (per case)
- 60–80% of findings are background: informational/low (TLS ciphers, self-signed certs, SSH banners), duplicates, accepted-risk items with valid exceptions.
- Every decider has a decoy: another Sim-KEV-listed item already patched; another WAF rule in detect mode on an unrelated app; another stale scan that is still valid.
- ScanRuns: ≥ 2 runs, one with partial coverage or auth failures. Tickets: ≥ 3 unrelated change tickets and one freeze.
- Row counts small (hundreds, not thousands): vuln work is about joining context, not searching haystacks. Reason: keeps worker build < 1 s on mobile.

### 6.4 Query layer
Same worker, same KQL/SQL. Schema docs, autocomplete and did-you-mean come from `schema.ts` automatically. Add 2–3 KQL reference
examples for joins (`VulnFindings | join kind=inner VulnIntel on VulnId | where KnownExploited`) to the in-app reference (executed by tests).

## 7. UI flow and accessibility
Routes (add to `router.ts`): `#/vuln` (library of vuln cases), `#/vuln/<slug>/<seed>` (case), debrief inline as SOC.
Home gets a "Vulnerability Management" card next to Practice/Shift.

**Not XP-gated.** The card and every vuln case are open from the first visit, as on the SOC side; XP and rank only display progress.
Difficulty works as in the SOC Library: each case has a tier (tier1–3, sizes per §2.3) and the vuln library offers the same
"Difficulty: All tiers / Tier 1 / Tier 2 / Tier 3" filter and tier labels. Reason: gating would hide exactly the cases a returning
analyst studying for the exam needs, and the SOC side already works this way.

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
- **Continuity (WP5): one SOC alert, upgradeable later.** Profile gains `vulnLedger: {vulnId, host, decision, decidedDay, caseRef}[]`
  (optional field, capped 50). When a *real* must-not-miss finding was marked FP/accept/standard-cycle, the next shift gets **exactly one**
  extra alert: SOC template `endpoint-known-vuln-exploit`, whose `build` receives `ctx.vulnHook {host, vulnId, decidedDay}` and emits
  exploitation telemetry for that host referencing the same fictional VulnId; its debrief links back to the vuln case. At most one per shift,
  no follow-on stages, no campaign state change, and the ledger entry is marked consumed.
  Upgrade path (not built in v1): the choice sits behind one pure function `selectVulnFollowUp(ledger, shiftSeed) → VulnHook | null`, and
  `planShift` takes the result as an optional slot parallel to the existing `campaign` slot. A later attacker-driven version can replace that
  function, or hand the same `VulnHook` to the campaign actor as its initial-access stage, without changing the template or the ledger format.
  Feasible because `shift/plan.ts` already composes templates around one optional campaign slot and templates already receive optional context (`foothold`).
- **Case of the Day**: future work.

## 9. Fact and safety policy (rules)
Decision (2026-09-28): **fictional only for v1; no real-vulnerability reference dataset.**
1. All organizations, hosts, users, IPs, hashes and credentials are synthetic. Nothing is presented as a real incident or real company.
2. **Scenario data is fully fictional.** Vulnerability ids use `SIMVULN-<4-digit year>-<5 digits>` (e.g., `SIMVULN-2026-10421`), which
   cannot be mistaken for a CVE; products are fictional; CVSS vectors are authored for fictional entries and scored by our calculator;
   exploitation signals come only from the simulated feeds Sim-KEV and Sim-EPSS (§3.1). Intel panels carry a "Simulated data" badge.
   "Scenario data" = everything under `src/core/vuln/**` (templates included) and everything a vuln case generates (corpus rows,
   briefing, hints, solution, explanation, debrief text).
3. No vulnerability fact (CVE id, real CVSS score or vector, KEV status, EPSS value, affected versions) is ever written from model memory.
   v1 ships **no real-vulnerability data at all**: no snapshot files, no lookup panel, no refresh script.
4. A guardrail test fails the build if any string matching `/CVE-\d{4}-\d{4,}/i` appears in scenario data (rule 2). No exceptions.
   The test applies to scenario data only; design docs and Help prose are outside its scope (and still carry no real CVE ids).
5. Help and debrief prose may *name* real public programs and standards (CVSS, NVD, CISA KEV, FIRST EPSS, CompTIA objectives) to explain
   concepts, and may quote aggregate figures from §11 with their source, but never a real vulnerability record.
6. Design-time calibration (§11) uses public feeds for aggregate statistics only; raw data stays out of the repo; nothing is fetched
   at build or run time.
7. Everything works offline as a static site. Any backend stays optional and additive.
8. CS0-003 objective mapping (§1) and CVSS test oracles (§6.2) were verified against primary sources on 2026-09-28; re-verify when
   the target exam version changes. Open items: NEEDS-HUMAN-CHECK list in PLAN.md.
9. The fact-checker agent may veto any scenario violating rules 1–5.

## 10. Non-goals and risks
Non-goals: real scanner file import (Nessus/Qualys XML); CVSS v4.0 calculator; live feeds; i18n; backend; editing existing SOC
templates (except adding one new continuity template).

CVSS version (verified 2026-09-28): the CS0-003 objectives name no CVSS version, but objective 2.3 lists **Scope** among the metrics to
interpret. Scope exists in v3.x only; v4.0 replaced it with separate vulnerable-system / subsequent-system impacts and added Attack
Requirements (https://www.first.org/cvss/v4.0/specification-document, retrieved 2026-09-28). So v3.1 matches the exam; v4.0 stays
future work (revisit if the CS0-004 objectives name it). NVD practice agrees (§11): 86% of recent CVEs carry a v3.1 score, 28% a v4.0 score.

| Risk | Mitigation |
|---|---|
| Fictional data feels unreal | Realistic vectors, plugin text shapes, version strings; scenario-reviewer + fact-checker gates |
| Reason codes become a checklist to game | contradicting-code penalty; codes differ per twin |
| Widening shared unions breaks profile/stats | additive widening, coercion tests with old fixtures |
| Worklist UI too heavy on mobile | card layout, no drag requirement, e2e at 360 px |
| Ordering grade feels arbitrary | tier-based relevance, ties free, debrief shows ideal tiers with reasons |
| Scope creep into CVSS v4 / real feeds | explicit non-goals; ADR-4, ADR-13 |
| Simulated feeds drift from reality | one-time calibration (§11); re-run it by hand if the mode is revised, never at build or run time |

## 11. Calibration (one-time, 2026-09-28)
Purpose: keep the simulated feeds realistic (§6.2 parameters). Only aggregates are recorded; no raw dumps and no real CVE ids are committed,
and nothing here enters scenario data. Sources, all retrieved 2026-09-28:
- CISA KEV JSON feed, catalogVersion 2026.09.27: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS daily file, model v2026.06.15, score date 2026-09-28: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  (spot-checked value-for-value against the FIRST API https://api.first.org/data/v1/epss)
- NVD CVE API 2.0, https://services.nvd.nist.gov/rest/json/cves/2.0: count queries by `cvssV3Severity` with and without `hasKev`,
  plus a sample of all 36,137 non-rejected CVEs published 2026-06-29 … 2026-09-26.

| Measure | Value |
|---|---|
| KEV size | 1,728 entries ≈ 0.45% of the 380,224 EPSS-scored CVEs |
| KEV additions per year | 2021: 311 · 2022: 555 (initial backfill) · 2023: 187 · 2024: 186 · 2025: 245 · 2026 to date: 244 |
| KEV share within each NVD v3 severity | Critical 1.6% (492 / 30,686) · High 0.87% (665 / 76,796) · Medium 0.16% (137 / 83,601) · Low 0.09% (3 / 3,297) |
| KEV entries by v3 severity | Critical 38% · High 51% · Medium 11% · Low < 1% of those with a v3 score; 25% have no v3 score (older CVEs) |
| KEV entries with CVE year ≤ 2019 | 32%; "known ransomware campaign use": 21% |
| EPSS, all CVEs | median 0.0067 · p75 0.016 · p90 0.039 · p95 0.088 · p99 0.55; share ≥ 0.1: 4.5%; ≥ 0.5: 1.1% |
| EPSS percentile anchors | 0.004 ≈ 32nd (31.6) · 0.01 ≈ 61st · 0.1 ≈ 95.5th · 0.5 ≈ 98.9th |
| EPSS of KEV entries | median 0.49; 26% below 0.1; 10% below 0.023 |
| KEV share of the top EPSS scores | top 100: 94% · top 1,000: 52% · top 10,000: 11% |
| NVD v3 severity mix, all CVEs with a v3 score (194,380) | Critical 15.8% · High 39.5% · Medium 43.0% · Low 1.7% |
| NVD sample, last 90 days (36,137) | v3.1 present 85.8%, v4.0 present 27.6%, v4.0 only 7.5%, no CVSS 6.2%; v3 mix Critical 13.5% · High 45.8% · Medium 36.9% · Low 3.7%; median 7.4; most common scores 7.5, 6.5, 8.8, 7.8, 9.8 |
| EPSS of recent CVEs by v3 band | Critical median 0.0056 (0.5% ≥ 0.1) · High 0.0039 · Medium 0.0031 · Low 0.0024; 66 of the 36,137 are already in KEV |

What changed because of it:
1. The draft had no numeric feed parameters; §6.2 now fixes the CVSS mix, the Sim-KEV count, and two Sim-EPSS anchor tables.
2. "Severity ≠ exploitation" is quantified: only 1.6% of Critical CVEs are KEV-listed. T3/T9 debriefs may state this as a real-world figure
   (source: this section), without naming any real CVE.
3. KEV and EPSS disagree often (a quarter of KEV entries score < 0.1), so Sim-KEV items no longer imply a high Sim-EPSS.
4. Twin T3's Sim-EPSS 0.004 is realistic as a low value (≈ 31st percentile); unchanged.
5. The catalogue is not critical-heavy, and old ids stay exploited (a third of KEV is 2019 or older).
