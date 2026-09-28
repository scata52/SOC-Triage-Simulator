# PROGRESS — Vulnerability Management

Branch: `feat/vuln-mgmt-wp1` (from `main` @ 849adce).

## Done
- **WP0 — Kickoff and progress file** (2026-09-28). Baseline on `main` @ 849adce: `npm run typecheck` ok, `npm test` 16 files / 233 tests
  passed, `npm run build` ok (Node 24.19.0).

## In progress
- WP1a — Core types, fictional catalogue, CVSS 3.1 calculator.

## Next
- WP1b — Corpus tables and scan writer
- WP1c — Grader
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

## Known issues
- NEEDS-HUMAN-CHECK 1–2 still open (PLAN.md).
