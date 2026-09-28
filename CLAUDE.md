# CLAUDE.md

Project overview: see `README.md` and `ARCHITECTURE.md`. Checks: `npm run typecheck`, `npm test`, `npm run build`, `npm run test:e2e`.

## Vulnerability Management workstream

Design: `docs/vuln-mgmt/DESIGN.md`. Plan: `docs/vuln-mgmt/PLAN.md`. State: `docs/vuln-mgmt/PROGRESS.md`. Baseline: `docs/vuln-mgmt/AS-BUILT.md`.

### Roles and delegation
The main session is the **coordinator** (run it on Opus: `/model opus`): plans, delegates, integrates, commits, decides. It does small edits inline (a few lines, docs, PROGRESS.md, wiring one import) instead of delegating.
- `explorer` (haiku, read-only): "where/how does X work" questions.
- `scenario-author`: vuln templates and twin pairs; writes only `src/core/vuln/templates/**` and `tests/vuln-scenarios/**`.
- `implementer`: one work package of engine/grader/schema/UI/tests; may edit docs only in `docs/vuln-mgmt/PROGRESS.md`.
- `fact-checker` (read-only + web): exam mapping and any real vulnerability data; can veto a scenario.
- `reviewer` (gate): every package; not done until it returns PASS.
- Existing `scenario-reviewer`, `guardrail-auditor`, `code-reviewer` stay available as extra reviewers.

### Handoff format
Every subagent returns: what changed, files touched, check results, open issues — max 200 words, no pasted file dumps.

### Context hygiene
- After WP0, read only the current work package in PLAN.md and the files it lists. Targeted reads, small tool output.
- Update `docs/vuln-mgmt/PROGRESS.md` after every package: Done / In progress / Next / Decisions / Known issues.

### File ownership
- `src/core/vuln/templates/**`, `tests/vuln-scenarios/**` → scenario-author.
- Other `src/**`, `tests/**`, `e2e/**` → implementer, per package file list.
- `docs/vuln-mgmt/DESIGN.md`, `PLAN.md`, `CLAUDE.md`, `.claude/agents/**` → coordinator only.
- Never run two agents on the same file at the same time; sequence them.

### Commits
One logical commit per package, conventional message (`feat(vuln): ...`, `test(vuln): ...`, `docs(vuln-mgmt): ...`), made by the coordinator after reviewer PASS with typecheck + tests + build green.

### Resume protocol
A fresh session reads `CLAUDE.md`, `docs/vuln-mgmt/PROGRESS.md`, and only the next work package in PLAN.md. Nothing else until the package requires it.

### Guardrails
Synthetic data only; fictional vuln ids `SIMVULN-YYYY-NNNNN` (DESIGN §9); offline static site; no new dependencies; keyboard, screen reader, 360 px, reduced motion; existing SOC content and scores unchanged; CI green.

Do not enable experimental agent teams.
