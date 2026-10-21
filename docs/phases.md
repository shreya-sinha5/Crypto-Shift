# phases.md — Project Phases

Durations are relative and adjustable. Scale to your actual timeline; keep the order and exit criteria.

## Overview

| Phase | Name | Goal | Relative effort |
|---|---|---|---|
| 0 | Foundations | Repo, demo target, schemas, literature | 10% |
| 1 | Ingestion and AST linking | CBOM → AST nodes | 15% |
| 2 | Enrichment and risk | Roles, context, prioritization | 15% |
| 3 | Transformation | Templates, LLM gateway, validator, codegen | 20% |
| 4 | Verification | Track A and Track B | 20% |
| 5 | CLI and CI plugin | End-to-end pipeline in GitHub Actions | 8% |
| 6 | Control Centre | Review and approve UI | 7% |
| 7 | Evaluation and delivery | Demo, metrics, report, viva prep | 5% |

Phases 3 and 4 are the heart of the project. Protect their time.

---

## Phase 0 — Foundations

**Tasks**
- Create repo and layout from Architecture.md; set up formatting, linting, CI skeleton.
- Choose and pin a demo target: a small open-source Java repo with real RSA/ECC usage (record the commit hash).
- Generate or curate a CycloneDX CBOM for it (try CBOMkit; fall back to a hand-curated CBOM).
- Write JSON Schemas for all artifacts.
- Read in full: Zhang (AQuA), the 2026 LLM-migration paper (arXiv:2606.07341), Näther et al. (IEEE Access 2024). Write a one-page positioning note.
- Confirm Bouncy Castle version and FIPS 203/204 support; download NIST KAT vectors.

**Exit criteria:** repo builds; demo repo and CBOM committed; schemas reviewed; positioning note written.

## Phase 1 — Ingestion and AST Linking

**Tasks**
- CBOM parser (CycloneDX) → internal finding objects.
- Java parser adapter using JavaParser; map file/line to AST node.
- Optional Semgrep bootstrap (only if time allows).

**Exit criteria:** ≥ 95% of CBOM findings on the demo repo linked to the correct AST node; unlinked findings reported explicitly.

## Phase 2 — Enrichment and Risk

**Tasks**
- Role classifier (key exchange / signature / symmetric / hash) using AST context and call chain.
- Lightweight call-context extraction; flag indirect usage.
- Risk scorer on three axes (sensitivity, criticality, lifespan) with an explainable breakdown.
- Emit `enriched_cbom.json`.

**Exit criteria:** role correct on a hand-labelled sample from the demo repo; risk breakdown visible per finding.

## Phase 3 — Transformation

**Tasks**
- Template registry format; write 5–10 templates (for example RSA key exchange → hybrid ECDH+ML-KEM; RSA/ECDSA signature → dual classical + ML-DSA; symmetric/hash left untouched or flagged).
- Validator: parameter allowlist and veto rules.
- LLM gateway: enum-constrained output, retry-once policy, `needs_human` fallback.
- Codegen: AST-preserving patch with signature preservation.

**Exit criteria:** at least 3 distinct findings on the demo repo transformed end-to-end into compilable patches; LLM never produces free-form code; validator veto demonstrated with a negative test.

## Phase 4 — Verification

**Tasks**
- Track A: differential runner (capture legacy I/O, replay on transformed), diff-scope check.
- Track B: NIST KAT conformance for each binding; parameter linter (allowlist, authenticated encryption, no nonce reuse, hedged where required).
- Stretch: one or two known-attack-pattern rules (for example skippable-branch security step) with tests.
- `verification_report.json` with A and B recorded separately.

**Exit criteria:** both tracks run on every candidate; a deliberately broken candidate is caught by Track B while passing Track A (this is the key demonstration).

## Phase 5 — CLI and CI Plugin

**Tasks**
- Typer CLI: `scan`, `enrich`, `transform`, `verify`, `pr`.
- GitHub Action wrapping the CLI; artifacts uploaded per run.
- PR creation via PyGithub with the required description template; no merge rights.

**Exit criteria:** a push to the demo repo triggers the workflow, produces artifacts, and (after approval) opens a PR containing diff, rationale, and both tracks' results.

## Phase 6 — Control Centre

**Tasks**
- Streamlit app reading artifacts: backlog (sorted by risk), finding detail, side-by-side diff, Track A/B results.
- Approve/reject writes `decision.json`; `pr` consumes it.
- Simple progress view (percent migrated, remaining by risk).

**Exit criteria:** a reviewer can go from backlog to approved decision without touching the CLI; the UI imports no engine code.

## Phase 7 — Evaluation and Delivery

**Tasks**
- Run the full pipeline on the pinned demo repo; record metrics (linkage rate, pass rates, overhead, review time vs manual estimate).
- Record demo video and a backup of all artifacts.
- Final report: problem, gap (with verified citations), architecture, results, honest limitations.
- Viva prep: what we solve, what we don't, why hybrid, why two tracks, why LLM is constrained.

**Exit criteria:** reproducible demo from the pinned commit; report and slides consistent with the limits stated in PRD.md.

---

## Cut Order (if time runs short)

Cut from the bottom; never cut the items marked protected.

1. GitLab/Jenkins plugins (already roadmap)
2. Shadow-run harness
3. Attack-pattern screening (keep one illustrative rule if possible)
4. Semgrep fallback scanner
5. Progress dashboard polish
6. Second parser language (already roadmap)
7. **Protected:** CBOM ingestion, AST linking, template transformation, Track A, NIST KAT conformance, parameter linter, human approval gate, GitHub Action end-to-end.

## Roadmap (post-MVP, not committed)

C/C++ adapter (libclang, liboqs/OpenSSL+OQS), GitLab CI component, Jenkins plugin, role-based Control Centre (1LOD/2LOD/3LOD), SOX/SOC-mapped audit export, regulatory-deadline calendar, COBOL/mainframe adapter, expanded attack-pattern database, dudect-style timing tests.

## Team Split (suggestion, adjust freely)

| Area | Suggested owner focus |
|---|---|
| Ingestion, parsers, enrichment | Member 1 |
| Registry, LLM gateway, validator, codegen | Member 2 |
| Verification (Track A and B) | Member 3 |
| CLI, CI plugin, Control Centre, delivery | Member 4 |
| Shared | Schemas, demo repo, report, viva prep |
