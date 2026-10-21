# build_prompt.md — Prompt Layout for Generating CryptoShift (with CI/CD Integration)

Use this with an AI coding assistant (Claude Code, Cursor, etc.). Do **not** paste everything as one mega-prompt. Load context once, then run the phase prompts one at a time and verify each before moving on.

## 0. How to Use

1. Put these files in `docs/` of the repo: `PRD.md`, `Architecture.md`, `rules.md`, `phases.md`, `memory.md`.
2. Start a session with the **Master Context Prompt** (section 1).
3. Run **Scaffold** (section 2), then **Phase prompts** (section 3) in order.
4. Run the **CI/CD Integration Prompt** (section 4) after Phase 4, then again to finalize after Phase 6.
5. After every phase run the **Self-Audit Prompt** (section 6) and update `docs/memory.md`.
6. If any acceptance test fails, fix it before continuing. Never skip forward.

---

## 1. Master Context Prompt (paste at session start)

```
You are a senior engineer building CryptoShift, an automated post-quantum
cryptographic migration engine, as a 4-person student minor project.

READ FIRST, IN ORDER: docs/rules.md, docs/memory.md, docs/Architecture.md,
docs/PRD.md, docs/phases.md. Treat rules.md as hard constraints.

WHAT WE BUILD
A headless CLI (`cryptoshift scan | enrich | transform | verify | pr`) that
consumes a CycloneDX CBOM, links findings to Java AST nodes, enriches them with
role and risk, transforms code into hybrid classical+PQC form via a template
registry, verifies on two tracks (A functional, B cryptographic assurance), and
opens one atomic PR per change after human approval. It runs locally and inside
GitHub Actions. A separate Streamlit Control Centre reads artifact files only.

MVP SCOPE (recommended, pending team confirmation): Java only, 5-10 templates,
Bouncy Castle PQC provider, JUnit differential tests, NIST KATs, parameter
linter, one GitHub Action, one Streamlit dashboard.

NON-NEGOTIABLE
- Never write or modify cryptographic primitives; call vetted libraries only.
- The LLM only selects template_id and enum parameters; never emits code.
- Hybrid by default. No unattended merges. Both tracks must pass.
- Do not claim the output is proven secure.
- If unsure about an API, version, or standard detail, say so and verify.
- Do not cite "QCecuring".

WORKING STYLE
- Work in small steps. For each task: state the plan, implement, run tests,
  show results. Stop and ask when a stop condition in rules.md section 10 hits.
- Every artifact has a JSON Schema in schemas/ and a schema_version.
- Fail loudly with explicit `needs_human`; never silently default.
- Write tests first for validators, linters, and schema checks.

OUTPUT CONTRACT FOR EVERY TASK
1. Files created/changed (paths)
2. How to run it (exact commands)
3. Tests added and their results
4. Acceptance criteria: met / not met, with evidence
5. Open questions or assumptions
```

---

## 2. Scaffold Prompt

```
TASK: Create the repository scaffold from docs/Architecture.md section 9.

DELIVERABLES
- Directory layout, pyproject.toml (Python 3.10+, Typer, pydantic, jsonschema,
  pytest, ruff, black, PyGithub, anthropic, streamlit), a Java helper module
  (Maven or Gradle, JDK 17, JavaParser) for AST linking.
- schemas/*.json for enriched_cbom, candidate, verification_report, decision,
  audit_record (each with schema_version).
- cryptoshift CLI skeleton with the five subcommands returning "not implemented"
  and correct exit codes (see section 4.3).
- Makefile targets: setup, lint, test, demo.
- Pre-commit: ruff, black, jsonschema validation of sample artifacts.
- A minimal CI workflow (lint + tests only) as .github/workflows/ci.yml.

ACCEPTANCE
- `make setup && make lint && make test` passes on a clean checkout.
- CI workflow is green on push.
- No engine logic yet; module boundaries match rules.md section 4.
```

---

## 3. Phase Prompts

Each uses the same shape. Replace nothing in the constraints.

### Phase 1 — Ingestion and AST Linking

```
TASK: Implement `cryptoshift scan`.

INPUTS: CycloneDX 1.6+ CBOM JSON; path to a Java repo checkout.
DO
- Parse cryptographic-asset components from the CBOM into internal Finding
  objects (algorithm, key size, location evidence, bom-ref).
- Implement the JavaParser adapter (JVM helper) that maps file+line to an AST
  node and returns node type and enclosing method/class.
- Report unlinked findings explicitly with a reason code.
- Optional (only if trivial): Semgrep bootstrap when no CBOM is supplied.
OUTPUT: artifacts/scan.json validated against schema.
ACCEPTANCE
- >= 95% of findings on the pinned demo repo linked to the correct AST node
  (hand-check a labelled sample and report the number).
- Malformed CBOM produces a clear error, not a crash.
TESTS: unit tests for CBOM parsing, golden-file test for AST linking.
DO NOT: use regex-only source matching; add engine logic to the UI.
```

### Phase 2 — Enrichment and Risk

```
TASK: Implement `cryptoshift enrich`.

DO
- Role classifier: key_exchange | signature | symmetric | hash | unknown, using
  AST context and call chain (not the API name alone). Emit role_confidence.
- Call-context extraction (caller chain, abbreviated) and flag indirect usage.
- Risk scorer on three axes: data sensitivity, system criticality, asset
  lifespan (HNDL exposure). Output the per-axis breakdown, not one opaque score.
- Unknown role => status needs_human.
OUTPUT: artifacts/enriched_cbom.json.
ACCEPTANCE
- Role correct on a hand-labelled sample from the demo repo (report accuracy).
- Every finding has an explainable risk breakdown.
TESTS: table-driven tests per role; negative tests for ambiguous cases.
```

### Phase 3 — Transformation

```
TASK: Implement `cryptoshift transform`.

DO
- Template registry: YAML per (language, library, role). Write 5-10 templates,
  for example: RSA key exchange -> hybrid ECDH+ML-KEM via HKDF with a context
  label; RSA/ECDSA signature -> dual classical + ML-DSA (verify requires both).
  Templates for symmetric/hash findings: leave untouched or flag.
- Validator (pure, deterministic): parameter allowlist and veto rules. No LLM,
  no network, no randomness.
- LLM gateway: Anthropic structured tool-use. Input = enriched finding + list
  of allowed template_ids and enums. Output JSON schema = {template_id,
  parameters (enums only), rationale}. Invalid output: retry once, then
  needs_human. Log prompt_hash and chosen enums only.
- Codegen: AST-preserving patch; preserve the original method signature via a
  wrapper; touch only the call site and wrapper.
OUTPUT: artifacts/candidates/<finding_id>/candidate.json + patch.
ACCEPTANCE
- >= 3 distinct findings on the demo repo become compilable patches.
- A negative test proves the validator vetoes a disallowed parameter set even
  when the model "chooses" it.
- The LLM path cannot produce free-form code (test by attempting to inject it).
DO NOT: let codegen accept raw model text; generate crypto primitives.
```

### Phase 4 — Verification

```
TASK: Implement `cryptoshift verify`.

TRACK A (functional)
- Differential runner: capture legacy I/O pairs, replay on transformed code.
- Diff-scope check: fail if the patch touches anything beyond the call site and
  its wrapper.
TRACK B (cryptographic assurance)
- NIST KAT conformance for every generated binding (ML-KEM, ML-DSA as used).
- Parameter linter: approved parameter sets only, authenticated encryption
  only, no nonce/IV reuse, no ECB, hedged mode where required, no hardcoded
  keys/seeds.
- Stretch: one or two known-attack-pattern rules (for example a security-
  critical step reduced to a skippable single branch) with tests.
OUTPUT: verification_report.json with trackA and trackB recorded separately;
overall = pass only if both pass. Failures are stored, never dropped.
ACCEPTANCE (key demonstration)
- A deliberately broken candidate (for example weak parameter set or nonce
  reuse) PASSES Track A but is CAUGHT by Track B.
- KAT results are in the report for every binding.
```

### Phase 5 — Delivery (`pr`) and CLI Hardening

```
TASK: Implement `cryptoshift pr` and finish CLI behavior.

DO
- Consume decision.json; refuse to open a PR without decision == approved.
- Branch per finding: cryptoshift/<finding_id>. One finding, one PR.
- PR description from a template: finding, role, template id, parameters,
  rationale, Track A results, Track B results, revert instructions.
- Write audit_record.json for every decision and outcome.
- Implement exit codes and --json output for pipeline use (section 4.3).
ACCEPTANCE
- No code path merges a PR. Token scope documented.
- Unapproved or missing decision => non-zero exit, no branch created.
```

### Phase 6 — Control Centre

```
TASK: Build the Streamlit Control Centre.

DO
- Read artifacts from a configurable directory only. Import NO engine modules.
- Views: backlog sorted by risk with per-axis breakdown; finding detail;
  side-by-side diff; Track A and Track B results; approve/reject with notes;
  simple progress view (percent migrated, remaining by risk).
- Approve/reject writes decisions/<finding_id>.json (schema-validated).
ACCEPTANCE
- Reviewer goes from backlog to an approved decision without the CLI.
- A test/grep check proves control_centre has no imports from engine packages.
```

### Phase 7 — Evaluation and Demo

```
TASK: Produce reproducible evaluation.

DO
- Script that runs the full pipeline on the pinned demo repo commit and emits a
  metrics report: linkage rate, role accuracy, transformation count, Track A/B
  pass rates, size/latency overhead of hybrid wrappers, reviewer time estimate
  versus a manual baseline (label estimates as estimates).
- Demo script and fallback artifact bundle for offline presentation.
ACCEPTANCE: `make demo` reproduces the report from a clean checkout.
```

---

## 4. CI/CD Integration Prompt (core of this request)

```
TASK: Integrate CryptoShift into GitHub Actions as a pipeline-native tool.

PRINCIPLES
- The workflow proposes and verifies; a human approves; nothing merges.
- The CLI is the only logic. Workflows are thin wrappers.
- Artifacts are the integration contract with the Control Centre.

4.1 WORKFLOWS TO CREATE (.github/workflows/)
A) cryptoshift-scan.yml
   Triggers: push, pull_request, schedule (nightly cron), workflow_dispatch.
   Steps: checkout -> set up Python and JDK 17 -> install cryptoshift ->
   obtain CBOM (input file in repo, or generated by a CBOM tool step) ->
   `cryptoshift scan` -> `cryptoshift enrich` -> upload artifacts
   (enriched_cbom.json, scan.json) -> post a short PR comment / job summary
   with counts by risk tier.
   Permissions: contents: read, pull-requests: write (comment only).
B) cryptoshift-apply.yml
   Trigger: workflow_dispatch with inputs (finding_ids), or a push touching
   decisions/*.json. Uses a GitHub Environment with required reviewers as an
   additional approval gate.
   Steps: checkout -> install -> download scan artifacts -> `cryptoshift
   transform` -> `cryptoshift verify` (fail job if overall != pass) -> upload
   candidates and verification reports -> `cryptoshift pr` only for findings
   with decision == approved.
   Permissions: contents: write (branch push), pull-requests: write. No merge.
C) ci.yml (from scaffold): lint, unit tests, schema validation, import-boundary
   check (control_centre must not import engine code).

4.2 REQUIREMENTS
- Pin third-party actions by commit SHA; check current versions before pinning.
- Secrets (LLM API key, tokens) only from repository/environment secrets; never
  echoed; mask in logs. Fork PRs must not receive secrets.
- Cache pip and Maven dependencies. Set timeouts and concurrency groups so runs
  for the same ref cancel superseded runs.
- Branch protection (documented in docs/ci-setup.md): require status checks
  `ci` and `cryptoshift/verify`, require PR review, block direct pushes.
- Note for docs: PRs created with the default GITHUB_TOKEN do not trigger other
  workflows; document whether to use a GitHub App or PAT so required checks
  run on generated PRs, and verify this behavior before relying on it.
- Provide a reusable composite action (action.yml) that wraps the CLI so other
  repos can adopt it with a few lines. Roadmap: GitLab CI component, Jenkins.

4.3 CLI CONTRACT FOR PIPELINES
Exit codes: 0 success; 1 tool/config error; 2 verification failed (Track A or
B); 3 findings need human input (needs_human); 4 approval missing/denied.
Flags: --json (machine output), --artifacts-dir, --config, --dry-run.
All commands are idempotent and safe to re-run.

4.4 PR TEMPLATE
Finding, role, template id, parameters, rationale, Track A results, Track B
results, overhead numbers, revert instructions, "Generated by CryptoShift;
requires human review".

ACCEPTANCE
- Push to the demo repo triggers workflow A and uploads artifacts.
- Approving a finding (decision file or environment approval) runs workflow B,
  which opens a PR containing diff, rationale, and both tracks' results.
- A candidate failing Track B fails the job and opens no PR.
- No workflow or token can merge.
- docs/ci-setup.md lets a new repo adopt the action in under 15 minutes.
```

---

## 5. Definition of Done (whole project)

- [ ] `make setup lint test` and `make demo` pass on a clean checkout.
- [ ] Pinned demo repo: >= 3 findings transformed, verified on both tracks, opened as PRs after approval.
- [ ] Broken-candidate demo: passes Track A, caught by Track B.
- [ ] LLM cannot inject free-form code (tested).
- [ ] Validator veto tested.
- [ ] Control Centre imports no engine code (checked in CI).
- [ ] No merge capability anywhere.
- [ ] Docs match reality: PRD, Architecture, rules, phases, memory updated.
- [ ] Limitations stated: no proof of security, no network/HSM/closed-source coverage.

## 6. Self-Audit Prompt (run after each phase)

```
Audit your last phase against docs/rules.md and docs/Architecture.md.
List any violation of: crypto-primitive rule, LLM boundary, hybrid-by-default,
human-approval gate, two-track verification, module import boundaries, schema
validation, silent defaults, weakened or deleted tests, unverified claims.
For each violation: file, line, fix. Then re-run tests and report results.
Update docs/memory.md (status, decisions, open questions).
```

## 7. Reject-on-Sight Patterns

- Model output written directly into source files.
- Regex-based rewriting of Java.
- A test skipped, mocked, or loosened to pass.
- Hard cutover to pure PQC without policy opt-in.
- Any merge, auto-merge, or bypass of branch protection.
- Secrets in code, logs, artifacts, or prompts.
- Claims like "guarantees quantum-safety."
- Fabricated citations, versions, or benchmark numbers.

## 8. Per-Task Prompt Template

```
CONTEXT: docs/rules.md, docs/Architecture.md, docs/memory.md are loaded.
TASK: <one sentence>
INPUTS: <files, artifacts, commands>
CONSTRAINTS: <specific rules from rules.md that apply>
DELIVERABLES: <paths>
ACCEPTANCE: <measurable checks>
TESTS: <what to add and run>
STOP AND ASK IF: <conditions>
```
