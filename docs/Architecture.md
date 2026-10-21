# CryptoShift — Architecture

## 1. Design Principles

1. **CBOM-first, not scan-first.** Detection is a solved input; the engineering effort goes into enrichment, transformation, and verification.
2. **Hybrid by default.** Classical + PQC combined; never a hard cutover.
3. **LLM proposes, deterministic code disposes.** The model selects from enumerated templates; validators can veto.
4. **Two independent verification tracks.** Functional equivalence and cryptographic assurance are different properties.
5. **Headless engine, human-governed interface.** The engine proposes; a person approves.
6. **Atomic, reversible changes.** One transformation, one PR, one revert.
7. **Language-agnostic core.** Parsers are adapters behind a common IR.

## 2. System Overview

```
┌────────────────────────────────────────────────────────────────────┐
│ 1. INGESTION                                                        │
│  CycloneDX CBOM (CBOMkit or curated) ─┐                             │
│  Fallback: Semgrep bootstrap scan ────┤→ locate files/lines         │
│  Parser adapter (JavaParser for MVP) ─┘→ link finding → AST node    │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│ 2. SEMANTIC ENRICHMENT                                              │
│  role classifier · call/data-flow context · indirect-usage tracing  │
│  risk scorer (sensitivity × criticality × lifespan)                 │
│  → enriched_cbom.json                                               │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│ 3. TRANSFORMATION                                                   │
│  template registry (language, library, role) → pattern              │
│  LLM: schema-constrained template selection + parameter choice      │
│  rule-based validator (veto) → hybrid wrapper codegen               │
│  → candidate.patch + rationale.json                                 │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│ 4. VERIFICATION (both tracks must pass)                             │
│  Track A: differential tests · diff-scope check · (shadow-run)      │
│  Track B: NIST KATs · parameter linter · attack-pattern screening   │
│  → verification_report.json (A and B recorded separately)           │
└──────────────────────────────┬─────────────────────────────────────┘
                               ▼
┌────────────────────────────────────────────────────────────────────┐
│ 5. DELIVERY                                                         │
│  human approval gate (Control Centre) → atomic PR → audit record   │
└────────────────────────────────────────────────────────────────────┘
```

## 3. Deployment Topology

```
        CryptoShift Core Engine (CLI)
        scan | enrich | transform | verify | pr
                 │                    │
     local terminal            CI/CD plugin layer
     (ad-hoc, debug)           GitHub Action (MVP)
                               GitLab CI / Jenkins (roadmap)
                                      │
                                      ▼
                          Pipeline artifacts (integration contract)
                          enriched_cbom · candidates · reports · audit
                                      │
                                      ▼
                          Control Centre (Streamlit for MVP)
                          reads artifacts only; never runs engine logic
```

The Control Centre is a **reader and decision surface**. Approval writes a small decision file (for example `decisions/<id>.json`) that the `pr` command consumes. No engine logic lives in the UI.

## 4. Components

| Component | Responsibility | MVP implementation |
|---|---|---|
| `ingest` | Parse CycloneDX CBOM; resolve file/line references; optional Semgrep bootstrap | Python, CycloneDX JSON |
| `parsers/java` | Source → AST; map finding to node | JavaParser (JVM helper invoked by CLI) |
| `enrich` | Role classification, context, risk score | Python + lightweight heuristics |
| `registry` | Versioned template store | YAML/JSON files, one per (language, library, role) |
| `llm_gateway` | Structured tool-use call; returns enum choices only | Anthropic API, JSON schema enforced |
| `validator` | Deterministic allowlist and veto | Pure Python, no LLM |
| `codegen` | Fill template, emit patch | Template engine, AST-preserving edits |
| `verify/trackA` | Differential runner, diff-scope check | JUnit + Python orchestrator |
| `verify/trackB` | KAT runner, linter, pattern matcher | Python + NIST vectors |
| `delivery` | Branch, commit, PR, audit record | PyGithub |
| `control_centre` | Backlog, diff review, approve/reject, progress | Streamlit |

## 5. Data Contracts (artifacts)

All inter-component data are JSON artifacts with a `schema_version` field.

**`enriched_cbom.json` (per finding)**
```json
{
  "finding_id": "f-0042",
  "cbom_ref": "component bom-ref from CycloneDX",
  "file": "src/main/java/.../KeyService.java",
  "line": 88,
  "ast_node": "MethodCallExpr:KeyPairGenerator.getInstance",
  "algorithm": "RSA",
  "key_size": 2048,
  "role": "signature | key_exchange | symmetric | hash",
  "role_confidence": 0.0,
  "call_context": ["caller chain, abbreviated"],
  "risk": {"sensitivity": 0, "criticality": 0, "lifespan": 0, "score": 0}
}
```

**`candidate.json`**: `finding_id`, `template_id`, `parameters` (enum values), `patch`, `rationale`, `llm_trace` (prompt hash, chosen enums), `validator_result`.

**`verification_report.json`**: `trackA` {tests_run, diffs, scope_ok}, `trackB` {kat_results, lint_results, pattern_flags}, `overall` (pass only if both pass).

**`decision.json`**: `finding_id`, `reviewer`, `decision`, `notes`, `timestamp`.

## 6. Transformation Model

- **Template key:** `(language, library, role)`, for example `(java, bouncycastle, key_exchange)`.
- **Hybrid patterns:**
  - Key exchange: classical shared secret (ECDH) and ML-KEM shared secret combined through a KDF (HKDF) with a context label.
  - Signatures: classical signature + ML-DSA signature; verification requires both to pass.
- **Signature preservation:** the old method signature is kept; the wrapper delegates to the hybrid implementation.
- **LLM contract:** input = enriched finding; output = `{template_id, parameter_set}` chosen from enumerated values. Free-form code output is rejected.

## 7. Verification Model

| Track | Question answered | Checks |
|---|---|---|
| A: functional | Does it behave like the original? | Replayed I/O pairs, diff-scope (only crypto call sites and wrapper changed), optional shadow-run |
| B: assurance | Is the crypto configured and bound correctly? | NIST KATs for ML-KEM/ML-DSA/SLH-DSA, parameter linter, known-attack-pattern screening, LLM veto |

Overall result is pass only if both tracks pass. Failures are stored as artifacts, never silently dropped. **Track B narrows risk to documented failure classes; it does not prove security.**

## 8. Tech Stack

| Layer | Choice | Notes |
|---|---|---|
| CLI | Python 3.10+ (Typer or Click) | Orchestrator |
| Java analysis | JavaParser (JDK 17+) | Type resolution for MVP |
| Bootstrap scan | Semgrep | Fallback only |
| CBOM format | CycloneDX 1.6+ CBOM | Input contract |
| PQC libraries | Bouncy Castle PQC provider (Java); liboqs, OpenSSL 3.x + OQS provider (roadmap, C/C++) | Verify exact version and FIPS 203/204 support before pinning |
| LLM | Anthropic Claude API, structured tool-use | Enum-constrained output |
| Testing | JUnit, pytest | Differential + unit |
| Delivery | Git, PyGithub, GitHub Actions | |
| Control Centre | Streamlit | Reads artifacts from disk |

## 9. Repository Layout (proposed)

```
cryptoshift/
  cli/                 # Typer entrypoints
  ingest/              # CBOM parsing, fallback scan
  parsers/java/        # JavaParser adapter (JVM helper)
  enrich/              # role classifier, risk scorer
  registry/templates/  # YAML templates (versioned)
  llm_gateway/         # schema, prompts, client
  validator/           # allowlist, veto rules
  codegen/             # patch generation
  verify/trackA/
  verify/trackB/       # kat vectors, linter, patterns
  delivery/            # PR, audit
  control_centre/      # Streamlit app
  schemas/             # JSON schemas for all artifacts
  demo/                # target repo pin, CBOM, walkthrough
  docs/                # PRD, Architecture, rules, phases, memory
```

## 10. CI/CD Integration (MVP)

A GitHub Action wraps the CLI: checkout → run `scan`, `enrich` → upload artifacts → (after human approval outside the workflow) run `transform`, `verify`, `pr`. Triggers: push, PR open, schedule, manual dispatch. The workflow never merges.

## 11. Security and Governance

- Engine credentials scoped to branch creation and PR opening; no merge permission.
- Secrets only from CI secret store; never in artifacts or logs.
- LLM receives code snippets only as needed; log prompt hashes, not secrets.
- Every automated decision recorded with template id, parameters, validator result, and reviewer decision.

## 12. Extensibility

- New language = new parser adapter implementing the same IR + new templates. Detection, transformation, and verification layers are unchanged.
- COBOL/mainframe is a roadmap adapter, not an MVP promise.
- New PQC algorithm (for example FN-DSA, HQC) = new template entries and KAT vectors, no engine rewrite (cryptographic agility).

## 13. Known Limits

Cannot fix network-layer fragmentation, hardware/HSM constraints, closed-source visibility, or algorithm maturity. Cannot prove implementations free of side-channel or fault-injection weaknesses.
