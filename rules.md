# rules.md — Rules for AI Assistants and Contributors

Read this before generating or editing anything in CryptoShift. These rules are hard constraints, not suggestions.

## 1. Golden Rules

1. **Never write, modify, or "optimize" cryptographic primitives.** No custom NTT, lattice math, hash, or random generation. Call vetted libraries only.
2. **The LLM never emits free-form cryptographic code into the product.** In the transformation path it selects from enumerated templates and parameter values; nothing else.
3. **Hybrid by default.** No hard cutover to pure PQC unless a template explicitly allows it and a human enabled it in policy.
4. **Nothing merges unattended.** The engine can propose and open PRs after approval; it must not merge.
5. **Both verification tracks must pass.** Never bypass, mock, or weaken a check to make a build green.
6. **Never claim more than we prove.** No wording like "guarantees security" or "quantum-safe" without qualification.
7. **Unsure about an API, version, or standard detail? Verify it. Don't guess.**

## 2. What to Use

| Purpose | Use |
|---|---|
| CBOM format | CycloneDX 1.6+ CBOM JSON |
| Java parsing | JavaParser |
| Bootstrap scan (fallback only) | Semgrep |
| PQC in Java | Bouncy Castle PQC provider (pin exact version, confirm ML-KEM/ML-DSA support in release notes) |
| PQC in C/C++ (roadmap) | liboqs, OpenSSL 3.x with OQS provider |
| KDF for hybrid | HKDF with explicit context label |
| Test vectors | Official NIST KATs for FIPS 203/204/205 |
| Tests | JUnit (Java), pytest (Python) |
| CLI | Typer or Click |
| Delivery | PyGithub, Git |
| LLM | Anthropic API with structured tool-use and JSON schema |
| Control Centre | Streamlit reading artifact files |
| Naming | ML-KEM, ML-DSA, SLH-DSA in code and docs (mention Kyber/Dilithium only as former names) |

## 3. What to Avoid

- Rolling your own crypto, "simplified" implementations, or copying crypto code from blog posts.
- ECB mode, unauthenticated encryption, nonce/IV reuse, hardcoded keys or seeds, `Math.random`/non-cryptographic RNG for anything security-related.
- Deterministic signing mode where hedged mode is the required default.
- Non-constant-time comparison of secrets, MACs, or signatures.
- Skippable single-branch logic around security-critical steps (absorption, seed derivation, verification) when an inlined or checked form is possible.
- Parameter sets outside the approved allowlist (for example weaker-than-policy ML-KEM/ML-DSA levels).
- Regex-only rewriting of source. Transformations go through the AST.
- Bulk rewrites or multi-finding mega-PRs. One finding, one PR.
- Editing files outside the scoped call site and its wrapper.
- Storing secrets, tokens, or private keys in code, artifacts, logs, or prompts.
- Citing "QCecuring" (unverified). Cite only sources listed in memory.md as verified.
- Marketing language that implies proof of security.

## 4. Library and Module Boundaries

**Dependency direction (imports flow downward only):**

```
cli → (ingest, enrich, transform, verify, delivery)
transform → (registry, llm_gateway, validator, codegen)
verify → (trackA, trackB)
control_centre → schemas + artifact files only
```

- `control_centre` must **not** import engine modules. It reads and writes artifact/decision files.
- `llm_gateway` may import `schemas` only. It has no filesystem write access and no ability to call `codegen` directly.
- `validator` is pure and deterministic: no network, no LLM, no randomness.
- `codegen` accepts a validated `{template_id, parameters}` object, never raw model text.
- `parsers/*` implement the shared IR; no parser-specific types leak past `ingest`.
- `verify/trackB` owns KAT vectors and lint rules; other modules may not override its verdict.
- Only `delivery` talks to the Git host.

## 5. LLM Boundary (detailed)

| Allowed | Not allowed |
|---|---|
| Choose `template_id` from the registry list provided in the prompt | Inventing a template or code path |
| Choose parameter values from provided enums | Free-text parameters, custom constants, custom sizes |
| Explain its choice in a short rationale field | Emitting patch text or crypto code |
| Flag "no suitable template" | Guessing when nothing fits (must flag and stop) |

- Output must validate against the JSON schema; on failure, retry once, then mark the finding `needs_human`.
- The validator can veto any choice regardless of model confidence.
- Log `prompt_hash`, chosen enums, validator result. Do not log secrets.
- Temperature low; results should be reproducible for the same input where possible.

## 6. Coding Conventions

- Python 3.10+, type hints required on public functions; format with Black, lint with Ruff.
- Java 17+; follow the target repo's style inside transformed code.
- Every artifact has a JSON Schema in `schemas/` and a `schema_version`.
- Fail loudly: unknown role, unknown algorithm, or missing template → explicit `needs_human` status, never a silent default.
- No global mutable state; pass config explicitly.
- Deterministic outputs: sort keys, stable ordering, fixed seeds in tests.

## 7. Testing Rules

- Every template ships with: a sample input, expected output, a KAT-backed binding test, and a differential test.
- Track B linter rules each need a positive and a negative test case.
- No test may be deleted or weakened without a written reason in the PR description.
- Demo target repo is pinned to a commit hash; results must be reproducible from it.

## 8. Git and PR Rules

- Branch per finding: `cryptoshift/<finding_id>`.
- PR description must include: finding, role, template id, parameters, rationale, Track A results, Track B results, revert instructions.
- Conventional commit messages. No force-push to shared branches.
- Engine tokens have no merge rights.

## 9. Writing and Citation Rules

- State limits plainly: Track B closes documented failure classes; it does not prove security.
- Only cite sources marked verified in memory.md; verify authors/venue at the source before formal citation.
- Do not invent statistics. If a number isn't sourced, don't state it.

## 10. When to Stop and Ask a Human

- A change would touch cryptographic primitives or library internals.
- No template fits, or the validator and LLM disagree repeatedly.
- A Track B check fails and the only "fix" is loosening it.
- Requirements conflict with these rules.
- Anything involving real production credentials or non-demo repositories.
