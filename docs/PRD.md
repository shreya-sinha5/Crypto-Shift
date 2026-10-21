# CryptoShift — Product Requirements Document

> Automated Post-Quantum Cryptographic Migration Engine
> Status: Draft v1 · Scope target: minor project MVP, with full vision documented

---

## 1. Project Details

| Field | Value |
|---|---|
| Project title | CryptoShift — An Automated Post-Quantum Cryptographic Migration Engine |
| Institution | The National Institute of Engineering (NIE), Mysuru |
| Batch | C14 (synopsis dated 21 September 2026) |
| Team | Shreya Sinha, Ritika Tiwari, Palak Agarwal, Rachana S |
| Internal guide | K M Aishwarya, Assistant Professor |
| Delivery form | Headless CLI + CI/CD plugin, governed through a separate Control Centre web interface |

---

## 2. Problem

NIST finalized the first post-quantum cryptography (PQC) standards in August 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA). Enterprise codebases in banking, critical infrastructure, and defense still contain deeply entangled, hardcoded RSA, ECC, and DH usage.

- Existing tools (CBOM scanners such as IBM's CBOMkit) **find** vulnerable crypto. They do not **fix** it.
- Manual refactoring is slow, error-prone, and risks breaking production logic.
- "Harvest Now, Decrypt Later" means data encrypted today is already at risk.
- Regulatory clocks are running: NIST IR 8547 (2030 deprecation, 2035 disallowance), NSA CNSA 2.0 (Jan 2027 acquisition gate), EO 14412/14413 (end-2030 key establishment, end-2031 signatures).

## 3. What CryptoShift Is

A context-aware code transformation engine that:

1. **Consumes** an existing CycloneDX CBOM (or bootstraps a minimal one) instead of rebuilding detection.
2. **Enriches** each finding with AST linkage and control/data-flow awareness, so it knows the semantic role of each crypto call.
3. **Transforms** the code into a **hybrid classical + PQC** form using a vetted template registry, with the LLM restricted to template selection.
4. **Verifies** each change on two independent tracks: functional equivalence, and cryptographic assurance.
5. **Delivers** each change as a small, atomic, revertible pull request, only after explicit human approval.

**One-line pitch:** CBOM scanners tell you where the problem is; consultants tell you what to do; CryptoShift is the layer that actually does it, safely and with auditable evidence.

## 4. Target Users

| Persona | Need | What CryptoShift gives them |
|---|---|---|
| Platform / infra engineer | Changes that don't break CI/CD or add latency regressions | Headless CLI + CI plugin, atomic diffs |
| Security / compliance engineer | Auditable migration trail for regulators | Track A/B evidence per change, exportable report |
| CISO / engineering leadership | Realistic, risk-bounded path to 2030/2031 deadlines | Risk-prioritized backlog, deadline-aware progress view |
| Release manager | Small, reviewable, revertible diffs | One PR per transformation, one-click revert |
| Risk / compliance function (2LOD) | Evidence aligned to SOX/SOC expectations | Policy config, audit records (roadmap: role-based tiers) |

## 5. Goals and Non-Goals

### Goals
1. Detect-and-link: map CBOM findings to exact AST nodes with role tagging.
2. Generate hybrid (classical + PQC) replacements through a template-governed engine, preserving existing function signatures where possible.
3. Verify every change on two tracks (functional + cryptographic assurance).
4. Deliver atomic, human-approved, revertible PRs.
5. Run as a CLI locally and as a CI/CD plugin, governed via a Control Centre.

### Non-Goals (stated honestly)
- Proving that generated code is cryptographically unbreakable. No automated tool can; we only close known, documented failure classes.
- Zero-human-in-the-loop deployment. Nothing merges unattended.
- Writing or modifying cryptographic primitives. We call vetted libraries only.
- Network-layer fixes (MTU, fragmentation, firewalls).
- Silicon/HSM-level constraints on low-power IoT/SCADA devices.
- Visibility into closed-source, obfuscated, or proprietary binaries (we inherit this blind spot from CBOM tooling).
- COBOL / mainframe support in v1 (architecture is adapter-based so it can be added later).

## 6. Scope: MVP vs Full Vision

The full vision is large. The buildable MVP must still prove the core claim (real code, real transformation, real verification, real human approval).

| Area | MVP (build) | Full vision (documented, not built) |
|---|---|---|
| Languages | Java only | + C/C++, later COBOL/mainframe |
| Input | CBOM from CBOMkit or a small curated CycloneDX CBOM | + first-party fallback scanner at scale |
| Enrichment | AST linking + lightweight role classifier | Full control/data-flow graph, CodeQL-grade tracing |
| Transformation | 5–10 hardcoded templates, Bouncy Castle PQC provider | Full (language, library, role) registry, liboqs, OpenSSL+OQS |
| Track A | JUnit differential testing | + shadow-run harness |
| Track B | NIST KAT conformance + parameter linter | + side-channel / fault-pattern DB, dudect-style timing tests |
| Delivery | CLI + one GitHub Action | + GitLab CI component, Jenkins plugin |
| Control Centre | Single Streamlit dashboard: backlog, diff review, approve | Role-based 1LOD/2LOD/3LOD tiers, SOX/SOC-mapped audit export |

**Do not cut:** NIST KAT conformance. It is the cheapest feature that separates this project from "an LLM rewrote some code."

## 7. Functional Requirements

**FR1 — CBOM ingestion and semantic enrichment.** Ingest CycloneDX CBOM as the primary input. Link each finding to its AST node. Build role context (key exchange / signature / symmetric / hash) from flow, not API name alone. Output an AST-linked, role-tagged enriched CBOM.

**FR2 — Risk prioritization.** Score findings on three axes: data sensitivity, system criticality, asset lifespan (HNDL exposure). Output a prioritized backlog, not a flat list.

**FR3 — Transformation engine.** Template registry keyed by (language, library, role). Hybrid mode by default (for example ECDH + ML-KEM combined via KDF; classical + ML-DSA dual signature). LLM selects and parameterizes from an enumerated, schema-validated set only. Preserve function signatures so callers don't change.

**FR4 — Verification harness (two tracks, both must pass).**
- Track A, functional: differential testing (legacy vs transformed on the same inputs), diff-scope check confirming only crypto call sites changed.
- Track B, cryptographic assurance: NIST KAT conformance; deterministic parameter/config linter (approved parameter sets, no ECB, authenticated encryption, no nonce reuse); known-attack-pattern screening (stretch); LLM output veto by rule-based validator.

**FR5 — Change delivery.** One atomic PR per transformation with diff, rationale, and Track A/B evidence. PR opens only after Control Centre approval.

**FR6 — Reporting and audit trail.** Exportable status report; per-change audit record with Track A and Track B results stored separately.

**FR7 — Extensible coverage.** Parser-adapter pattern; language-agnostic IR between layers.

**FR8 — Deployment model.** Headless CLI (`cryptoshift scan | enrich | transform | verify | pr`) → CI/CD plugin wrappers → pipeline artifacts → Control Centre that reads artifacts only and never re-implements engine logic.

**FR9 — Three Lines of Defense integration (roadmap).** 1LOD engineers run and propose; 2LOD sets policy and views deadline dashboards; 3LOD has read-only audit access. Audit records tagged to COSO/SOC Trust Services Criteria.

## 8. Non-Functional Requirements

- **Safety over speed.** A missed detection is bad; a wrongly transformed working call site is worse.
- **Auditability.** Every automated decision is traceable and reproducible.
- **Determinism.** Template-driven output is reproducible; the LLM never invents cryptographic logic.
- **Depth over breadth.** One language done properly beats three done shallowly.
- **Least privilege.** Engine has read access to source and write access to a branch only; merge stays human.

## 9. Success Metrics

| Metric | Target (MVP) |
|---|---|
| Detection linkage | ≥ 95% of CBOM findings on the demo repo linked to correct AST nodes |
| Transformation safety | 100% of emitted PRs pass Track A and Track B; zero silent failures |
| KAT conformance | All applicable NIST vectors pass for every generated binding |
| Reviewer effort | Median review time per PR recorded and reported vs manual baseline |
| Demo proof | Before/after on a real open-source Java repo with real RSA/ECC usage, passing both tracks |

## 10. Market Gap (what is and isn't new)

**Already exists (we consume, not compete):** CBOM/detection tools (CBOMkit, CycloneDX schema), NIST-standardized PQC algorithms, vetted libraries (Bouncy Castle, liboqs, OpenSSL+OQS), consultant roadmaps.

**Not yet solved (our target):**
1. Automated, semantic code transformation from a CBOM finding to a verified hybrid-PQC replacement.
2. A verification model that separates "behaves the same" from "is cryptographically sound."
3. A CI/CD-native, continuously running, human-gated migration process.

## 11. Literature Grounding (verified sources)

Confirm authors/venue directly at the source before formal citation.

1. Näther, Herzinger, Gazdag, Steghöfer, Daum, Loebenberger (2024). *Migrating Software Systems towards Post-Quantum Cryptography — A Systematic Literature Review.* IEEE Access 12, 132107–132126. DOI 10.1109/ACCESS.2024.3450306. arXiv:2404.12854.
2. Zhang, L. (2026). *Toward Quantum-Safe Software Engineering: A Vision for PQC Migration* (AQuA framework: detection, semantic refactoring, hybrid verification). ICSE 2026. arXiv:2602.05759.
3. *Empirical Evaluation of Large Language Models for Migration of Code Fragments to Post-Quantum Cryptography* (2026). arXiv:2606.07341. Closest prior work; read in full and position CryptoShift as extending it. (Author attribution came via a secondary source; verify at arxiv.org/abs/2606.07341.)
4. *Assessing and Enhancing Quantum Readiness in Mobile Apps* (2025). arXiv:2506.00790. LLMs handle basic refactoring but fall short on secure, compilable PQC migration.
5. Shaw, A. (2026). *Quantum-Safe Code Auditing.* arXiv:2604.00560. Gap in automated inventory and quantum-aware prioritization.
6. Shaw, A. (2026). *quantum-safe: Bridging the Post-Quantum Production Gap.* arXiv:2605.17061. Quantifies hybrid KEM (11%) and migration tooling (22%) coverage gaps across nine libraries.
7. Jendral, Mattsson, Dubrova (2024). *A Single-Trace Fault Injection Attack on Hedged ML-DSA.* FDTC 2024. Shows a standard-compliant implementation can be broken while signatures still verify, motivating Track B.
8. Ikwuogu et al. (2024), IJCATR 13(12); Kemp, Padbury, Reeves (KPMG, 2026). Financial-sector migration architecture and second-line-of-defense responsibilities.

**Do not cite "QCecuring."** It could not be verified as an existing tool.

## 12. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| LLM proposes an insecure or non-standard parameter | Enumerated, schema-validated choices; rule-based validator has unconditional veto |
| Functional tests pass but crypto is broken | Independent Track B gate; stated limit, not claimed as proof |
| Hybrid mode adds size/latency overhead | Benchmark and report overhead per transformation |
| Scope too large for a 4-person team | MVP slice in §6; cut order defined in phases.md |
| Overclaiming | Limits section and audit output state what is not guaranteed |
| Incomplete language coverage | Adapter architecture; COBOL explicitly Tier 2 |

## 13. Known Limitations (explicitly out of scope)

Network-layer packet engineering, silicon-level constraints, closed-source visibility, PQC algorithm maturity, workforce training, and the open research questions raised by the KPMG paper (cross-sector 2LOD scaling, enterprise-scale cost-effectiveness, hardware-breakthrough regulatory impact).
