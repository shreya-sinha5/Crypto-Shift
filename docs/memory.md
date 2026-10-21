# memory.md — CryptoShift Project Memory

Living context file for the team and any AI assistant. Read this first, then rules.md. Update it whenever a decision, status, or source changes. Newest entries go at the top of each log.

## 1. Identity

- **Project:** CryptoShift, an automated post-quantum cryptographic migration engine.
- **Context:** Minor project, NIE Mysuru, batch C14 (synopsis dated 21 Sep 2026). Guide: K M Aishwarya.
- **Related docs:** PRD.md, Architecture.md, rules.md, phases.md. The earlier long-form vision document is PQC_Migration_Engine_PRD.md.

## 2. One-Paragraph Summary

CryptoShift consumes an existing CycloneDX CBOM, links each finding to its AST node, enriches it with role and context, transforms the code into a hybrid classical + PQC form via a vetted template registry (LLM limited to template selection), verifies the change on two independent tracks (functional equivalence and cryptographic assurance), and delivers one atomic PR per change after human approval. It runs as a headless CLI and CI/CD plugin, with a separate Control Centre for review and approval.

## 3. Decisions Log

| Status | Decision | Rationale |
|---|---|---|
| Confirmed by team | Core engine is built as a CLI / CI-CD plugin with a separate control centre interface | Continuous, pipeline-native operation; humans govern through the interface |
| Adopted in design | Consume CBOM (CycloneDX, e.g. CBOMkit) rather than build detection | Detection is mature; the transformation layer is the gap |
| Adopted in design | Hybrid (classical + PQC) by default, never hard cutover | Matches financial-sector and NIST-aligned guidance in the sources; safe transition |
| Adopted in design | Two verification tracks (functional and cryptographic assurance), both must pass | A faulted or misconfigured implementation can pass functional tests |
| Adopted in design | LLM selects from enumerated templates; deterministic validator can veto | Documented LLM failures on secure PQC migration |
| Adopted in design | Human approval gate before any PR | Non-negotiable governance |
| Recommended, pending team confirmation | MVP scope: Java only, 5–10 templates, Bouncy Castle, JUnit + NIST KATs + linter, one GitHub Action, one Streamlit dashboard | Full vision is too large for four people |
| Recommended, pending team confirmation | Roles for 1LOD/2LOD/3LOD are roadmap, not MVP | Scope control |

## 4. Current Status

- Synopsis submitted (title, description, objectives, software/hardware requirements).
- PRD, Architecture, rules, phases, and memory files drafted.
- Not started: repo, demo target selection, CBOM generation, any code.
- Next actions: confirm MVP scope with the team; pick and pin the demo Java repo; read the three key papers in full; verify Bouncy Castle version and KAT vectors.

## 5. Glossary

| Term | Meaning |
|---|---|
| PQC | Post-quantum cryptography |
| ML-KEM / ML-DSA / SLH-DSA | NIST FIPS 203 / 204 / 205 (formerly Kyber / Dilithium / SPHINCS+) |
| CBOM | Cryptographic Bill of Materials (CycloneDX 1.6+ supports it) |
| HNDL | Harvest Now, Decrypt Later |
| Hybrid | Classical and PQC combined so security holds if either holds |
| KAT | Known-Answer Test (official NIST test vectors) |
| Track A / Track B | Functional equivalence / cryptographic assurance verification |
| AST | Abstract Syntax Tree |
| IR | Intermediate representation shared across parser adapters |
| 1LOD / 2LOD / 3LOD | Three lines of defense: operations, risk/compliance, internal audit |
| AQuA | Automated Quantum-safe Adaptation (Zhang, ICSE 2026): detection, semantic refactoring, hybrid verification |

## 6. Sources

### Verified to exist (confirm authors/venue at the source before formal citation)
- Näther et al. (2024), IEEE Access 12, 132107–132126, DOI 10.1109/ACCESS.2024.3450306, arXiv:2404.12854.
- Zhang (2026), Toward Quantum-Safe Software Engineering, ICSE 2026, arXiv:2602.05759.
- Empirical Evaluation of LLMs for Migration of Code Fragments to PQC (2026), arXiv:2606.07341. Closest prior work. Author attribution came from a secondary source; verify.
- Assessing and Enhancing Quantum Readiness in Mobile Apps (2025), arXiv:2506.00790.
- Shaw (2026), Quantum-Safe Code Auditing, arXiv:2604.00560.
- Shaw (2026), quantum-safe: Bridging the Post-Quantum Production Gap, arXiv:2605.17061.
- Jendral, Mattsson, Dubrova (2024), Single-Trace Fault Injection Attack on Hedged ML-DSA, FDTC 2024.
- Ikwuogu et al. (2024), IJCATR 13(12), 198–213.
- Kemp, Padbury, Reeves (KPMG), second line of defense in PQC migration and cryptographic auditing (2026).
- CBOMkit (IBM Research, now under the PQC Alliance): open-source CBOM generation.

### Unverified / do not cite
- "QCecuring": no evidence it exists as a tool. Omit from all submissions until a primary source is found.

## 7. Key Findings to Remember

- CBOM/ACDI tools focus on discovery and inventory, not remediation (stated in the 2026 LLM-migration paper and AQuA).
- General-purpose LLMs do simple replacements well but fail secure, compilable PQC migration because of multi-file changes, missing imports, and missing context (mobile-apps study and related work). This motivates the enrichment layer and template constraint.
- A standard-compliant ML-DSA implementation can be broken by a single fault while signatures still verify (Jendral et al.). This motivates Track B.
- Hybrid schemes are the recommended transition approach in the financial-sector paper and the KPMG paper.

## 8. Honest Scope Boundaries (say these out loud in the viva)

We do not solve: network-layer fragmentation, silicon/HSM limits on low-power devices, closed-source or obfuscated code visibility, PQC algorithm maturity, workforce training, or provable side-channel immunity. We do solve: the software transformation step between "CBOM says RSA at line 42" and "line 42 now safely calls a hybrid PQC path, with evidence."

## 9. Open Questions

1. Which open-source Java repo is the demo target (real RSA/ECC usage, permissive license, small enough)?
2. Can CBOMkit produce a usable CBOM for it, or do we curate by hand?
3. How does our approach differ measurably from the 2026 LLM-migration paper (Python fragments, functional tests only)? Write the positioning note in Phase 0.
4. Exact Bouncy Castle version and API for ML-KEM/ML-DSA in hybrid wrappers.
5. Do we implement any attack-pattern rule for Track B in the MVP?
6. Who owns which phase (see phases.md suggested split)?

## 10. How to Update This File

- Add a dated line to the relevant log; don't silently rewrite history.
- Mark each decision as Confirmed, Adopted in design, or Recommended pending confirmation.
- Move a source from "unverified" to "verified" only after checking a primary source.
- Keep status honest: list what is not started.
