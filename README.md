# 🔐 CryptoShift

**Automated Post-Quantum Cryptographic Migration Engine**

CryptoShift consumes a CycloneDX CBOM, links each finding to its AST node, enriches it with role and context, transforms code into hybrid classical + PQC form via a vetted template registry, verifies each change on two independent tracks, and delivers atomic PRs after human approval.

> CBOM scanners tell you where the problem is; consultants tell you what to do; CryptoShift is the layer that actually does it, safely and with auditable evidence.

---

## Quick Start

```bash
# Clone and set up
git clone https://github.com/your-org/CryptoShift.git
cd CryptoShift
make setup

# Run lint and tests
make lint
make test

# Run the full demo pipeline
make demo

# Launch the Control Centre
make dashboard
```

## CLI Usage

```bash
# Scan: Parse CBOM and link to AST nodes
cryptoshift scan --cbom demo/cbom.json --repo demo/target-repo --json

# Enrich: Add role classification and risk scoring
cryptoshift enrich --artifacts-dir artifacts/ --json

# Transform: Generate hybrid PQC patches
cryptoshift transform --finding-ids f-0042 --artifacts-dir artifacts/ --json

# Verify: Run Track A (functional) + Track B (assurance)
cryptoshift verify --finding-ids f-0042 --artifacts-dir artifacts/ --json

# PR: Open atomic pull requests for approved findings
cryptoshift pr --finding-ids f-0042 --artifacts-dir artifacts/ --json
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Tool/config error |
| 2 | Verification failed (Track A or B) |
| 3 | Findings need human input |
| 4 | Approval missing/denied |

## Architecture

```
CycloneDX CBOM → scan → enrich → transform → verify → pr
                                                 ↕
                                     Control Centre (Streamlit)
                                     reads artifacts only
```

**Key principles:**
- **CBOM-first:** Detection is a solved input; we focus on transformation + verification
- **Hybrid by default:** Classical + PQC combined; never a hard cutover
- **LLM proposes, rules dispose:** Model selects templates; validator can veto
- **Two verification tracks:** Functional equivalence (A) + cryptographic assurance (B)
- **Human-governed:** Nothing merges without human approval

## CI/CD Integration

Three GitHub Actions workflows:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | push, PR | Lint, test, schema validation, import-boundary check |
| `cryptoshift-scan.yml` | push, PR, nightly, manual | Scan + enrich + artifact upload |
| `cryptoshift-apply.yml` | manual, decision file push | Transform + verify + PR creation |

See [docs/ci-setup.md](docs/ci-setup.md) for adoption instructions.

## Project Structure

```
cryptoshift/
  cli/                 # Typer CLI entrypoints
  ingest/              # CBOM parsing, fallback scan
  parsers/java/        # JavaParser adapter (JVM helper)
  enrich/              # Role classifier, risk scorer
  registry/templates/  # YAML templates (versioned)
  llm_gateway/         # Schema-constrained LLM calls
  validator/           # Allowlist, veto rules (pure, deterministic)
  codegen/             # Template-driven patch generation
  verify/trackA/       # Functional equivalence verification
  verify/trackB/       # KAT vectors, parameter linter, patterns
  delivery/            # PR creation, audit records
  control_centre/      # Streamlit dashboard (reads artifacts only)
schemas/               # JSON Schemas for all artifacts
java_helper/           # Maven project for JavaParser
tests/                 # pytest test suite
docs/                  # PRD, Architecture, rules, phases, memory
.github/workflows/     # CI/CD pipelines
```

## Documentation

- [PRD](docs/PRD.md) — Product Requirements Document
- [Architecture](docs/Architecture.md) — System design and data contracts
- [Rules](docs/rules.md) — Hard constraints for AI and contributors
- [Phases](docs/phases.md) — Project phases and cut order
- [Memory](/main/memory.md) — Living project context
- [CI Setup](docs/ci-setup.md) — GitHub Actions adoption guide

## Known Limitations

Track B closes documented failure classes; it does not prove security. CryptoShift cannot fix network-layer issues, hardware/HSM constraints, closed-source visibility, or PQC algorithm maturity.

## License

MIT
