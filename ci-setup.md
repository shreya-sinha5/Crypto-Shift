# CI/CD Setup Guide for CryptoShift

> Adopt CryptoShift in a new repository in under 15 minutes.

---

## Prerequisites

- GitHub repository with Java source code
- Python 3.10+
- JDK 17+
- Maven
- A CycloneDX CBOM for your project (or use CBOMkit to generate one)

## Quick Start: Using the Composite Action

Add CryptoShift to any repo with a few lines in your workflow:

```yaml
# .github/workflows/cryptoshift.yml
name: CryptoShift Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "0 2 * * *"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Checkout CryptoShift
        uses: actions/checkout@v4
        with:
          repository: your-org/CryptoShift
          path: .cryptoshift

      - name: Run CryptoShift Scan
        uses: ./.cryptoshift
        with:
          command: scan
          cbom-path: path/to/your/cbom.json

      - name: Run CryptoShift Enrich
        uses: ./.cryptoshift
        with:
          command: enrich

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: cryptoshift-artifacts
          path: artifacts/
```

## Full Setup

### 1. Repository Secrets

Configure these in **Settings → Secrets and variables → Actions**:

| Secret | Purpose | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | LLM gateway for template selection | For `transform` only |
| `GITHUB_TOKEN` | Auto-provided, used for PR creation | Auto |

> ⚠️ **Fork PRs must NOT receive secrets.** GitHub Actions already enforces this
> for repository secrets. Do not use `pull_request_target` with secret access.

### 2. GitHub Environment

Create a **GitHub Environment** named `cryptoshift-apply`:

1. Go to **Settings → Environments → New environment**
2. Name: `cryptoshift-apply`
3. Add **Required reviewers** (at least one team member)
4. This ensures human approval before `transform` + `verify` + `pr` runs

### 3. Branch Protection Rules

Configure on your `main` branch (**Settings → Branches → Branch protection rules**):

| Setting | Value |
|---|---|
| Require a pull request before merging | ✅ |
| Require approvals | ≥ 1 |
| Require status checks to pass | ✅ |
| Required status checks | `ci`, `cryptoshift-scan / Scan & Enrich` |
| Require branches to be up to date | ✅ |
| Do not allow bypassing | ✅ |
| Block direct pushes | ✅ |

### 4. Generated PR Token Behavior

> **Important:** PRs created with the default `GITHUB_TOKEN` do **not** trigger
> other workflows. This means required status checks won't run on CryptoShift-generated PRs.

**Options to fix this:**

#### Option A: GitHub App (recommended)
1. Create a GitHub App with `contents: write` and `pull-requests: write`
2. Install it on your repo
3. Use [tibdex/github-app-token](https://github.com/tibdex/github-app-token) to generate a token
4. Pass it to the `pr` command via `GITHUB_TOKEN`

#### Option B: Personal Access Token (PAT)
1. Create a fine-grained PAT with repo access
2. Add as secret `CRYPTOSHIFT_PAT`
3. Use it instead of `GITHUB_TOKEN` in the apply workflow

**Verify behavior:** After setup, create a test PR via CryptoShift and confirm
that required status checks trigger on the generated PR.

## Workflow Reference

### A) `cryptoshift-scan.yml`
- **Triggers:** push, pull_request, nightly cron, workflow_dispatch
- **Does:** scan → enrich → upload artifacts → PR comment with risk summary
- **Permissions:** `contents: read`, `pull-requests: write` (comment only)

### B) `cryptoshift-apply.yml`
- **Triggers:** workflow_dispatch (with finding IDs), push to `decisions/*.json`
- **Does:** transform → verify (fail if !pass) → PR creation
- **Permissions:** `contents: write` (branch), `pull-requests: write`
- **Environment:** `cryptoshift-apply` (requires reviewer approval)
- **Safety:** Verification failure = job failure = no PR created

### C) `ci.yml`
- **Triggers:** push, pull_request
- **Does:** lint, tests, schema validation, import-boundary check

## CLI Exit Codes

| Code | Meaning | Pipeline behavior |
|---|---|---|
| 0 | Success | Continue |
| 1 | Tool/config error | Debug and retry |
| 2 | Verification failed | **Block PR creation** |
| 3 | Needs human input | Review findings manually |
| 4 | Approval missing/denied | Provide decision first |

## Security Considerations

- **No merge capability.** The `GITHUB_TOKEN` and engine tokens have no merge rights.
- **Secrets masked.** API keys are never echoed in logs.
- **Fork safety.** Fork PRs don't receive secrets.
- **Concurrency groups.** Superseded runs are cancelled automatically.
- **Timeouts.** All jobs have explicit timeout limits.
- **Pinned actions.** All third-party actions are pinned by commit SHA.

## Roadmap

- [ ] GitLab CI component (`.gitlab-ci.yml` template)
- [ ] Jenkins shared library
- [ ] GitHub Marketplace listing for the composite action
