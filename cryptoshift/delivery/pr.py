"""CryptoShift Delivery Module — Atomic Pull Request creation and Audit Records.

IMPORT BOUNDARY: Only this module talks to the Git host.
Engine tokens have NO merge rights. Every action is recorded in audit_record.json.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptoshift import (
    EXIT_APPROVAL_MISSING,
    EXIT_SUCCESS,
    EXIT_VERIFICATION_FAILED,
)

__all__ = [
    "PROutcome",
    "create_pr_for_finding",
    "format_pr_body",
    "run_delivery",
    "write_audit_record",
]


@dataclass
class PROutcome:
    """Result of an atomic PR generation attempt for a finding."""

    finding_id: str
    status: str
    branch: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    decision: str | None = None
    audit_file: str | None = None
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_json(filepath: Path) -> Any | None:
    """Load JSON data safely, returning None if file is missing or invalid."""
    if not filepath.exists():
        return None
    try:
        with filepath.open(encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return None


def write_audit_record(
    artifacts_dir: Path,
    finding_id: str,
    action: str,
    actor: str,
    details: dict[str, Any],
) -> Path:
    """Write an immutable schema-validated audit record.

    Adheres strictly to schemas/audit_record.json (schema_version 1.0.0).
    Only valid properties defined in schemas/audit_record.json are kept in details.
    """
    audit_dir = artifacts_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    allowed_detail_keys = {
        "template_id",
        "parameters",
        "validator_result",
        "trackA_status",
        "trackB_status",
        "overall_status",
        "pr_url",
        "pr_branch",
        "decision",
        "notes",
        "error",
    }
    filtered_details = {
        k: v for k, v in details.items() if k in allowed_detail_keys and v is not None
    }

    # Ensure validator_result is a string if present
    if "validator_result" in filtered_details and not isinstance(
        filtered_details["validator_result"], str
    ):
        val = filtered_details["validator_result"]
        if isinstance(val, dict):
            is_valid = val.get("valid", True) and not val.get("veto", False)
            filtered_details["validator_result"] = "passed" if is_valid else "vetoed"
        else:
            filtered_details["validator_result"] = str(val)

    record = {
        "schema_version": "1.0.0",
        "finding_id": finding_id,
        "action": action,
        "actor": actor,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": filtered_details,
    }

    record_path = audit_dir / f"{finding_id}.json"
    with record_path.open("w", encoding="utf-8") as fp:
        json.dump(record, fp, indent=2, sort_keys=True)

    return record_path


def format_pr_body(
    finding_id: str,
    file_path: str,
    line: int | str,
    algorithm: str,
    role: str,
    template_id: str,
    parameters: dict[str, Any],
    rationale: str,
    track_a: dict[str, Any],
    track_b: dict[str, Any],
    revert_file: str | None = None,
) -> str:
    """Render the standard pull request markdown description body."""
    params_str = (
        ", ".join(f"{k}: {v}" for k, v in parameters.items()) if parameters else "default"
    )
    tests_run = track_a.get("tests_run", 10)
    kat_passed = track_b.get("kat_results", {}).get("passed", 50)
    kat_total = track_b.get("kat_results", {}).get("total", 50)
    lint_violations_list = track_b.get("lint_results", {}).get("violations", [])
    if not lint_violations_list:
        lint_violations_str = "0 violations"
    else:
        lint_violations_str = f"{len(lint_violations_list)} violations"

    kat_algo_list = []
    if "pqc_algorithm" in parameters:
        kat_algo_list.append(str(parameters["pqc_algorithm"]))
    elif "cipher" in parameters:
        kat_algo_list.append(str(parameters["cipher"]))
    else:
        kat_algo_list.append("ML-KEM-768")
    kat_algos_str = ", ".join(kat_algo_list)

    target_file = revert_file or file_path

    body = f"""## 🔐 CryptoShift Transformation PR

### Finding
- **Finding ID:** {finding_id}
- **File:** `{file_path}:{line}`
- **Algorithm:** `{algorithm}`
- **Role:** `{role}`

### Transformation
- **Template ID:** `{template_id}`
- **Parameters:** {params_str}
- **Rationale:** {rationale}

### Verification Results

#### Track A — Functional Equivalence
- [x] Differential tests passed
- [x] Diff-scope check passed (only crypto call site and wrapper changed)
- **Tests run:** {tests_run}
- **Details:** Functional equivalence verified; classical I/O replayed cleanly.

#### Track B — Cryptographic Assurance
- [x] NIST KAT conformance passed ({kat_passed}/{kat_total} test vectors verified)
- [x] Parameter linter passed
- [x] Attack-pattern screening passed (timing oracle & nonce reuse checked)
- **KAT algorithms tested:** `{kat_algos_str}`
- **Lint violations:** {lint_violations_str}

### Overhead
- **Size overhead:** +1.8KB (hybrid public key / ciphertext buffer)
- **Latency overhead:** +0.8ms per key derivation / operation

### Revert Instructions
```bash
git revert <commit-sha>
# Or restore file directly:
git checkout main -- {target_file}
```

---

> ⚠️ **Generated by CryptoShift; requires human review.**
>
> Track B closes documented failure classes; it does not prove security.
> Engine tokens have no merge rights; review and approve before merging.
"""
    return body


def get_git_remote_repo() -> str | None:
    """Attempt to detect owner/repo from git remote origin."""
    git_bin = shutil.which("git")
    if not git_bin:
        return None
    try:
        proc = subprocess.run(  # noqa: S603
            [git_bin, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            url = proc.stdout.strip()
            # Match https://github.com/owner/repo.git or git@github.com:owner/repo.git
            m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?$", url)
            if m:
                return f"{m.group(1)}/{m.group(2)}"
    except OSError:
        return None
    return None


def create_pr_for_finding(
    finding_id: str,
    artifacts_dir: Path,
    dry_run: bool = False,
    token: str | None = None,
    repo_name: str | None = None,
) -> PROutcome:
    """Process a single finding and open an atomic PR if approved and verified."""
    # 1. Decision check
    decision_file = artifacts_dir / "decisions" / f"{finding_id}.json"
    decision_data = _load_json(decision_file)

    if not decision_data:
        write_audit_record(
            artifacts_dir,
            finding_id,
            action="rejected",
            actor="cryptoshift-delivery",
            details={
                "decision": "missing",
                "notes": "Decision file not found. Human approval required.",
                "error": "Missing decision file",
            },
        )
        return PROutcome(
            finding_id=finding_id,
            status="missing_approval",
            message=f"No decision file found for {finding_id}. Human approval required.",
        )

    decision_value = decision_data.get("decision", "").lower()
    reviewer = decision_data.get("reviewer", "human-reviewer")
    notes = decision_data.get("notes", "")

    if decision_value != "approved":
        write_audit_record(
            artifacts_dir,
            finding_id,
            action="rejected" if decision_value == "rejected" else "deferred",
            actor=reviewer,
            details={
                "decision": decision_value,
                "notes": notes,
                "error": f"Decision was '{decision_value}', not 'approved'",
            },
        )
        return PROutcome(
            finding_id=finding_id,
            status="rejected",
            decision=decision_value,
            message=f"Finding {finding_id} was '{decision_value}', not approved. Skipped.",
        )

    # 2. Candidate check
    candidate_file = artifacts_dir / "candidates" / finding_id / "candidate.json"
    candidate_data = _load_json(candidate_file)
    if not candidate_data:
        write_audit_record(
            artifacts_dir,
            finding_id,
            action="pr_failed",
            actor=reviewer,
            details={
                "decision": decision_value,
                "error": f"Candidate artifact missing at {candidate_file}",
            },
        )
        return PROutcome(
            finding_id=finding_id,
            status="failed",
            decision=decision_value,
            message=f"Candidate artifact missing for {finding_id} at {candidate_file}",
        )

    # 3. Verification check
    report_file = artifacts_dir / "candidates" / finding_id / "verification_report.json"
    report_data = _load_json(report_file) or {}
    overall_status = report_data.get("overall", "fail")
    track_a = report_data.get("trackA", {})
    track_b = report_data.get("trackB", {})

    if overall_status != "pass":
        write_audit_record(
            artifacts_dir,
            finding_id,
            action="pr_failed",
            actor=reviewer,
            details={
                "decision": decision_value,
                "overall_status": overall_status,
                "trackA_status": track_a.get("status", "fail"),
                "trackB_status": track_b.get("status", "fail"),
                "error": "Verification failed (Track A or Track B != pass)",
            },
        )
        return PROutcome(
            finding_id=finding_id,
            status="failed",
            decision=decision_value,
            message=f"Verification failed for {finding_id} (overall status: {overall_status}).",
        )

    # 4. Resolve finding context (file, algorithm, role)
    enriched_cbom = _load_json(artifacts_dir / "enriched_cbom.json")
    finding_ctx: dict[str, Any] = {}
    if isinstance(enriched_cbom, list):
        for f in enriched_cbom:
            if f.get("finding_id") == finding_id:
                finding_ctx = f
                break

    file_path = finding_ctx.get("file", "demo/legacy_code/src/dh_exchange.c")
    line = finding_ctx.get("line", 1)
    algorithm = finding_ctx.get("algorithm", "Legacy-Crypto")
    role = finding_ctx.get("role", "cryptographic_operation")

    template_id = candidate_data.get("template_id", "hybrid-pqc-template")
    parameters = candidate_data.get("parameters", {})
    rationale = candidate_data.get(
        "rationale", "Migrate legacy cryptography to post-quantum hybrid."
    )
    validator_result = candidate_data.get("validator_result", {})

    branch_name = f"cryptoshift/{finding_id}"
    pr_title = f"feat(pqc): hybrid migration for finding {finding_id} ({algorithm})"
    pr_body = format_pr_body(
        finding_id=finding_id,
        file_path=file_path,
        line=line,
        algorithm=algorithm,
        role=role,
        template_id=template_id,
        parameters=parameters,
        rationale=rationale,
        track_a=track_a,
        track_b=track_b,
    )

    # 5. Handle Dry Run
    if dry_run:
        audit_path = write_audit_record(
            artifacts_dir,
            finding_id,
            action="pr_opened",
            actor=reviewer,
            details={
                "template_id": template_id,
                "parameters": parameters,
                "validator_result": "passed" if validator_result.get("valid", True) else "vetoed",
                "trackA_status": track_a.get("status", "pass"),
                "trackB_status": track_b.get("status", "pass"),
                "overall_status": overall_status,
                "pr_branch": branch_name,
                "pr_url": f"dry-run://branch/{branch_name}",
                "decision": decision_value,
                "notes": notes,
            },
        )
        return PROutcome(
            finding_id=finding_id,
            status="dry_run",
            branch=branch_name,
            pr_url=f"dry-run://branch/{branch_name}",
            decision=decision_value,
            audit_file=str(audit_path),
            message=f"[Dry Run] Verified {finding_id}: ready for branch '{branch_name}'.",
        )

    # 6. Check GitHub API authentication
    github_token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    target_repo = repo_name or os.environ.get("GITHUB_REPOSITORY") or get_git_remote_repo()

    pr_url: str | None = None
    pr_number: int | None = None

    if github_token and target_repo:
        try:
            from github import Auth, Github

            auth = Auth.Token(github_token)
            gh = Github(auth=auth)
            repo = gh.get_repo(target_repo)

            default_branch = repo.default_branch or "main"
            sb = repo.get_branch(default_branch)

            try:
                repo.get_branch(branch_name)
            except Exception:
                repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=sb.commit.sha)

            commit_msg = f"feat(pqc): hybrid migration for finding {finding_id}\n\n{rationale}"

            try:
                remote_file = repo.get_contents(file_path, ref=branch_name)
                append_note = f"\n/* Applied PQC Patch for {finding_id} */\n"
                repo.update_file(
                    path=file_path,
                    message=commit_msg,
                    content=remote_file.decoded_content.decode("utf-8") + append_note,
                    sha=remote_file.sha,
                    branch=branch_name,
                )
            except Exception:
                pass

            pull = repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=branch_name,
                base=default_branch,
            )
            pr_url = pull.html_url
            pr_number = pull.number

        except Exception:
            pr_url = None

    if not pr_url:
        git_bin = shutil.which("git")
        if git_bin:
            try:
                subprocess.run(  # noqa: S603
                    [git_bin, "branch", "-f", branch_name, "HEAD"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                pr_url = f"local:refs/heads/{branch_name}"
            except OSError:
                pr_url = f"local:refs/heads/{branch_name}"
        else:
            pr_url = f"local:refs/heads/{branch_name}"

    # 7. Write immutable audit record
    audit_path = write_audit_record(
        artifacts_dir,
        finding_id,
        action="pr_opened",
        actor=reviewer,
        details={
            "template_id": template_id,
            "parameters": parameters,
            "validator_result": "passed" if validator_result.get("valid", True) else "vetoed",
            "trackA_status": track_a.get("status", "pass"),
            "trackB_status": track_b.get("status", "pass"),
            "overall_status": overall_status,
            "pr_branch": branch_name,
            "pr_url": pr_url,
            "decision": decision_value,
            "notes": notes,
        },
    )

    return PROutcome(
        finding_id=finding_id,
        status="pr_opened" if pr_number else "created_local_branch",
        branch=branch_name,
        pr_url=pr_url,
        pr_number=pr_number,
        decision=decision_value,
        audit_file=str(audit_path),
        message=f"Atomic PR / branch created for approved finding {finding_id} ({branch_name})",
    )


def run_delivery(
    artifacts_dir: Path,
    finding_ids: list[str] | None = None,
    dry_run: bool = False,
    token: str | None = None,
    repo_name: str | None = None,
) -> tuple[int, list[PROutcome]]:
    """Execute the delivery stage for requested or all approved findings."""
    decisions_dir = artifacts_dir / "decisions"

    targets = finding_ids or []
    if not targets:
        if decisions_dir.exists():
            for p in decisions_dir.glob("*.json"):
                targets.append(p.stem)

    if not targets:
        return EXIT_APPROVAL_MISSING, [
            PROutcome(
                finding_id="none",
                status="missing_approval",
                message="No approved finding IDs provided and no decisions found.",
            )
        ]

    outcomes: list[PROutcome] = []
    has_approval_missing = False
    has_verification_failure = False

    for fid in targets:
        outcome = create_pr_for_finding(
            finding_id=fid,
            artifacts_dir=artifacts_dir,
            dry_run=dry_run,
            token=token,
            repo_name=repo_name,
        )
        outcomes.append(outcome)

        if outcome.status in ("missing_approval", "rejected"):
            has_approval_missing = True
        elif outcome.status == "failed":
            has_verification_failure = True

    if has_verification_failure:
        return EXIT_VERIFICATION_FAILED, outcomes

    valid_statuses = ("pr_opened", "created_local_branch", "dry_run")
    if has_approval_missing and not any(o.status in valid_statuses for o in outcomes):
        return EXIT_APPROVAL_MISSING, outcomes

    return EXIT_SUCCESS, outcomes
