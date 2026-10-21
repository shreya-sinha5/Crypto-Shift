"""SQLite storage engine for legacy code cryptographic findings.

Provides persistent queryable storage for findings discovered across
codebases, commits, and repositories.
"""

from __future__ import annotations

import datetime
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptoshift.parsers.c import CryptoFinding

DEFAULT_DB_PATH = Path("legacy_crypto.db")


class CryptoDatabase:
    """Manages SQLite storage for legacy cryptographic findings."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.is_memory = str(db_path) == ":memory:"
        self.db_path = Path(db_path) if not self.is_memory else None
        self._mem_conn: sqlite3.Connection | None = None
        if self.is_memory:
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self.is_memory and self._mem_conn is not None:
            return self._mem_conn
        assert self.db_path is not None
        if self.db_path.parent != Path("."):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Create tables and indices if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    url TEXT,
                    commit_hash TEXT,
                    scanned_at TEXT NOT NULL
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_id INTEGER,
                    file_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL,
                    col_start INTEGER,
                    col_end INTEGER,
                    rule_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    library TEXT NOT NULL,
                    role TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    key_size INTEGER,
                    message TEXT NOT NULL,
                    matched_text TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'detected',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (repo_id) REFERENCES repositories(id) ON DELETE CASCADE
                )
            """)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_algo ON findings(algorithm);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_id);")
            conn.commit()

    def record_scan(
        self,
        repo_name: str,
        findings: Sequence[CryptoFinding],
        repo_url: str | None = None,
        commit_hash: str | None = None,
        base_dir: Path | str | None = None,
    ) -> int:
        """Record scan results for a repository.

        Replaces previous findings for this repository name.
        Returns the number of findings inserted.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Upsert repository
            cursor.execute("SELECT id FROM repositories WHERE name = ?", (repo_name,))
            row = cursor.fetchone()
            if row:
                repo_id = row["id"]
                cursor.execute(
                    "UPDATE repositories SET url = ?, commit_hash = ?, scanned_at = ? WHERE id = ?",
                    (repo_url, commit_hash, now, repo_id),
                )
                # Clear previous findings for this repo
                cursor.execute("DELETE FROM findings WHERE repo_id = ?", (repo_id,))
            else:
                cursor.execute(
                    "INSERT INTO repositories (name, url, commit_hash, scanned_at) "
                    "VALUES (?, ?, ?, ?)",
                    (repo_name, repo_url, commit_hash, now),
                )
                repo_id = cursor.lastrowid

            # Insert findings
            rows_to_insert = []
            for f in findings:
                file_path = f.file
                if base_dir:
                    try:
                        file_path = str(Path(f.file).relative_to(Path(base_dir)))
                    except ValueError:
                        file_path = f.file
                file_path = file_path.replace("\\", "/")

                rows_to_insert.append(
                    (
                        repo_id,
                        file_path,
                        f.line,
                        f.col_start,
                        f.col_end,
                        f.rule_id,
                        f.algorithm,
                        f.library,
                        f.role,
                        f.severity,
                        f.key_size,
                        f.message,
                        f.matched_text,
                        "detected",
                        now,
                    )
                )

            cursor.executemany(
                """
                INSERT INTO findings (
                    repo_id, file_path, line_number, col_start, col_end,
                    rule_id, algorithm, library, role, severity,
                    key_size, message, matched_text, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows_to_insert,
            )
            conn.commit()
            return len(rows_to_insert)

    def query_findings(
        self,
        repo_name: str | None = None,
        algorithm: str | None = None,
        severity: str | None = None,
        role: str | None = None,
        library: str | None = None,
        status: str | None = None,
        file_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters."""
        query = """
            SELECT
                f.id,
                r.name AS repo_name,
                f.file_path,
                f.line_number,
                f.col_start,
                f.col_end,
                f.rule_id,
                f.algorithm,
                f.library,
                f.role,
                f.severity,
                f.key_size,
                f.message,
                f.matched_text,
                f.status,
                f.created_at
            FROM findings f
            LEFT JOIN repositories r ON f.repo_id = r.id
            WHERE 1=1
        """
        params: list[Any] = []

        if repo_name:
            query += " AND r.name = ?"
            params.append(repo_name)
        if algorithm:
            query += " AND UPPER(f.algorithm) = UPPER(?)"
            params.append(algorithm)
        if severity:
            query += " AND LOWER(f.severity) = LOWER(?)"
            params.append(severity)
        if role:
            query += " AND LOWER(f.role) = LOWER(?)"
            params.append(role)
        if library:
            query += " AND LOWER(f.library) = LOWER(?)"
            params.append(library)
        if status:
            query += " AND LOWER(f.status) = LOWER(?)"
            params.append(status)
        if file_path:
            query += " AND f.file_path LIKE ?"
            params.append(f"%{file_path}%")

        query += " ORDER BY f.severity DESC, f.file_path ASC, f.line_number ASC"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def update_status(self, finding_id: int, status: str) -> bool:
        """Update the migration status of a finding."""
        valid_statuses = {"detected", "migrating", "migrated", "ignored"}
        if status not in valid_statuses:
            raise ValueError(f"Invalid status '{status}'. Must be one of {valid_statuses}")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            conn.commit()
            return cursor.rowcount > 0

    def get_summary(self, repo_name: str | None = None) -> dict[str, Any]:
        """Compute aggregated summary of findings."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            where_clause = ""
            params: list[Any] = []
            if repo_name:
                where_clause = " WHERE r.name = ?"
                params.append(repo_name)

            cursor.execute(
                f"""
                SELECT COUNT(*) as total_findings,
                       COUNT(DISTINCT f.file_path) as total_files
                FROM findings f
                LEFT JOIN repositories r ON f.repo_id = r.id
                {where_clause}
                """,
                params,
            )
            base_stats = dict(cursor.fetchone() or {})

            # By severity
            cursor.execute(
                f"""
                SELECT f.severity, COUNT(*) as count
                FROM findings f
                LEFT JOIN repositories r ON f.repo_id = r.id
                {where_clause}
                GROUP BY f.severity
                """,
                params,
            )
            by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

            # By algorithm
            cursor.execute(
                f"""
                SELECT f.algorithm, COUNT(*) as count
                FROM findings f
                LEFT JOIN repositories r ON f.repo_id = r.id
                {where_clause}
                GROUP BY f.algorithm
                ORDER BY count DESC
                """,
                params,
            )
            by_algorithm = {row["algorithm"]: row["count"] for row in cursor.fetchall()}

            # By role
            cursor.execute(
                f"""
                SELECT f.role, COUNT(*) as count
                FROM findings f
                LEFT JOIN repositories r ON f.repo_id = r.id
                {where_clause}
                GROUP BY f.role
                ORDER BY count DESC
                """,
                params,
            )
            by_role = {row["role"]: row["count"] for row in cursor.fetchall()}

            # By status
            cursor.execute(
                f"""
                SELECT f.status, COUNT(*) as count
                FROM findings f
                LEFT JOIN repositories r ON f.repo_id = r.id
                {where_clause}
                GROUP BY f.status
                """,
                params,
            )
            by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_findings": base_stats.get("total_findings", 0),
                "total_files": base_stats.get("total_files", 0),
                "by_severity": by_severity,
                "by_algorithm": by_algorithm,
                "by_role": by_role,
                "by_status": by_status,
            }
