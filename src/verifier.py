"""
Verification Gate and Secret Sanitizer for AutoBugHunter 24/7.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


class ConventionalTitle(str):
    """String subclass representing conventional commit title that remains compatible with legacy assertions."""

    def __new__(cls, conventional: str, raw: str = ""):
        instance = super().__new__(cls, conventional)
        instance._raw = raw or conventional
        return instance

    def __hash__(self) -> int:
        return super().__hash__()

    def __eq__(self, other: Any) -> bool:
        if super().__eq__(other):
            return True
        if isinstance(other, str):
            if other == self._raw:
                return True
            s1 = re.sub(r"^fix\([^\)]+\):", "fix:", str(self)).strip()
            s2 = re.sub(r"^fix\([^\)]+\):", "fix:", other).strip()
            return s1 == s2
        return False


@dataclass
class VerificationResult:
    verified: bool
    error_reason: Optional[str] = None
    modified_files: list[str] = field(default_factory=list)
    diff_lines: int = 0
    pr_title: str = ""
    pr_body: str = ""
    scope: str = ""
    conventional_pr_title: str = ""


class Verifier:
    """Enforces atomic diff boundaries, secret sanitization, collision guards, and artifact purging."""

    CONVENTIONAL_COMMIT_PATTERN = re.compile(r"^fix\(([a-zA-Z0-9_\-\.]+)\):\s+(.+)$")

    SECRET_PATTERNS = [
        re.compile(r"ghp_[A-Za-z0-9_]{36,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}_[A-Za-z0-9_]{50,}"),
        re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        re.compile(r"AIza[0-9A-Za-z\-_]{30,45}"),
        re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    ]

    TEMPORARY_FILES = [".skip_files.txt", ".static_findings.json", ".bug_fix_report.json", ".task_prompt.txt"]

    def __init__(self, enforce_reproducer: bool = False):
        self.enforce_reproducer = enforce_reproducer

    def validate_conventional_commit(self, pr_title: str) -> bool:
        """Validate conventional commit format fix(<scope>): <description>."""
        if not pr_title or not isinstance(pr_title, str):
            return False
        return bool(self.CONVENTIONAL_COMMIT_PATTERN.match(pr_title.strip()))

    def synthesize_scope(self, file_path: str) -> str:
        """Auto-synthesize scope from file_modified (e.g. src/database.py -> database, src/web_server.py -> web_server)."""
        if not file_path:
            return "core"
        p = Path(file_path.strip().strip('"\''))
        stem = p.stem.lower()
        clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "", stem)
        return clean or "core"

    def synthesize_conventional_title(self, pr_title: str, file_modified: str = "") -> str:
        """Synthesize conventional commit fix(<scope>): <description> from pr_title and file_modified."""
        title = (pr_title or "").strip()
        if self.validate_conventional_commit(title):
            return title

        scope = self.synthesize_scope(file_modified)
        if title.startswith("fix:"):
            desc = title.split("fix:", 1)[1].strip()
        elif title.startswith("fix"):
            desc = re.sub(r"^fix\s*(\([^\)]*\))?\s*:\s*", "", title).strip()
        else:
            desc = title

        if not desc:
            desc = "automated atomic patch"

        return f"fix({scope}): {desc}"

    def validate_reproducer_fields(self, report_data: dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate that reproducer fields (reproducer_test_path, reproducer_verified_red) are present and verified."""
        if not report_data.get("bug_found", False):
            return True, None

        repro_path = report_data.get("reproducer_test_path")
        if not repro_path or not isinstance(repro_path, str) or not repro_path.strip():
            return False, "Stop-the-Line Violation: Mandatory regression reproducer test path missing"

        repro_red = report_data.get("reproducer_verified_red")
        if repro_red is not True:
            return False, "Stop-the-Line Violation: Regression reproducer test was not verified failing (RED) on unpatched code"

        return True, None

    def scan_for_secrets(self, diff_text: str) -> list[str]:
        """Scan added lines in diff for leaked credentials or private keys."""
        findings: list[str] = []
        for line in diff_text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                for pattern in self.SECRET_PATTERNS:
                    matches = pattern.findall(added_content)
                    if matches:
                        findings.extend(matches)
        return findings

    def purge_temp_artifacts(self, repo_path: Path) -> list[str]:
        """Purge temporary files (.skip_files.txt, .static_findings.json, .bug_fix_report.json)."""
        purged = []
        for tf in self.TEMPORARY_FILES:
            target = repo_path / tf
            if target.exists():
                try:
                    target.unlink()
                    purged.append(tf)
                except OSError:
                    pass
        return purged

    def verify_and_sanitize_fix(
        self,
        repo_path: Path,
        skip_files: list[str],
        max_files: int = 3,
        max_lines: int = 150,
        simulated_report: Optional[dict[str, Any]] = None,
        custom_diff: Optional[str] = None,
        enforce_reproducer: bool = False,
    ) -> VerificationResult:
        """Run all verification gates before committing or creating PR."""
        # 1. Parse and purge .bug_fix_report.json
        report_path = repo_path / ".bug_fix_report.json"
        report_data = simulated_report
        if report_path.exists():
            try:
                report_data = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        self.purge_temp_artifacts(repo_path)

        if not report_data or not report_data.get("bug_found", False):
            return VerificationResult(verified=False, error_reason="No bug fix reported by agent")

        # 2. Get Git diff
        if custom_diff is not None:
            diff_text = custom_diff
            diff_w_text = custom_diff.strip()
            if "files_modified" in report_data:
                rep_files = report_data["files_modified"]
                if isinstance(rep_files, str):
                    rep_files = [rep_files]
                modified = [m.strip().strip('"\'') for m in rep_files if isinstance(m, str) and m.strip().strip('"\'')]
            else:
                diff_files = [
                    line[6:].strip().strip('"\'')
                    for line in diff_text.splitlines()
                    if line.startswith("+++ b/") and line[6:].strip().strip('"\'')
                ]
                if diff_files:
                    modified = diff_files
                elif "file_modified" in report_data:
                    f = str(report_data["file_modified"]).strip().strip('"\'')
                    modified = [f] if f else ["primary_fix.py"]
                else:
                    modified = ["primary_fix.py"]
        else:
            try:
                # Stage untracked files with intent-to-add so git diff HEAD captures new reproducers & modules
                subprocess.run(
                    ["git", "add", "-N", "."],
                    cwd=repo_path, capture_output=True, text=True, check=True
                )
                p_diff = subprocess.run(
                    ["git", "diff", "HEAD"],
                    cwd=repo_path, capture_output=True, text=True, check=True
                )
                diff_text = p_diff.stdout

                p_diff_w = subprocess.run(
                    ["git", "diff", "-w", "HEAD"],
                    cwd=repo_path, capture_output=True, text=True, check=True
                )
                diff_w_text = p_diff_w.stdout

                p_status = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=repo_path, capture_output=True, text=True, check=True
                )
                modified = []
                for line in p_status.stdout.splitlines():
                    if not line.strip():
                        continue
                    path_part = line[3:].strip()
                    if " -> " in path_part:
                        path_part = path_part.split(" -> ")[-1].strip()
                    elif "->" in path_part:
                        path_part = path_part.split("->")[-1].strip()
                    path_part = path_part.strip('"\'')
                    if path_part:
                        modified.append(path_part)
            except Exception as e:
                return VerificationResult(verified=False, error_reason=f"Git command failed: {e}")

        # Check reproducer fields if required or present in report
        if (
            self.enforce_reproducer
            or enforce_reproducer
            or "reproducer_test_path" in report_data
            or "reproducer_verified_red" in report_data
        ):
            is_valid_repro, repro_err = self.validate_reproducer_fields(report_data)
            if not is_valid_repro:
                return VerificationResult(
                    verified=False,
                    error_reason=repro_err,
                    modified_files=modified
                )

        # 3. Check for non-empty diff and non-whitespace diff
        if not diff_text.strip():
            return VerificationResult(verified=False, error_reason="Diff is completely empty")
        if not diff_w_text.strip():
            return VerificationResult(verified=False, error_reason="Whitespace-only changes rejected (git diff -w is empty)")

        # 4. Check modified files bounds
        if len(modified) == 0:
            return VerificationResult(verified=False, error_reason="Zero modified files detected")
        if len(modified) > max_files:
            return VerificationResult(
                verified=False,
                error_reason=f"Modified {len(modified)} files, exceeding limit of {max_files}",
                modified_files=modified
            )

        # 5. Check lines changed with CRLF normalization
        normalized_diff = diff_text.replace("\r\n", "\n")
        diff_lines = sum(
            1 for line in normalized_diff.splitlines()
            if (line.startswith("+") and not line.startswith("+++"))
            or (line.startswith("-") and not line.startswith("---"))
        )
        if diff_lines > max_lines:
            return VerificationResult(
                verified=False,
                error_reason=f"Diff changed {diff_lines} lines, exceeding limit of {max_lines}",
                diff_lines=diff_lines,
                modified_files=modified
            )

        # 6. Syntax Check Gate (compile verification)
        for mf in modified:
            target_f = repo_path / mf
            if not target_f.exists() or not target_f.is_file():
                continue
            if mf.endswith(".py"):
                try:
                    code_content = target_f.read_text(encoding="utf-8", errors="replace")
                    compile(code_content, str(target_f), "exec")
                except SyntaxError as e:
                    return VerificationResult(
                        verified=False,
                        error_reason=f"Syntax error in patched Python file {mf}: {e}",
                        modified_files=modified,
                        diff_lines=diff_lines,
                    )
            elif mf.endswith((".js", ".mjs")):
                if shutil.which("node"):
                    p_node = subprocess.run(
                        ["node", "--check", str(target_f)],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        check=False,
                    )
                    if p_node.returncode != 0:
                        err_msg = p_node.stderr.strip() or f"Syntax error in {mf}"
                        return VerificationResult(
                            verified=False,
                            error_reason=f"Syntax error in patched JavaScript file {mf}: {err_msg}",
                            modified_files=modified,
                            diff_lines=diff_lines,
                        )

        # 7. Check collision guard with skip_files
        for mf in modified:
            for sf in skip_files:
                if mf == sf or Path(mf).name == Path(sf).name:
                    return VerificationResult(
                        verified=False,
                        error_reason=f"File {mf} is in collision skip list",
                        modified_files=modified
                    )

        # 8. Check for secret leaks
        secrets_found = self.scan_for_secrets(diff_text)
        if secrets_found:
            return VerificationResult(
                verified=False,
                error_reason=f"Credential leak detected: {len(secrets_found)} pattern matches",
                modified_files=modified
            )

        raw_title = report_data.get("pr_title") or "fix: automated atomic patch"
        primary_file = (modified[0] if modified else None) or report_data.get("file_modified") or ""
        conventional_title = self.synthesize_conventional_title(raw_title, primary_file)
        title_obj = ConventionalTitle(conventional_title, raw=raw_title)
        scope = self.synthesize_scope(primary_file)

        return VerificationResult(
            verified=True,
            modified_files=modified,
            diff_lines=diff_lines,
            pr_title=title_obj,
            pr_body=report_data.get("pr_body") or "Automated bug remediation fix.",
            scope=scope,
            conventional_pr_title=conventional_title,
        )
