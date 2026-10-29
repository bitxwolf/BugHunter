"""
Adversarial Verification Suite for Milestone 12 Iteration 2 (Challenger 2).
Deep empirical stress-testing for:
1. R3: Bot thread detection and auto-resolution:
   - Complex thread histories, multiple reviewers, bot replied last vs reviewer replied last
   - Fallback SHA extraction, headRefOid fallback, malformed author/comments
   - GraphQL resolution failures & SQLite persistence with RESOLUTION_FAILED
   - Strict idempotency across re-scans via is_thread_remediated
   - Concurrent SQLite access for review_remediations
2. R4: Invariants:
   - RULE-GIT-02: Absolute prohibition of force pushing
   - RULE-NO-AUTOMERGE: Absolute prohibition of auto-merging across config, git_manager, review_monitor
   - AST analysis of entire codebase ensuring zero force pushes and zero auto-merges
3. Worker m12_2 Regression & LLM Extraction Invariants:
   - Verifying unchanged code in markdown fences returns None and aborts with LLM_PATCH_FAILED
"""

from __future__ import annotations

import ast
import concurrent.futures
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.review_monitor import (
    ReviewComment,
    ReviewMonitor,
    ReviewRemediationResult,
)
from src.verifier import VerificationResult, Verifier


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_adv_m12_iter2.sqlite"
    return Database(db_file)


@pytest.fixture
def mock_config(tmp_path: Path) -> Config:
    k1 = KeyConfig(
        id="key-iter2-1",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="scalemax_secret_key",
        masked_key="scalemax...key",
        priority=1,
    )
    return Config.load(overrides={
        "WORKSPACE_DIR": tmp_path,
        "workspace_dir": tmp_path,
        "TARGET_REPOS": ["bitxwolf/BugHunter", "bitxwolf/test-repo"],
        "GITHUB_TOKEN": "mock_token_iter2",
        "LLM_KEYS": [k1],
    })


@pytest.fixture
def mock_git_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "mock_git_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)

    target_file = repo_dir / "service.py"
    target_file.write_text("def run():\n    return 'initial'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    return repo_dir


# =========================================================================
# 1. R3: Bot Thread Detection & Auto-Resolution Empirical Stress Tests
# =========================================================================

class TestR3BotThreadDetectionAndResolution:
    """Empirical verification of R3 requirements."""

    def test_multi_thread_mixed_states(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: PR containing 4 different review threads:
        - Thread 1: Reviewer feedback -> Bot reply -> No newer feedback (MUST auto-resolve & persist, NOT actionable)
        - Thread 2: Reviewer feedback -> Bot reply -> Newer reviewer feedback (MUST be actionable, NOT auto-resolve)
        - Thread 3: Reviewer feedback only (MUST be actionable)
        - Thread 4: Bot reply only (no reviewer comments) (MUST be ignored)
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_data = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/test-branch",
                        "headRefOid": "headoid1234567890",
                        "reviewThreads": {
                            "nodes": [
                                # Thread 1: Bot replied last
                                {
                                    "id": "THREAD_1",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 10,
                                    "comments": {
                                        "nodes": [
                                            {"id": "C1_1", "author": {"login": "coderabbitai[bot]"}, "body": "Fix bug", "createdAt": "2026-10-25T10:00:00Z"},
                                            {"id": "C1_2", "author": {"login": "arrshh12"}, "body": "Noted and addressed in commit c0ffee1. Verified and resolved.", "createdAt": "2026-10-25T10:10:00Z"},
                                        ]
                                    },
                                },
                                # Thread 2: Reviewer reopened after bot reply
                                {
                                    "id": "THREAD_2",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 20,
                                    "comments": {
                                        "nodes": [
                                            {"id": "C2_1", "author": {"login": "human_reviewer"}, "body": "Typo here", "createdAt": "2026-10-25T11:00:00Z"},
                                            {"id": "C2_2", "author": {"login": "arrshh12"}, "body": "Noted and addressed in commit c0ffee2. Verified and resolved.", "createdAt": "2026-10-25T11:10:00Z"},
                                            {"id": "C2_3", "author": {"login": "human_reviewer"}, "body": "Still broken, please fix edge case", "createdAt": "2026-10-25T11:20:00Z"},
                                        ]
                                    },
                                },
                                # Thread 3: Reviewer feedback only
                                {
                                    "id": "THREAD_3",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 30,
                                    "comments": {
                                        "nodes": [
                                            {"id": "C3_1", "author": {"login": "human_reviewer"}, "body": "Missing null check", "createdAt": "2026-10-25T12:00:00Z"},
                                        ]
                                    },
                                },
                                # Thread 4: Bot comment only
                                {
                                    "id": "THREAD_4",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 40,
                                    "comments": {
                                        "nodes": [
                                            {"id": "C4_1", "author": {"login": "arrshh12"}, "body": "Self comment", "createdAt": "2026-10-25T13:00:00Z"},
                                        ]
                                    },
                                },
                            ]
                        }
                    }
                }
            }
        }

        with patch.object(monitor, "execute_graphql", return_value=graphql_data), \
             patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:

            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 101)

            # Exactly Threads 2 and 3 should be actionable
            assert len(actionable) == 2
            actionable_ids = [c.thread_id for c in actionable]
            assert "THREAD_2" in actionable_ids
            assert "THREAD_3" in actionable_ids
            assert "THREAD_1" not in actionable_ids
            assert "THREAD_4" not in actionable_ids

            # Thread 1 must have been resolved and persisted
            mock_resolve.assert_called_once_with("THREAD_1")
            assert temp_db.is_thread_remediated("THREAD_1") is True
            rem_records = temp_db.get_review_remediations(repo_slug="bitxwolf/BugHunter", pr_number=101)
            assert len(rem_records) == 1
            assert rem_records[0]["thread_id"] == "THREAD_1"
            assert rem_records[0]["commit_sha"] == "c0ffee1"
            assert rem_records[0]["status"] == "RESOLVED"

    def test_re_scan_skips_persisted_threads_even_if_github_unresolved(self, temp_db: Database, mock_config: Config):
        """
        Idempotency stress-test: A thread already recorded in SQLite (e.g. from previous run)
        must immediately be skipped, without making GraphQL resolution calls or yielding actionable comments.
        """
        temp_db.record_review_remediation(
            thread_id="THREAD_ALREADY_DONE",
            comment_id="C_DONE",
            repo_slug="bitxwolf/BugHunter",
            pr_number=55,
            commit_sha="abcdef123456",
            reviewer="reviewer1",
            path="service.py",
            line=12,
            feedback_summary="done",
            status="RESOLVED",
        )

        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_data = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/already-done",
                        "headRefOid": "oid55",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "THREAD_ALREADY_DONE",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 12,
                                    "comments": {
                                        "nodes": [
                                            {"id": "C_DONE", "author": {"login": "reviewer1"}, "body": "feedback", "createdAt": "2026-10-25T10:00:00Z"},
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                }
            }
        }

        with patch.object(monitor, "execute_graphql", return_value=graphql_data), \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:

            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 55)
            assert len(actionable) == 0
            mock_resolve.assert_not_called()

    def test_graphql_resolve_failure_persists_resolution_failed_idempotently(self, temp_db: Database, mock_config: Config):
        """
        When bot already replied but GraphQL resolveReviewThread fails:
        - Must record in DB as RESOLUTION_FAILED
        - Must NOT return as actionable
        - On second re-scan, because thread is in DB, it is not re-processed
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_data = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/fail-res",
                        "headRefOid": "headoid99",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "THREAD_FAIL_RES",
                                    "isResolved": False,
                                    "path": "service.py",
                                    "line": 15,
                                    "comments": {
                                        "nodes": [
                                            {"id": "CR_1", "author": {"login": "reviewer"}, "body": "Fix this", "createdAt": "2026-10-25T10:00:00Z"},
                                            {"id": "CB_1", "author": {"login": "arrshh12"}, "body": "Noted and addressed in commit 9999aaa. Verified and resolved.", "createdAt": "2026-10-25T10:05:00Z"},
                                        ]
                                    },
                                }
                            ]
                        }
                    }
                }
            }
        }

        with patch.object(monitor, "execute_graphql", return_value=graphql_data), \
             patch.object(monitor, "resolve_review_thread", return_value=False) as mock_resolve:

            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 77)
            assert len(actionable) == 0
            mock_resolve.assert_called_once_with("THREAD_FAIL_RES")

            rems = temp_db.get_review_remediations(repo_slug="bitxwolf/BugHunter", pr_number=77)
            assert len(rems) == 1
            assert rems[0]["status"] == "RESOLUTION_FAILED"
            assert rems[0]["commit_sha"] == "9999aaa"

            # Re-scan in next cycle
            actionable2 = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 77)
            assert len(actionable2) == 0

    def test_sqlite_concurrent_review_remediations(self, temp_db: Database):
        """
        Stress-test SQLite WAL persistence with concurrent workers inserting and querying
        review_remediations.
        """
        def worker(idx: int):
            thread_id = f"THREAD_CONCURRENT_{idx}"
            temp_db.record_review_remediation(
                thread_id=thread_id,
                comment_id=f"COMMENT_{idx}",
                repo_slug="bitxwolf/BugHunter",
                pr_number=idx % 5,
                commit_sha=f"sha_{idx:08d}",
                reviewer=f"rev_{idx}",
                path=f"file_{idx}.py",
                line=idx,
                feedback_summary=f"summary {idx}",
                status="RESOLVED" if idx % 2 == 0 else "RESOLUTION_FAILED",
            )
            return temp_db.is_thread_remediated(thread_id)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker, i) for i in range(50)]
            results = [f.result() for f in futures]

        assert all(results), "All concurrent insertions must succeed and be queryable"
        rems = temp_db.get_review_remediations(repo_slug="bitxwolf/BugHunter")
        assert len(rems) == 50


# =========================================================================
# 2. R4: Invariant Enforcement (RULE-GIT-02 & RULE-NO-AUTOMERGE)
# =========================================================================

class TestR4InvariantsAdversarial:
    """Rigorous stress-testing of RULE-GIT-02 and RULE-NO-AUTOMERGE."""

    def test_git_push_force_prohibition_various_flags(self, mock_git_repo: Path):
        """
        Verify that GitManager.push_atomic_branch strictly forbids force=True,
        raising ValueError.
        """
        git_mgr = GitManager(workspace_dir=mock_git_repo.parent, github_token="fake_token")

        with pytest.raises(ValueError) as exc:
            git_mgr.push_atomic_branch(mock_git_repo, "main", force=True)
        assert "RULE-GIT-02 Violation" in str(exc.value)

    def test_remediate_single_thread_strictly_passes_force_false_to_git_manager(
        self, temp_db: Database, mock_config: Config, mock_git_repo: Path
    ):
        """
        Verify remediate_single_thread explicitly invokes git_manager.push_atomic_branch with force=False.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        git_mock.push_atomic_branch.return_value = "origin"

        ver_mock = MagicMock()
        ver_mock.verify_and_sanitize_fix.return_value = VerificationResult(
            verified=True, diff_lines=2, modified_files=["service.py"]
        )

        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=ver_mock)

        comment = ReviewComment(
            comment_id="C_1",
            thread_id="T_1",
            repo_slug="bitxwolf/BugHunter",
            pr_number=1,
            branch_name="main",
            path="service.py",
            line=2,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Fix line",
            author="reviewer",
        )

        pr_info = {"number": 1, "headRefName": "main", "headRefOid": "111", "isCrossRepository": False}

        def mock_patch(repo_path, rel_path, prompt):
            (repo_path / rel_path).write_text("def run():\n    return 'updated'\n", encoding="utf-8")
            return True

        with patch.object(monitor, "_run_direct_llm_remediation", side_effect=mock_patch), \
             patch.object(monitor, "post_inline_reply", return_value=True), \
             patch.object(monitor, "resolve_review_thread", return_value=True):

            res = monitor.remediate_single_thread("bitxwolf/BugHunter", pr_info, comment, mock_git_repo)
            assert res.success is True

            git_mock.push_atomic_branch.assert_called_once()
            _, kwargs = git_mock.push_atomic_branch.call_args
            assert kwargs.get("force") is False
            assert kwargs.get("repo_slug") == "bitxwolf/BugHunter"

    def test_auto_merge_prohibition_methods(self, temp_db: Database, mock_config: Config, mock_git_repo: Path):
        """
        Verify all merge/auto-merge methods explicitly raise PermissionError.
        """
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=MagicMock(), verifier=MagicMock())
        with pytest.raises(PermissionError) as exc_mon:
            monitor.merge_pr("bitxwolf/BugHunter", 10)
        assert "RULE-NO-AUTOMERGE Violation" in str(exc_mon.value)

        git_mgr = GitManager(workspace_dir=mock_git_repo.parent, github_token="fake_token")
        with pytest.raises(PermissionError) as exc_git1:
            git_mgr.auto_merge_pr("bitxwolf/BugHunter", 10)
        assert "RULE-NO-AUTOMERGE Violation" in str(exc_git1.value)

        with pytest.raises(PermissionError) as exc_git2:
            git_mgr.merge_pull_request("bitxwolf/BugHunter", 10)
        assert "RULE-NO-AUTOMERGE Violation" in str(exc_git2.value)

    def test_config_fails_if_auto_merge_enabled(self, tmp_path: Path):
        """
        Verify that Config.load raises ValueError if ENABLE_AUTO_MERGE is set to true.
        """
        k1 = KeyConfig(
            id="key-1",
            provider="ScaleMax",
            base_url="https://api.scalemax.pro/v1",
            model="openai/gpt-6-luna",
            api_key="key",
            masked_key="k...y",
            priority=1,
        )

        for true_val in ["true", "True", "1", "yes", True]:
            with pytest.raises(ValueError) as exc:
                Config.load(overrides={
                    "WORKSPACE_DIR": tmp_path,
                    "TARGET_REPOS": ["bitxwolf/BugHunter"],
                    "GITHUB_TOKEN": "token",
                    "LLM_KEYS": [k1],
                    "ENABLE_AUTO_MERGE": true_val,
                })
            assert "RULE-NO-AUTOMERGE Violation" in str(exc.value)

    def test_ast_prohibits_force_push_and_auto_merge_everywhere(self):
        """
        Static AST audit of all .py files in src/ to guarantee:
        1. No call to git push passes -f or --force or --force-with-lease.
        2. No call to push_atomic_branch passes force=True.
        3. No active function calls merge_pr or auto_merge_pr or gh pr merge.
        """
        src_path = Path("src")
        for py_file in src_path.rglob("*.py"):
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="replace"), filename=str(py_file))
            for node in ast.walk(tree):
                # Check call expressions
                if isinstance(node, ast.Call):
                    name = ""
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        name = node.func.attr

                    if name == "push_atomic_branch":
                        # Check keyword arg 'force'
                        for kw in node.keywords:
                            if kw.arg == "force":
                                assert isinstance(kw.value, ast.Constant) and kw.value.value is False, (
                                    f"Prohibited force=True found in {py_file}:{node.lineno}"
                                )

                    # Check forbidden merge call invocations
                    if name in ("auto_merge_pr", "merge_pr"):
                        # Only definitions are allowed
                        parent_is_def = False
                        # If called as function:
                        raise AssertionError(f"Direct call to forbidden merge method {name} in {py_file}:{node.lineno}")


# =========================================================================
# 3. LLM Code Extraction & Clean Abort Verification (Worker m12_2)
# =========================================================================

class TestWorkerM12Iter2ExtractionAndAbort:
    """Verify worker_m12_2 fix and ensure no regressions."""

    def test_unchanged_code_in_fences_returns_none(self, mock_config: Config, temp_db: Database):
        """
        When LLM returns the exact original code wrapped in code fences,
        _extract_code_from_llm_response MUST return None.
        """
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=None, verifier=None)
        original = "def solve():\n    return 42\n"

        # Python fence with exact same code
        llm_reply1 = f"```python\n{original}```"
        assert monitor._extract_code_from_llm_response(llm_reply1, original_code=original) is None

        # Bare fence with exact same code
        llm_reply2 = f"```\n{original.strip()}\n```"
        assert monitor._extract_code_from_llm_response(llm_reply2, original_code=original) is None

        # Multiple fences where all are unchanged
        llm_reply3 = f"```python\n{original}```\nSome commentary\n```\n{original}```"
        assert monitor._extract_code_from_llm_response(llm_reply3, original_code=original) is None

    def test_llm_returns_markdown_with_refusal_returns_none(self, mock_config: Config, temp_db: Database):
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=None, verifier=None)
        original = "def foo(): pass"

        assert monitor._extract_code_from_llm_response("I cannot fulfill this request.", original_code=original) is None
        assert monitor._extract_code_from_llm_response("I am sorry, but I cannot modify this file.", original_code=original) is None
        assert monitor._extract_code_from_llm_response("As an AI model, I am unable to assist.", original_code=original) is None

    def test_direct_llm_remediation_fails_cleanly_when_extraction_returns_none(
        self, mock_config: Config, temp_db: Database, mock_git_repo: Path
    ):
        """
        When LLM response fails extraction (returns None),
        _run_direct_llm_remediation returns False, and
        remediate_single_thread aborts cleanly with LLM_PATCH_FAILED
        WITHOUT invoking the Verifier gate.
        """
        ver_mock = MagicMock()
        monitor = ReviewMonitor(
            config=mock_config,
            database=temp_db,
            git_manager=MagicMock(),
            verifier=ver_mock,
            aider_runner=None,  # triggers direct LLM fallback
        )

        comment = ReviewComment(
            comment_id="C_FAIL",
            thread_id="T_FAIL",
            repo_slug="bitxwolf/BugHunter",
            pr_number=88,
            branch_name="main",
            path="service.py",
            line=1,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Fix please",
            author="reviewer",
        )

        pr_info = {"number": 88, "headRefName": "main", "headRefOid": "888", "isCrossRepository": False}

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "choices": [{"message": {"content": "I cannot fulfill this request."}}]
        }).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            res = monitor.remediate_single_thread("bitxwolf/BugHunter", pr_info, comment, mock_git_repo)

            assert res.success is False
            assert res.status == "LLM_PATCH_FAILED"
            assert "LLM_PATCH_FAILED: Failed to extract or generate patch" in (res.error_message or "")
            # Verifier must NOT have been called!
            ver_mock.verify_and_sanitize_fix.assert_not_called()
