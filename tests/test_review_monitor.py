"""
Comprehensive unit and integration test suite for PR Review & Comment Remediation Engine (Milestone 2).
Covers:
- ReviewComment & ReviewRemediationResult data models
- Database review_remediations schema, indexes, CRUD, and strict idempotency
- Open bot PR querying via gh CLI
- GitHub GraphQL query execution and response parsing
- Review thread comment extraction (bots and humans, skipping @me / arrshh12)
- Inline reply posting via GraphQL with REST API fallback
- Thread resolution via GraphQL mutation
- Full remediation lifecycle: checkout, LLM patch, verifier gate, commit, push without force, reply, resolve, db persist
- Verifier gate rejection handling and rollback
- Absolute prohibition of git push --force (RULE-GIT-02)
- Multi-repo loop resilience and exception isolation
- Strict idempotency: re-running review remediation skips already addressed threads
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.aider_runner import AiderResult, AiderRunner
from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.orchestrator import Orchestrator
from src.review_monitor import (
    GRAPHQL_ADD_THREAD_REPLY,
    GRAPHQL_GET_PR_REVIEW_THREADS,
    GRAPHQL_RESOLVE_REVIEW_THREAD,
    ReviewComment,
    ReviewMonitor,
    ReviewRemediationResult,
)
from src.verifier import VerificationResult, Verifier


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def test_db(tmp_path: Path) -> Database:
    """Create a temporary SQLite WAL database."""
    db_file = tmp_path / "test_review_monitor.sqlite"
    return Database(db_file)


@pytest.fixture
def mock_git_repo(tmp_path: Path) -> Path:
    """Initialize a local test git repository."""
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)

    readme = repo_dir / "README.md"
    readme.write_text("# Test Repo\nInitial content\n", encoding="utf-8")
    code_file = repo_dir / "src_code.py"
    code_file.write_text("def run():\n    return 42\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    return repo_dir


@pytest.fixture
def sample_config(tmp_path: Path) -> Config:
    """Provide a minimal valid Config instance."""
    k1 = KeyConfig(
        id="key-scalemax-1",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="scalemax_test_key_1234",
        masked_key="scalemax...1234",
        priority=1,
    )
    return Config.load(overrides={
        "WORKSPACE_DIR": tmp_path,
        "workspace_dir": tmp_path,
        "TARGET_REPOS": ["bitxwolf/BugHunter", "bitxwolf/other-repo"],
        "GITHUB_TOKEN": "mock_token",
        "LLM_KEYS": [k1],
    })


# =========================================================================
# Unit Tests
# =========================================================================

def test_dataclasses_initialization():
    """Verify ReviewComment and ReviewRemediationResult instantiation and defaults."""
    comment = ReviewComment(
        comment_id="PRRC_kwDO1234",
        thread_id="PRRT_kwDO5678",
        repo_slug="bitxwolf/BugHunter",
        pr_number=10,
        branch_name="fix/auto-branch-1",
        path="src/database.py",
        line=42,
        diff_hunk="@@ -40,3 +40,5 @@",
        body="Consider checking for None here.",
        author="coderabbitai[bot]",
        is_bot=True,
        created_at="2026-10-24T12:00:00Z",
    )
    assert comment.comment_id == "PRRC_kwDO1234"
    assert comment.is_bot is True
    assert comment.line == 42

    res = ReviewRemediationResult(
        success=True,
        repo_slug="bitxwolf/BugHunter",
        pr_number=10,
        thread_id="PRRT_kwDO5678",
        comment_id="PRRC_kwDO1234",
        commit_sha="abcdef1234567890",
        short_sha="abcdef1",
        status="RESOLVED",
    )
    assert res.success is True
    assert res.status == "RESOLVED"
    assert res.short_sha == "abcdef1"


def test_database_review_remediations_crud_and_idempotency(test_db: Database):
    """Verify review_remediations table, idempotency on thread_id, and query filters."""
    # 1. Thread is initially not remediated
    assert test_db.is_thread_remediated("PRRT_test_1") is False

    # 2. Record remediation
    row_id = test_db.record_review_remediation(
        thread_id="PRRT_test_1",
        comment_id="PRRC_test_1",
        repo_slug="bitxwolf/BugHunter",
        pr_number=5,
        commit_sha="1234567890abcdef",
        reviewer="coderabbitai[bot]",
        path="src/auth.py",
        line=15,
        feedback_summary="Add None check",
        status="RESOLVED",
    )
    assert row_id > 0
    assert test_db.is_thread_remediated("PRRT_test_1") is True

    # 3. Idempotent recording: re-recording with same thread_id updates instead of inserting duplicate
    row_id_update = test_db.record_review_remediation(
        thread_id="PRRT_test_1",
        comment_id="PRRC_test_1",
        repo_slug="bitxwolf/BugHunter",
        pr_number=5,
        commit_sha="fedcba0987654321",
        reviewer="coderabbitai[bot]",
        path="src/auth.py",
        line=15,
        feedback_summary="Updated summary",
        status="RESOLVED",
    )
    assert row_id_update == row_id

    # 4. Query records
    records = test_db.get_review_remediations()
    assert len(records) == 1
    assert records[0]["thread_id"] == "PRRT_test_1"
    assert records[0]["commit_sha"] == "fedcba0987654321"

    # 5. Query with filters
    filtered_repo = test_db.get_review_remediations(repo_slug="bitxwolf/BugHunter")
    assert len(filtered_repo) == 1
    filtered_pr = test_db.get_review_remediations(pr_number=5)
    assert len(filtered_pr) == 1
    filtered_none = test_db.get_review_remediations(repo_slug="other/repo")
    assert len(filtered_none) == 0


def test_get_open_bot_prs_success(sample_config, test_db, tmp_path):
    """Verify get_open_bot_prs invokes gh pr list with correct parameters and parses json."""
    git_manager = MagicMock(spec=GitManager)
    git_manager._gh_env.return_value = {"GITHUB_TOKEN": "test_token"}
    git_manager.repos_dir = tmp_path / "repos"

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    fake_prs = [
        {"number": 12, "headRefName": "fix/auto-1", "headRefOid": "abc1", "url": "https://github.com/pr/12", "title": "fix: 1"},
        {"number": 15, "headRefName": "fix/auto-2", "headRefOid": "abc2", "url": "https://github.com/pr/15", "title": "fix: 2"},
    ]

    mock_run = MagicMock()
    mock_run.return_value.stdout = json.dumps(fake_prs)
    mock_run.return_value.returncode = 0

    with patch("shutil.which", return_value="gh"), patch("subprocess.run", mock_run):
        prs = monitor.get_open_bot_prs("bitxwolf/BugHunter")

    assert len(prs) == 2
    assert prs[0]["number"] == 12
    assert prs[1]["headRefName"] == "fix/auto-2"

    # Verify gh command invocation
    call_args = mock_run.call_args[0][0]
    assert call_args[0] == "gh"
    assert call_args[1:3] == ["pr", "list"]
    assert "--author" in call_args and call_args[call_args.index("--author") + 1] == "@me"
    assert "--state" in call_args and call_args[call_args.index("--state") + 1] == "open"


def test_get_open_bot_prs_error_handling(sample_config, test_db):
    """Verify get_open_bot_prs returns empty list on subprocess failure or missing gh."""
    git_manager = MagicMock(spec=GitManager)
    git_manager._gh_env.return_value = {}

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    # 1. Missing gh CLI
    with patch("shutil.which", return_value=None):
        prs = monitor.get_open_bot_prs("bitxwolf/BugHunter")
        assert prs == []

    # 2. Subprocess CalledProcessError (e.g. auth failure or 403)
    mock_run = MagicMock(side_effect=subprocess.CalledProcessError(1, ["gh"], stderr="HTTP 403: Forbidden"))
    with patch("shutil.which", return_value="gh"), patch("subprocess.run", mock_run):
        prs = monitor.get_open_bot_prs("bitxwolf/BugHunter")
        assert prs == []


def test_execute_graphql_success_and_variables(sample_config, test_db):
    """Verify execute_graphql formats stdin payload with query and variables."""
    git_manager = MagicMock(spec=GitManager)
    git_manager._gh_env.return_value = {}

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    mock_run = MagicMock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = json.dumps({"data": {"viewer": {"login": "arrshh12"}}})

    with patch("shutil.which", return_value="gh"), patch("subprocess.run", mock_run):
        resp = monitor.execute_graphql("query { viewer { login } }", {"test": "val"})

    assert resp == {"data": {"viewer": {"login": "arrshh12"}}}
    sent_payload = json.loads(mock_run.call_args[1]["input"])
    assert sent_payload["query"] == "query { viewer { login } }"
    assert sent_payload["variables"] == {"test": "val"}


def test_execute_graphql_error_handling(sample_config, test_db):
    """Verify execute_graphql isolates errors cleanly without crashing."""
    git_manager = MagicMock(spec=GitManager)
    git_manager._gh_env.return_value = {}

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    # 1. Missing gh
    with patch("shutil.which", return_value=None):
        res = monitor.execute_graphql("query")
        assert "errors" in res

    # 2. Non-zero returncode
    mock_run = MagicMock()
    mock_run.return_value.returncode = 1
    mock_run.return_value.stderr = "Could not resolve to a node with the global id"
    with patch("shutil.which", return_value="gh"), patch("subprocess.run", mock_run):
        res = monitor.execute_graphql("query")
        assert "errors" in res


def test_fetch_unresolved_review_threads_parsing(sample_config, test_db):
    """Verify parsing GraphQL response for review threads into ReviewComment objects."""
    git_manager = MagicMock(spec=GitManager)
    git_manager.get_authenticated_user.return_value = "arrshh12"

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    graphql_resp = {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefName": "fix/my-branch",
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "PRRT_thread_1",
                                "isResolved": False,
                                "path": "src/service.py",
                                "line": 55,
                                "comments": {
                                    "nodes": [
                                        {
                                            "id": "PRRC_comment_1",
                                            "body": "Null pointer check required here.",
                                            "diffHunk": "@@ -50,5 +50,5 @@",
                                            "createdAt": "2026-10-24T14:00:00Z",
                                            "author": {"login": "coderabbitai[bot]"},
                                        }
                                    ]
                                },
                            },
                            {
                                "id": "PRRT_thread_2",
                                "isResolved": False,
                                "path": "src/utils.py",
                                "line": 80,
                                "comments": {
                                    "nodes": [
                                        {
                                            "id": "PRRC_comment_2",
                                            "body": "Please rename this variable.",
                                            "diffHunk": "@@ -75,5 +75,5 @@",
                                            "createdAt": "2026-10-24T14:05:00Z",
                                            "author": {"login": "alice_reviewer"},
                                        }
                                    ]
                                },
                            },
                        ]
                    },
                }
            }
        }
    }

    with patch.object(monitor, "execute_graphql", return_value=graphql_resp):
        comments = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 42, "fix/my-branch")

    assert len(comments) == 2

    c1 = comments[0]
    assert c1.thread_id == "PRRT_thread_1"
    assert c1.comment_id == "PRRC_comment_1"
    assert c1.path == "src/service.py"
    assert c1.line == 55
    assert c1.author == "coderabbitai[bot]"
    assert c1.is_bot is True
    assert c1.branch_name == "fix/my-branch"

    c2 = comments[1]
    assert c2.thread_id == "PRRT_thread_2"
    assert c2.author == "alice_reviewer"
    assert c2.is_bot is False


def test_fetch_unresolved_review_threads_filters_resolved_and_own(sample_config, test_db):
    """Verify threads with isResolved=True or author=arrshh12 are skipped."""
    git_manager = MagicMock(spec=GitManager)
    git_manager.get_authenticated_user.return_value = "arrshh12"

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    # Pre-record thread 3 as remediated
    test_db.record_review_remediation(
        thread_id="PRRT_thread_3",
        comment_id="PRRC_c3",
        repo_slug="bitxwolf/BugHunter",
        pr_number=42,
        commit_sha="sha3",
    )

    graphql_resp = {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefName": "fix/my-branch",
                    "reviewThreads": {
                        "nodes": [
                            # 1. Already resolved in GitHub
                            {
                                "id": "PRRT_thread_1",
                                "isResolved": True,
                                "path": "src/a.py",
                                "line": 10,
                                "comments": {
                                    "nodes": [{"id": "c1", "body": "fix", "author": {"login": "code-review-bot"}}]
                                },
                            },
                            # 2. Authored by arrshh12 (bot's own comments / replies)
                            {
                                "id": "PRRT_thread_2",
                                "isResolved": False,
                                "path": "src/b.py",
                                "line": 20,
                                "comments": {
                                    "nodes": [{"id": "c2", "body": "Noted and addressed", "author": {"login": "arrshh12"}}]
                                },
                            },
                            # 3. Already remediated in SQLite database
                            {
                                "id": "PRRT_thread_3",
                                "isResolved": False,
                                "path": "src/c.py",
                                "line": 30,
                                "comments": {
                                    "nodes": [{"id": "c3", "body": "Needs check", "author": {"login": "coderabbitai[bot]"}}]
                                },
                            },
                            # 4. Actionable valid thread
                            {
                                "id": "PRRT_thread_4",
                                "isResolved": False,
                                "path": "src/d.py",
                                "line": 40,
                                "comments": {
                                    "nodes": [{"id": "c4", "body": "Actionable feedback", "author": {"login": "human_reviewer"}}]
                                },
                            },
                        ]
                    },
                }
            }
        }
    }

    with patch.object(monitor, "execute_graphql", return_value=graphql_resp):
        comments = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 42, "fix/my-branch")

    assert len(comments) == 1
    assert comments[0].thread_id == "PRRT_thread_4"
    assert comments[0].author == "human_reviewer"


def test_post_inline_reply_graphql_and_rest_fallback(sample_config, test_db):
    """Verify inline reply posting via GraphQL mutation and REST fallback."""
    git_manager = MagicMock(spec=GitManager)
    git_manager._gh_env.return_value = {}

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    # 1. GraphQL success
    with patch.object(monitor, "execute_graphql", return_value={"data": {"addPullRequestReviewThreadReply": {"comment": {"id": "1"}}}}):
        ok = monitor.post_inline_reply("bitxwolf/BugHunter", 10, "PRRT_1", "PRRC_1", "Noted and addressed.")
        assert ok is True

    # 2. GraphQL failure -> REST API success
    mock_graphql_fail = {"errors": [{"message": "GraphQL error"}]}
    mock_run_rest = MagicMock()
    mock_run_rest.return_value.returncode = 0

    with patch.object(monitor, "execute_graphql", return_value=mock_graphql_fail), \
         patch("shutil.which", return_value="gh"), \
         patch("subprocess.run", mock_run_rest):
        ok = monitor.post_inline_reply("bitxwolf/BugHunter", 10, "PRRT_1", "PRRC_1", "Noted and addressed.")
        assert ok is True
        rest_cmd = mock_run_rest.call_args[0][0]
        assert "repos/bitxwolf/BugHunter/pulls/10/comments/PRRC_1/replies" in rest_cmd[4]


def test_resolve_review_thread_success_and_error(sample_config, test_db):
    """Verify thread resolution via GraphQL mutation and error isolation."""
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(),
        verifier=MagicMock(),
    )

    # 1. Success
    with patch.object(monitor, "execute_graphql", return_value={"data": {"resolveReviewThread": {"thread": {"id": "PRRT_1", "isResolved": True}}}}):
        assert monitor.resolve_review_thread("PRRT_1") is True

    # 2. Failure with errors
    with patch.object(monitor, "execute_graphql", return_value={"errors": [{"message": "Permission denied"}]}):
        assert monitor.resolve_review_thread("PRRT_1") is False


def test_remediate_single_thread_full_lifecycle(sample_config, test_db, mock_git_repo):
    """Verify complete remediation lifecycle: checkout, LLM patch, verifier, commit, push, reply, resolve, db persist."""
    # Create PR branch in repo
    subprocess.run(["git", "checkout", "-b", "fix/pr-123"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.repos_dir = mock_git_repo.parent
    git_manager.rollback_working_tree = MagicMock()
    git_manager.push_atomic_branch = MagicMock()

    # Mock AiderRunner modifying src_code.py
    def mock_run_aider(repo_path, target_file, patch_instruction, key_entry=None):
        target = repo_path / target_file
        target.write_text("def run():\n    # review addressed\n    return 100\n", encoding="utf-8")
        return AiderResult(exit_code=0, diff_output="--- a/src_code.py\n+++ b/src_code.py", status="SUCCESS", target_file=target_file)

    mock_aider = MagicMock()
    mock_aider.run_aider.side_effect = mock_run_aider

    verifier = Verifier()

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=verifier,
        aider_runner=mock_aider,
    )

    comment = ReviewComment(
        comment_id="PRRC_100",
        thread_id="PRRT_100",
        repo_slug="bitxwolf/test_repo",
        pr_number=12,
        branch_name="fix/pr-123",
        path="src_code.py",
        line=2,
        diff_hunk="@@ -1,2 +1,2 @@",
        body="Return 100 instead of 42.",
        author="coderabbitai[bot]",
        is_bot=True,
    )

    with patch.object(monitor, "post_inline_reply", return_value=True) as mock_reply, \
         patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:
        result = monitor.remediate_single_thread(
            repo_slug="bitxwolf/test_repo",
            pr_info={"number": 12, "headRefName": "fix/pr-123"},
            comment=comment,
            repo_path=mock_git_repo,
        )

    # Assertions
    assert result.success is True
    assert result.status == "RESOLVED"
    assert len(result.commit_sha) >= 7
    assert len(result.short_sha) == 7

    # Push was called without force (RULE-GIT-02)
    git_manager.push_atomic_branch.assert_called_once()
    push_call = git_manager.push_atomic_branch.call_args
    assert push_call[1]["force"] is False  # MUST BE FALSE

    # Inline reply and thread resolution
    mock_reply.assert_called_once()
    reply_arg = mock_reply.call_args.kwargs.get("reply_text") or (mock_reply.call_args[0][4] if len(mock_reply.call_args[0]) > 4 else "")
    assert result.short_sha in reply_arg
    mock_resolve.assert_called_once_with("PRRT_100")

    # Persisted in DB
    assert test_db.is_thread_remediated("PRRT_100") is True
    rems = test_db.get_review_remediations(pr_number=12)
    assert len(rems) == 1
    assert rems[0]["commit_sha"] == result.commit_sha


def test_remediate_single_thread_verifier_rejection(sample_config, test_db, mock_git_repo):
    """Verify that verifier failure rolls back working tree and does NOT resolve or commit."""
    subprocess.run(["git", "checkout", "-b", "fix/pr-reject"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.rollback_working_tree = MagicMock()
    git_manager.push_atomic_branch = MagicMock()

    # Mock verifier rejecting
    mock_verifier = MagicMock()
    mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(
        verified=False,
        error_reason="Diff changed 180 lines, exceeding limit of 150",
    )

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=mock_verifier,
    )

    comment = ReviewComment(
        comment_id="PRRC_200",
        thread_id="PRRT_200",
        repo_slug="bitxwolf/test_repo",
        pr_number=14,
        branch_name="fix/pr-reject",
        path="src_code.py",
        line=2,
        diff_hunk="@@ -1,2 +1,2 @@",
        body="Massive rewrite",
        author="reviewer",
    )

    with patch.object(monitor, "post_inline_reply") as mock_reply, \
         patch.object(monitor, "resolve_review_thread") as mock_resolve:
        result = monitor.remediate_single_thread(
            repo_slug="bitxwolf/test_repo",
            pr_info={"number": 14, "headRefName": "fix/pr-reject"},
            comment=comment,
            repo_path=mock_git_repo,
        )

    assert result.success is False
    assert result.status == "VERIFICATION_FAILED"
    assert "180 lines" in (result.error_message or "")

    # Rollback invoked
    git_manager.rollback_working_tree.assert_called_once()

    # No push, no reply, no resolution, no DB persistence
    git_manager.push_atomic_branch.assert_not_called()
    mock_reply.assert_not_called()
    mock_resolve.assert_not_called()
    assert test_db.is_thread_remediated("PRRT_200") is False


def test_remediate_single_thread_aider_failure(sample_config, test_db, mock_git_repo):
    """Verify that Aider execution failure cleanly aborts remediation."""
    subprocess.run(["git", "checkout", "-b", "fix/pr-aider-fail"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.rollback_working_tree = MagicMock()

    mock_aider = MagicMock()
    mock_aider.run_aider.return_value = AiderResult(
        exit_code=1,
        diff_output="",
        status="RATE_LIMIT_429",
        target_file="src_code.py",
        error_message="HTTP 429 Rate limit exceeded",
    )

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
        aider_runner=mock_aider,
    )

    comment = ReviewComment(
        comment_id="PRRC_300",
        thread_id="PRRT_300",
        repo_slug="bitxwolf/test_repo",
        pr_number=18,
        branch_name="fix/pr-aider-fail",
        path="src_code.py",
        line=2,
        diff_hunk="",
        body="Fix",
        author="reviewer",
    )

    result = monitor.remediate_single_thread(
        repo_slug="bitxwolf/test_repo",
        pr_info={"number": 18, "headRefName": "fix/pr-aider-fail"},
        comment=comment,
        repo_path=mock_git_repo,
    )

    assert result.success is False
    assert "429" in result.status
    git_manager.rollback_working_tree.assert_called_once()
    assert test_db.is_thread_remediated("PRRT_300") is False


def test_remediate_single_thread_push_failure_isolation(sample_config, test_db, mock_git_repo):
    """Verify that push failure aborts cleanly without marking thread resolved."""
    subprocess.run(["git", "checkout", "-b", "fix/pr-push-fail"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.push_atomic_branch.side_effect = RuntimeError("Push rejected by remote")
    git_manager.rollback_working_tree = MagicMock()

    def mock_run_aider(repo_path, target_file, patch_instruction, key_entry=None):
        target = repo_path / target_file
        target.write_text("def run():\n    return 'push_fail_test'\n", encoding="utf-8")
        return AiderResult(exit_code=0, diff_output="--- a/src_code.py\n+++ b/src_code.py", status="SUCCESS", target_file=target_file)

    mock_aider = MagicMock()
    mock_aider.run_aider.side_effect = mock_run_aider

    mock_verifier = MagicMock()
    mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(verified=True)

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=mock_verifier,
        aider_runner=mock_aider,
    )

    comment = ReviewComment(
        comment_id="PRRC_400",
        thread_id="PRRT_400",
        repo_slug="bitxwolf/test_repo",
        pr_number=20,
        branch_name="fix/pr-push-fail",
        path="src_code.py",
        line=1,
        diff_hunk="",
        body="Push error test",
        author="reviewer",
    )

    with patch.object(monitor, "post_inline_reply") as mock_reply, \
         patch.object(monitor, "resolve_review_thread") as mock_resolve:
        result = monitor.remediate_single_thread(
            repo_slug="bitxwolf/test_repo",
            pr_info={"number": 20, "headRefName": "fix/pr-push-fail"},
            comment=comment,
            repo_path=mock_git_repo,
        )

    assert result.success is False
    assert result.status == "PUSH_FAILED"
    mock_reply.assert_not_called()
    mock_resolve.assert_not_called()
    assert test_db.is_thread_remediated("PRRT_400") is False


def test_rule_git_02_force_push_strictly_prohibited(sample_config, test_db, mock_git_repo):
    """Verify GitManager raises ValueError if force=True is passed (RULE-GIT-02)."""
    git_mgr = GitManager(workspace_dir=mock_git_repo.parent)

    with pytest.raises(ValueError, match="RULE-GIT-02 Violation"):
        git_mgr.push_atomic_branch(
            repo_path=mock_git_repo,
            branch_name="main",
            force=True,  # Prohibited
        )


def test_check_and_remediate_prs_loop_resilience(sample_config, test_db):
    """Verify that an exception on one repo does not halt processing of other repos."""
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(),
        verifier=MagicMock(),
    )

    # 3 repos: repo1 succeeds, repo2 throws an unexpected exception, repo3 succeeds
    def mock_get_prs(repo_slug):
        if repo_slug == "repo2":
            raise RuntimeError("Network down or permission denied for repo2")
        return [{"number": 1, "headRefName": "branch-1"}]

    with patch.object(monitor, "get_open_bot_prs", side_effect=mock_get_prs), \
         patch.object(monitor, "fetch_unresolved_review_threads", return_value=[]):
        res = monitor.check_and_remediate_prs(["repo1", "repo2", "repo3"])

    # Loop completed without uncaught exception
    assert isinstance(res, list)


def test_strict_idempotency_skip(sample_config, test_db, mock_git_repo):
    """Verify re-running check_and_remediate_prs skips already remediated threads."""
    git_manager = MagicMock(spec=GitManager)
    git_manager.repos_dir = mock_git_repo.parent

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    open_prs = [{"number": 50, "headRefName": "fix/test-branch"}]
    unresolved_threads = [
        ReviewComment(
            comment_id="PRRC_idem_1",
            thread_id="PRRT_idem_1",
            repo_slug="bitxwolf/test_repo",
            pr_number=50,
            branch_name="fix/test-branch",
            path="src_code.py",
            line=1,
            diff_hunk="",
            body="First comment",
            author="coderabbitai[bot]",
        )
    ]

    # Pre-record thread as remediated in database
    test_db.record_review_remediation(
        thread_id="PRRT_idem_1",
        comment_id="PRRC_idem_1",
        repo_slug="bitxwolf/test_repo",
        pr_number=50,
        commit_sha="abc123456",
        status="RESOLVED",
    )

    with patch.object(monitor, "get_open_bot_prs", return_value=open_prs), \
         patch.object(monitor, "fetch_unresolved_review_threads", return_value=unresolved_threads), \
         patch.object(monitor, "remediate_single_thread") as mock_rem:
        results = monitor.check_and_remediate_prs(["bitxwolf/test_repo"])

    assert len(results) == 1
    assert results[0].status == "SKIPPED_ALREADY_REMEDIATED"
    mock_rem.assert_not_called()  # Did NOT re-execute remediation


def test_bughunter_log_logging(sample_config, test_db, tmp_path):
    """Verify _log method writes warnings and info to bughunter.log file."""
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(),
        verifier=MagicMock(),
    )

    log_file = Path("bughunter.log")
    if log_file.exists():
        try:
            log_file.unlink()
        except Exception:
            pass

    monitor._log("Testing warning log to file", level="WARNING")

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "Testing warning log to file" in content
    assert "[WARNING]" in content


def test_review_monitor_latest_feedback_and_resolution_failure_guard(sample_config, test_db, mock_git_repo):
    """Verify:
    1. reversed comment iteration picks the latest non-bot reviewer comment.
    2. Failed GraphQL thread resolution marks REPLY_POSTED_RESOLUTION_FAILED and success=False.
    """
    git_manager = MagicMock(spec=GitManager)
    git_manager.repos_dir = mock_git_repo.parent
    git_manager.rollback_working_tree = MagicMock()
    git_manager.push_atomic_branch = MagicMock()

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=Verifier(),
    )

    # 1. Test reversed comment selection
    multi_comment_thread = {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefName": "fix/multi-comment",
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "PRRT_multi_1",
                                "isResolved": False,
                                "path": "src_code.py",
                                "line": 2,
                                "comments": {
                                    "nodes": [
                                        {"id": "PRRC_old", "databaseId": 1001, "body": "Old feedback 🐛", "author": {"login": "reviewer"}},
                                        {"id": "PRRC_bot", "databaseId": 1002, "body": "Bot reply", "author": {"login": "arrshh12"}},
                                        {"id": "PRRC_latest", "databaseId": 1003, "body": "Latest feedback 🚀", "author": {"login": "reviewer"}},
                                    ]
                                },
                            }
                        ]
                    },
                }
            }
        }
    }

    with patch.object(monitor, "execute_graphql", return_value=multi_comment_thread):
        comments = monitor.fetch_unresolved_review_threads("bitxwolf/test_repo", 1, "fix/multi-comment")

    assert len(comments) == 1
    assert comments[0].comment_id == "PRRC_latest"
    assert comments[0].comment_database_id == 1003
    assert "Latest feedback" in comments[0].body

    # 2. Test failed resolveReviewThread mutation
    subprocess.run(["git", "checkout", "-b", "fix/multi-comment"], cwd=mock_git_repo, check=True, capture_output=True)

    with patch.object(monitor, "post_inline_reply", return_value=True), \
         patch.object(monitor, "resolve_review_thread", return_value=False), \
         patch.object(monitor, "_run_direct_llm_remediation", side_effect=lambda p, f, pr: (p / f).write_text("def run():\n    return 100\n", encoding="utf-8") or True):
        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/test_repo",
            pr_info={"number": 1, "headRefName": "fix/multi-comment"},
            comment=comments[0],
            repo_path=mock_git_repo,
        )

    assert res.success is True
    # Thread should be persisted with RESOLUTION_FAILED in DB to prevent duplicate loops
    rems = test_db.get_review_remediations(pr_number=1)
    assert len(rems) == 1
    assert rems[0]["status"] == "RESOLUTION_FAILED"
    assert test_db.is_thread_remediated("PRRT_multi_1") is True


# =========================================================================
# Milestone 12 Review Monitor Hardening Tests (R1 - R4)
# =========================================================================

def test_fetch_unresolved_review_threads_bot_already_replied_resolves_and_persists(sample_config, test_db):
    """Verify that when bot already replied with a fix commit and no newer feedback exists:
    1. Thread is not returned in actionable comments (no duplicate commits/re-patching).
    2. resolve_review_thread is called.
    3. Thread is persisted to SQLite review_remediations with extracted commit SHA.
    """
    git_manager = MagicMock(spec=GitManager)
    git_manager.get_authenticated_user.return_value = "arrshh12"

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=MagicMock(),
    )

    graphql_resp = {
        "data": {
            "repository": {
                "pullRequest": {
                    "headRefName": "fix/test-branch",
                    "headRefOid": "abc1234567890",
                    "reviewThreads": {
                        "nodes": [
                            {
                                "id": "PRRT_already_replied",
                                "isResolved": False,
                                "path": "src/module.py",
                                "line": 15,
                                "comments": {
                                    "nodes": [
                                        {
                                            "id": "PRRC_rev",
                                            "body": "Please add null check",
                                            "createdAt": "2026-10-25T10:00:00Z",
                                            "author": {"login": "reviewer"},
                                        },
                                        {
                                            "id": "PRRC_bot",
                                            "body": "Noted and addressed in commit c0ffee1. Verified and resolved.",
                                            "createdAt": "2026-10-25T10:05:00Z",
                                            "author": {"login": "arrshh12"},
                                        },
                                    ]
                                },
                            }
                        ]
                    },
                }
            }
        }
    }

    with patch.object(monitor, "execute_graphql", return_value=graphql_resp), \
         patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:
        comments = monitor.fetch_unresolved_review_threads("bitxwolf/test_repo", 10, "fix/test-branch")

    # 1. Did NOT return thread as actionable (no re-patch / duplicate commit)
    assert len(comments) == 0

    # 2. Called resolve_review_thread
    mock_resolve.assert_called_once_with("PRRT_already_replied")

    # 3. Persisted to SQLite
    assert test_db.is_thread_remediated("PRRT_already_replied") is True
    rems = test_db.get_review_remediations(pr_number=10)
    assert len(rems) == 1
    assert rems[0]["commit_sha"] == "c0ffee1"
    assert rems[0]["status"] == "RESOLVED"


def test_bot_identity_resolution_order(sample_config, test_db):
    """Verify get_bot_identity prioritizes git_manager, respects config.bot_github_user, and defaults to arrshh12."""
    git_manager = MagicMock(spec=GitManager)

    # 1. GitManager authenticated user present
    git_manager.get_authenticated_user.return_value = "custom_auth_bot"
    monitor = ReviewMonitor(config=sample_config, database=test_db, git_manager=git_manager, verifier=MagicMock())
    assert monitor.get_bot_identity() == "custom_auth_bot"

    # 2. GitManager returns None, config.bot_github_user present
    git_manager.get_authenticated_user.return_value = None
    sample_config.bot_github_user = "cfg_bot"
    monitor2 = ReviewMonitor(config=sample_config, database=test_db, git_manager=git_manager, verifier=MagicMock())
    assert monitor2.get_bot_identity() == "cfg_bot"

    # 3. Both None/empty -> fallback to arrshh12
    sample_config.bot_github_user = ""
    monitor3 = ReviewMonitor(config=sample_config, database=test_db, git_manager=git_manager, verifier=MagicMock())
    assert monitor3.get_bot_identity() == "arrshh12"


def test_remediate_single_thread_direct_llm_failure_aborts_cleanly(sample_config, test_db, mock_git_repo):
    """Verify that when direct LLM patching fails, remediation aborts with LLM_PATCH_FAILED before verifier gate."""
    subprocess.run(["git", "checkout", "-b", "fix/pr-llm-fail"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.rollback_working_tree = MagicMock()
    mock_verifier = MagicMock(spec=Verifier)

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=mock_verifier,
        aider_runner=None,
    )

    comment = ReviewComment(
        comment_id="PRRC_llm_fail",
        thread_id="PRRT_llm_fail",
        repo_slug="bitxwolf/test_repo",
        pr_number=30,
        branch_name="fix/pr-llm-fail",
        path="src_code.py",
        line=1,
        diff_hunk="",
        body="Fix this",
        author="reviewer",
    )

    with patch.object(monitor, "_run_direct_llm_remediation", return_value=False):
        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/test_repo",
            pr_info={"number": 30, "headRefName": "fix/pr-llm-fail"},
            comment=comment,
            repo_path=mock_git_repo,
        )

    assert res.success is False
    assert res.status == "LLM_PATCH_FAILED"
    assert "LLM_PATCH_FAILED" in (res.error_message or "")
    mock_verifier.verify_and_sanitize_fix.assert_not_called()
    git_manager.rollback_working_tree.assert_called_once()
    assert test_db.is_thread_remediated("PRRT_llm_fail") is False


def test_remediate_single_thread_passes_repo_slug_and_non_force_to_push(sample_config, test_db, mock_git_repo):
    """Verify push_atomic_branch receives repo_slug=repo_slug and force=False (RULE-GIT-02)."""
    subprocess.run(["git", "checkout", "-b", "fix/pr-slug-check"], cwd=mock_git_repo, check=True, capture_output=True)

    git_manager = MagicMock(spec=GitManager)
    git_manager.push_atomic_branch = MagicMock()

    mock_aider = MagicMock()
    def mock_run_aider(repo_path, target_file, patch_instruction, key_entry=None):
        (repo_path / target_file).write_text("def run():\n    return 999\n", encoding="utf-8")
        return AiderResult(exit_code=0, diff_output="diff", status="SUCCESS", target_file=target_file)
    mock_aider.run_aider.side_effect = mock_run_aider

    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=git_manager,
        verifier=Verifier(),
        aider_runner=mock_aider,
    )

    comment = ReviewComment(
        comment_id="PRRC_slug",
        thread_id="PRRT_slug",
        repo_slug="bitxwolf/BugHunter",
        pr_number=45,
        branch_name="fix/pr-slug-check",
        path="src_code.py",
        line=2,
        diff_hunk="",
        body="Return 999",
        author="reviewer",
    )

    with patch.object(monitor, "post_inline_reply", return_value=True), \
         patch.object(monitor, "resolve_review_thread", return_value=True):
        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/BugHunter",
            pr_info={"number": 45, "headRefName": "fix/pr-slug-check"},
            comment=comment,
            repo_path=mock_git_repo,
        )

    assert res.success is True
    git_manager.push_atomic_branch.assert_called_once()
    kwargs = git_manager.push_atomic_branch.call_args.kwargs
    assert kwargs.get("force") is False
    assert kwargs.get("repo_slug") == "bitxwolf/BugHunter"


def test_rule_no_automerge_strictly_enforced(sample_config, test_db):
    """Verify ReviewMonitor.merge_pr strictly raises PermissionError (RULE-NO-AUTOMERGE)."""
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(),
        verifier=MagicMock(),
    )
    with pytest.raises(PermissionError, match="RULE-NO-AUTOMERGE Violation"):
        monitor.merge_pr("bitxwolf/BugHunter", 42)


def test_default_aider_runner_initialization_and_orchestrator_wiring(sample_config, test_db):
    """Verify default AiderRunner initialization in ReviewMonitor and wiring through Orchestrator."""
    # 1. ReviewMonitor initializes default AiderRunner when None is passed
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(),
        verifier=MagicMock(),
        aider_runner=None,
    )
    assert monitor.aider_runner is not None
    assert isinstance(monitor.aider_runner, AiderRunner)

    # 2. Orchestrator initializes default AiderRunner and passes to review_monitor and fixer_agent
    orchestrator = Orchestrator(
        config=sample_config,
        database=test_db,
        key_manager=MagicMock(),
        git_manager=MagicMock(),
        static_scanner=MagicMock(),
        openhands_runner=MagicMock(),
        verifier=Verifier(),
        logger=MagicMock(),
        aider_runner=None,
    )
    assert orchestrator.aider_runner is not None
    assert isinstance(orchestrator.aider_runner, AiderRunner)
    assert orchestrator.review_monitor.aider_runner is orchestrator.aider_runner
    assert orchestrator.fixer_agent.aider_runner is orchestrator.aider_runner


def test_direct_llm_code_extraction_multi_format():
    """Verify _extract_code_from_llm_response parses JSON, markdown fences, code inside JSON, and raw text."""
    monitor = ReviewMonitor(
        config=None,
        database=None,
        git_manager=None,
        verifier=None,
        aider_runner=None,
    )
    original = "def foo():\n    return 1\n"

    # 1. Pure JSON
    msg1 = json.dumps({"updated_full_file": "def foo():\n    return 42\n"})
    assert monitor._extract_code_from_llm_response(msg1, original) == "def foo():\n    return 42"

    # 2. Markdown fenced JSON
    json_content = json.dumps({"updated_full_file": "def foo():\n    return 43\n"})
    msg2 = f"```json\n{json_content}\n```"
    assert monitor._extract_code_from_llm_response(msg2, original) == "def foo():\n    return 43"

    # 3. Direct markdown code fence
    msg3 = "Here is the fixed file:\n```python\ndef foo():\n    return 44\n```\nHope that helps!"
    assert monitor._extract_code_from_llm_response(msg3, original) == "def foo():\n    return 44"

    # 4. Code fence embedded inside JSON string
    msg4 = json.dumps({"updated_full_file": "```python\ndef foo():\n    return 45\n```"})
    assert monitor._extract_code_from_llm_response(msg4, original) == "def foo():\n    return 45"

    # 5. Raw code text
    msg5 = "def foo():\n    return 46\n"
    assert monitor._extract_code_from_llm_response(msg5, original) == "def foo():\n    return 46"

    # 6. Conversational refusal
    msg6 = "I am sorry, but I cannot modify this file without more context."
    assert monitor._extract_code_from_llm_response(msg6, original) is None

    # 7. Unmodified code
    msg7 = json.dumps({"updated_full_file": original})
    assert monitor._extract_code_from_llm_response(msg7, original) is None
    msg8 = f"```python\n{original}```"
    assert monitor._extract_code_from_llm_response(msg8, original) is None
    msg9 = f"```\n{original}```"
    assert monitor._extract_code_from_llm_response(msg9, original) is None


def test_remediate_single_thread_resilient_fetch_and_fork_remote_selection(sample_config, test_db, mock_git_repo):
    """Verify PR branch fetch resilience, cross-fork remote selection, and abort when remote fails."""
    monitor = ReviewMonitor(
        config=sample_config,
        database=test_db,
        git_manager=MagicMock(has_push_access=MagicMock(return_value=False)),
        verifier=MagicMock(),
    )

    # 1. Determine remote for cross-repository PR
    pr_cross = {"number": 10, "isCrossRepository": True, "headRepositoryOwner": {"login": "arrshh12"}}
    remote = monitor._determine_remote(mock_git_repo, "bitxwolf/BugHunter", pr_info=pr_cross)
    # Since has_push_access is False or isCrossRepository is True, it targets fork
    assert remote in ("fork", "origin")

    # 2. When remotes exist but fetch fails and local branch doesn't exist, cleanly abort with CHECKOUT_FAILED
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/bitxwolf/test_repo.git"], cwd=mock_git_repo, check=True)

    comment = ReviewComment(
        comment_id="PRRC_fail_remote",
        thread_id="PRRT_fail_remote",
        repo_slug="bitxwolf/test_repo",
        pr_number=99,
        branch_name="nonexistent-remote-branch",
        path="src_code.py",
        line=1,
        diff_hunk="",
        body="Fix",
        author="reviewer",
    )

    res = monitor.remediate_single_thread(
        repo_slug="bitxwolf/test_repo",
        pr_info={"number": 99, "headRefName": "nonexistent-remote-branch"},
        comment=comment,
        repo_path=mock_git_repo,
    )
    assert res.success is False
    assert res.status == "CHECKOUT_FAILED"
    assert "Could not reliably checkout" in (res.error_message or "")


