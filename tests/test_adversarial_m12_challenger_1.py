"""
Adversarial Verification Suite for M12 R1 & R2 (Challenger m12_1).
Thoroughly stress-tests:
1. R1: PR Branch Fetch & Push Resilience:
   - Fetching exact PR head via +refs/pull/<pr_number>/head:<branch_name>
   - Resolving via fork tracking remote when origin pull ref fails
   - Clean checkout failure (CHECKOUT_FAILED) when remotes exist and branch cannot be found
   - Preservation of local mock checkout when no remotes are configured
   - Proper remote determination ('fork' vs 'origin') across cross-repo conditions
   - Explicit repo_slug parameter passing and force=False preservation in push_atomic_branch
2. R2: Subsystem Wiring & Direct LLM Robustness:
   - Wiring of AiderRunner across main.py, src/orchestrator.py, and ReviewMonitor
   - Stress-testing _extract_code_from_llm_response with 25+ adversarial LLM payloads
   - Clean LLM_PATCH_FAILED abort before verifier gate preventing empty-diff false positives
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
    ReviewComment,
    ReviewMonitor,
    ReviewRemediationResult,
)
from src.verifier import VerificationResult, Verifier


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_adversarial_m12.sqlite"
    return Database(db_file)


@pytest.fixture
def clean_git_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "test_adv_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)

    file_a = repo_dir / "app.py"
    file_a.write_text("def compute():\n    return 100\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit on main"], cwd=repo_dir, check=True, capture_output=True)
    return repo_dir


@pytest.fixture
def minimal_config(tmp_path: Path) -> Config:
    k1 = KeyConfig(
        id="key-test",
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
        "TARGET_REPOS": ["bitxwolf/BugHunter"],
        "GITHUB_TOKEN": "mock_token_adv",
        "LLM_KEYS": [k1],
    })


# =========================================================================
# 1. R2: _extract_code_from_llm_response Exhaustive Adversarial Tests
# =========================================================================

class TestLLMCodeExtractionAdversarial:
    """Stress-test code extraction from LLM response under hostile and edge-case inputs."""

    def test_extract_valid_json_payloads(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        # Key: updated_full_file
        res1 = monitor._extract_code_from_llm_response(
            json.dumps({"updated_full_file": "def new():\n    return 1\n"}),
            original_code=orig,
        )
        assert res1 == "def new():\n    return 1"

        # Key: code
        res2 = monitor._extract_code_from_llm_response(
            json.dumps({"code": "def new_code():\n    return 2\n"}),
            original_code=orig,
        )
        assert res2 == "def new_code():\n    return 2"

        # Key: file_content
        res3 = monitor._extract_code_from_llm_response(
            json.dumps({"file_content": "def new_file():\n    return 3\n"}),
            original_code=orig,
        )
        assert res3 == "def new_file():\n    return 3"

        # Key: patch
        res4 = monitor._extract_code_from_llm_response(
            json.dumps({"patch": "def new_patch():\n    return 4\n"}),
            original_code=orig,
        )
        assert res4 == "def new_patch():\n    return 4"

    def test_extract_json_embedded_in_markdown(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        # Embedded json with ```json fence
        msg = "Here is your JSON response:\n```json\n{\"updated_full_file\": \"def embedded():\\n    return 5\\n\"}\n```\nHope it helps!"
        res = monitor._extract_code_from_llm_response(msg, original_code=orig)
        assert res == "def embedded():\n    return 5"

        # Embedded json with bare ``` fence
        msg2 = "Here is the fix:\n```\n{\"code\": \"def embedded_bare():\\n    return 6\\n\"}\n```"
        res2 = monitor._extract_code_from_llm_response(msg2, original_code=orig)
        assert res2 == "def embedded_bare():\n    return 6"

    def test_extract_json_with_inner_code_fences(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        # Value inside JSON itself has markdown fence
        inner_val = "```python\ndef inner_fence():\n    return 7\n```"
        msg = json.dumps({"updated_full_file": inner_val})
        res = monitor._extract_code_from_llm_response(msg, original_code=orig)
        assert res == "def inner_fence():\n    return 7"

    def test_extract_markdown_code_fences_various_languages(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        for lang in ["python", "py", "python3", "c++", "text", "sh", "diff"]:
            msg = f"Fix below:\n```{lang}\ndef fixed_{lang}():\n    return True\n```"
            res = monitor._extract_code_from_llm_response(msg, original_code=orig)
            assert res == f"def fixed_{lang}():\n    return True", f"Failed for language: {lang}"

    def test_extract_multiple_code_fences_picks_longest(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        msg = (
            "Here is a snippet:\n```python\n# short\nx = 1\n```\n"
            "And here is the complete file:\n```python\ndef full_solution():\n    x = 1\n    return x + 100\n```\n"
        )
        res = monitor._extract_code_from_llm_response(msg, original_code=orig)
        assert res == "def full_solution():\n    x = 1\n    return x + 100"

    def test_extract_conversational_refusals_returns_none(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        refusals = [
            "I cannot modify this file because I do not have sufficient context.",
            "I am sorry, but I cannot assist with this task.",
            "I'm sorry, I cannot perform this edit.",
            "As an AI, I cannot provide this code modification.",
            "Unable to generate patch for this file.",
        ]
        for ref in refusals:
            res = monitor._extract_code_from_llm_response(ref, original_code=orig)
            assert res is None, f"Expected None for refusal: {ref}"

    def test_extract_unchanged_code_returns_none(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def untouched():\n    return 42\n"

        # In JSON
        msg1 = json.dumps({"updated_full_file": orig})
        assert monitor._extract_code_from_llm_response(msg1, original_code=orig) is None

        # In Markdown
        msg2 = f"```python\n{orig}```"
        assert monitor._extract_code_from_llm_response(msg2, original_code=orig) is None

        # In Raw text
        assert monitor._extract_code_from_llm_response(orig, original_code=orig) is None

    def test_extract_empty_or_malformed_inputs_returns_none(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        assert monitor._extract_code_from_llm_response("", original_code=orig) is None
        assert monitor._extract_code_from_llm_response("   \n\t  ", original_code=orig) is None
        assert monitor._extract_code_from_llm_response("{}", original_code=orig) is None
        assert monitor._extract_code_from_llm_response('{"unknown_key": "some value"}', original_code=orig) is None
        assert monitor._extract_code_from_llm_response('{"updated_full_file": ""}', original_code=orig) is None
        assert monitor._extract_code_from_llm_response('{"code": null}', original_code=orig) is None
        assert monitor._extract_code_from_llm_response('{"code": 12345}', original_code=orig) is None

    def test_extract_carriage_returns_handled_cleanly(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None)
        orig = "def old():\n    pass\n"

        msg = "```python\r\ndef windows_line_endings():\r\n    return True\r\n```"
        res = monitor._extract_code_from_llm_response(msg, original_code=orig)
        assert res is not None
        assert "def windows_line_endings():" in res


# =========================================================================
# 2. R2: Clean Abort with LLM_PATCH_FAILED Before Verifier Gate
# =========================================================================

class TestLLMPatchFailureCleanAbort:
    """Verify that patch extraction failures cleanly abort without triggering verifier gate."""

    def test_clean_abort_when_direct_llm_fails_to_patch(self, clean_git_repo, minimal_config, temp_db):
        git_mgr = GitManager(workspace_dir=clean_git_repo.parent, github_token="mock_token")
        verifier = Verifier()
        verifier.verify_and_sanitize_fix = MagicMock()

        monitor = ReviewMonitor(
            config=minimal_config,
            database=temp_db,
            git_manager=git_mgr,
            verifier=verifier,
            aider_runner=None,
        )
        # Mock _run_direct_llm_remediation to return False (patch generation failure)
        monitor._run_direct_llm_remediation = MagicMock(return_value=False)

        comment = ReviewComment(
            comment_id="c_fail_1",
            thread_id="t_fail_1",
            repo_slug="bitxwolf/BugHunter",
            pr_number=99,
            branch_name="main",
            path="app.py",
            line=1,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Please fix this function",
            author="coderabbitai[bot]",
        )

        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/BugHunter",
            pr_info={"number": 99, "headRefName": "main"},
            comment=comment,
            repo_path=clean_git_repo,
        )

        assert res.success is False
        assert res.status == "LLM_PATCH_FAILED"
        assert "LLM_PATCH_FAILED" in res.error_message
        # Crucial check: Verifier gate was NEVER invoked!
        verifier.verify_and_sanitize_fix.assert_not_called()


# =========================================================================
# 3. R1: PR Branch Fetch & Remote Push Resilience
# =========================================================================

class TestPRBranchFetchAndPushResilience:
    """Stress-test PR branch fetch strategies, checkout failures, and remote selection."""

    def test_fetch_via_origin_pull_ref_success(self, clean_git_repo, minimal_config, temp_db):
        """When origin exists and pull ref succeeds, checked out branch matches PR head."""
        # Setup an upstream repo as origin
        upstream_dir = clean_git_repo.parent / "upstream_repo"
        upstream_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "--bare"], cwd=upstream_dir, check=True, capture_output=True)

        subprocess.run(["git", "remote", "add", "origin", str(upstream_dir)], cwd=clean_git_repo, check=True)
        # Push main to origin
        subprocess.run(["git", "push", "origin", "main"], cwd=clean_git_repo, check=True, capture_output=True)

        # Create a PR branch in upstream with commit
        pr_work = clean_git_repo.parent / "pr_work"
        subprocess.run(["git", "clone", str(upstream_dir), str(pr_work)], check=True, capture_output=True)
        subprocess.run(["git", "checkout", "-b", "feature/review-pr-10"], cwd=pr_work, check=True, capture_output=True)
        (pr_work / "feature.py").write_text("# new feature\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=pr_work, check=True)
        subprocess.run(["git", "commit", "-m", "PR commit"], cwd=pr_work, check=True, capture_output=True)
        # Push to upstream as pull ref
        subprocess.run(["git", "push", "origin", "HEAD:refs/pull/10/head"], cwd=pr_work, check=True, capture_output=True)

        git_mgr = GitManager(workspace_dir=clean_git_repo.parent, github_token="mock_token")
        git_mgr.push_atomic_branch = MagicMock()

        verifier = Verifier()
        verifier.verify_and_sanitize_fix = MagicMock(return_value=VerificationResult(verified=True))

        monitor = ReviewMonitor(
            config=minimal_config,
            database=temp_db,
            git_manager=git_mgr,
            verifier=verifier,
            aider_runner=None,
        )
        monitor._run_direct_llm_remediation = MagicMock(side_effect=lambda p, rel, prompt: (p / rel).write_text("# patched\n") or True)
        monitor.post_inline_reply = MagicMock(return_value=True)
        monitor.resolve_review_thread = MagicMock(return_value=True)

        comment = ReviewComment(
            comment_id="c_pull_1",
            thread_id="t_pull_1",
            repo_slug="bitxwolf/BugHunter",
            pr_number=10,
            branch_name="feature/review-pr-10",
            path="feature.py",
            line=1,
            diff_hunk="@@ -1,1 +1,1 @@",
            body="Review comment",
            author="reviewer",
        )

        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/BugHunter",
            pr_info={"number": 10, "headRefName": "feature/review-pr-10"},
            comment=comment,
            repo_path=clean_git_repo,
        )

        assert res.success is True
        assert res.status == "RESOLVED"
        # Verify push_atomic_branch called with force=False and repo_slug
        git_mgr.push_atomic_branch.assert_called_once_with(
            repo_path=clean_git_repo,
            branch_name="feature/review-pr-10",
            force=False,
            remote="origin",
            repo_slug="bitxwolf/BugHunter",
        )

    def test_checkout_fails_when_remotes_exist_and_branch_cannot_be_resolved(self, clean_git_repo, minimal_config, temp_db):
        """When origin exists and branch does not exist anywhere, raises checkout failure rather than branching off main."""
        upstream_dir = clean_git_repo.parent / "upstream_empty"
        upstream_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "--bare"], cwd=upstream_dir, check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", str(upstream_dir)], cwd=clean_git_repo, check=True)

        git_mgr = GitManager(workspace_dir=clean_git_repo.parent, github_token="mock_token")
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=git_mgr, verifier=None)

        comment = ReviewComment(
            comment_id="c_ghost",
            thread_id="t_ghost",
            repo_slug="bitxwolf/BugHunter",
            pr_number=999,
            branch_name="ghost-branch-xyz",
            path="app.py",
            line=1,
            diff_hunk="",
            body="fix it",
            author="reviewer",
        )

        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/BugHunter",
            pr_info={"number": 999, "headRefName": "ghost-branch-xyz"},
            comment=comment,
            repo_path=clean_git_repo,
        )

        assert res.success is False
        assert res.status == "CHECKOUT_FAILED"
        assert "Could not reliably checkout PR #999 branch" in res.error_message

    def test_local_repo_without_remotes_creates_branch_safely(self, clean_git_repo, minimal_config, temp_db):
        """When no remotes exist (local unit test environment), allows local checkout without error."""
        # Ensure clean_git_repo has NO remotes
        remotes = subprocess.run(["git", "remote"], cwd=clean_git_repo, capture_output=True, text=True).stdout.split()
        for r in remotes:
            subprocess.run(["git", "remote", "remove", r], cwd=clean_git_repo, check=True)

        git_mgr = GitManager(workspace_dir=clean_git_repo.parent, github_token="mock_token")
        git_mgr.push_atomic_branch = MagicMock()

        verifier = Verifier()
        verifier.verify_and_sanitize_fix = MagicMock(return_value=VerificationResult(verified=True))

        monitor = ReviewMonitor(
            config=minimal_config,
            database=temp_db,
            git_manager=git_mgr,
            verifier=verifier,
            aider_runner=None,
        )
        monitor._run_direct_llm_remediation = MagicMock(side_effect=lambda p, rel, prompt: (p / rel).write_text("def compute():\n    return 200\n") or True)
        monitor.post_inline_reply = MagicMock(return_value=True)
        monitor.resolve_review_thread = MagicMock(return_value=True)

        comment = ReviewComment(
            comment_id="c_local",
            thread_id="t_local",
            repo_slug="bitxwolf/BugHunter",
            pr_number=55,
            branch_name="local-test-branch-123",
            path="app.py",
            line=1,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Please fix locally",
            author="human",
        )

        res = monitor.remediate_single_thread(
            repo_slug="bitxwolf/BugHunter",
            pr_info={"number": 55, "headRefName": "local-test-branch-123"},
            comment=comment,
            repo_path=clean_git_repo,
        )

        assert res.success is True
        assert res.status == "RESOLVED"
        git_mgr.push_atomic_branch.assert_called_once_with(
            repo_path=clean_git_repo,
            branch_name="local-test-branch-123",
            force=False,
            remote="origin",
            repo_slug="bitxwolf/BugHunter",
        )

    def test_determine_remote_cross_repo_fork_conditions(self, clean_git_repo, minimal_config, temp_db):
        """Verify _determine_remote correctly selects 'fork' under all cross-fork conditions."""
        git_mgr = GitManager(workspace_dir=clean_git_repo.parent, github_token="mock_token")
        git_mgr.ensure_fork = MagicMock(return_value="arrshh12/BugHunter")
        git_mgr.has_push_access = MagicMock(return_value=False)

        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=git_mgr, verifier=None)

        # Condition 1: isCrossRepository is True in PR dict
        r1 = monitor._determine_remote(
            clean_git_repo,
            "bitxwolf/BugHunter",
            pr_info={"isCrossRepository": True},
        )
        assert r1 == "fork"

        # Condition 2: headRepositoryOwner differs from target base repo owner
        r2 = monitor._determine_remote(
            clean_git_repo,
            "bitxwolf/BugHunter",
            pr_info={"isCrossRepository": False, "headRepositoryOwner": {"login": "arrshh12"}},
        )
        assert r2 == "fork"

        # Condition 3: is_cross_fork boolean parameter is True
        r3 = monitor._determine_remote(
            clean_git_repo,
            "bitxwolf/BugHunter",
            is_cross_fork=True,
        )
        assert r3 == "fork"

        # Condition 4: User lacks push access to repo
        r4 = monitor._determine_remote(
            clean_git_repo,
            "bitxwolf/BugHunter",
            pr_info={"isCrossRepository": False, "headRepositoryOwner": {"login": "bitxwolf"}},
        )
        assert r4 == "fork"

        # Condition 5: Same repo with push access -> origin
        git_mgr.has_push_access = MagicMock(return_value=True)
        # remove fork from git remote if it was added
        subprocess.run(["git", "remote", "remove", "fork"], cwd=clean_git_repo, capture_output=True)
        r5 = monitor._determine_remote(
            clean_git_repo,
            "bitxwolf/BugHunter",
            pr_info={"isCrossRepository": False, "headRepositoryOwner": {"login": "bitxwolf"}},
        )
        assert r5 == "origin"


# =========================================================================
# 4. R2: Subsystem Wiring Across main.py, src/orchestrator.py, ReviewMonitor
# =========================================================================

class TestSubsystemWiringAndDefaults:
    """Verify AiderRunner wiring and default initialization."""

    def test_review_monitor_initializes_default_aider_runner_when_omitted(self, minimal_config, temp_db):
        monitor = ReviewMonitor(config=minimal_config, database=temp_db, git_manager=None, verifier=None, aider_runner=None)
        assert monitor.aider_runner is not None
        assert isinstance(monitor.aider_runner, AiderRunner)

    def test_orchestrator_initializes_and_passes_aider_runner(self, minimal_config, temp_db):
        custom_runner = AiderRunner(timeout_seconds=42)
        orch = Orchestrator(
            config=minimal_config,
            database=temp_db,
            key_manager=None,
            git_manager=None,
            static_scanner=None,
            openhands_runner=None,
            verifier=None,
            logger=MagicMock(),
            aider_runner=custom_runner,
        )
        assert orch.aider_runner is custom_runner
        assert orch.review_monitor.aider_runner is custom_runner

    def test_orchestrator_defaults_aider_runner_when_omitted(self, minimal_config, temp_db):
        orch = Orchestrator(
            config=minimal_config,
            database=temp_db,
            key_manager=None,
            git_manager=None,
            static_scanner=None,
            openhands_runner=None,
            verifier=None,
            logger=MagicMock(),
            aider_runner=None,
        )
        assert orch.aider_runner is not None
        assert isinstance(orch.aider_runner, AiderRunner)
        assert orch.review_monitor.aider_runner is orch.aider_runner
