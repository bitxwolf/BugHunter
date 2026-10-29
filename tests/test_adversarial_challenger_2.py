"""
Adversarial Verification Test Suite 2 for AutoBugHunter 24/7 (Challenger 2).
Focuses rigorously on:
1. R3: Actionable Thread Detection & Lifecycle Idempotency
   - Complex thread histories (missing/mixed createdAt, multiple reviewers, bot in middle vs end)
   - Auto-resolution & SQLite persistence when last_bot_idx > last_reviewer_idx
   - Prevention of duplicate remediation commits
   - SHA extraction and fallback behavior
   - Bot identity precedence (git_manager auth user -> config.bot_github_user -> "arrshh12")
   - Handling of malformed comments, None authors, non-dict payloads
2. R4: Non-Breaking Invariants & Safety Rules
   - RULE-GIT-02: Absolute prohibition of git push --force (raises ValueError)
   - RULE-GIT-02: remediate_single_thread passes force=False and explicit repo_slug
   - RULE-NO-AUTOMERGE: ReviewMonitor.merge_pr & GitManager.auto_merge_pr raise PermissionError
   - RULE-NO-AUTOMERGE: Verify zero references to auto-merging across active workflows
"""

import os
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.config import Config, KeyConfig
from src.database import Database
from src.git_manager import GitManager
from src.review_monitor import (
    GRAPHQL_GET_PR_REVIEW_THREADS,
    GRAPHQL_RESOLVE_REVIEW_THREAD,
    ReviewComment,
    ReviewMonitor,
    ReviewRemediationResult,
)
from src.verifier import VerificationResult, Verifier


@pytest.fixture
def temp_db(tmp_path: Path) -> Database:
    """Create a temporary SQLite WAL database."""
    db_file = tmp_path / "test_adversarial_2.sqlite"
    return Database(db_file)


@pytest.fixture
def mock_git_repo(tmp_path: Path) -> Path:
    """Initialize a local test git repository."""
    repo_dir = tmp_path / "test_repo_adv2"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "arrshh12"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "arrshh12@users.noreply.github.com"], cwd=repo_dir, check=True, capture_output=True)

    test_file = repo_dir / "target.py"
    test_file.write_text("def solve():\n    return 100\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)
    return repo_dir


@pytest.fixture
def mock_config(tmp_path: Path) -> Config:
    """Provide a valid Config instance."""
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
        "GITHUB_TOKEN": "test_token_adversarial",
        "LLM_KEYS": [k1],
    })


class TestR3BotThreadIdempotencyAdversarial:
    """Adversarial stress-testing of R3 Actionable Thread Detection & Idempotency."""

    def test_missing_created_at_preserves_chronological_stability(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: comments with missing, None, or empty createdAt strings.
        Reviewer comment (index 0) followed by bot reply (index 1), both with no createdAt.
        Should recognize bot as having the last word, auto-resolve, and not return actionable.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/issue-1",
                        "headRefOid": "1111222233334444555566667777888899990000",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_missing_dates",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 15,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_rev_nodate",
                                                "body": "Needs bounds check",
                                                "createdAt": None,
                                                "author": {"login": "coderabbitai[bot]"},
                                            },
                                            {
                                                "id": "RC_bot_nodate",
                                                "body": "Noted and addressed in commit deadbeef01. Verified and resolved.",
                                                "createdAt": "",
                                                # missing createdAt key or empty
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 42)

            assert len(actionable) == 0, "Thread with bot reply last must NOT be returned as actionable"
            mock_resolve.assert_called_once_with("PRRT_missing_dates")
            assert temp_db.is_thread_remediated("PRRT_missing_dates") is True

            # Verify persisted commit sha extracted from bot reply
            rem_list = temp_db.get_review_remediations()
            assert len(rem_list) == 1
            rem = rem_list[0]
            assert rem["commit_sha"] == "deadbeef01"
            assert rem["status"] == "RESOLVED"

    def test_mixed_created_at_with_valid_and_missing_timestamps(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: comment 1 has ISO date, comment 2 has None, comment 3 has higher ISO date.
        Reviewer (2026-10-25T10:00:00Z) -> Bot (missing date, sorts first) -> Reviewer (2026-10-25T11:00:00Z).
        Reviewer has the last word! Thread MUST be returned as actionable.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/issue-2",
                        "headRefOid": "aaaa1111bbbb2222cccc3333dddd4444eeee5555",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_mixed_dates",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 20,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_1",
                                                "body": "First comment from reviewer",
                                                "createdAt": "2026-10-25T10:00:00Z",
                                                "author": {"login": "human-reviewer"},
                                            },
                                            {
                                                "id": "RC_2",
                                                "body": "Noted and addressed in commit feedbeef. Verified.",
                                                "createdAt": None,
                                                "author": {"login": "arrshh12"},
                                            },
                                            {
                                                "id": "RC_3",
                                                "body": "Follow-up: still failing edge case with zero length",
                                                "createdAt": "2026-10-25T11:00:00Z",
                                                "author": {"login": "human-reviewer"},
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 43)

            assert len(actionable) == 1, "Thread with newer reviewer comment MUST be actionable"
            mock_resolve.assert_not_called()
            assert actionable[0].comment_id == "RC_3"
            assert "zero length" in actionable[0].body

    def test_multiple_reviewers_interleaved_with_bot_reply(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: Reviewer A -> Reviewer B -> Bot Reply.
        Both reviewers gave feedback, then bot addressed it.
        Should auto-resolve and persist to SQLite without returning actionable.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/multi-reviewer",
                        "headRefOid": "headsha1234567890",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_multi_rev",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 40,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_rev1",
                                                "body": "Check null pointer here",
                                                "createdAt": "2026-10-25T12:00:00Z",
                                                "author": {"login": "reviewer1"},
                                            },
                                            {
                                                "id": "RC_rev2",
                                                "body": "Also format with black",
                                                "createdAt": "2026-10-25T12:05:00Z",
                                                "author": {"login": "reviewer2"},
                                            },
                                            {
                                                "id": "RC_bot",
                                                "body": "Noted and addressed in commit c0ffee1234. Verified and resolved.",
                                                "createdAt": "2026-10-25T12:10:00Z",
                                                "author": {"login": "Arrshh12"},  # mixed case bot login
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 44)

            assert len(actionable) == 0
            mock_resolve.assert_called_once_with("PRRT_multi_rev")
            assert temp_db.is_thread_remediated("PRRT_multi_rev") is True
            rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == "PRRT_multi_rev"]
            assert len(rem_list) == 1
            rem = rem_list[0]
            assert rem["commit_sha"] == "c0ffee1234"
            assert rem["reviewer"] == "reviewer2"  # Last reviewer before bot

    def test_bot_reply_in_middle_followed_by_human_reopening(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: Reviewer A -> Bot Reply -> Reviewer B rejects fix.
        last_reviewer_idx > last_bot_idx.
        Must NOT auto-resolve; must return actionable comment for Reviewer B.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/reopened",
                        "headRefOid": "headsha111",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_reopened",
                                    "isResolved": False,
                                    "path": "src/module.py",
                                    "line": 55,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_initial",
                                                "body": "Initial bug",
                                                "createdAt": "2026-10-25T13:00:00Z",
                                                "author": {"login": "bitxwolf"},
                                            },
                                            {
                                                "id": "RC_bot_reply",
                                                "body": "Noted and addressed in commit aabbccddeeff.",
                                                "createdAt": "2026-10-25T13:05:00Z",
                                                "author": {"login": "arrshh12"},
                                            },
                                            {
                                                "id": "RC_rejection",
                                                "body": "This commit introduced a syntax error on line 58.",
                                                "createdAt": "2026-10-25T13:10:00Z",
                                                "author": {"login": "bitxwolf"},
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 45)

            assert len(actionable) == 1
            mock_resolve.assert_not_called()
            assert actionable[0].comment_id == "RC_rejection"
            assert actionable[0].author == "bitxwolf"
            assert "syntax error" in actionable[0].body

    def test_bot_reply_without_sha_falls_back_to_head_ref_oid(self, temp_db: Database, mock_config: Config):
        """
        Verify that when a bot reply lacks an explicit commit hash, commit_sha falls back to headRefOid.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/no-sha",
                        "headRefOid": "fallbacksheadsha999",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_no_sha",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 10,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_rev",
                                                "body": "Feedback without commit mention",
                                                "createdAt": "2026-10-25T14:00:00Z",
                                                "author": {"login": "coderabbitai[bot]"},
                                            },
                                            {
                                                "id": "RC_bot_nosha",
                                                "body": "Acknowledged and resolved manually in workspace.",
                                                "createdAt": "2026-10-25T14:05:00Z",
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread", return_value=True):
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 46)

            assert len(actionable) == 0
            rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == "PRRT_no_sha"]
            assert len(rem_list) == 1
            rem = rem_list[0]
            assert rem["commit_sha"] == "fallbacksheadsha999"

    def test_graphql_resolve_failure_persists_resolution_failed_without_remediation_loop(self, temp_db: Database, mock_config: Config):
        """
        When resolve_review_thread returns False (e.g., token lacks thread-resolve permission),
        it should persist status='RESOLUTION_FAILED' to SQLite, but still NOT return actionable
        to avoid an infinite duplicate-commit loop.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/failed-resolve",
                        "headRefOid": "headoid123",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_failed_resolve",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 12,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_rev",
                                                "body": "Fix this",
                                                "createdAt": "2026-10-25T15:00:00Z",
                                                "author": {"login": "coderabbitai[bot]"},
                                            },
                                            {
                                                "id": "RC_bot",
                                                "body": "Noted in commit 1234567. Verified.",
                                                "createdAt": "2026-10-25T15:02:00Z",
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread", return_value=False):
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 47)

            assert len(actionable) == 0, "Failed resolution must still skip actionable to prevent duplicate loop"
            rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == "PRRT_failed_resolve"]
            assert len(rem_list) == 1
            rem = rem_list[0]
            assert rem["status"] == "RESOLUTION_FAILED"
            assert temp_db.is_thread_remediated("PRRT_failed_resolve") is True

    def test_malformed_and_edge_case_comment_nodes(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: corrupted comment nodes:
        - None in comment nodes
        - Missing author object
        - Missing author login
        - Thread with only bot comments (no reviewer comments)
        - Thread already resolved (isResolved: True)
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/malformed",
                        "headRefOid": "headoid999",
                        "reviewThreads": {
                            "nodes": [
                                None,  # corrupted thread node
                                {
                                    "id": "PRRT_already_resolved",
                                    "isResolved": True,
                                    "comments": {"nodes": [{"author": {"login": "reviewer"}, "body": "done"}]},
                                },
                                {
                                    "id": "PRRT_bot_only",
                                    "isResolved": False,
                                    "comments": {
                                        "nodes": [
                                            {"author": {"login": "arrshh12"}, "body": "Self comment by bot"}
                                        ]
                                    },
                                },
                                {
                                    "id": "PRRT_none_author",
                                    "isResolved": False,
                                    "comments": {
                                        "nodes": [
                                            None,
                                            {"author": None, "body": "Ghost comment"},
                                            {"author": {}, "body": "Empty login"},
                                            {"author": {"login": ""}, "body": "Blank login"},
                                        ]
                                    },
                                },
                            ]
                        },
                    }
                }
            }
        }

        with patch.object(monitor, "execute_graphql", return_value=graphql_response):
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 48)
            assert len(actionable) == 0, "Malformed nodes and bot-only threads must yield zero actionable comments"

    def test_get_bot_identity_precedence_exhaustive(self, temp_db: Database, mock_config: Config):
        """
        Verify exact order of precedence for get_bot_identity():
        1. git_manager.get_authenticated_user() (if non-empty)
        2. config.bot_github_user (if non-empty)
        3. Default fallback "arrshh12"
        """
        # Case 1: git_manager returns authenticated user
        git_m1 = MagicMock()
        git_m1.get_authenticated_user.return_value = "custom_git_bot"
        cfg1 = MagicMock()
        cfg1.bot_github_user = "config_bot"
        mon1 = ReviewMonitor(config=cfg1, database=temp_db, git_manager=git_m1, verifier=MagicMock())
        assert mon1.get_bot_identity() == "custom_git_bot"

        # Case 2: git_manager returns None -> falls back to config.bot_github_user
        git_m2 = MagicMock()
        git_m2.get_authenticated_user.return_value = None
        mon2 = ReviewMonitor(config=cfg1, database=temp_db, git_manager=git_m2, verifier=MagicMock())
        assert mon2.get_bot_identity() == "config_bot"

        # Case 3: git_manager raises exception -> falls back to config.bot_github_user
        git_m3 = MagicMock()
        git_m3.get_authenticated_user.side_effect = RuntimeError("gh auth unavailable")
        mon3 = ReviewMonitor(config=cfg1, database=temp_db, git_manager=git_m3, verifier=MagicMock())
        assert mon3.get_bot_identity() == "config_bot"

        # Case 4: git_manager is None, config has bot_github_user
        mon4 = ReviewMonitor(config=cfg1, database=temp_db, git_manager=None, verifier=MagicMock())
        assert mon4.get_bot_identity() == "config_bot"

        # Case 5: git_manager returns whitespace, config is empty/None -> defaults to "arrshh12"
        git_m5 = MagicMock()
        git_m5.get_authenticated_user.return_value = "   "
        cfg5 = MagicMock()
        cfg5.bot_github_user = None
        mon5 = ReviewMonitor(config=cfg5, database=temp_db, git_manager=git_m5, verifier=MagicMock())
        assert mon5.get_bot_identity() == "arrshh12"

        # Case 6: git_manager is None, config is None -> defaults to "arrshh12"
        mon6 = ReviewMonitor(config=None, database=temp_db, git_manager=None, verifier=MagicMock())
        assert mon6.get_bot_identity() == "arrshh12"


class TestR4NonBreakingInvariantsAdversarial:
    """Adversarial stress-testing of R4 Non-Breaking Invariants & Safety Rules."""

    def test_rule_git_02_absolute_force_push_prohibition(self, mock_git_repo: Path, mock_config: Config):
        """
        Verify that GitManager.push_atomic_branch strictly forbids force=True.
        Must raise ValueError with 'RULE-GIT-02 Violation: Force pushing is strictly prohibited'.
        """
        git_mgr = GitManager(workspace_dir=mock_git_repo.parent, github_token="test_token")

        with pytest.raises(ValueError) as excinfo:
            git_mgr.push_atomic_branch(
                repo_path=mock_git_repo,
                branch_name="main",
                force=True,
                remote="origin",
                repo_slug="bitxwolf/other-repo",
            )
        assert "RULE-GIT-02 Violation" in str(excinfo.value)
        assert "Force pushing is strictly prohibited" in str(excinfo.value)

    def test_rule_git_02_remediate_single_thread_always_enforces_force_false(
        self, temp_db: Database, mock_config: Config, mock_git_repo: Path
    ):
        """
        Verify that ReviewMonitor.remediate_single_thread explicitly passes force=False
        and passes the exact repo_slug to GitManager.push_atomic_branch.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        git_mock.push_atomic_branch.return_value = "origin"

        ver_mock = MagicMock()
        ver_mock.verify_and_sanitize_fix.return_value = VerificationResult(
            verified=True,
            diff_lines=5,
            modified_files=["target.py"],
        )

        monitor = ReviewMonitor(
            config=mock_config,
            database=temp_db,
            git_manager=git_mock,
            verifier=ver_mock,
        )

        comment = ReviewComment(
            comment_id="RC_force_test",
            thread_id="PRRT_force_test",
            repo_slug="bitxwolf/BugHunter",
            pr_number=99,
            branch_name="main",
            path="target.py",
            line=2,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Please update return value to 200",
            author="reviewer",
        )

        pr_info = {
            "number": 99,
            "headRefName": "main",
            "headRefOid": "abcd1234abcd1234",
            "isCrossRepository": False,
        }

        # Mock direct LLM patching to modify the file
        def fake_llm(repo_path, rel_path, prompt):
            (repo_path / rel_path).write_text("def solve():\n    return 200\n", encoding="utf-8")
            return True

        with patch.object(monitor, "_run_direct_llm_remediation", side_effect=fake_llm), \
             patch.object(monitor, "post_inline_reply", return_value=True), \
             patch.object(monitor, "resolve_review_thread", return_value=True):

            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info=pr_info,
                comment=comment,
                repo_path=mock_git_repo,
            )

            assert res.success is True
            # Verify push_atomic_branch was called with force=False and repo_slug
            git_mock.push_atomic_branch.assert_called_once()
            _, kwargs = git_mock.push_atomic_branch.call_args
            assert kwargs.get("force") is False
            assert kwargs.get("repo_slug") == "bitxwolf/BugHunter"
            assert kwargs.get("branch_name") == "main"

    def test_rule_no_automerge_strictly_enforced(self, temp_db: Database, mock_config: Config, mock_git_repo: Path):
        """
        Verify that ReviewMonitor.merge_pr and GitManager.auto_merge_pr raise PermissionError
        with 'RULE-NO-AUTOMERGE Violation'.
        """
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=MagicMock(), verifier=MagicMock())

        with pytest.raises(PermissionError) as exc_mon:
            monitor.merge_pr(repo_slug="bitxwolf/BugHunter", pr_number=10)
        assert "RULE-NO-AUTOMERGE Violation" in str(exc_mon.value)
        assert "strictly forbidden from auto-merging" in str(exc_mon.value)

        git_mgr = GitManager(workspace_dir=mock_git_repo.parent, github_token="test_token")
        with pytest.raises(PermissionError) as exc_git:
            git_mgr.auto_merge_pr(repo_slug="bitxwolf/BugHunter", pr_number=10)
        assert "RULE-NO-AUTOMERGE Violation" in str(exc_git.value)
        assert "strictly forbidden from auto-merging" in str(exc_git.value)

    def test_zero_references_to_auto_merge_in_active_pipelines(self):
        """
        Adversarially scan src/ for any unauthorized calls to gh pr merge or merge APIs.
        """
        src_dir = Path("src")
        prohibited_patterns = [
            re.compile(r"\bgh\s+pr\s+merge\b", re.IGNORECASE),
            re.compile(r"\.merge_pr\(", re.IGNORECASE),
            re.compile(r"\.auto_merge_pr\(", re.IGNORECASE),
        ]

        violations = []
        for py_file in src_dir.rglob("*.py"):
            text = py_file.read_text(encoding="utf-8", errors="replace")
            for line_no, line in enumerate(text.splitlines(), start=1):
                # Ignore method definitions and docstrings in review_monitor.py & git_manager.py
                if "def merge_pr(" in line or "def auto_merge_pr(" in line:
                    continue
                if "RULE-NO-AUTOMERGE" in line:
                    continue
                for pat in prohibited_patterns:
                    if pat.search(line):
                        violations.append(f"{py_file}:{line_no}: {line.strip()}")

        assert not violations, f"Detected prohibited auto-merge invocations: {violations}"

    def test_raw_comments_out_of_order_sorted_chronologically(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: raw_comments list is deliberately out of order.
        Comment 1 in list: Bot reply with timestamp 2026-10-25T14:00:00Z.
        Comment 2 in list: Reviewer feedback with timestamp 2026-10-25T12:00:00Z.
        Sorting MUST place reviewer first (12:00) and bot second (14:00).
        Since bot is latest, it must auto-resolve and persist.
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        graphql_response = {
            "data": {
                "repository": {
                    "pullRequest": {
                        "headRefName": "fix/out-of-order",
                        "headRefOid": "headsha999",
                        "reviewThreads": {
                            "nodes": [
                                {
                                    "id": "PRRT_out_of_order",
                                    "isResolved": False,
                                    "path": "target.py",
                                    "line": 33,
                                    "comments": {
                                        "nodes": [
                                            {
                                                "id": "RC_bot_later",
                                                "body": "Noted and addressed in commit bbbb123456. Verified and resolved.",
                                                "createdAt": "2026-10-25T14:00:00Z",
                                                "author": {"login": "arrshh12"},
                                            },
                                            {
                                                "id": "RC_rev_earlier",
                                                "body": "Earlier reviewer feedback",
                                                "createdAt": "2026-10-25T12:00:00Z",
                                                "author": {"login": "human-reviewer"},
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

        with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
             patch.object(monitor, "resolve_review_thread", return_value=True) as mock_resolve:
            actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 49)

            assert len(actionable) == 0
            mock_resolve.assert_called_once_with("PRRT_out_of_order")
            assert temp_db.is_thread_remediated("PRRT_out_of_order") is True
            rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == "PRRT_out_of_order"]
            assert len(rem_list) == 1
            assert rem_list[0]["commit_sha"] == "bbbb123456"

    def test_bot_reply_commit_sha_punctuation_and_length_variants(self, temp_db: Database, mock_config: Config):
        """
        Stress-test: regex extraction of commit SHA in bot comments with varying punctuation:
        - Parenthesized: "addressed in commit (4b825dc642cb6eb9a060e54bf8d69288fbee4904)."
        - Bracketed: "addressed in commit [7a8b9c0]!"
        - Markdown backticks: "addressed in commit `deadbeef`."
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        monitor = ReviewMonitor(config=mock_config, database=temp_db, git_manager=git_mock, verifier=MagicMock())

        test_cases = [
            ("commit (4b825dc642cb6eb9a060e54bf8d69288fbee4904).", "4b825dc642cb6eb9a060e54bf8d69288fbee4904", "PRRT_sha_1"),
            ("commit [7a8b9c0]!", "7a8b9c0", "PRRT_sha_2"),
            ("commit `deadbeef`.", "deadbeef", "PRRT_sha_3"),
        ]

        for body_text, expected_sha, thread_id in test_cases:
            graphql_response = {
                "data": {
                    "repository": {
                        "pullRequest": {
                            "headRefName": "fix/sha-test",
                            "headRefOid": "defaultheadoid",
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "id": thread_id,
                                        "isResolved": False,
                                        "path": "target.py",
                                        "line": 10,
                                        "comments": {
                                            "nodes": [
                                                {"id": f"RC_rev_{thread_id}", "body": "Change this", "author": {"login": "rev"}, "createdAt": "2026-10-25T10:00:00Z"},
                                                {"id": f"RC_bot_{thread_id}", "body": body_text, "author": {"login": "arrshh12"}, "createdAt": "2026-10-25T10:05:00Z"},
                                            ]
                                        },
                                    }
                                ]
                            },
                        }
                    }
                }
            }

            with patch.object(monitor, "execute_graphql", return_value=graphql_response), \
                 patch.object(monitor, "resolve_review_thread", return_value=True):
                actionable = monitor.fetch_unresolved_review_threads("bitxwolf/BugHunter", 50)
                assert len(actionable) == 0
                rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == thread_id]
                assert len(rem_list) == 1
                assert rem_list[0]["commit_sha"] == expected_sha

    def test_remediate_single_thread_push_failure_cleans_up_and_does_not_resolve(
        self, temp_db: Database, mock_config: Config, mock_git_repo: Path
    ):
        """
        Verify that if push_atomic_branch fails in remediate_single_thread:
        - git rollback_working_tree is invoked
        - post_inline_reply is NOT called
        - resolve_review_thread is NOT called
        - DB is NOT updated with resolution
        - Returns success=False, status='PUSH_FAILED'
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        git_mock.push_atomic_branch.side_effect = RuntimeError("Network error connecting to remote")

        ver_mock = MagicMock()
        ver_mock.verify_and_sanitize_fix.return_value = VerificationResult(
            verified=True,
            diff_lines=5,
            modified_files=["target.py"],
        )

        monitor = ReviewMonitor(
            config=mock_config,
            database=temp_db,
            git_manager=git_mock,
            verifier=ver_mock,
        )

        comment = ReviewComment(
            comment_id="RC_push_fail",
            thread_id="PRRT_push_fail",
            repo_slug="bitxwolf/BugHunter",
            pr_number=101,
            branch_name="main",
            path="target.py",
            line=2,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Change line 2",
            author="reviewer",
        )

        pr_info = {
            "number": 101,
            "headRefName": "main",
            "headRefOid": "headoid101",
            "isCrossRepository": False,
        }

        def fake_llm(repo_path, rel_path, prompt):
            (repo_path / rel_path).write_text("def solve():\n    return 300\n", encoding="utf-8")
            return True

        with patch.object(monitor, "_run_direct_llm_remediation", side_effect=fake_llm), \
             patch.object(monitor, "post_inline_reply") as mock_reply, \
             patch.object(monitor, "resolve_review_thread") as mock_resolve:

            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info=pr_info,
                comment=comment,
                repo_path=mock_git_repo,
            )

            assert res.success is False
            assert res.status == "PUSH_FAILED"
            assert "Network error" in (res.error_message or "")
            git_mock.rollback_working_tree.assert_called_once()
            mock_reply.assert_not_called()
            mock_resolve.assert_not_called()
            assert temp_db.is_thread_remediated("PRRT_push_fail") is False

    def test_remediate_single_thread_post_push_resolve_failure_records_resolution_failed(
        self, temp_db: Database, mock_config: Config, mock_git_repo: Path
    ):
        """
        Verify that if push and reply succeed but GraphQL thread resolution fails:
        - Returns success=True with status='RESOLUTION_FAILED'
        - Persists to DB with status='RESOLUTION_FAILED' to avoid duplicate pushes
        """
        git_mock = MagicMock()
        git_mock.get_authenticated_user.return_value = "arrshh12"
        git_mock.push_atomic_branch.return_value = "origin"

        ver_mock = MagicMock()
        ver_mock.verify_and_sanitize_fix.return_value = VerificationResult(
            verified=True,
            diff_lines=5,
            modified_files=["target.py"],
        )

        monitor = ReviewMonitor(
            config=mock_config,
            database=temp_db,
            git_manager=git_mock,
            verifier=ver_mock,
        )

        comment = ReviewComment(
            comment_id="RC_res_fail",
            thread_id="PRRT_res_fail",
            repo_slug="bitxwolf/BugHunter",
            pr_number=102,
            branch_name="main",
            path="target.py",
            line=2,
            diff_hunk="@@ -1,2 +1,2 @@",
            body="Change line 2 again",
            author="reviewer",
        )

        pr_info = {
            "number": 102,
            "headRefName": "main",
            "headRefOid": "headoid102",
            "isCrossRepository": False,
        }

        def fake_llm(repo_path, rel_path, prompt):
            (repo_path / rel_path).write_text("def solve():\n    return 400\n", encoding="utf-8")
            return True

        with patch.object(monitor, "_run_direct_llm_remediation", side_effect=fake_llm), \
             patch.object(monitor, "post_inline_reply", return_value=True) as mock_reply, \
             patch.object(monitor, "resolve_review_thread", return_value=False) as mock_resolve:

            res = monitor.remediate_single_thread(
                repo_slug="bitxwolf/BugHunter",
                pr_info=pr_info,
                comment=comment,
                repo_path=mock_git_repo,
            )

            assert res.success is True
            assert res.status == "RESOLVED"
            mock_reply.assert_called_once()
            mock_resolve.assert_called_once_with("PRRT_res_fail")
            assert temp_db.is_thread_remediated("PRRT_res_fail") is True
            rem_list = [r for r in temp_db.get_review_remediations() if r["thread_id"] == "PRRT_res_fail"]
            assert len(rem_list) == 1
            assert rem_list[0]["status"] == "RESOLUTION_FAILED"

    def test_static_ast_verification_push_atomic_branch_callers_never_force(self):
        """
        Adversarially parse all Python ASTs in src/ to guarantee that NO call
        to push_atomic_branch passes force=True, and ReviewMonitor explicitly passes force=False.
        """
        import ast

        src_dir = Path("src")
        push_atomic_calls = 0

        for py_path in src_dir.rglob("*.py"):
            tree = ast.parse(py_path.read_text(encoding="utf-8", errors="replace"), filename=str(py_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if func_name == "push_atomic_branch":
                        push_atomic_calls += 1
                        # Check keyword arguments: force must never be True
                        force_kw = [kw for kw in node.keywords if kw.arg == "force"]
                        if force_kw:
                            val_node = force_kw[0].value
                            assert isinstance(val_node, ast.Constant), (
                                f"{py_path}:{node.lineno}: force parameter must be a constant boolean"
                            )
                            assert val_node.value is False, (
                                f"{py_path}:{node.lineno}: RULE-GIT-02 Violation! push_atomic_branch passed force={val_node.value}"
                            )
                        # Check positional arguments: arg index 2 is force (repo_path, branch_name, force)
                        if len(node.args) >= 3:
                            arg2 = node.args[2]
                            if isinstance(arg2, ast.Constant):
                                assert arg2.value is False, (
                                    f"{py_path}:{node.lineno}: RULE-GIT-02 Violation! 3rd positional argument force={arg2.value}"
                                )

                        # ReviewMonitor must explicitly pass force=False
                        if "review_monitor.py" in str(py_path):
                            assert len(force_kw) == 1 and force_kw[0].value.value is False, (
                                f"{py_path}:{node.lineno}: ReviewMonitor must explicitly pass force=False"
                            )

        assert push_atomic_calls >= 3, f"Expected at least 3 push_atomic_branch calls in codebase, found {push_atomic_calls}"

