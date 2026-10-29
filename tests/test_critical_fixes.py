"""
Unit and boundary tests for Critical Bug Fixes:
1. Google AIza API Key Redaction Regex in src/logger.py and src/verifier.py
2. Credential scrubbing in FixResult.error_message and ReviewRemediationResult.error_message
3. RingBufferLogger.get_recent() alias contract and boundaries
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.aider_runner import AiderResult
from src.fixer_agent import FixResult, MainFixerAgent
from src.git_manager import GitManager
from src.logger import RingBufferLogger, redact_secrets
from src.review_monitor import ReviewComment, ReviewMonitor, ReviewRemediationResult
from src.verifier import VerificationResult, Verifier

# ==============================================================================
# Critical Issue 1: Google AIza API Key Redaction Regex
# ==============================================================================

def _make_dummy_token(*parts: str) -> str:
    return "".join(parts)


def test_aiza_regex_variable_lengths_in_logger():
    """Verify redact_secrets redacts AIza keys of variable lengths (30 to 45 chars) with hyphens and underscores."""
    test_keys = [
        _make_dummy_token("AI", "za", "a" * 30),                              # 30 chars
        _make_dummy_token("AI", "za", "a" * 34),                              # 34 chars (reported issue)
        _make_dummy_token("AI", "za", "B" * 35),                              # 35 chars (standard)
        _make_dummy_token("AI", "zaSy", "A" * 33),                            # 39 chars (Google standard format)
        _make_dummy_token("AI", "za", "x-y_z" * 8),                           # 40 chars with - and _
        _make_dummy_token("AI", "za", "Z" * 45),                              # 45 chars max bound
    ]

    for key in test_keys:
        text = f"Error: Request failed with key {key} in authorization."
        redacted = redact_secrets(text)
        assert key not in redacted, f"Failed to redact key: {key}"
        assert "[REDACTED]" in redacted

    # Sub-boundary check: keys shorter than 30 chars after AIza should NOT match the AIza regex
    short_text = _make_dummy_token("AI", "za", "ShortKey123")
    assert redact_secrets(short_text) == short_text


def test_aiza_regex_variable_lengths_in_verifier():
    """Verify verifier scans and catches variable length AIza keys in diffs."""
    verifier = Verifier()

    for length in (30, 34, 35, 39, 45):
        key = _make_dummy_token("AI", "za", "k" * length)
        diff = f"""--- a/config.py
+++ b/config.py
@@ -1,1 +1,2 @@
+GOOGLE_API_KEY = "{key}"
"""
        findings = verifier.scan_for_secrets(diff)
        assert len(findings) >= 1, f"Verifier missed AIza key of length {length}"
        assert any(key in f for f in findings)


# ==============================================================================
# Critical Issue 2: Credential Scrubbing in FixResult and ReviewRemediationResult
# ==============================================================================

def test_fixer_agent_scrubs_credentials_in_push_failed(tmp_path: Path):
    """Verify MainFixerAgent scrubs sensitive tokens and URLs from push failure error_message."""
    git_manager = MagicMock(spec=GitManager)
    secret_tok = _make_dummy_token("gh", "p_", "secretToken", "1" * 20)
    git_manager.github_token = secret_tok
    git_manager._scrub_credentials = GitManager._scrub_credentials.__get__(git_manager, GitManager)
    raw_err = f"fatal: Authentication failed for 'https://x-access-token:{secret_tok}@github.com/org/repo.git'"
    git_manager.push_atomic_branch.side_effect = RuntimeError(raw_err)

    agent = MainFixerAgent(git_manager=git_manager)

    # Directly verify _scrub method
    scrubbed = agent._scrub(raw_err)
    assert secret_tok not in scrubbed
    assert "[REDACTED]" in scrubbed

    # Verify FixResult construction with scrubbed error_message
    res = FixResult(
        success=False,
        repo_slug="org/repo",
        bug_id="BUG-101",
        target_file="src/code.py",
        status="PUSH_FAILED",
        error_message=agent._scrub(f"Git push failed: {raw_err}"),
    )
    assert secret_tok not in res.error_message
    assert "[REDACTED]" in res.error_message


def test_fixer_agent_scrubs_credentials_in_pr_creation_failure():
    """Verify MainFixerAgent scrubs tokens in gh pr create error messages."""
    token = _make_dummy_token("github_", "pat_", "A" * 82)
    agent = MainFixerAgent()

    raw_err = f"GraphQL: Bad credentials ({token})"
    scrubbed = agent._scrub(f"PR creation failed on GitHub: {raw_err}")
    assert token not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_review_monitor_scrubs_credentials_in_remediation_results():
    """Verify ReviewMonitor scrubs sensitive credentials from ReviewRemediationResult.error_message."""
    git_manager = MagicMock(spec=GitManager)
    review_tok = _make_dummy_token("gh", "p_", "secretReviewToken", "1" * 15)
    git_manager.github_token = review_tok
    git_manager._scrub_credentials = GitManager._scrub_credentials.__get__(git_manager, GitManager)

    monitor = ReviewMonitor(
        config=None,
        database=None,
        git_manager=git_manager,
        verifier=Verifier(),
        aider_runner=None,
    )

    # 1. Test _scrub method
    raw_error = f"Failed to push to https://{review_tok}@github.com/org/repo.git"
    scrubbed = monitor._scrub(raw_error)
    assert review_tok not in scrubbed
    assert "[REDACTED]" in scrubbed

    # 2. Test ReviewRemediationResult with exception
    res = ReviewRemediationResult(
        success=False,
        repo_slug="org/repo",
        pr_number=12,
        thread_id="thread_1",
        comment_id="comment_1",
        status="PUSH_FAILED",
        error_message=monitor._scrub(raw_error),
    )
    assert review_tok not in res.error_message
    assert "[REDACTED]" in res.error_message


def test_review_monitor_execute_graphql_scrubs_errors():
    """Verify execute_graphql scrubs credentials from stderr and exceptions."""
    monitor = ReviewMonitor(
        config=None,
        database=None,
        git_manager=None,
        verifier=Verifier(),
        aider_runner=None,
    )

    leaked_tok = _make_dummy_token("gh", "p_", "leakedSecretToken", "1" * 22)
    with patch("shutil.which", return_value="/usr/bin/gh"), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1,
            stderr=f"Failed request with token {leaked_tok}",
            stdout="",
        )
        resp = monitor.execute_graphql("query { viewer { login } }")
        assert "errors" in resp
        err_msg = resp["errors"][0]["message"]
        assert leaked_tok not in err_msg
        assert "[REDACTED]" in err_msg


def test_authenticated_url_scrubbing_across_agents():
    """Verify _scrub and redact_secrets thoroughly redact URLs with user:password, x-access-token, and tokens."""
    agent = MainFixerAgent()
    monitor = ReviewMonitor(config=None, database=None, git_manager=None, verifier=Verifier())

    sensitive_urls = [
        ("fatal: https://x-access-token:customSecretToken12345@github.com/org/repo.git",
         "https://x-access-token:[REDACTED]@github.com/org/repo.git"),
        ("error: https://bitxwolf:superSecretPassword987@github.com/org/repo.git",
         "https://bitxwolf:[REDACTED]@github.com/org/repo.git"),
        ("push failed: https://myTokenAlphaNumeric12345@github.com/org/repo.git",
         "https://[REDACTED]@github.com/org/repo.git"),
    ]

    for raw, expected in sensitive_urls:
        agent_scrubbed = agent._scrub(raw)
        monitor_scrubbed = monitor._scrub(raw)
        redact_direct = redact_secrets(raw)

        assert expected in agent_scrubbed, f"Agent failed on {raw}: got {agent_scrubbed}"
        assert expected in monitor_scrubbed, f"Monitor failed on {raw}: got {monitor_scrubbed}"
        assert expected in redact_direct, f"Direct redact failed on {raw}: got {redact_direct}"
        assert "customSecretToken12345" not in agent_scrubbed
        assert "superSecretPassword987" not in agent_scrubbed
        assert "myTokenAlphaNumeric12345" not in agent_scrubbed


def test_post_init_defence_in_depth_scrubbing():
    """Verify FixResult and ReviewRemediationResult __post_init__ redacts secrets even when unscrubbed string is passed."""
    secret_pass = "topSecretPass123456"
    raw_msg = f"fatal: Authentication failed for 'https://bot:{secret_pass}@github.com/org/repo.git'"

    fix_res = FixResult(
        success=False,
        repo_slug="org/repo",
        bug_id="BUG-001",
        target_file="src/code.py",
        error_message=raw_msg,
    )
    assert secret_pass not in (fix_res.error_message or "")
    assert "[REDACTED]" in (fix_res.error_message or "")

    review_res = ReviewRemediationResult(
        success=False,
        repo_slug="org/repo",
        pr_number=5,
        thread_id="T1",
        comment_id="C1",
        error_message=raw_msg,
    )
    assert secret_pass not in (review_res.error_message or "")
    assert "[REDACTED]" in (review_res.error_message or "")


def test_fixer_agent_fix_next_bug_end_to_end_push_failure_scrubs_credentials(tmp_path: Path):
    """Verify that calling agent.fix_next_bug() scrubs credentials in FixResult on git push exception."""
    # Set up simulated repo
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True)
    test_file = tmp_path / "main.py"
    test_file.write_text("def run():\n    return 0\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=tmp_path, check=True)

    bug_log = tmp_path / "Bug-log.md"
    bug_log.write_text("- [ ] **BUG-999**: main.py:1 - [ruff:E999] return 42 instead of 0\n", encoding="utf-8")

    git_manager = MagicMock(spec=GitManager)
    secret_url = "https://x-access-token:verySecretPushToken456@github.com/org/repo.git"
    git_manager.push_atomic_branch.side_effect = RuntimeError(f"fatal: Authentication failed for '{secret_url}'")
    git_manager._scrub_credentials = GitManager._scrub_credentials.__get__(git_manager, GitManager)

    mock_aider = MagicMock()
    def mock_run_aider(repo_path, target_file, patch_instruction, key_entry=None, log_callback=None):
        (repo_path / target_file).write_text("def run():\n    return 42\n", encoding="utf-8")
        return AiderResult(exit_code=0, diff_output="--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,2 @@\n- return 0\n+ return 42\n", status="SUCCESS", target_file="main.py")
    mock_aider.run_aider.side_effect = mock_run_aider

    mock_verifier = MagicMock()
    mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(verified=True, diff_lines=2)

    agent = MainFixerAgent(git_manager=git_manager, verifier=mock_verifier, aider_runner=mock_aider)
    res = agent.fix_next_bug("org/repo", tmp_path, bug_log_path=bug_log)

    assert res.success is False
    assert res.status == "PUSH_FAILED"
    assert "verySecretPushToken456" not in (res.error_message or "")
    assert "[REDACTED]" in (res.error_message or "")


def test_review_monitor_remediate_single_thread_end_to_end_push_failure_scrubs_credentials(tmp_path: Path):
    """Verify that calling monitor.remediate_single_thread() scrubs credentials in ReviewRemediationResult on git push exception."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, check=True)
    test_file = tmp_path / "foo.py"
    test_file.write_text("def val():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True)
    subprocess.run(["git", "checkout", "-b", "fix/test-branch"], cwd=tmp_path, check=True)

    git_manager = MagicMock(spec=GitManager)
    secret_url = "https://botUser:botSecretPassword789@github.com/org/repo.git"
    git_manager.push_atomic_branch.side_effect = RuntimeError(f"fatal: push error to '{secret_url}'")
    git_manager._scrub_credentials = GitManager._scrub_credentials.__get__(git_manager, GitManager)

    mock_aider = MagicMock()
    def mock_run_aider_rm(repo_path, target_file, patch_instruction, key_entry=None, log_callback=None):
        (repo_path / target_file).write_text("def val():\n    return 42\n", encoding="utf-8")
        return AiderResult(exit_code=0, diff_output="--- a/foo.py\n+++ b/foo.py\n@@ -1,2 +1,2 @@\n- return 1\n+ return 42\n", status="SUCCESS", target_file="foo.py")
    mock_aider.run_aider.side_effect = mock_run_aider_rm

    mock_verifier = MagicMock()
    mock_verifier.verify_and_sanitize_fix.return_value = VerificationResult(verified=True, diff_lines=1)

    monitor = ReviewMonitor(
        config=None,
        database=None,
        git_manager=git_manager,
        verifier=mock_verifier,
        aider_runner=mock_aider,
    )

    comment = ReviewComment(
        comment_id="C_123",
        thread_id="T_123",
        repo_slug="org/repo",
        pr_number=10,
        branch_name="fix/test-branch",
        path="foo.py",
        line=1,
        diff_hunk="",
        body="Improve val",
        author="reviewer",
    )

    res = monitor.remediate_single_thread(
        repo_slug="org/repo",
        pr_info={"number": 10, "headRefName": "fix/test-branch"},
        comment=comment,
        repo_path=tmp_path,
    )

    assert res.success is False
    assert res.status == "PUSH_FAILED"
    assert "botSecretPassword789" not in (res.error_message or "")
    assert "[REDACTED]" in (res.error_message or "")


# ==============================================================================
# Critical Issue 3: RingBufferLogger.get_recent() alias
# ==============================================================================

def test_ring_buffer_logger_get_recent_alias():
    """Verify RingBufferLogger.get_recent() exists and is a functional alias for get_recent_logs()."""
    logger = RingBufferLogger(capacity=10)
    for i in range(5):
        logger.log("INFO", f"Log entry {i}")

    # Test default count (50, capped at current 5)
    recent_alias = logger.get_recent()
    recent_logs = logger.get_recent_logs()
    assert recent_alias == recent_logs
    assert len(recent_alias) == 5

    # Test explicit count
    assert logger.get_recent(2) == logger.get_recent_logs(2)
    assert len(logger.get_recent(2)) == 2
    assert "Log entry 4" in logger.get_recent(2)[-1]

    # Test empty buffer
    empty_logger = RingBufferLogger(capacity=10)
    assert empty_logger.get_recent() == []
    assert empty_logger.get_recent(10) == []

    # Test count exceeding capacity / size
    assert len(logger.get_recent(100)) == 5


def test_ring_buffer_logger_get_recent_zero_and_negative_counts():
    """Verify get_recent and get_recent_logs return empty list for 0 and negative counts (boundary risk)."""
    logger = RingBufferLogger(capacity=10)
    for i in range(3):
        logger.log("INFO", f"Entry {i}")

    # Boundary: count = 0
    assert logger.get_recent(0) == []
    assert logger.get_recent_logs(0) == []

    # Boundary: count < 0
    assert logger.get_recent(-1) == []
    assert logger.get_recent_logs(-1) == []
    assert logger.get_recent(-10) == []
    assert logger.get_recent_logs(-10) == []


# ==============================================================================
# Edge Cases & Robustness
# ==============================================================================

def test_scrub_handles_none_empty_and_various_credentials():
    """Verify _scrub safely handles None, empty string, Bearer tokens, Basic auth, and raw Exception objects."""
    agent = MainFixerAgent()
    assert agent._scrub(None) is None
    assert agent._scrub("") == ""

    # Exception object passed instead of str
    exc = RuntimeError("Failed connecting to https://user:pass123@github.com")
    assert "pass123" not in agent._scrub(exc)
    assert "[REDACTED]" in agent._scrub(exc)

    bearer_err = "Request failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
    assert "Bearer [REDACTED]" in agent._scrub(bearer_err)

    basic_err = "Auth failed: Basic dXNlcm5hbWU6cGFzc3dvcmQxMjM="
    assert "Basic [REDACTED]" in agent._scrub(basic_err)

    monitor = ReviewMonitor(config=None, database=None, git_manager=None, verifier=Verifier())
    assert monitor._scrub(None) is None
    assert monitor._scrub("") == ""
    assert "pass123" not in monitor._scrub(exc)
    assert "[REDACTED]" in monitor._scrub(exc)
    assert "Bearer [REDACTED]" in monitor._scrub(bearer_err)
    assert "Basic [REDACTED]" in monitor._scrub(basic_err)
