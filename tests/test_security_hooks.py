"""
Unit and integration tests for Git Security Hooks:
- scripts/install_hooks.py (Lifecycle, permissions, backups, CLI flags)
- scripts/pre_commit_secret_sanitizer.py (Secret detection, high entropy, banned files)
"""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess
import sys
from unittest.mock import patch
import pytest

# Ensure scripts directory is on sys.path
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import install_hooks
from install_hooks import (
    find_git_dir,
    get_hooks_dir,
    generate_hook_script,
    install_pre_commit_hook,
    check_hook_installed,
    main as install_main,
)

from pre_commit_secret_sanitizer import (
    main as sanitizer_main,
    scan_text_for_secrets,
    check_blocked_file,
    is_blocked_file,
    shannon_entropy,
    mask_token,
    PATTERNS,
    BLOCKED_NAMES,
    BLOCKED_EXTENSIONS,
    ALLOWED_ENV_FILES,
)


@pytest.fixture
def temp_git_repo(tmp_path: pathlib.Path) -> pathlib.Path:
    """Fixture initializing a clean Git repository with author identity configured."""
    repo_dir = tmp_path / "git_test_repo"
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Security Tester"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "tester@security.local"], cwd=repo_dir, check=True, capture_output=True)

    # Initial commit
    readme = repo_dir / "README.md"
    readme.write_text("# Security Test Repo\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=repo_dir, check=True, capture_output=True)

    # Mirror scripts into the repo for hook wrapper execution
    scripts_dir = repo_dir / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(SCRIPTS_DIR / "pre_commit_secret_sanitizer.py", scripts_dir / "pre_commit_secret_sanitizer.py")
    shutil.copy(SCRIPTS_DIR / "install_hooks.py", scripts_dir / "install_hooks.py")

    return repo_dir


# =====================================================================
# 1. install_hooks.py Lifecycle & CLI Tests
# =====================================================================

def test_install_pre_commit_hook_fresh_repo(temp_git_repo: pathlib.Path):
    """Verify install_pre_commit_hook creates hook file and check_hook_installed returns True."""
    assert check_hook_installed(temp_git_repo) is False

    success = install_pre_commit_hook(temp_git_repo)
    assert success is True
    assert check_hook_installed(temp_git_repo) is True

    hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"
    assert hook_file.is_file()
    content = hook_file.read_text(encoding="utf-8")
    assert content.startswith("#!/bin/sh")
    assert "scripts/pre_commit_secret_sanitizer.py" in content


def test_install_pre_commit_hook_executable_permissions(temp_git_repo: pathlib.Path):
    """Verify executable permissions are set on non-Windows platforms."""
    assert install_pre_commit_hook(temp_git_repo) is True
    hook_file = temp_git_repo / ".git" / "hooks" / "pre-commit"

    if os.name != "nt":
        file_mode = hook_file.stat().st_mode
        assert (file_mode & stat.S_IXUSR) != 0


def test_install_pre_commit_hook_backups_foreign_hook(temp_git_repo: pathlib.Path):
    """Verify foreign pre-commit hook is backed up to pre-commit.backup.<pid> when force=False."""
    hooks_dir = temp_git_repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"
    hook_file.write_text("#!/bin/sh\necho 'foreign pre-commit hook'\n", encoding="utf-8")

    pid = os.getpid()
    success = install_pre_commit_hook(temp_git_repo, force=False)
    assert success is True

    # Foreign hook backed up
    backup_file = hooks_dir / f"pre-commit.backup.{pid}"
    assert backup_file.is_file()
    assert "foreign pre-commit hook" in backup_file.read_text(encoding="utf-8")

    # New hook installed
    assert "scripts/pre_commit_secret_sanitizer.py" in hook_file.read_text(encoding="utf-8")


def test_install_pre_commit_hook_force_overwrite(temp_git_repo: pathlib.Path):
    """Verify force=True overwrites existing hook without creating a backup file."""
    hooks_dir = temp_git_repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"
    hook_file.write_text("#!/bin/sh\necho 'foreign hook'\n", encoding="utf-8")

    success = install_pre_commit_hook(temp_git_repo, force=True)
    assert success is True

    # No backup file created
    backups = list(hooks_dir.glob("pre-commit.backup.*"))
    assert len(backups) == 0
    assert "scripts/pre_commit_secret_sanitizer.py" in hook_file.read_text(encoding="utf-8")


def test_install_pre_commit_hook_non_git_directory(tmp_path: pathlib.Path):
    """Verify install_pre_commit_hook returns False in a non-git directory."""
    non_git = tmp_path / "plain_dir"
    non_git.mkdir(parents=True, exist_ok=True)

    assert install_pre_commit_hook(non_git) is False
    assert check_hook_installed(non_git) is False


def test_install_hooks_cli_flags(temp_git_repo: pathlib.Path, monkeypatch):
    """Verify CLI parser handles --check, --repo-dir, --force, and --python-path."""
    custom_py = sys.executable

    # 1. --check when not installed -> exit code 1
    monkeypatch.setattr(sys, "argv", ["install_hooks.py", "--repo-dir", str(temp_git_repo), "--check"])
    assert install_main() == 1

    # 2. Normal install with --repo-dir and --python-path
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_hooks.py", "--repo-dir", str(temp_git_repo), "--python-path", custom_py],
    )
    assert install_main() == 0

    # 3. --check when installed -> exit code 0
    monkeypatch.setattr(sys, "argv", ["install_hooks.py", "--repo-dir", str(temp_git_repo), "--check"])
    assert install_main() == 0

    # 4. Overwrite with --force
    monkeypatch.setattr(
        sys,
        "argv",
        ["install_hooks.py", "--repo-dir", str(temp_git_repo), "--force"],
    )
    assert install_main() == 0


def test_generate_hook_script_custom_python():
    """Verify generate_hook_script generates valid POSIX shell script with given python path."""
    content = generate_hook_script("/opt/custom/python3")
    assert content.startswith("#!/bin/sh")
    assert 'INSTALL_PYTHON="/opt/custom/python3"' in content
    assert 'scripts/pre_commit_secret_sanitizer.py "$@"' in content


# =====================================================================
# 2. pre_commit_secret_sanitizer.py Secret Detection Tests
# =====================================================================

def test_detect_github_tokens():
    """Verify detection of GitHub PATs, fine-grained PATs, and OAuth tokens."""
    # Classical PAT
    pat = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    findings = scan_text_for_secrets(f"GITHUB_TOKEN = '{pat}'")
    assert any(rule == "github_pat" for rule, _ in findings)

    # Fine-grained PAT
    fg_pat = "github_pat_" + "11ABCDEF" * 11
    findings_fg = scan_text_for_secrets(f"token = '{fg_pat}'")
    assert any(rule == "github_fine_grained" for rule, _ in findings_fg)

    # OAuth tokens (gho_, ghu_, ghs_, ghr_)
    for prefix in ["gho_", "ghu_", "ghs_", "ghr_"]:
        oauth_tok = prefix + "abcdefghijklmnopqrstuvwxyz1234567890"
        findings_oa = scan_text_for_secrets(f"oauth = '{oauth_tok}'")
        assert any(rule == "github_oauth" for rule, _ in findings_oa)


def test_detect_llm_api_keys():
    """Verify detection of OpenAI, Anthropic, and Google API keys."""
    # OpenAI sk- and sk-proj-
    openai_key = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    findings_oai = scan_text_for_secrets(f"openai_key = '{openai_key}'")
    assert any(rule == "openai_key" for rule, _ in findings_oai)

    openai_proj = "sk-proj-" + "abcdefghijklmnopqrstuvwxyz123456"
    findings_proj = scan_text_for_secrets(f"api_key = '{openai_proj}'")
    assert any(rule == "openai_key" for rule, _ in findings_proj)

    # Anthropic sk-ant-
    anthropic_key = "sk-ant-" + "api03-abcdefghijklmnopqrstuvwxyz12345"
    findings_ant = scan_text_for_secrets(f"anthropic_key = '{anthropic_key}'")
    assert any(rule == "anthropic_key" for rule, _ in findings_ant)

    # Google AIza...
    google_key = "AIza" + "d" * 35
    findings_goog = scan_text_for_secrets(f"google_api_key = '{google_key}'")
    assert any(rule == "google_api_key" for rule, _ in findings_goog)


def test_detect_private_key_blocks():
    """Verify detection of PEM/PKCS#8 private key header blocks."""
    pkcs8 = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."
    findings_pkcs8 = scan_text_for_secrets(pkcs8)
    assert any(rule == "private_key" for rule, _ in findings_pkcs8)

    rsa = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    findings_rsa = scan_text_for_secrets(rsa)
    assert any(rule == "private_key" for rule, _ in findings_rsa)


def test_detect_high_entropy_credentials():
    """Verify generic assignment detection for high-entropy secrets."""
    # Low entropy/predictable token should not trigger generic_assignment
    low_entropy = 'api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    assert len(scan_text_for_secrets(low_entropy)) == 0

    # High entropy token
    high_entropy = 'client_secret = "9xK#mP$2vL&8qR*1zT@4wY!6bN^0"'
    findings = scan_text_for_secrets(high_entropy)
    assert any(rule == "generic_assignment" for rule, _ in findings)


# =====================================================================
# 3. pre_commit_secret_sanitizer.py Prohibited File Blocking Tests
# =====================================================================

@pytest.mark.parametrize(
    "banned_file",
    [
        ".skip_files.txt",
        ".static_findings.json",
        ".bug_fix_report.json",
        ".env",
        ".env.local",
        ".env.production",
        "app.sqlite",
        "database.db",
        "store.sqlite3",
        "data.sqlite-wal",
        "data.sqlite-shm",
        "server.pem",
        "id_rsa",
        "id_ed25519",
        "server.key",
    ],
)
def test_blocking_prohibited_files(banned_file: str):
    """Verify exact prohibited files and extensions are flagged by check_blocked_file and is_blocked_file."""
    assert is_blocked_file(banned_file) is True
    reason = check_blocked_file(banned_file)
    assert reason is not None
    assert isinstance(reason, str)


@pytest.mark.parametrize(
    "allowed_file",
    [
        ".env.example",
        ".env.sample",
        ".env.template",
        "src/main.py",
        "tests/test_verifier.py",
        "README.md",
        "package.json",
    ],
)
def test_allowed_env_templates_and_standard_files(allowed_file: str):
    """Verify safe files including .env templates are permitted."""
    assert is_blocked_file(allowed_file) is False
    assert check_blocked_file(allowed_file) is None


# =====================================================================
# 4. End-to-End Sanitizer Main CLI Tests
# =====================================================================

def test_sanitizer_main_blocks_staged_prohibited_file(temp_git_repo: pathlib.Path):
    """Verify sanitizer main() detects staged prohibited file and exits 1."""
    banned = temp_git_repo / ".skip_files.txt"
    banned.write_text("src/auth.py\n", encoding="utf-8")
    subprocess.run(["git", "add", ".skip_files.txt"], cwd=temp_git_repo, check=True)

    with patch("sys.argv", ["pre_commit_secret_sanitizer.py", "--repo-path", str(temp_git_repo)]):
        exit_code = sanitizer_main()
        assert exit_code == 1


def test_sanitizer_main_blocks_staged_secret(temp_git_repo: pathlib.Path):
    """Verify sanitizer main() detects staged secret diff and exits 1."""
    leak_file = temp_git_repo / "src" / "config.py"
    leak_file.parent.mkdir(parents=True, exist_ok=True)
    leak_file.write_text('GITHUB_TOKEN = "ghp_111122223333444455556666777788889999"\n', encoding="utf-8")
    subprocess.run(["git", "add", "src/config.py"], cwd=temp_git_repo, check=True)

    with patch("sys.argv", ["pre_commit_secret_sanitizer.py", "--repo-path", str(temp_git_repo)]):
        exit_code = sanitizer_main()
        assert exit_code == 1


def test_sanitizer_main_allows_clean_commit(temp_git_repo: pathlib.Path):
    """Verify sanitizer main() allows clean, compliant staged changes and exits 0."""
    clean_file = temp_git_repo / "src" / "utils.py"
    clean_file.parent.mkdir(parents=True, exist_ok=True)
    clean_file.write_text("def multiply(x: int, y: int) -> int:\n    return x * y\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/utils.py"], cwd=temp_git_repo, check=True)

    with patch("sys.argv", ["pre_commit_secret_sanitizer.py", "--repo-path", str(temp_git_repo)]):
        exit_code = sanitizer_main()
        assert exit_code == 0
