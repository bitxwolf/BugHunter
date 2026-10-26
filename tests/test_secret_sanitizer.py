"""
Comprehensive Test Suite for Secret Sanitizer and Pre-Commit Hook Installer.
Covers token regexes, Shannon entropy calculation, blocked staged files,
.env.example exceptions, clean code allowances, and live Git hook integration.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import pytest

# Ensure scripts/ directory is in Python module search path
SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from pre_commit_secret_sanitizer import (
    BLOCKED_NAMES,
    BLOCKED_EXTENSIONS,
    shannon_entropy,
    mask_token,
    is_blocked_file,
    check_blocked_file,
    scan_text_for_secrets,
    main as sanitizer_main,
    _get_diff_base,
    get_staged_files,
)
from install_hooks import (
    find_git_dir,
    get_hooks_dir,
    generate_hook_script,
    install_pre_commit_hook,
    check_hook_installed,
)


class TestShannonEntropy:
    """Tests for Shannon entropy calculation across varied token strings."""

    def test_entropy_empty(self):
        assert shannon_entropy("") == 0.0

    def test_entropy_repeated_chars(self):
        assert shannon_entropy("A" * 50) == 0.0
        assert shannon_entropy("1" * 32) == 0.0

    def test_entropy_low_predictable(self):
        assert shannon_entropy("development_key_placeholder") < 3.8
        assert shannon_entropy("dummy_mock_secret_token") < 3.8
        assert shannon_entropy("placeholder_token_value_abc") < 3.8
        assert shannon_entropy("test_secret_12345") < 3.8

    def test_entropy_high_random(self):
        # Cryptographic base64 / hex keys must exceed 3.8 bits/char
        b64_sample = "dGhpc2lz" + "YXNhbXBs" + "ZXNlY3Jl" + "dGtleTEy" + "MzQ1Ng=="
        assert shannon_entropy(b64_sample) >= 3.8
        rnd_sample = "K3x9ZbQ8" + "vW2N4jL1" + "mP9sR6tY" + "0uI3oE5w"
        assert shannon_entropy(rnd_sample) >= 3.8
        hex_sample = "c8f7a1b2" + "d3e4f506" + "1728394a" + "5b6c7d8e"
        assert shannon_entropy(hex_sample) >= 3.8
        sym_sample = "xJ8!kL2@" + "mN9#oP4$" + "qR7%sT0^" + "uV3&wY6*"
        assert shannon_entropy(sym_sample) >= 3.8


class TestTokenDetection:
    """Tests detection of simulated API tokens, PATs, and private keys."""

    def test_github_classic_pat(self):
        tok = "ghp_" + "a" * 36
        findings = scan_text_for_secrets(f'token = "{tok}"')
        assert len(findings) == 1
        assert findings[0][0] == "github_pat"
        assert findings[0][1] == "ghp_...aaaa"

    def test_github_fine_grained_pat(self):
        tok = "github_pat_" + "b" * 82
        findings = scan_text_for_secrets(f'pat = "{tok}"')
        assert len(findings) == 1
        assert findings[0][0] == "github_fine_grained"
        assert findings[0][1].startswith("gith")
        assert findings[0][1].endswith("bbbb")

    def test_github_oauth_tokens(self):
        for prefix in ("gho_", "ghu_", "ghs_", "ghr_"):
            tok = prefix + "c" * 36
            findings = scan_text_for_secrets(f'auth = "{tok}"')
            assert len(findings) >= 1
            assert findings[0][0] == "github_oauth"
            assert findings[0][1].startswith(prefix)

    def test_openai_api_keys(self):
        tok1 = "sk-" + "d" * 48
        findings1 = scan_text_for_secrets(f'api_key = "{tok1}"')
        assert any(f[0] == "openai_key" for f in findings1)

        tok2 = "sk-proj-" + "e" * 48
        findings2 = scan_text_for_secrets(f'api_key = "{tok2}"')
        assert any(f[0] == "openai_key" for f in findings2)

    def test_anthropic_api_key(self):
        tok = "sk-ant-" + "f" * 40
        findings = scan_text_for_secrets(f'api_key = "{tok}"')
        assert len(findings) == 1
        assert findings[0][0] == "anthropic_key"
        # Must not be classified as generic openai_key due to negative lookahead
        assert not any(f[0] == "openai_key" for f in findings)

    def test_google_cloud_api_key(self):
        tok = "AIza" + "g" * 35
        findings = scan_text_for_secrets(f'gcp_key = "{tok}"')
        assert len(findings) == 1
        assert findings[0][0] == "google_api_key"

    def test_private_keys(self):
        # Dynamically synthesize headers to prevent self-flagging when staged
        prefix = "-----" + "BEGIN "
        suffix = " PRIVATE KEY" + "-----"
        headers = [
            prefix + "RSA" + suffix,
            prefix + "OPENSSH" + suffix,
            prefix + "EC" + suffix,
            "-----" + "BEGIN PRIVATE KEY" + "-----",
            prefix + "DSA" + suffix,
            prefix + "ENCRYPTED" + suffix,
        ]
        for h in headers:
            findings = scan_text_for_secrets(h)
            assert len(findings) == 1, f"Failed matching header: {h}"
            assert findings[0][0] == "private_key"

    def test_high_entropy_assignments(self):
        # Dynamically build high-entropy token pieces (< 20 chars each) to avoid tripping pre-commit hook during commit
        sample_payload = "dGhpc2lz" + "YXNhbXBs" + "ZXNlY3Jl" + "dGtleTEy" + "MzQ1Ng=="
        for var_name in ("api_key", "OPENAI_API_KEY", "secret", "MY_SECRET_KEY", "token", "auth_token", "password"):
            findings = scan_text_for_secrets(f'{var_name} = "{sample_payload}"')
            assert any(f[0] == "generic_assignment" for f in findings), f"Failed for {var_name}"


class TestKeyMasking:
    """Tests masked output of credentials in logs and errors."""

    def test_short_token_mask(self):
        assert mask_token("abc") == "****"
        assert mask_token("12345678") == "****"

    def test_long_token_mask(self):
        tok = "ghp_1234567890abcdefghijklmnopqrstuv"
        masked = mask_token(tok)
        assert masked == "ghp_...stuv"
        assert len(masked) == 11
        assert "1234567890abcdefghijklmnopqr" not in masked


class TestBlockedFiles:
    """Tests detection of prohibited repository files."""

    def test_banned_env_files(self):
        assert is_blocked_file(".env") is True
        assert is_blocked_file(".env.local") is True
        assert is_blocked_file(".env.production") is True
        assert is_blocked_file("src/.env") is True
        assert is_blocked_file("workspace/.env.staging") is True

    def test_allowed_env_example(self):
        assert is_blocked_file(".env.example") is False
        assert is_blocked_file("subfolder/.env.example") is False
        assert is_blocked_file(".env.sample") is False
        assert is_blocked_file(".env.template") is False

    def test_banned_orchestration_artifacts(self):
        assert is_blocked_file(".skip_files.txt") is True
        assert is_blocked_file("workspace/.skip_files.txt") is True
        assert is_blocked_file(".static_findings.json") is True
        assert is_blocked_file("state/.bug_fix_report.json") is True

    def test_banned_sqlite_files(self):
        assert is_blocked_file("bughunter.sqlite") is True
        assert is_blocked_file("bughunter.sqlite-wal") is True
        assert is_blocked_file("bughunter.sqlite-shm") is True
        assert is_blocked_file("test.db") is True
        assert is_blocked_file("workspace/state/data.sqlite") is True

    def test_banned_private_key_files(self):
        assert is_blocked_file("server.key") is True
        assert is_blocked_file("cert.pem") is True
        assert is_blocked_file("id_rsa") is True
        assert is_blocked_file("id_ed25519") is True
        assert is_blocked_file("id_ecdsa") is True
        assert is_blocked_file("id_dsa") is True

    def test_banned_files_with_spaces_and_quotes(self):
        assert is_blocked_file("my secret.key") is True
        assert is_blocked_file('"my secret.key"') is True
        assert is_blocked_file("keys/server cert.pem") is True
        assert is_blocked_file('"keys/server cert.pem"') is True
        assert is_blocked_file("config/my database.sqlite") is True

    def test_allowed_standard_files(self):
        assert is_blocked_file("main.py") is False
        assert is_blocked_file("src/config.py") is False
        assert is_blocked_file("README.md") is False
        assert is_blocked_file("pyproject.toml") is False
        assert is_blocked_file("requirements.txt") is False
        assert is_blocked_file("Dockerfile") is False
        assert is_blocked_file("docker-compose.yml") is False


class TestFalsePositiveResistance:
    """Verifies that clean production code, comments, and low entropy strings are not flagged."""

    def test_clean_python_code(self):
        code = '''
import os
import sys

def calculate_kpis(repo_list: list[str]) -> dict:
    total = len(repo_list)
    return {"total": total, "status": "active"}
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_low_entropy_variable_assignment(self):
        code = '''
api_key = "development_placeholder"
secret = "mock_secret_value"
token = "test_token_123"
admin_password = "password123"
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_unquoted_function_calls(self):
        code = '''
api_key = get_secure_credential_token()
api_key: str = get_secure_credential_token()
token = retrieve_auth_token_for_user(request)
secret = generate_random_entropy_token()
password = hash_user_password(raw_input)
auth_token = fetch_token(user_id=123)
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_comments_without_secrets(self):
        code = '''
# Please provide an api_key in your local .env file
# Example: token = "YOUR_TOKEN_HERE"
# API keys can be generated from https://platform.openai.com
'''
        assert len(scan_text_for_secrets(code)) == 0


class TestHookInstallationUnit:
    """Unit tests for install_hooks.py functions."""

    def test_install_fresh_repo(self, tmp_path):
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        assert install_pre_commit_hook(tmp_path) is True
        assert check_hook_installed(tmp_path) is True

        hook_file = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook_file.exists()
        content = hook_file.read_text(encoding="utf-8")
        assert "AutoBugHunter" in content
        assert "scripts/pre_commit_secret_sanitizer.py" in content

    def test_install_non_git_repo(self, tmp_path):
        assert install_pre_commit_hook(tmp_path) is False
        assert check_hook_installed(tmp_path) is False

    def test_install_idempotency(self, tmp_path):
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        assert install_pre_commit_hook(tmp_path) is True
        assert install_pre_commit_hook(tmp_path) is True
        assert check_hook_installed(tmp_path) is True


class TestPreCommitHookIntegration:
    """Integration tests running Git commits against real pre-commit hook in temporary repos."""

    @pytest.fixture
    def git_repo(self, tmp_path):
        # 1. Initialize Git repo
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "committer@test.local"], cwd=tmp_path, check=True)

        # 2. Initial commit to establish HEAD branch
        (tmp_path / "README.md").write_text("# Test Repo\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=tmp_path, check=True)

        # 3. Set up scripts directory with real pre_commit_secret_sanitizer.py
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        source_sanitizer = SCRIPTS_DIR / "pre_commit_secret_sanitizer.py"
        shutil.copy(source_sanitizer, scripts_dir / "pre_commit_secret_sanitizer.py")

        # 4. Install pre-commit hook
        assert install_pre_commit_hook(tmp_path) is True
        return tmp_path

    def test_hook_blocks_banned_files(self, git_repo):
        for banned_file in [".env", ".skip_files.txt", ".static_findings.json", ".bug_fix_report.json", "test.sqlite", "server.key"]:
            f = git_repo / banned_file
            f.write_text("dummy payload", encoding="utf-8")
            subprocess.run(["git", "add", banned_file], cwd=git_repo, check=True)
            res = subprocess.run(["git", "commit", "-m", f"add {banned_file}"], cwd=git_repo, capture_output=True, text=True)
            assert res.returncode == 1, f"Expected commit to fail for {banned_file}"
            assert "Staging of banned file detected" in res.stderr
            subprocess.run(["git", "reset", "HEAD", banned_file], cwd=git_repo, check=True)
            f.unlink()

    def test_hook_allows_env_example(self, git_repo):
        ex = git_repo / ".env.example"
        ex.write_text("GITHUB_TOKEN=placeholder\nLLM_KEYS_POOL=none\n", encoding="utf-8")
        subprocess.run(["git", "add", ".env.example"], cwd=git_repo, check=True)
        res = subprocess.run(["git", "commit", "-m", "add .env.example"], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 0, f"Expected .env.example to commit cleanly: {res.stderr}"

    def test_hook_blocks_github_pat(self, git_repo):
        f = git_repo / "leak_pat.py"
        pat = "ghp_" + "1" * 36
        f.write_text(f'token = "{pat}"\n', encoding="utf-8")
        subprocess.run(["git", "add", "leak_pat.py"], cwd=git_repo, check=True)
        res = subprocess.run(["git", "commit", "-m", "leak pat"], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 1
        assert "Secret token detected (github_pat)" in res.stderr
        subprocess.run(["git", "reset", "HEAD", "leak_pat.py"], cwd=git_repo, check=True)
        f.unlink()

    def test_hook_blocks_openai_key(self, git_repo):
        f = git_repo / "leak_ai.py"
        key = "sk-proj-" + "2" * 48
        f.write_text(f'key = "{key}"\n', encoding="utf-8")
        subprocess.run(["git", "add", "leak_ai.py"], cwd=git_repo, check=True)
        res = subprocess.run(["git", "commit", "-m", "leak ai"], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 1
        assert "Secret token detected (openai_key)" in res.stderr
        subprocess.run(["git", "reset", "HEAD", "leak_ai.py"], cwd=git_repo, check=True)
        f.unlink()

    def test_hook_blocks_private_key(self, git_repo):
        f = git_repo / "leak_key.py"
        header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        f.write_text(f'KEY = "{header}\\nMIIEowIBAAKCAQEA..."\n', encoding="utf-8")
        subprocess.run(["git", "add", "leak_key.py"], cwd=git_repo, check=True)
        res = subprocess.run(["git", "commit", "-m", "leak rsa key"], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 1
        assert "Secret token detected (private_key)" in res.stderr
        subprocess.run(["git", "reset", "HEAD", "leak_key.py"], cwd=git_repo, check=True)
        f.unlink()

    def test_hook_allows_secret_removal(self, git_repo):
        # 1. First commit a clean file
        f = git_repo / "auth.py"
        f.write_text("api_key = os.getenv('KEY')\n", encoding="utf-8")
        subprocess.run(["git", "add", "auth.py"], cwd=git_repo, check=True)
        res1 = subprocess.run(["git", "commit", "-m", "clean auth"], cwd=git_repo, capture_output=True, text=True)
        assert res1.returncode == 0

        # 2. Modify file cleanly (removal of secret / normal refactoring)
        f.write_text("api_key = os.environ.get('KEY')\n", encoding="utf-8")
        subprocess.run(["git", "add", "auth.py"], cwd=git_repo, check=True)
        res2 = subprocess.run(["git", "commit", "-m", "refactor auth"], cwd=git_repo, capture_output=True, text=True)
        assert res2.returncode == 0

    def test_direct_sanitizer_cli_execution(self, git_repo):
        sanitizer_path = git_repo / "scripts" / "pre_commit_secret_sanitizer.py"
        # When clean
        res = subprocess.run([sys.executable, str(sanitizer_path)], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 0

        # When dirty (staged banned file)
        banned = git_repo / ".skip_files.txt"
        banned.write_text("test", encoding="utf-8")
        subprocess.run(["git", "add", ".skip_files.txt"], cwd=git_repo, check=True)
        res = subprocess.run([sys.executable, str(sanitizer_path)], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 1
        subprocess.run(["git", "reset", "HEAD", ".skip_files.txt"], cwd=git_repo, check=True)
        banned.unlink()

    def test_unborn_head_fresh_repo(self, tmp_path):
        """Sanitizer operates correctly on a newborn repository before the initial commit (unborn HEAD)."""
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPTS_DIR / "pre_commit_secret_sanitizer.py", scripts_dir / "pre_commit_secret_sanitizer.py")
        sanitizer_path = scripts_dir / "pre_commit_secret_sanitizer.py"

        # 1. Clean staged file on unborn HEAD
        (tmp_path / "README.md").write_text("# Hello World\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
        res = subprocess.run([sys.executable, str(sanitizer_path)], cwd=tmp_path, capture_output=True, text=True)
        assert res.returncode == 0

        # 2. Banned file staged on unborn HEAD
        (tmp_path / ".env").write_text("FOO=bar\n", encoding="utf-8")
        subprocess.run(["git", "add", ".env"], cwd=tmp_path, check=True)
        res_fail = subprocess.run([sys.executable, str(sanitizer_path)], cwd=tmp_path, capture_output=True, text=True)
        assert res_fail.returncode == 1
        assert "Staging of banned file detected" in res_fail.stderr

    def test_hook_blocks_files_with_spaces(self, git_repo):
        """Staging a banned file whose filename contains spaces is detected and blocked."""
        space_file = git_repo / "server private.key"
        space_file.write_text("private key content", encoding="utf-8")
        subprocess.run(["git", "add", "server private.key"], cwd=git_repo, check=True)
        res = subprocess.run(["git", "commit", "-m", "add key with spaces"], cwd=git_repo, capture_output=True, text=True)
        assert res.returncode == 1
        assert "Staging of banned file detected" in res.stderr
        subprocess.run(["git", "reset", "HEAD", "server private.key"], cwd=git_repo, check=True)
        space_file.unlink()

    def test_get_staged_files_unborn_and_spaces(self, tmp_path):
        """get_staged_files returns cleanly unquoted paths on unborn HEAD with spaces."""
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        (tmp_path / "spaced file name.txt").write_text("content", encoding="utf-8")
        subprocess.run(["git", "add", "spaced file name.txt"], cwd=tmp_path, check=True)

        staged = get_staged_files(str(tmp_path))
        assert "spaced file name.txt" in staged
        assert '"spaced file name.txt"' not in staged
        assert not any(f.startswith('"') or f.endswith('"') for f in staged)

    def test_check_blocked_file_comprehensive(self):
        """check_blocked_file identifies prohibited files with explanatory reasons and allows templates."""
        # Blocked exact names
        for b in [".skip_files.txt", ".static_findings.json", "id_rsa", "id_ecdsa", "id_dsa", ".env"]:
            assert check_blocked_file(b) is not None
            assert check_blocked_file(f"subdir/{b}") is not None
            assert check_blocked_file(f'"{b}"') is not None

        # Blocked extensions (case-insensitive)
        for ext in [".key", ".KEY", ".pem", ".PEM", ".sqlite", ".db"]:
            assert check_blocked_file(f"server{ext}") is not None
            assert check_blocked_file(f"path/to/my{ext}") is not None

        # Allowed templates
        assert check_blocked_file(".env.example") is None
        assert check_blocked_file(".env.sample") is None
        assert check_blocked_file(".env.template") is None
        assert check_blocked_file("path/to/.env.example") is None

        # Clean standard files
        assert check_blocked_file("main.py") is None
        assert check_blocked_file("src/config.py") is None
        assert check_blocked_file("README.md") is None


