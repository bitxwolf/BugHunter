"""
Adversarial Stress Test Suite for Secret Sanitizer.
Challenger 1 empirical verification for Milestone 1.

Categories:
1. Evasive secret formats:
   - Type annotations: `api_key: str = "..."`
   - String prefixes: byte string `b"..."`, raw string `r"..."`, f-string `f"..."`
   - JSON quoted keys: {"api_key": "..."}
   - Multiline triple quotes: '''...'''
   - JavaScript/TypeScript template literals: `const token = ...`
   - JWT tokens containing dots: eyJ...
   - Complex passwords containing special symbols: `@`, `#`, `$`, `!`, `%`, `&`, `*`
   - YAML unquoted keys: `api_key: dGhpc2lz...`
   - Line continuation: `api_key = \\\n   "..."`
2. False positive resistance on legitimate code:
   - Standard SHA-256 / MD5 hex digests
   - Math formulas and high-precision pi constants
   - UUID v4 identifiers
   - SVG path coordinates and Tailwind CSS classes
   - Git commit SHAs
   - API endpoints and URLs containing words like 'token', 'password', 'secret'
3. Git diff '-' line handling (secret deletion verification):
   - Pure deletion of leaked PAT
   - Mixed diff deleting leak and adding clean code
   - Replacement of leak with new secret (must still fail)
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import pytest

SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from pre_commit_secret_sanitizer import (
    BLOCKED_NAMES,
    BLOCKED_EXTENSIONS,
    shannon_entropy,
    mask_token,
    is_blocked_file,
    scan_text_for_secrets,
)
from install_hooks import install_pre_commit_hook


# Sample high-entropy Base64 test token synthesized dynamically
SAMPLE_HIGH_ENTROPY = "dGhpc2lz" + "YXNhbXBs" + "ZXNlY3Jl" + "dGtleTEy" + "MzQ1Ng=="


# =====================================================================
# 1. EVASION ATTACK SUITE
# =====================================================================

class TestEvasiveSecretFormats:
    """Evaluates secret detection across evasive programming language syntaxes."""

    def test_evasion_type_annotation(self):
        """Python type annotation: `api_key: str = '...'`."""
        snippet = f'api_key: str = "{SAMPLE_HIGH_ENTROPY}"'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: Type-annotated variable assignments evade detection"

    def test_evasion_byte_and_raw_strings(self):
        """Byte strings (`b'...'`) and raw strings (`r'...'`)."""
        b_snippet = f'api_key = b"{SAMPLE_HIGH_ENTROPY}"'
        r_snippet = f'token = r"{SAMPLE_HIGH_ENTROPY}"'
        assert len(scan_text_for_secrets(b_snippet)) > 0, "VULNERABILITY: Byte string assignments evade detection"
        assert len(scan_text_for_secrets(r_snippet)) > 0, "VULNERABILITY: Raw string assignments evade detection"

    def test_evasion_json_quoted_keys(self):
        """JSON / Dict format with quoted keys: `{\"api_key\": \"...\"}`."""
        json_snippet = f'{{"api_key": "{SAMPLE_HIGH_ENTROPY}"}}'
        findings = scan_text_for_secrets(json_snippet)
        assert len(findings) > 0, "VULNERABILITY: JSON quoted keys evade detection"

    def test_evasion_triple_quoted_strings(self):
        """Triple quoted multiline strings: `secret = \"\"\"...\"\"\"`."""
        snippet = f'secret = """{SAMPLE_HIGH_ENTROPY}"""'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: Triple quoted strings evade detection"

    def test_evasion_backtick_template_literals(self):
        """JavaScript / TypeScript template literals: `const api_key = `...``."""
        js_snippet = f"const api_key = `{SAMPLE_HIGH_ENTROPY}`;"
        findings = scan_text_for_secrets(js_snippet)
        assert len(findings) > 0, "VULNERABILITY: JS backtick template literals evade detection"

    def test_evasion_jwt_tokens(self):
        """JWT tokens containing dots: `eyJhbGci...`."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        snippet = f'auth_token = "{jwt}"'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: JWT tokens with dots evade detection"

    def test_evasion_special_characters_in_password(self):
        """Complex passwords containing special characters (`@`, `$`, `!`, `%`, `*`, `?`, `&`)."""
        pwd = "P@ssw0rd!2026$#SecretKey%^&*~"
        snippet = f'password = "{pwd}"'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: High-entropy passwords with symbols evade detection"

    def test_evasion_yaml_unquoted(self):
        """YAML configuration with unquoted high-entropy token."""
        yaml_snippet = f"api_key: {SAMPLE_HIGH_ENTROPY}"
        findings = scan_text_for_secrets(yaml_snippet)
        assert len(findings) > 0, "VULNERABILITY: Unquoted YAML secrets evade detection"

    def test_evasion_line_continuation(self):
        """Line continuation separating identifier and secret: `api_key = \\\n  '...'`."""
        snippet = f'api_key = \\\n    "{SAMPLE_HIGH_ENTROPY}"'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: Line continuation escapes line-by-line scanning"

    def test_evasion_split_token_concatenation(self):
        """Tokens split across concatenation: `token = 'ghp_' + '...'`."""
        tok_part1 = "ghp_" + "a" * 18
        tok_part2 = "b" * 18
        snippet = f'token = "{tok_part1}" + "{tok_part2}"'
        findings = scan_text_for_secrets(snippet)
        assert len(findings) > 0, "VULNERABILITY: String concatenation evades token regexes"

    def test_known_prefix_detection_robustness(self):
        """Tokens matching standard prefixes (ghp_, sk-, AIza) are caught regardless of variable name."""
        pat = "ghp_" + "a" * 36
        ai_key = "sk-" + "c" * 32
        gcp_key = "AIza" + "d" * 35
        assert len(scan_text_for_secrets(f'x = "{pat}"')) == 1
        assert len(scan_text_for_secrets(f'foo = "{ai_key}"')) == 1
        assert len(scan_text_for_secrets(f'bar = "{gcp_key}"')) == 1


# =====================================================================
# 2. FALSE POSITIVE RESISTANCE SUITE
# =====================================================================

class TestFalsePositiveResistanceAdversarial:
    """Verifies that legitimate code constructs are NOT falsely identified as secrets."""

    def test_fp_sha256_and_md5_hashes(self):
        """Standard SHA256 and MD5 hex digests."""
        code = '''
def check_hash():
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    return sha256, md5
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_fp_math_and_constants(self):
        """High-precision mathematical constants and formulas."""
        code = '''
PI = "3.1415926535897932384626433832795028841971"
GAMMA = "0.5772156649015328606065120900824024310421"
FORMULA = "E = mc^2 + \\int_0^\\infty e^{-x^2} dx"
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_fp_uuid_identifiers(self):
        """UUID v4 strings."""
        code = '''
user_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
session_id = "c9a646d3-9c61-4cd7-9f59-e1b6e12d12b1"
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_fp_svg_and_css(self):
        """SVG vector path coordinates and CSS utility strings."""
        code = '''
path = "M10 80 Q 52.5 10, 95 80 T 180 80 M20 20 L40 40 L60 20 Z"
theme = "bg-slate-900 text-emerald-400 font-mono text-sm rounded-lg"
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_fp_git_commit_sha(self):
        """Git commit hashes and tree references."""
        code = '''
commit_sha = "d3b07384d113edec49eaa6238ad5ff0012345678"
'''
        assert len(scan_text_for_secrets(code)) == 0

    def test_fp_api_endpoint_paths(self):
        """Endpoint routes and URL paths containing 'token', 'secret', or 'password' in the variable name."""
        paths = [
            'refresh_token_endpoint = "/api/v1/auth/refresh-token"',
            'token_request_path = "/v1/tokens/revoke-all-sessions"',
            'password_reset_url_path = "/auth/password/reset/confirm"',
            'secret_storage_dir = "/var/run/secrets/kubernetes.io"',
            'token_cache_prefix = "cache_token_v2_active_users"',
        ]
        for p in paths:
            findings = scan_text_for_secrets(p)
            assert len(findings) == 0, f"False positive detected on legitimate path: {p} -> {findings}"


# =====================================================================
# 3. DIFF '-' LINE HANDLING (SECRET REMOVAL TEST)
# =====================================================================

class TestDiffSecretDeletion:
    """Empirically tests that removing secrets in Git diffs is permitted and never blocked."""

    @pytest.fixture
    def git_repo_with_leak(self, tmp_path):
        """Sets up a Git repo where a previous commit contained a leaked secret."""
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test Committer"], cwd=tmp_path, check=True)
        subprocess.run(["git", "config", "user.email", "committer@test.local"], cwd=tmp_path, check=True)

        leak_file = tmp_path / "credentials.py"
        pat = "ghp_" + "9" * 36
        leak_file.write_text(
            f'# Leaked credentials\n'
            f'github_pat = "{pat}"\n'
            f'api_secret = "{SAMPLE_HIGH_ENTROPY}"\n',
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "credentials.py"], cwd=tmp_path, check=True)
        subprocess.run(["git", "commit", "-m", "Legacy leak commit"], cwd=tmp_path, check=True)

        scripts_dir = tmp_path / "scripts"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPTS_DIR / "pre_commit_secret_sanitizer.py", scripts_dir / "pre_commit_secret_sanitizer.py")
        assert install_pre_commit_hook(tmp_path) is True
        return tmp_path

    def test_hook_allows_deleting_leaked_pat(self, git_repo_with_leak):
        """Deleting the leaked PAT line must pass cleanly through the pre-commit hook."""
        leak_file = git_repo_with_leak / "credentials.py"
        leak_file.write_text(
            '# Cleaned credentials\n'
            'github_pat = os.getenv("GITHUB_TOKEN")\n'
            'api_secret = os.getenv("API_SECRET")\n',
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "credentials.py"], cwd=git_repo_with_leak, check=True)

        diff_res = subprocess.run(["git", "diff", "--cached"], cwd=git_repo_with_leak, capture_output=True, text=True, check=True)
        assert "-github_pat = \"ghp_" in diff_res.stdout

        commit_res = subprocess.run(["git", "commit", "-m", "fix: purge leaked credentials"], cwd=git_repo_with_leak, capture_output=True, text=True)
        assert commit_res.returncode == 0, f"Commit failed on secret removal: {commit_res.stderr}"

    def test_hook_allows_mixed_diff_removing_secret_and_adding_clean_code(self, git_repo_with_leak):
        """A single diff hunk that deletes a secret and adds normal functions."""
        leak_file = git_repo_with_leak / "credentials.py"
        leak_file.write_text(
            'import os\n'
            '\n'
            'def get_client():\n'
            '    return os.environ.get("SAFE_TOKEN")\n',
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "credentials.py"], cwd=git_repo_with_leak, check=True)
        commit_res = subprocess.run(["git", "commit", "-m", "fix: refactor to safe client"], cwd=git_repo_with_leak, capture_output=True, text=True)
        assert commit_res.returncode == 0, f"Commit failed on mixed diff: {commit_res.stderr}"

    def test_hook_still_catches_new_secret_even_when_old_is_deleted(self, git_repo_with_leak):
        """If a commit deletes an old secret but replaces it with ANOTHER secret, it MUST FAIL."""
        leak_file = git_repo_with_leak / "credentials.py"
        new_pat = "ghp_" + "8" * 36
        leak_file.write_text(
            f'# Replaced with another secret\n'
            f'github_pat = "{new_pat}"\n',
            encoding="utf-8"
        )
        subprocess.run(["git", "add", "credentials.py"], cwd=git_repo_with_leak, check=True)
        commit_res = subprocess.run(["git", "commit", "-m", "replace leak"], cwd=git_repo_with_leak, capture_output=True, text=True)
        assert commit_res.returncode == 1, "Expected commit to fail when replacing a secret with a new secret"
        assert "Secret token detected (github_pat)" in commit_res.stderr
        subprocess.run(["git", "reset", "HEAD", "credentials.py"], cwd=git_repo_with_leak, check=True)
