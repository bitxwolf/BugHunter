#!/usr/bin/env python3
"""
AutoBugHunter 24/7 - Pre-Commit Secret & Temporary File Sanitizer.

Inspects staged git changes before commit to prevent credential leaks
(PATs, API keys, private keys, high entropy assignments) and banned
orchestration files (.env, .skip_files.txt, .static_findings.json, etc.).
Enforces RULE-GIT-05, RULE-LLM-01, RULE-LLM-02, and RULE-CODE-03.
"""

from __future__ import annotations

import argparse
import math
import pathlib
import re
import subprocess
import sys
from typing import List, Optional, Tuple

# =====================================================================
# Secret Detection Regex Patterns
# =====================================================================

PATTERNS = {
    "github_pat": re.compile(r"ghp_[A-Za-z0-9_]{36,}"),
    "github_fine_grained": re.compile(r"github_pat_[A-Za-z0-9_]{82,}"),
    "github_oauth": re.compile(r"gh[ours]_[A-Za-z0-9_]{36,}"),
    "openai_key": re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    "generic_assignment": re.compile(
        r"""(?ix)
        (?:['\"]?[a-z0-9_]*(?:api[_-]?key|secret|token|password|auth_token)[a-z0-9_]*['\"]?)
        (?:\s*:\s*[^=:\r\n\"'{}]{1,50}\s*=\s*|\s*[:=]\s*)
        (?:[brfBRF]{1,2})?
        (?:(?P<quote>['\"`]{1,3})(?P<val_quoted>[A-Za-z0-9_\-+/=.@$!%*?&#~^]{20,})(?P=quote)|(?<=:\s)(?P<val_unquoted>[A-Za-z0-9_\-+/=.@$!%*?&#~^]{20,})(?!\s*[\(]))
        """
    ),
}

# Compatibility alias
SECRET_PATTERNS = PATTERNS

# =====================================================================
# Prohibited File Staging Rules
# =====================================================================

BLOCKED_NAMES = {
    ".skip_files.txt",
    ".static_findings.json",
    ".bug_fix_report.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}

BLOCKED_EXACT_NAMES = BLOCKED_NAMES

BLOCKED_EXTENSIONS = (
    ".sqlite",
    ".db",
    ".sqlite3",
    ".sqlite-wal",
    ".sqlite-shm",
    ".pem",
    ".key",
)

BLOCKED_GLOBS = [f"*{ext}" for ext in BLOCKED_EXTENSIONS]

ALLOWED_ENV_FILES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}

ENTROPY_THRESHOLD = 3.8
COMMENT_BYPASS_PATTERNS = (
    "ghp_",
    "github_pat_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "sk-",
    "AIza",
    "-----BEGIN",
)


# =====================================================================
# Core Algorithms
# =====================================================================

def shannon_entropy(data: str) -> float:
    """Computes Shannon entropy of a string in bits per character.

    Returns:
        float: Entropy value (bits/char). 0.0 for identical characters,
               typically < 3.8 for predictable/English text,
               and >= 3.8 for cryptographic/random tokens.
    """
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for char in set(data):
        prob = float(data.count(char)) / length
        entropy -= prob * math.log2(prob)
    return entropy


calculate_shannon_entropy = shannon_entropy


def mask_token(token: str) -> str:
    """Masks sensitive token preserving only the first 4 and last 4 characters.

    Example: 'ghp_1234567890abcdefghijklmnopqrstuv' -> 'ghp_...stuv'
    """
    if len(token) <= 8:
        return "****"
    return f"{token[:4]}...{token[-4:]}"


mask_secret = mask_token


def is_blocked_file(filepath: str) -> bool:
    """Checks if a file matches prohibited staging targets.

    Returns True if file is blocked, False if clean.
    """
    normalized = filepath.strip().strip('"\\'').replace("\\", "/")
    filename = pathlib.PurePosixPath(normalized).name
    filename_lower = filename.lower()

    if filename in BLOCKED_NAMES or filename_lower in BLOCKED_NAMES:
        return True

    if filename == ".env" or filename_lower == ".env":
        return True
    if filename.startswith(".env.") or filename_lower.startswith(".env."):
        if filename in ALLOWED_ENV_FILES or filename_lower in ALLOWED_ENV_FILES:
            return False
        return True

    for ext in BLOCKED_EXTENSIONS:
        if filename_lower.endswith(ext):
            return True

    return False


def check_blocked_file(filepath: str) -> Optional[str]:
    """Checks file path against blocked file rules.

    Returns explanation reason if blocked, None if clean.
    """
    normalized = filepath.strip().strip('"\\'').replace("\\", "/")
    filename = pathlib.PurePosixPath(normalized).name
    filename_lower = filename.lower()

    if filename in BLOCKED_NAMES or filename_lower in BLOCKED_NAMES:
        return f"Banned orchestration or private key artifact ({filename})."

    if filename == ".env" or filename_lower == ".env":
        return "Banned environment file (.env). Keep secrets local and uncommitted."
    if filename.startswith(".env.") or filename_lower.startswith(".env."):
        if filename in ALLOWED_ENV_FILES or filename_lower in ALLOWED_ENV_FILES:
            return None
        return f"Banned environment file ({filename}). Only templates (.env.example) are allowed."

    for ext in BLOCKED_EXTENSIONS:
        if filename_lower.endswith(ext):
            return f"Banned file extension matching pattern '*{ext}'."

    return None


def is_false_positive_token(token: str) -> bool:
    """Checks if a matched token is a false positive (e.g. URL, endpoint route, path)."""
    if token.startswith(("/", "\\", "http://", "https://", "ws://", "wss://", "file://", "./", "../")):
        return True
    if token.count("/") >= 2:
        if any(token.startswith(p) for p in ("api/", "v1/", "v2/", "auth/", "tokens/", "static/", "assets/", "var/", "usr/", "etc/")):
            return True
        segments = [s.lower() for s in token.split("/")]
        if any(seg in ("api", "v1", "v2", "auth", "tokens", "oauth", "password", "reset", "kubernetes.io") for seg in segments):
            return True
    return False


def scan_text_for_secrets(text: str) -> List[Tuple[str, str]]:
    """Scans text content for secret tokens.

    Returns list of tuples: (rule_name, masked_token).
    """
    findings: List[Tuple[str, str]] = []
    # Normalize line continuations (e.g. backslash before newline)
    normalized_text = re.sub(r"\\\r?\n[ \t]*", " ", text)

    for raw_line in normalized_text.splitlines():
        line_clean = raw_line.strip()
        # Skip comments unless explicit token signature is present
        if line_clean.startswith("#") or line_clean.startswith("//"):
            if not any(sig in line_clean for sig in COMMENT_BYPASS_PATTERNS):
                continue

        lines_to_check = [raw_line]
        deconcatenated = re.sub(r"""['\"`]\s*\+\s*['\"`]""", "", raw_line)
        if deconcatenated != raw_line:
            lines_to_check.append(deconcatenated)

        for line in lines_to_check:
            for p_name, pattern in PATTERNS.items():
                if p_name == "generic_assignment":
                    for m in pattern.finditer(line):
                        val = m.group("val_quoted") or m.group("val_unquoted")
                        if not val:
                            continue
                        if is_false_positive_token(val):
                            continue
                        if shannon_entropy(val) >= ENTROPY_THRESHOLD:
                            item = (p_name, mask_token(val))
                            if item not in findings:
                                findings.append(item)
                else:
                    for m in pattern.finditer(line):
                        tok = m.group(0)
                        if is_false_positive_token(tok):
                            continue
                        item = (p_name, mask_token(tok))
                        if item not in findings:
                            findings.append(item)
    return findings


# =====================================================================
# Git Inspection & Main Entrypoint
# =====================================================================

EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _get_diff_base(repo_path: str = ".") -> str:
    """Returns 'HEAD' if commits exist, or Git's standard empty tree hash if HEAD is unborn."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return "HEAD"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return EMPTY_TREE_SHA


def get_staged_files(repo_path: str = ".") -> List[str]:
    """Retrieves list of staged file paths from git index."""
    try:
        base = _get_diff_base(repo_path)
        cmd = ["git", "diff", "--cached", "--name-only", base]
        res = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return [f.strip().strip('"\\'') for f in res.stdout.splitlines() if f.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        sys.stderr.write(f"Git error checking staged files: {e}\n")
        return []


def get_staged_diff(repo_path: str = ".") -> str:
    """Retrieves unified staged diff with zero context lines."""
    try:
        base = _get_diff_base(repo_path)
        cmd = ["git", "diff", "--cached", "-U0", base]
        res = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return res.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        sys.stderr.write(f"Git error checking staged diff: {e}\n")
        return ""


def main() -> int:
    """Git pre-commit entrypoint: scans staged files and staged diffs."""
    parser = argparse.ArgumentParser(description="Pre-commit secret and artifact sanitizer")
    parser.add_argument("--repo-path", default=".", help="Path to git repository root (default: .)")
    args, _ = parser.parse_known_args()
    repo_path = args.repo_path

    # 1. Check staged filenames
    staged_files = get_staged_files(repo_path)
    blocked_found = False
    for f in staged_files:
        reason = check_blocked_file(f)
        if reason:
            sys.stderr.write(f"[ERROR] Staging of banned file detected: '{f}' - {reason}\n")
            sys.stderr.write(f"       Run 'git restore --staged \"{f}\"' to un-stage this file.\n")
            blocked_found = True

    if blocked_found:
        return 1

    # 2. Check added lines in staged diff
    diff_text = get_staged_diff(repo_path)
    added_lines = [
        line[1:] for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]

    findings = scan_text_for_secrets("\n".join(added_lines))
    if findings:
        for p_name, masked_tok in findings:
            if p_name == "generic_assignment":
                sys.stderr.write(
                    f"[ERROR] High-entropy credential assignment detected: {masked_tok}\n"
                )
            else:
                sys.stderr.write(
                    f"[ERROR] Secret token detected ({p_name}): {masked_tok}\n"
                )
        sys.stderr.write("[ERROR] Commit rejected: Remove credentials from staged changes.\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
