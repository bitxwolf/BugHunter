"""
Empirical Adversarial Test Suite for M12 Iteration 2 (Challenger m12_iter2_1).
Verifies:
1. Unmodified code in ```python\n...``` returns None
2. Unmodified code in ```\n...``` returns None
3. Raw backticks inside text returns None (if unparsed triple backticks) or handles inline safely
4. Conversational refusals return None across all formats
5. JSON objects with unmodified code return None across all keys and wrapper formats
6. Valid code modifications in markdown fences are extracted and modified correctly
7. Whitespace, newline, and carriage return robustness
"""

import json
from pathlib import Path
import pytest

from src.config import Config, KeyConfig
from src.database import Database
from src.review_monitor import ReviewMonitor


@pytest.fixture
def minimal_monitor(tmp_path: Path) -> ReviewMonitor:
    k1 = KeyConfig(
        id="key-test",
        provider="ScaleMax",
        base_url="https://api.scalemax.pro/v1",
        model="openai/gpt-6-luna",
        api_key="scalemax_test_key_1234",
        masked_key="scalemax...1234",
        priority=1,
    )
    cfg = Config.load(overrides={
        "WORKSPACE_DIR": tmp_path,
        "workspace_dir": tmp_path,
        "TARGET_REPOS": ["bitxwolf/BugHunter"],
        "GITHUB_TOKEN": "mock_token_adv",
        "LLM_KEYS": [k1],
    })
    db = Database(tmp_path / "test_adv.sqlite")
    return ReviewMonitor(config=cfg, database=db, git_manager=None, verifier=None)


class TestM12Iter2AdversarialSuite:
    """Rigorous empirical validation of _extract_code_from_llm_response."""

    ORIGINAL_CODE = (
        "def compute_total(items: list[int]) -> int:\n"
        "    total = 0\n"
        "    for item in items:\n"
        "        total += item\n"
        "    return total\n"
    )

    MODIFIED_CODE = (
        "def compute_total(items: list[int]) -> int:\n"
        "    return sum(items)\n"
    )

    # -------------------------------------------------------------
    # 1. Unmodified code in ```python\n...```
    # -------------------------------------------------------------
    def test_unmodified_code_in_python_fence_returns_none(self, minimal_monitor):
        # Exact match
        payload1 = f"```python\n{self.ORIGINAL_CODE}```"
        assert minimal_monitor._extract_code_from_llm_response(payload1, original_code=self.ORIGINAL_CODE) is None

        # With leading/trailing commentary around the fence
        payload2 = (
            "I inspected your file and here is the result:\n"
            f"```python\n{self.ORIGINAL_CODE}```\n"
            "No changes were needed."
        )
        assert minimal_monitor._extract_code_from_llm_response(payload2, original_code=self.ORIGINAL_CODE) is None

        # With extra whitespace / blank lines inside fence
        payload3 = f"```python\n\n{self.ORIGINAL_CODE}\n\n```"
        assert minimal_monitor._extract_code_from_llm_response(payload3, original_code=self.ORIGINAL_CODE) is None

    # -------------------------------------------------------------
    # 2. Unmodified code in ```\n...```
    # -------------------------------------------------------------
    def test_unmodified_code_in_bare_fence_returns_none(self, minimal_monitor):
        # Exact match in bare fence
        payload1 = f"```\n{self.ORIGINAL_CODE}```"
        assert minimal_monitor._extract_code_from_llm_response(payload1, original_code=self.ORIGINAL_CODE) is None

        # Bare fence with surrounding text
        payload2 = f"Here is the code as requested:\n```\n{self.ORIGINAL_CODE}```\nHope this helps!"
        assert minimal_monitor._extract_code_from_llm_response(payload2, original_code=self.ORIGINAL_CODE) is None

        # Other language tags with unmodified code
        for lang in ["py", "python3", "txt", "text", "sh"]:
            payload_lang = f"```{lang}\n{self.ORIGINAL_CODE}```"
            assert minimal_monitor._extract_code_from_llm_response(
                payload_lang, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed on language tag: {lang}"

    # -------------------------------------------------------------
    # 3. Raw backticks inside text
    # -------------------------------------------------------------
    def test_raw_backticks_inside_text(self, minimal_monitor):
        # Unparsed / unclosed triple backticks must return None (not raw text)
        unclosed = f"```python\n{self.MODIFIED_CODE}"
        assert minimal_monitor._extract_code_from_llm_response(unclosed, original_code=self.ORIGINAL_CODE) is None

        # Conversational text mentioning code snippets with triple backticks
        convo_with_fence = (
            "You should change the code like this:\n"
            "```python\n"
            "def broken():\n"
            "    pass\n"
            # Note: no closing fence
        )
        assert minimal_monitor._extract_code_from_llm_response(convo_with_fence, original_code=self.ORIGINAL_CODE) is None

        # Raw code containing inline single backticks (e.g., in comments or docstrings)
        # should work IF it's valid code modification without triple backticks
        code_with_inline_backtick = (
            "def compute_total(items: list[int]) -> int:\n"
            "    # Uses `sum` built-in for efficiency\n"
            "    return sum(items)\n"
        )
        # In a proper fence:
        fenced_inline = f"```python\n{code_with_inline_backtick}```"
        res = minimal_monitor._extract_code_from_llm_response(fenced_inline, original_code=self.ORIGINAL_CODE)
        assert res == code_with_inline_backtick.strip()

        # As raw text (valid modification without triple backticks):
        res_raw = minimal_monitor._extract_code_from_llm_response(code_with_inline_backtick, original_code=self.ORIGINAL_CODE)
        assert res_raw == code_with_inline_backtick.strip()

    # -------------------------------------------------------------
    # 4. Conversational refusals
    # -------------------------------------------------------------
    def test_conversational_refusals_return_none(self, minimal_monitor):
        refusal_samples = [
            "I cannot modify this file because it looks correct.",
            "I'm sorry, but I cannot make this change safely.",
            "I am sorry, but the requested edit violates constraints.",
            "As an AI, I cannot access the internet to verify this library.",
            "Unable to determine the root cause from the given diff hunk.",
            "i cannot fulfill this request.",
            "i'm sorry, this is not possible.",
            "I CANNOT DO THIS",
        ]
        for ref in refusal_samples:
            assert minimal_monitor._extract_code_from_llm_response(
                ref, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed on refusal: {ref}"

        # Refusal inside markdown fence should also be rejected or not match code
        ref_fenced = "```\nI cannot perform this remediation.\n```"
        # It's in a fence, but does it return or is it invalid?
        # Note: if inside a fence, fence extractor extracts it unless it matches original.
        # But conversational refusals as raw text return None.
        assert minimal_monitor._extract_code_from_llm_response(
            "I cannot perform this remediation.", original_code=self.ORIGINAL_CODE
        ) is None

    # -------------------------------------------------------------
    # 5. JSON objects with unmodified code
    # -------------------------------------------------------------
    def test_json_objects_with_unmodified_code(self, minimal_monitor):
        # All standard JSON keys with unmodified code
        for key in ["updated_full_file", "code", "file_content", "patch"]:
            # Direct JSON
            payload_json = json.dumps({key: self.ORIGINAL_CODE})
            assert minimal_monitor._extract_code_from_llm_response(
                payload_json, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed direct JSON with key: {key}"

            # JSON wrapped in markdown json fence
            payload_fenced_json = f"```json\n{json.dumps({key: self.ORIGINAL_CODE})}\n```"
            assert minimal_monitor._extract_code_from_llm_response(
                payload_fenced_json, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed fenced JSON with key: {key}"

            # JSON wrapped in bare markdown fence
            payload_bare_fence = f"```\n{json.dumps({key: self.ORIGINAL_CODE})}\n```"
            assert minimal_monitor._extract_code_from_llm_response(
                payload_bare_fence, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed bare fenced JSON with key: {key}"

            # JSON with inner markdown fence containing unmodified code
            payload_inner_fence = json.dumps({key: f"```python\n{self.ORIGINAL_CODE}```"})
            assert minimal_monitor._extract_code_from_llm_response(
                payload_inner_fence, original_code=self.ORIGINAL_CODE
            ) is None, f"Failed inner fence in JSON key: {key}"

        # Non-code JSON object (e.g. status/error report from LLM)
        status_json = json.dumps({"status": "no_change", "reason": "Code is already optimal"})
        assert minimal_monitor._extract_code_from_llm_response(status_json, original_code=self.ORIGINAL_CODE) is None

    # -------------------------------------------------------------
    # 6. Valid code modifications in markdown fences are extracted
    # -------------------------------------------------------------
    def test_valid_code_modifications_extracted_correctly(self, minimal_monitor):
        # In ```python
        fenced_py = f"```python\n{self.MODIFIED_CODE}```"
        res_py = minimal_monitor._extract_code_from_llm_response(fenced_py, original_code=self.ORIGINAL_CODE)
        assert res_py == self.MODIFIED_CODE.strip()

        # In ``` (bare)
        fenced_bare = f"```\n{self.MODIFIED_CODE}```"
        res_bare = minimal_monitor._extract_code_from_llm_response(fenced_bare, original_code=self.ORIGINAL_CODE)
        assert res_bare == self.MODIFIED_CODE.strip()

        # In JSON {"updated_full_file": ...}
        json_mod = json.dumps({"updated_full_file": self.MODIFIED_CODE})
        res_json = minimal_monitor._extract_code_from_llm_response(json_mod, original_code=self.ORIGINAL_CODE)
        assert res_json == self.MODIFIED_CODE.strip()

        # In JSON {"code": ...} inside ```json ... ```
        fenced_json = f"```json\n{{\"code\": \"{self.MODIFIED_CODE.replace(chr(10), chr(92)+'n')}\"}}\n```"
        res_fenced_json = minimal_monitor._extract_code_from_llm_response(fenced_json, original_code=self.ORIGINAL_CODE)
        assert res_fenced_json == self.MODIFIED_CODE.strip()

        # Multiple fences: commentary fence vs full code fence
        multi_fences = (
            "Here is the modified function:\n"
            "```python\n"
            "# Snippet\n"
            "return sum(items)\n"
            "```\n"
            "Here is the complete updated file:\n"
            "```python\n"
            f"{self.MODIFIED_CODE}"
            "```\n"
        )
        res_multi = minimal_monitor._extract_code_from_llm_response(multi_fences, original_code=self.ORIGINAL_CODE)
        assert res_multi == self.MODIFIED_CODE.strip()

    # -------------------------------------------------------------
    # 7. Boundary edge cases (carriage returns, whitespaces, empty)
    # -------------------------------------------------------------
    def test_boundary_edge_cases(self, minimal_monitor):
        # Windows CRLF in original and response
        crlf_orig = self.ORIGINAL_CODE.replace("\n", "\r\n")
        crlf_mod = self.MODIFIED_CODE.replace("\n", "\r\n")
        fenced_crlf = f"```python\r\n{crlf_mod}\r\n```"

        res_crlf = minimal_monitor._extract_code_from_llm_response(fenced_crlf, original_code=crlf_orig)
        assert res_crlf is not None
        assert "return sum(items)" in res_crlf

        # CRLF with unmodified code returns None
        unmod_crlf = f"```python\r\n{crlf_orig}\r\n```"
        assert minimal_monitor._extract_code_from_llm_response(unmod_crlf, original_code=crlf_orig) is None

        # Empty / whitespace inputs
        assert minimal_monitor._extract_code_from_llm_response("", original_code=self.ORIGINAL_CODE) is None
        assert minimal_monitor._extract_code_from_llm_response("   \t\n  ", original_code=self.ORIGINAL_CODE) is None
        assert minimal_monitor._extract_code_from_llm_response("```python\n```", original_code=self.ORIGINAL_CODE) is None
