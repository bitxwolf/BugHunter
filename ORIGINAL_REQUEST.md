# Original User Request

## Initial Request — 2026-10-21T04:13:50Z

Requested team: Full team (with parallel workstreams for all 7 phases)

Build **AutoBugHunter 24/7**, an autonomous, containerized software engineering daemon running on an Oracle Cloud Free Tier ARM64 (`linux/arm64`) instance that continuously monitors 20+ GitHub repositories, isolates single bugs via static analysis pre-filters and headless OpenHands, applies minimal atomic patches, verifies tests pass, and submits Pull Requests.

Working directory: `C:\antigravity\bughunter`
Integrity mode: development

## Requirements

### R1. Open-Source Component Leverage & Zero Unnecessary Reinvention
Do not write custom tools from scratch where battle-tested open-source software is available:
- Agent Harness: Leverage OpenHands CLI (`openhands-ai`) in headless mode (`RUNTIME=process`).
- Static Pre-Scanner: Leverage Ruff (`ruff check`) and Semgrep OSS (`semgrep`).
- LLM Rotator: Leverage LiteLLM / OpenAI-compatible routing for ScaleMax (`openai/claude-haiku-5.5`) with multi-key cooldown fallback.
- GitHub Integration: Leverage GitHub CLI (`gh`) for collision checks, auth, and PR creation.
- Web Dashboard: Leverage FastAPI + WebSockets + Tailwind CSS (CDN) + Lucide Icons.

### R2. Core Persistence & Resilient Key Routing (Phases 1 & 2)
Implement `src/config.py`, SQLite WAL engine in `src/database.py` with the 4 core tables (`repositories`, `pull_requests`, `api_key_status`, `scan_logs`), ring-buffer logger in `src/logger.py`, and multi-key circuit breaker in `src/key_manager.py`.

### R3. Git Workspace, Pre-Filter & OpenHands Runner (Phases 3 & 4)
Implement `src/git_manager.py` with hard-reset syncing and open PR collision guard (`.skip_files.txt`), `prompts/task_prompt.txt` enforcing the One Bug = One PR rule, `src/static_scanner.py` compiling `.static_findings.json`, and `src/openhands_runner.py` with process-tree isolation (`os.killpg`) and live log streaming.

### R4. Verification Gate, Master Loop & PR Dispatcher (Phase 5)
Implement `src/verifier.py` to enforce diff bounds (≤ 3 files, ≤ 150 lines, zero whitespace-only changes, zero credential leaks) and `src/orchestrator.py` to drive the continuous 24/7 scanning cycle and dispatch `gh pr create`.

### R5. Mission Control UI & Production Container Packaging (Phases 6 & 7)
Implement FastAPI dashboard endpoints and WebSocket streaming in `src/web_server.py`, `src/templates/dashboard.html` adhering to the cyber-ops dark theme, entrypoint in `main.py`, native ARM64 multi-arch `Dockerfile`, `docker-compose.yml` (20 GB RAM limit), and `scripts/deploy_oracle_arm64.sh`.

## Acceptance Criteria

### Verification & Test Suite
- [ ] Comprehensive unit test suite covering database operations, key rotator failover on `429`/`402`, Git reset & collision guards, diff verification, and API endpoints.
- [ ] All tests pass cleanly (`pytest tests/`).
- [ ] Python syntax validation passes without warnings (`python -m py_compile main.py src/*.py`).
- [ ] Pre-commit secret sanitizer detects and blocks simulated GitHub PATs and LLM API keys.
- [ ] Temporary files (`.skip_files.txt`, `.static_findings.json`, `.bug_fix_report.json`) are purged before commit.


## Follow-up — 2026-10-21T08:27:02Z

# Teamwork Project Prompt

Fix all security vulnerabilities (GitHub token leakage, unauthenticated API control, subprocess credential leakage, path traversal, CSWSH) and expand QA test coverage (hook installer lifecycle, diff boundary limits, database WAL concurrency stress) in AutoBugHunter 24/7 without regressions.

Working directory: c:\antigravity\bughunter
Integrity mode: development

## Requirements

### R1. Security Hardening & Secret Protection
- Remediate GitHub token exposure in `src/git_manager.py` by cloning with `http.extraHeader` instead of embedding the token in the URL, and scrub credentials from exceptions and log messages.
- Add automatic secret scrubbing to `src/logger.py` RingBufferLogger before buffering, logging to disk, or streaming to WebSockets.
- Whitelist and sanitize subprocess execution environment in `src/openhands_runner.py`, explicitly preventing `GITHUB_TOKEN` and host credential leakage.
- Enforce strict repository slug validation (`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`) preventing path traversal and argument confusion in `src/git_manager.py` and `src/web_server.py`.
- Implement configurable API key authentication (`DASHBOARD_API_KEY`) and standard defensive HTTP security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`) in `src/web_server.py`.
- Validate `Origin` headers on WebSocket `/ws/logs` connection to prevent Cross-Site WebSocket Hijacking (CSWSH).
- Set `dashboard_host` default to `127.0.0.1` in `src/config.py`.

### R2. QA Expansion & Boundary Verification
- Implement unit tests in `tests/test_security_hooks.py` covering `scripts/install_hooks.py` and `scripts/pre_commit_secret_sanitizer.py`.
- Implement exact diff boundary limit tests (3 vs 4 files, 150 vs 151 lines) in `tests/test_verifier.py`.
- Implement multi-threaded concurrency stress tests in `tests/test_database.py` for SQLite WAL operations.
- Implement security unit tests in `tests/test_web_server.py` and `tests/test_git_manager.py` verifying authentication, slug validation, and sanitized cloning.
- Purge temporary artifacts when all LLM keys are exhausted in `src/orchestrator.py`.

### R3. Backward Compatibility & Compilation Integrity
- All existing 188 automated tests must continue to pass cleanly with zero regressions.
- All new and existing code must compile and pass lint/type integrity checks.

## Acceptance Criteria

### Security Criteria
- [ ] No plaintext GitHub token appears in git clone arguments, process lists, or exception strings.
- [ ] RingBufferLogger automatically redacts any credential string matching token regexes.
- [ ] Subprocess environment passed to OpenHands runner excludes `GITHUB_TOKEN` and parent environment secrets.
- [ ] Path traversal attempts (e.g. `../../etc` or slugs with `\`) in `POST /api/control/scan-now` and `GitManager.sync_repository` are rejected.
- [ ] Administrative API endpoints require valid `X-API-Key` or `Authorization: Bearer` when `DASHBOARD_API_KEY` is configured.
- [ ] WebSocket `/ws/logs` rejects unauthorized external origins.

### Test & Quality Criteria
- [ ] `tests/test_security_hooks.py` passes with full lifecycle verification of hook installation and secret scanning.
- [ ] Exact boundary condition tests for diff lines and files pass in `tests/test_verifier.py`.
- [ ] Multithreaded concurrency stress tests pass in `tests/test_database.py`.
- [ ] `pytest tests/` passes 100% (all 188+ tests green) without regressions.

## Follow-up — 2026-10-21T10:25:41Z

# Teamwork Project Prompt

Remediate all remaining findings from the Security Re-Audit Report (fail-open auth lockout, telemetry route protection, Mission Control UI API key integration, agent subprocess container sandboxing support, and Content-Security-Policy headers) without breaking existing test suites.

Working directory: c:\antigravity\bughunter
Integrity mode: development

## Requirements

### R1. Web Server Authentication Lockdown & Telemetry Security
- In `src/web_server.py`, modify `verify_control_auth`:
  - When `DASHBOARD_API_KEY` is empty/unset, restrict access to loopback (`127.0.0.1`, `::1`, `localhost`, `testclient`). If a remote client connects without an API key, reject with HTTP 403 Forbidden (`Remote access requires DASHBOARD_API_KEY`).
  - When `DASHBOARD_API_KEY` is configured, enforce valid `X-API-Key` or `Authorization: Bearer <key>` using `hmac.compare_digest`.
- Protect `GET /api/state` using `verify_control_auth`.
- Protect `WebSocket /ws/logs`: validate token query parameter `?token=...` or `?api_key=...` when `DASHBOARD_API_KEY` is configured. When unset, restrict connections to loopback/testclient.
- In `add_security_headers` middleware, add `Content-Security-Policy` and `Referrer-Policy: strict-origin-when-cross-origin`.

### R2. Mission Control Dashboard UI Authentication
- In `src/templates/dashboard.html`, add API key management supporting `localStorage` persistence (`bughunter_api_key`) and URL query parameter (`?key=...`).
- Add an API key input in the header bar allowing the operator to view, enter, or update the key.
- Pass `X-API-Key` in all `fetch()` requests (`/api/state`, `/api/control/*`).
- Pass `?token=${apiKey}` on WebSocket connection (`/ws/logs`).

### R3. Agent Subprocess Container Sandboxing Support
- In `src/openhands_runner.py` and `src/config.py`, make OpenHands runtime configurable via `Config.openhands_runtime` and `OPENHANDS_RUNTIME` environment variable (supporting `"docker"` for container sandboxing and `"process"` for host execution).
- Set `env["RUNTIME"] = self.runtime` in `_build_subprocess_env`.

### R4. Configuration & Deployment Documentation Sync
- Document `DASHBOARD_API_KEY` in `.env.example` with clear instructions on loopback vs remote deployment.
- Update `docker-compose.yml` environment section with `DASHBOARD_API_KEY` and recommend loopback binding `127.0.0.1:8080:8080`.

### R5. Test Verification & Zero Regression
- Add unit tests in `tests/test_web_server.py` verifying:
  - Remote client without API key receives 403 Forbidden.
  - `/api/state` requires authentication when configured.
  - `/ws/logs` enforces token query parameter when configured.
  - `Content-Security-Policy` header is present on HTTP responses.
- Ensure all existing 291 automated tests pass cleanly with 0 regressions.

## Acceptance Criteria

### Security Criteria
- [ ] Non-loopback requests to `/api/control/*` and `/api/state` without `DASHBOARD_API_KEY` return HTTP 403 Forbidden.
- [ ] Valid `X-API-Key` or Bearer token grants access when `DASHBOARD_API_KEY` is set; invalid credentials return 401 Unauthorized.
- [ ] `WebSocket /ws/logs` rejects connections lacking token when `DASHBOARD_API_KEY` is set, and rejects remote clients when unset.
- [ ] `Content-Security-Policy` header is attached to all HTTP responses.
- [ ] `dashboard.html` allows saving and sending the API key on all fetch and WebSocket requests.
- [ ] `OpenHandsRunner` supports container sandboxing via `OPENHANDS_RUNTIME`.

### Test Criteria
- [ ] All new security test cases in `tests/test_web_server.py` pass.
- [ ] `pytest tests/` passes 100% (291+ tests green) with zero regressions.
- [ ] Python compilation (`python -m py_compile`) passes with zero errors.

## Follow-up — 2026-10-22T12:39:44Z

# Teamwork Project Prompt

Requested team: Full team (with specialized workstreams for Memory Layer, Bug Hunter Triage, OpenHands Agent Harness, and Verification Gate)

Integrate open-source agent skills from addyosmani/agent-skills and a Dual-Layer Hybrid Memory architecture (sqlite-vec + Cognee) into AutoBugHunter 24/7 to autonomously drive bug triaging, root-cause patch generation, diff budget control, and cross-run memory with zero manual triggers.

Working directory: c:\antigravity\bughunter
Integrity mode: development

## Requirements

### R1. Agent Skills Division & Autonomous Lifecycle
Deconstruct and embed the requested agent skills without manual triggers into two distinct agent execution pipelines:
- **Bug Finding Agent (`longcatpreview`)**:
  - `code-review-and-quality`: 5-axis static finding triage (correctness, readability, architecture, security, performance) to filter noise before code dispatch.
  - `security-and-hardening`: Boundary defense, STRIDE threat modeling, OWASP validation, and input sanitization check on all suspect code paths.
- **Main Code Writing Agent (`luna 6` / OpenHands Patch Runner)**:
  - `debugging-and-error-recovery`: Stop-the-Line protocol, hypothesis testing, and mandatory regression reproducer before patching.
  - `code-simplification`: Diff budget control enforcing <= 3 files and <= 150 lines, zero speculative abstractions, minimal atomic patch invariant.
  - `git-workflow-and-versioning`: Conventional commit formatting (`fix(<scope>): <description>`), branch naming (`fix/auto-...`), and atomic PR description synthesis.

### R2. Dual-Layer Hybrid Memory Architecture
- **Layer 1: Episodic & Rejection Memory (`sqlite-vec`)**:
  - Load `sqlite-vec` extension inside `src/database.py` onto `bughunter.sqlite` in WAL mode.
  - Maintain `bug_memory` table tracking findings, code embeddings, patch outcomes, and PR maintainer rejection reasons.
  - Implement zero-cost pre-filtering: Skip recurring false positives with cosine similarity > 0.88.
- **Layer 2: Structural Codebase Memory (`Cognee`)**:
  - Ingest repository symbols, AST trees, class hierarchies, and test-to-source relationships into a graph memory.
  - Inject localized dependency graphs directly into OpenHands prompts to eliminate blind shell exploration.

### R3. Harness Verification & Regression Invariants
- All changes must run purely autonomously within `src/orchestrator.py` and `src/verifier.py`.
- Ensure 100% backward compatibility with all 188 existing tests in `pytest tests/`.
- Ensure compatibility with Oracle Cloud Free Tier ARM64 (`linux/arm64`) within memory bounds (< 2 GB).

## Acceptance Criteria

### Memory & Performance Criteria
- [ ] `bughunter.sqlite` initializes `sqlite-vec` successfully on ARM64 and records vector embeddings for scan outcomes.
- [ ] Recurring false positives and previously rejected PR patterns are intercepted and skipped before triggering OpenHands.
- [ ] Structural codebase graphs from Cognee provide targeted file context and test mappings to the agent prompt.

### Autonomous Skills Criteria
- [ ] Bug finding agent (`longcatpreview`) pre-filters static findings using 5-axis code quality and security boundaries.
- [ ] Code writing agent (`luna 6`) generates atomic reproducer tests before patching and abides by the 150-line diff cap.
- [ ] Commit messages follow conventional commit standard `fix(<scope>): <description>` and branch names use `fix/auto-...`.
- [ ] All 188 existing unit and integration tests continue to pass cleanly (`pytest tests/`).


## 2026-10-22T19:13:53Z

# Teamwork Project Prompt

> Status: Launched
> Goal: Fix all audited bugs across the bughunter codebase in parallel without regressions
> Requested team: Parallel subagent team

Fix all 12 correctness, security, concurrency, and infrastructure bugs identified in the 5-axis code audit without breaking any existing functionality or regressing any of the 361 passing tests.

Working directory: c:/antigravity/bughunter
Integrity mode: development

## Requirements

### R1. Triage Classification Hardening (`src/static_scanner.py`)
Prioritize Security and Correctness axes ahead of Readability in `FiveAxisTriageEngine.classify_axis`. Enforce strict digit patterns on Flake8 codes (`I\d{3}`, `N\d{3}`, `COM\d{3}`) so security rules like `INJECTION`, `INSECURE_CIPHER`, `INSECURE_COOKIE`, `COMMAND_INJECTION`, and `NULL_POINTER` are never misclassified as cosmetic readability.

### R2. Rate Limit Detection Precision (`src/openhands_runner.py`)
Replace raw substring `"429"` in `RATE_LIMIT_SIGNATURES` / line scanner with word-bounded regex matching (e.g. `\b429\b` or status code pattern) to prevent spurious aborts on console lines mentioning line numbers, ports, or commit hashes.

### R3. Untracked Files & Remote Push Safety (`src/verifier.py`, `src/git_manager.py`)
- In `Verifier.verify_and_sanitize_fix`, stage untracked files with intent-to-add (`git add -N .`) so `git diff HEAD` captures newly generated reproducer tests and modules in diff line bounds and secret scanning.
- In `GitManager.push_atomic_branch`, check for a configured remote origin (`git remote get-url origin`) before swallowing push errors, re-raising `CalledProcessError` with scrubbed credentials when origin is configured.

### R4. Logging & Daemon Lifecycle Resilience (`src/logger.py`, `main.py`, `src/orchestrator.py`)
- In `setup_logger`, reuse `ring_logger._file_handler` rather than instantiating a duplicate `RotatingFileHandler` to avoid Windows `PermissionError` (WinError 32) file locks.
- In `main.py`, wrap `orchestrator.run_cycle()` in a `try...except Exception as e:` block to keep the 24/7 daemon alive on transient faults.
- In `src/orchestrator.py`, protect `force_queue` mutations with a `threading.Lock()` and resolve `prompts/task_prompt.txt` relative to `__file__`.

### R5. Infrastructure, Graph & Database Memory (`docker-compose.yml`, `src/web_server.py`, `src/database.py`, `src/code_graph.py`)
- In `docker-compose.yml`, update container memory limit from `1800M` to `20G`.
- In `src/web_server.py`, allow matching against client `Host` header and `ALLOWED_ORIGINS` env var in WebSocket origin validation.
- In `src/database.py`, add `ORDER BY id DESC LIMIT 500` to the pure-Python fallback query in `query_similar_bugs`.
- In `src/code_graph.py`, resolve relative imports using `node.level` and parent module path so target edges are never empty strings.

## Acceptance Criteria

### Automated Test Suite & Integrity
- [ ] All 361 existing test cases in pytest continue to pass with 0 failures.
- [ ] Dedicated unit tests added for each of the bug fixes.
- [ ] All secrets and tokens remain redacted in logs and error traces.
- [ ] No regression in line bounds (150 lines) or file counts (3 files) for atomic patches.


## 2026-10-22T20:06:17Z

accorfing to @[conversation:"Full Project Bug Scan Schedule"]  only 6/25 bugs re fixed 
#task fix them fully


## 2026-10-23T18:47:50Z

Refactor the AutoBugHunter remediation pipeline to decouple bug discovery and planning (via modular skills in `src/bughunter_agent.py`) from code editing (via `src/aider_runner.py`), updating all model configurations and fallback headers from `longcat-preview` to `gpt-6-luna` pointing to the ScaleMax endpoint `https://api.scalemax.pro/v1`.

Working directory: c:/antigravity/bughunter
Integrity mode: development

## Requirements

### R1. Modular BugHunter Agent with Skills
Refactor/create `src/bughunter_agent.py` to decouple bug triage and patch planning from code editing through modular skills:
- **Static Analysis & Triage Skill**: Parse findings from Flake8, ESLint, Bandit, Semgrep, and Trivy; deduplicate identical issues and rank by severity and blast radius.
- **Context Extraction Skill**: Extract only relevant functions, classes, and immediate imports rather than passing entire files.
- **Patch Planning Skill**: Formulate surgical step-by-step patch instructions for Aider adhering strictly to One Bug = One PR and a <=150 lines diff ceiling.

### R2. Aider Execution Runner
Implement `src/aider_runner.py` wrapping `aider-chat`:
- Support headless execution (CLI or Python API) with arguments:
  `aider --model openai/gpt-6-luna --openai-api-base https://api.scalemax.pro/v1 --openai-api-key "$ACTIVE_KEY" --yes --no-auto-commits --edit-format diff --message "$PATCH_INSTRUCTION" path/to/target_file.py`
- Expose a clean execution interface to accept a target file and patch plan from BugHunter and return exit code, diff output, and status.

### R3. Model Shift & ScaleMax Configuration
- Update all model identifiers from `longcat-preview` to `gpt-6-luna` (and `openai/gpt-6-luna` for LiteLLM/Aider compatibility).
- Configure base URL to `https://api.scalemax.pro/v1`.
- Ensure `OPENAI_API_BASE=https://api.scalemax.pro/v1` is propagated in the process environment.
- Extract API keys dynamically from `LLM_KEYS_POOL` or `OPENAI_API_KEY`.

### R4. Test Suite and Verification
Implement an automated test suite (`tests/` or equivalent) covering:
- Parsing, ranking, and deduplication of findings in the Triage Skill.
- Accurate AST/text slicing in the Context Extraction Skill.
- Enforcement of <=150 line ceiling and patch prompt formatting in the Patch Planning Skill.
- Execution runner argument construction and exit code handling with mocked Aider processes.

## Acceptance Criteria

### Automated Tests
- [ ] `pytest` runs and all tests pass with zero failures.
- [ ] Unit tests verify Flake8, ESLint, Bandit, Semgrep, and Trivy parsers.
- [ ] Unit tests verify context extraction isolates target scope without full file dumps.
- [ ] Unit tests verify patch planner generates valid Aider instructions enforcing <=150 lines limit.
- [ ] Unit tests verify `aider_runner` builds the correct CLI args / environment variables and handles subprocess return codes.

### Code Quality & Standards
- [ ] All new and modified Python files pass lint and syntax validation.
- [ ] No remaining references to `longcat-preview` across the codebase configuration.
- [ ] Environment variables and keys are safely accessed without hardcoding secrets.


## Follow-up — 2026-10-23T19:44:56Z

there was an interuption/connection error finish without flaws

## Follow-up — 2026-10-24T17:20:24Z

Fix the AutoBugHunter multi-repo PR creation pipeline and implement an autonomous PR review and comment remediation engine without breaking existing features.

Working directory: c:\antigravity\bughunter
Integrity mode: development

## Requirements

### R1. Multi-Repo Discovery, Push/Fork Resilience & Logging
- In `src/git_manager.py` (`discover_or_load_repos`): When `auto_discover=True`, ensure `gh repo list` queries `bitxwolf` explicitly (`gh repo list bitxwolf --limit 100 --json nameWithOwner,name,isFork,isArchived,createdAt`).
- Ensure `DEFAULT_CURATED_REPOS` ordering has `bitxwolf/BugHunter` as priority 6 (scanned last) and is properly iterated in `main.py` and `src/orchestrator.py` without premature loop exit if an individual repo fails.
- In `push_atomic_branch` & `ensure_fork`: When direct push to `bitxwolf/<repo>` fails due to permission denial (HTTP 403), automatically fork the repo to authenticated user (`arrshh12`), push to `fork`, and open PR using cross-fork `head_spec` `<fork_user>:<branch>`.
- Provide descriptive logging in `bughunter.log` if a repository is skipped due to token permission denials.

### R2. PR Review & Comment Remediation Engine
- Create `src/review_monitor.py` implementing `check_and_remediate_prs()` executed at the beginning of each cycle before opening new PRs.
- Query open bot PRs across target repos (`gh pr list --repo <repo_slug> --author "@me" --state open`).
- Fetch unresolved review comments and pull request reviews from bots (`coderabbitai[bot]`, `code-review-bot`) and human reviewers via GitHub GraphQL API.
- Extract `comment_id`, `thread_id`, `path`, `line`, `diff_hunk`, and comment body.
- For each actionable comment: checkout PR branch, invoke LLM for root-cause analysis and minimal non-breaking patch, verify patch via `src/verifier.py`, commit (`fix(review): address feedback from CodeRabbit on <filename>`), push without force-push (`RULE-GIT-02`).
- Post inline reply: `"Noted and addressed in commit <short_sha>. Verified and resolved."`.
- Resolve review thread via GraphQL mutation `resolveReviewThread(input: {threadId: $threadId})`.
- Persist remediated threads in SQLite database table `review_remediations` for strict idempotency.

### R3. Non-Breaking Safety Protocol & Invariant Enforcement
- Strict zero-regression guarantee: all 779 baseline tests in `pytest tests/` must remain 100% passing.
- Absolute prohibition of `git push --force` (`RULE-GIT-02`).
- Full backward compatibility for CLI arguments (`--once`, `--repo`, `--max-cycles`, `--backup-state`), environment variables, database schemas, and FastAPI endpoints.
- Robust exception isolation: permission denials and GraphQL resolution failures must be logged cleanly and never crash the orchestrator daemon.

## Acceptance Criteria

### Automated Test Verification
- [ ] New unit and integration test suite in `tests/test_review_monitor.py` passes completely.
- [ ] Full existing test suite (`pytest`) passes all 779 tests with 0 regressions.
- [ ] Cross-fork `head_spec` generation and fallback verified in tests.
- [ ] Thread resolution GraphQL call and reply posting verified in tests.
- [ ] Idempotency verified: re-running review remediation skips already addressed threads.

## Follow-up — 2026-10-25T21:01:49Z

Fix the PR review comment analysis, inline reply, and GraphQL thread resolution engine in AutoBugHunter 24/7 (`src/review_monitor.py`) so that review threads across open pull requests on target repositories are reliably fetched, checked out, remediated, committed, fast-forward pushed, replied to, and resolved without breaking existing features or safety invariants.

Working directory: c:\antigravity\bughunter
Integrity mode: development

## Requirements

### R1. PR Branch Fetch & Fast-Forward Push Resilience
- In `src/review_monitor.py` (`remediate_single_thread`), ensure the PR branch is reliably checked out from the exact PR head commit on GitHub using `+refs/pull/<pr_number>/head:<branch_name>` or tracking fork remotes, rather than falling back to an unanchored branch off `main`.
- Properly determine and configure the push target remote (`fork` for cross-repo fork PRs or `origin` for same-repo PRs) so that commits are fast-forward pushes on top of the fetched PR head without requiring `--force` (enforcing `RULE-GIT-02`).
- Pass `repo_slug=repo_slug` explicitly to `push_atomic_branch`.
- Retain complete compatibility with local repos in unit tests (where `origin` does not exist and branches are local).

### R2. Subsystem Wiring & Direct LLM Robustness
- In `main.py` and `src/orchestrator.py`, wire and pass `AiderRunner` to `ReviewMonitor` so that surgical AST/search-replace edits are prioritized for review remediations.
- Ensure `ReviewMonitor` initializes a default `AiderRunner` if one is not supplied.
- In `_run_direct_llm_remediation`, robustly handle LLM outputs (cleanly extract code even if wrapped in markdown code fences or raw blocks), and if code generation fails, abort cleanly with a descriptive status (`LLM_PATCH_FAILED`) before invoking the verifier gate, preventing misleading `"Diff is completely empty"` errors.

### R3. Actionable Thread Detection & Lifecycle Idempotency
- In `fetch_unresolved_review_threads`, robustly detect whether the bot (`arrshh12`) has already replied to the thread with a fix commit. If the bot already replied and no newer feedback exists from reviewers, do not re-patch or duplicate commits; instead, attempt to resolve the thread with `resolve_review_thread(thread_id)` and persist to SQLite.
- Ensure `bot_identity` correctly respects `config.bot_github_user` and authenticated identity.
- Verify `post_inline_reply` and `resolve_review_thread` execute with proper error handling and logging.

### R4. Non-Breaking Invariants & Test Integrity
- All existing tests in `tests/test_review_monitor.py` and the full suite must pass with 0 regressions.
- Absolute prohibition of `git push --force` (`RULE-GIT-02`).
- Absolute prohibition of auto-merging (`RULE-NO-AUTOMERGE`).

## Acceptance Criteria

### Test Verification
- [ ] `pytest tests/test_review_monitor.py` passes 100% (all 19+ tests green).
- [ ] Multi-repo cross-fork PR branch fetch and push verified with simulated and dry-run tests.
- [ ] Failed patch generation cleanly aborts with descriptive error without tripping verifier empty-diff false positives.
- [ ] Idempotency verified: threads where the bot already replied are not re-patched with duplicate commits.
- [ ] No regressions introduced in core orchestrator, git_manager, or database tests.
