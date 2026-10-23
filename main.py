"""
Main Application Entrypoint for AutoBugHunter 24/7.
Spawns FastAPI Mission Control in a background daemon thread and Orchestrator on the main thread,
or executes a one-shot cloud scan cycle (--once) for GitHub Actions.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from typing import Any, Optional

import uvicorn

from src.config import Config
from src.database import Database
from src.git_manager import GitManager
from src.key_manager import KeyManager
from src.logger import setup_logger
from src.openhands_runner import OpenHandsRunner
from src.orchestrator import Orchestrator
from src.state_syncer import StateSyncer
from src.static_scanner import StaticScanner
from src.verifier import Verifier
from src.web_server import create_app


def start_web_server(app, host: str, port: int):
    """Run uvicorn ASGI server in background thread."""
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main(args_list: Optional[list[str]] = None):
    parser = argparse.ArgumentParser(description="AutoBugHunter 24/7 // Autonomous Engineering Daemon")
    parser.add_argument("--once", action="store_true", help="Execute cloud scan cycles and exit cleanly without starting web server")
    parser.add_argument("--max-cycles", type=int, default=int(os.getenv("MAX_CYCLES", "7")), help="Max cycles per run in one-shot mode (default: 7)")
    parser.add_argument("--repo", type=str, default=os.getenv("TARGET_REPO", ""), help="Specific repository slug to scan")
    parser.add_argument("--backup-state", action="store_true", help="Snapshot SQLite database and push to state repo, then exit")
    args, _ = parser.parse_known_args(args_list)

    is_run_once = args.once or os.getenv("RUN_ONCE", "").strip().lower() in ("true", "1", "yes")

    print("=" * 60)
    print("  AutoBugHunter 24/7 // Autonomous Engineering Daemon")
    mode_str = "Scheduled Cloud Runner (One-Shot)" if is_run_once else "24/7 Continuous Daemon"
    print(f"  Mode: {mode_str}")
    print("=" * 60)

    # 1. Load configuration
    config = Config.load()
    if args.repo:
        config.target_repos = [args.repo.strip()]

    print(f"[*] Workspace: {config.workspace_dir}")
    print(f"[*] LLM Keys Configured: {len(config.llm_keys)}")
    print(f"[*] Max Open PRs Window: {config.max_open_prs_per_repo}")

    # 2. Setup logger
    py_logger, ring_logger, broadcaster = setup_logger(
        name="autobughunter",
        log_file=config.log_file_path,
        capacity=config.log_ring_buffer_size,
    )
    ring_logger.log("INFO", f"AutoBugHunter initialization started in {mode_str} mode.")

    # 3. State persistence synchronization (Method A)
    state_syncer = StateSyncer(
        db_path=config.db_path,
        state_dir=config.state_dir,
        state_repo=config.state_repo,
        github_token=config.github_token,
        logger=ring_logger,
    )

    if args.backup_state:
        if config.state_repo:
            ring_logger.log("INFO", f"Triggered standalone state backup to {config.state_repo}...")
            ok = state_syncer.backup_state()
            return 0 if ok else 1
        ring_logger.log("WARN", "No STATE_REPO configured for backup.")
        return 0

    if config.state_repo:
        state_syncer.restore_state()

    # 4. Setup database
    database = Database(config.db_path)

    # 5. Setup subsystems
    key_manager = KeyManager(config, database)
    git_manager = GitManager(config.workspace_dir, config.github_token, config.max_open_prs_per_repo, state_repo=config.state_repo)
    git_manager.configure_git_and_gh()

    if not config.target_repos:
        discovered = git_manager.discover_or_load_repos("", auto_discover=config.auto_discover_repos)
        config.target_repos = discovered
        ring_logger.log("INFO", f"Curated catalog: {len(discovered)} active repositories: {', '.join(discovered)}")
    print(f"[*] Monitored Repositories: {len(config.target_repos)}")

    static_scanner = StaticScanner(config.static_scan_timeout_seconds)
    openhands_runner = OpenHandsRunner(config.agent_timeout_seconds)
    verifier = Verifier()

    orchestrator = Orchestrator(
        config=config,
        database=database,
        key_manager=key_manager,
        git_manager=git_manager,
        static_scanner=static_scanner,
        openhands_runner=openhands_runner,
        verifier=verifier,
        logger=ring_logger,
    )

    # 6. One-Shot Mode (for GitHub Actions Cloud Runner)
    if is_run_once:
        max_cycles = max(1, args.max_cycles)
        ring_logger.log("INFO", f"Starting cloud runner scanning across {len(config.target_repos)} repos (up to {max_cycles} cycles)...")
        total_prs_created = 0
        try:
            for cycle_idx in range(1, max_cycles + 1):
                ring_logger.log("INFO", f"--- Cycle {cycle_idx}/{max_cycles} ---")
                results = orchestrator.run_cycle()
                prs_in_cycle = sum(1 for r in results if r.get("outcome") == "PR_CREATED")
                total_prs_created += prs_in_cycle
                active_repos = sum(
                    1 for r in results
                    if r.get("outcome") not in ("SKIPPED_MAX_PRS", "SKIPPED_EXHAUSTED", "CLEAN_EXHAUSTED")
                )
                ring_logger.log("INFO", f"Cycle {cycle_idx} complete: {prs_in_cycle} PRs created. Active repos: {active_repos}.")
                if active_repos == 0:
                    ring_logger.log("INFO", "All target repositories are at max open PR ceiling or clean/exhausted.")
                    break
        except Exception as e:
            ring_logger.log("ERROR", f"Cloud runner cycle failed: {e}")
        finally:
            if config.state_repo:
                ring_logger.log("INFO", f"Saving persistent state snapshot to {config.state_repo}...")
                try:
                    state_syncer.backup_state()
                except Exception as e:
                    ring_logger.log("ERROR", f"Failed to push final state backup: {e}")

        ring_logger.log("INFO", f"Cloud scan finished cleanly. Total PRs created in run: {total_prs_created}.")
        return

    # 7. Daemon Mode: Initialize Web Server & Continuous Loop
    app = create_app(orchestrator, broadcaster)
    web_thread = threading.Thread(
        target=start_web_server,
        args=(app, config.dashboard_host, config.dashboard_port),
        daemon=True,
    )
    web_thread.start()
    ring_logger.log("INFO", f"Mission Control UI running on http://{config.dashboard_host}:{config.dashboard_port}")

    # 8. Signal handling
    def shutdown_handler(signum, frame):
        ring_logger.log("WARN", "Shutdown signal received. Stopping daemon loop cleanly...")
        orchestrator.stop()
        if config.state_repo:
            try:
                state_syncer.backup_state()
            except Exception as e:
                ring_logger.log("ERROR", f"Failed to backup state on shutdown: {e}")
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)
    except Exception:
        pass

    # 9. Main Continuous Orchestrator Loop
    ring_logger.log("INFO", "Starting 24/7 continuous autonomous scanning cycle...")
    try:
        while not orchestrator.stop_requested:
            try:
                orchestrator.run_cycle()
                if config.state_repo:
                    state_syncer.backup_state()
            except Exception as e:
                ring_logger.log("ERROR", f"Unhandled exception in daemon scan cycle: {e}")
            time.sleep(config.scan_cooldown_seconds)
    except KeyboardInterrupt:
        shutdown_handler(None, None)


if __name__ == "__main__":
    main()
