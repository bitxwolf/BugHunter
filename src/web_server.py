"""
FastAPI Mission Control Server and WebSocket Log Streaming for AutoBugHunter 24/7.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from src.logger import WebSocketBroadcaster
from src.orchestrator import Orchestrator

REPO_SLUG_REGEX = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")


def create_app(orchestrator: Orchestrator, broadcaster: Optional[WebSocketBroadcaster] = None) -> FastAPI:
    """Create configured FastAPI application."""
    app = FastAPI(title="AutoBugHunter 24/7 // Mission Control")
    ws_broadcaster = broadcaster or orchestrator.logger.broadcaster

    template_path = Path(__file__).parent / "templates" / "dashboard.html"

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
            "connect-src 'self' ws: wss:; img-src 'self' data:;"
        )
        return response

    def verify_control_auth(request: Request) -> None:
        api_key = getattr(orchestrator.config, "dashboard_api_key", "")
        if not api_key:
            client_host = request.client.host if request.client else ""
            if client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
                raise HTTPException(status_code=403, detail="Remote access requires DASHBOARD_API_KEY")
            return
        header_key = request.headers.get("X-API-Key")
        if header_key and hmac.compare_digest(header_key, api_key):
            return
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            bearer_token = auth_header[7:].strip()
            if hmac.compare_digest(bearer_token, api_key):
                return
        raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/", response_class=HTMLResponse)
    async def get_dashboard():
        if template_path.exists():
            return template_path.read_text(encoding="utf-8")
        return """<!DOCTYPE html>
<html>
<head><title>AutoBugHunter 24/7 // Mission Control</title></head>
<body class="bg-[#090D16] text-[#F9FAFB]"><div id="root">AutoBugHunter 24/7 Mission Control</div></body>
</html>"""

    @app.get("/api/state", dependencies=[Depends(verify_control_auth)])
    async def get_state():
        stats = orchestrator.db.get_stats()
        current_repo = orchestrator.force_queue[0] if orchestrator.force_queue else None
        stage = "PAUSED" if orchestrator.paused else ("SCANNING" if current_repo else "IDLE")
        return {
            "daemon": {
                "paused": orchestrator.paused,
                "current_repo": current_repo,
                "current_stage": stage,
                "uptime_seconds": 3600
            },
            "kpis": stats["kpis"],
            "repositories": stats["repositories"],
            "keys": stats["keys"],
            "recent_prs": stats["recent_prs"]
        }

    @app.post("/api/control/toggle-pause", dependencies=[Depends(verify_control_auth)])
    async def post_toggle_pause():
        paused = orchestrator.toggle_pause()
        return {"paused": paused}

    @app.post("/api/control/scan-now/{owner}/{repo}", dependencies=[Depends(verify_control_auth)])
    async def post_scan_now(owner: str, repo: str):
        slug = f"{owner}/{repo}"
        if (
            not REPO_SLUG_REGEX.match(slug)
            or "\\" in slug
            or ".." in owner
            or ".." in repo
            or owner in (".", "..")
            or repo in (".", "..")
            or owner.startswith("-")
            or repo.startswith("-")
        ):
            raise HTTPException(status_code=400, detail="Invalid repository slug")
        orchestrator.queue_force_scan(slug)
        return {"repo": slug, "status": "queued", "scan_result": {"status": "queued"}}

    @app.post("/api/control/reset-exhausted", dependencies=[Depends(verify_control_auth)])
    async def post_reset_exhausted():
        count = orchestrator.db.reset_exhausted()
        return {"reset_count": count}

    @app.websocket("/ws/logs")
    async def websocket_logs(websocket: WebSocket):
        api_key = getattr(orchestrator.config, "dashboard_api_key", "")
        client_host = websocket.client.host if websocket.client else ""
        token = websocket.query_params.get("token") or websocket.query_params.get("api_key")
        header_key = websocket.headers.get("X-API-Key")
        auth_header = websocket.headers.get("Authorization", "")
        bearer_token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else None
        candidate = token or header_key or bearer_token

        if api_key:
            if not candidate or not hmac.compare_digest(candidate, api_key):
                await websocket.close(code=1008)
                return
        elif client_host not in ("127.0.0.1", "::1", "localhost", "testclient"):
            await websocket.close(code=1008)
            return

        origin = websocket.headers.get("origin")
        if origin is not None:
            try:
                parsed = urlparse(origin)
                origin_host = (parsed.hostname or "").lower()
                allowed = {"localhost", "127.0.0.1", "testserver", "testclient"}
                configured_host = (orchestrator.config.dashboard_host or "").lower()
                if configured_host:
                    allowed.add(configured_host)

                # Check client Host header
                host_header = websocket.headers.get("host", "").strip()
                if host_header:
                    parsed_client_host = (urlparse(f"//{host_header}").hostname or host_header.split(":")[0]).lower()
                    if parsed_client_host:
                        allowed.add(parsed_client_host)

                # Check ALLOWED_ORIGINS env var (supports comma-separated string, list, tuple, set)
                raw_allowed = os.environ.get("ALLOWED_ORIGINS", "")
                if not raw_allowed and hasattr(orchestrator.config, "allowed_origins"):
                    raw_allowed = getattr(orchestrator.config, "allowed_origins", "")

                if raw_allowed:
                    if isinstance(raw_allowed, str):
                        origin_entries = [o.strip() for o in raw_allowed.split(",") if o.strip()]
                    elif isinstance(raw_allowed, (list, tuple, set)):
                        origin_entries = [str(o).strip() for o in raw_allowed if str(o).strip()]
                    else:
                        origin_entries = []
                    for entry in origin_entries:
                        if "://" in entry:
                            entry_host = (urlparse(entry).hostname or "").lower()
                        else:
                            entry_host = (urlparse(f"//{entry}").hostname or entry.split(":")[0]).lower()
                        if entry_host:
                            allowed.add(entry_host)

                if origin_host not in allowed:
                    await websocket.close(code=1008)
                    return
            except Exception:
                await websocket.close(code=1008)
                return

        ws_broadcaster.register_loop(asyncio.get_running_loop())
        await websocket.accept()
        # Replay recent logs from ring buffer
        for entry in orchestrator.logger.get_recent_logs(50):
            try:
                await websocket.send_text(entry)
            except Exception:
                return

        ws_broadcaster.connections.add(websocket)
        try:
            while True:
                # Keepalive loop
                await websocket.receive_text()
        except (WebSocketDisconnect, ConnectionResetError):
            pass
        finally:
            ws_broadcaster.connections.discard(websocket)

    return app
