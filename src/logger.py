"""
Ring-Buffer Logger, Rotating File Handler, and WebSocket Live Broadcaster for AutoBugHunter 24/7.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import re
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable, Optional


def redact_secrets(text: str) -> str:
    """Scrub sensitive credentials, tokens, API keys, and private keys from text."""
    if not text or not isinstance(text, str):
        return text

    scrubbed = text

    # 1. Private Keys (multiline and single-line)
    scrubbed = re.sub(
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
        "[REDACTED]",
        scrubbed
    )
    scrubbed = re.sub(
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*",
        "[REDACTED]",
        scrubbed
    )

    # 2. GitHub PATs and OAuth tokens
    scrubbed = re.sub(r"ghp_[A-Za-z0-9_]{36,}", "[REDACTED]", scrubbed)
    scrubbed = re.sub(r"github_pat_[A-Za-z0-9_]{82,}", "[REDACTED]", scrubbed)
    scrubbed = re.sub(r"gh[ours]_[A-Za-z0-9_]{36,}", "[REDACTED]", scrubbed)

    # 3. LLM API Keys
    scrubbed = re.sub(r"sk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}", "[REDACTED]", scrubbed)
    scrubbed = re.sub(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "[REDACTED]", scrubbed)
    scrubbed = re.sub(r"AIza[0-9A-Za-z\-_]{30,45}", "[REDACTED]", scrubbed)

    # 4. Bearer & Basic auth tokens
    scrubbed = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}", "Bearer [REDACTED]", scrubbed)
    scrubbed = re.sub(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{20,}", "Basic [REDACTED]", scrubbed)

    # 5. Generic credential assignments
    scrubbed = re.sub(
        r"""(?i)\b(api[_-]?key|secret|token|password|auth_token)\s*([:=])\s*(['"]?)([A-Za-z0-9_\-+/=.@$!%*?&#~^]{20,})\3""",
        r"\1\2\3[REDACTED]\3",
        scrubbed
    )

    return scrubbed


class SanitizingFormatter(logging.Formatter):
    """Logging formatter that automatically redacts secrets from log output."""

    def format(self, record: logging.LogRecord) -> str:
        formatted = super().format(record)
        return redact_secrets(formatted)


class WebSocketBroadcaster:
    """Thread-safe WebSocket broadcaster for live streaming log messages to dashboard clients."""

    def __init__(self):
        self.connections: set[Any] = set()
        self.loop: Optional[asyncio.AbstractEventLoop] = None

    def register_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the running asyncio event loop (e.g. from FastAPI/uvicorn)."""
        self.loop = loop

    async def connect(self, websocket: Any, initial_logs: Optional[list[str]] = None) -> None:
        """Accept WebSocket connection and replay recent log lines."""
        await websocket.accept()
        self.connections.add(websocket)
        if initial_logs:
            for line in initial_logs:
                try:
                    await websocket.send_text(line)
                except Exception:
                    break

    def disconnect(self, websocket: Any) -> None:
        """Remove disconnected client from active subscriber pool."""
        self.connections.discard(websocket)

    def broadcast_sync(self, line: str) -> None:
        """Bridge synchronous log calls to the asynchronous event loop."""
        if not self.connections:
            return
        line = redact_secrets(line)
        if self.loop and self.loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(self.broadcast(line), self.loop)
            except Exception:
                pass

    async def broadcast(self, line: str) -> None:
        """Broadcast message to all connected clients, removing dead sockets."""
        if not self.connections:
            return
        line = redact_secrets(line)
        dead = []
        for ws in list(self.connections):
            try:
                await ws.send_text(line)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.connections.discard(ws)


class RingBufferLogHandler(logging.Handler):
    """Logging handler storing messages in a memory ring buffer and broadcasting over WebSocket."""

    def __init__(self, buffer: collections.deque, broadcaster: Optional[WebSocketBroadcaster] = None):
        super().__init__()
        self.buffer = buffer
        self.broadcaster = broadcaster

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = redact_secrets(self.format(record))
            self.buffer.append(line)
            if self.broadcaster:
                self.broadcaster.broadcast_sync(line)
        except Exception:
            self.handleError(record)


class RingBufferLogger:
    """Fixed-capacity ring buffer logger with subscriber callbacks and optional file persistence."""

    def __init__(self, capacity: int = 500, log_file: Optional[Path] = None, broadcaster: Optional[WebSocketBroadcaster] = None):
        self.capacity = capacity
        self.buffer: collections.deque = collections.deque(maxlen=capacity)
        self.subscribers: list[Callable[[str], None]] = []
        self.broadcaster: WebSocketBroadcaster = broadcaster or WebSocketBroadcaster()
        self.log_file = Path(log_file).resolve() if log_file else None
        self._file_handler: Optional[RotatingFileHandler] = None
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handler = RotatingFileHandler(
                str(self.log_file),
                maxBytes=10 * 1024 * 1024,
                backupCount=5,
                encoding="utf-8"
            )
            self._file_handler.setFormatter(SanitizingFormatter("%(message)s"))

    def add_subscriber(self, callback: Callable[[str], None]) -> None:
        """Register subscriber callback function."""
        self.subscribers.append(callback)

    def log(self, level: str, message: str) -> str:
        """Log message with timestamp prefix, append to buffer, write to disk, and broadcast."""
        sanitized_msg = redact_secrets(message)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        entry = redact_secrets(f"[{ts}] [{level.upper()}] {sanitized_msg}")
        self.buffer.append(entry)

        if self._file_handler:
            try:
                record = logging.LogRecord(
                    name="ring_logger",
                    level=getattr(logging, level.upper(), logging.INFO),
                    pathname="",
                    lineno=0,
                    msg=entry,
                    args=(),
                    exc_info=None
                )
                self._file_handler.emit(record)
            except Exception:
                pass

        for sub in list(self.subscribers):
            try:
                sub(entry)
            except Exception:
                pass

        self.broadcaster.broadcast_sync(entry)
        return entry

    def get_recent_logs(self, count: int = 50) -> list[str]:
        """Return the most recent count entries from the in-memory ring buffer."""
        return list(self.buffer)[-count:]

    def get_recent(self, count: int = 50) -> list[str]:
        """Alias for get_recent_logs for interface compatibility."""
        return self.get_recent_logs(count)

    def close(self) -> None:
        """Close rotating file handler if open."""
        if self._file_handler:
            try:
                self._file_handler.close()
            except Exception:
                pass


def setup_logger(
    name: str = "autobughunter",
    log_file: Optional[Path] = None,
    capacity: int = 500,
    broadcaster: Optional[WebSocketBroadcaster] = None,
) -> tuple[logging.Logger, RingBufferLogger, WebSocketBroadcaster]:
    """Configure system logger with console, rotating file, ring buffer, and WebSocket broadcast."""
    ws_broadcaster = broadcaster or WebSocketBroadcaster()
    ring_logger = RingBufferLogger(capacity=capacity, log_file=log_file, broadcaster=ws_broadcaster)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = SanitizingFormatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Clear existing handlers
    logger.handlers.clear()

    # 1. Ring buffer handler
    rb_handler = RingBufferLogHandler(ring_logger.buffer, ws_broadcaster)
    rb_handler.setFormatter(formatter)
    logger.addHandler(rb_handler)

    # 2. Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 3. Rotating file handler: reuse ring_logger._file_handler to prevent duplicate file locks on Windows
    if ring_logger._file_handler:
        logger.addHandler(ring_logger._file_handler)

    return logger, ring_logger, ws_broadcaster
