"""Local liveness/readiness endpoints for long-running agent host processes."""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class AgentHostHealthState:
    """Thread-safe readiness state based on successful recent polling cycles."""

    def __init__(self, *, max_staleness_seconds: float = 30.0) -> None:
        if not 1.0 <= max_staleness_seconds <= 300.0:
            raise ValueError("max_staleness_seconds must be between 1 and 300")
        self._max_staleness = float(max_staleness_seconds)
        self._lock = threading.Lock()
        self._last_success: float | None = None
        self._last_failure: float | None = None

    def mark_success(self) -> None:
        with self._lock:
            self._last_success = time.monotonic()
            self._last_failure = None

    def mark_failure(self) -> None:
        with self._lock:
            self._last_failure = time.monotonic()

    def is_ready(self) -> bool:
        with self._lock:
            if self._last_success is None or self._last_failure is not None:
                return False
            return time.monotonic() - self._last_success <= self._max_staleness


class AgentHostHealthServer:
    """Serve unauthenticated, non-sensitive local health endpoints."""

    def __init__(
        self,
        state: AgentHostHealthState,
        *,
        host: str = "0.0.0.0",
        port: int = 8000,
    ) -> None:
        if not 1 <= port <= 65535:
            raise ValueError("health port must be between 1 and 65535")
        self._state = state
        state_ref = state

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    status, payload = 200, {"status": "ok"}
                elif self.path == "/ready":
                    ready = state_ref.is_ready()
                    status = 200 if ready else 503
                    payload = {"status": "ready" if ready else "not_ready"}
                else:
                    status, payload = 404, {"status": "not_found"}
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args) -> None:
                # Do not emit request data from a public-facing HTTP handler.
                return

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="jas-si-agent-health",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        if self._thread.is_alive():
            self._server.shutdown()
            self._thread.join(timeout=3.0)
        self._server.server_close()


__all__ = ["AgentHostHealthState", "AgentHostHealthServer"]
