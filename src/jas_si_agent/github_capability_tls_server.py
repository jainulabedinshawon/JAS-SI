"""Dedicated mTLS listener for GitHub capability workload routes.

This runtime uses Anycorn because it implements the ASGI TLS extension required
by github_capability_asgi_tls. Uvicorn can require/verify client certificates
but does not expose the peer chain in ASGI scope, so it is not suitable here.
"""
from __future__ import annotations

import importlib
import os
import ssl
from pathlib import Path
from typing import Any


_REQUIRED_FILES = (
    "JAS_SI_CAPABILITY_TLS_SERVER_CERT",
    "JAS_SI_CAPABILITY_TLS_SERVER_KEY",
    "JAS_SI_CAPABILITY_TLS_CLIENT_CA",
)


def _required_file(name: str) -> str:
    raw = os.environ.get(name, "").strip()
    if not raw:
        raise RuntimeError(f"Required TLS setting is missing: {name}")
    path = Path(raw)
    if not path.is_file() or not os.access(path, os.R_OK):
        raise RuntimeError(f"Required TLS file is not readable: {name}")
    return str(path)


def build_config() -> Any:
    """Create a TLS-only Anycorn config with mandatory workload CA validation."""
    # Lazy import keeps the normal Vercel/API runtime independent of this
    # optional dedicated listener dependency.
    from anycorn.config import Config

    paths = {name: _required_file(name) for name in _REQUIRED_FILES}
    host = os.environ.get("JAS_SI_CAPABILITY_TLS_BIND_HOST", "0.0.0.0").strip()
    if not host or any(ch in host for ch in "/\\r\\n"):
        raise RuntimeError("Capability TLS bind host is invalid")
    raw_port = os.environ.get("JAS_SI_CAPABILITY_TLS_BIND_PORT", "8443").strip()
    try:
        port = int(raw_port)
    except ValueError:
        raise RuntimeError("Capability TLS bind port must be an integer") from None
    if not 1 <= port <= 65535:
        raise RuntimeError("Capability TLS bind port is outside 1..65535")

    bind_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    config = Config()
    config.bind = [f"{bind_host}:{port}"]
    config.insecure_bind = []
    config.certfile = paths["JAS_SI_CAPABILITY_TLS_SERVER_CERT"]
    config.keyfile = paths["JAS_SI_CAPABILITY_TLS_SERVER_KEY"]
    config.ca_certs = paths["JAS_SI_CAPABILITY_TLS_CLIENT_CA"]
    config.verify_mode = ssl.CERT_REQUIRED
    config.verify_flags = ssl.VERIFY_X509_STRICT
    config.workers = 1
    config.use_reloader = False
    return config


def load_application() -> Any:
    """Load the configured ASGI app; never accept an arbitrary CLI argument."""
    target = os.environ.get(
        "JAS_SI_CAPABILITY_TLS_ASGI_APP", "jas_si_agent.api:app"
    ).strip()
    module_name, separator, attribute = target.partition(":")
    if not separator or not module_name or not attribute or ":" in attribute:
        raise RuntimeError("Capability TLS ASGI app must use module:attribute form")
    try:
        application = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError):
        raise RuntimeError("Configured capability TLS ASGI app could not be loaded") from None
    if not callable(application):
        raise RuntimeError("Configured capability TLS ASGI app is not callable")
    return application


def main() -> None:
    """Run the isolated TLS listener; no plaintext listener is configured."""
    import anyio
    from anycorn import serve

    config = build_config()
    application = load_application()
    anyio.run(serve, application, config)


if __name__ == "__main__":
    main()
