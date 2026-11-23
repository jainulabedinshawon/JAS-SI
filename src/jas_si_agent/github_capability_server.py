"""Dedicated mTLS Anycorn entrypoint for the isolated GitHub capability Broker.

The public API remains on Uvicorn. This process is a separate private service and
requires an explicit Staging preview configuration plus mounted TLS materials.
"""
from __future__ import annotations

import os
import ssl
from pathlib import Path
from typing import Mapping

try:
    import anyio
    from anycorn import Config, serve
except ModuleNotFoundError as exc:
    if exc.name not in {"anycorn", "anyio"}:
        raise
    anyio = None
    Config = None
    serve = None

ANYCORN_AVAILABLE = Config is not None and serve is not None and anyio is not None

from jas_si_agent.config import Settings
from jas_si_agent.github_capability_runtime import app


def build_server_config(
    *,
    environ: Mapping[str, str] | None = None,
    active_settings: Settings | None = None,
) -> Config:
    """Build a fail-closed mTLS server configuration from mounted secret files."""
    if Config is None:
        raise RuntimeError("The Broker ASGI runtime dependency is not installed")
    env = os.environ if environ is None else environ
    configured = active_settings or Settings.from_env()

    if (
        not configured.github_capability_broker_enabled
        or str(configured.environment).casefold() != "preview"
        or not configured.github_capability_broker_database_url
        or configured.github_capability_workload_identities is None
    ):
        raise RuntimeError("Staging Broker authorization and identity configuration is required")

    required_paths = {
        "certfile": "JAS_SI_GITHUB_BROKER_TLS_CERT_PATH",
        "keyfile": "JAS_SI_GITHUB_BROKER_TLS_KEY_PATH",
        "ca_certs": "JAS_SI_GITHUB_BROKER_CLIENT_CA_PATH",
    }
    paths: dict[str, str] = {}
    for config_key, env_key in required_paths.items():
        value = env.get(env_key, "")
        if not isinstance(value, str) or not value.strip() or not Path(value).is_file():
            raise RuntimeError(f"Required Broker TLS file is unavailable: {env_key}")
        paths[config_key] = value

    host = env.get("JAS_SI_GITHUB_BROKER_BIND_HOST", "0.0.0.0")
    if not isinstance(host, str) or not host.strip() or any(ch.isspace() for ch in host):
        raise RuntimeError("Broker bind host is invalid")
    try:
        port = int(env.get("JAS_SI_GITHUB_BROKER_PORT", "8787"))
    except (TypeError, ValueError):
        raise RuntimeError("Broker port is invalid") from None
    if not 1 <= port <= 65535:
        raise RuntimeError("Broker port is invalid")

    config = Config()
    config.bind = [f"{host}:{port}"]
    config.certfile = paths["certfile"]
    config.keyfile = paths["keyfile"]
    config.ca_certs = paths["ca_certs"]
    config.verify_mode = ssl.CERT_REQUIRED
    config.alpn_protocols = ["http/1.1"]
    config.workers = 1
    config.daemon = False
    config.accesslog = None
    config.errorlog = "-"
    return config


def main() -> None:
    """Start the private Broker with mandatory client-certificate validation."""
    if anyio is None or serve is None:
        raise RuntimeError("The Broker ASGI runtime dependency is not installed")
    config = build_server_config()
    anyio.run(serve, app, config)


if __name__ == "__main__":
    main()
