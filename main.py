"""Vercel entrypoint for the JAS-SI FastAPI application."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = PROJECT_ROOT / "src"

if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from jas_si_agent.api import app  # noqa: E402
