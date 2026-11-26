"""Guard direct cryptography pins across all maintained dependency manifests."""
from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _one(pattern: str, content: str, label: str) -> str:
    matches = re.findall(pattern, content, flags=re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f"expected one cryptography pin in {label}, found {len(matches)}")
    return matches[0]


class DependencyManifestConsistencyTests(unittest.TestCase):
    def test_cryptography_pin_matches_all_manifests(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        requirements_in = (ROOT / "requirements.in").read_text(encoding="utf-8")
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        lock = (ROOT / "requirements.lock.txt").read_text(encoding="utf-8")

        versions = {
            "pyproject.toml": _one(r'"cryptography==([^";]+)"', pyproject, "pyproject.toml"),
            "requirements.in": _one(r"^cryptography==([^\s;]+)$", requirements_in, "requirements.in"),
            "requirements.txt": _one(r"^cryptography==([^\s;]+)$", requirements, "requirements.txt"),
            "requirements.lock.txt": _one(r"^cryptography==([^\s;]+)", lock, "requirements.lock.txt"),
        }
        self.assertEqual(
            len(set(versions.values())),
            1,
            "cryptography must resolve to the same exact version in every manifest: "
            + repr(versions),
        )


if __name__ == "__main__":
    unittest.main()
