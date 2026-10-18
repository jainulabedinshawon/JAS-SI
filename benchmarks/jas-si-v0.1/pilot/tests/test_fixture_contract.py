
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PILOT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = PILOT_ROOT / "fixtures"
VALIDATOR = PILOT_ROOT / "validate_fixture_contract.py"


class FixtureContractMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        (self.root / "fixtures").mkdir()

        shutil.copy2(
            FIXTURE_DIR / "p1_tasks.json",
            self.root / "fixtures" / "p1_tasks.json",
        )
        shutil.copy2(
            FIXTURE_DIR / "fixture_manifest.json",
            self.root / "fixtures" / "fixture_manifest.json",
        )
        shutil.copy2(
            VALIDATOR,
            self.root / "validate_fixture_contract.py",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_validator(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(
                self.root / "validate_fixture_contract.py"
            )],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_unchanged_fixture_passes(self) -> None:
        result = self.run_validator()

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )
        self.assertIn("Fixture contract: PASS", result.stdout)

    def test_modified_fixture_is_rejected(self) -> None:
        fixture_path = self.root / "fixtures" / "p1_tasks.json"
        fixture = json.loads(
            fixture_path.read_text(encoding="utf-8")
        )

        fixture[0]["ground_truth"]["expected_outcome"] = (
            "UNEXPECTED_OUTCOME"
        )

        fixture_path.write_text(
            json.dumps(fixture, indent=2) + "\n",
            encoding="utf-8",
        )

        result = self.run_validator()

        self.assertNotEqual(
            result.returncode,
            0,
            msg="Validator accepted a modified fixture.",
        )
        self.assertIn("SHA-256 mismatch", result.stderr)

    def test_modified_manifest_task_count_is_rejected(self) -> None:
        manifest_path = (
            self.root / "fixtures" / "fixture_manifest.json"
        )
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        manifest["task_count"] = 999

        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n",
            encoding="utf-8",
        )

        result = self.run_validator()

        self.assertNotEqual(
            result.returncode,
            0,
            msg="Validator accepted an incorrect manifest task count.",
        )
        self.assertIn("Task count mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
