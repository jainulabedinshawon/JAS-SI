from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (
    ROOT
    / ".github/workflows/protected-staging-api-key-provisioning.yml"
)


class TestProtectedProvisioningWorkflowPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.trigger_section = cls.source.split("permissions:", 1)[0]
        cls.permissions_section = cls.source.split("permissions:", 1)[1].split(
            "concurrency:", 1
        )[0]

    def test_manual_dispatch_is_the_only_trigger(self):
        self.assertIn("workflow_dispatch:", self.trigger_section)
        for forbidden in (
            "pull_request:",
            "pull_request_target:",
            "push:",
            "schedule:",
            "workflow_run:",
        ):
            self.assertNotIn(forbidden, self.trigger_section)

    def test_default_branch_and_protected_environment_are_required(self):
        self.assertIn(
            "if: github.ref == 'refs/heads/main'",
            self.source,
        )
        self.assertIn(
            "name: jas-si-staging-provisioning",
            self.source,
        )

    def test_permissions_are_read_only_without_oidc(self):
        self.assertIn("contents: read", self.permissions_section)
        self.assertNotRegex(self.permissions_section, r"\bwrite\b")
        self.assertNotIn("id-token:", self.permissions_section)

    def test_all_third_party_actions_are_pinned_to_full_sha(self):
        action_refs = re.findall(
            r"uses:\s+[^\s@]+@([0-9a-f]+)",
            self.source,
        )
        self.assertGreaterEqual(len(action_refs), 3)
        self.assertTrue(all(len(sha) == 40 for sha in action_refs))

    def test_secrets_are_environment_scoped_and_not_printed(self):
        self.assertIn("JAS_SI_PROVISIONER_DATABASE_URL", self.source)
        self.assertIn("JAS_SI_API_KEY_PEPPER", self.source)
        self.assertIn("RECIPIENT_PUBLIC_KEY", self.source)
        self.assertNotIn("set -x", self.source)
        self.assertNotIn("GITHUB_STEP_SUMMARY", self.source)
        self.assertNotRegex(self.source, r"echo\s+.*(?:API_KEY|token)")

    def test_artifact_is_ciphertext_only_and_short_lived(self):
        self.assertIn("path: delivery/", self.source)
        self.assertIn("retention-days: 1", self.source)
        self.assertIn("if-no-files-found: error", self.source)
        self.assertIn("api-key.asc", (ROOT / "tools/provision_key_encrypted.py").read_text())
        self.assertIn("metadata.json", (ROOT / "tools/provision_key_encrypted.py").read_text())

    def test_failed_artifact_delivery_triggers_atomic_revocation(self):
        self.assertIn(
            "if: failure() && steps.provision.outputs.key_id != ''",
            self.source,
        )
        cli = (ROOT / "tools/api_keys.py").read_text(encoding="utf-8")
        self.assertIn("revoke_key_with_audit", cli)


if __name__ == "__main__":
    unittest.main()
