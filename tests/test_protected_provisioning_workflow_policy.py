from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/protected-staging-api-key-provisioning.yml"


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

    def test_preview_branch_and_protected_environment_are_required(self):
        self.assertIn("github.event_name == 'workflow_dispatch'", self.source)
        self.assertIn("github.ref == 'refs/heads/feat/developer-console-landing-v0.1'", self.source)
        self.assertIn("name: jas-si-staging-provisioning", self.source)
        self.assertIn("JAS_SI_PREVIEW_BASE_URL", self.source)

    def test_permissions_are_read_only_without_oidc(self):
        self.assertIn("contents: read", self.permissions_section)
        self.assertNotRegex(self.permissions_section, r"\bwrite\b")
        self.assertNotIn("id-token:", self.permissions_section)

    def test_all_third_party_actions_are_pinned_to_full_sha(self):
        action_refs = re.findall(r"uses:\s+[^\s@]+@([0-9a-f]+)", self.source)
        self.assertEqual(len(action_refs), 2)
        self.assertTrue(all(len(sha) == 40 for sha in action_refs))

    def test_protected_secrets_are_only_passed_to_smoke_test_step(self):
        self.assertIn("JAS_SI_PROVISIONER_DATABASE_URL", self.source)
        self.assertIn("JAS_SI_API_KEY_PEPPER", self.source)
        self.assertIn("python tools/staging_api_smoke_test.py", self.source)
        self.assertNotIn("RECIPIENT_PUBLIC_KEY", self.source)
        self.assertNotIn("GITHUB_STEP_SUMMARY", self.source)
        self.assertNotRegex(self.source, r"echo\s+.*(?:API_KEY|token)")

    def test_no_raw_key_artifact_or_key_output_exists(self):
        self.assertNotIn("upload-artifact", self.source)
        self.assertNotIn("GITHUB_OUTPUT", self.source)
        self.assertNotIn("api-key.asc", self.source)

    def test_cancellation_and_runtime_cleanup_are_documented_in_script(self):
        script = (ROOT / "tools/staging_api_smoke_test.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("finally:", script)
        self.assertIn("revoke_key_with_audit", script)
        self.assertIn("timedelta(minutes=30)", script)
        self.assertNotIn("print(issued.token)", script)
        self.assertIn('if path == "/v1/verify":', script)
        self.assertIn('"claimed_success": True', script)
        cleanup = (ROOT / "tools/revoke_staging_key_for_run.py").read_text(encoding="utf-8")
        self.assertIn("revoke_key_with_audit", cleanup)
        self.assertIn("github-actions:{run_id}", cleanup)
        self.assertIn("if: always()", self.source)


if __name__ == "__main__":
    unittest.main()
