"""HTTP-boundary tests for the GitHub OAuth browser handoff."""
from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace

from fastapi.testclient import TestClient

from jas_si_agent import api
from jas_si_agent.customer_identity import CustomerAccount
from jas_si_agent.github_oauth_service import ConsumedGitHubOAuthAttempt


class FakeCustomerStore:
    def __init__(self, account):
        self.account = account

    def authenticate_session(self, token):
        return self.account if token == "S" * 43 else None


class FakeOAuthService:
    def __init__(self, account):
        self.account = account
        self.consumed = None

    def begin(self, *, session_token, account):
        assert session_token == "S" * 43
        assert account == self.account
        return "https://github.com/login/oauth/authorize?client_id=Iv1.example&state=" + "A" * 43

    def consume_callback(self, *, session_token, state, authorization_code):
        assert session_token == "S" * 43
        assert state == "A" * 43
        assert authorization_code == "github-authorization-code"
        self.consumed = ConsumedGitHubOAuthAttempt(
            attempt_id=uuid.uuid4(), tenant_id=self.account.tenant_id,
            account_id=self.account.account_id, code_verifier="V" * 43,
        )
        return self.consumed


class FakeProvider:
    def exchange_code(self, *, code, code_verifier, redirect_uri):
        assert code == "github-authorization-code"
        assert code_verifier == "V" * 43
        assert redirect_uri == "https://jas-si.example.test/v1/github/oauth/callback"
        return SimpleNamespace(access_token="gho_" + "T" * 36)

    def authenticated_user(self, token):
        return SimpleNamespace(github_user_id=12345, login="jas-user")


class FakeOwnershipVerifier:
    def verify(self, *, user_access_token, installation_id):
        assert user_access_token == "gho_" + "T" * 36
        assert installation_id == 98765
        return SimpleNamespace(
            user=SimpleNamespace(user_id=12345, login="jas-user"),
            installation_id=98765, app_id=4567, account_id=7654,
            account_login="jas-org", account_type="Organization",
        )


class GitHubOAuthApiTests(unittest.TestCase):
    def setUp(self):
        self.account = CustomerAccount(
            account_id=uuid.uuid4(), tenant_id=uuid.uuid4(),
            email="customer@example.test", organization_name="Customer Org",
            status="active",
        )
        self.old_settings = api.settings
        self.settings = SimpleNamespace(
            environment="test",
            customer_database_url="postgresql://not-used",
            customer_token_pepper=b"P" * 32,
            github_oauth_client_id="Iv1.example",
            github_oauth_client_secret="secret-" + "S" * 32,
            github_oauth_redirect_uri="https://jas-si.example.test/v1/github/oauth/callback",
            github_oauth_encryption_keyring={"test-v1": b"K" * 32},
            github_oauth_active_key_version="test-v1",
            github_app_id=4567,
        )
        api.settings = self.settings
        self.state_names = (
            "customer_identity_store", "github_oauth_service",
            "github_oauth_provider", "github_installation_ownership_verifier",
        )
        self.old_state = {name: getattr(api.app.state, name, None) for name in self.state_names}
        api.app.state.customer_identity_store = FakeCustomerStore(self.account)
        api.app.state.github_oauth_service = FakeOAuthService(self.account)
        api.app.state.github_oauth_provider = FakeProvider()
        api.app.state.github_installation_ownership_verifier = FakeOwnershipVerifier()
        self.old_identity_helper = api._get_customer_identity_store
        self.old_oauth_components = api._get_github_oauth_components
        api._get_customer_identity_store = lambda request: api.app.state.customer_identity_store
        api._get_github_oauth_components = lambda request: (
            api.app.state.github_oauth_service,
            api.app.state.github_oauth_provider,
            api.app.state.github_installation_ownership_verifier,
        )
        self.client = TestClient(api.app, base_url="https://jas-si.example.test")
        self.client.cookies.set("jassi_customer_session", "S" * 43, path="/")
        self.client.cookies.set("jassi_customer_csrf", "C" * 43, path="/")

    def tearDown(self):
        self.client.close()
        api.settings = self.old_settings
        api._get_customer_identity_store = self.old_identity_helper
        api._get_github_oauth_components = self.old_oauth_components
        for name, value in self.old_state.items():
            if value is None:
                try:
                    delattr(api.app.state, name)
                except AttributeError:
                    pass
            else:
                setattr(api.app.state, name, value)

    def test_start_requires_csrf_and_sets_short_lived_lax_state_cookie(self):
        denied = self.client.post("/v1/customer/github/oauth/start")
        self.assertEqual(denied.status_code, 403)
        response = self.client.post(
            "/v1/customer/github/oauth/start",
            headers={"X-JAS-SI-CSRF": "C" * 43},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["expires_in"], 300)
        cookie = response.headers["set-cookie"].lower()
        self.assertIn("jassi_github_oauth_state=", cookie)
        self.assertIn("httponly", cookie)
        self.assertIn("samesite=lax", cookie)
        self.assertIn("path=/v1/github/oauth/callback", cookie)
        self.assertIn("max-age=300", cookie)

    def test_callback_page_validates_state_and_hides_code_from_history(self):
        started = self.client.post(
            "/v1/customer/github/oauth/start",
            headers={"X-JAS-SI-CSRF": "C" * 43},
        )
        self.assertEqual(started.status_code, 200)
        response = self.client.get(
            "/v1/github/oauth/callback?state=" + "A" * 43
            + "&code=github-authorization-code&installation_id=98765"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("history.replaceState", response.text)
        self.assertIn("nonce-", response.headers["content-security-policy"])
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")
        self.assertIn("no-store", response.headers["cache-control"])

    def test_callback_page_rejects_duplicate_state(self):
        started = self.client.post(
            "/v1/customer/github/oauth/start",
            headers={"X-JAS-SI-CSRF": "C" * 43},
        )
        self.assertEqual(started.status_code, 200)
        response = self.client.get(
            "/v1/github/oauth/callback?state=" + "A" * 43
            + "&state=" + "A" * 43
            + "&code=github-authorization-code&installation_id=98765"
        )
        self.assertEqual(response.status_code, 400)

    def test_callback_completes_user_and_installation_ownership_but_not_activation(self):
        started = self.client.post(
            "/v1/customer/github/oauth/start",
            headers={"X-JAS-SI-CSRF": "C" * 43},
        )
        self.assertEqual(started.status_code, 200)
        page = self.client.get(
            "/v1/github/oauth/callback?state=" + "A" * 43
            + "&code=github-authorization-code&installation_id=98765"
        )
        self.assertEqual(page.status_code, 200)
        response = self.client.post(
            "/v1/github/oauth/callback/complete",
            headers={"X-JAS-SI-CSRF": "C" * 43},
            json={
                "state": "A" * 43,
                "code": "github-authorization-code",
                "installation_id": 98765,
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ownership_proof_verified_not_persisted")
        self.assertTrue(body["reconciliation_required"])
        self.assertEqual(body["persistence"], "not_recorded")
        self.assertEqual(body["activation"], "not_performed")
        self.assertEqual(body["github_user"]["login"], "jas-user")
        self.assertEqual(body["installation"]["installation_id"], 98765)
        self.assertIn("jassi_github_oauth_state=", response.headers.get("set-cookie", ""))

    def test_callback_complete_rejects_wrong_state_cookie(self):
        response = self.client.post(
            "/v1/github/oauth/callback/complete",
            headers={"X-JAS-SI-CSRF": "C" * 43},
            json={
                "state": "A" * 43,
                "code": "github-authorization-code",
                "installation_id": 98765,
            },
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
