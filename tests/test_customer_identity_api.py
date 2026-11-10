"""HTTP tests for the standalone customer onboarding and session flow."""
from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from jas_si_agent import api
from jas_si_agent.customer_identity import CustomerAccount, CustomerLink, CustomerSession


class FakeCustomerIdentityStore:
    def __init__(self):
        self.account = CustomerAccount(
            uuid.uuid4(), uuid.uuid4(), "user@example.test",
            "Example Organization", "active",
        )
        self.link = CustomerLink(
            self.account.account_id, self.account.email, "verify_email",
            "v" * 48, datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.login_link = CustomerLink(
            self.account.account_id, self.account.email, "login",
            "l" * 48, datetime.now(timezone.utc) + timedelta(minutes=15),
        )
        self.session = CustomerSession(
            self.account, "s" * 48,
            datetime.now(timezone.utc) + timedelta(days=7),
        )
        self.unknown_email = False
        self.revoked = False

    def register(self, email, organization_name):
        return self.link

    def issue_verification_link(self, email):
        return self.link

    def issue_login_link(self, email):
        return None if self.unknown_email else self.login_link

    def verify_email(self, token):
        if token != self.link.token:
            raise ValueError("invalid")
        return self.account

    def consume_login_link(self, token):
        if token != self.login_link.token:
            raise ValueError("invalid")
        return self.session

    def authenticate_session(self, token):
        return self.account if token == self.session.token and not self.revoked else None

    def revoke_session(self, token):
        self.revoked = True
        return True


class FakeCustomerEmailSender:
    def __init__(self):
        self.sent = []

    def send_link(self, **kwargs):
        self.sent.append(kwargs)


class TestCustomerIdentityApi(unittest.TestCase):
    def setUp(self):
        self.store = FakeCustomerIdentityStore()
        self.sender = FakeCustomerEmailSender()
        api._customer_email_attempts.clear()
        self.store_patch = patch.object(api, "_get_customer_identity_store", return_value=self.store)
        self.sender_patch = patch.object(api, "_get_customer_email_sender", return_value=self.sender)
        self.store_patch.start()
        self.sender_patch.start()
        self.addCleanup(self.store_patch.stop)
        self.addCleanup(self.sender_patch.stop)
        self.client = TestClient(api.app, base_url="https://testserver")

    def test_registration_sends_verification_link_without_returning_token(self):
        response = self.client.post(
            "/v1/customer/register",
            json={"email": "USER@example.test", "organization_name": "Example Organization"},
        )
        self.assertEqual(response.status_code, 202)
        self.assertNotIn(self.store.link.token, response.text)
        self.assertEqual(len(self.sender.sent), 1)
        self.assertEqual(self.sender.sent[0]["purpose"], "verify_email")

    def test_login_response_does_not_disclose_account_existence(self):
        known = self.client.post("/v1/customer/login", json={"email": "user@example.test"})
        self.store.unknown_email = True
        unknown = self.client.post("/v1/customer/login", json={"email": "unknown@example.test"})
        self.assertEqual(known.status_code, 202)
        self.assertEqual(unknown.status_code, 202)
        self.assertEqual(known.json(), unknown.json())

    def test_email_verification_and_one_time_login_set_secure_session_cookies(self):
        verified = self.client.post(
            "/v1/customer/verify-email", json={"token": self.store.link.token}
        )
        self.assertEqual(verified.status_code, 200)
        response = self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.store.session.token, response.text)
        self.assertIn("jassi_customer_session", response.cookies)
        self.assertIn("jassi_customer_csrf", response.cookies)
        session_cookie = response.headers.get("set-cookie", "")
        self.assertIn("httponly", session_cookie.lower())
        self.assertIn("samesite=strict", session_cookie.lower())

    def test_session_me_and_csrf_protected_logout(self):
        self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        me = self.client.get("/v1/customer/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["email"], "user@example.test")
        blocked = self.client.post("/v1/customer/logout", json={})
        self.assertEqual(blocked.status_code, 403)
        csrf = self.client.cookies.get("jassi_customer_csrf")
        logout = self.client.post(
            "/v1/customer/logout",
            json={},
            headers={"X-JAS-SI-CSRF": csrf},
        )
        self.assertEqual(logout.status_code, 200)
        self.assertTrue(self.store.revoked)

    def test_customer_email_requests_have_a_dedicated_ip_rate_limit(self):
        for _ in range(api._CUSTOMER_EMAIL_LIMIT):
            response = self.client.post(
                "/v1/customer/login", json={"email": "user@example.test"}
            )
            self.assertEqual(response.status_code, 202)
        blocked = self.client.post(
            "/v1/customer/login", json={"email": "user@example.test"}
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn("Retry-After", blocked.headers)

    def test_customer_api_key_list_requires_customer_session(self):
        with patch.object(api, "_get_customer_api_key_registry") as registry:
            response = self.client.get("/v1/customer/api-keys")
        self.assertEqual(response.status_code, 401)
        registry.assert_not_called()

    def test_customer_api_key_create_list_and_revoke_are_session_and_csrf_protected(self):
        self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        csrf = self.client.cookies.get("jassi_customer_csrf")
        issued = SimpleNamespace(
            key_id=uuid.uuid4(),
            token="jassi_live_one-time-secret",
            prefix="jassi_live_prefix",
            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
        )
        registry = SimpleNamespace(
            list_tenant_keys=lambda tenant_id: [
                {"key_id": str(issued.key_id), "key_name": "test", "key_prefix": issued.prefix,
                 "scopes": ["authorization:check"], "status": "active",
                 "created_at": datetime.now(timezone.utc).isoformat(),
                 "expires_at": issued.expires_at.isoformat(), "last_used_at": None, "revoked_at": None}
            ],
            issue_key_with_audit=lambda **kwargs: issued,
            revoke_key_with_audit=lambda **kwargs: True,
        )
        with patch.object(api, "_get_customer_api_key_registry", return_value=registry):
            denied = self.client.post(
                "/v1/customer/api-keys",
                json={"key_name": "test", "scopes": ["authorization:check"]},
            )
            self.assertEqual(denied.status_code, 403)
            created = self.client.post(
                "/v1/customer/api-keys",
                headers={"X-JAS-SI-CSRF": csrf},
                json={"key_name": "test", "scopes": ["authorization:check"]},
            )
            self.assertEqual(created.status_code, 201)
            self.assertEqual(created.json()["token"], issued.token)
            listed = self.client.get("/v1/customer/api-keys")
            self.assertEqual(listed.status_code, 200)
            self.assertEqual(listed.json()["count"], 1)
            revoked = self.client.post(
                f"/v1/customer/api-keys/{issued.key_id}/revoke",
                headers={"X-JAS-SI-CSRF": csrf},
            )
            self.assertEqual(revoked.status_code, 200)
            self.assertTrue(revoked.json()["revoked"])

    def test_customer_api_key_rejects_unapproved_scope(self):
        self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        csrf = self.client.cookies.get("jassi_customer_csrf")
        with patch.object(api, "_get_customer_api_key_registry") as registry:
            response = self.client.post(
                "/v1/customer/api-keys",
                headers={"X-JAS-SI-CSRF": csrf},
                json={"key_name": "admin", "scopes": ["admin:*"]},
            )
        self.assertEqual(response.status_code, 422)
        registry.assert_not_called()

    def test_customer_portal_is_served(self):
        response = self.client.get("/customer")
        self.assertEqual(response.status_code, 200)
        self.assertIn("JAS-SI Customer Portal", response.text)


if __name__ == "__main__":
    unittest.main()
