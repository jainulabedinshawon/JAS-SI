"""HTTP tests for the standalone customer onboarding and session flow."""
from __future__ import annotations

import unittest
import uuid
from dataclasses import replace
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


class FakeCustomerRateLimiter:
    def __init__(self):
        self.attempts = {}

    def check(self, client_ip, *, limit, window_seconds):
        count = self.attempts.get(client_ip, 0) + 1
        self.attempts[client_ip] = count
        return count <= limit, window_seconds


class FakeCustomerEmailSender:
    def __init__(self):
        self.sent = []

    def send_link(self, **kwargs):
        self.sent.append(kwargs)


class TestCustomerIdentityApi(unittest.TestCase):
    def setUp(self):
        self.store = FakeCustomerIdentityStore()
        self.sender = FakeCustomerEmailSender()
        self.limiter = FakeCustomerRateLimiter()
        self.limiter_patch = patch.object(api, "_get_customer_rate_limiter", return_value=self.limiter)
        self.limiter_patch.start()
        self.addCleanup(self.limiter_patch.stop)
        self.store_patch = patch.object(api, "_get_customer_identity_store", return_value=self.store)
        self.sender_patch = patch.object(api, "_get_customer_email_sender", return_value=self.sender)
        self.store_patch.start()
        self.sender_patch.start()
        self.addCleanup(self.store_patch.stop)
        self.addCleanup(self.sender_patch.stop)
        self.client = TestClient(
            api.app,
            base_url="https://testserver",
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

    def test_identity_store_fails_closed_when_database_privileges_are_not_isolated(self):
        # setUp patches this getter for HTTP-route tests; restore the real getter
        # so this test exercises the readiness guard itself.
        self.store_patch.stop()
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
        unsafe_store = SimpleNamespace(
            verify_schema=lambda: True,
            verify_security_boundary=lambda: False,
        )
        configured = replace(
            api.settings,
            customer_database_url="postgresql://identity-test",
            customer_token_pepper=b"customer-identity-test-pepper-32-bytes-minimum",
        )
        with patch.object(api, "settings", configured), patch.object(
            api, "PostgresCustomerIdentityStore", return_value=unsafe_store
        ):
            with self.assertRaises(api.HTTPException) as raised:
                api._get_customer_identity_store(request)
        self.assertEqual(raised.exception.status_code, 503)
        self.assertFalse(hasattr(request.app.state, "customer_identity_store"))

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

    def test_customer_usage_requires_customer_session(self):
        response = self.client.get("/v1/customer/usage")
        self.assertEqual(response.status_code, 401)

    def test_customer_usage_is_scoped_to_authenticated_tenant_and_not_billing(self):
        self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        observed = {}
        previous_meter = getattr(api.app.state, "usage_meter", None)
        class FakeUsageMeter:
            def summary(self, *, tenant_id, since):
                observed["tenant_id"] = tenant_id
                observed["since"] = since
                return {"tenant_id": tenant_id, "units": 7, "events": 4, "by_operation": []}
            def quota_status(self, *, tenant_id, monthly_limit):
                observed["quota_tenant_id"] = tenant_id
                return {"monthly_limit": monthly_limit, "used_units": 7, "remaining_units": monthly_limit - 7}
        fake_meter = FakeUsageMeter()
        api.app.state.usage_meter = fake_meter
        try:
            with patch.object(api, "settings", replace(api.settings, database_url="postgresql://test")), \
                 patch.object(api, "get_free_monthly_units", return_value=100):
                response = self.client.get("/v1/customer/usage")
        finally:
            if previous_meter is None:
                if hasattr(api.app.state, "usage_meter"):
                    delattr(api.app.state, "usage_meter")
            else:
                api.app.state.usage_meter = previous_meter
        self.assertEqual(response.status_code, 200)
        self.assertEqual(observed["tenant_id"], str(self.store.account.tenant_id))
        self.assertEqual(observed["quota_tenant_id"], str(self.store.account.tenant_id))
        self.assertEqual(response.json()["quota"]["remaining_units"], 93)
        self.assertEqual(response.json()["billing_status"], "not_connected")
        self.assertIn("No monetary balance", response.json()["note"])

    def test_customer_api_key_list_requires_customer_session(self):
        with patch.object(api, "_get_customer_api_key_registry") as registry:
            response = self.client.get("/v1/customer/api-keys")
        self.assertEqual(response.status_code, 401)
        registry.assert_not_called()

    def test_inactive_customer_cannot_manage_api_keys(self):
        self.client.post(
            "/v1/customer/session", json={"token": self.store.login_link.token}
        )
        self.store.account = replace(self.store.account, status="suspended")
        with patch.object(api, "_get_customer_api_key_registry") as registry:
            response = self.client.get("/v1/customer/api-keys")
        self.assertEqual(response.status_code, 403)
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
            customer_list_keys=lambda session_token: [
                {"key_id": str(issued.key_id), "key_name": "test", "key_prefix": issued.prefix,
                 "scopes": ["authorization:check"], "status": "active",
                 "created_at": datetime.now(timezone.utc).isoformat(),
                 "expires_at": issued.expires_at.isoformat(), "last_used_at": None, "revoked_at": None}
            ],
            customer_issue_key=lambda session_token, key_name, scopes, expires_at: issued,
            customer_revoke_key=lambda session_token, key_id: True,
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
            self.assertEqual(created.headers["cache-control"], "no-store")
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
        self.assertIn("plan-list", response.text)
        self.assertIn("Manual TrxID checkout is not active", response.text)
        self.assertIn("create-key", response.text)


    def test_vercel_preserved_client_ip_takes_precedence_over_generic_forwarded_header(self):
        request = SimpleNamespace(
            headers={
                "x-vercel-forwarded-for": "198.51.100.44",
                "x-forwarded-for": "203.0.113.99",
            },
            client=None,
        )
        self.assertEqual(api._customer_client_ip(request), "198.51.100.44")

    def test_invalid_vercel_client_ip_fails_closed_instead_of_trusting_xff(self):
        request = SimpleNamespace(
            headers={
                "x-vercel-forwarded-for": "not-an-ip",
                "x-forwarded-for": "203.0.113.99",
            },
            client=None,
        )
        with self.assertRaises(api.HTTPException) as raised:
            api._customer_client_ip(request)
        self.assertEqual(raised.exception.status_code, 503)

    def test_missing_trusted_ip_headers_fail_closed_in_preview_and_production(self):
        request = SimpleNamespace(headers={}, client=SimpleNamespace(host="10.0.0.8"))
        for environment in ("preview", "production"):
            with self.subTest(environment=environment), patch.object(
                api, "settings", replace(api.settings, environment=environment)
            ):
                with self.assertRaises(api.HTTPException) as raised:
                    api._customer_client_ip(request)
                self.assertEqual(raised.exception.status_code, 503)

    def test_local_environment_may_use_direct_peer_when_proxy_headers_are_absent(self):
        request = SimpleNamespace(headers={}, client=SimpleNamespace(host="127.0.0.1"))
        with patch.object(
            api, "settings", replace(api.settings, environment="development")
        ):
            self.assertEqual(api._customer_client_ip(request), "127.0.0.1")



    def test_shared_rate_limit_failure_fails_closed_before_sending_email(self):
        self.limiter.check = lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        )
        response = self.client.post(
            "/v1/customer/login",
            json={"email": "user@example.test"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.sender.sent, [])



if __name__ == "__main__":
    unittest.main()
