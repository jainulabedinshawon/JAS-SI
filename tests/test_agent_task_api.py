"""Tenant-scoped agent task API tests with isolated stores."""

from datetime import datetime, timezone
from types import SimpleNamespace
import uuid
from types import SimpleNamespace
from unittest import TestCase

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from jas_si_agent import api
from jas_si_agent.customer_portal import CUSTOMER_PORTAL_HTML
from jas_si_agent.agent_task_store import AgentTask, AgentTaskSubmission


class FakeEventStore:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class FakeUsageMeter:
    def __init__(self):
        self.records = []

    def record_authenticated(self, **kwargs):
        self.records.append(kwargs)
        return {
            "event_id": "00000000-0000-0000-0000-000000000099",
            "replayed": False,
            "monthly_limit": 100,
            "used_units": 1,
            "remaining_units": 99,
            "resets_at": "2026-12-01T00:00:00+00:00",
        }


class FakeCustomerIdentityStore:
    def __init__(self):
        self.account = SimpleNamespace(
            account_id=uuid.UUID("00000000-0000-0000-0000-000000000033"),
            tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000011"),
            status="active",
        )

    def authenticate_session(self, token):
        return self.account if token == "valid-customer-session" else None


class FakeTaskStore:
    def __init__(self):
        now = datetime(2026, 11, 15, tzinfo=timezone.utc)
        self.task = AgentTask(
            task_id=__import__("uuid").UUID("00000000-0000-0000-0000-000000000080"),
            task_type="research",
            status="queued",
            input_payload={"question": "test"},
            result_payload=None,
            error_code=None,
            attempt_count=0,
            max_attempts=3,
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
        self.created = []
        self.cancelled = []
        self.review_decisions = []
        self.review_queue_requests = []
        self.review_history_requests = []

    def create(self, **kwargs):
        self.created.append(kwargs)
        return AgentTaskSubmission(self.task, True)

    def get(self, **kwargs):
        return self.task if kwargs["task_id"] == self.task.task_id else None

    def get_review_metadata(self, **kwargs):
        self.review_metadata_requests = getattr(self, "review_metadata_requests", [])
        self.review_metadata_requests.append(kwargs)
        if kwargs["task_id"] != self.task.task_id:
            raise AssertionError("review metadata must only be requested for the fetched task")
        return {
            "review_required": self.task.status == "human_review_required",
            "verification_status": "INCONCLUSIVE" if self.task.status == "human_review_required" else None,
            "verification_reason_code": "EVIDENCE_MISSING" if self.task.status == "human_review_required" else None,
        }



    def list_human_review_queue(self, **kwargs):
        self.review_queue_requests.append(kwargs)
        return [{
            "task_id": str(self.task.task_id),
            "task_type": "github.read_repository",
            "status": "human_review_required",
            "verification_status": "INCONCLUSIVE",
            "verification_reason_code": "EVIDENCE_MISSING",
            "verifier_attempt_count": 3,
            "created_at": "2026-11-17T00:00:00+00:00",
            "updated_at": "2026-11-17T00:01:00+00:00",
        }]

    def get_human_review_history(self, **kwargs):
        self.review_history_requests.append(kwargs)
        if kwargs["task_id"] != self.task.task_id:
            return None
        return {
            "task_id": str(self.task.task_id),
            "items": [{
                "decision_event_id": "00000000-0000-0000-0000-000000000044",
                "decision": "close_unverified",
                "reason_code": "OWNER_CONFIRMED",
                "previous_status": "human_review_required",
                "resulting_status": "closed_unverified",
                "decided_at": "2026-11-17T00:00:00+00:00",
            }],
        }

    def verify_review_schema(self):
        return True

    def record_human_review_decision(self, **kwargs):
        self.review_decisions.append(kwargs)
        return {
            "decision_event_id": "00000000-0000-0000-0000-000000000044",
            "task_status": (
                "closed_unverified"
                if kwargs["decision"] == "close_unverified"
                else "human_review_required"
            ),
            "created": True,
            "decided_at": "2026-11-17T00:00:00+00:00",
        }

    def cancel(self, **kwargs):
        self.cancelled.append(kwargs)
        return kwargs["task_id"] == self.task.task_id


class TestAgentTaskAPI(TestCase):
    def setUp(self):
        self.old_settings = api.settings
        api.settings = api.settings.__class__(
            service_name="JAS-SI API",
            environment="test",
            api_enabled=True,
            api_key="test-key",
            rate_limit_requests=100,
            rate_limit_window_seconds=60,
        )
        self.addCleanup(self._restore_settings)

        self.old_event_store = api.app.state.security_event_store
        self.events = FakeEventStore()
        api.app.state.security_event_store = self.events
        self.addCleanup(self._restore_event_store)

        self.old_meter = getattr(api.app.state, "usage_meter", None)
        self.meter = FakeUsageMeter()
        api.app.state.usage_meter = self.meter
        self.addCleanup(self._restore_meter)

        self.old_task_store = getattr(api.app.state, "agent_task_store", None)
        self.store = FakeTaskStore()
        api.app.state.agent_task_store = self.store
        self.addCleanup(self._restore_task_store)

        self.old_customer_identity_store = getattr(
            api.app.state, "customer_identity_store", None
        )
        self.customer_identity_store = FakeCustomerIdentityStore()
        api.app.state.customer_identity_store = self.customer_identity_store
        self.addCleanup(self._restore_customer_identity_store)

        self.old_enabled = getattr(api.app.state, "agent_task_submission_enabled", None)
        api.app.state.agent_task_submission_enabled = True
        self.addCleanup(self._restore_enabled)

        self.old_override = api.app.dependency_overrides.get(api._require_api_key)

        def authenticate(request: Request):
            request.state.tenant_id = "00000000-0000-0000-0000-000000000011"
            request.state.api_key_id = "00000000-0000-0000-0000-000000000022"
            request.state.api_key_candidate_digest = b"x" * 32
            request.state.api_key_scopes = ["agent:tasks:read", "agent:tasks:write"]
            request.state.api_key_required_scope = "agent:tasks:write"
            api._record_usage_for_authenticated_tenant(request)

        api.app.dependency_overrides[api._require_api_key] = authenticate
        self.client = TestClient(api.app)
        with api._rate_limit_lock:
            api._rate_limit_buckets.clear()

    def _restore_settings(self):
        api.settings = self.old_settings

    def _restore_event_store(self):
        api.app.state.security_event_store = self.old_event_store

    def _restore_meter(self):
        if self.old_meter is None:
            if hasattr(api.app.state, "usage_meter"):
                delattr(api.app.state, "usage_meter")
        else:
            api.app.state.usage_meter = self.old_meter

    def _restore_task_store(self):
        if self.old_task_store is None:
            if hasattr(api.app.state, "agent_task_store"):
                delattr(api.app.state, "agent_task_store")
        else:
            api.app.state.agent_task_store = self.old_task_store

    def _restore_customer_identity_store(self):
        if self.old_customer_identity_store is None:
            if hasattr(api.app.state, "customer_identity_store"):
                delattr(api.app.state, "customer_identity_store")
        else:
            api.app.state.customer_identity_store = self.old_customer_identity_store

    def _restore_enabled(self):
        if self.old_enabled is None:
            if hasattr(api.app.state, "agent_task_submission_enabled"):
                delattr(api.app.state, "agent_task_submission_enabled")
        else:
            api.app.state.agent_task_submission_enabled = self.old_enabled

    def tearDown(self):
        if self.old_override is None:
            api.app.dependency_overrides.pop(api._require_api_key, None)
        else:
            api.app.dependency_overrides[api._require_api_key] = self.old_override

    def test_submit_task_reserves_one_metered_unit_and_persists_tenant_scoped_task(self):
        response = self.client.post(
            "/v1/agent/tasks",
            headers={"Idempotency-Key": "customer-task-001"},
            json={"task_type": "research", "input_payload": {"question": "test"}},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["task"]["status"], "queued")
        self.assertEqual(response.json()["execution_status"], "queued_for_worker")
        self.assertEqual(len(self.meter.records), 1)
        self.assertEqual(self.meter.records[0]["operation"], "agent.task.submit")
        self.assertEqual(self.meter.records[0]["required_scope"], "agent:tasks:write")
        self.assertEqual(self.meter.records[0]["idempotency_key"], "customer-task-001")
        self.assertEqual(self.store.created[0]["idempotency_key"], "customer-task-001")
        self.assertEqual(self.events.events[-1]["event_type"], "agent_task_submitted")

    def test_task_submission_is_rejected_when_worker_host_is_not_ready(self):
        api.app.state.agent_task_submission_enabled = False

        def authenticate_without_meter(request: Request):
            request.state.tenant_id = "00000000-0000-0000-0000-000000000011"
            request.state.api_key_id = "00000000-0000-0000-0000-000000000022"
            request.state.api_key_candidate_digest = b"x" * 32
            request.state.api_key_scopes = ["agent:tasks:write"]

        api.app.dependency_overrides[api._require_api_key] = authenticate_without_meter
        response = self.client.post(
            "/v1/agent/tasks",
            json={"task_type": "research", "input_payload": {"question": "test"}},
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.meter.records, [])
        self.assertEqual(self.store.created, [])

    def test_get_task_returns_not_found_for_other_tenant_or_unknown_task(self):
        response = self.client.get(
            "/v1/agent/tasks/00000000-0000-0000-0000-000000000081"
        )
        self.assertEqual(response.status_code, 404)

    def test_get_task_includes_sanitized_review_metadata_for_authenticated_tenant(self):
        self.store.task = self.store.task.__class__(
            **{**self.store.task.__dict__, "status": "human_review_required"}
        )
        response = self.client.get(
            "/v1/agent/tasks/00000000-0000-0000-0000-000000000080"
        )
        self.assertEqual(response.status_code, 200)
        task = response.json()["task"]
        self.assertTrue(task["review_required"])
        self.assertEqual(task["verification_status"], "INCONCLUSIVE")
        self.assertEqual(task["verification_reason_code"], "EVIDENCE_MISSING")
        request = self.store.review_metadata_requests[0]
        self.assertEqual(request["task_id"], self.store.task.task_id)
        self.assertEqual(
            request["api_key_id"],
            __import__("uuid").UUID("00000000-0000-0000-0000-000000000022"),
        )
        self.assertEqual(request["candidate_digest"], b"x" * 32)

    def test_get_task_returns_review_metadata_for_non_review_task(self):
        response = self.client.get(
            "/v1/agent/tasks/00000000-0000-0000-0000-000000000080"
        )
        self.assertEqual(response.status_code, 200)
        task = response.json()["task"]
        self.assertFalse(task["review_required"])
        self.assertIsNone(task["verification_status"])
        self.assertIsNone(task["verification_reason_code"])




    def test_customer_portal_exposes_session_protected_human_review_workflow(self):
        self.assertIn("/v1/customer/agent/tasks/review-queue", CUSTOMER_PORTAL_HTML)
        self.assertIn("/review-history?limit=50", CUSTOMER_PORTAL_HTML)
        self.assertIn("close_unverified", CUSTOMER_PORTAL_HTML)
        self.assertIn("request_more_evidence", CUSTOMER_PORTAL_HTML)
        self.assertIn("X-JAS-SI-CSRF", CUSTOMER_PORTAL_HTML)
        self.assertIn("Idempotency-Key", CUSTOMER_PORTAL_HTML)
        self.assertIn("Verified Success: no.", CUSTOMER_PORTAL_HTML)

    def test_human_review_queue_requires_customer_session(self):
        response = self.client.get("/v1/customer/agent/tasks/review-queue")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.store.review_queue_requests, [])

    def test_human_review_queue_uses_session_tenant_and_returns_sanitized_items(self):
        response = self.client.get(
            "/v1/customer/agent/tasks/review-queue?limit=25",
            cookies={"jassi_customer_session": "valid-customer-session"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        item = response.json()["items"][0]
        self.assertEqual(item["status"], "human_review_required")
        self.assertNotIn("input_payload", item)
        self.assertEqual(
            self.store.review_queue_requests[0],
            {
                "tenant_id": uuid.UUID("00000000-0000-0000-0000-000000000011"),
                "limit": 25,
            },
        )

    def test_human_review_history_is_session_tenant_scoped(self):
        response = self.client.get(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000080/review-history",
            cookies={"jassi_customer_session": "valid-customer-session"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["decision"], "close_unverified")
        self.assertEqual(
            self.store.review_history_requests[0]["tenant_id"],
            uuid.UUID("00000000-0000-0000-0000-000000000011"),
        )

    def test_human_review_history_hides_tasks_outside_authenticated_tenant(self):
        response = self.client.get(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000081/review-history",
            cookies={"jassi_customer_session": "valid-customer-session"},
        )
        self.assertEqual(response.status_code, 404)

    def test_human_review_requires_a_valid_customer_session(self):
        response = self.client.post(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000080/review",
            json={"decision": "close_unverified", "reason_code": "OWNER_CONFIRMED"},
            headers={"Idempotency-Key": "review-session-001"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.store.review_decisions, [])

    def test_human_review_requires_csrf_even_with_a_valid_customer_session(self):
        response = self.client.post(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000080/review",
            cookies={
                "jassi_customer_session": "valid-customer-session",
                "jassi_customer_csrf": "csrf-token",
            },
            json={"decision": "close_unverified", "reason_code": "OWNER_CONFIRMED"},
            headers={"Idempotency-Key": "review-csrf-001"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.store.review_decisions, [])

    def test_human_review_uses_server_derived_identity_and_never_asserts_success(self):
        response = self.client.post(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000080/review",
            cookies={
                "jassi_customer_session": "valid-customer-session",
                "jassi_customer_csrf": "csrf-token",
            },
            headers={
                "X-JAS-SI-CSRF": "csrf-token",
                "Idempotency-Key": "review-close-001",
            },
            json={"decision": "close_unverified", "reason_code": "OWNER_CONFIRMED"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["verified_success"])
        self.assertEqual(response.json()["task_status"], "closed_unverified")
        self.assertEqual(len(self.store.review_decisions), 1)
        decision = self.store.review_decisions[0]
        self.assertEqual(
            decision["tenant_id"],
            uuid.UUID("00000000-0000-0000-0000-000000000011"),
        )
        self.assertEqual(
            decision["reviewer_account_id"],
            uuid.UUID("00000000-0000-0000-0000-000000000033"),
        )
        self.assertEqual(decision["decision"], "close_unverified")
        self.assertEqual(decision["idempotency_key"], "review-close-001")

    def test_human_review_rejects_unknown_decision_without_database_write(self):
        response = self.client.post(
            "/v1/customer/agent/tasks/00000000-0000-0000-0000-000000000080/review",
            cookies={
                "jassi_customer_session": "valid-customer-session",
                "jassi_customer_csrf": "csrf-token",
            },
            headers={
                "X-JAS-SI-CSRF": "csrf-token",
                "Idempotency-Key": "review-invalid-001",
            },
            json={"decision": "mark_verified_success", "reason_code": "OWNER_CONFIRMED"},
        )
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.store.review_decisions, [])

    def test_cancel_task_uses_authenticated_key_context(self):
        response = self.client.post(
            "/v1/agent/tasks/00000000-0000-0000-0000-000000000080/cancel"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["cancellation_requested"])
        self.assertEqual(self.store.cancelled[0]["api_key_id"], __import__("uuid").UUID(
            "00000000-0000-0000-0000-000000000022"
        ))


    def test_github_repository_read_task_accepts_only_bounded_immutable_input(self):
        valid = {
            "task_type": "github.read_repository",
            "input_payload": {
                "repository": "example/project",
                "commit_sha": "a" * 40,
                "paths": ["README.md", "src/main.py"],
            },
        }
        response = self.client.post("/v1/agent/tasks", json=valid)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.store.created[-1]["task_type"], "github.read_repository")
        self.assertEqual(self.store.created[-1]["input_payload"], valid["input_payload"])

    def test_github_repository_read_task_rejects_malformed_or_unbounded_input(self):
        base = {
            "task_type": "github.read_repository",
            "input_payload": {
                "repository": "example/project",
                "commit_sha": "a" * 40,
                "paths": ["README.md"],
            },
        }
        invalid_payloads = []

        missing_field = dict(base["input_payload"])
        missing_field.pop("commit_sha")
        invalid_payloads.append(missing_field)

        invalid_sha = dict(base["input_payload"], commit_sha="not-a-full-sha")
        invalid_payloads.append(invalid_sha)

        traversal = dict(base["input_payload"], paths=["../secrets.txt"])
        invalid_payloads.append(traversal)

        duplicate_paths = dict(base["input_payload"], paths=["README.md", "README.md"])
        invalid_payloads.append(duplicate_paths)

        too_many_paths = dict(
            base["input_payload"],
            paths=[f"file-{index}.txt" for index in range(11)],
        )
        invalid_payloads.append(too_many_paths)

        unknown_field = dict(base["input_payload"], command="arbitrary")
        invalid_payloads.append(unknown_field)

        invalid_repository = dict(base["input_payload"], repository="example/../private")
        invalid_payloads.append(invalid_repository)

        for input_payload in invalid_payloads:
            with self.subTest(input_payload=input_payload):
                response = self.client.post(
                    "/v1/agent/tasks",
                    json=dict(base, input_payload=input_payload),
                )
                self.assertEqual(response.status_code, 422)

        self.assertEqual(self.store.created, [])
        self.assertFalse(
            any(event.get("event_type") == "agent_task_submitted" for event in self.events.events)
        )
