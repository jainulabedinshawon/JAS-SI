"""Tenant-scoped agent task API tests with isolated stores."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase

from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from jas_si_agent import api
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

    def create(self, **kwargs):
        self.created.append(kwargs)
        return AgentTaskSubmission(self.task, True)

    def get(self, **kwargs):
        return self.task if kwargs["task_id"] == self.task.task_id else None


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

    def test_github_repository_read_task_accepts_only_bounded_immutable_input(self):
        payload = {
            "task_type": "github.read_repository",
            "input_payload": {
                "repository": "example/project",
                "commit_sha": "a" * 40,
                "paths": ["README.md", "src/main.py"],
            },
        }
        response = self.client.post("/v1/agent/tasks", json=payload)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.store.created[-1]["input_payload"], payload["input_payload"])

    def test_github_repository_read_task_rejects_malformed_or_unbounded_input(self):
        base = {
            "task_type": "github.read_repository",
            "input_payload": {
                "repository": "example/project",
                "commit_sha": "a" * 40,
                "paths": ["README.md"],
            },
        }
        invalid_inputs = []
        missing_sha = dict(base["input_payload"])
        missing_sha.pop("commit_sha")
        invalid_inputs.append(missing_sha)
        invalid_inputs.append(dict(base["input_payload"], commit_sha="not-a-full-sha"))
        invalid_inputs.append(dict(base["input_payload"], paths=["../secrets.txt"]))
        invalid_inputs.append(dict(base["input_payload"], paths=["/etc/passwd"]))
        invalid_inputs.append(dict(base["input_payload"], paths=["a\\\\b"]))
        invalid_inputs.append(dict(base["input_payload"], paths=["\x00"]))
        invalid_inputs.append(dict(base["input_payload"], paths=["x" * 501]))
        invalid_inputs.append(dict(base["input_payload"], paths=["."]))
        invalid_inputs.append(dict(base["input_payload"], paths=["a\\\\b"]))
        invalid_inputs.append(dict(base["input_payload"], paths=["README.md", "README.md"]))
        invalid_inputs.append(dict(base["input_payload"], paths=[f"file-{i}.txt" for i in range(11)]))
        invalid_inputs.append(dict(base["input_payload"], command="arbitrary"))
        invalid_inputs.append(dict(base["input_payload"], repository="example/../private"))

        for input_payload in invalid_inputs:
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



    def test_cancel_task_uses_authenticated_key_context(self):
        response = self.client.post(
            "/v1/agent/tasks/00000000-0000-0000-0000-000000000080/cancel"
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["cancellation_requested"])
        self.assertEqual(self.store.cancelled[0]["api_key_id"], __import__("uuid").UUID(
            "00000000-0000-0000-0000-000000000022"
        ))



