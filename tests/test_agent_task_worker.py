from __future__ import annotations

import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from jas_si_agent.agent_task_worker import AgentTaskWorker, SimulationResult, TaskHandler
from jas_si_agent.authorization import AuthorizationGrant
from jas_si_agent.grant_signing import sign_task_grant, verify_task_grant_signature

TEST_GRANT_KEY = b"jas-si-test-grant-signing-key-32-bytes-minimum"
from jas_si_agent.agent_task_worker_store import AgentTaskLease, AgentTaskWorkerStoreError


class FakeStore:
    def __init__(self, lease=None, *, renew_result=True, cancel_ack=False):
        self.lease = lease
        self.renew_result = renew_result
        self.cancel_ack = cancel_ack
        self.report_result = True
        self.claim_calls = []
        self.renew_calls = []
        self.ack_calls = []
        self.report_calls = []
        self.fail_calls = []

    def claim(self, *, lease_seconds):
        self.claim_calls.append(lease_seconds)
        lease, self.lease = self.lease, None
        return lease

    def renew(self, *, task_id, lease_fence, lease_seconds):
        self.renew_calls.append((task_id, lease_fence, lease_seconds))
        return self.renew_result

    def acknowledge_cancel(self, *, task_id, lease_fence):
        self.ack_calls.append((task_id, lease_fence))
        return self.cancel_ack

    def report(self, *, task_id, lease_fence, result_payload):
        self.report_calls.append((task_id, lease_fence, dict(result_payload)))
        return self.report_result

    def fail(self, *, task_id, lease_fence, error_code, retry_delay_seconds=0):
        self.fail_calls.append((task_id, lease_fence, error_code))
        return "failed"


def make_lease(task_type="reasoning"):
    return AgentTaskLease(
        task_id=uuid.uuid4(), tenant_id=uuid.UUID("00000000-0000-0000-0000-000000000099"),
        task_type=task_type, input_payload={"prompt": "test"},
        attempt_count=1, max_attempts=2, lease_fence=4,
        lease_expires_at=datetime.now(timezone.utc),
    )


class AgentTaskWorkerTests(unittest.TestCase):
    def make_worker(self, store, handler):
        return AgentTaskWorker(
            store=store, handlers={"reasoning": handler}, lease_seconds=15,
            heartbeat_interval_seconds=14,
        )

    def test_empty_queue_does_not_execute_handler(self):
        calls = []
        handler = TaskHandler(
            "reasoning", "read_repository", lambda _lease: "README.md",
            lambda _lease, _cancelled: calls.append("execute") or {"ok": True},
        )
        outcome = self.make_worker(FakeStore(), handler).run_once()
        self.assertEqual(outcome.state, "idle")
        self.assertEqual(calls, [])

    def test_authorized_task_reports_only_for_verification(self):
        lease = make_lease()
        calls = []
        handler = TaskHandler(
            "reasoning", "read_repository", lambda item: f"tasks/{item.task_id}",
            lambda item, _cancelled: calls.append(item.task_id) or {"answer": "evidence-backed"},
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "awaiting_verification")
        self.assertEqual(calls, [lease.task_id])
        self.assertEqual(lease.tenant_id, uuid.UUID("00000000-0000-0000-0000-000000000099"))
        self.assertEqual(store.report_calls[0][0], lease.task_id)
        self.assertEqual(store.fail_calls, [])

    def test_grant_required_action_is_denied_without_server_grant(self):
        lease = make_lease()
        calls = []
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            lambda _item, _cancelled: calls.append("must-not-run") or {"ok": True},
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(calls, [])
        self.assertEqual(store.report_calls, [])
        self.assertEqual(store.fail_calls[0][2], "ACTION_NOT_AUTHORIZED")


    def test_consequential_action_rejects_unsigned_grant_before_simulation(self):
        lease = make_lease()
        calls = []
        grant = AuthorizationGrant(
            grant_id="grant-unsigned", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), tenant_id=lease.tenant_id,
        )
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            lambda _item, _cancelled: calls.append("execute") or {"ok": True},
            grant_for=lambda _item: grant,
            simulate=lambda _item: calls.append("simulate") or SimulationResult(True, "preflight"),
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(store.fail_calls[0][2], "GRANT_SIGNATURE_REQUIRED")
        self.assertEqual(calls, [])
        self.assertEqual(store.report_calls, [])

    def test_signed_grant_from_another_tenant_is_rejected_before_simulation(self):
        lease = make_lease()
        calls = []
        grant = AuthorizationGrant(
            grant_id="grant-other-tenant", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            tenant_id=uuid.uuid4(),
        )
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            lambda _item, _cancelled: calls.append("execute") or {"ok": True},
            grant_for=lambda _item: grant,
            grant_signature_for=lambda _item: sign_task_grant(grant, _item.task_id, TEST_GRANT_KEY),
            verify_grant_signature=lambda item, task_id, signature: verify_task_grant_signature(item, task_id, signature, TEST_GRANT_KEY),
            simulate=lambda _item: calls.append("simulate") or SimulationResult(True, "preflight"),
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(store.fail_calls[0][2], "GRANT_TENANT_MISMATCH")
        self.assertEqual(calls, [])
        self.assertEqual(store.report_calls, [])

    def test_consequential_action_requires_simulation_even_with_valid_grant(self):
        lease = make_lease()
        calls = []
        grant = AuthorizationGrant(
            grant_id="grant-1", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            tenant_id=lease.tenant_id,
        )
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            lambda _item, _cancelled: calls.append("execute") or {"ok": True},
            grant_for=lambda _item: grant, grant_signature_for=lambda _item: sign_task_grant(grant, _item.task_id, TEST_GRANT_KEY), verify_grant_signature=lambda item, task_id, signature: verify_task_grant_signature(item, task_id, signature, TEST_GRANT_KEY),
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(calls, [])
        self.assertEqual(store.fail_calls[0][2], "SIMULATION_REQUIRED")
        self.assertEqual(store.report_calls, [])

    def test_consequential_action_simulates_after_authorization_before_execution(self):
        lease = make_lease()
        calls = []
        grant = AuthorizationGrant(
            grant_id="grant-2", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            tenant_id=lease.tenant_id,
        )
        def simulate(_item):
            calls.append("simulate")
            return SimulationResult(proceed=True, summary="Patch is bounded to the approved file")
        def execute(_item, _cancelled):
            calls.append("execute")
            return {"ok": True}
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            execute, grant_for=lambda _item: grant, grant_signature_for=lambda _item: sign_task_grant(grant, _item.task_id, TEST_GRANT_KEY), verify_grant_signature=lambda item, task_id, signature: verify_task_grant_signature(item, task_id, signature, TEST_GRANT_KEY), simulate=simulate,
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "awaiting_verification")
        self.assertEqual(calls, ["simulate", "execute"])
        self.assertEqual(
            store.report_calls[0][2]["jas_si_pre_action_simulation"],
            {"proceed": True, "summary": "Patch is bounded to the approved file"},
        )

    def test_lease_loss_during_simulation_prevents_executor_invocation(self):
        lease = make_lease()
        renewal_rejected = threading.Event()
        calls = []

        class LeaseLossStore(FakeStore):
            def renew(self, *, task_id, lease_fence, lease_seconds):
                self.renew_calls.append((task_id, lease_fence, lease_seconds))
                renewal_rejected.set()
                return False

        grant = AuthorizationGrant(
            grant_id="grant-lease-loss", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            tenant_id=lease.tenant_id,
        )

        def simulate(_item):
            calls.append("simulate")
            self.assertTrue(renewal_rejected.wait(1))
            return SimulationResult(proceed=True, summary="Preflight completed")

        def execute(_item, _cancelled):
            calls.append("execute")
            return {"ok": True}

        store = LeaseLossStore(lease, cancel_ack=True)
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            execute, grant_for=lambda _item: grant, grant_signature_for=lambda _item: sign_task_grant(grant, _item.task_id, TEST_GRANT_KEY), verify_grant_signature=lambda item, task_id, signature: verify_task_grant_signature(item, task_id, signature, TEST_GRANT_KEY), simulate=simulate,
        )
        worker = AgentTaskWorker(
            store=store, handlers={"reasoning": handler}, lease_seconds=15,
            heartbeat_interval_seconds=0.01,
        )
        outcome = worker.run_once()
        self.assertEqual(outcome.state, "cancelled")
        self.assertEqual(calls, ["simulate"])
        self.assertEqual(store.report_calls, [])
        self.assertEqual(store.ack_calls, [(lease.task_id, lease.lease_fence)])

    def test_rejected_simulation_prevents_consequential_execution(self):
        lease = make_lease()
        calls = []
        grant = AuthorizationGrant(
            grant_id="grant-3", approved_by="human", human_approved=True,
            allowed_actions=("write_file",), allowed_resources=("src/example.py",),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            tenant_id=lease.tenant_id,
        )
        handler = TaskHandler(
            "reasoning", "write_file", lambda _item: "src/example.py",
            lambda _item, _cancelled: calls.append("execute") or {"ok": True},
            grant_for=lambda _item: grant, grant_signature_for=lambda _item: sign_task_grant(grant, _item.task_id, TEST_GRANT_KEY), verify_grant_signature=lambda item, task_id, signature: verify_task_grant_signature(item, task_id, signature, TEST_GRANT_KEY),
            simulate=lambda _item: SimulationResult(proceed=False, summary="Risk threshold exceeded"),
        )
        store = FakeStore(lease)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(calls, [])
        self.assertEqual(store.fail_calls[0][2], "SIMULATION_REJECTED")
        self.assertEqual(store.report_calls, [])

    def test_unknown_task_type_fails_closed(self):
        store = FakeStore(make_lease("unregistered"))
        handler = TaskHandler(
            "reasoning", "read_repository", lambda _item: "README.md",
            lambda _item, _cancelled: {"ok": True},
        )
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(store.fail_calls[0][2], "UNSUPPORTED_TASK_TYPE")

    def test_handler_exception_is_reported_as_bounded_failure_code(self):
        def explode(_lease, _cancelled):
            raise RuntimeError("exception details must not enter task record")
        store = FakeStore(make_lease())
        handler = TaskHandler("reasoning", "read_repository", lambda _item: "README.md", explode)
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "failed")
        self.assertEqual(store.fail_calls[0][2], "HANDLER_EXECUTION_ERROR")

    def test_lost_lease_stops_execution_and_never_reports(self):
        store = FakeStore(make_lease(), renew_result=False)
        def cooperative_handler(_lease, cancelled):
            cancelled.wait(1)
            return {"claimed_success": True}
        handler = TaskHandler("reasoning", "read_repository", lambda _item: "README.md", cooperative_handler)
        worker = AgentTaskWorker(
            store=store, handlers={"reasoning": handler}, lease_seconds=15,
            heartbeat_interval_seconds=0.01,
        )
        outcome = worker.run_once()
        self.assertEqual(outcome.state, "lease_lost")
        self.assertEqual(store.report_calls, [])
        self.assertEqual(len(store.ack_calls), 1)

    def test_report_rejection_acknowledges_racing_cancellation(self):
        lease = make_lease()
        store = FakeStore(lease, cancel_ack=True)
        store.report_result = False
        handler = TaskHandler(
            "reasoning", "read_repository", lambda _item: "README.md",
            lambda _item, _cancelled: {"claimed_success": True},
        )
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "cancelled")
        self.assertEqual(len(store.report_calls), 1)
        self.assertEqual(len(store.ack_calls), 1)

    def test_report_rejection_without_cancel_ack_is_lease_lost(self):
        lease = make_lease()
        store = FakeStore(lease, cancel_ack=False)
        store.report_result = False
        handler = TaskHandler(
            "reasoning", "read_repository", lambda _item: "README.md",
            lambda _item, _cancelled: {"claimed_success": True},
        )
        outcome = self.make_worker(store, handler).run_once()
        self.assertEqual(outcome.state, "lease_lost")
        self.assertEqual(len(store.ack_calls), 1)

    def test_cancel_is_acknowledged_only_after_handler_returns(self):
        stopped = threading.Event()

        class CancellationStore(FakeStore):
            def acknowledge_cancel(self, *, task_id, lease_fence):
                self.assert_handler_stopped = stopped.is_set()
                return super().acknowledge_cancel(task_id=task_id, lease_fence=lease_fence)

        store = CancellationStore(make_lease(), renew_result=False, cancel_ack=True)

        def cooperative_handler(_lease, cancelled):
            cancelled.wait(1)
            stopped.set()
            return {"claimed_success": True}

        handler = TaskHandler(
            "reasoning", "read_repository", lambda _item: "README.md",
            cooperative_handler,
        )
        worker = AgentTaskWorker(
            store=store, handlers={"reasoning": handler}, lease_seconds=15,
            heartbeat_interval_seconds=0.01,
        )
        outcome = worker.run_once()
        self.assertEqual(outcome.state, "cancelled")
        self.assertTrue(store.assert_handler_stopped)
        self.assertEqual(store.report_calls, [])

    def test_invalid_registration_and_heartbeat_configuration_rejected(self):
        store = FakeStore()
        handler = TaskHandler("reasoning", "read_repository", lambda _item: "README.md", lambda _item, _cancelled: {"ok": True})
        with self.assertRaises(ValueError):
            AgentTaskWorker(store=store, handlers={}, lease_seconds=15)
        with self.assertRaises(ValueError):
            AgentTaskWorker(store=store, handlers={"wrong": handler}, lease_seconds=15)
        with self.assertRaises(ValueError):
            AgentTaskWorker(store=store, handlers={"reasoning": handler}, lease_seconds=15, heartbeat_interval_seconds=15)

    def test_run_forever_backs_off_after_database_failure_and_honors_shutdown(self):
        class BrokenStore(FakeStore):
            def claim(self, *, lease_seconds):
                stop.set()
                raise AgentTaskWorkerStoreError("database unavailable")
        stop = threading.Event()
        handler = TaskHandler("reasoning", "read_repository", lambda _item: "README.md", lambda _item, _cancelled: {"ok": True})
        worker = AgentTaskWorker(
            store=BrokenStore(), handlers={"reasoning": handler}, lease_seconds=15,
            heartbeat_interval_seconds=14,
        )
        worker.run_forever(stop, error_wait_seconds=0.001)
        self.assertTrue(stop.is_set())


if __name__ == "__main__":
    unittest.main()
