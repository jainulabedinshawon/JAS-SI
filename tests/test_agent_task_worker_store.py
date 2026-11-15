from __future__ import annotations

import sys
import types
import uuid
from datetime import datetime, timezone

import pytest

from jas_si_agent.agent_task_worker_store import (
    AgentTaskLease,
    PostgresAgentTaskWorkerStore,
)


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.executed = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, params):
        self.executed = (query, params)

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row, capture):
        self.cursor_instance = FakeCursor(row)
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.capture.append(self.cursor_instance.executed)
        return False

    def cursor(self):
        return self.cursor_instance


def install_fake_psycopg(monkeypatch, row, capture):
    def connect(dsn):
        assert dsn == "postgresql://worker"
        return FakeConnection(row, capture)

    psycopg = types.ModuleType("psycopg")
    psycopg.connect = connect
    psycopg_types = types.ModuleType("psycopg.types")
    psycopg_json = types.ModuleType("psycopg.types.json")

    class Jsonb:
        def __init__(self, obj):
            self.obj = obj

    psycopg_json.Jsonb = Jsonb
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.types", psycopg_types)
    monkeypatch.setitem(sys.modules, "psycopg.types.json", psycopg_json)
    return Jsonb


def make_store():
    return PostgresAgentTaskWorkerStore(
        "postgresql://worker", uuid.UUID("00000000-0000-0000-0000-000000000001")
    )


def test_claim_maps_database_lease(monkeypatch):
    task_id = uuid.uuid4()
    expires = datetime.now(timezone.utc)
    capture = []
    install_fake_psycopg(
        monkeypatch,
        (task_id, "reasoning", {"prompt": "test"}, 1, 3, 7, expires),
        capture,
    )

    lease = make_store().claim(lease_seconds=45)

    assert lease == AgentTaskLease(
        task_id, "reasoning", {"prompt": "test"}, 1, 3, 7, expires
    )
    assert capture[0][1] == (
        uuid.UUID("00000000-0000-0000-0000-000000000001"), 45
    )
    assert "jas_si_agent_task_claim" in capture[0][0]


def test_claim_returns_none_for_empty_queue(monkeypatch):
    capture = []
    install_fake_psycopg(monkeypatch, None, capture)
    assert make_store().claim() is None


@pytest.mark.parametrize("seconds", [14, 301, True, 1.5, "60"])
def test_claim_rejects_invalid_lease_before_database(seconds):
    with pytest.raises(ValueError):
        make_store().claim(lease_seconds=seconds)


def test_renew_uses_worker_identity_and_fence(monkeypatch):
    capture = []
    install_fake_psycopg(monkeypatch, (True,), capture)
    worker_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    task_id = uuid.uuid4()

    assert make_store().renew(task_id=task_id, lease_fence=9, lease_seconds=30)
    assert capture[0][1] == (worker_id, task_id, 9, 30)
    assert "jas_si_agent_task_renew" in capture[0][0]


def test_report_is_jsonb_and_database_keeps_verification_gate(monkeypatch):
    capture = []
    Jsonb = install_fake_psycopg(monkeypatch, (True,), capture)
    task_id = uuid.uuid4()

    assert make_store().report(
        task_id=task_id, lease_fence=2, result_payload={"reported": "done"}
    )
    params = capture[0][1]
    assert isinstance(params[3], Jsonb)
    assert params[3].obj == {"reported": "done"}
    assert "jas_si_agent_task_report" in capture[0][0]


@pytest.mark.parametrize(
    "payload",
    [{"bad": float("nan")}, {"bad": object()}, {"nested": {"x": float("inf")}}],
)
def test_report_rejects_non_json_results_without_database(monkeypatch, payload):
    def forbidden_connect(_dsn):
        pytest.fail("database must not be called for invalid payloads")

    psycopg = types.ModuleType("psycopg")
    psycopg.connect = forbidden_connect
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)

    with pytest.raises(ValueError):
        make_store().report(
            task_id=uuid.uuid4(), lease_fence=1, result_payload=payload
        )


def test_acknowledge_cancel_uses_current_fence(monkeypatch):
    capture = []
    install_fake_psycopg(monkeypatch, (True,), capture)
    task_id = uuid.uuid4()

    assert make_store().acknowledge_cancel(task_id=task_id, lease_fence=4)
    assert capture[0][1][1:] == (task_id, 4)
    assert "jas_si_agent_task_ack_cancel" in capture[0][0]


def test_fail_returns_database_state(monkeypatch):
    capture = []
    install_fake_psycopg(monkeypatch, ("queued",), capture)
    task_id = uuid.uuid4()

    assert make_store().fail(
        task_id=task_id, lease_fence=3, error_code="MODEL_TIMEOUT",
        retry_delay_seconds=15,
    ) == "queued"
    assert capture[0][1][2:] == (3, "MODEL_TIMEOUT", 15)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"error_code": "lowercase"},
        {"error_code": "BAD CODE"},
        {"error_code": "x" * 65},
        {"error_code": "VALID", "retry_delay_seconds": -1},
        {"error_code": "VALID", "retry_delay_seconds": 3601},
        {"error_code": "VALID", "retry_delay_seconds": True},
    ],
)
def test_fail_rejects_invalid_arguments(kwargs):
    values = {"error_code": "VALID", "retry_delay_seconds": 0}
    values.update(kwargs)
    with pytest.raises(ValueError):
        make_store().fail(task_id=uuid.uuid4(), lease_fence=1, **values)


def test_stale_or_invalid_fencing_token_is_rejected_before_database():
    with pytest.raises(ValueError):
        make_store().renew(task_id=uuid.uuid4(), lease_fence=0)
