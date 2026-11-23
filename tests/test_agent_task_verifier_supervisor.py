from __future__ import annotations

import threading
import unittest

from jas_si_agent.agent_host_health import AgentHostHealthState
from jas_si_agent.agent_task_verifier_supervisor import run_verifier_loop


class StopAfterWait:
    def __init__(self, stop_after: int = 1):
        self.calls = 0
        self.stop_after = stop_after

    def is_set(self):
        return False

    def wait(self, _seconds):
        self.calls += 1
        return self.calls >= self.stop_after


class FakeVerifier:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = 0

    def run_once(self):
        self.calls += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class VerifierSupervisorTests(unittest.TestCase):
    def test_rejects_invalid_poll_intervals(self):
        for interval in (0, -1, 60.1, True, "2"):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    run_verifier_loop(
                        FakeVerifier([]),
                        stop_event=threading.Event(),
                        poll_interval_seconds=interval,
                    )

    def test_runs_one_batch_then_honours_stop(self):
        outcome = type(
            "Batch", (),
            {"scanned": 2, "finalized": 1, "inconclusive": 1, "lost_finalization_race": 0},
        )()
        verifier = FakeVerifier([outcome])
        stop = StopAfterWait()
        run_verifier_loop(verifier, stop_event=stop, poll_interval_seconds=0.5)
        self.assertEqual(verifier.calls, 1)
        self.assertEqual(stop.calls, 1)

    def test_health_state_tracks_successful_verification_poll(self):
        state = AgentHostHealthState()
        outcome = type("Batch", (), {"scanned": 0, "finalized": 0, "inconclusive": 0, "lost_finalization_race": 0})()
        verifier = FakeVerifier([RuntimeError("db unavailable"), outcome])
        stop = StopAfterWait(stop_after=2)
        run_verifier_loop(verifier, stop_event=stop, poll_interval_seconds=0.5, health_state=state)
        self.assertTrue(state.is_ready())

    def test_health_state_stays_unready_when_verifier_poll_fails(self):
        state = AgentHostHealthState()
        verifier = FakeVerifier([RuntimeError("db unavailable")])
        stop = StopAfterWait()
        run_verifier_loop(verifier, stop_event=stop, poll_interval_seconds=0.5, health_state=state)
        self.assertFalse(state.is_ready())

    def test_retries_after_error_without_leaking_exception(self):
        outcome = type(
            "Batch", (),
            {"scanned": 0, "finalized": 0, "inconclusive": 0, "lost_finalization_race": 0},
        )()
        verifier = FakeVerifier([RuntimeError("secret verifier DSN"), outcome])
        stop = StopAfterWait(stop_after=2)
        run_verifier_loop(verifier, stop_event=stop, poll_interval_seconds=0.5)
        self.assertEqual(verifier.calls, 2)
        self.assertEqual(stop.calls, 2)


if __name__ == "__main__":
    unittest.main()
