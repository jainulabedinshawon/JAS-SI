from __future__ import annotations

import threading
import unittest

from jas_si_agent.agent_task_worker_supervisor import run_worker_loop


class StopAfterWait:
    def __init__(self, stop_after: int = 1):
        self.calls = 0
        self.stop_after = stop_after

    def is_set(self):
        return False

    def wait(self, _seconds):
        self.calls += 1
        return self.calls >= self.stop_after


class FakeWorker:
    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.calls = 0

    def run_once(self):
        self.calls += 1
        outcome = next(self.outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class WorkerSupervisorTests(unittest.TestCase):
    def test_rejects_invalid_poll_intervals(self):
        for interval in (0, -1, 60.1, True, "2"):
            with self.subTest(interval=interval):
                with self.assertRaises(ValueError):
                    run_worker_loop(
                        FakeWorker([]),
                        stop_event=threading.Event(),
                        poll_interval_seconds=interval,
                    )

    def test_runs_one_iteration_then_honours_stop(self):
        worker = FakeWorker([type("Outcome", (), {"state": "idle"})()])
        stop = StopAfterWait()
        run_worker_loop(worker, stop_event=stop, poll_interval_seconds=0.5)
        self.assertEqual(worker.calls, 1)
        self.assertEqual(stop.calls, 1)

    def test_retries_after_worker_error_without_leaking_exception(self):
        worker = FakeWorker([
            RuntimeError("secret DSN must not be logged"),
            type("Outcome", (), {"state": "idle"})(),
        ])
        stop = StopAfterWait(stop_after=2)
        run_worker_loop(worker, stop_event=stop, poll_interval_seconds=0.5)
        self.assertEqual(worker.calls, 2)
        self.assertEqual(stop.calls, 2)


if __name__ == "__main__":
    unittest.main()
