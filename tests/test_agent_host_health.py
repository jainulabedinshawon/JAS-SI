from __future__ import annotations

import json
import socket
import threading
import unittest
import urllib.error
import urllib.request

from jas_si_agent.agent_host_health import AgentHostHealthServer, AgentHostHealthState


class AgentHostHealthTests(unittest.TestCase):
    def setUp(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.state = AgentHostHealthState(max_staleness_seconds=2)
        self.server = AgentHostHealthServer(
            self.state, host="127.0.0.1", port=self.port
        )
        self.server.start()
        self.addCleanup(self.server.close)
        self.base = f"http://127.0.0.1:{self.port}"

    def request(self, path):
        try:
            with urllib.request.urlopen(self.base + path, timeout=2) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_liveness_is_independent_of_readiness(self):
        self.assertEqual(self.request("/health"), (200, {"status": "ok"}))
        self.assertEqual(
            self.request("/ready"),
            (503, {"status": "not_ready"}),
        )

    def test_readiness_requires_successful_poll(self):
        self.state.mark_success()
        self.assertEqual(
            self.request("/ready"),
            (200, {"status": "ready"}),
        )

    def test_failure_revokes_readiness_until_next_success(self):
        self.state.mark_success()
        self.state.mark_failure()
        self.assertEqual(
            self.request("/ready"),
            (503, {"status": "not_ready"}),
        )
        self.state.mark_success()
        self.assertEqual(
            self.request("/ready"),
            (200, {"status": "ready"}),
        )

    def test_unknown_path_is_not_found(self):
        self.assertEqual(
            self.request("/anything"),
            (404, {"status": "not_found"}),
        )

    def test_rejects_invalid_staleness_and_port(self):
        for seconds in (0, 0.9, 301):
            with self.subTest(seconds=seconds), self.assertRaises(ValueError):
                AgentHostHealthState(max_staleness_seconds=seconds)
        with self.assertRaises(ValueError):
            AgentHostHealthServer(self.state, port=65536)


if __name__ == "__main__":
    unittest.main()
