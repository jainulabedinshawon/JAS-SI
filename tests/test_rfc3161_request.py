
from __future__ import annotations

import subprocess
import tempfile
import unittest

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jas_si_agent.rfc3161_request import (
    RFC3161RequestError,
    create_timestamp_request,
)


FAKE_DIGEST = "a" * 64
FAKE_DER_REQUEST = b"\x30\x03\x02\x01\x01"


class TestRFC3161Request(unittest.TestCase):

    def make_runtime(self):
        return SimpleNamespace(
            available=True,
            executable="/usr/bin/openssl",
            version="OpenSSL 3.0.13",
            require_available=lambda: None,
        )

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_creates_request(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()

        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("-out") + 1])
            output_path.write_bytes(FAKE_DER_REQUEST)

            return SimpleNamespace(returncode=0)

        mock_run.side_effect = fake_run

        result = create_timestamp_request(FAKE_DIGEST)

        self.assertEqual(
            result.request_bytes,
            FAKE_DER_REQUEST,
        )
        self.assertEqual(result.digest_algorithm, "sha256")
        self.assertEqual(result.digest_hex, FAKE_DIGEST)
        self.assertEqual(result.openssl_version, "OpenSSL 3.0.13")

        command = mock_run.call_args.args[0]

        self.assertEqual(command[1:3], ["ts", "-query"])
        self.assertIn("-sha256", command)
        self.assertIn("-cert", command)

        kwargs = mock_run.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    def test_rejects_non_string_digest(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(None)

    def test_rejects_short_digest(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request("a" * 63)

    def test_rejects_long_digest(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request("a" * 65)

    def test_rejects_non_hex_digest(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request("z" * 64)

    def test_normalizes_digest(self):
        self.assertEqual(
            "A" * 64 .lower(),
            "a" * 64,
        )

    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_rejects_unavailable_runtime(self, mock_runtime):
        mock_runtime.return_value = SimpleNamespace(
            available=False,
            executable=None,
            version=None,
            require_available=unavailable,
        )

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(FAKE_DIGEST)

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_handles_openssl_failure(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()
        mock_run.return_value = SimpleNamespace(returncode=1)

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(FAKE_DIGEST)

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_handles_timeout(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="openssl",
            timeout=10,
        )

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(FAKE_DIGEST)

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_rejects_missing_output(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()
        mock_run.return_value = SimpleNamespace(returncode=0)

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(FAKE_DIGEST)

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_rejects_empty_output(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()

        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("-out") + 1])
            output_path.write_bytes(b"")
            return SimpleNamespace(returncode=0)

        mock_run.side_effect = fake_run

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(FAKE_DIGEST)

    @patch("jas_si_agent.rfc3161_request.subprocess.run")
    @patch("jas_si_agent.rfc3161_request.check_openssl_runtime")
    def test_rejects_oversized_output(
        self,
        mock_runtime,
        mock_run,
    ):
        mock_runtime.return_value = self.make_runtime()

        def fake_run(command, **kwargs):
            output_path = Path(command[command.index("-out") + 1])
            output_path.write_bytes(b"x" * 2048)
            return SimpleNamespace(returncode=0)

        mock_run.side_effect = fake_run

        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(
                FAKE_DIGEST,
                max_request_bytes=1024,
            )

    def test_rejects_invalid_timeout(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(
                FAKE_DIGEST,
                timeout=0,
            )

    def test_rejects_invalid_size_limit(self):
        with self.assertRaises(RFC3161RequestError):
            create_timestamp_request(
                FAKE_DIGEST,
                max_request_bytes=100,
            )


def unavailable():
    raise RuntimeError("OpenSSL unavailable")


if __name__ == "__main__":
    unittest.main()
