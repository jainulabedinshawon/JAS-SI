from __future__ import annotations

import subprocess
import unittest

from unittest.mock import patch, Mock

from jas_si_agent.rfc3161_runtime import (
    RFC3161RuntimeError,
    check_openssl_runtime,
)


class TestRFC3161Runtime(unittest.TestCase):

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_accepts_supported_openssl(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=0,
            stdout="OpenSSL 3.0.13 30 Jan 2024\n",
            stderr="",
        )

        result = check_openssl_runtime()

        self.assertTrue(result.available)
        self.assertEqual(
            result.version_tuple,
            (3, 0, 13),
        )
        self.assertIsNone(result.error)

        args, kwargs = mock_run.call_args

        self.assertEqual(
            args[0],
            ["/usr/bin/openssl", "version"],
        )

        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], 5)

    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_rejects_missing_openssl(self, mock_which):
        mock_which.return_value = None

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertIsNone(result.executable)

        with self.assertRaises(RFC3161RuntimeError):
            result.require_available()

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_rejects_nonzero_exit_code(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="command failed",
        )

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertIn("non-zero", result.error)

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_rejects_malformed_version(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=0,
            stdout="not-an-openssl-version",
            stderr="",
        )

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertIsNone(result.version_tuple)

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_rejects_libressl(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=0,
            stdout="LibreSSL 3.8.2",
            stderr="",
        )

        result = check_openssl_runtime()

        self.assertFalse(result.available)

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_rejects_old_openssl(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=0,
            stdout="OpenSSL 1.0.2u 20 Dec 2019",
            stderr="",
        )

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertEqual(
            result.version_tuple,
            (1, 0, 2),
        )

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_handles_timeout(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="openssl",
            timeout=5,
        )

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertIn("timed out", result.error)

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_handles_execution_error(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.side_effect = OSError("execution failed")

        result = check_openssl_runtime()

        self.assertFalse(result.available)
        self.assertIsNotNone(result.error)

    def test_rejects_nonpositive_timeout(self):
        result = check_openssl_runtime(timeout=0)

        self.assertFalse(result.available)
        self.assertIn("positive", result.error)

    @patch("jas_si_agent.rfc3161_runtime.subprocess.run")
    @patch("jas_si_agent.rfc3161_runtime.shutil.which")
    def test_uses_fixed_arguments(
        self,
        mock_which,
        mock_run,
    ):
        mock_which.return_value = "/usr/bin/openssl"

        mock_run.return_value = Mock(
            returncode=0,
            stdout="OpenSSL 3.0.13 30 Jan 2024",
            stderr="",
        )

        check_openssl_runtime()

        args, kwargs = mock_run.call_args

        self.assertEqual(
            args[0],
            ["/usr/bin/openssl", "version"],
        )

        self.assertNotIn("shell", kwargs) if kwargs.get("shell") is None else self.assertFalse(kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
