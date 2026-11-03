
from __future__ import annotations

import tempfile
import unittest

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jas_si_agent.rfc3161_request import RFC3161TimestampRequest
from jas_si_agent.rfc3161_response import RFC3161Response
from jas_si_agent.rfc3161_verifier import (
    RFC3161VerificationError,
    verify_timestamp_response,
)


FAKE_DIGEST = "a" * 64
FAKE_REQUEST = b"\x30\x03\x02\x01\x01"
FAKE_RESPONSE = b"\x30\x09\x02\x01\x00\x30\x04\x04\x02\xab\xcd"
TSA_URL = "https://freetsa.org/tsr"


class TestRFC3161Verifier(unittest.TestCase):

    def setUp(self):
        self.request = RFC3161TimestampRequest(
            request_bytes=FAKE_REQUEST,
            digest_algorithm="sha256",
            digest_hex=FAKE_DIGEST,
            openssl_version="OpenSSL 3.0.13",
        )

        self.response = RFC3161Response(
            response_bytes=FAKE_RESPONSE,
            tsa_url=TSA_URL,
            status_code=200,
            content_type="application/timestamp-reply",
        )

        self.temp_dir = tempfile.TemporaryDirectory()
        self.trust_store = Path(self.temp_dir.name) / "trust.pem"
        self.trust_store.write_text(
            "TEST TRUST STORE",
            encoding="ascii",
        )

        self.runtime = SimpleNamespace(
            available=True,
            executable="/usr/bin/openssl",
            version="OpenSSL 3.0.13",
            require_available=lambda: None,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("jas_si_agent.rfc3161_verifier.subprocess.run")
    @patch("jas_si_agent.rfc3161_verifier.check_openssl_runtime")
    def test_successful_crypto_check_remains_indeterminate(
        self, mock_runtime, mock_run
    ):
        mock_runtime.return_value = self.runtime
        mock_run.return_value = SimpleNamespace(returncode=0)

        result = verify_timestamp_response(
            self.response,
            self.request,
            FAKE_DIGEST,
            trust_store=self.trust_store,
        )

        self.assertTrue(result.cryptographic_valid)
        self.assertEqual(result.status, "INDETERMINATE")
        self.assertEqual(result.digest_hex, FAKE_DIGEST)
        self.assertEqual(result.tsa_url, TSA_URL)
        self.assertEqual(
            result.openssl_version,
            "OpenSSL 3.0.13",
        )

        command = mock_run.call_args.args[0]

        self.assertEqual(command[1:3], ["ts", "-verify"])
        self.assertIn("-queryfile", command)
        self.assertIn("-in", command)
        self.assertIn("-CAfile", command)

        kwargs = mock_run.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], -3)

    @patch("jas_si_agent.rfc3161_verifier.subprocess.run")
    @patch("jas_si_agent.rfc3161_verifier.check_openssl_runtime")
    def test_openssl_failure_never_returns_valid(
        self, mock_runtime, mock_run
    ):
        mock_runtime.return_value = self.runtime
        mock_run.return_value = SimpleNamespace(returncode=1)

        result = verify_timestamp_response(
            self.response,
            self.request,
            FAKE_DIGEST,
            trust_store=self.trust_store,
        )

        self.assertIsNone(result.cryptographic_valid)
        self.assertEqual(result.status, "INDETERMINATE")

    def test_rejects_wrong_digest(self):
        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                self.response,
                self.request,
                "b" * 64,
                trust_store=self.trust_store,
            )

    def test_rejects_invalid_digest(self):
        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                self.response,
                self.request,
                "short",
                trust_store=self.trust_store,
            )

    def test_rejects_empty_response(self):
        bad_response = RFC3161Response(
            response_bytes=b"",
            tsa_url=TSA_URL,
            status_code=200,
            content_type="application/timestamp-reply",
        )

        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                bad_response,
                self.request,
                FAKE_DIGEST,
                trust_store=self.trust_store,
            )

    def test_rejects_wrong_content_type(self):
        bad_response = RFC3161Response(
            response_bytes=FAKE_RESPONSE,
            tsa_url=TSA_URL,
            status_code=200,
            content_type="application/octet-stream",
        )

        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                bad_response,
                self.request,
                FAKE_DIGEST,
                trust_store=self.trust_store,
            )

    def test_rejects_non_200_status(self):
        bad_response = RFC3161Response(
            response_bytes=FAKE_RESPONSE,
            tsa_url=TSA_URL,
            status_code=500,
            content_type="application/timestamp-reply",
        )

        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                bad_response,
                self.request,
                FAKE_DIGEST,
                trust_store=self.trust_store,
            )

    def test_rejects_missing_trust_store(self):
        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                self.response,
                self.request,
                FAKE_DIGEST,
                trust_store=Path(self.temp_dir.name) / "missing.pem",
            )

    def test_rejects_invalid_timeout(self):
        with self.assertRaises(RFC3161VerificationError):
            verify_timestamp_response(
                self.response,
                self.request,
                FAKE_DIGEST,
                trust_store=self.trust_store,
                timeout=0,
            )


if __name__ == "__main__":
    unittest.main()
