
from __future__ import annotations

import unittest
import urllib.error

from unittest.mock import MagicMock, patch

from jas_si_agent.rfc3161_request import RFC3161TimestampRequest
from jas_si_agent.rfc3161_response import (
    RFC3161FetchError,
    fetch_timestamp_response,
)


FAKE_REQ_BYTES = b"\x30\x03\x02\x01\x01"
FAKE_RESP_BYTES = b"\x30\x09\x02\x01\x00\x30\x04\x04\x02\xab\xcd"

TSA_URL = "https://freetsa.org/tsr"


class TestRFC3161Response(unittest.TestCase):

    def setUp(self):
        self.request = RFC3161TimestampRequest(
            request_bytes=FAKE_REQ_BYTES,
            digest_algorithm="sha256",
            digest_hex="a" * 64,
            openssl_version="OpenSSL 3.0.13",
        )

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_fetch_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.headers = {
            "Content-Type": "application/timestamp-reply"
        }
        mock_resp.read.return_value = FAKE_RESP_BYTES
        mock_resp.__enter__.return_value = mock_resp

        mock_urlopen.return_value = mock_resp

        result = fetch_timestamp_response(
            self.request,
            TSA_URL,
        )

        self.assertEqual(
            result.response_bytes,
            FAKE_RESP_BYTES,
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.tsa_url, TSA_URL)
        self.assertEqual(
            result.content_type,
            "application/timestamp-reply",
        )

        mock_urlopen.assert_called_once()

    def test_invalid_url_scheme(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                "ftp://invalid-url.com",
            )

    def test_invalid_url_without_host(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                "https://",
            )

    def test_url_with_credentials_is_rejected(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                "https://user:password@example.com/tsr",
            )

    def test_url_with_fragment_is_rejected(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                "https://example.com/tsr#fragment",
            )

    def test_invalid_timeout(self):
        invalid_timeouts = [
            -1.0,
            0,
            float("inf"),
            float("nan"),
            True,
        ]

        for timeout in invalid_timeouts:
            with self.subTest(timeout=timeout):
                with self.assertRaises(RFC3161FetchError):
                    fetch_timestamp_response(
                        self.request,
                        TSA_URL,
                        timeout=timeout,
                    )

    def test_invalid_response_size_limit(self):
        invalid_limits = [
            0,
            -1,
            1048577,
            True,
            1.5,
        ]

        for limit in invalid_limits:
            with self.subTest(limit=limit):
                with self.assertRaises(RFC3161FetchError):
                    fetch_timestamp_response(
                        self.request,
                        TSA_URL,
                        max_response_bytes=limit,
                    )

    def test_invalid_request_object(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                object(),
                TSA_URL,
            )

    def test_empty_request_bytes(self):
        invalid_request = RFC3161TimestampRequest(
            request_bytes=b"",
            digest_algorithm="sha256",
            digest_hex="a" * 64,
            openssl_version="OpenSSL 3.0.13",
        )

        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                invalid_request,
                TSA_URL,
            )

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_handles_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url=TSA_URL,
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None,
        )

        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                TSA_URL,
            )

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_rejects_oversized_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.headers = {
            "Content-Type": "application/timestamp-reply"
        }
        mock_resp.read.return_value = b"A" * 11
        mock_resp.__enter__.return_value = mock_resp

        mock_urlopen.return_value = mock_resp

        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                TSA_URL,
                max_response_bytes=10,
            )

        mock_resp.read.assert_called_once_with(11)

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_rejects_empty_response(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.headers = {
            "Content-Type": "application/timestamp-reply"
        }
        mock_resp.read.return_value = b""
        mock_resp.__enter__.return_value = mock_resp

        mock_urlopen.return_value = mock_resp

        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(
                self.request,
                TSA_URL,
            )


if __name__ == "__main__":
    unittest.main()
