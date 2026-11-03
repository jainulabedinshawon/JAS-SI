from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from jas_si_agent.rfc3161_request import RFC3161Request
from jas_si_agent.rfc3161_response import (
    RFC3161FetchError,
    fetch_timestamp_response,
)

FAKE_REQ_BYTES = b"\x30\x03\x02\x01\x01"
FAKE_RESP_BYTES = b"\x30\x09\x02\x01\x00\x30\x04\x04\x02\xab\xcd"
TSA_URL = "https://freetsa.org/tsr"


class TestRFC3161Response(unittest.TestCase):

    def setUp(self):
        self.request = RFC3161Request(
            request_bytes=FAKE_REQ_BYTES,
            digest_algorithm="sha256",
            digest_hex="a" * 64,
            openssl_version="OpenSSL 3.0.13",
        )

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_fetch_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.headers = {"Content-Type": "application/timestamp-reply"}
        mock_resp.read.return_value = FAKE_RESP_BYTES
        mock_resp.__enter__.return_value = mock_resp

        mock_urlopen.return_value = mock_resp

        res = fetch_timestamp_response(self.request, TSA_URL)

        self.assertEqual(res.response_bytes, FAKE_RESP_BYTES)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.tsa_url, TSA_URL)

    def test_invalid_url(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(self.request, "ftp://invalid-url.com")

    def test_invalid_timeout(self):
        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(self.request, TSA_URL, timeout=-1.0)

    @patch("jas_si_agent.rfc3161_response.urllib.request.urlopen")
    def test_handles_http_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url=TSA_URL, code=503, msg="Service Unavailable", hdrs={}, fp=None
        )

        with self.assertRaises(RFC3161FetchError):
            fetch_timestamp_response(self.request, TSA_URL)


if __name__ == "__main__":
    unittest.main()
