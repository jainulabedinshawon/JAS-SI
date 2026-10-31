
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.trusted_anchor_provider_profile import (
    TrustedAnchorProviderProfile,
    TrustedAnchorProviderProfileError,
)


class TestTrustedAnchorProviderProfile(unittest.TestCase):

    def make_profile(self, **overrides):
        values = {
            "provider_id": "example-provider",
            "base_url": "https://anchors.example.com",
        }
        values.update(overrides)
        return TrustedAnchorProviderProfile(**values)

    def test_accepts_valid_https_profile(self):
        profile = self.make_profile()

        self.assertEqual(
            profile.provider_id,
            "example-provider",
        )
        self.assertEqual(
            profile.base_url,
            "https://anchors.example.com",
        )

    def test_rejects_http_endpoint(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(
                base_url="http://anchors.example.com"
            )

    def test_rejects_missing_hostname(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(base_url="https://")

    def test_rejects_url_credentials(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(
                base_url="https://user:password@anchors.example.com"
            )

    def test_rejects_query_string(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(
                base_url="https://anchors.example.com?token=secret"
            )

    def test_rejects_fragment(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(
                base_url="https://anchors.example.com#fragment"
            )

    def test_rejects_invalid_provider_id(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(provider_id="invalid provider")

    def test_rejects_excessive_connect_timeout(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(connect_timeout_seconds=31)

    def test_rejects_excessive_read_timeout(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(read_timeout_seconds=61)

    def test_rejects_oversized_response_limit(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(max_response_bytes=2_000_000)

    def test_rejects_boolean_timeout(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(connect_timeout_seconds=True)

    def test_rejects_boolean_response_limit(self):
        with self.assertRaises(TrustedAnchorProviderProfileError):
            self.make_profile(max_response_bytes=True)


if __name__ == "__main__":
    unittest.main()
