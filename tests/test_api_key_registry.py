from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from jas_si_agent.api_key_registry import (
    ApiKeyError,
    KEY_PREFIX,
    PostgresApiKeyRegistry,
    _digest,
    parse_token,
)



class TestAuditWriterBoundaryReadiness(unittest.TestCase):
    def _registry_with_boundary_row(self, row):
        cursor = FakeRegistryCursor(row)
        connection = FakeRegistryConnection(cursor)
        psycopg_module = ModuleType("psycopg")
        psycopg_module.connect = lambda dsn: connection
        registry = PostgresApiKeyRegistry(
            "postgresql://test:test@localhost/test",
            b"p" * 32,
        )
        return registry, psycopg_module

    def test_accepts_database_owned_audit_writer_boundary(self):
        row = (
            True, ["search_path=pg_catalog"], "jas_si_audit_writer_owner",
            False, False, False, False, False, False, False,
            True, True, False, False,
        )
        registry, psycopg_module = self._registry_with_boundary_row(row)
        with patch.dict(sys.modules, {"psycopg": psycopg_module}):
            self.assertTrue(registry.verify_audit_writer_boundary())

    def test_rejects_public_execute_on_audit_writer(self):
        row = (
            True, ["search_path=pg_catalog"], "jas_si_audit_writer_owner",
            False, False, False, False, False, False, False,
            True, True, True, False,
        )
        registry, psycopg_module = self._registry_with_boundary_row(row)
        with patch.dict(sys.modules, {"psycopg": psycopg_module}):
            self.assertFalse(registry.verify_audit_writer_boundary())


class FakeRegistryCursor:
    def __init__(self, row):
        self.row = row
        self.query = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=None):
        self.query = query

    def fetchone(self):
        return self.row


class FakeRegistryConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self.fake_cursor


class TestApiKeyPrimitives(unittest.TestCase):
    def test_token_round_trip(self):
        secret = bytes(range(32))
        import uuid
        key_id = uuid.uuid4()
        token = f"{KEY_PREFIX}{key_id.hex}_{base64.urlsafe_b64encode(secret).decode().rstrip('=')}"
        parsed_id, parsed_secret = parse_token(token)
        self.assertEqual(parsed_id, key_id)
        self.assertEqual(parsed_secret, secret)

    def test_noncanonical_base64url_secret_encoding_is_rejected(self):
        import uuid

        secret = bytes(range(32))
        encoded = base64.urlsafe_b64encode(secret).decode().rstrip("=")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        last = alphabet.index(encoded[-1])
        alias = encoded[:-1] + alphabet[last ^ 1]
        token = f"{KEY_PREFIX}{uuid.uuid4().hex}_{alias}"
        with self.assertRaises(ApiKeyError):
            parse_token(token)

    def test_digest_is_keyed_and_stable(self):
        secret = b"s" * 32
        pepper = b"p" * 32
        self.assertEqual(_digest(secret, pepper), _digest(secret, pepper))
        self.assertNotEqual(_digest(secret, pepper), _digest(secret, b"q" * 32))

    def test_short_pepper_rejected(self):
        with self.assertRaises(ApiKeyError):
            _digest(b"s" * 32, b"short")

    def test_malformed_token_rejected(self):
        for token in ("", "wrong", f"{KEY_PREFIX}bad_secret", f"{KEY_PREFIX}{'a'*32}_short"):
            with self.subTest(token=token):
                with self.assertRaises(ApiKeyError):
                    parse_token(token)


if __name__ == "__main__":
    unittest.main()
