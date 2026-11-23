from __future__ import annotations

import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from jas_si_agent.github_capability_server import build_server_config


class BrokerServerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.cert = root / "server.pem"
        self.key = root / "server-key.pem"
        self.ca = root / "client-ca.pem"
        for path in (self.cert, self.key, self.ca):
            path.write_text("test-only")
        self.env = {
            "JAS_SI_GITHUB_BROKER_TLS_CERT_PATH": str(self.cert),
            "JAS_SI_GITHUB_BROKER_TLS_KEY_PATH": str(self.key),
            "JAS_SI_GITHUB_BROKER_CLIENT_CA_PATH": str(self.ca),
            "JAS_SI_GITHUB_BROKER_BIND_HOST": "0.0.0.0",
            "JAS_SI_GITHUB_BROKER_PORT": "8787",
        }
        self.settings = SimpleNamespace(
            github_capability_broker_enabled=True,
            environment="preview",
            github_capability_broker_database_url="postgresql://broker.invalid/db?sslmode=verify-full",
            github_capability_workload_identities=object(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_builds_tls_listener_that_requires_client_certificates(self):
        config = build_server_config(environ=self.env, active_settings=self.settings)
        self.assertEqual(config.bind, ["0.0.0.0:8787"])
        self.assertEqual(config.certfile, str(self.cert))
        self.assertEqual(config.keyfile, str(self.key))
        self.assertEqual(config.ca_certs, str(self.ca))
        self.assertEqual(config.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(config.alpn_protocols, ["http/1.1"])
        self.assertEqual(config.workers, 1)

    def test_rejects_missing_or_unconfigured_staging_authority(self):
        for key, value in (
            ("github_capability_broker_enabled", False),
            ("environment", "production"),
            ("github_capability_broker_database_url", None),
            ("github_capability_workload_identities", None),
        ):
            altered = vars(self.settings).copy()
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                build_server_config(
                    environ=self.env,
                    active_settings=SimpleNamespace(**altered),
                )

    def test_rejects_missing_tls_file(self):
        env = dict(self.env)
        env["JAS_SI_GITHUB_BROKER_CLIENT_CA_PATH"] = str(Path(self.temp.name) / "missing.pem")
        with self.assertRaises(RuntimeError):
            build_server_config(environ=env, active_settings=self.settings)

    def test_rejects_invalid_port(self):
        env = dict(self.env)
        env["JAS_SI_GITHUB_BROKER_PORT"] = "70000"
        with self.assertRaises(RuntimeError):
            build_server_config(environ=env, active_settings=self.settings)


if __name__ == "__main__":
    unittest.main()
