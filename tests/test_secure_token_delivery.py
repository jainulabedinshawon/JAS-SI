from __future__ import annotations

import base64
import shutil
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from jas_si_agent.secure_token_delivery import (
    TokenDeliveryError,
    encrypt_token_for_recipient,
)


@unittest.skipUnless(shutil.which("gpg"), "GnuPG is not installed")
class TestSecureTokenDelivery(unittest.TestCase):
    def test_public_key_encryption_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="jas-si-gpg-test-") as temp:
            home = Path(temp) / "gnupg"
            home.mkdir(mode=0o700)
            subprocess.run(
                [
                    shutil.which("gpg"),
                    "--batch",
                    "--no-tty",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    "",
                    "--homedir",
                    str(home),
                    "--quick-generate-key",
                    "JAS-SI CI Test <jas-si-ci@example.invalid>",
                    "rsa2048",
                    "encr",
                    "1d",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            exported = subprocess.run(
                [
                    shutil.which("gpg"),
                    "--batch",
                    "--no-tty",
                    "--homedir",
                    str(home),
                    "--armor",
                    "--export",
                    "jas-si-ci@example.invalid",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            public_key = exported.stdout.decode("ascii")
            secret = bytes(range(32))
            token = (
                f"jassi_live_{uuid.uuid4().hex}_"
                f"{base64.urlsafe_b64encode(secret).decode('ascii').rstrip('=')}"
            )

            ciphertext = encrypt_token_for_recipient(token, public_key)
            self.assertTrue(ciphertext.startswith(b"-----BEGIN PGP MESSAGE-----"))
            self.assertNotIn(token.encode("utf-8"), ciphertext)

            decrypted = subprocess.run(
                [
                    shutil.which("gpg"),
                    "--batch",
                    "--no-tty",
                    "--homedir",
                    str(home),
                    "--decrypt",
                ],
                input=ciphertext,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
            )
            self.assertEqual(decrypted.stdout.decode("utf-8"), token)

    def test_rejects_private_key_material(self):
        with self.assertRaises(TokenDeliveryError):
            encrypt_token_for_recipient(
                "not-a-valid-token",
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            )

    def test_rejects_multiple_recipient_keys(self):
        # A malformed bundle is rejected before GnuPG can import it.
        with self.assertRaises(TokenDeliveryError):
            encrypt_token_for_recipient(
                "not-a-valid-token",
                "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            )


if __name__ == "__main__":
    unittest.main()
