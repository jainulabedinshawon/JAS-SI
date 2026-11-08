"""End-to-end encryption for one-time JAS-SI API tokens.

Only an operator-held OpenPGP public key is accepted. The raw token is passed
to GnuPG over stdin and is never written to disk by this module.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from jas_si_agent.api_key_registry import ApiKeyError, parse_token


class TokenDeliveryError(ValueError):
    """Raised when a one-time token cannot be safely encrypted."""


def encrypt_token_for_recipient(token: str, public_key_armored: str) -> bytes:
    """Return an ASCII-armored OpenPGP ciphertext for exactly one public key."""
    try:
        parse_token(token)
    except ApiKeyError:
        raise TokenDeliveryError("Refusing to encrypt a malformed API token") from None

    if not isinstance(public_key_armored, str):
        raise TokenDeliveryError("An armored OpenPGP public key is required")
    public_key = public_key_armored.encode("utf-8")
    if (
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----" not in public_key
        or b"-----BEGIN PGP PRIVATE KEY BLOCK-----" in public_key
    ):
        raise TokenDeliveryError("Only an OpenPGP public key is accepted")

    gpg = shutil.which("gpg")
    if not gpg:
        raise TokenDeliveryError("OpenPGP encryption is unavailable")

    try:
        with tempfile.TemporaryDirectory(prefix="jas-si-gpg-") as temp_dir:
            os.chmod(temp_dir, 0o700)
            home = Path(temp_dir) / "gnupg"
            home.mkdir(mode=0o700)

            imported = subprocess.run(
                [gpg, "--batch", "--no-tty", "--homedir", str(home), "--import"],
                input=public_key,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            if imported.returncode != 0:
                raise TokenDeliveryError("OpenPGP public-key import failed")

            listed = subprocess.run(
                [
                    gpg, "--batch", "--no-tty", "--homedir", str(home),
                    "--with-colons", "--fingerprint", "--list-keys",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            if listed.returncode != 0:
                raise TokenDeliveryError("OpenPGP recipient validation failed")

            primary_fingerprints: list[str] = []
            awaiting_primary_fingerprint = False
            for line in listed.stdout.decode("utf-8", errors="strict").splitlines():
                fields = line.split(":")
                if fields[0] == "pub":
                    awaiting_primary_fingerprint = True
                elif fields[0] == "fpr" and awaiting_primary_fingerprint:
                    fingerprint = fields[9].upper()
                    if not re.fullmatch(r"[0-9A-F]{40,64}", fingerprint):
                        raise TokenDeliveryError("Invalid OpenPGP fingerprint")
                    primary_fingerprints.append(fingerprint)
                    awaiting_primary_fingerprint = False

            if len(primary_fingerprints) != 1:
                raise TokenDeliveryError(
                    "Exactly one OpenPGP recipient key must be supplied"
                )

            ciphertext_path = Path(temp_dir) / "token.asc"
            encrypted = subprocess.run(
                [
                    gpg, "--batch", "--no-tty", "--homedir", str(home),
                    "--trust-model", "always", "--armor", "--encrypt",
                    "--recipient", primary_fingerprints[0],
                    "--output", str(ciphertext_path),
                ],
                input=token.encode("utf-8"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            if encrypted.returncode != 0 or not ciphertext_path.is_file():
                raise TokenDeliveryError("OpenPGP token encryption failed")

            ciphertext = ciphertext_path.read_bytes()
            if not ciphertext.startswith(b"-----BEGIN PGP MESSAGE-----"):
                raise TokenDeliveryError("Encrypted token output is invalid")
            if token.encode("utf-8") in ciphertext:
                raise TokenDeliveryError("Plaintext token detected in ciphertext")
            return ciphertext
    except TokenDeliveryError:
        raise
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise TokenDeliveryError(
            "Secure token encryption failed; do not deliver the token"
        ) from None
