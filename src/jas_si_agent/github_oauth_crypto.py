"""Authenticated encryption for durable GitHub OAuth PKCE verifiers.

Keys are injected by the application from an external secret manager. This
module never reads keys from PostgreSQL and never persists plaintext verifiers.
"""
from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_KEY_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_PKCE_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_NONCE_BYTES = 12
_KEY_BYTES = 32
_AAD_DOMAIN = b"JAS-SI:github-oauth:pkce-verifier:v1"


class GitHubOAuthEncryptionError(ValueError):
    """OAuth verifier encryption, key selection, or authentication failed."""


@dataclass(frozen=True)
class EncryptedGitHubOAuthVerifier:
    ciphertext: bytes
    key_version: str

    def __repr__(self) -> str:
        return (
            "EncryptedGitHubOAuthVerifier(ciphertext=<redacted>, "
            "key_version=<redacted>)"
        )


@dataclass(frozen=True)
class GitHubOAuthVerifierCipher:
    """AES-256-GCM envelope bound to one OAuth attempt and tenant identity.

    Supply a keyring fetched from an external secret manager/KMS. The active
    key version selects encryption; old versions remain available only for
    decrypting outstanding attempts during a controlled rotation window.
    """

    keys: Mapping[str, bytes] = field(repr=False)
    active_key_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.keys, Mapping) or not self.keys:
            raise GitHubOAuthEncryptionError("OAuth encryption keyring is unavailable")
        if not isinstance(self.active_key_version, str) or not _KEY_VERSION_RE.fullmatch(
            self.active_key_version
        ):
            raise GitHubOAuthEncryptionError("OAuth encryption key version is invalid")
        for version, key in self.keys.items():
            if not isinstance(version, str) or not _KEY_VERSION_RE.fullmatch(version):
                raise GitHubOAuthEncryptionError("OAuth encryption key version is invalid")
            if not isinstance(key, bytes) or len(key) != _KEY_BYTES:
                raise GitHubOAuthEncryptionError("OAuth AES-256-GCM keys must be 32 bytes")
        if self.active_key_version not in self.keys:
            raise GitHubOAuthEncryptionError("Active OAuth encryption key is unavailable")

    @staticmethod
    def _aad(
        *,
        attempt_id: uuid.UUID,
        tenant_id: uuid.UUID,
        account_id: uuid.UUID,
        redirect_uri_digest: bytes,
    ) -> bytes:
        if not all(isinstance(value, uuid.UUID) for value in (attempt_id, tenant_id, account_id)):
            raise GitHubOAuthEncryptionError("OAuth attempt identity is invalid")
        if not isinstance(redirect_uri_digest, bytes) or len(redirect_uri_digest) != 32:
            raise GitHubOAuthEncryptionError("OAuth redirect binding is invalid")
        return b"\x00".join((
            _AAD_DOMAIN,
            attempt_id.bytes,
            tenant_id.bytes,
            account_id.bytes,
            redirect_uri_digest,
        ))

    def encrypt(
        self,
        verifier: str,
        *,
        attempt_id: uuid.UUID,
        tenant_id: uuid.UUID,
        account_id: uuid.UUID,
        redirect_uri_digest: bytes,
    ) -> EncryptedGitHubOAuthVerifier:
        if not isinstance(verifier, str) or not _PKCE_VERIFIER_RE.fullmatch(verifier):
            raise GitHubOAuthEncryptionError("PKCE verifier is invalid")
        aad = self._aad(
            attempt_id=attempt_id,
            tenant_id=tenant_id,
            account_id=account_id,
            redirect_uri_digest=redirect_uri_digest,
        )
        nonce = secrets.token_bytes(_NONCE_BYTES)
        ciphertext = AESGCM(self.keys[self.active_key_version]).encrypt(
            nonce, verifier.encode("ascii"), aad
        )
        return EncryptedGitHubOAuthVerifier(
            ciphertext=nonce + ciphertext,
            key_version=self.active_key_version,
        )

    def decrypt(
        self,
        envelope: EncryptedGitHubOAuthVerifier,
        *,
        attempt_id: uuid.UUID,
        tenant_id: uuid.UUID,
        account_id: uuid.UUID,
        redirect_uri_digest: bytes,
    ) -> str:
        if not isinstance(envelope, EncryptedGitHubOAuthVerifier):
            raise GitHubOAuthEncryptionError("OAuth verifier envelope is invalid")
        if (
            not isinstance(envelope.key_version, str)
            or not _KEY_VERSION_RE.fullmatch(envelope.key_version)
            or envelope.key_version not in self.keys
        ):
            raise GitHubOAuthEncryptionError("OAuth encryption key version is unavailable")
        if (
            not isinstance(envelope.ciphertext, bytes)
            or len(envelope.ciphertext) < _NONCE_BYTES + 16 + 43
            or len(envelope.ciphertext) > _NONCE_BYTES + 16 + 128
        ):
            raise GitHubOAuthEncryptionError("OAuth verifier ciphertext is invalid")
        aad = self._aad(
            attempt_id=attempt_id,
            tenant_id=tenant_id,
            account_id=account_id,
            redirect_uri_digest=redirect_uri_digest,
        )
        nonce, ciphertext = envelope.ciphertext[:_NONCE_BYTES], envelope.ciphertext[_NONCE_BYTES:]
        try:
            plaintext = AESGCM(self.keys[envelope.key_version]).decrypt(
                nonce, ciphertext, aad
            )
            verifier = plaintext.decode("ascii")
        except (InvalidTag, UnicodeDecodeError):
            raise GitHubOAuthEncryptionError(
                "OAuth verifier authentication failed"
            ) from None
        if not _PKCE_VERIFIER_RE.fullmatch(verifier):
            raise GitHubOAuthEncryptionError("Decrypted PKCE verifier is invalid")
        return verifier
