"""Customer-session-bound GitHub OAuth attempt orchestration.

This layer persists before redirect and consumes before decrypting. It does
not perform the provider token exchange or Installation activation.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import urlsplit

from jas_si_agent.github_oauth import (
    GitHubOAuthError,
    build_github_oauth_authorization_request,
    create_github_oauth_attempt,
    validate_github_oauth_callback,
)
from jas_si_agent.github_oauth_crypto import (
    EncryptedGitHubOAuthVerifier,
    GitHubOAuthEncryptionError,
    GitHubOAuthVerifierCipher,
)


_SESSION_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class GitHubOAuthServiceError(ValueError):
    """OAuth service failed closed."""


@dataclass(frozen=True)
class ConsumedGitHubOAuthAttempt:
    attempt_id: uuid.UUID
    tenant_id: uuid.UUID
    account_id: uuid.UUID
    code_verifier: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "ConsumedGitHubOAuthAttempt(attempt_id=<redacted>, "
            "tenant_id=<redacted>, account_id=<redacted>, "
            "code_verifier=<redacted>)"
        )


class GitHubOAuthAttemptStore(Protocol):
    def create(
        self, *, session_digest: bytes, attempt_id: uuid.UUID,
        state_digest: bytes, verifier_ciphertext: bytes,
        verifier_key_version: str, redirect_uri_digest: bytes,
        expires_at: datetime,
    ) -> None: ...

    def consume(
        self, *, session_digest: bytes, state_digest: bytes,
        redirect_uri_digest: bytes,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, bytes, str] | None: ...


class PostgresGitHubOAuthAttemptStore:
    """Use only the customer runtime DB role and the OAuth SECURITY DEFINER API."""

    def __init__(self, dsn: str, session_pepper: bytes) -> None:
        if not isinstance(dsn, str) or not dsn.strip():
            raise GitHubOAuthServiceError("OAuth database is not configured")
        if not isinstance(session_pepper, bytes) or len(session_pepper) < 32:
            raise GitHubOAuthServiceError("Customer session pepper is unavailable")
        self._dsn = dsn.strip()
        self._pepper = session_pepper

    def session_digest(self, session_token: str) -> bytes:
        if not isinstance(session_token, str) or not _SESSION_TOKEN_RE.fullmatch(session_token):
            raise GitHubOAuthServiceError("Invalid or expired customer session")
        return hmac.new(
            self._pepper, session_token.encode("utf-8"), hashlib.sha256
        ).digest()

    def create(
        self, *, session_digest: bytes, attempt_id: uuid.UUID,
        state_digest: bytes, verifier_ciphertext: bytes,
        verifier_key_version: str, redirect_uri_digest: bytes,
        expires_at: datetime,
    ) -> None:
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT * FROM public.customer_github_oauth_attempt_create(
                         %s,%s,%s,%s,%s,%s,%s)""",
                    (session_digest, attempt_id, state_digest, verifier_ciphertext,
                     verifier_key_version, redirect_uri_digest, expires_at),
                )
                if cur.fetchone() is None:
                    raise GitHubOAuthServiceError("OAuth attempt could not be persisted")
        except GitHubOAuthServiceError:
            raise
        except Exception:
            raise GitHubOAuthServiceError(
                "OAuth attempt could not be persisted"
            ) from None

    def consume(
        self, *, session_digest: bytes, state_digest: bytes,
        redirect_uri_digest: bytes,
    ) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, bytes, str] | None:
        import psycopg
        try:
            with psycopg.connect(self._dsn) as conn, conn.cursor() as cur:
                cur.execute(
                    """SELECT * FROM public.customer_github_oauth_attempt_consume(
                         %s,%s,%s)""",
                    (session_digest, state_digest, redirect_uri_digest),
                )
                row = cur.fetchone()
            if row is None:
                return None
            return (row[0], row[1], row[2], bytes(row[3]), str(row[4]))
        except Exception:
            raise GitHubOAuthServiceError(
                "OAuth callback could not be validated"
            ) from None


class GitHubOAuthService:
    """Persist-before-redirect and consume-before-decrypt OAuth orchestration."""

    def __init__(
        self, *, store: GitHubOAuthAttemptStore,
        cipher: GitHubOAuthVerifierCipher, client_id: str,
        redirect_uri: str, attempt_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if not isinstance(attempt_ttl, timedelta) or not (
            timedelta(seconds=1) <= attempt_ttl <= timedelta(minutes=10)
        ):
            raise GitHubOAuthServiceError("OAuth attempt lifetime must be 1–600 seconds")
        self._store = store
        self._cipher = cipher
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._redirect_digest = hashlib.sha256(redirect_uri.encode("utf-8")).digest()
        self._ttl = attempt_ttl

    @staticmethod
    def _session_digest(store: GitHubOAuthAttemptStore, session_token: str) -> bytes:
        digest_method = getattr(store, "session_digest", None)
        if not callable(digest_method):
            raise GitHubOAuthServiceError("OAuth store cannot authenticate customer sessions")
        return digest_method(session_token)

    def begin(self, *, session_token: str, account) -> str:
        """Create and persist an attempt before returning GitHub's redirect URL."""
        try:
            if getattr(account, "status", None) != "active":
                raise GitHubOAuthServiceError("Active customer account required")
            tenant_id = account.tenant_id
            account_id = account.account_id
            if not isinstance(tenant_id, uuid.UUID) or not isinstance(account_id, uuid.UUID):
                raise GitHubOAuthServiceError("Authenticated customer identity is invalid")
            session_digest = self._session_digest(self._store, session_token)
            attempt = create_github_oauth_attempt()
            request = build_github_oauth_authorization_request(
                client_id=self._client_id,
                redirect_uri=self._redirect_uri,
                attempt=attempt,
            )
            attempt_id = uuid.uuid4()
            envelope = self._cipher.encrypt(
                attempt.code_verifier,
                attempt_id=attempt_id,
                tenant_id=tenant_id,
                account_id=account_id,
                redirect_uri_digest=self._redirect_digest,
            )
            expires_at = datetime.now(timezone.utc) + self._ttl
            self._store.create(
                session_digest=session_digest,
                attempt_id=attempt_id,
                state_digest=attempt.state_digest,
                verifier_ciphertext=envelope.ciphertext,
                verifier_key_version=envelope.key_version,
                redirect_uri_digest=self._redirect_digest,
                expires_at=expires_at,
            )
            return request.authorization_url
        except (GitHubOAuthServiceError, GitHubOAuthError, GitHubOAuthEncryptionError):
            raise
        except Exception:
            raise GitHubOAuthServiceError("GitHub OAuth could not be started") from None

    def consume_callback(
        self, *, session_token: str, state: str, authorization_code: str,
    ) -> ConsumedGitHubOAuthAttempt:
        """Atomically consume a session-bound attempt, then decrypt its verifier."""
        try:
            # Validate syntax before consuming the one-time database record.
            state_digest = hashlib.sha256(state.encode("ascii")).digest() if isinstance(state, str) else b""
            validate_github_oauth_callback(
                supplied_state=state,
                expected_state_digest=state_digest,
                authorization_code=authorization_code,
            )
            session_digest = self._session_digest(self._store, session_token)
            row = self._store.consume(
                session_digest=session_digest,
                state_digest=state_digest,
                redirect_uri_digest=self._redirect_digest,
            )
            if row is None:
                raise GitHubOAuthServiceError("OAuth callback is invalid, expired, or already used")
            attempt_id, tenant_id, account_id, ciphertext, key_version = row
            verifier = self._cipher.decrypt(
                EncryptedGitHubOAuthVerifier(ciphertext, key_version),
                attempt_id=attempt_id,
                tenant_id=tenant_id,
                account_id=account_id,
                redirect_uri_digest=self._redirect_digest,
            )
            return ConsumedGitHubOAuthAttempt(
                attempt_id=attempt_id, tenant_id=tenant_id,
                account_id=account_id, code_verifier=verifier,
            )
        except (GitHubOAuthServiceError, GitHubOAuthError, GitHubOAuthEncryptionError):
            raise
        except Exception:
            raise GitHubOAuthServiceError("GitHub OAuth callback was rejected") from None
