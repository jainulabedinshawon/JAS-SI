"""SMTP delivery adapter for one-time JAS-SI customer identity links.

Tokens are delivered only by email and are never returned by public API routes
or written to application logs. Links place tokens in URL fragments so they
are not sent in HTTP requests or Referer headers.
"""
from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlsplit


class CustomerEmailDeliveryError(RuntimeError):
    """Raised when a customer email cannot be delivered."""


class SmtpCustomerEmailSender:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        sender: str,
        public_base_url: str,
        timeout: float = 10.0,
    ) -> None:
        if not host or not sender:
            raise ValueError("SMTP host and sender address are required")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535")
        if bool(username) != bool(password):
            raise ValueError("SMTP username and password must be configured together")
        parsed = urlsplit(public_base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("Customer public base URL must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise ValueError("Customer public base URL must use HTTPS")
        if parsed.query or parsed.fragment:
            raise ValueError("Customer public base URL must not contain query or fragment")
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.sender, self.public_base_url = sender, public_base_url.rstrip("/")
        self.timeout = timeout

    def send_link(self, *, recipient: str, purpose: str, token: str, expires_at) -> None:
        if purpose == "verify_email":
            subject = "Verify your JAS-SI account"
            fragment_key = "verify-email"
            action = "verify your email address"
        elif purpose == "login":
            subject = "Your JAS-SI sign-in link"
            fragment_key = "login"
            action = "sign in to JAS-SI"
        else:
            raise ValueError("Unsupported customer email purpose")

        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise ValueError("Invalid one-time customer token")
        link = f"{self.public_base_url}/customer#{fragment_key}={token}"
        safe_link = html.escape(link, quote=True)
        safe_expiry = html.escape(expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at))
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.sender
        message["To"] = recipient
        message.set_content(
            f"Use this one-time link to {action}:\n\n{link}\n\n"
            f"This link expires at {expires_at}. If you did not request it, ignore this email."
        )
        message.add_alternative(
            f"<p>Use this one-time link to {html.escape(action)}:</p>"
            f'<p><a href="{safe_link}">Continue to JAS-SI</a></p>'
            f"<p>This link expires at {safe_expiry}. If you did not request it, ignore this email.</p>",
            subtype="html",
        )
        try:
            if self.port == 465:
                with smtplib.SMTP_SSL(
                    self.host, self.port, timeout=self.timeout,
                    context=ssl.create_default_context(),
                ) as client:
                    if self.username:
                        client.login(self.username, self.password)
                    client.send_message(message)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as client:
                    client.ehlo()
                    client.starttls(context=ssl.create_default_context())
                    client.ehlo()
                    if self.username:
                        client.login(self.username, self.password)
                    client.send_message(message)
        except Exception as exc:
            raise CustomerEmailDeliveryError("Customer email delivery failed") from exc
