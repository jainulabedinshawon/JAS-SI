"""Unit tests for the customer SMTP delivery adapter."""
from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from jas_si_agent.customer_email import (
    CustomerEmailDeliveryError,
    SmtpCustomerEmailSender,
)


class TestCustomerEmailSender(unittest.TestCase):
    def sender(self):
        return SmtpCustomerEmailSender(
            host="smtp.example.test",
            port=587,
            username="mailer",
            password="not-a-real-password",
            sender="no-reply@example.test",
            public_base_url="https://jas-si.example.test",
        )

    def test_verification_link_uses_fragment_and_never_query(self):
        sender = self.sender()
        with patch("jas_si_agent.customer_email.smtplib.SMTP") as smtp:
            client = smtp.return_value.__enter__.return_value
            sender.send_link(
                recipient="user@example.test",
                purpose="verify_email",
                token="v" * 48,
                expires_at=datetime(2026, 11, 11, tzinfo=timezone.utc),
            )
            message = client.send_message.call_args.args[0]
        self.assertIn("#verify-email=", message.get_body(preferencelist=("plain",)).get_content())
        self.assertNotIn("?token=", message.get_body(preferencelist=("plain",)).get_content())
        self.assertEqual(message["To"], "user@example.test")

    def test_login_link_uses_login_fragment(self):
        sender = self.sender()
        with patch("jas_si_agent.customer_email.smtplib.SMTP") as smtp:
            client = smtp.return_value.__enter__.return_value
            sender.send_link(
                recipient="user@example.test",
                purpose="login",
                token="l" * 48,
                expires_at=datetime(2026, 11, 11, tzinfo=timezone.utc),
            )
            message = client.send_message.call_args.args[0]
        self.assertIn("#login=", message.get_body(preferencelist=("plain",)).get_content())

    def test_rejects_public_non_https_url(self):
        with self.assertRaises(ValueError):
            SmtpCustomerEmailSender(
                host="smtp.example.test", port=587, username=None, password=None,
                sender="no-reply@example.test", public_base_url="http://public.example.test",
            )

    def test_smtp_failure_is_wrapped_without_secret_details(self):
        sender = self.sender()
        with patch("jas_si_agent.customer_email.smtplib.SMTP", side_effect=RuntimeError("secret transport detail")):
            with self.assertRaises(CustomerEmailDeliveryError) as caught:
                sender.send_link(
                    recipient="user@example.test", purpose="login", token="l" * 48,
                    expires_at=datetime(2026, 11, 11, tzinfo=timezone.utc),
                )
        self.assertEqual(str(caught.exception), "Customer email delivery failed")


if __name__ == "__main__":
    unittest.main()
