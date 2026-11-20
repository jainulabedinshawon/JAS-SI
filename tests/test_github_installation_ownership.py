import unittest

import httpx

from jas_si_agent.github_installation_ownership import (
    GitHubInstallationOwnershipError,
    GitHubUserInstallationAccessVerifier,
)


APP_ID = 5818164


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestGitHubInstallationOwnership(unittest.TestCase):
    def test_verifies_user_and_exact_installation_and_app(self):
        def handler(request):
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 42, "login": "octocat"})
            if request.url.path == "/user/installations":
                return httpx.Response(200, json={
                    "total_count": 1,
                    "installations": [{
                        "id": 183349938,
                        "app_id": APP_ID,
                        "account": {"id": 99, "login": "octo-org", "type": "Organization"},
                    }],
                })
            return httpx.Response(404)

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler)
        )
        proof = verifier.verify(
            user_access_token="short-lived-user-token", installation_id=183349938
        )
        self.assertEqual(proof.user.user_id, 42)
        self.assertEqual(proof.user.login, "octocat")
        self.assertEqual(proof.installation_id, 183349938)
        self.assertEqual(proof.account_id, 99)
        self.assertEqual(proof.account_login, "octo-org")
        self.assertEqual(proof.account_type, "Organization")

    def test_rejects_installation_not_visible_to_authenticated_user(self):
        def handler(request):
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 42, "login": "octocat"})
            return httpx.Response(200, json={"total_count": 0, "installations": []})

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler)
        )
        with self.assertRaises(GitHubInstallationOwnershipError):
            verifier.verify(user_access_token="user-token", installation_id=183349938)

    def test_rejects_installation_from_different_app(self):
        def handler(request):
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 42, "login": "octocat"})
            return httpx.Response(200, json={
                "total_count": 1,
                "installations": [{
                    "id": 183349938,
                    "app_id": APP_ID + 1,
                    "account": {"id": 99, "login": "octo-org", "type": "Organization"},
                }],
            })

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler)
        )
        with self.assertRaises(GitHubInstallationOwnershipError):
            verifier.verify(user_access_token="user-token", installation_id=183349938)

    def test_fails_closed_on_github_api_failure_without_leaking_token(self):
        def handler(request):
            return httpx.Response(503, text="upstream error")

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler)
        )
        with self.assertRaises(GitHubInstallationOwnershipError) as exc:
            verifier.verify(
                user_access_token="do-not-leak-this", installation_id=183349938
            )
        self.assertNotIn("do-not-leak-this", str(exc.exception))

    def test_rejects_incomplete_pagination(self):
        calls = {"page": 0}

        def handler(request):
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 42, "login": "octocat"})
            calls["page"] += 1
            return httpx.Response(200, json={
                "total_count": 101,
                "installations": [{
                    "id": i + 1,
                    "app_id": APP_ID,
                    "account": {
                        "id": 99, "login": "octo-org", "type": "Organization"
                    },
                } for i in range(100)] if calls["page"] == 1 else [],
            })

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler), max_pages=1
        )
        with self.assertRaises(GitHubInstallationOwnershipError):
            verifier.verify(user_access_token="user-token", installation_id=1)



    def test_rejects_installation_count_mismatch_even_when_candidate_is_present(self):
        def handler(request):
            if request.url.path == "/user":
                return httpx.Response(200, json={"id": 42, "login": "octocat"})
            return httpx.Response(200, json={
                "total_count": 1,
                "installations": [{
                    "id": 183349938,
                    "app_id": APP_ID,
                    "account": {
                        "id": 99, "login": "octo-org", "type": "Organization"
                    },
                }, {
                    "id": 183349939,
                    "app_id": APP_ID,
                    "account": {
                        "id": 100, "login": "another-org", "type": "Organization"
                    },
                }],
            })

        verifier = GitHubUserInstallationAccessVerifier(
            expected_app_id=APP_ID, http_client=_client(handler)
        )
        with self.assertRaises(GitHubInstallationOwnershipError):
            verifier.verify(
                user_access_token="user-token", installation_id=183349938
            )

if __name__ == "__main__":
    unittest.main()
