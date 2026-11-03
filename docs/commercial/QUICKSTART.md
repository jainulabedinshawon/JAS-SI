JAS-SI Commercial MVP v0.1 — Quickstart

JAS-SI provides authorization evaluation and evidence-integrity verification for AI-agent workflows.

This quickstart demonstrates how to verify that selected files in a GitHub repository match an immutable commit using the JAS-SI GitHub Evidence Verification API.

---

1. What This API Verifies

The GitHub Evidence Verification endpoint:

- Accepts a GitHub repository, immutable commit SHA, and file paths.
- Retrieves the selected files from GitHub at the specified commit.
- Recalculates each file's Git blob SHA-1.
- Compares the calculated hash with GitHub's reported blob SHA.
- Returns SHA-256 fingerprints for additional evidence tracking.
- Operates in read-only mode.
- Does not modify repositories or execute agent actions.

«Important: "EVIDENCE_INTEGRITY_VERIFIED" confirms GitHub commit and file integrity. It does not establish semantic truth, task completion, or whether an AI agent fulfilled its intended objective.»

The verification result must not be interpreted as proof that an agent's reported task outcome is correct.

---

2. Requirements

Before using the API, you need:

- Python 3.10 or later.
- A running JAS-SI API deployment.
- A valid JAS-SI API key.
- A public GitHub repository for the initial demonstration.
- A full 40-character Git commit SHA.
- One or more file paths that exist at that commit.

The endpoint used in this guide is:

"POST /v1/github/evidence"

Protected API endpoints require the "X-API-Key" HTTP header.

---

3. Configure Your Environment

Set your API URL and API key in your terminal.

Linux / macOS

export JAS_SI_API_URL="https://YOUR-DEPLOYED-API"
export JAS_SI_API_KEY="YOUR_API_KEY"

Replace both values with the actual API URL and credentials supplied by your JAS-SI deployment administrator.

Security notes:

- Use HTTPS.
- Never commit API keys to GitHub.
- Do not expose API keys in screenshots, logs, or public issue reports.
- Do not use placeholder credentials in a real request.

---

4. Make Your First API Request

First, identify a full 40-character commit SHA from your GitHub repository.

Then execute:

curl --fail-with-body \
  --request POST \
  "$JAS_SI_API_URL/v1/github/evidence" \
  --header "Content-Type: application/json" \
  --header "Accept: application/json" \
  --header "X-API-Key: $JAS_SI_API_KEY" \
  --data '{
    "repository": "OWNER/REPOSITORY",
    "commit_sha": "REPLACE_WITH_40_CHARACTER_COMMIT_SHA",
    "paths": [
      "README.md"
    ]
  }'

Replace the following values:

Placeholder| Required value
"OWNER/REPOSITORY"| Your GitHub repository in "owner/repository" format
"REPLACE_WITH_40_CHARACTER_COMMIT_SHA"| The exact full commit SHA
"README.md"| A file path that exists at the specified commit

The request supports up to 10 file paths.

---

5. Example Successful Response

The following JSON is an illustrative response showing the expected response structure.

The commit identifiers and file hashes are examples only. They are not live verification results and must not be used as actual evidence.

{
  "service": "JAS-SI Verify",
  "status": "EVIDENCE_INTEGRITY_VERIFIED",
  "verification_scope": "github_commit_and_file_integrity",
  "repository": "OWNER/REPOSITORY",
  "commit_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "tree_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "files_verified": 1,
  "files": [
    {
      "path": "README.md",
      "blob_sha": "cccccccccccccccccccccccccccccccccccccccc",
      "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "size_bytes": 1234,
      "integrity": "VERIFIED"
    }
  ],
  "read_only": true,
  "semantic_truth_verified": false
}

Understanding the result

Response field| Meaning
"status"| Overall evidence-integrity verification result
"verification_scope"| The scope of verification performed
"commit_sha"| The immutable Git commit checked
"tree_sha"| Git tree identifier reported for the commit
"files_verified"| Number of files verified
"blob_sha"| Git blob identifier reported for the file
"sha256"| SHA-256 fingerprint calculated for the file content
"integrity"| File-integrity verification result
"read_only"| Indicates that the request did not modify the repository
"semantic_truth_verified"| Indicates whether semantic truth was verified; currently "false"

A successful response establishes the stated evidence-integrity result, not the correctness of the underlying task or agent claim.

---

6. Run the Python Demo

The repository includes a minimal Python client:

"examples/github_evidence_demo.py"

From the repository root, install the required HTTP client:

python -m pip install httpx

Set the environment variables described in Section 3.

Run the demo:

python examples/github_evidence_demo.py \
  OWNER/REPOSITORY \
  YOUR_40_CHARACTER_COMMIT_SHA \
  README.md

To verify multiple files, provide additional paths:

python examples/github_evidence_demo.py \
  OWNER/REPOSITORY \
  YOUR_40_CHARACTER_COMMIT_SHA \
  README.md \
  src/main.py \
  docs/architecture.md

The demo:

- Sends a read-only verification request.
- Displays the API response.
- Checks the verification status.
- Checks that the returned file count matches the requested file count.
- Checks that each returned file has "integrity: VERIFIED".
- Confirms that semantic truth has not been claimed.

The demo exits with a non-zero status when configuration, request, or verification checks fail.

A successful client execution does not expand the verification scope of the API.

---

7. Common HTTP Response Codes

HTTP Status| Meaning
200| Evidence-integrity verification completed successfully
401| Missing or invalid API key
404| Commit or requested evidence file not found
413| Evidence file exceeds the supported size limit
422| Invalid request or evidence-integrity validation failure
429| JAS-SI API rate limit exceeded
502| GitHub evidence service or unexpected upstream response error
503| Service configuration or GitHub API unavailable
504| GitHub request timed out

The exact error detail is returned by the API response where available.

An upstream GitHub rate-limit response may be surfaced as a service-unavailable response rather than the JAS-SI API's own rate-limit response.

---

8. Security and Verification Boundaries

The current endpoint implements the following safeguards:

- Read-only GitHub evidence retrieval.
- Full immutable commit SHA validation.
- File-path validation.
- GitHub redirect following disabled.
- Evidence file size limits.
- Independent recalculation of Git blob SHA-1.
- SHA-256 fingerprint generation.
- API-key protection.
- No execution of AI-agent actions.

Important verification boundary

JAS-SI distinguishes between an agent's report and independently retrieved evidence.

However, verifying that a file matches a GitHub commit does not independently establish that:

- The code is correct.
- The requested task was completed successfully.
- The agent's reasoning was accurate.
- The system's intended objective was achieved.
- The evidence proves semantic truth.

These require additional verification mechanisms and evidence sources.

---

9. Current MVP Limitations

JAS-SI Commercial MVP v0.1 is an early-stage API offering.

The current release does not yet provide:

- Self-service customer registration.
- Multi-tenant customer and API-key management.
- Subscription billing.
- A hosted public customer dashboard.
- Distributed rate limiting.
- Semantic verification of agent objectives.
- A production security certification.

The API should be deployed and operated with appropriate infrastructure, access controls, monitoring, and secret management.

Do not interpret this MVP release as a production security certification or a guarantee of semantic correctness.

---

10. Early Pilot Access

Organizations and developers interested in testing JAS-SI can request an early pilot.

Please prepare the following information:

1. Your use case.
2. Your AI-agent workflow.
3. The GitHub evidence you want to verify.
4. Your expected API request volume.
5. Your deployment and integration requirements.

Pilot access, deployment details, and API credentials must be provisioned separately.

Commercial availability and pricing are subject to the pilot agreement.

---

11. Project Scope and Next Steps

The initial commercial direction is to provide practical evidence-integrity verification for AI-agent workflows.

The next development stages may include:

1. A reproducible end-to-end customer demonstration.
2. Hosted API deployment.
3. Controlled pilot onboarding.
4. Usage monitoring and customer-specific API keys.
5. Commercial billing and subscription support.
6. Expanded verification capabilities supported by measurable evidence.

Future capabilities will be introduced only after implementation and validation.

---

JAS-SI — Reality-Based Intelligence Through Authorization, Independent Verification, and Accountable Evidence.
