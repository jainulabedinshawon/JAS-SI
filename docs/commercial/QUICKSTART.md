JAS-SI Commercial MVP v0.1 — Quickstart

JAS-SI provides authorization evaluation and independent evidence-integrity verification for AI-agent workflows.

This quickstart demonstrates how to verify that selected files in a GitHub repository match an immutable commit.

1. What this API verifies

The GitHub Evidence Verification endpoint:

- Accepts a GitHub repository, immutable commit SHA, and file paths.
- Retrieves the selected files from GitHub.
- Recalculates each Git blob SHA-1.
- Compares the calculated hash with GitHub's reported blob SHA.
- Returns SHA-256 fingerprints for additional evidence tracking.
- Does not modify the repository or execute actions.

Important: "EVIDENCE_INTEGRITY_VERIFIED" confirms GitHub commit and file integrity. It does not establish semantic truth, task completion, or whether an AI agent fulfilled its intended objective.

2. Requirements

- Python 3.10+
- A JAS-SI API deployment
- A valid JAS-SI API key
- A public GitHub repository for the initial demo

The API endpoint used in this guide is:

"POST /v1/github/evidence"

Protected endpoints require the "X-API-Key" HTTP header.

3. Configure your environment

Set your API URL and API key.

export JAS_SI_API_URL="https://YOUR-DEPLOYED-API"
export JAS_SI_API_KEY="YOUR_API_KEY"

Replace both values with credentials supplied by your JAS-SI deployment administrator.

Do not commit API keys to GitHub or include them in screenshots or logs.

4. Make your first request

First, identify a full 40-character commit SHA from your repository.

Then run:

curl --fail-with-body \
  --request POST \
  "$JAS_SI_API_URL/v1/github/evidence" \
  --header "Content-Type: application/json" \
  --header "X-API-Key: $JAS_SI_API_KEY" \
  --data '{
    "repository": "OWNER/REPOSITORY",
    "commit_sha": "REPLACE_WITH_40_CHARACTER_COMMIT_SHA",
    "paths": [
      "README.md"
    ]
  }'

Replace:

- "OWNER/REPOSITORY" with your GitHub repository.
- "REPLACE_WITH_40_CHARACTER_COMMIT_SHA" with the exact commit SHA.
- "README.md" with a file path that exists at that commit.

5. Example successful response

The following is an illustrative response. Hashes and commit identifiers are examples, not live verification results.

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
      "sha256": "example-sha256-fingerprint",
      "size_bytes": 1234,
      "integrity": "VERIFIED"
    }
  ],
  "read_only": true,
  "semantic_truth_verified": false
}

6. Run the Python demo

From the repository root:

python -m pip install httpx

Set the environment variables as described above, then run:

python examples/github_evidence_demo.py \
  OWNER/REPOSITORY \
  YOUR_40_CHARACTER_COMMIT_SHA \
  README.md

You can pass up to 10 file paths.

7. Common response codes

HTTP status| Meaning
200| Evidence integrity verified
401| Missing or invalid API key
404| Commit or evidence file not found
413| Evidence file exceeds the size limit
422| Invalid request or integrity validation failed
429| JAS-SI API rate limit exceeded
502| GitHub evidence service or response error
503| Service configuration or GitHub API unavailable
504| GitHub request timed out

The exact error detail is returned by the API.

8. Security and verification boundaries

- The endpoint is read-only.
- A full immutable commit SHA is required.
- GitHub redirects are not followed.
- File paths are validated.
- Evidence files are size-limited.
- Git blob integrity is independently recalculated.
- The API does not execute agent actions.
- Caller-submitted evidence is not automatically independent evidence.

9. Current MVP limitations

This release is an early commercial MVP.

It does not yet provide:

- Self-service customer registration.
- Multi-tenant API key management.
- Subscription billing.
- A hosted public dashboard.
- Distributed rate limiting.
- Semantic verification of agent objectives.

Do not treat this release as a production security certification.

10. Pilot access

For an early pilot, contact the JAS-SI project maintainer with:

- Your use case.
- Your AI-agent workflow.
- The GitHub evidence you want to verify.
- Your expected request volume.

Pilot access and API credentials must be provisioned separately.

---

JAS-SI — Reality-Based Intelligence Through Authorization, Independent Verification, and Accountable Evidence.
