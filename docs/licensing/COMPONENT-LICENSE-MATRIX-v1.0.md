JAS-SI Component License Matrix v1.0

Licensing Model: Hybrid / Open Core
Status: Proposed — Pending Technical Separation

1. Proprietary Core — Initial Classification

Component| Current Path| Proposed License
Authorization Engine| "src/jas_si_agent/authorization.py"| Proprietary
Verification Engine| "src/jas_si_agent/verification.py"| Proprietary
Developer SDK| "src/jas_si_agent/sdk.py"| Proprietary pending separation
REST API| "src/jas_si_agent/api.py"| Proprietary
Configuration and Security| "src/jas_si_agent/config.py" and security modules| Proprietary pending review

2. Community Edition — Candidates

Component| Proposed License| Status
Public integration examples| Apache-2.0| Candidate
Independent client SDK| Apache-2.0| Requires separation
Public API documentation| Apache-2.0| Candidate
Developer tutorials| Apache-2.0| Candidate
Public integration utilities| Apache-2.0| Requires review

3. Research Materials

Research papers, benchmark specifications, and methodology documents require separate licensing decisions.

4. Separation Requirements

- Community components must not expose proprietary implementation.
- Public SDKs must communicate with the API through documented interfaces.
- Third-party dependencies must retain their original licenses.
- Existing contributors' rights must be reviewed.
- No existing source file is relicensed by this classification document.

5. Release Rule

No Apache-2.0 LICENSE file will be applied to the entire repository until the component separation and licensing review are complete.

Next milestone: Community SDK separation and licensing review.
