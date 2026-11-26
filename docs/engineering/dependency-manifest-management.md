# Dependency Manifest Management

JAS-SI maintains several dependency manifests for different installation and verification paths. Their direct package pins must remain consistent:

- `pyproject.toml`: package metadata and direct runtime dependencies.
- `requirements.in`: input to the hash-locked deployment/runtime dependency resolution.
- `requirements.lock.txt`: generated, hash-pinned dependency set produced with Python 3.10 and pip-tools.
- `requirements.txt`: fully pinned runtime manifest consumed by deployment/test workflows that install this file.

When a direct runtime dependency changes, update the applicable source manifests and regenerate the lock using the documented command at the top of `requirements.lock.txt`. Do not hand-edit hashes in the lock file. Confirm that the fully pinned `requirements.txt` agrees with the resolved direct dependency version.

The dependency-lock verification workflow regenerates and compares `requirements.lock.txt`, installs it with hash checking, compiles source/tests, and runs the unit-test suite. `tests/test_dependency_manifest_consistency.py` additionally guards the exact `cryptography` pin across all four manifests. This guard addresses the concrete drift found during the 2026-11-26 repository audit; it is not a general resolver or vulnerability audit.

A passing manifest check establishes consistency of the tested pin, not that a dependency is vulnerability-free or that every deployment environment has installed the same artifact. Deployment evidence remains separate.
