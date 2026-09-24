# Releasing

Provider releases require migration and upgrade tests, crash/reconciliation
coverage, the pinned cross-repository integration manifest, real Core and LND
E2E results, dependency and image SBOMs, and documented recovery drills.

`integration-lock.json` and `scripts/check_integration_lock.py` establish a
local pinned historical baseline, **not** a release sign-off or hosted CI.
The consumed native and provider-wheel hashes are produced in the receipt,
not preapproved release artifacts. Supply immutable remote artifacts and
extend coverage to funded two-direction trials and upgrade/recovery before
calling a release reproducible or production ready.
