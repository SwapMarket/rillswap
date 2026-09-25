# Contributing

Provider changes must preserve crash safety, idempotency, secret redaction,
reservation accounting, and reconciliation after ambiguous external effects.
Network calls must not occur inside SQLite transactions. Add focused tests and
real-node E2E coverage for money-path changes.

Developer Certificate of Origin sign-off is required on commits.
