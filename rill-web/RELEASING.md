# Releasing

The current read-only CI builds from locked dependencies, runs unit/browser
checks, then stages a deterministic ZIP and SHA-256 manifest from the same
`dist/`. It checks that every ZIP member has exactly the tested build bytes.
Nothing is attached to a release or deployed to Pages yet. Before a release,
an authorized, separately reviewed workflow must publish this **same staged
artifact** to both destinations, enforce tag/release permissions, and check
provenance, SBOM, recovery interop, and ZIP/Pages artifact identity. The local
check alone does not satisfy W12. Active swaps never silently adopt new
executable code.
