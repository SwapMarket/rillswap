# Releasing

The current read-only CI builds from locked dependencies, runs unit/browser
checks, then stages a deterministic ZIP and SHA-256 manifest from the same
`dist/`. It verifies the manifest, ZIP members, and a clean Pages candidate
extracted from that ZIP against every tested file. The candidate is not
deployed. Nothing is attached to a release or published to Pages yet.

Before enabling a separately reviewed publisher, an administrator must verify
release-tag creation/update/deletion rules, a protected production environment
with required reviewers, self-review/bypass restrictions and selected tag
rules, and protection of the release workflow itself. Missing GitHub
environments can be created without protection, so a tag trigger or environment
name in YAML alone is **not** an authorization gate. The privileged job must
publish the *same checked ZIP* to the release and only its verified extraction
to Pages, without rebuilding. Provenance, SBOM, recovery interoperability and
remote ZIP/Pages byte identity also remain release gates. Local checks alone
do not satisfy W12. Active swaps never silently adopt new executable code.
