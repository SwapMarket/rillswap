# Releasing

The read-only component checks build from locked dependencies, run
unit/browser checks, then stage a deterministic ZIP and SHA-256 manifest from
the same `dist/`. They verify the manifest, ZIP members, and a clean Pages
candidate extracted from that ZIP against every tested file. The
`Publish static RillSwap` workflow (`.github/workflows/pages.yml`) separately
tests, uploads and deploys the Pages artifact on every push to `main`. Release ZIP
publication is not automated yet.

Before running the Pages publisher or enabling release publication, an
administrator must verify
release-tag creation/update/deletion rules, a protected production environment
with required reviewers, self-review/bypass restrictions and selected tag
rules, and protection of the release workflow itself. Missing GitHub
environments can be created without protection, so a tag trigger or environment
name in YAML alone is **not** an authorization gate. The privileged job must
publish the *same checked ZIP* to the release and only its verified extraction
to Pages, without rebuilding. Provenance, SBOM, recovery interoperability and
remote ZIP/Pages byte identity are also verification requirements. Local checks alone
do not satisfy W12. Active swaps never silently adopt new executable code.
