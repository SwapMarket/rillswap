#!/usr/bin/env bash
# Regenerate requirements.txt, the hash-locked third-party runtime
# dependencies of the provider image. Versions are constrained to the
# component development locks so the image runs exactly what CI tests.
# Run after changing a pyproject.toml or a requirements-dev.txt.
set -euo pipefail
cd "$(dirname "$0")/../.."
uv pip compile --quiet --no-annotate --universal --python-version 3.14 --generate-hashes \
    --custom-compile-command rill-provider/docker/lock.sh \
    --no-emit-package rill-provider --no-emit-package rill-cli \
    --no-emit-package rill-core --no-emit-package rill-crypto \
    -c <(grep -v '^-e' rill-provider/requirements-dev.txt) \
    -c <(grep -v '^-e' rill-cli/requirements-dev.txt) \
    rill-provider/docker/requirements.in -o rill-provider/docker/requirements.txt
uv pip compile --quiet --no-annotate --universal --python-version 3.14 --generate-hashes \
    --custom-compile-command rill-provider/docker/lock.sh \
    rill-provider/docker/build-requirements.in -o rill-provider/docker/build-requirements.txt
