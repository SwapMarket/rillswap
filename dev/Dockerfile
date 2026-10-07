# Development image for the regtest stack (dev/compose.yaml). It runs the
# makers, the `rill` CLI, the bootstrap/miner tooling and the web dev server.
# The repository is bind-mounted read-only at /src at runtime; the editable
# Python installs below resolve through that mount, so source edits apply
# after a container restart without rebuilding.
FROM oven/bun:1.3.11 AS bun

FROM python:3.14-slim-trixie

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates curl socat jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY --from=ghcr.io/astral-sh/uv:0.9.2 /uv /usr/local/bin/uv

# Native crypto facade. CMake downloads the checksum-pinned secp256k1 release.
COPY rill-crypto/CMakeLists.txt /build/rill-crypto/CMakeLists.txt
COPY rill-crypto/c /build/rill-crypto/c
RUN cmake -S /build/rill-crypto -B /build/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build/native --parallel \
    && mkdir -p /opt/rill/native \
    && cp -a /build/native/librill_crypto.so* /opt/rill/native/ \
    && rm -rf /build

# Python packages, installed editable from /src (the runtime bind mount).
COPY rill-core/packages/core /src/rill-core/packages/core
COPY rill-crypto/python /src/rill-crypto/python
COPY rill-provider /src/rill-provider
COPY rill-cli /src/rill-cli
ENV VIRTUAL_ENV=/opt/venv
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv --python /usr/local/bin/python3.14 /opt/venv \
    && cd /src/rill-cli && uv pip install --python /opt/venv/bin/python -r requirements-dev.txt

# JavaScript dependencies. Compose mounts named volumes over these
# node_modules directories, seeded from the image on first use.
COPY rill-payments/package.json rill-payments/bun.lock /src/rill-payments/
RUN cd /src/rill-payments && bun install --frozen-lockfile --ignore-scripts
COPY rill-web/package.json rill-web/bun.lock /src/rill-web/
COPY rill-payments /src/rill-payments
RUN cd /src/rill-web && bun install --frozen-lockfile --ignore-scripts

COPY dev/entrypoint.sh /usr/local/bin/rill-dev-entrypoint
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RILL_CRYPTO_LIBRARY=/opt/rill/native/librill_crypto.so
WORKDIR /src
ENTRYPOINT ["rill-dev-entrypoint"]
CMD ["sleep", "infinity"]
