# Production image: the rill-provider daemon, the rill CLI, the native crypto
# library and a Tor client for relay connections. Build from the repository
# root:
#   docker build -f rill-provider/docker/Dockerfile -t rill-provider .
# Running it is described in rill-provider/README.md (Docker section).
ARG PYTHON_IMAGE=python:3.14-slim-trixie@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c

FROM ghcr.io/astral-sh/uv:0.11.7@sha256:240fb85ab0f263ef12f492d8476aa3a2e4e1e333f7d67fbdd923d00a506a516a AS uv

FROM ${PYTHON_IMAGE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1

# Native crypto facade. CMake downloads the checksum-pinned secp256k1 release.
COPY rill-crypto/CMakeLists.txt /build/rill-crypto/CMakeLists.txt
COPY rill-crypto/c /build/rill-crypto/c
RUN cmake -S /build/rill-crypto -B /build/native -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    && cmake --build /build/native --parallel \
    && mkdir -p /opt/rill/native \
    && cp -a /build/native/librill_crypto.so* /opt/rill/native/

# Third-party runtime dependencies: binary wheels only, every hash verified.
COPY rill-provider/docker/requirements.txt rill-provider/docker/build-requirements.txt /build/
RUN uv venv --python /usr/local/bin/python3.14 /opt/venv \
    && uv pip install --python /opt/venv/bin/python --require-hashes --only-binary :all: \
        -r /build/requirements.txt

# The local packages, built with the hash-locked build backend and installed
# without dependencies so nothing outside the lock is resolved.
COPY rill-core/packages/core /build/src/rill-core
COPY rill-crypto/python /build/src/rill-crypto
COPY rill-provider/pyproject.toml rill-provider/README.md rill-provider/LICENSE /build/src/rill-provider/
COPY rill-provider/src /build/src/rill-provider/src
COPY rill-cli/pyproject.toml rill-cli/README.md /build/src/rill-cli/
COPY rill-cli/src /build/src/rill-cli/src
RUN uv venv --python /usr/local/bin/python3.14 /build/backend \
    && uv pip install --python /build/backend/bin/python --require-hashes --only-binary :all: \
        -r /build/build-requirements.txt \
    && for package in rill-core rill-crypto rill-provider rill-cli; do \
        uv build --wheel --no-build-isolation --python /build/backend/bin/python \
            --out-dir /build/wheels "/build/src/$package" || exit 1; \
    done \
    && uv pip install --python /opt/venv/bin/python --no-deps /build/wheels/*.whl

FROM ${PYTHON_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends socat tini tor \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 rill \
    && useradd --uid 1000 --gid 1000 --home-dir /rill --no-create-home --shell /usr/sbin/nologin rill \
    && install -d -o 1000 -g 1000 -m 0755 /rill \
    && install -d -o 1000 -g 1000 -m 0700 /rill/config /rill/store /rill/credentials \
        /var/lib/rill-tor
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/rill/native /opt/rill/native
COPY rill-docs/networks/mainnet.json rill-docs/networks/signet.json rill-docs/networks/testnet4.json /opt/rill/networks/
COPY rill-provider/docker/torrc /etc/rill/torrc
COPY --chmod=0755 rill-provider/docker/entrypoint.sh /usr/local/bin/rill-provider-entrypoint
COPY --chmod=0755 rill-provider/docker/healthcheck.py /usr/local/bin/rill-provider-healthcheck
COPY --chmod=0755 rill-provider/docker/init.py /usr/local/bin/rill-provider-init
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RILL_CRYPTO_LIBRARY=/opt/rill/native/librill_crypto.so
USER 1000:1000
WORKDIR /rill
ENTRYPOINT ["tini", "--", "rill-provider-entrypoint"]
CMD ["rill-provider", "--help"]
