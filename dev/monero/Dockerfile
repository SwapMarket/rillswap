# monerod and monero-wallet-rpc from the official release tarball. The
# SHA256 comes from getmonero.org/downloads/hashes.txt, whose signature by
# binaryFate (81AC 591F E9C4 B65C 5806 AFC3 F0AF 4D46 2A0B DF92) was verified
# when pinning.
FROM debian:trixie-slim

ARG MONERO_VERSION=v0.18.5.3
ARG MONERO_SHA256=3333d0e04c9cbe3023e7e2b6dd369c407f36bb8df5b05fb0a19d7685b3d56dfc

RUN apt-get update \
    && apt-get install -y --no-install-recommends bzip2 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/monero.tar.bz2 \
        "https://downloads.getmonero.org/cli/monero-linux-x64-${MONERO_VERSION}.tar.bz2" \
    && echo "${MONERO_SHA256}  /tmp/monero.tar.bz2" | sha256sum -c - \
    && tar -xjf /tmp/monero.tar.bz2 -C /tmp \
    && install -m 0755 /tmp/monero-x86_64-linux-gnu-*/monerod /tmp/monero-x86_64-linux-gnu-*/monero-wallet-rpc /usr/local/bin/ \
    && rm -rf /tmp/monero*

CMD ["monerod", "--version"]
