#!/bin/sh
# The provider only connects to Bitcoin Core, LND and the relay proxy over
# numeric loopback, so forward local ports to those services before starting.
# RILL_FORWARD is a space-separated list of LOCAL_PORT=HOST:PORT entries, for
# example "8332=bitcoind:8332 10009=lnd:10009 9080=rill-provider-tor:9080".
set -eu

is_port() {
    case "$1" in '' | *[!0-9]*) return 1 ;; esac
}

for entry in ${RILL_FORWARD:-}; do
    local_port=${entry%%=*}
    target=${entry#*=}
    host=${target%:*}
    if [ "$target" = "$entry" ] || [ -z "$host" ] || [ "$host" = "$target" ] \
        || ! is_port "$local_port" || ! is_port "${target##*:}"; then
        echo "rill-provider-entrypoint: invalid RILL_FORWARD entry '$entry'" >&2
        exit 2
    fi
    socat "TCP-LISTEN:${local_port},bind=127.0.0.1,fork,reuseaddr" "TCP:${target}" &
done

exec "$@"
