#!/bin/sh
# Rill clients only talk to Bitcoin Core and LND over numeric loopback, so each
# container forwards its local ports to the stack services first.
# RILL_FORWARD is a space-separated list of LOCAL_PORT=HOST:PORT entries.
set -eu

for entry in ${RILL_FORWARD:-}; do
    local_port=${entry%%=*}
    target=${entry#*=}
    socat "TCP-LISTEN:${local_port},bind=127.0.0.1,fork,reuseaddr" "TCP:${target}" &
done

# RILL_EXPOSE publishes loopback-only services (e.g. the merchant API) to the
# compose network: space-separated PORT=127.0.0.1:TARGET_PORT entries.
for entry in ${RILL_EXPOSE:-}; do
    port=${entry%%=*}
    target=${entry#*=}
    socat "TCP-LISTEN:${port},fork,reuseaddr" "TCP:${target}" &
done

exec "$@"
