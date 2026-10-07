#!/bin/sh
# Merchant service: provision the ledger on first start, then serve the
# rill-payments merchant API on 127.0.0.1:8787 (reached by the shop, which
# shares this container's network namespace).
set -eu
cd /src/rill-payments
config=/state/merchant/config.json
if [ ! -e /state/merchant/ledger/merchant.sqlite ]; then
    bun src/cli.ts provision "$config"
fi
exec bun src/cli.ts serve "$config"
