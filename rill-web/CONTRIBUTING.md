# Contributing

The TypeScript client is an independent implementation, not generated Python
business logic. Keep runtime validation bounded, render provider text as plain
text, and preserve explicit chain-trust and recovery behavior. Bundle all
runtime assets locally.

Developer Certificate of Origin sign-off is required on commits.

`src/vendor/rill-crypto` holds the exact output of `rill-crypto/scripts/test-wasm.sh`.
After changing rill-crypto, rerun that script, copy `tmp/wasm/rill_crypto_wasm.{mjs,wasm}`
here, and regenerate `SHA256SUMS`; CI rebuilds the WASM and requires byte equality.
