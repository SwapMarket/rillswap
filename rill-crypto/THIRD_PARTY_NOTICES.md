# Third-party notices

`rill-crypto` builds against official `bitcoin-core/secp256k1`, licensed under
the MIT license. The exact release, source digest, commit, and enabled modules
are recorded in `vendor-manifest/secp256k1.json`.

WebAssembly builds use the Emscripten SDK toolchain pinned in
`vendor-manifest/emscripten.json`. Emscripten and its container include multiple
components with their own license notices. Release SBOM and license collection
must be generated from the exact pinned build image.

No upstream curve arithmetic is copied into RillSwap-authored source files.
