LND protobufs from the signed v0.21.0-beta tag at commit
0c4a70340d21d5cd87bb77b940acb02c90f4e8e7 (MIT LICENSE in this folder).
Only lightning.proto, routerrpc/router.proto, invoicesrpc/invoices.proto and
their generated Python messages are vendored. The exact upstream Git blobs are:

  be43c88a458797728e91fbbb2f387a291ab1bc08  lnrpc/lightning.proto
  a7c1e98c15d76b0c7c0dfa569f1e2d88d572925e  lnrpc/routerrpc/router.proto
  d9d3bc12365019c814290cb25ec8df3409bfa363  lnrpc/invoicesrpc/invoices.proto

The SHA-256 values and generation dependency versions are checked by
scripts/generate_lnd_protos.py. The generated package intentionally contains
no RouterStub, InvoicesStub, or callable methods capable of a financial effect.
The invoices message descriptors include names of mutating RPC methods, but
there is no runtime invoice action adapter or permission to invoke them. This source pin is
not proof of live LND behavior or authorization to send funds.
The upstream LICENSE is also copied into the generated package and wheel.
An additional walletunlocker.proto, Git blob
f1375d45073a6405ed269edf4fc41dec9a21ed4e, is vendored only under
tests/fixtures/lnd-v0.21.0-beta for disposable-wallet interoperability.
It is never packaged with the provider runtime or invoked by the observer.
