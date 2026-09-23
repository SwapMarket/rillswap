LND protobufs from the signed v0.21.0-beta tag at commit
0c4a70340d21d5cd87bb77b940acb02c90f4e8e7 (MIT LICENSE in this folder).
Only lightning.proto and routerrpc/router.proto and their generated Python
messages are vendored. The exact upstream Git blobs are:

  be43c88a458797728e91fbbb2f387a291ab1bc08  lnrpc/lightning.proto
  a7c1e98c15d76b0c7c0dfa569f1e2d88d572925e  lnrpc/routerrpc/router.proto

The SHA-256 values and generation dependency versions are checked by
scripts/generate_lnd_protos.py. The generated package intentionally contains
no RouterStub or methods capable of initiating a payment. This source pin is
not proof of live LND behavior or authorization to send funds.
The upstream LICENSE is also copied into the generated package and wheel.
