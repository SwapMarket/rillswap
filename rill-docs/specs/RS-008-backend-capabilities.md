# RS-008: Backend capabilities and evidence

Status: draft

Version: `0.1.0-pre.1`

Adapters report semantic capabilities, not product names. A profile MUST be
rejected before terms are offered when a required capability is unavailable.

Chain backends report network identity, best-chain tip with block hash,
outpoint and transaction observation, reorganization detection, broadcast,
fee estimation, and an evidence mode. Evidence modes are `own-node`,
`remote-chain-source`, and future versioned verified-light-client modes.
Strict own-node mode rejects provider-only and unverified remote assertions.

Lightning backends report exact support for fixed BOLT11 decoding, invoice
lookup/subscription, hold creation/settlement/cancellation, accepted HTLC part
amounts and expiries, outgoing route construction, absolute first-hop CLTV
validation, attempt tracking, and restart reconciliation.

The initial LND profile uses pinned official protobufs. Outgoing payment uses
an explicit route whose `total_time_lock` is validated against the negotiated
absolute cap before every `SendToRouteV2` submission. Intent and route are
durable first. An ambiguous result is reconciled with `TrackPaymentV2` by hash
and attempt. Cancellation of further attempts does not prove that an in-flight
HTLC cannot settle.

Incoming acceptance requires exact expected aggregate amount and inspection
of every relevant accepted HTLC expiry, including MPP parts. A backend or
version that cannot reliably expose this after restart cannot enable LN to BTC.
