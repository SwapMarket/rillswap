# Attack catalog

Known Lightning and atomic-swap attacks, what RillSwap does about each, and
the test that pins the behavior. Status values:

- **protected**: RillSwap refuses or survives the attack, as the test shows.
- **dependency-patched**: fixed in the pinned dependency; operators need at
  least the version given.
- **unsupported**: the feature the attack needs is refused.
- **residual risk**: mitigated at most; the row says what remains.

Pinned dependencies are LND `v0.21.5-beta` and Bitcoin Core `30.4`
(`dev/compose.yaml` and the pinned tests, which assert both versions).

## Invoices

| Attack | Description | Reference | Status | Test |
|---|---|---|---|---|
| Duplicate payment hash | An invoice with two `p` fields lets readers that keep the first and the last disagree on what was paid; this drained lnp2pBot. | [bolts#1357](https://github.com/lightning/bolts/pull/1357), [Stacker News](https://stacker.news/items/1576513), [lnd#11190](https://github.com/lightningnetwork/lnd/pull/11190) | protected | [`test_fields_a_first_wins_lnd_reads_differently_are_rejected`](../rill-provider/tests/test_lnd_invoice_decode.py), [`test_pinned_lnd_and_wire_reader_disagreements_are_refused`](../rill-provider/tests/test_lnd_payment_pinned.py) |
| Other duplicate or malformed fields | Repeated `s`, `x`, `c` or `n` fields, or wrong-length fields LND skips, give LND and RillSwap's reader different terms for the same bytes. Firm quotes answer `invoice_unacceptable`. | [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) | protected | [`test_wire_agreement_refuses_fields_a_first_wins_node_would_pick`](../rill-core/tests/unit/test_bolt11.py), [`test_an_ambiguous_invoice_is_rejected_not_an_outage`](../rill-provider/tests/test_handshake_service.py) |
| Repeated feature field | Two `9` fields: LND keeps the first, the published v1 vectors the last. LND paths refuse any disagreement; a browser-only reader still keeps the last. | [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) | residual risk | [`test_a_repeated_feature_field_stays_last_wins_but_cannot_disagree_with_a_node`](../rill-core/tests/unit/test_bolt11.py) |
| Batched or wrapped invoices | Several invoices concatenated, separated, prefixed or padded in one string, so a payer pays one it did not check, or all of them. | [bolts#1357](https://github.com/lightning/bolts/pull/1357) | protected | [`test_batched_or_wrapped_invoices_are_one_rejection_before_any_signature`](../rill-core/tests/unit/test_bolt11.py), [`test_batched_invoice_strings_are_rejected`](../rill-provider/tests/test_lnd_invoice_decode.py), ["batched, wrapped or padded invoice strings are one refusal"](../rill-payments/tests/bolt11Metadata.test.ts) |
| Default final CLTV mismatch | Without a `c` field BOLT 11 requires at least 18 blocks and LND assumes 24. A node may assume a longer delta, never a shorter one. | [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md), [LND `hophint.go`](https://github.com/lightningnetwork/lnd/blob/v0.21.5-beta/zpay32/hophint.go) | protected | [`test_without_a_final_cltv_field_a_node_may_assume_only_a_larger_delta`](../rill-core/tests/unit/test_bolt11.py) |
| Ambiguous invoice stored before upgrade | An invoice admitted by an older release is read again before routing and refused for good, never paid. | [bolts#1357](https://github.com/lightning/bolts/pull/1357) | protected | [`test_an_in_flight_ambiguous_invoice_is_a_final_refusal_before_routing`](../rill-provider/tests/test_lnd_payment_send.py) |
| AMP, keysend and blinded paths | Payments without one fixed payment hash, or along routes RillSwap cannot check, break the hash lock. | [LND AMP](https://docs.lightning.engineering/lightning-network-tools/lnd/amp), [Boltz fix](https://github.com/BoltzExchange/boltz-backend/commit/08bc278971b1aeeda5a3adbe4df66c88e3c36806) | unsupported | [`test_unbindable_invoices_are_rejected`](../rill-provider/tests/test_lnd_invoice_decode.py) |
| Wrong-network invoice | An invoice for another network offered to a provider. | [BOLT 11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) | protected | [`test_public_networks_bind_invoices_to_their_own_prefix`](../rill-provider/tests/test_lnd_invoice_decode.py) |

## Lightning payments

| Attack | Description | Reference | Status | Test |
|---|---|---|---|---|
| Payment hash reuse | One preimage settles two swaps, or the provider pays one hash twice. | [Boltz `SWAP_WITH_PREIMAGE_EXISTS`](https://github.com/BoltzExchange/boltz-backend/blob/4d131ef8562eea25ab687bcc75a17ce899110b66/lib/service/Errors.ts) | protected (per provider store) | [`test_only_new_paying_transition_creates_a_one_shot_grant`](../rill-provider/tests/test_payment_dispatch_store.py), [`test_reserved_hash_and_later_firm_requests_are_refused`](../rill-provider/tests/test_reverse_quote_policy.py) |
| Partial MPP settlement | Settling a hold invoice before every shard is held, or trusting a later shard's expiry instead of the earliest. | [Optech: multipath payments](https://bitcoinops.org/en/topics/multipath-payments/) | protected | [`test_accepted_aborts_unless_every_part_and_the_window_check_out`](../rill-provider/tests/test_reverse_settlement.py), [`test_accepted_total_must_be_exact_without_restricting_valid_multipart`](../rill-provider/tests/test_lnd_bound_settlement.py) |
| Hostile channel force close | A payer opens a channel to the provider, pays a hold invoice in shards and force-closes with the HTLCs held while the provider restarts. On real LND the provider still sweeps every shard with the preimage; without a settlement the payer only times them out. Fee races are the pinning and cycling rows. | [LND advisories](https://security.lightning.engineering/) | protected | [`test_settling_after_a_hostile_close_and_restart_claims_every_shard`](../rill-provider/tests/test_lnd_incoming_mpp_close_pinned.py), [`test_without_a_settlement_the_payer_times_out_every_shard`](../rill-provider/tests/test_lnd_incoming_mpp_close_pinned.py) |
| Pending-commitment failback | A direct peer combines a DoS with a race so LND fails back HTLCs that a pending commitment can still settle, stealing them. | [LND advisory](https://security.lightning.engineering/2026/08/11/lnd-pending-commitment-failback-exploit.html) | dependency-patched (0.18.0) | [`test_pinned_two_node_funded_channel_bootstrap`](../rill-provider/tests/test_lnd_payment_pinned.py) (version) |
| `update_fee` breach | A channel initiator burns a revoked high-fee commitment so the victim recovers almost nothing from the breach. | [LND advisory](https://security.lightning.engineering/2026/08/11/lnd-update-fee-breach-exploit.html) | dependency-patched (0.18.3) | [`test_pinned_two_node_funded_channel_bootstrap`](../rill-provider/tests/test_lnd_payment_pinned.py) (version) |
| HTLC sweep budget | An anchor-channel peer force-closes so outgoing HTLCs above about 50,000 sat go unswept for lack of wallet budget. | [LND advisory](https://security.lightning.engineering/2026/08/11/lnd-htlc-sweep-budget-failure.html) | dependency-patched (0.19.0) | [`test_pinned_two_node_funded_channel_bootstrap`](../rill-provider/tests/test_lnd_payment_pinned.py) (version) |
| Node denial of service | Onion bombs, gossip floods, connection floods, out-of-memory and panic bugs crash or blind the node during a swap. | [LND advisories](https://security.lightning.engineering/) | dependency-patched (0.21.1) | [`test_pinned_two_node_funded_channel_bootstrap`](../rill-provider/tests/test_lnd_payment_pinned.py) (version) |
| HTLC modifier accounting | An invoice recorded as settled while its HTLC was canceled on the wire. RillSwap uses no HTLC interceptor, modifier or channel acceptor. | [LND advisory](https://security.lightning.engineering/2026/09/21/lnd-tapd-cancelled-htlc-marked-settled.html) | unsupported | none |
| Channel jamming and hold griefing | Holding HTLCs or a hold invoice open to tie up the provider's liquidity and HTLC slots. | [Optech: channel jamming](https://bitcoinops.org/en/topics/channel-jamming-attacks/) | residual risk | [`test_accepted_waits_for_an_open_hold_until_it_expires`](../rill-provider/tests/test_reverse_settlement.py) |
| Quote and reservation exhaustion | Taking firm quotes and reservations without paying (the swap's free option), starving honest clients. Capped, not charged for. | [Optech: hold invoices](https://bitcoinops.org/en/topics/hold-invoices/) | residual risk | [`test_offer_reservations_refuse_over_budget_and_release_on_expiry`](../rill-provider/tests/test_economic_reservations.py) |
| Ambiguous payment results | Treating "not found" or a timeout as a failure, then paying again or refunding while the payment can still settle. | [lnp2pBot loss](https://stacker.news/items/1544986) | protected | [`test_non_witness_outcomes_preserve_all_authority_across_restart`](../rill-provider/tests/test_payment_reconciliation.py) |
| Route amount, fee or expiry manipulation | A route that pays more, charges more fees or locks longer than requested. | [BOLT 4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) | protected | [`test_route_bounds_are_checked_not_just_requested`](../rill-provider/tests/test_lnd_payment_send.py) |
| Dust exposure | Many trimmed HTLCs inflate what a force close burns to fees. Bounded only by LND's `channel-max-fee-exposure` (500,000 sat default). | [LND `sample-lnd.conf`](https://github.com/lightningnetwork/lnd/blob/v0.21.5-beta/sample-lnd.conf) | residual risk | none |

## On-chain contract

| Attack | Description | Reference | Status | Test |
|---|---|---|---|---|
| Timeout inversion | The Lightning HTLC expires after the on-chain refund lock, so one side can take both legs. | [BOLT 2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) | protected | [`test_contract_terms_reject_invalid_economics_roles_and_timing`](../rill-core/tests/unit/test_wire_messages.py) |
| Early refund | Refunding before the provider had its full window to claim. After maturity claim and refund race by design. | [BIP 65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki) | protected | [`test_refund_construction_requires_exact_selected_record_and_maturity`](../rill-core/tests/unit/test_recovery_inspection.py) |
| Replacement cycling | Repeatedly replacing a victim's claim out of mempools until its timelock passes. Claims are rebroadcast and fee-bumped. | [Optech: replacement cycling](https://bitcoinops.org/en/topics/replacement-cycling/) | residual risk | [`test_an_unconfirmed_claim_is_recorded_before_the_bump_is_broadcast`](../rill-provider/tests/test_claim_escalation.py) |
| Transaction pinning | Large or low-fee descendants keep a claim or refund from confirming. RillSwap uses RBF only, no TRUC or CPFP anchors. | [Optech: transaction pinning](https://bitcoinops.org/en/topics/transaction-pinning/) | residual risk | [`test_a_bump_needs_a_new_block_and_the_incremental_relay_fee`](../rill-provider/tests/test_claim_escalation.py) |
| Flood and loot | Mass force closes congest blocks until HTLCs expire. Concurrent swap exposure is capped. | [Harris and Zohar 2020](https://arxiv.org/abs/2006.08513) | residual risk | [`test_offer_reservations_refuse_over_budget_and_release_on_expiry`](../rill-provider/tests/test_economic_reservations.py) |
| Time dilation and eclipse | A stale chain view misjudges timelocks. Only nodes that report themselves unsynced or in initial download are refused. | [Riard and Naumenko 2020](https://arxiv.org/abs/2006.01418), [Optech: eclipse](https://bitcoinops.org/en/topics/eclipse-attacks/) | residual risk | [`test_submission_rechecks_expiry_sync_and_network`](../rill-provider/tests/test_lnd_payment_send.py) |
| Zero-confirmation double spend | The client double-spends unconfirmed funding after the provider paid. Only possible when the provider's signed terms accept zero confirmations. | [Optech: RBF](https://bitcoinops.org/en/topics/replace-by-fee/) | residual risk (provider policy) | [`test_funded_tip_uses_mempool_evidence_only_for_zero_conf_terms`](../rill-provider/tests/test_settlement_engine.py) |
| Reorg after payment | A deep reorg removes funding or a claim after the Lightning leg settled. | [Bitcoin Wiki](https://en.bitcoin.it/wiki/Irreversible_Transactions) | residual risk | [`test_floor_crossing_reorg_blocks_refund_even_after_restart`](../rill-provider/tests/test_reverse_scan_reorg.py) |
| Script or address substitution | A lock address whose script differs from the signed terms (wrong key, timelock or missing refund path). | [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki), [Optech: submarine swaps](https://bitcoinops.org/en/topics/submarine-swaps/) | protected | [`test_rejects_output_substitution_and_fee_violations`](../rill-core/tests/unit/test_funding.py) |
| MuSig2 nonce reuse | Signing twice with one nonce leaks the private key. | [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) | protected | [`test_musig_attempt_is_one_shot_and_final_signature_verifies`](../rill-crypto/tests/python/test_binding.py) |
| Cooperative transaction substitution | Asking the client to co-sign a key-path spend that pays elsewhere or overpays fees. Cooperative refunds are not offered. | [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) | protected | ["any changed byte, fee above the cap, or other funding is refused"](../rill-web/unit/cooperative.test.ts) |
| Fee caps and fee spikes | A claim or refund above the signed fee cap or with a dust output; caps cannot buy confirmation in a fee spike. | [Optech: fee sniping](https://bitcoinops.org/en/topics/fee-sniping/) | protected (caps), residual risk (confirmation) | [`test_builder_rejects_fee_and_preimage_policy_violations`](../rill-core/tests/unit/test_unilateral.py) |

## Clients, terms and nodes

| Attack | Description | Reference | Status | Test |
|---|---|---|---|---|
| Weak or reused client secrets | Predictable or reused preimages and keys. Clients draw them from a CSPRNG, but reuse is not regression-tested. | [Boltz `SWAP_WITH_PREIMAGE_EXISTS`](https://github.com/BoltzExchange/boltz-backend/blob/4d131ef8562eea25ab687bcc75a17ce899110b66/lib/service/Errors.ts) | residual risk | ["test-network accounts are distinct and address indices never wrap"](../rill-web/unit/browserRecoveryWallet.test.ts) |
| Lost or tampered recovery data | Refund data lost with a closed tab, or a forged recovery file. Files are authenticated; keeping them is up to the user. | [Boltz rescue file](https://github.com/BoltzExchange/boltz-web-app/blob/9cc7b2ab368148f9a74f4a90db97bdd426c39751/src/components/BackupVerifyContent.tsx) | residual risk | [`test_wrong_signed_context_or_metadata_is_rejected`](../rill-core/tests/unit/test_recovery_inspection.py) |
| Signed terms substitution or replay | Terms not signed by the advertised identity, bound to another session, or past their expiry. | [RS-001](specs/RS-001-wire-and-types.md) | protected | ["offers above a limit or bound elsewhere are refused"](../rill-web/unit/wire.test.ts) |
| EVM replay and hostile tokens | Signatures replayed on another chain or contract, fee-on-transfer or rebasing tokens, or EVM reorgs. Domain separation and a token allowlist; no fee-on-transfer detection. | [EIP-712](https://eips.ethereum.org/EIPS/eip-712) | residual risk | [`test_forward_swap_pays_once_after_the_lock_and_claims_with_the_preimage`](../rill-provider/tests/test_evm_settlement.py) |
| Bitcoin Core node bugs | Memory exhaustion and crashes in the node RillSwap trusts for chain state. | [Bitcoin Core advisories](https://bitcoincore.org/en/security-advisories/), [30.4 fix](https://bitcoincore.org/en/2026/10/28/disclose-fpausesend-oom/) | dependency-patched (30.4) | [`test_bitcoin_core_v30.py`](tests/test_bitcoin_core_v30.py) (version) |

## Operator notes

- Run LND 0.19.0 or newer for every fund-loss fix above, and 0.21.1 or newer
  for the denial-of-service fixes; the pinned 0.21.5 has both. LND itself
  refuses two payment hashes only from 0.20.5 and 0.21.4 (lnd#11190);
  RillSwap's own reader refuses them on any version.
- Run Bitcoin Core 30.4 or newer. btcd and tapd advisories do not apply:
  RillSwap uses neither.
- Incoming channel policy (minimum size, zero-confirmation channels) is LND
  configuration; RillSwap installs no channel acceptor.
- Repeated `9` fields stay last-wins in the v1 vectors, which are never
  rewritten. A v2 vector set should refuse them outright.
- If LND's decode of an admitted invoice later differs from the signed
  binding, the provider retries until the invoice expires. It never pays,
  but the swap stays open until then.
- For an invoice without `c`, the browser binds 18 blocks and the provider
  LND's 24, so such swaps fail closed at the client's terms check.
