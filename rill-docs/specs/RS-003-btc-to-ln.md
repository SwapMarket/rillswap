# RS-003: BTC to Lightning profile

Status: pre-release draft

Version: `btc-to-ln/v1`

The state sequence is `NEGOTIATING`, `TERMS_ACCEPTED`, `RECOVERY_DURABLE`,
`FUNDING_OBSERVED`, `FUNDING_CONFIRMED`, `LN_PAYMENT_PENDING`,
`PREIMAGE_KNOWN`, `CLAIM_PENDING`, `COMPLETED`. Before funding a failed swap is
`ABORTED`. A funded unpaid swap proceeds through `REFUND_WAIT`,
`REFUND_PENDING`, `REFUNDED`. Ambiguous effects enter
`RECONCILIATION_REQUIRED` without erasing prior knowledge.

The user supplies a fixed-amount BOLT11 invoice from a receiver whose secret
handling the user trusts. Terms bind the decoded amount, payment hash, network,
both contract keys, fees, exact contract, confirmation count, destinations,
and deadlines. The contract value is Lightning sats plus success fee.

The user MUST durably export recovery material before funding. The provider
MUST independently validate the exact funding transaction and required best
chain confirmations before initiating payment.

For current validated height `h`, first refundable block `R`, and latest
outgoing HTLC exposure `E_out`, provider policy MUST establish
`E_out + delta_learn_and_claim < R`. It MUST persist payment intent, hash,
route, absolute exposure, attempt identity, and fee cap before submission.
An unknown RPC result is reconciled by payment hash and attempt, never retried
as a new payment merely because the call failed.

Once the provider knows a valid preimage it has unilateral claim authority.
A cooperative claim is optional. The client MUST validate the exact
transaction and valid preimage before issuing its partial signature. The UI
MUST distinguish seeing provider claim authority from independently observing
receipt by the invoice destination.

If the provider does not obtain claim authority, the user monitors through
refund eligibility, constructs or fee-bumps the unilateral refund, broadcasts,
and continues until the configured confirmation depth. The claim branch
remains valid after the refund height, so eligibility alone is not completion.
