# RS-010: ERC20 stablecoin profiles

Status: pre-release draft

Versions: `erc20-to-ln/v1`, `ln-to-erc20/v1`

These profiles swap an ERC20 token (USDC, USDT, or any fixed-decimals token)
on an EVM chain against a Lightning payment. The EVM leg replaces the Bitcoin
Taproot contract of RS-003 and RS-004 with a hash time-locked contract
(HTLC) on the EVM chain; the Lightning leg, sessions, discovery, transport,
and recovery container are shared with RS-003 and RS-004. The design follows
the Boltz ERC20 swap model: the same SHA-256 preimage settles both legs, the
EVM lock is keyed by all of its parameters, and the HTLC timelock is an
absolute EVM block height.

## HTLC contract

The on-chain contract is the Boltz `ERC20Swap` contract, version 6, vendored
unmodified (MIT) under `rill-contracts/`. Its relevant interface:

```
lock(bytes32 preimageHash, uint256 amount, address tokenAddress,
     address claimAddress, address refundAddress, uint256 timelock)
claim(bytes32 preimage, uint256 amount, address tokenAddress,
      address claimAddress, address refundAddress, uint256 timelock)
claim(..., uint8 v, bytes32 r, bytes32 s)        // claimAddress-signed relay
refund(bytes32 preimageHash, uint256 amount, address tokenAddress,
       address claimAddress, address refundAddress, uint256 timelock)
refundCooperative(..., uint8 v, bytes32 r, bytes32 s)
event Lockup(bytes32 indexed preimageHash, uint256 amount,
             address tokenAddress, address indexed claimAddress,
             address indexed refundAddress, uint256 timelock)
event Claim(bytes32 indexed preimageHash, bytes32 preimage)
event Refund(bytes32 indexed preimageHash)
```

A lock is identified by `keccak256(abi.encode(preimageHash, amount,
tokenAddress, claimAddress, refundAddress, timelock))`. `preimageHash` is the
SHA-256 hash of the preimage, which is the Lightning payment hash of the swap
invoice. Claim pays `amount` to `claimAddress` and requires either
`msg.sender == claimAddress` or an EIP-712 signature by `claimAddress`.
Refund requires `block.number >= timelock` and pays `refundAddress`.
Every party MUST reconstruct the lock key from its own terms, never from
counterparty-supplied call data.

Implementations MUST only interact with an HTLC contract whose address and
version are bound in the signed terms, and MUST verify the deployed bytecode
hash against the vendored artifact before the first use of a contract
address on a chain.

## EVM asset identity

`EvmAssetIdentity` (schema `common-v1.schema.json#/$defs/evmAssetIdentity`)
binds every chain-level fact the swap depends on:

| field | meaning |
| --- | --- |
| `family` | `"evm"` |
| `chain_id` | EIP-155 chain id |
| `name` | identifier such as `anvil-dev`, `base`, `arbitrum-one` |
| `htlc_contract` | lowercase `0x` address of the ERC20Swap deployment |
| `htlc_version` | `6` |
| `token_contract` | lowercase `0x` address of the ERC20 token |
| `token_symbol` | display symbol, 1 to 16 printable ASCII characters |
| `token_decimals` | 0 to 36 |
| `block_seconds` | expected average block interval used for cross-chain timing |
| `deployment_namespace` | required for chain id 31337 (local dev chains), null otherwise |

Addresses are canonical lowercase hex so that canonical JSON hashing and
comparisons never depend on EIP-55 checksums. Amounts in token base units are
decimal strings of at most 39 digits (`decimalTokenUnits`); they are never
JSON numbers.

Providers announce supported assets in the advertisement extension
`rillswap/evm-assets-v1`, whose value is an array of `EvmAssetIdentity`.
Clients MUST ignore assets whose `htlc_version` they do not implement.

## Economics

Rates are integers: `rate_token_base_per_btc` is the number of token base
units the provider exchanges for one bitcoin (100,000,000 sat). For a token
with 6 decimals at 100,000 USD per BTC the rate is `100000000000`.

`erc20-to-ln` (client locks tokens, provider pays the invoice):

```
lock_amount_token_base = ceil(lightning_principal_sat * rate / 1e8) + success_fee_token_base
```

`ln-to-erc20` (client pays a hold invoice, provider locks tokens):

```
payout_sat_equivalent = ceil(payout_token_base * 1e8 / rate)
hold_invoice_sat = payout_sat_equivalent + success_fee_sat
```

Rounding always favors the provider by at most one base unit or one
satoshi. Both objects carry every term of their equation so that any party
can recompute it. Gas is paid by the party sending each transaction: the
client pays lock gas (erc20-to-ln) or claim gas (ln-to-erc20); the provider
pays its own claim, lock, and refund gas and prices it into the success fee.
A client may instead have its claim gas paid by a third-party sponsor (see
Recovery); that arrangement is outside the signed terms and invisible to the
provider, which only ever sees `client_evm_address`.

## Contract terms

`EvmContractTerms` (schema `evm-contract-terms-v1.schema.json`) replaces
`ContractTermsV1` for these profiles. `ProviderTermsV1.contract_terms` is
either object; the `contract_hash` tagged hash is the same construction over
the canonical JSON of whichever object is present, so a terms hash never
collides across profiles because `profile_id` is part of the hashed terms.

| field | meaning |
| --- | --- |
| `protocol`, `contract_version` | `"rillswap"`, `"1"` |
| `profile_id` | `erc20-to-ln/v1` or `ln-to-erc20/v1` |
| `network_identity` | Bitcoin network of the Lightning leg (RS-001) |
| `evm_asset` | `EvmAssetIdentity` |
| `provider_identity_key` | as RS-001 |
| `client_evm_address`, `provider_evm_address` | the two HTLC parties; distinct |
| `claimant`, `refund_party` | `provider`/`client` for erc20-to-ln, `client`/`provider` for ln-to-erc20 |
| `invoice_binding` | as RS-003/RS-004; its `payment_hash` is the HTLC `preimageHash` |
| `economics` | `Erc20ToLnEconomics` or `LnToErc20Economics` |
| `htlc_timelock_block` | absolute EVM block height; refund allowed at and after it |
| `evm_reference_block`, `btc_reference_height` | heights observed by the provider when it built the terms |
| `funding_confirmations` | EVM blocks on top of the lock block before the lock counts as funded |
| `settlement_confirmations` | EVM blocks before a claim or refund counts as final |
| `recovery_authorization_xonly_key` | as RS-003 |
| `terms_expiry` | as RS-003 |
| `timing_policy` | `Erc20ToLnTiming` or `LnToErc20Timing` |
| `required_features`, `extensions` | as RS-001 |

HTLC roles: for `erc20-to-ln` the lock is
`lock(payment_hash, lock_amount_token_base, token_contract,
provider_evm_address, client_evm_address, htlc_timelock_block)`. For
`ln-to-erc20` it is `lock(payment_hash, payout_token_base, token_contract,
client_evm_address, provider_evm_address, htlc_timelock_block)`. A lockup
whose event fields differ from the terms in any field is not a funding of
the swap; the party that sent it refunds it after the timelock on its own.

### Cross-chain timing

Lightning exposure is expressed in Bitcoin blocks (RS-003/RS-004); the EVM
timelock is in EVM blocks. Terms convert through the reference heights and
`block_seconds`, with 600 s per Bitcoin block:

`erc20-to-ln` (`Erc20ToLnTiming`: `max_outgoing_htlc_expiry_height`,
`learn_and_claim_seconds`):

```
(max_outgoing_htlc_expiry_height - btc_reference_height) * 600 + learn_and_claim_seconds
    < (htlc_timelock_block - evm_reference_block) * block_seconds
```

The provider MUST have claimed, or at least broadcast a claim that will be
final within `settlement_confirmations`, before the client can refund.

`ln-to-erc20` (`LnToErc20Timing`: `min_incoming_htlc_expiry_height`,
`refund_and_ln_resolution_seconds`):

```
(htlc_timelock_block - evm_reference_block) * block_seconds + refund_and_ln_resolution_seconds
    < (min_incoming_htlc_expiry_height - btc_reference_height) * 600
```

Block intervals are not clocks. Providers MUST add their own safety margin
on top of these inequalities and MUST refuse to pay or lock when the live
heights no longer satisfy them.

## Flows

### erc20-to-ln

States: `NEGOTIATING`, `TERMS_ACCEPTED`, `RECOVERY_DURABLE`,
`LOCK_OBSERVED`, `LOCK_CONFIRMED`, `LN_PAYMENT_PENDING`, `PREIMAGE_KNOWN`,
`CLAIM_PENDING`, `COMPLETED`; `ABORTED` before a lock; `REFUND_WAIT`,
`REFUND_PENDING`, `REFUNDED` for a locked unpaid swap.

1. The client requests a quote (`kind: "erc20-to-ln"`) with the invoice,
   its `client_evm_address`, the asset (`chain_id`, `token_contract`), and
   limits (`max_success_fee_token_base`, `max_htlc_timelock_block`).
2. The provider answers with signed `EvmContractTerms`. The client verifies
   the asset against its own configuration, the economics equation, the
   timing inequality, and the deadlines, and accepts.
3. The client saves recovery material, then its EVM wallet calls `approve`
   (if needed) and `lock` with the terms' exact parameters. No funding
   binding message is required: the provider discovers the lock from the
   `Lockup(preimageHash)` log. The client MAY send the observation
   `evm_lockup_observed` to speed discovery; the provider never trusts it
   without reading the log itself.
4. The provider validates the log against the terms, waits
   `funding_confirmations`, re-checks the timing inequality against live
   heights, sends `evm_lockup_observed`, and pays the invoice under the same
   payment persistence rules as RS-003.
5. With the preimage the provider sends `payment_settled`, claims with
   `claim(...)`, and sends `claim_broadcast` with the claim transaction hash.
6. If the provider will not pay it sends `payment_failed`. The client
   refunds with `refund(...)` from `htlc_timelock_block` onward; the provider
   MAY offer `refundCooperative` earlier (future extension).

### ln-to-erc20

States: `NEGOTIATING`, `TERMS_ACCEPTED`, `RECOVERY_DURABLE`,
`HOLD_INVOICE_OPEN`, `LN_HELD`, `LOCK_PENDING`, `LOCK_CONFIRMED`,
`CLAIM_READY`, `PREIMAGE_RELEASED`, `LN_SETTLEMENT_PENDING`, `COMPLETED`;
`ABORTED` when the hold is never paid; provider refund then hold cancel
then `REFUNDED` when the client never claims.

1. The client generates the preimage, journals it encrypted, and requests a
   quote (`kind: "ln-to-erc20"`) with `payment_hash`, `payout_token_base`,
   its `client_evm_address`, the asset, and limits (`max_success_fee_sat`,
   `max_htlc_timelock_block`).
2. The provider answers with signed terms plus the hold invoice for
   `hold_invoice_sat`. The client verifies and accepts.
3. The client pays the hold invoice from any Lightning wallet.
4. When every HTLC is accepted the provider sends `hold_accepted`, locks
   tokens with the terms' exact parameters, and sends `evm_lockup_observed`
   with its lock transaction hash and log index.
5. The client reads the log itself, checks every field against the terms,
   waits `funding_confirmations`, and claims with `claim(preimage, ...)`
   from `client_evm_address`.
6. The provider observes `Claim(preimageHash, preimage)`, settles the hold
   with the preimage, and sends `hold_settled`.
7. If no claim appears before `htlc_timelock_block` the provider refunds,
   waits `settlement_confirmations`, cancels the hold, and sends
   `refund_broadcast` and `refund_confirmed` with transaction hashes.

Settlement observation payloads reuse RS-003/RS-004 kinds; EVM transaction
hashes are 32-byte lowercase hex without `0x`, like `claim_txid`. The new
kind `evm_lockup_observed` carries `lock_tx_hash`, `log_index`, and
`block_number`.

## Recovery

The recovery container (RS-007) stores the signed terms and acceptance, the
EVM asset, both EVM addresses, and the lock parameters. For `ln-to-erc20` it
also stores the encrypted preimage. A wallet that controls
`client_evm_address` can always refund (erc20-to-ln) or claim (ln-to-erc20)
from the container alone, without the provider. No EVM private key is
stored for the direct-wallet mode.

For gas-sponsored receiving, the client generates a fresh secp256k1 claim
key per swap, names its address as `client_evm_address`, and stores the key
(`claim_key`) and the user's token destination (`claim_destination`) in the
container next to the preimage. The claim is an ERC-4337 v0.7 user operation
from that address as an EIP-7702 account (delegated to a pinned contract),
batching `claim` and the ERC20 `transfer` to the destination, submitted via
an Alchemy-compatible sponsor API (`wallet_prepareCalls`,
`wallet_sendPreparedCalls`, `wallet_getCallsStatus`). The sponsor is
untrusted: the client recomputes the EIP-7702 authorization digest and the
EntryPoint user operation hash from calldata it built itself, requires the
pinned chain, delegate, EntryPoint, and live nonces, and signs nothing
opaque. The staging account never holds native coin. The sponsor learns the
preimage and the destination; the client records its exposure marker before
the first request that carries the preimage. A container holding
`claim_key` can repeat the sponsored claim without a wallet.
