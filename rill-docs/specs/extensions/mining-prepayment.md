# Mining prepayment extension

Status: draft, disabled

Identifier: `org.rillswap/mining-prepayment/v1`

The default is zero. A nonzero mining prepayment is an explicitly accepted,
bounded, irrecoverable exposure and is not principal protection, a bond, or
proof of provider behavior.

Let contract value be `V`, success fee `S`, and prepayment `M`. Implementations
MUST enforce `0 <= M <= max(S, 0)` (a negative success fee, which is a
provider rebate, forbids prepayment), use a payment hash distinct from principal, and
display the maximum loss before success. The held principal invoice amount is
`V + S - M`; total successful Lightning payment is `V + S`, excluding routing
fees. Failure to pay or verify the prepayment MUST NOT weaken base-profile
validation.
