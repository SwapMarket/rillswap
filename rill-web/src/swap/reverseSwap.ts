/**
 * Browser LN to BTC (RS-004) price discovery. An indicative quote names only
 * the payout: no payment hash, keys, or destination leave the browser, and
 * nobody is committed. RS-004 requires the preimage to be durably saved
 * before any firm request, so firm terms (checkReverseTermsOffer) belong to
 * execution, after persistence, never to this step.
 */
import { verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { handshake } from "./handshake";
import { type RelayLink, Session, SwapError } from "./session";
import type { SwapRequest } from "./swap";
import { MAX_SATS, ProtocolError, requireShape, sats } from "./wire";
import type { PreparedReverseExecution, ReverseExecutionConfiguration } from "./reverseExecution";

export const REVERSE_PROFILE = "ln-to-btc/v1";

export interface ReverseLimitsInput {
  readonly maxSuccessFeeSat: bigint;
  readonly minClaimFeeReserveSat: bigint;
  readonly maxClaimFeeSat: bigint;
  /** The provider may not refund before this many blocks pass. */
  readonly minRefundDelayBlocks: number;
  /** The Lightning payment may stay held at most this many blocks. */
  readonly maxIncomingHtlcDelayBlocks: number;
}

export interface ReverseSwapRequest {
  readonly identity: string;
  readonly network: SwapRequest["network"];
  readonly payoutSat: bigint;
  readonly limits: ReverseLimitsInput;
}

/** Indicative: authenticated as this provider's session, but committing nobody. */
export interface ReverseQuote {
  readonly providerIdentity: string;
  readonly providerSlot: string;
  readonly payoutSat: bigint;
  /** What the user's Lightning wallet pays, before its own routing fees. */
  readonly holdInvoiceSat: bigint;
  readonly successFeeSat: bigint;
  readonly claimFeeReserveSat: bigint;
  readonly fundingConfirmations: number;
  readonly refundDelayBlocks: number;
  readonly incomingHtlcExpiryDeltaBlocks: number;
  readonly expiresAt: number;
}

export interface PreparedReverseQuote {
  readonly quote: ReverseQuote;
  prepareExecution(configuration: ReverseExecutionConfiguration): Promise<PreparedReverseExecution>;
  dispose(): void;
}

interface ReverseQuoteOffer {
  readonly kind: "ln-to-btc";
  readonly economics: {
    readonly contract_amount_sat: string; readonly nominal_payout_sat: string; readonly claim_fee_reserve_sat: string;
    readonly success_fee_sat: string; readonly mining_prepayment_sat: string; readonly hold_invoice_sat: string;
  };
  readonly funding_confirmations: number;
  readonly refund_delay_blocks: number;
  readonly incoming_htlc_expiry_delta_blocks: number;
  readonly max_claim_fee_sat: string;
  readonly expires_at: number;
}

/** ReverseQuoteOffer model rules plus the client's limits; refuses anything it could not later accept. */
export function checkReverseQuoteOffer(payload: unknown, request: Omit<ReverseSwapRequest, "identity">, now: number): ReverseQuoteOffer {
  const offer = requireShape<ReverseQuoteOffer>("validateReverseQuoteOffer", payload);
  const economics = offer.economics;
  const contract = sats(economics.contract_amount_sat, "contract amount", true);
  const payout = sats(economics.nominal_payout_sat, "payout", true);
  const reserve = sats(economics.claim_fee_reserve_sat, "claim fee reserve");
  const fee = sats(economics.success_fee_sat, "success fee");
  const prepayment = sats(economics.mining_prepayment_sat, "mining prepayment");
  const hold = sats(economics.hold_invoice_sat, "hold invoice", true);
  if (payout + reserve !== contract || prepayment > fee || contract + fee > MAX_SATS || contract + fee - prepayment !== hold) {
    throw new ProtocolError("quote economics are inconsistent");
  }
  if (prepayment !== 0n) throw new ProtocolError("mining prepayment is not supported");
  if (offer.incoming_htlc_expiry_delta_blocks <= offer.refund_delay_blocks) {
    throw new ProtocolError("incoming HTLC expiry must be after the refund delay");
  }
  const { limits } = request;
  const checks: [boolean, string][] = [
    [payout === request.payoutSat, "payout"],
    [fee <= limits.maxSuccessFeeSat, "success fee"],
    [reserve >= limits.minClaimFeeReserveSat, "claim fee reserve"],
    [sats(offer.max_claim_fee_sat, "claim fee") <= limits.maxClaimFeeSat, "claim fee"],
    [offer.refund_delay_blocks >= limits.minRefundDelayBlocks, "refund delay"],
    [offer.incoming_htlc_expiry_delta_blocks <= limits.maxIncomingHtlcDelayBlocks, "Lightning hold"],
    [offer.expires_at > now, "expiry"],
  ];
  for (const [ok, what] of checks) if (!ok) throw new ProtocolError(`quote does not honor request: ${what}`);
  return offer;
}

function checkReverseRequest(request: Omit<ReverseSwapRequest, "identity">): void {
  if (request.network.name === "mainnet") throw new SwapError("mainnet is not release-accepted; the web client refuses it");
  if (request.payoutSat <= 0n || request.payoutSat > MAX_SATS) throw new SwapError("payout invalid");
  const { minRefundDelayBlocks: refund, maxIncomingHtlcDelayBlocks: incoming } = request.limits;
  if (!Number.isSafeInteger(refund) || refund <= 0 || !Number.isSafeInteger(incoming) || incoming <= refund) {
    throw new SwapError("the maximum hold must exceed the minimum refund delay");
  }
}

export async function prepareReverseQuote(
  relay: RelayLink,
  request: ReverseSwapRequest,
  options: { readonly announcement: string; readonly replyMs?: number; readonly clock?: () => number },
): Promise<PreparedReverseQuote> {
  request = structuredClone(request);
  checkReverseRequest(request);
  const clock = options.clock ?? Date.now;
  const { identity, network } = request;
  const provider = verifyNostrProviderAnnouncement(options.announcement, identity, network, REVERSE_PROFILE);
  const session = new Session(relay, network, REVERSE_PROFILE, options.replyMs ?? 15_000, clock);
  try {
    await handshake(session, provider, identity);
    const indicative = requireShape<Record<string, unknown>>("validateReverseIndicativeQuoteRequest",
      { kind: "ln-to-btc", mode: "indicative", nominal_payout_sat: request.payoutSat.toString(), extensions: {} });
    const envelope = session.envelope("quote_request", indicative);
    await session.send(envelope, session.providerKey!);
    const answer = await session.replyTo(envelope, "quote_offer");
    const offer = checkReverseQuoteOffer(answer.payload, request, Math.floor(clock() / 1000));
    const economics = offer.economics;
    let used = false, disposed = false;
    let firmSession: Session | undefined;
    return Object.freeze({
      quote: Object.freeze({
        providerIdentity: identity,
        providerSlot: provider.slot,
        payoutSat: BigInt(economics.nominal_payout_sat),
        holdInvoiceSat: BigInt(economics.hold_invoice_sat),
        successFeeSat: BigInt(economics.success_fee_sat),
        claimFeeReserveSat: BigInt(economics.claim_fee_reserve_sat),
        fundingConfirmations: offer.funding_confirmations,
        refundDelayBlocks: offer.refund_delay_blocks,
        incomingHtlcExpiryDeltaBlocks: offer.incoming_htlc_expiry_delta_blocks,
        expiresAt: offer.expires_at,
      }),
      prepareExecution: async (configuration: ReverseExecutionConfiguration) => {
        configuration.assertCurrent();
        if (used || disposed || Math.floor(clock() / 1000) >= offer.expires_at) throw new SwapError("Estimate already used, expired, or discarded"); used = true;
        session.secret.fill(0);
        const { prepareReverseExecution } = await import("./reverseExecution");
        configuration.assertCurrent(); if (disposed) throw new SwapError("Estimate discarded");
        // RS-003/RS-004 require firm requests to be the first quote in a NEW
        // session. Pin the selected provider, never its indicative session key.
        firmSession = new Session(relay, network, REVERSE_PROFILE, options.replyMs ?? 15_000, clock);
        try {
          const agreed = await handshake(firmSession, provider, identity);
          configuration.assertCurrent(); if (disposed) throw new SwapError("Estimate discarded");
          return await prepareReverseExecution(firmSession, agreed, request, configuration, clock);
        } catch (error) { firmSession.secret.fill(0); throw error; }
      },
      dispose: () => { used = disposed = true; session.secret.fill(0); firmSession?.secret.fill(0); },
    });
  } catch (error) {
    session.secret.fill(0);
    throw error;
  }
}
