/** Offer-bound estimated BTC mining fees, independently implemented from rill-core. */
import { bytesToHex } from "@noble/hashes/utils.js";
import { schnorr } from "@noble/curves/secp256k1.js";
import canonicalize from "canonicalize";
import type { BtcToLnTerms, LnToBtcTerms } from "./wire";

export const FEE_POLICY_FEATURE = "btc-network-fees/v1";
export const FEE_POLICY_EXTENSION = "org.rillswap/fee-policy-v1";
export const FEE_MODEL = "p2tr-cooperative-1in-2out/v1";
export const NETWORK_FEE_VBYTES = 154n;
const MAX_SATS = 2_100_000_000_000_000n;
const HEX32 = /^[0-9a-f]{64}$/;

export interface BtcFeePolicy {
  readonly model: typeof FEE_MODEL;
  readonly base_sat: string;
  readonly proportional_millionths: number;
  readonly max_network_feerate_sat_kvb: string;
  readonly max_routing_fee_ppm: number;
}

export interface FeeBreakdown {
  readonly offer_event_id: string;
  readonly policy: BtcFeePolicy;
  readonly feerate_sat_kvb: string;
  readonly estimated_at: number;
  readonly issued_at: number;
  readonly service_fee_sat: string;
  readonly network_fee_sat: string;
}

function require(ok: boolean, reason: string): asserts ok {
  if (!ok) throw new Error(`Fee policy refused: ${reason}`);
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  require(value !== null && typeof value === "object" && !Array.isArray(value), "malformed object");
  const result = value as Record<string, unknown>;
  require(Object.keys(result).length === keys.length && keys.every((key) => Object.hasOwn(result, key)), "unexpected fields");
  return result;
}

function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  require(typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= maximum, "integer out of range");
  return value;
}

function amount(value: unknown, positive = false): bigint {
  require(typeof value === "string" && /^(0|[1-9][0-9]{0,15})$/.test(value), "malformed amount");
  const result = BigInt(value);
  require(result <= MAX_SATS && (!positive || result > 0n), "amount out of range");
  return result;
}

/** A signed service fee (never `-0`): a provider may discount, even below zero. */
function signedAmount(value: unknown): bigint {
  require(typeof value === "string" && /^(0|-?[1-9][0-9]{0,15})$/.test(value), "malformed amount");
  const result = BigInt(value);
  require(result <= MAX_SATS && -result <= MAX_SATS, "amount out of range");
  return result;
}

export function parseFeePolicy(extensions: Record<string, unknown>): BtcFeePolicy | undefined {
  if (!Object.hasOwn(extensions, FEE_POLICY_EXTENSION)) return undefined;
  const policy = record(extensions[FEE_POLICY_EXTENSION], ["model", "base_sat", "proportional_millionths", "max_network_feerate_sat_kvb", "max_routing_fee_ppm"]);
  require(policy.model === FEE_MODEL, "unknown transaction-size model");
  amount(policy.base_sat); amount(policy.max_network_feerate_sat_kvb, true);
  integer(policy.proportional_millionths, 1_000_000); integer(policy.max_routing_fee_ppm, 1_000_000);
  return Object.freeze({ ...policy }) as unknown as BtcFeePolicy;
}

export const feePolicyHash = (policy: BtcFeePolicy): string =>
  bytesToHex(schnorr.utils.taggedHash("RillSwap/fee-policy/v1", new TextEncoder().encode(canonicalize(policy))));

/** The caller supplies trusted evidence, never the provider's quoted rate. */
export function networkFeeRequest(
  provider: { readonly feePolicy?: BtcFeePolicy; readonly outerEventId: string },
  independentRateSatKvb?: number,
): Record<string, unknown> {
  const policy = provider.feePolicy;
  if (!policy) return {};
  require(independentRateSatKvb !== undefined && integer(independentRateSatKvb) > 0, "independent feerate unavailable");
  require(HEX32.test(provider.outerEventId), "announcement ID missing");
  const local = BigInt(independentRateSatKvb) * 2n;
  const advertised = BigInt(policy.max_network_feerate_sat_kvb);
  return { [FEE_POLICY_EXTENSION]: {
    offer_event_id: provider.outerEventId,
    policy_hash: feePolicyHash(policy),
    max_network_feerate_sat_kvb: (local < advertised ? local : advertised).toString(),
  } };
}

/** Recovery omits request/now: historic accepted prices never need a fresh estimator. */
export function checkFeeBreakdown(
  terms: Pick<BtcToLnTerms | LnToBtcTerms, "extensions" | "required_features" | "economics" | "profile_id" | "terms_expiry" | "max_claim_fee_sat" | "max_funding_fee_sat">,
  requestExtensions?: Record<string, unknown>,
  now?: number,
): FeeBreakdown | undefined {
  const required = terms.required_features.includes(FEE_POLICY_FEATURE);
  const value = terms.extensions[FEE_POLICY_EXTENSION];
  require(Object.hasOwn(terms.extensions, FEE_POLICY_EXTENSION) === required, "breakdown must be required");
  const requested = requestExtensions?.[FEE_POLICY_EXTENSION];
  if (!required) {
    require(requested === undefined, "provider omitted requested policy");
    return undefined;
  }
  require(terms.required_features.every((feature, i, all) => i === 0 || all[i - 1]! < feature), "features must be sorted and unique");
  const entry = record(value, ["offer_event_id", "policy", "feerate_sat_kvb", "estimated_at", "issued_at", "service_fee_sat", "network_fee_sat"]);
  const policy = parseFeePolicy({ [FEE_POLICY_EXTENSION]: entry.policy })!;
  require(typeof entry.offer_event_id === "string" && HEX32.test(entry.offer_event_id), "announcement ID malformed");
  const rate = amount(entry.feerate_sat_kvb, true), service = signedAmount(entry.service_fee_sat), network = amount(entry.network_fee_sat);
  const issued = integer(entry.issued_at), estimated = integer(entry.estimated_at);
  require(issued >= estimated && issued - estimated <= 10, "stale or future estimate");
  require(rate <= BigInt(policy.max_network_feerate_sat_kvb), "feerate exceeds advertised maximum");
  require(network === (NETWORK_FEE_VBYTES * rate + 999n) / 1000n, "network fee differs from transaction-size model");
  const principal = BigInt(terms.economics.kind === "btc-to-ln" ? terms.economics.lightning_principal_sat : terms.economics.nominal_payout_sat);
  // The advertised formula is a ceiling: discounts (even rebates) are allowed, surcharges are not.
  require(service <= BigInt(policy.base_sat) + (principal * BigInt(policy.proportional_millionths) + 999_999n) / 1_000_000n, "service fee exceeds advertised policy");
  require(service + network === BigInt(terms.economics.success_fee_sat), "breakdown does not sum to success fee");
  require(network <= BigInt(terms.profile_id === "btc-to-ln/v1" ? terms.max_claim_fee_sat : terms.max_funding_fee_sat), "network charge exceeds spend cap");
  require(terms.terms_expiry > issued && terms.terms_expiry - issued <= 60, "acceptance lifetime exceeds 60 seconds");
  if (now !== undefined) require(issued <= now + 5 && now < terms.terms_expiry, "quote expired or issued in the future");
  if (requestExtensions !== undefined) {
    const request = record(requested, ["offer_event_id", "policy_hash", "max_network_feerate_sat_kvb"]);
    require(request.offer_event_id === entry.offer_event_id, "different announcement");
    require(request.policy_hash === feePolicyHash(policy), "advertised policy changed");
    require(rate <= amount(request.max_network_feerate_sat_kvb, true), "feerate exceeds independent ceiling");
  }
  return { ...entry, policy } as unknown as FeeBreakdown;
}
