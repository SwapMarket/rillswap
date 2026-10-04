import { MAX_MSAT, parseTerms, type NativeLightningTerms, type Network } from "./contract";

export interface NativePolicy {
  readonly version: "native-lightning/1";
  readonly merchantOrigin: string;
  readonly receiver: string;
  readonly network: Network;
  readonly maxBuyerExtraMsat: string;
  readonly maxBuyerExtraBps: number;
}
export type EligibilityReason = "eligible" | "invalid_terms" | "invalid_policy" | "origin_mismatch" | "receiver_mismatch" | "network_mismatch" | "expired" | "fee_limit";
export interface Eligibility {
  readonly eligible: boolean;
  readonly reason: EligibilityReason;
}

/** Both consumers evaluate the same pure rule. Only a merchant transaction owns authority. */
export function evaluateNative(input: unknown, policy: NativePolicy, now: number): Eligibility {
  const result = (reason: EligibilityReason): Eligibility => Object.freeze({ eligible: reason === "eligible", reason });
  if (!Number.isSafeInteger(now) || now < 0 || policy.version !== "native-lightning/1" ||
      !Number.isInteger(policy.maxBuyerExtraBps) || policy.maxBuyerExtraBps < 0 || policy.maxBuyerExtraBps > 10000 ||
      !/^(0|[1-9][0-9]{0,18})$/.test(policy.maxBuyerExtraMsat) || BigInt(policy.maxBuyerExtraMsat) > MAX_MSAT) {
    return result("invalid_policy");
  }
  let terms: Readonly<NativeLightningTerms>;
  try { terms = parseTerms(input); } catch { return result("invalid_terms"); }
  if (terms.merchantOrigin !== policy.merchantOrigin) return result("origin_mismatch");
  if (terms.receiver !== policy.receiver) return result("receiver_mismatch");
  if (terms.network !== policy.network) return result("network_mismatch");
  if (now >= terms.expiresAt) return result("expired");
  const extra = BigInt(terms.buyerExtraMsat);
  if (extra > BigInt(policy.maxBuyerExtraMsat) || extra * 10000n > BigInt(terms.amountMsat) * BigInt(policy.maxBuyerExtraBps)) {
    return result("fee_limit");
  }
  return result("eligible");
}
