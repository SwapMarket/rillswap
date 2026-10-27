import validate from "./generated/native-lightning.js";

export const NETWORKS = ["regtest", "signet", "mainnet"] as const;
export type Network = typeof NETWORKS[number];
export interface NativeLightningTerms {
  readonly version: "checkout/0.1";
  readonly policyVersion: "native-lightning/1";
  readonly merchantOrigin: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly network: Network;
  readonly amountMsat: string;
  readonly paymentHash: string;
  readonly receiver: string;
  readonly expiresAt: number;
  readonly buyerExtraMsat: string;
}

export const MAX_MSAT = 2_100_000_000_000_000_000n;

/** Structural and semantic terms validation, not invoice authentication or receipt verification. */
export function parseTerms(input: unknown): Readonly<NativeLightningTerms> {
  if (!validate(input)) throw new Error("Invalid native Lightning checkout terms");
  const terms = input as NativeLightningTerms;
  const origin = new URL(terms.merchantOrigin);
  if (origin.protocol !== "https:" || origin.origin !== terms.merchantOrigin || origin.username || origin.password) {
    throw new Error("Merchant origin must be an exact HTTPS origin");
  }
  const amount = BigInt(terms.amountMsat);
  if (amount > MAX_MSAT || amount % 1000n !== 0n || BigInt(terms.buyerExtraMsat) > MAX_MSAT) {
    throw new Error("Unsupported Lightning quantity");
  }
  return Object.freeze({ version: terms.version, policyVersion: terms.policyVersion, merchantOrigin: terms.merchantOrigin,
    intentId: terms.intentId, attemptId: terms.attemptId, network: terms.network, amountMsat: terms.amountMsat,
    paymentHash: terms.paymentHash, receiver: terms.receiver, expiresAt: terms.expiresAt, buyerExtraMsat: terms.buyerExtraMsat });
}
