/** Read-only manual application-advertisement verification, not Nostr discovery. */
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";

import { validateAdvertisement, validateNetwork } from "./generated/manualAdvertisementValidators.js";

const MAX_MANUAL_ADVERTISEMENT_BYTES = 64 * 1024;
const MAX_FUTURE_SECONDS = 300; // Local input policy, not a Nostr wire requirement.
const MAX_SATOSHIS = 2_100_000_000_000_000n;
const XONLY_HEX = /^[0-9a-f]{64}$/;
const SUITE = "nostr-nip44v2-nip59/v1";
const encoder = new TextEncoder();

interface SignedAdvertisement {
  advertisement: {
    protocol: string;
    binding_version: string;
    provider_identity_xonly_key: string;
    network_identities: unknown[];
    profiles: string[];
    communication_suites: string[];
    amount_bands: { minimum_sat: string; maximum_sat: string }[];
    indicative_fee_policy: { base_sat: string; proportional_millionths: number };
    transport_endpoints: string[];
    epoch_inbox_xonly_keys: string[];
    slot: string;
    revision: number;
    created_at: number;
    expires_at: number;
  };
  signature: string;
}

/** Only a historical authenticated offer, not a live endpoint or session. */
export interface ManualProviderCandidate {
  readonly source: "manual-app-signature-only";
  readonly identityXOnlyKey: string;
  readonly networkIdentityJcs: string;
  readonly profileId: "btc-to-ln/v1" | "ln-to-btc/v1";
  readonly slot: string;
  readonly revision: number;
  readonly expiresAt: number;
  readonly advertisedEndpoints: readonly string[];
  readonly advertisedEpochInboxKeys: readonly string[];
  /** Complete authenticated data for same-revision conflict checks. */
  readonly advertisementJcs: string;
  readonly amountBands: readonly Readonly<{ minimum_sat: string; maximum_sat: string }>[];
  readonly indicativeFeePolicy: Readonly<{ base_sat: string; proportional_millionths: number }>;
}

export class ManualAdvertisementRefusedError extends Error {
  constructor() {
    super("Manual provider advertisement refused");
    this.name = "ManualAdvertisementRefusedError";
  }
}

function protocolNumbersAreExact(value: unknown): boolean {
  if (typeof value === "number") return Number.isSafeInteger(value);
  if (Array.isArray(value)) return value.every(protocolNumbersAreExact);
  if (value !== null && typeof value === "object") {
    return Object.values(value).every(protocolNumbersAreExact);
  }
  return true;
}

/**
 * Verify a manually supplied application-signed object against an identity the
 * user approved independently of these bytes. No NIP-01 event is accepted here:
 * future relay import must additionally authenticate event ID/signature/tags.
 * Does not choose an endpoint/inbox, contact a service, store a trust pin, or
 * establish freshness relative to omitted/restored advertisement history.
 */
export function verifyManualProviderAdvertisement(
  rawCanonicalJson: string,
  approvedIdentityXOnlyKey: string,
  independentlySelectedNetwork: unknown,
  independentlySelectedProfile: "btc-to-ln/v1" | "ln-to-btc/v1",
): ManualProviderCandidate {
  try {
    if (typeof rawCanonicalJson !== "string" ||
        encoder.encode(rawCanonicalJson).length === 0 ||
        encoder.encode(rawCanonicalJson).length > MAX_MANUAL_ADVERTISEMENT_BYTES ||
        typeof approvedIdentityXOnlyKey !== "string" ||
        !XONLY_HEX.test(approvedIdentityXOnlyKey) ||
        !validateNetwork(independentlySelectedNetwork) ||
        !["btc-to-ln/v1", "ln-to-btc/v1"].includes(independentlySelectedProfile)) {
      throw new ManualAdvertisementRefusedError();
    }
    const document: unknown = JSON.parse(rawCanonicalJson);
    // Exact JCS comparison rejects duplicate JSON members, ambiguous numeric
    // or string encodings, and whitespace before validation or signature use.
    if (canonicalize(document) !== rawCanonicalJson ||
        !protocolNumbersAreExact(document) ||
        !validateAdvertisement(document)) {
      throw new ManualAdvertisementRefusedError();
    }
    const { advertisement: ad, signature } = document as unknown as SignedAdvertisement;
    const networkJcs = canonicalize(independentlySelectedNetwork);
    if (networkJcs === undefined ||
        ad.provider_identity_xonly_key !== approvedIdentityXOnlyKey ||
        !ad.network_identities.some((candidate) => canonicalize(candidate) === networkJcs) ||
        !ad.profiles.includes(independentlySelectedProfile) ||
        !ad.communication_suites.includes(SUITE) ||
        ad.amount_bands.some((band) =>
          BigInt(band.minimum_sat) === 0n ||
          BigInt(band.minimum_sat) > BigInt(band.maximum_sat) ||
          BigInt(band.maximum_sat) > MAX_SATOSHIS,
        ) ||
        BigInt(ad.indicative_fee_policy.base_sat) > MAX_SATOSHIS) {
      throw new ManualAdvertisementRefusedError();
    }
    for (const key of ad.epoch_inbox_xonly_keys) {
      schnorr.utils.lift_x(BigInt(`0x${key}`));
    }
    const now = Math.floor(Date.now() / 1000);
    if (ad.created_at > now + MAX_FUTURE_SECONDS ||
        ad.expires_at <= now || ad.expires_at <= ad.created_at) {
      throw new ManualAdvertisementRefusedError();
    }
    const applicationBytes = encoder.encode(canonicalize(ad));
    const tag = sha256(encoder.encode("RillSwap/advertisement/v1"));
    const taggedInput = new Uint8Array(tag.length * 2 + applicationBytes.length);
    taggedInput.set(tag);
    taggedInput.set(tag, tag.length);
    taggedInput.set(applicationBytes, tag.length * 2);
    if (!schnorr.verify(
      hexToBytes(signature), sha256(taggedInput), hexToBytes(approvedIdentityXOnlyKey),
    )) {
      throw new ManualAdvertisementRefusedError();
    }
    return Object.freeze({
      source: "manual-app-signature-only" as const,
      identityXOnlyKey: approvedIdentityXOnlyKey,
      networkIdentityJcs: networkJcs,
      profileId: independentlySelectedProfile,
      slot: ad.slot,
      revision: ad.revision,
      expiresAt: ad.expires_at,
      advertisedEndpoints: Object.freeze([...ad.transport_endpoints]),
      advertisedEpochInboxKeys: Object.freeze([...ad.epoch_inbox_xonly_keys]),
      advertisementJcs: canonicalize(ad)!,
      amountBands: Object.freeze(ad.amount_bands.map((band) => Object.freeze({ ...band }))),
      indicativeFeePolicy: Object.freeze({ ...ad.indicative_fee_policy }),
    });
  } catch {
    // Do not leak untrusted input, signature details, or endpoint strings.
    throw new ManualAdvertisementRefusedError();
  }
}
