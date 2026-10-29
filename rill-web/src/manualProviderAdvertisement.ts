/** Read-only manual application-advertisement verification, not Nostr discovery. */
import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";

import { validateAdvertisement, validateEvmAssetIdentity, validateNetwork } from "./generated/manualAdvertisementValidators.js";
import type { ProfileId } from "./swapPairs";
import { parseFeePolicy, type BtcFeePolicy } from "./swap/feePolicy";

const MAX_MANUAL_ADVERTISEMENT_BYTES = 64 * 1024;
const MAX_FUTURE_SECONDS = 300; // Local input policy, not a Nostr wire requirement.
const MAX_SATOSHIS = 2_100_000_000_000_000n;
const XONLY_HEX = /^[0-9a-f]{64}$/;
const SUITE = "nostr-nip44v2-nip59/v1";
const PROFILES: ReadonlySet<unknown> = new Set(["btc-to-ln/v1", "ln-to-btc/v1", "erc20-to-ln/v1", "ln-to-erc20/v1"]);
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
    extensions: Record<string, unknown>;
  };
  signature: string;
}

/** RS-010 advertisement extension listing the ERC20 assets a provider serves. */
export const EVM_ASSETS_EXTENSION = "rillswap/evm-assets-v1";
const MAX_EVM_ASSETS = 16;

export interface EvmAssetIdentity {
  readonly family: "evm";
  readonly chain_id: number;
  readonly name: string;
  readonly htlc_contract: string;
  readonly htlc_version: 6;
  readonly token_contract: string;
  readonly token_symbol: string;
  readonly token_decimals: number;
  readonly block_seconds: number;
  readonly deployment_namespace: string | null;
}

/** The validated assets of the RS-010 extension, or null when it is absent or malformed. */
export function evmAssetsOf(extensions: Record<string, unknown>): readonly EvmAssetIdentity[] | null {
  if (!Object.hasOwn(extensions, EVM_ASSETS_EXTENSION)) return [];
  const listed = extensions[EVM_ASSETS_EXTENSION];
  if (!Array.isArray(listed) || listed.length === 0 || listed.length > MAX_EVM_ASSETS ||
      !listed.every((asset) => validateEvmAssetIdentity(asset))) {
    return null;
  }
  const assets = listed as EvmAssetIdentity[];
  const keys = new Set(assets.map((asset) => `${asset.chain_id}:${asset.token_contract}`));
  return keys.size === assets.length ? assets.map((asset) => Object.freeze({ ...asset })) : null;
}

/** RS-005 extension: the funding_confirmations every offer of this advertisement carries. */
export const FUNDING_CONFIRMATIONS_EXTENSION = "rillswap/funding-confirmations";

/**
 * The announced funding depth, null when absent (unknown, never 0 or 1), or
 * undefined when malformed. Zero is only valid when every listed profile is
 * BTC to LN, the one direction where only the paying provider takes the risk.
 */
export function fundingConfirmationsOf(
  extensions: Record<string, unknown>, profiles: readonly string[],
): number | null | undefined {
  if (!Object.hasOwn(extensions, FUNDING_CONFIRMATIONS_EXTENSION)) return null;
  const value = extensions[FUNDING_CONFIRMATIONS_EXTENSION];
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const entry = value as Record<string, unknown>;
  const depth = entry.confirmations;
  if (Object.keys(entry).length !== 1 || typeof depth !== "number" ||
      !Number.isSafeInteger(depth) || depth < 0 ||
      (depth === 0 && !profiles.every((profile) => profile === "btc-to-ln/v1"))) {
    return undefined;
  }
  return depth;
}

/** Only a historical authenticated offer, not a live endpoint or session. */
export interface ManualProviderCandidate {
  readonly source: "manual-app-signature-only";
  readonly identityXOnlyKey: string;
  readonly networkIdentityJcs: string;
  readonly profileId: ProfileId;
  readonly slot: string;
  readonly revision: number;
  readonly expiresAt: number;
  readonly advertisedEndpoints: readonly string[];
  readonly advertisedEpochInboxKeys: readonly string[];
  /** Complete authenticated data for same-revision conflict checks. */
  readonly advertisementJcs: string;
  readonly amountBands: readonly Readonly<{ minimum_sat: string; maximum_sat: string }>[];
  readonly indicativeFeePolicy: Readonly<{ base_sat: string; proportional_millionths: number }>;
  readonly feePolicy?: BtcFeePolicy;
  /** RS-010 assets served, empty for Bitcoin-only providers. */
  readonly evmAssets: readonly EvmAssetIdentity[];
  /** RS-005 announced funding depth; null when the provider did not announce one. */
  readonly fundingConfirmations: number | null;
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
  independentlySelectedProfile: ProfileId,
): ManualProviderCandidate {
  try {
    if (typeof rawCanonicalJson !== "string" ||
        encoder.encode(rawCanonicalJson).length === 0 ||
        encoder.encode(rawCanonicalJson).length > MAX_MANUAL_ADVERTISEMENT_BYTES ||
        typeof approvedIdentityXOnlyKey !== "string" ||
        !XONLY_HEX.test(approvedIdentityXOnlyKey) ||
        !validateNetwork(independentlySelectedNetwork) ||
        !PROFILES.has(independentlySelectedProfile)) {
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
    const evmAssets = evmAssetsOf(ad.extensions);
    const fundingConfirmations = fundingConfirmationsOf(ad.extensions, ad.profiles);
    const feePolicy = parseFeePolicy(ad.extensions);
    if (feePolicy && (feePolicy.base_sat !== ad.indicative_fee_policy.base_sat ||
      feePolicy.proportional_millionths !== ad.indicative_fee_policy.proportional_millionths ||
      ad.profiles.some((profile) => !["btc-to-ln/v1", "ln-to-btc/v1"].includes(profile)))) {
      throw new ManualAdvertisementRefusedError();
    }
    if (networkJcs === undefined || evmAssets === null || fundingConfirmations === undefined ||
        (independentlySelectedProfile.includes("erc20") && evmAssets.length === 0) ||
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
      ...(feePolicy ? { feePolicy } : {}),
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
      evmAssets: Object.freeze(evmAssets),
      fundingConfirmations,
    });
  } catch {
    // Do not leak untrusted input, signature details, or endpoint strings.
    throw new ManualAdvertisementRefusedError();
  }
}
