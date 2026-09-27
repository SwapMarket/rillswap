/** RS-001 canonical tagged hashes; JCS of the exact wire JSON values. */
import { schnorr } from "@noble/curves/secp256k1.js";
import canonicalize from "canonicalize";

const encoder = new TextEncoder();

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/** RFC 8785 canonical UTF-8 bytes; refuses values JCS cannot represent. */
export function jcs(value: unknown): Uint8Array {
  const text = canonicalize(value);
  if (typeof text !== "string") throw new Error("value has no canonical JSON form");
  return encoder.encode(text);
}

export const taggedHash = (tag: string, message: Uint8Array): Uint8Array =>
  schnorr.utils.taggedHash(tag, message);

const tagged = (tag: string) => (value: unknown): Uint8Array => taggedHash(tag, jcs(value));

export const contractHash = tagged("RillSwap/contract/v1");
export const handshakeInitHash = tagged("RillSwap/handshake-init/v1");
export const handshakeAcceptHash = tagged("RillSwap/handshake/v1");
export const providerTermsHash = tagged("RillSwap/provider-terms/v1");
export const clientAcceptanceHash = tagged("RillSwap/client-acceptance/v1");
export const fundingBindingHash = tagged("RillSwap/funding-binding/v1");
export const advertisementHash = tagged("RillSwap/advertisement/v1");

export function handshakeHash(init: unknown, accept: unknown): Uint8Array {
  return taggedHash("RillSwap/transcript/v1", jcs({ accept, init }));
}

/** Hash the entire envelope with only its signature member omitted. */
export function unsignedEnvelopeHash(envelope: Record<string, unknown>): Uint8Array {
  const { signature: _omitted, ...rest } = envelope;
  return taggedHash("RillSwap/envelope/v1", jcs(rest));
}

export function epochBoundSessionId(
  network: unknown,
  providerIdentity: string,
  epochInboxKey: string,
  clientSessionKey: string,
): Uint8Array {
  const keys = [providerIdentity, epochInboxKey, clientSessionKey];
  if (!keys.every((key) => /^[0-9a-f]{64}$/.test(key)) || new Set(keys).size !== 3) {
    throw new Error("epoch admission role keys must be distinct x-only keys");
  }
  return taggedHash(
    "RillSwap/epoch-bound-session/v1",
    jcs({
      network_identity: network,
      provider_identity_xonly_key: providerIdentity,
      epoch_inbox_xonly_key: epochInboxKey,
      client_session_xonly_key: clientSessionKey,
    }),
  );
}
