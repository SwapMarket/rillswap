/**
 * RS-007 recovery document for either browser swap direction, byte-compatible
 * with rill-cli's `_recovery_document` so `rill recover inspect` and
 * `rill recover watch-refund` accept it. Encryption reuses the pinned
 * age X25519 container.
 */
import { bytesToHex } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";

import { encryptCanonicalRecoveryForRecipient } from "../recoveryAgeContainer";
import type { RecoveryFundingBinding } from "../recoveryInspection";
import { reconstructTaprootContract } from "./taproot";
import type { HandshakeAccept, HandshakeInit, TermsOffer, ReverseTermsOffer } from "./wire";

export interface RecoveryParts {
  readonly network: unknown;
  readonly profile: string;
  readonly init: HandshakeInit;
  readonly accept: HandshakeAccept;
  readonly acceptSignature: string;
  readonly offer: TermsOffer | ReverseTermsOffer;
  readonly acceptanceSignature: string;
  readonly clientSessionKey: string;
  readonly contractSecret: Uint8Array;
  readonly birthday: number;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly funding: readonly { readonly binding: RecoveryFundingBinding; readonly signature: string }[];
  readonly preimage: string | null;
  /** Recovery extensions, such as the cooperative reservation; empty by default. */
  readonly extensions?: Readonly<Record<string, unknown>>;
}

export function recoveryDocument(parts: RecoveryParts): Uint8Array {
  const terms = parts.offer.terms.contract_terms;
  const text = canonicalize({
    format: "rillswap-recovery",
    format_version: "1-pre.1",
    specification_version: "0.1.0-pre.1",
    created_at: parts.createdAt,
    updated_at: parts.funding.length > 0 ? parts.updatedAt : parts.createdAt,
    network_identity: parts.network,
    profile_id: parts.profile,
    contract_hash: parts.offer.terms.contract_hash,
    contract_terms: terms,
    verification_context: {
      handshake_init: parts.init,
      handshake_accept: parts.accept,
      provider_identity_signature: parts.acceptSignature,
      handshake_hash: parts.offer.terms.handshake_hash,
      client_session_xonly_key: parts.clientSessionKey,
      provider_session_xonly_key: parts.accept.provider_session_xonly_key,
      expected_provider_identity_source: { kind: "manual", advertisement_digest: null },
      provider_terms_signature: parts.offer.provider_terms_signature,
      client_acceptance_signature: parts.acceptanceSignature,
    },
    taproot_contract: reconstructTaprootContract(terms),
    user_secret: { kind: "raw-secp256k1-v1", contract_secret_key: bytesToHex(parts.contractSecret) },
    funding_history: parts.funding.map((item) => ({
      binding: item.binding,
      funder_session_signature: item.signature,
    })),
    chain_scan_birthday_height: parts.birthday,
    fee_policy: { max_claim_fee_sat: terms.max_claim_fee_sat, max_refund_fee_sat: terms.max_refund_fee_sat },
    recovery_authorization_xonly_key: terms.recovery_authorization_xonly_key,
    monotonic_knowledge: {
      preimage_known: parts.preimage !== null,
      preimage: parts.preimage,
      dangerous_signature_issued: false,
    },
    extensions: parts.extensions ?? {},
  });
  if (text === undefined) throw new Error("recovery document is not JSON");
  return new TextEncoder().encode(text);
}

/** The age-encrypted recovery file bytes for one pinned recipient. */
export function encryptRecovery(parts: RecoveryParts, ageRecipient: string): Promise<Uint8Array> {
  return encryptCanonicalRecoveryForRecipient(recoveryDocument(parts), ageRecipient);
}
