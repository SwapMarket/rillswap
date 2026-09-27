import { describe, expect, test } from "bun:test";
import { hexToBytes } from "@noble/hashes/utils.js";
import { Decrypter, generateIdentity, identityToRecipient } from "age-encryption";
import canonicalize from "canonicalize";

import type { FundingBinding } from "../src/swap/funding";
import { encryptRecovery, type RecoveryParts, recoveryDocument } from "../src/swap/recovery";
import type { HandshakeAccept, HandshakeInit, TermsOffer } from "../src/swap/wire";
import vector from "./fixtures/initial-btc-to-ln-v1.json";

const context = vector.verification_context;
const parts: RecoveryParts = {
  network: vector.network_identity,
  profile: vector.profile_id,
  init: context.handshake_init as unknown as HandshakeInit,
  accept: context.handshake_accept as unknown as HandshakeAccept,
  acceptSignature: context.provider_identity_signature,
  offer: {
    terms: {
      contract_hash: vector.contract_hash,
      contract_terms: vector.contract_terms,
      handshake_hash: context.handshake_hash,
    },
    provider_terms_signature: context.provider_terms_signature,
  } as unknown as TermsOffer,
  acceptanceSignature: context.client_acceptance_signature,
  clientSessionKey: context.client_session_xonly_key,
  contractSecret: hexToBytes(vector.user_secret.contract_secret_key),
  birthday: vector.chain_scan_birthday_height,
  createdAt: vector.created_at,
  updatedAt: vector.updated_at + 50,
  funding: [],
  preimage: null,
};

describe("recovery document", () => {
  test("rebuilding the rill-docs initial BTC to LN vector is byte-identical", () => {
    expect(new TextDecoder().decode(recoveryDocument(parts))).toBe(canonicalize(vector)!);
  });

  test("a funded document records the binding and its update time", () => {
    const binding = { contract_hash: vector.contract_hash } as unknown as FundingBinding;
    const funded = JSON.parse(new TextDecoder().decode(recoveryDocument({
      ...parts,
      funding: [{ binding, signature: "ab".repeat(64) }],
    }))) as { updated_at: number; funding_history: unknown[] };
    expect(funded.updated_at).toBe(vector.updated_at + 50);
    expect(funded.funding_history).toEqual([{ binding, funder_session_signature: "ab".repeat(64) }]);
  });

  test("the age file decrypts to the canonical document", async () => {
    const identity = await generateIdentity();
    const ciphertext = await encryptRecovery(parts, await identityToRecipient(identity));
    const decrypter = new Decrypter();
    decrypter.addIdentity(identity);
    expect(await decrypter.decrypt(ciphertext, "text")).toBe(canonicalize(vector)!);
  });
});
