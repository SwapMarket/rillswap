import { describe, expect, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import {
  contractHash,
  handshakeAcceptHash,
  handshakeHash,
  handshakeInitHash,
  unsignedEnvelopeHash,
} from "../src/swap/hashes";
import auth from "./fixtures/authentication-cases-v1.json";
import taproot from "./fixtures/taproot-cases-v1.json";

describe("RS-001 tagged hashes match rill-core", () => {
  for (const vector of auth.valid) {
    test(vector.id, () => {
      expect(bytesToHex(handshakeInitHash(vector.handshake_init.object))).toBe(
        vector.handshake_init.tagged_hash,
      );
      expect(bytesToHex(handshakeAcceptHash(vector.handshake_accept.object))).toBe(
        vector.handshake_accept.tagged_hash,
      );
      expect(
        bytesToHex(handshakeHash(vector.handshake_init.object, vector.handshake_accept.object)),
      ).toBe(vector.transcript.tagged_hash);
      const envelope = vector.confirm_envelope.object as Record<string, unknown>;
      const digest = unsignedEnvelopeHash(envelope);
      expect(bytesToHex(digest)).toBe(vector.confirm_envelope.tagged_hash);
      expect(
        schnorr.verify(
          hexToBytes(vector.confirm_envelope.signature),
          digest,
          hexToBytes(vector.confirm_envelope.signer_xonly_key),
        ),
      ).toBe(true);
    });
  }

  for (const vector of taproot.valid) {
    test(`contract hash ${vector.id}`, () => {
      expect(bytesToHex(contractHash(vector.contract_terms))).toBe(vector.contract_hash);
    });
  }
});

test("epoch-bound session id matches the rill-core vector", async () => {
  const { epochBoundSessionId } = await import("../src/swap/hashes");
  const recovery = (await import("./fixtures/initial-btc-to-ln-v1.json")).default.verification_context;
  const init = recovery.handshake_init;
  const id = epochBoundSessionId(
    init.network_identity,
    init.expected_provider_identity_xonly_key,
    recovery.handshake_accept.provider_session_xonly_key,
    init.client_session_xonly_key,
  );
  expect(bytesToHex(id)).toBe("6abb41432e6c051dc91efba1426d2dbc2ec44e6dd174b086f229981121e6dcea");
});
