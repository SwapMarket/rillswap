import { describe, expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { keyAgg, reconstructTaprootContract, type TaprootTermsInput } from "../src/swap/taproot";
import vectors from "./fixtures/taproot-cases-v1.json";
import btcToLn from "./fixtures/initial-btc-to-ln-v1.json";
import lnToBtc from "./fixtures/initial-ln-to-btc-no-prepayment-v1.json";

describe("RS-002 Taproot reconstruction matches rill-core", () => {
  for (const vector of vectors.valid) {
    test(vector.id, () => {
      const got = reconstructTaprootContract(vector.contract_terms as TaprootTermsInput);
      const want = vector.artifacts;
      expect(got.internal_xonly_key).toBe(want.internal_key);
      expect(got.internal_key_parity).toBe(want.internal_parity as 0 | 1);
      expect(got.claim_script).toBe(want.claim_script);
      expect(got.refund_script).toBe(want.refund_script);
      expect(got.claim_leaf_hash).toBe(want.claim_leaf_hash);
      expect(got.refund_leaf_hash).toBe(want.refund_leaf_hash);
      expect(got.merkle_root).toBe(want.merkle_root);
      expect(got.tap_tweak).toBe(want.tap_tweak);
      expect(got.output_xonly_key).toBe(want.output_key);
      expect(got.output_key_parity).toBe(want.output_parity as 0 | 1);
      expect(got.script_pubkey).toBe(want.script_pubkey);
      expect(got.claim_control_block).toBe(want.claim_control_block);
      expect(got.refund_control_block).toBe(want.refund_control_block);
    });
  }

  for (const [name, fixture] of [["btc-to-ln", btcToLn], ["ln-to-btc", lnToBtc]] as const) {
    test(`recovery fixture ${name}`, () => {
      expect(reconstructTaprootContract(fixture.contract_terms as TaprootTermsInput)).toEqual(
        fixture.taproot_contract as never,
      );
    });
  }

  test("key aggregation order is client then provider", () => {
    const swapped = vectors.invalid.find((item) => item.id === "swapped-key-aggregation-order");
    const terms = vectors.valid[0]!.contract_terms;
    const reversed = keyAgg(
      hexToBytes(terms.provider_contract_compressed_key),
      hexToBytes(terms.client_contract_compressed_key),
    );
    expect(bytesToHex(reversed.toBytes(true).slice(1))).toBe(swapped!.replacement_internal_key!);
    expect(() => keyAgg(hexToBytes(terms.client_contract_compressed_key), hexToBytes(terms.client_contract_compressed_key))).toThrow();
  });
});
