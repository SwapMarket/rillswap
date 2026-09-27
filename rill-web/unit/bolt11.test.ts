import { describe, expect, test } from "bun:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { decodeBolt11, invoiceBinding, InvoiceRejectedError } from "../src/swap/bolt11";
import spec from "./fixtures/bolt11-spec-examples.json";

const PAYEE = bytesToHex(secp256k1.getPublicKey(hexToBytes(spec.payee_secret_key), true));
const COFFEE = spec.valid[1]!.invoice; // 2500u, expiry 60, features 8 and 14
const HASH = "0001020304050607080900010203040506070809000102030405060708090102";

describe("BOLT11 reader rules (specification examples)", () => {
  for (const example of spec.valid) {
    test(`decodes: ${example.title}`, () => {
      const decoded = decodeBolt11(example.invoice);
      if (!example.title.startsWith("Public-key recovery with high-S")) {
        expect(decoded.payee).toBe(PAYEE);
      }
    });
  }

  test("fields of the coffee example", () => {
    const decoded = decodeBolt11(COFFEE);
    expect(decoded.currency).toBe("bc");
    expect(decoded.amountMsat).toBe(250_000_000n);
    expect(decoded.timestamp).toBe(1496314658);
    expect(decoded.paymentHash).toBe(HASH);
    expect(decoded.paymentSecret).toBe("11".repeat(32));
    expect(decoded.expirySeconds).toBe(60);
    expect(decoded.minFinalCltvDelta).toBe(18);
    expect([...decoded.features].sort((a, b) => a - b)).toEqual([8, 14]);
  });

  test("pico amounts", () => {
    const pico = spec.valid.find((item) => item.invoice.startsWith("lnbc9678785340p"))!;
    expect(decodeBolt11(pico.invoice).amountMsat).toBe(967_878_534n);
  });
});

describe("admission policy and binding", () => {
  test("the coffee invoice binds on mainnet only", () => {
    const binding = invoiceBinding(COFFEE, "mainnet");
    expect(binding).toEqual({
      bolt11_sha256: bytesToHex(sha256(new TextEncoder().encode(COFFEE))),
      payment_hash: HASH,
      amount_msat: "250000000",
      payee_compressed_pubkey: PAYEE,
      created_at: 1496314658,
      expires_at: 1496314718,
      min_final_cltv_delta: 18,
    });
    for (const network of ["signet", "testnet4", "regtest"]) {
      expect(() => invoiceBinding(COFFEE, network)).toThrow(InvoiceRejectedError);
    }
  });

  test("amountless, unknown-feature, and uppercase invoices are refused", () => {
    const refused = [
      spec.valid[0]!.invoice, // no amount
      spec.valid.find((item) => item.title.includes("features 8, 14 and 99"))!.invoice,
      spec.valid.find((item) => item.title.includes("all upper case"))!.invoice,
    ];
    for (const invoice of refused) {
      expect(() => invoiceBinding(invoice, "mainnet")).toThrow(InvoiceRejectedError);
    }
  });

  for (const example of spec.invalid) {
    test(`refuses: ${example.title}`, () => {
      expect(() => invoiceBinding(example.invoice, "mainnet")).toThrow(InvoiceRejectedError);
    });
  }
});
