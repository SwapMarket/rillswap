import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { contractHash, handshakeAcceptHash, providerTermsHash } from "../src/swap/hashes";
import {
  type BtcToLnTerms,
  checkHandshakeAccept,
  checkTermsOffer,
  type FirmQuoteRequest,
  type HandshakeInit,
  ProtocolError,
  requireShape,
} from "../src/swap/wire";
import auth from "./fixtures/authentication-cases-v1.json";
import quotes from "./fixtures/quote-v1.json";
import taproot from "./fixtures/taproot-cases-v1.json";

const IDENTITY_SECRET = hexToBytes(`${"00".repeat(31)}01`);
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

test("vendored wire schemas equal rill-docs", () => {
  for (const name of ["common", "contract-terms", "envelope", "funding-binding", "handshake", "quote", "settlement"]) {
    const file = `schemas/wire/${name}-v1.schema.json`;
    const docs = readFileSync(resolve(import.meta.dir, "../../rill-docs", file), "utf8");
    expect(readFileSync(resolve(import.meta.dir, "../src", file), "utf8")).toBe(docs);
  }
});

describe("handshake accept", () => {
  const vector = auth.valid.find((item) => item.profile_id === "btc-to-ln/v1")!;
  const init = vector.handshake_init.object as unknown as HandshakeInit;
  const accept = vector.handshake_accept.object as Record<string, unknown>;
  const payload = { accept, provider_identity_signature: vector.handshake_accept.signature };
  const sender = accept.provider_session_xonly_key as string;

  test("the authentication vector is accepted", () => {
    expect(checkHandshakeAccept(clone(payload), init, sender).session_id).toBe(init.session_id);
  });

  test("another sender, identity, echo, or signature is refused", () => {
    expect(() => checkHandshakeAccept(clone(payload), init, init.client_session_xonly_key)).toThrow(ProtocolError);
    const otherIdentity = { ...init, expected_provider_identity_xonly_key: init.client_session_xonly_key };
    expect(() => checkHandshakeAccept(clone(payload), otherIdentity, sender)).toThrow(ProtocolError);
    const otherChallenge = { ...init, client_challenge: "22".repeat(32) };
    expect(() => checkHandshakeAccept(clone(payload), otherChallenge, sender)).toThrow(ProtocolError);
    const badSignature = { ...payload, provider_identity_signature: "00".repeat(64) };
    expect(() => checkHandshakeAccept(badSignature, init, sender)).toThrow(ProtocolError);
  });

  test("an unrequested required feature is refused even when signed", () => {
    const secret = hexToBytes(vector.handshake_accept.signer_secret_key);
    const featured = { ...accept, required_features: ["unknown-feature/v1"] };
    const signature = bytesToHex(schnorr.sign(handshakeAcceptHash(featured), secret));
    expect(() =>
      checkHandshakeAccept({ accept: featured, provider_identity_signature: signature }, init, sender),
    ).toThrow(ProtocolError);
  });
});

describe("terms offer", () => {
  const terms = clone(taproot.valid[0]!.contract_terms) as unknown as BtcToLnTerms;
  const transcript = "ab".repeat(32);
  const request: FirmQuoteRequest = {
    kind: "btc-to-ln",
    mode: "firm",
    lightning_principal_sat: terms.economics.lightning_principal_sat,
    invoice: "lnbcrt1unused",
    client_contract_compressed_key: terms.client_contract_compressed_key,
    recovery_authorization_xonly_key: terms.recovery_authorization_xonly_key,
    client_destination_script: terms.client_destination_script,
    limits: {
      max_success_fee_sat: terms.economics.success_fee_sat,
      max_funding_fee_sat: terms.max_funding_fee_sat,
      max_claim_fee_sat: terms.max_claim_fee_sat,
      max_refund_fee_sat: terms.max_refund_fee_sat,
      max_refund_lock_height: terms.refund_lock_height,
    },
    extensions: {},
  };
  const sign = (contractTerms: BtcToLnTerms) => {
    const provider = { contract_hash: bytesToHex(contractHash(contractTerms)), contract_terms: contractTerms,
      handshake_hash: transcript };
    return { terms: provider, provider_terms_signature: bytesToHex(schnorr.sign(providerTermsHash(provider),
      IDENTITY_SECRET)) };
  };
  const context = {
    request,
    invoiceBinding: terms.invoice_binding,
    transcript,
    envelopeContractHash: bytesToHex(contractHash(terms)),
    identity: terms.provider_identity_key,
    network: terms.network_identity,
    now: terms.terms_expiry - 60,
  };

  test("a signed offer within the limits is accepted", () => {
    expect(checkTermsOffer(sign(terms), context).refund_lock_height).toBe(terms.refund_lock_height);
  });

  test("offers above a limit or bound elsewhere are refused", () => {
    const tighter = { ...request, limits: { ...request.limits, max_refund_lock_height: terms.refund_lock_height - 1 } };
    const cases = [
      () => checkTermsOffer(sign(terms), { ...context, request: tighter }),
      () => checkTermsOffer(sign(terms), { ...context, now: terms.terms_expiry }),
      () => checkTermsOffer(sign(terms), { ...context, transcript: "cd".repeat(32) }),
      () => checkTermsOffer(sign(terms), { ...context, envelopeContractHash: "00".repeat(32) }),
      () => checkTermsOffer(sign(terms), { ...context, identity: terms.recovery_authorization_xonly_key }),
      () => checkTermsOffer({ ...sign(terms), provider_terms_signature: "00".repeat(64) }, context),
    ];
    for (const run of cases) expect(run).toThrow(ProtocolError);
  });

  test("terms breaking a model rule are refused even when signed", () => {
    const unbalanced = clone(terms);
    (unbalanced.economics as { success_fee_sat: string }).success_fee_sat = "999";
    const late = clone(terms);
    (late.timing_policy as { max_outgoing_htlc_expiry_height: number }).max_outgoing_htlc_expiry_height = 1081;
    for (const broken of [unbalanced, late]) {
      expect(() => checkTermsOffer(sign(broken), { ...context, envelopeContractHash: bytesToHex(contractHash(broken)) }))
        .toThrow(ProtocolError);
    }
  });

  test("generated validators follow the quote vectors", () => {
    for (const offer of quotes.valid.termsOffer) expect(requireShape<unknown>("validateTermsOffer", offer)).toBe(offer);
  });
});
