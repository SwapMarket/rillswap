import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { contractHash, handshakeAcceptHash, handshakeInitHash, providerTermsHash } from "../src/swap/hashes";
import {
  type BtcToLnTerms,
  checkHandshakeAccept,
  checkTermsOffer,
  COOPERATIVE_CLAIM_FEATURE,
  EPOCH_SESSION_FEATURE,
  EPOCH_SESSION_EXTENSION,
  type FirmQuoteRequest,
  type HandshakeInit,
  ProtocolError,
  requireAnnouncedDepth,
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

test("an offer may wait fewer funding confirmations than announced, never more", () => {
  expect(() => requireAnnouncedDepth(0, 1)).not.toThrow();
  expect(() => requireAnnouncedDepth(1, 1)).not.toThrow();
  expect(() => requireAnnouncedDepth(6, null)).not.toThrow(); // nothing announced, nothing to hold it to
  expect(() => requireAnnouncedDepth(2, 1)).toThrow(ProtocolError);
  expect(() => requireAnnouncedDepth(1, 0)).toThrow("more than the announced 0");
});

describe("handshake accept", () => {
  const vector = auth.valid.find((item) => item.profile_id === "btc-to-ln/v1")!;
  const secret = hexToBytes(vector.handshake_accept.signer_secret_key);
  // The vector predates mandatory cooperation; both halves now carry the feature.
  const featured = (initFeatures: string[], acceptFeatures: string[]) => {
    const init = { ...(vector.handshake_init.object as unknown as HandshakeInit), required_features: initFeatures };
    const accept: Record<string, unknown> = {
      ...(vector.handshake_accept.object as Record<string, unknown>),
      handshake_init_hash: bytesToHex(handshakeInitHash(init)),
      required_features: acceptFeatures,
    };
    const signature = bytesToHex(schnorr.sign(handshakeAcceptHash(accept), secret));
    return { init, accept, payload: { accept, provider_identity_signature: signature } };
  };
  const { init, accept, payload } = featured([COOPERATIVE_CLAIM_FEATURE], [COOPERATIVE_CLAIM_FEATURE]);
  const sender = accept.provider_session_xonly_key as string;

  test("a jointly cooperative accept is accepted", () => {
    expect(checkHandshakeAccept(clone(payload), init, sender).session_id).toBe(init.session_id);
  });

  test("cooperation missing from either half is refused", () => {
    const unfeatured = {
      accept: vector.handshake_accept.object,
      provider_identity_signature: vector.handshake_accept.signature,
    };
    const legacy = vector.handshake_init.object as unknown as HandshakeInit;
    expect(() => checkHandshakeAccept(unfeatured, legacy, sender)).toThrow("cooperative claim must be jointly");
    const halves: Array<[string[], string[]]> = [[[COOPERATIVE_CLAIM_FEATURE], []], [[], [COOPERATIVE_CLAIM_FEATURE]]];
    for (const [initFeatures, acceptFeatures] of halves) {
      const half = featured(initFeatures, acceptFeatures);
      expect(() => checkHandshakeAccept(half.payload, half.init, sender)).toThrow("cooperative claim must be jointly");
    }
  });

  test("RS-010 profiles settle in the HTLC contract: cooperation is refused, its absence accepted", () => {
    const evm = (initFeatures: string[], acceptFeatures: string[]) => {
      const half = featured(initFeatures, acceptFeatures);
      const init = { ...half.init, profile_id: "erc20-to-ln/v1" } as HandshakeInit;
      const accept = { ...half.accept, profile_id: "erc20-to-ln/v1", handshake_init_hash: bytesToHex(handshakeInitHash(init)) };
      return { init, payload: { accept, provider_identity_signature: bytesToHex(schnorr.sign(handshakeAcceptHash(accept), secret)) } };
    };
    const plain = evm([], []);
    expect(checkHandshakeAccept(plain.payload, plain.init, sender).session_id).toBe(init.session_id);
    const negotiated = evm([COOPERATIVE_CLAIM_FEATURE], [COOPERATIVE_CLAIM_FEATURE]);
    expect(() => checkHandshakeAccept(negotiated.payload, negotiated.init, sender)).toThrow("cooperative claim must be jointly");
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
    const unknown = { ...accept, required_features: [COOPERATIVE_CLAIM_FEATURE, "unknown-feature/v1"] };
    const signature = bytesToHex(schnorr.sign(handshakeAcceptHash(unknown), secret));
    expect(() =>
      checkHandshakeAccept({ accept: unknown, provider_identity_signature: signature }, init, sender),
    ).toThrow(ProtocolError);
  });
});

describe("reverse handshake settlement selection", () => {
  const vector = auth.valid.find((item) => item.profile_id === "ln-to-btc/v1")!, secret = hexToBytes(vector.handshake_accept.signer_secret_key);
  const selected = (initFeatures: string[], acceptFeatures: string[]) => {
    const init = { ...(vector.handshake_init.object as unknown as HandshakeInit), required_features: initFeatures,
      extensions: initFeatures.includes(EPOCH_SESSION_FEATURE) ? { [EPOCH_SESSION_EXTENSION]: { epoch_inbox_xonly_key: bytesToHex(schnorr.getPublicKey(hexToBytes("0".repeat(63) + "4"))) } } : {} };
    const accept = { ...vector.handshake_accept.object, required_features: acceptFeatures, handshake_init_hash: bytesToHex(handshakeInitHash(init)) };
    return { init, sender: accept.provider_session_xonly_key, payload: { accept, provider_identity_signature: bytesToHex(schnorr.sign(handshakeAcceptHash(accept), secret)) } };
  };
  test("unilateral and cooperative reverse commitments both require exact joint selection", () => {
    for (const features of [[], [COOPERATIVE_CLAIM_FEATURE]]) {
      const { init, sender, payload } = selected(features, features); expect(checkHandshakeAccept(payload, init, sender).required_features).toEqual(features);
    }
    for (const [a, b] of [[[], [COOPERATIVE_CLAIM_FEATURE]], [[COOPERATIVE_CLAIM_FEATURE], []]]) {
      const { init, sender, payload } = selected(a!, b!); expect(() => checkHandshakeAccept(payload, init, sender)).toThrow("cooperative claim must be jointly");
    }
  });
  test("epoch admission stays independent of unilateral selection", () => {
    const selectedEpoch = selected([EPOCH_SESSION_FEATURE], [EPOCH_SESSION_FEATURE]);
    expect(checkHandshakeAccept(selectedEpoch.payload, selectedEpoch.init, selectedEpoch.sender).required_features).toEqual([EPOCH_SESSION_FEATURE]);
    for (const [a, b] of [[[EPOCH_SESSION_FEATURE], []], [[], [EPOCH_SESSION_FEATURE]]]) {
      const { init, sender, payload } = selected(a!, b!); expect(() => checkHandshakeAccept(payload, init, sender)).toThrow("epoch-bound admission");
    }
  });
});

describe("terms offer", () => {
  const terms = {
    ...(clone(taproot.valid[0]!.contract_terms) as unknown as BtcToLnTerms),
    required_features: [COOPERATIVE_CLAIM_FEATURE],
  } as BtcToLnTerms;
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

  test("an offer without cooperative claims is refused", () => {
    const unfeatured = { ...terms, required_features: [] } as unknown as BtcToLnTerms;
    expect(() =>
      checkTermsOffer(sign(unfeatured), { ...context, envelopeContractHash: bytesToHex(contractHash(unfeatured)) }),
    ).toThrow("terms offer does not commit to cooperative claims");
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
