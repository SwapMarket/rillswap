import { describe, expect, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { contractHash, providerTermsHash } from "../src/swap/hashes";
import type { InvoiceBinding } from "../src/swap/bolt11";
import {
  checkReverseFirmQuoteRequest, checkReverseTermsOffer, COOPERATIVE_CLAIM_FEATURE, type LnToBtcTerms, ProtocolError,
  type ReverseFirmQuoteRequest, type ReverseOfferContext,
} from "../src/swap/wire";
import taproot from "./fixtures/taproot-cases-v1.json";

// Public test identity secret (never for funds); the vector's provider identity is its x-only key.
const IDENTITY_SECRET = hexToBytes(`${"00".repeat(31)}01`);
const HOLD_INVOICE = "lnbcrt1020u1" + "q".repeat(60);
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

describe("LN to BTC terms offer", () => {
  const vector = taproot.valid.find((item) => item.contract_terms.profile_id === "ln-to-btc/v1")!;
  // The vector negotiates a mining prepayment, which this client never does; use M = 0 and H = V + S.
  const base = clone(vector.contract_terms) as unknown as LnToBtcTerms;
  const hold = (BigInt(base.economics.contract_amount_sat) + BigInt(base.economics.success_fee_sat)).toString();
  const terms: LnToBtcTerms = {
    ...base,
    economics: { ...base.economics, mining_prepayment_sat: "0", hold_invoice_sat: hold },
    invoice_binding: { ...base.invoice_binding, amount_msat: `${hold}000` },
    required_features: [COOPERATIVE_CLAIM_FEATURE],
  };
  const transcript = "cd".repeat(32);
  const request: ReverseFirmQuoteRequest = {
    kind: "ln-to-btc",
    mode: "firm",
    nominal_payout_sat: terms.economics.nominal_payout_sat,
    payment_hash: terms.invoice_binding.payment_hash,
    client_contract_compressed_key: terms.client_contract_compressed_key,
    recovery_authorization_xonly_key: terms.recovery_authorization_xonly_key,
    client_destination_script: terms.client_destination_script,
    limits: {
      max_success_fee_sat: terms.economics.success_fee_sat,
      min_claim_fee_reserve_sat: terms.economics.claim_fee_reserve_sat,
      max_claim_fee_sat: terms.max_claim_fee_sat,
      min_refund_lock_height: terms.refund_lock_height,
      max_incoming_htlc_expiry_height: terms.timing_policy.min_incoming_htlc_expiry_height,
    },
    extensions: {},
  };
  const sign = (contractTerms: LnToBtcTerms, holdInvoice = HOLD_INVOICE) => {
    const provider = { contract_hash: bytesToHex(contractHash(contractTerms)), contract_terms: contractTerms, handshake_hash: transcript };
    return { terms: provider, provider_terms_signature: bytesToHex(schnorr.sign(providerTermsHash(provider), IDENTITY_SECRET)),
      hold_invoice: holdInvoice };
  };
  const decoded = new Map<string, InvoiceBinding>([[HOLD_INVOICE, terms.invoice_binding]]);
  const context = (changes: Partial<ReverseOfferContext> = {}, signed: LnToBtcTerms = terms): ReverseOfferContext => ({
    request,
    decodeInvoice: (invoice) => { const binding = decoded.get(invoice); if (!binding) throw new Error("bad invoice"); return binding; },
    transcript,
    envelopeContractHash: bytesToHex(contractHash(signed)),
    identity: terms.provider_identity_key,
    network: terms.network_identity,
    now: terms.terms_expiry - 60,
    ...changes,
  });

  test("the browser-built request is the RS-004 firm request shape", () => {
    expect(checkReverseFirmQuoteRequest(clone(request))).toEqual(request);
    expect(() => checkReverseFirmQuoteRequest({ ...request, client_destination_script: "0020" + "00".repeat(32) })).toThrow(ProtocolError);
    expect(() => checkReverseFirmQuoteRequest({ ...request, nominal_payout_sat: "0" })).toThrow(ProtocolError);
  });

  test("a signed offer honoring the request returns the terms and hold invoice", () => {
    const result = checkReverseTermsOffer(sign(terms), context());
    expect(result.holdInvoice).toBe(HOLD_INVOICE);
    expect(result.terms.economics.hold_invoice_sat).toBe(terms.economics.hold_invoice_sat);
  });

  test("offers outside each request limit are refused", () => {
    const limits = request.limits;
    for (const tightened of [
      { ...limits, max_success_fee_sat: (BigInt(limits.max_success_fee_sat) - 1n).toString() },
      { ...limits, min_claim_fee_reserve_sat: (BigInt(limits.min_claim_fee_reserve_sat) + 1n).toString() },
      { ...limits, max_claim_fee_sat: (BigInt(limits.max_claim_fee_sat) - 1n).toString() },
      { ...limits, min_refund_lock_height: limits.min_refund_lock_height + 1 },
      { ...limits, max_incoming_htlc_expiry_height: limits.max_incoming_htlc_expiry_height - 1 },
    ]) {
      expect(() => checkReverseTermsOffer(sign(terms), context({ request: { ...request, limits: tightened } }))).toThrow("does not honor request");
    }
    for (const changed of [{ payment_hash: "ee".repeat(32) }, { nominal_payout_sat: "99999" },
      { client_destination_script: "5120" + "11".repeat(32) }]) {
      expect(() => checkReverseTermsOffer(sign(terms), context({ request: { ...request, ...changed } }))).toThrow("does not honor request");
    }
  });

  test("the hold invoice must decode to exactly the signed binding", () => {
    expect(() => checkReverseTermsOffer(sign(terms, "lnbcrt1other"), context())).toThrow("hold invoice unacceptable");
    const other = "lnbcrt1other";
    decoded.set(other, { ...terms.invoice_binding, amount_msat: "1" });
    expect(() => checkReverseTermsOffer(sign(terms, other), context())).toThrow("invoice binding");
    expect(() => checkReverseTermsOffer({ ...sign(terms), hold_invoice: undefined }, context())).toThrow("validateReverseTermsOffer");
  });

  test("identity, network, time, envelope, and handshake bindings are enforced", () => {
    expect(() => checkReverseTermsOffer(sign(terms), context({ now: terms.terms_expiry }))).toThrow("bound to this provider");
    expect(() => checkReverseTermsOffer(sign(terms), context({ envelopeContractHash: "00".repeat(32) }))).toThrow("bound to this provider");
    expect(() => checkReverseTermsOffer(sign(terms), context({ network: { ...terms.network_identity as object, name: "signet" } })))
      .toThrow("bound to this provider");
    expect(() => checkReverseTermsOffer(sign(terms), context({ transcript: "00".repeat(32) }))).toThrow("handshake hash");
    const forged = { ...sign(terms), provider_terms_signature: "00".repeat(64) };
    expect(() => checkReverseTermsOffer(forged, context())).toThrow("signature invalid");
  });

  test("signed terms breaking RS-004 model rules are refused", () => {
    const mutate = (edit: (draft: { economics: Record<string, string>; timing_policy: Record<string, number>; [k: string]: unknown }) => void) => {
      const draft = clone(terms) as unknown as Parameters<typeof edit>[0];
      edit(draft);
      return draft as unknown as LnToBtcTerms;
    };
    for (const broken of [
      mutate((t) => { t.economics.contract_amount_sat = "100501"; }),
      mutate((t) => { t.economics.hold_invoice_sat = "102001"; }),
      mutate((t) => { t.economics.mining_prepayment_sat = "1"; t.economics.hold_invoice_sat = "101999"; }),
      mutate((t) => { t.claimant = "provider"; t.refund_party = "client"; }),
      mutate((t) => { t.timing_policy.refund_and_ln_resolution_blocks = 29; }),
      mutate((t) => { t.required_features = []; }),
      mutate((t) => { t.recovery_authorization_xonly_key = t.provider_identity_key as string; }),
    ]) {
      expect(() => checkReverseTermsOffer(sign(broken), context({}, broken))).toThrow(ProtocolError);
    }
  });

  test("forward offers never pass the reverse check", () => {
    const forward = taproot.valid.find((item) => item.contract_terms.profile_id === "btc-to-ln/v1")!;
    const offer = sign(forward.contract_terms as unknown as LnToBtcTerms);
    expect(() => checkReverseTermsOffer(offer, context())).toThrow(ProtocolError);
  });
});
