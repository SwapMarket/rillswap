import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { parseTransaction, serializeTransaction } from "../src/swap/transaction";
import { appendReverseClaimFallback, constructSelectedReverseClaim, inspectReverseRecoveryPlaintext, verifySelectedReverseClaim, inspectRecoveryPlaintext } from "../src/recoveryInspection";
import { reverseCase, reverseRecord, reverseRecoveryCases, signReverseRecord } from "./fixtures/reverseRecoveryCases";
import { clientSessionSecret, signDigest } from "./fixtures/recoveryInspectionFixture";
import { fundingBindingHash } from "../src/swap/hashes";
import { recoveryDocument, type RecoveryParts } from "../src/swap/recovery";
import type { ReverseTermsOffer, HandshakeInit } from "../src/swap/wire";

const bytes = (record: unknown): Uint8Array => new TextEncoder().encode(canonicalize(record)!);
for (const item of reverseRecoveryCases()) {
  test(`reverse claim ${item.name}`, () => {
    const sign = spyOn(schnorr, "sign"); let claim: ReturnType<typeof constructSelectedReverseClaim> | undefined;
    try {
      try { claim = constructSelectedReverseClaim(bytes(item.record), item.expectedNetwork, { fundingAttemptId: item.fundingAttemptId,
        bindingRevision: item.bindingRevision, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, confirmations: item.confirmations, feeSat: BigInt(item.feeSat) }); } catch {}
      expect(Boolean(claim)).toBe(item.accepted);
      if (claim) {
        expect(sign).toHaveBeenCalledTimes(1); const tx = parseTransaction(hexToBytes(claim.transactionHex));
        expect(tx.locktime).toBe(0); expect(tx.inputs[0]!.witness).toHaveLength(4);
        expect(claim.outputValueSat).toBe((51000n - BigInt(item.feeSat)).toString());
        sign.mockClear(); expect(verifySelectedReverseClaim(bytes(item.record), item.expectedNetwork, item, hexToBytes(item.fundingTxHex), hexToBytes(claim.transactionHex))).toEqual(claim);
        expect(sign).not.toHaveBeenCalled();
      } else expect(sign).not.toHaveBeenCalled();
    } finally { sign.mockRestore(); }
  });
}

for (const mutation of ["roles", "economics", "invoice amount", "timing", "preimage", "missing preimage", "secret", "handshake", "binding role", "binding signer", "terms signature"]) {
  test(`reverse authentication rejects internally inconsistent ${mutation} without signing`, () => {
    const record = reverseRecord();
    if (mutation === "roles") Object.assign(record.contract_terms, { claimant: "provider", refund_party: "client" });
    if (mutation === "economics") record.contract_terms.economics.contract_amount_sat = "50000";
    if (mutation === "invoice amount") record.contract_terms.invoice_binding.amount_msat = "50000000";
    if (mutation === "timing") record.contract_terms.timing_policy.min_incoming_htlc_expiry_height = 231;
    if (mutation === "preimage") record.monotonic_knowledge.preimage = "0".repeat(64);
    if (mutation === "missing preimage") record.monotonic_knowledge = { preimage_known: false, preimage: null, dangerous_signature_issued: false };
    if (mutation === "secret") record.user_secret.contract_secret_key = "0".repeat(63) + "9";
    if (mutation === "handshake") record.verification_context.handshake_accept.client_challenge = "e".repeat(64);
    if (mutation === "binding role") record.funding_history[0]!.binding.funder_role = "client";
    signReverseRecord(record);
    if (mutation === "binding signer") record.funding_history[0]!.funder_session_signature = signDigest(fundingBindingHash(record.funding_history[0]!.binding), clientSessionSecret);
    if (mutation === "terms signature") record.verification_context.provider_terms_signature = "0".repeat(128);
    const sign = spyOn(schnorr, "sign"); try { expect(() => inspectReverseRecoveryPlaintext(bytes(record), record.network_identity)).toThrow(); expect(sign).not.toHaveBeenCalled(); }
    finally { sign.mockRestore(); }
  });
}

test("inspection is redacted, profile-pinned and not a claim or chain authorization", () => {
  const item = reverseCase(), report = inspectReverseRecoveryPlaintext(bytes(item.record), item.expectedNetwork);
  expect(report.verification).toBe("historical-static"); expect(report.fallbackTxid).toBeNull(); expect(report.fundingHistory[0]!.funder_role).toBe("provider");
  const text = JSON.stringify(report); expect(text).not.toContain(item.record.user_secret.contract_secret_key); expect(text).not.toContain(item.record.monotonic_knowledge.preimage!);
  expect(() => inspectRecoveryPlaintext(bytes(item.record), item.expectedNetwork)).toThrow();
  expect(() => inspectReverseRecoveryPlaintext(bytes(item.record), { ...item.record.network_identity, deployment_namespace: "other" })).toThrow();
});

test("the shared native recovery serializer preserves reverse roles and the initial client preimage", () => {
  const item = reverseCase(), record = item.record, context = record.verification_context;
  const offer: ReverseTermsOffer = { terms: { contract_hash: record.contract_hash, contract_terms: record.contract_terms, handshake_hash: context.handshake_hash },
    provider_terms_signature: context.provider_terms_signature, hold_invoice: "lnbcrt-public-test-placeholder" };
  const parts: RecoveryParts = { network: item.expectedNetwork, profile: "ln-to-btc/v1", init: context.handshake_init as HandshakeInit,
    accept: context.handshake_accept, acceptSignature: context.provider_identity_signature, offer, acceptanceSignature: context.client_acceptance_signature,
    clientSessionKey: context.client_session_xonly_key, contractSecret: hexToBytes(record.user_secret.contract_secret_key), birthday: record.chain_scan_birthday_height,
    createdAt: record.created_at, updatedAt: record.updated_at, funding: record.funding_history.map(({ binding, funder_session_signature }) => ({ binding: { ...binding, binding_revision: 0, replaces_txid: null }, signature: funder_session_signature })),
    preimage: record.monotonic_knowledge.preimage };
  const produced = recoveryDocument(parts), report = inspectReverseRecoveryPlaintext(produced, item.expectedNetwork);
  expect(report.contractHash).toBe(record.contract_hash); expect(report.fundingHistory).toHaveLength(1);
  const document = JSON.parse(new TextDecoder().decode(produced)); expect(document.monotonic_knowledge).toEqual(record.monotonic_knowledge);
  expect(document.funding_history[0].binding.funder_role).toBe("provider");
});

test("fallback successor retains a distinct funded predecessor, exact signed bytes and unchanged knowledge", () => {
  const item = reverseCase(), funded = bytes(item.record), claim = constructSelectedReverseClaim(funded, item.expectedNetwork,
    { ...item, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: BigInt(item.feeSat) });
  const sign = spyOn(schnorr, "sign"); try {
    const fallback = appendReverseClaimFallback(funded, item.expectedNetwork, hexToBytes(claim.transactionHex));
    const successor = JSON.parse(new TextDecoder().decode(fallback));
    expect(successor.funding_history).toEqual(item.record.funding_history); expect(successor.monotonic_knowledge).toEqual(item.record.monotonic_knowledge);
    expect(Object.keys(successor.extensions["rillswap/reverse-claim-fallback"]).sort()).toEqual(["funding_binding_hash", "transaction", "version"]);
    expect(inspectReverseRecoveryPlaintext(fallback, item.expectedNetwork).fallbackTxid).toBe(claim.txid);
    expect(() => appendReverseClaimFallback(fallback, item.expectedNetwork, hexToBytes(claim.transactionHex))).toThrow();
    expect(funded).toEqual(bytes(item.record)); expect(sign).not.toHaveBeenCalled();
  } finally { sign.mockRestore(); }
});

test("historical higher-fee fallbacks remain refused when they exceed the browser reserve/payout policy", () => {
  const item = reverseCase(), claim = constructSelectedReverseClaim(bytes(item.record), item.expectedNetwork,
    { ...item, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: 900n });
  item.record.contract_terms.economics.claim_fee_reserve_sat = "500"; item.record.contract_terms.economics.nominal_payout_sat = "50500"; signReverseRecord(item.record);
  expect(inspectReverseRecoveryPlaintext(bytes(item.record), item.expectedNetwork).claimFeeReserveSat).toBe("500");
  item.record.extensions["rillswap/reverse-claim-fallback"] = { version: 1,
    funding_binding_hash: bytesToHex(fundingBindingHash(item.record.funding_history[0]!.binding)), transaction: claim.transactionHex };
  const original = bytes(item.record);
  expect(() => inspectReverseRecoveryPlaintext(original, item.expectedNetwork)).toThrow(); expect(original).toEqual(bytes(item.record));
});

for (const mutation of ["signature", "preimage", "destination", "locktime", "leaf", "fee", "outpoint"]) {
  test(`saved claim reauthorization independently rejects ${mutation} without re-signing`, () => {
    const item = reverseCase(), funded = bytes(item.record), claim = constructSelectedReverseClaim(funded, item.expectedNetwork,
      { ...item, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: BigInt(item.feeSat) });
    const parsed = parseTransaction(hexToBytes(claim.transactionHex)), tx = { ...parsed, inputs: [...parsed.inputs], outputs: [...parsed.outputs] }, input = tx.inputs[0]!;
    if (mutation === "signature") input.witness[0]![0] = input.witness[0]![0]! ^ 1;
    if (mutation === "preimage") input.witness[1]![0] = input.witness[1]![0]! ^ 1;
    if (mutation === "leaf") input.witness[2]![0] = input.witness[2]![0]! ^ 1;
    if (mutation === "destination") tx.outputs[0] = { ...tx.outputs[0]!, script: hexToBytes("0014" + "55".repeat(20)) };
    if (mutation === "locktime") tx.locktime = 220;
    if (mutation === "fee") tx.outputs[0] = { ...tx.outputs[0]!, value: 49999n };
    if (mutation === "outpoint") tx.inputs[0] = { ...input, txid: "f".repeat(64) };
    const sign = spyOn(schnorr, "sign"); try { expect(() => verifySelectedReverseClaim(funded, item.expectedNetwork, item, hexToBytes(item.fundingTxHex), serializeTransaction(tx, true))).toThrow(); expect(sign).not.toHaveBeenCalled(); }
    finally { sign.mockRestore(); }
  });
}
