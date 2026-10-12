import { describe, expect, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { generateIdentity, identityToRecipient } from "age-encryption";

import {
  checkErc20TermsOffer, type Erc20FirmQuoteRequest, type Erc20ToLnTerms, encryptEvmRecovery, lockAmountTokenBase, lockOf, parseEvmRecovery,
} from "../src/swap/erc20Swap";
import { ABI, encodeClaim, encodeLock, encodeRefund, lockHash } from "../src/swap/evmHtlc";
import { contractHash, providerTermsHash } from "../src/swap/hashes";
import { ProtocolError } from "../src/swap/wire";
import { decryptRecoveryContainer } from "../src/recoveryKeys";
import fixture from "./fixtures/initial-btc-to-ln-v1.json";

const IDENTITY_SECRET = hexToBytes(`${"00".repeat(31)}01`);
const CLIENT = `0x${"c1".repeat(20)}`;
const PROVIDER = `0x${"a7".repeat(20)}`;
const ASSET = {
  family: "evm" as const, chain_id: 31337, name: "anvil-dev", htlc_contract: `0x${"1a".repeat(20)}`, htlc_version: 6 as const,
  token_contract: `0x${"2b".repeat(20)}`, token_symbol: "fUSDC", token_decimals: 6, block_seconds: 2, deployment_namespace: "dev",
};
const base = fixture.contract_terms;
const TERMS: Erc20ToLnTerms = {
  protocol: "rillswap", contract_version: "1", profile_id: "erc20-to-ln/v1", network_identity: base.network_identity,
  evm_asset: ASSET, provider_identity_key: base.provider_identity_key, client_evm_address: CLIENT, provider_evm_address: PROVIDER,
  claimant: "provider", refund_party: "client", invoice_binding: base.invoice_binding,
  economics: { kind: "erc20-to-ln", lightning_principal_sat: "100000", rate_token_base_per_btc: "100000000000", success_fee_token_base: "200000", lock_amount_token_base: "100200000" },
  htlc_timelock_block: 61_000, evm_reference_block: 1_000, btc_reference_height: 100, funding_confirmations: 1, settlement_confirmations: 1,
  recovery_authorization_xonly_key: base.recovery_authorization_xonly_key, terms_expiry: 1700000600,
  timing_policy: { kind: "erc20-to-ln", max_outgoing_htlc_expiry_height: 244, learn_and_claim_seconds: 600 }, required_features: [], extensions: {},
};
const REQUEST: Erc20FirmQuoteRequest = {
  kind: "erc20-to-ln", mode: "firm", lightning_principal_sat: "100000", invoice: "lnbcrt1unused",
  evm_asset: { chain_id: 31337, token_contract: ASSET.token_contract }, client_evm_address: CLIENT,
  recovery_authorization_xonly_key: base.recovery_authorization_xonly_key,
  limits: { max_success_fee_token_base: "1000000", max_htlc_timelock_block: 100_000 }, extensions: {},
};
const TRANSCRIPT = "77".repeat(32);
const signed = (terms: Erc20ToLnTerms) => {
  const provider = { contract_hash: bytesToHex(contractHash(terms)), contract_terms: terms, handshake_hash: TRANSCRIPT };
  return { terms: provider, provider_terms_signature: bytesToHex(schnorr.sign(providerTermsHash(provider), IDENTITY_SECRET)) };
};
const context = (terms = TERMS, request = REQUEST) => ({
  request, invoiceBinding: base.invoice_binding, asset: ASSET, transcript: TRANSCRIPT,
  envelopeContractHash: bytesToHex(contractHash(terms)), identity: base.provider_identity_key, network: base.network_identity, now: TERMS.terms_expiry - 60,
});

describe("erc20-to-ln terms offer", () => {
  test("an exact signed offer is accepted and names the HTLC lock", () => {
    const terms = checkErc20TermsOffer(signed(TERMS), context());
    expect(lockOf(terms)).toEqual({ preimageHash: base.invoice_binding.payment_hash, amount: 100_200_000n, token: ASSET.token_contract, claimAddress: PROVIDER, refundAddress: CLIENT, timelock: 61_000 });
    expect(lockAmountTokenBase(100_000n, 100_000_000_000n, 200_000n)).toBe(100_200_000n);
    expect(lockAmountTokenBase(1n, 3n, 0n)).toBe(1n); // ceiling
  });

  test.each<[string, Partial<Erc20ToLnTerms>, string]>([
    ["lock amount", { economics: { ...TERMS.economics, lock_amount_token_base: "100200001" } }, "lock amount"],
    ["success fee", { economics: { ...TERMS.economics, success_fee_token_base: "2000000", lock_amount_token_base: "102000000" } }, "success fee"],
    ["timelock", { htlc_timelock_block: 100_001 }, "timelock"],
    ["timelock window", { htlc_timelock_block: 1_001 }, "timelock window"],
    ["client address", { client_evm_address: `0x${"c2".repeat(20)}` }, "client EVM address"],
    ["provider equals client", { provider_evm_address: CLIENT }, "provider EVM address"],
    ["asset", { evm_asset: { ...ASSET, token_contract: `0x${"2c".repeat(20)}` } }, "EVM asset"],
    ["features", { required_features: ["cooperative-claim/v1"] }, "required features"],
    ["principal", { economics: { ...TERMS.economics, lightning_principal_sat: "100001" } }, "principal"],
  ])("refuses an offer that changes the %s", (_name, change, what) => {
    expect(() => checkErc20TermsOffer(signed({ ...TERMS, ...change }), context({ ...TERMS, ...change }))).toThrow(new ProtocolError(`terms offer does not honor request: ${what}`));
  });

  test("refuses a wrong profile, a bad signature, another identity, and expired terms", () => {
    const reverse = {
      ...TERMS, profile_id: "ln-to-erc20/v1", claimant: "client", refund_party: "provider",
      economics: { kind: "ln-to-erc20", payout_token_base: "100000000", rate_token_base_per_btc: "100000000000", payout_sat_equivalent: "100000", success_fee_sat: "200", hold_invoice_sat: "100200" },
      timing_policy: { kind: "ln-to-erc20", min_incoming_htlc_expiry_height: 300, refund_and_ln_resolution_seconds: 600 },
    } as unknown as Erc20ToLnTerms;
    expect(() => checkErc20TermsOffer(signed(reverse), context(reverse))).toThrow("not an erc20-to-ln contract");
    const offer = signed(TERMS);
    expect(() => checkErc20TermsOffer({ ...offer, provider_terms_signature: "00".repeat(64) }, context())).toThrow(ProtocolError);
    expect(() => checkErc20TermsOffer(offer, { ...context(), identity: "ab".repeat(32) })).toThrow(ProtocolError);
    expect(() => checkErc20TermsOffer(offer, { ...context(), now: TERMS.terms_expiry })).toThrow("not bound to this provider, network, or time");
    expect(() => checkErc20TermsOffer({ ...offer, extra: 1 }, context())).toThrow(ProtocolError);
  });
});

describe("EVM HTLC encoding", () => {
  const lock = lockOf(TERMS);
  test("uses the ERC20Swap v6 selectors and packs every argument as one word", () => {
    expect(ABI.approve).toBe("095ea7b3");
    expect(ABI.lock).toBe("e64fafcc");
    expect(encodeLock(lock)).toBe(`0x${ABI.lock}${base.invoice_binding.payment_hash}${(100_200_000n).toString(16).padStart(64, "0")}${"2b".repeat(20).padStart(64, "0")}${"a7".repeat(20).padStart(64, "0")}${"c1".repeat(20).padStart(64, "0")}${(61_000).toString(16).padStart(64, "0")}`);
    expect(encodeRefund(lock).slice(10)).toBe(encodeLock(lock).slice(10));
    expect(encodeClaim(lock, "ee".repeat(32)).slice(10)).toBe(`${"ee".repeat(32)}${encodeLock(lock).slice(74)}`);
    expect(lockHash(lock)).toMatch(/^[0-9a-f]{64}$/);
    expect(() => encodeLock({ ...lock, token: "0xABCD" })).toThrow("lowercase 0x address");
  });
});

describe("EVM recovery record", () => {
  test("round-trips through the age container and authenticates the signed terms", async () => {
    const identity = await generateIdentity();
    const parts = {
      network: base.network_identity, init: fixture.handshake_init as never, accept: fixture.handshake_accept as never, acceptSignature: "11".repeat(64),
      offer: signed(TERMS), acceptanceSignature: "22".repeat(64), clientSessionKey: "33".repeat(32), lockTxHash: "44".repeat(32), preimage: null, createdAt: 1, updatedAt: 2,
    };
    const ciphertext = await encryptEvmRecovery(parts, await identityToRecipient(identity));
    const plaintext = await decryptRecoveryContainer(ciphertext, identity);
    const record = parseEvmRecovery(plaintext, base.network_identity, TERMS.terms_expiry + 1_000_000);
    expect(record.lock).toEqual(lockOf(TERMS));
    expect(record.lockTxHash).toBe("44".repeat(32));
    expect(record.contractHash).toBe(bytesToHex(contractHash(TERMS)));
    expect(() => parseEvmRecovery(plaintext, { ...base.network_identity, name: "signet" }, 3)).toThrow("not an RS-010 recovery record");
    // The lock tx hash is the client's own note; the signed terms are what a refund relies on.
    const text = new TextDecoder().decode(plaintext);
    const forged = new TextEncoder().encode(text.replace('"htlc_timelock_block":61000', '"htlc_timelock_block":61001'));
    expect(() => parseEvmRecovery(forged, base.network_identity, 3)).toThrow("provider terms signature invalid");
  });
});
