/** Signed fake-money invoice and provider terms for browser RS-010 tests. */
import { bech32 } from "@scure/base";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { invoiceBinding } from "../../src/swap/bolt11";
import { contractHash, providerTermsHash } from "../../src/swap/hashes";
import type { LnToErc20Terms } from "../../src/swap/erc20Swap";
import forward from "./initial-btc-to-ln-v1.json";

export const SECRET = hexToBytes(`${"00".repeat(31)}01`);
export const PREIMAGE = "42".repeat(32);
export const PAYMENT_HASH = bytesToHex(sha256(hexToBytes(PREIMAGE)));
export const ASSET = { family: "evm" as const, chain_id: 31337, name: "anvil-dev", htlc_contract: `0x${"1a".repeat(20)}`, htlc_version: 6 as const,
  token_contract: `0x${"2b".repeat(20)}`, token_symbol: "fUSDC", token_decimals: 6, block_seconds: 2, deployment_namespace: "dev" };
export const CLIENT = `0x${"c1".repeat(20)}`, PROVIDER = `0x${"a7".repeat(20)}`, NOW = 1_700_000_000;

export function testHoldInvoice(paymentHash = PAYMENT_HASH): string {
  const hrp = "lnbcrt511u", timestamp = NOW;
  const tagged = (tag: number, bytes: Uint8Array): number[] => {
    const words = bech32.toWords(bytes); return [tag, words.length >> 5, words.length & 31, ...words];
  };
  const words = [...Array.from({ length: 7 }, (_, i) => Math.floor(timestamp / 2 ** (5 * (6 - i))) & 31),
    ...tagged(1, hexToBytes(paymentHash)), ...tagged(23, sha256(new TextEncoder().encode("test hold invoice"))),
    ...tagged(19, secp256k1.getPublicKey(SECRET, true)), ...tagged(16, new Uint8Array(32).fill(7)),
    6, 0, 3, 3, 16, 16, 5, 0, 3, 16, 8, 0]; // x = 3600 seconds; feature bits 8 and 14
  const data: number[] = []; let accumulator = 0, bits = 0;
  for (const word of words) { accumulator = (accumulator << 5) | word; bits += 5; while (bits >= 8) { bits -= 8; data.push((accumulator >> bits) & 255); } }
  if (bits) data.push((accumulator << (8 - bits)) & 255);
  const digest = sha256(new Uint8Array([...new TextEncoder().encode(hrp), ...data]));
  const signature = secp256k1.sign(digest, SECRET, { prehash: false });
  return bech32.encode(hrp, [...words, ...bech32.toWords(new Uint8Array([...signature, 0]))], 4096);
}
export const HOLD_INVOICE = testHoldInvoice();
export const TERMS: LnToErc20Terms = {
  protocol: "rillswap", contract_version: "1", profile_id: "ln-to-erc20/v1", network_identity: forward.network_identity,
  evm_asset: ASSET, provider_identity_key: bytesToHex(schnorr.getPublicKey(SECRET)), client_evm_address: CLIENT, provider_evm_address: PROVIDER,
  claimant: "client", refund_party: "provider", invoice_binding: invoiceBinding(HOLD_INVOICE, "regtest"),
  economics: { kind: "ln-to-erc20", payout_token_base: "51000000", rate_token_base_per_btc: "100000000000", payout_sat_equivalent: "51000", success_fee_sat: "100", hold_invoice_sat: "51100" },
  htlc_timelock_block: 2800, evm_reference_block: 1000, btc_reference_height: 100, funding_confirmations: 2, settlement_confirmations: 2,
  recovery_authorization_xonly_key: forward.contract_terms.recovery_authorization_xonly_key, terms_expiry: NOW + 600,
  timing_policy: { kind: "ln-to-erc20", min_incoming_htlc_expiry_height: 300, refund_and_ln_resolution_seconds: 600 }, required_features: [], extensions: {},
};
export function signedReverse(terms = TERMS, invoice = HOLD_INVOICE) {
  const provider = { contract_hash: bytesToHex(contractHash(terms)), contract_terms: terms, handshake_hash: "77".repeat(32) };
  return { terms: provider, provider_terms_signature: bytesToHex(schnorr.sign(providerTermsHash(provider), SECRET)), hold_invoice: invoice };
}
