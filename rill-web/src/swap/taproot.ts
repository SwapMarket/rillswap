/**
 * RS-002 Taproot contract reconstruction, parity-tested against rill-core.
 *
 * The internal key is the BIP327 KeyAgg of the ordered (never sorted) client
 * and provider compressed keys; the output key applies the x-only TapTweak of
 * the two-leaf script tree. Everything the funding output commits to is
 * derived here from signed terms, never taken from the provider.
 */
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

const Point = secp256k1.Point;
const ORDER = Point.Fn.ORDER;
const TAPLEAF_VERSION = 0xc0;
const MAX_LOCK_HEIGHT_EXCLUSIVE = 500_000_000;

export interface TaprootTermsInput {
  readonly client_contract_compressed_key: string;
  readonly provider_contract_compressed_key: string;
  readonly claimant: "client" | "provider";
  readonly refund_party: "client" | "provider";
  readonly refund_lock_height: number;
  readonly invoice_binding: { readonly payment_hash: string };
}

export interface TaprootContract {
  readonly internal_xonly_key: string;
  readonly internal_key_parity: 0 | 1;
  readonly claim_script: string;
  readonly refund_script: string;
  readonly claim_leaf_hash: string;
  readonly refund_leaf_hash: string;
  readonly merkle_root: string;
  readonly tap_tweak: string;
  readonly output_xonly_key: string;
  readonly output_key_parity: 0 | 1;
  readonly script_pubkey: string;
  readonly claim_control_block: string;
  readonly refund_control_block: string;
}

const tagged = (tag: string, ...parts: Uint8Array[]): Uint8Array =>
  schnorr.utils.taggedHash(tag, concatBytes(...parts));

const toScalar = (bytes: Uint8Array): bigint => BigInt(`0x${bytesToHex(bytes)}`) % ORDER;

type AffinePoint = InstanceType<typeof Point>;

const parity = (point: AffinePoint): 0 | 1 => (point.toAffine().y % 2n === 0n ? 0 : 1);

const xOnly = (point: AffinePoint): Uint8Array => point.toBytes(true).slice(1);

/** BIP327 KeyAgg for two distinct keys in the given order. */
export function keyAgg(first: Uint8Array, second: Uint8Array): AffinePoint {
  if (first.length !== 33 || second.length !== 33 || bytesToHex(first) === bytesToHex(second)) {
    throw new Error("KeyAgg needs two distinct compressed keys");
  }
  const list = tagged("KeyAgg list", first, second);
  // The second distinct key (here always `second`) takes coefficient one.
  const coefficient = toScalar(tagged("KeyAgg coefficient", list, first));
  const aggregate = Point.fromBytes(first).multiply(coefficient).add(Point.fromBytes(second));
  if (aggregate.equals(Point.ZERO)) throw new Error("KeyAgg produced infinity");
  return aggregate;
}

/** BIP327 ApplyTweak with is_xonly: negate an odd aggregate, then add t*G. */
export function xOnlyTweak(aggregate: AffinePoint, tweak: Uint8Array): AffinePoint {
  const t = BigInt(`0x${bytesToHex(tweak)}`);
  if (tweak.length !== 32 || t >= ORDER) throw new Error("tweak out of range");
  const even = parity(aggregate) === 0 ? aggregate : aggregate.negate();
  const tweaked = t === 0n ? even : even.add(Point.BASE.multiply(t));
  if (tweaked.equals(Point.ZERO)) throw new Error("tweak produced infinity");
  return tweaked;
}

function compactSize(length: number): Uint8Array {
  if (length < 0xfd) return Uint8Array.of(length);
  if (length <= 0xffff) return Uint8Array.of(0xfd, length & 0xff, length >> 8);
  throw new Error("script too long");
}

function scriptNumber(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value <= 0 || value >= MAX_LOCK_HEIGHT_EXCLUSIVE) {
    throw new Error("refund lock height is outside the RS-002 range");
  }
  if (value <= 16) return Uint8Array.of(0x50 + value); // OP_1 .. OP_16
  const encoded: number[] = [];
  for (let remaining = value; remaining > 0; remaining = Math.floor(remaining / 256)) {
    encoded.push(remaining % 256);
  }
  if ((encoded.at(-1) ?? 0) & 0x80) encoded.push(0);
  return Uint8Array.of(encoded.length, ...encoded);
}

function claimScript(paymentHash: Uint8Array, claimant: Uint8Array): Uint8Array {
  // OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <claimant> OP_CHECKSIG
  return concatBytes(
    Uint8Array.of(0x82, 0x01, 0x20, 0x88, 0xa8, 0x20),
    paymentHash,
    Uint8Array.of(0x88, 0x20),
    claimant,
    Uint8Array.of(0xac),
  );
}

function refundScript(lockHeight: number, refundKey: Uint8Array): Uint8Array {
  // <lock> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund> OP_CHECKSIG
  return concatBytes(scriptNumber(lockHeight), Uint8Array.of(0xb1, 0x75, 0x20), refundKey, Uint8Array.of(0xac));
}

const tapLeaf = (script: Uint8Array): Uint8Array =>
  tagged("TapLeaf", Uint8Array.of(TAPLEAF_VERSION), compactSize(script.length), script);

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let index = 0; index < left.length; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

/** Reconstruct every committed RS-002 Taproot artifact from signed terms. */
export function reconstructTaprootContract(terms: TaprootTermsInput): TaprootContract {
  const client = hexToBytes(terms.client_contract_compressed_key);
  const provider = hexToBytes(terms.provider_contract_compressed_key);
  const paymentHash = hexToBytes(terms.invoice_binding.payment_hash);
  if (paymentHash.length !== 32) throw new Error("payment hash must be 32 bytes");
  const clientX = client.slice(1);
  const providerX = provider.slice(1);
  const claim = claimScript(paymentHash, terms.claimant === "client" ? clientX : providerX);
  const refund = refundScript(terms.refund_lock_height, terms.refund_party === "client" ? clientX : providerX);
  const claimLeaf = tapLeaf(claim);
  const refundLeaf = tapLeaf(refund);
  const [left, right] = compareBytes(claimLeaf, refundLeaf) <= 0 ? [claimLeaf, refundLeaf] : [refundLeaf, claimLeaf];
  const merkleRoot = tagged("TapBranch", left, right);
  const internal = keyAgg(client, provider);
  const internalX = xOnly(internal);
  const tweak = tagged("TapTweak", internalX, merkleRoot);
  if (toScalar(tweak) !== BigInt(`0x${bytesToHex(tweak)}`)) throw new Error("tweak out of range");
  const output = xOnlyTweak(internal, tweak);
  const outputParity = parity(output);
  const prefix = Uint8Array.of(TAPLEAF_VERSION | outputParity);
  return {
    internal_xonly_key: bytesToHex(internalX),
    internal_key_parity: parity(internal),
    claim_script: bytesToHex(claim),
    refund_script: bytesToHex(refund),
    claim_leaf_hash: bytesToHex(claimLeaf),
    refund_leaf_hash: bytesToHex(refundLeaf),
    merkle_root: bytesToHex(merkleRoot),
    tap_tweak: bytesToHex(tweak),
    output_xonly_key: bytesToHex(xOnly(output)),
    output_key_parity: outputParity,
    script_pubkey: `5120${bytesToHex(xOnly(output))}`,
    claim_control_block: bytesToHex(concatBytes(prefix, internalX, refundLeaf)),
    refund_control_block: bytesToHex(concatBytes(prefix, internalX, claimLeaf)),
  };
}
