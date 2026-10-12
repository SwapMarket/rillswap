/**
 * Gas-sponsored EVM claims through an Alchemy-compatible wallet API
 * (`wallet_prepareCalls`, `wallet_sendPreparedCalls`, `wallet_getCallsStatus`) for an
 * EIP-7702 account whose key lives in this browser (the "staging key").
 *
 * Trust model: the sponsor is untrusted. The staging key signs only
 *  (a) an EIP-7702 delegation to the pinned delegate, on the pinned chain, at the live nonce, and
 *  (b) an ERC-4337 v0.7 user operation whose hash this module recomputes over calldata it built
 *      itself (`executeBatch` of the exact calls the caller asked for).
 * Nothing the sponsor returns is signed opaquely. The staging account never holds native coin,
 * so gas fields cannot drain it; value moves only through the bound calls.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { EvmError, checkEvmAddress, type EvmRpc } from "./evmHtlc";

const encoder = new TextEncoder();
const ADDRESS = /^0x[0-9a-f]{40}$/;
const HEX = /^0x(?:[0-9a-fA-F]{2})*$/;
const HEX32 = /^0x[0-9a-fA-F]{64}$/;
const MAX_UINT128 = (1n << 128n) - 1n;
const MAX_UINT256 = (1n << 256n) - 1n;

const selector = (signature: string): string => bytesToHex(keccak_256(encoder.encode(signature))).slice(0, 8);
export const SPONSOR_ABI = Object.freeze({
  executeBatch: selector("executeBatch((address,uint256,bytes)[])"),
  executeUserOp: selector("executeUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes),bytes32)"),
  getNonce: selector("getNonce(address,uint192)"),
});

export interface SponsorConfig {
  readonly url: string;
  readonly chainId: number;
  /** ERC-4337 EntryPoint v0.7 the user operation hash is bound to. */
  readonly entryPoint: string;
  /** The only EIP-7702 delegate the staging key may authorize. */
  readonly delegate: string;
  /** Alchemy gas policy (`paymasterService.policyId`); omit for a proxy that applies its own. */
  readonly policyId?: string;
}
export interface SponsoredCall {
  readonly to: string;
  readonly data: string;
}
/** Alchemy `user-operation-v070` payload (all quantities hex strings). */
export interface UserOpV070 {
  readonly sender: string;
  readonly nonce: string;
  readonly factory?: string;
  readonly factoryData?: string;
  readonly callData: string;
  readonly callGasLimit: string;
  readonly verificationGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly paymaster?: string;
  readonly paymasterData?: string;
  readonly paymasterVerificationGasLimit?: string;
  readonly paymasterPostOpGasLimit?: string;
}
export interface Authorization {
  readonly chainId: number;
  readonly address: string;
  readonly nonce: bigint;
}
export interface VerifiedPrepared {
  readonly userOp: UserOpV070;
  readonly userOpHash: string;
  readonly userOpChainId: string;
  readonly authorization: { readonly entry: Record<string, unknown>; readonly digest: string } | null;
  readonly sponsored: boolean;
}
export interface PreparedExpectation {
  readonly sender: string;
  readonly callData: string;
  /** `null` when the account already delegates to the pinned delegate. */
  readonly authorizationNonce: bigint | null;
  /** Live sequence for the nonce key the sponsor picks: `(key) => EntryPoint.getNonce(sender, key)`. */
  accountSequence(key: bigint): Promise<bigint>;
}

/* ---------- hex, ABI, RLP helpers ---------- */

export function checkHex(value: unknown, what: string): string {
  if (typeof value !== "string" || !HEX.test(value)) throw new EvmError(`${what} is not 0x hex bytes`);
  return value.toLowerCase();
}
function quantity(value: unknown, what: string, max = MAX_UINT256): bigint {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new EvmError(`${what} is not a hex quantity`);
  const parsed = BigInt(value);
  if (parsed > max) throw new EvmError(`${what} is out of range`);
  return parsed;
}
const word = (value: bigint): string => {
  if (value < 0n || value > MAX_UINT256) throw new EvmError("value does not fit uint256");
  return value.toString(16).padStart(64, "0");
};
const addressWord = (address: string): string => checkEvmAddress(address, "address").slice(2).padStart(64, "0");
const half = (value: bigint): string => {
  if (value < 0n || value > MAX_UINT128) throw new EvmError("value does not fit uint128");
  return value.toString(16).padStart(32, "0");
};
const padded = (hex: string): string => { const body = hex.slice(2); return body + "0".repeat((64 - (body.length % 64)) % 64); };

/** `executeBatch((address target, uint256 value, bytes data)[])` with every value zero. */
export function encodeExecuteBatch(calls: readonly SponsoredCall[]): string {
  if (calls.length === 0) throw new EvmError("empty call batch");
  const tuples = calls.map((call) => {
    const data = checkHex(call.data, "call data");
    return addressWord(call.to) + word(0n) + word(96n) + word(BigInt(data.length / 2 - 1)) + padded(data);
  });
  let offset = BigInt(calls.length * 32);
  const offsets = tuples.map((tuple) => { const current = offset; offset += BigInt(tuple.length / 2); return word(current); });
  return `0x${SPONSOR_ABI.executeBatch}${word(32n)}${word(BigInt(calls.length))}${offsets.join("")}${tuples.join("")}`;
}

const rlpInt = (value: bigint): Uint8Array => {
  if (value === 0n) return Uint8Array.of(0x80);
  const hex = value.toString(16);
  return rlpBytes(hexToBytes(hex.length % 2 ? `0${hex}` : hex));
};
const rlpBytes = (bytes: Uint8Array): Uint8Array => {
  if (bytes.length === 1 && bytes[0]! < 0x80) return bytes;
  if (bytes.length >= 56) throw new EvmError("RLP item too long");
  return concatBytes(Uint8Array.of(0x80 + bytes.length), bytes);
};
const rlpList = (items: readonly Uint8Array[]): Uint8Array => {
  const body = concatBytes(...items);
  if (body.length >= 56) throw new EvmError("RLP list too long");
  return concatBytes(Uint8Array.of(0xc0 + body.length), body);
};

/** EIP-7702: `keccak256(0x05 || rlp([chain_id, address, nonce]))`, 0x-prefixed. */
export function authorizationDigest(authorization: Authorization): string {
  if (!Number.isSafeInteger(authorization.chainId) || authorization.chainId <= 0) throw new EvmError("authorization chain id must be a positive integer");
  if (authorization.nonce < 0n || authorization.nonce >= 1n << 64n) throw new EvmError("authorization nonce out of range");
  const payload = rlpList([rlpInt(BigInt(authorization.chainId)), rlpBytes(hexToBytes(checkEvmAddress(authorization.address, "delegate").slice(2))), rlpInt(authorization.nonce)]);
  return `0x${bytesToHex(keccak_256(concatBytes(Uint8Array.of(0x05), payload)))}`;
}

/** EntryPoint v0.7 `getUserOpHash`: the packed operation, then the EntryPoint and chain. */
export function userOpHash(entryPoint: string, chainId: number, op: UserOpV070): string {
  const factory = op.factory === undefined || op.factory === "0x" ? "" : addressWord(op.factory).slice(24) + checkHex(op.factoryData ?? "0x", "factoryData").slice(2);
  const paymaster = op.paymaster === undefined || op.paymaster === "0x" ? "" :
    addressWord(op.paymaster).slice(24) + half(quantity(op.paymasterVerificationGasLimit ?? "0x0", "paymasterVerificationGasLimit", MAX_UINT128)) +
    half(quantity(op.paymasterPostOpGasLimit ?? "0x0", "paymasterPostOpGasLimit", MAX_UINT128)) + checkHex(op.paymasterData ?? "0x", "paymasterData").slice(2);
  const hashOf = (hex: string): string => bytesToHex(keccak_256(hexToBytes(hex)));
  const packed = addressWord(op.sender) + word(quantity(op.nonce, "nonce")) + hashOf(factory) + hashOf(checkHex(op.callData, "callData").slice(2)) +
    half(quantity(op.verificationGasLimit, "verificationGasLimit", MAX_UINT128)) + half(quantity(op.callGasLimit, "callGasLimit", MAX_UINT128)) +
    word(quantity(op.preVerificationGas, "preVerificationGas")) +
    half(quantity(op.maxPriorityFeePerGas, "maxPriorityFeePerGas", MAX_UINT128)) + half(quantity(op.maxFeePerGas, "maxFeePerGas", MAX_UINT128)) + hashOf(paymaster);
  return `0x${bytesToHex(keccak_256(hexToBytes(hashOf(packed) + addressWord(entryPoint) + word(BigInt(chainId)))))}`;
}

/* ---------- staging key ---------- */

export const newStagingSecret = (): Uint8Array => secp256k1.utils.randomSecretKey();

export function stagingAddress(secret: Uint8Array): string {
  const publicKey = secp256k1.getPublicKey(secret, false);
  return `0x${bytesToHex(keccak_256(publicKey.subarray(1))).slice(24)}`;
}

/** 65-byte `r || s || v` (v = 27/28) over a 32-byte digest, no prefix. */
export function signDigest(secret: Uint8Array, digest: string): string {
  if (!HEX32.test(digest)) throw new EvmError("digest must be 32 bytes");
  const recovered = secp256k1.sign(hexToBytes(digest.slice(2)), secret, { prehash: false, format: "recovered" });
  return `0x${bytesToHex(recovered.subarray(1))}${(recovered[0]! + 27).toString(16)}`;
}

/** EIP-191 digest of a 32-byte hash, as `personal_sign` over raw bytes computes it. */
export function eip191Digest(hash: string): string {
  if (!HEX32.test(hash)) throw new EvmError("hash must be 32 bytes");
  return `0x${bytesToHex(keccak_256(concatBytes(encoder.encode("\x19Ethereum Signed Message:\n32"), hexToBytes(hash.slice(2)))))}`;
}

/* ---------- prepared-call verification ---------- */

const record = (value: unknown, what: string): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new EvmError(`${what} is not an object`);
  return value as Record<string, unknown>;
};
const sameAddress = (a: unknown, b: string): boolean => typeof a === "string" && a.toLowerCase() === b;

/**
 * Accept only a response that is exactly what we asked for: one `user-operation-v070` for the
 * staging account over our calldata on our chain, plus one `authorization` iff the account still
 * needs to delegate. Every digest is recomputed; the sponsor's own payloads must match it.
 */
export async function verifyPreparedCalls(config: SponsorConfig, result: unknown, expect: PreparedExpectation): Promise<VerifiedPrepared> {
  const top = record(result, "prepared calls");
  const entries = top.type === "array" ? (Array.isArray(top.data) ? top.data : []).map((entry) => record(entry, "prepared entry")) : [top];
  const ops = entries.filter((entry) => entry.type === "user-operation-v070");
  const auths = entries.filter((entry) => entry.type === "authorization");
  if (ops.length !== 1 || auths.length > 1 || ops.length + auths.length !== entries.length) throw new EvmError("sponsor returned an unexpected set of prepared entries");
  const opEntry = ops[0]!;
  if (quantity(opEntry.chainId, "user operation chain id") !== BigInt(config.chainId)) throw new EvmError("sponsor prepared the user operation for another chain");
  const op = record(opEntry.data, "user operation") as unknown as UserOpV070;
  if (!sameAddress(op.sender, expect.sender)) throw new EvmError("sponsor changed the user operation sender");
  if ((op.factory !== undefined && op.factory !== "0x") || (op.factoryData !== undefined && op.factoryData !== "0x")) throw new EvmError("sponsor added account deployment code");
  const callData = checkHex(op.callData, "callData");
  if (callData !== expect.callData && callData !== `0x${SPONSOR_ABI.executeUserOp}${expect.callData.slice(2)}`) throw new EvmError("sponsor changed the calls to execute");
  const nonce = quantity(op.nonce, "nonce");
  if ((nonce & ((1n << 64n) - 1n)) !== await expect.accountSequence(nonce >> 64n)) throw new EvmError("sponsor used a stale account nonce");
  const hasPaymaster = op.paymaster !== undefined && op.paymaster !== "0x";
  if (!hasPaymaster && quantity(op.maxFeePerGas, "maxFeePerGas", MAX_UINT128) !== 0n) throw new EvmError("sponsor is not paying for gas");
  const hash = userOpHash(config.entryPoint, config.chainId, op);
  const request = record(opEntry.signatureRequest, "signature request");
  if (request.type !== "personal_sign" || !sameAddress(record(request.data, "signature request data").raw, hash)) throw new EvmError("sponsor asked to sign something other than the user operation");
  const feePayment = opEntry.feePayment === undefined ? null : record(opEntry.feePayment, "fee payment");
  // A token paymaster would charge the account (which holds the payout) instead of sponsoring it.
  if (feePayment !== null && feePayment.sponsored !== true) throw new EvmError("sponsor is not paying for gas");
  let authorization: VerifiedPrepared["authorization"] = null;
  if (expect.authorizationNonce === null) {
    if (auths.length !== 0) throw new EvmError("sponsor requested a delegation the account does not need");
  } else {
    const entry = auths[0];
    if (!entry) throw new EvmError("sponsor did not include the required delegation");
    const data = record(entry.data, "authorization data");
    if (quantity(entry.chainId, "authorization chain id") !== BigInt(config.chainId) || !sameAddress(data.address, config.delegate) || quantity(data.nonce, "authorization nonce") !== expect.authorizationNonce) {
      throw new EvmError("sponsor requested a delegation to another delegate, chain, or nonce");
    }
    const digest = authorizationDigest({ chainId: config.chainId, address: config.delegate, nonce: expect.authorizationNonce });
    const authRequest = record(entry.signatureRequest, "authorization signature request");
    if (authRequest.type !== "eip7702Auth" || !sameAddress(authRequest.rawPayload, digest)) throw new EvmError("sponsor's delegation payload does not match the pinned delegation");
    authorization = { entry, digest };
  }
  return { userOp: op, userOpHash: hash, userOpChainId: opEntry.chainId as string, authorization, sponsored: feePayment?.sponsored === true };
}

export function signPreparedCalls(verified: VerifiedPrepared, secret: Uint8Array): unknown {
  const opSignature = signDigest(secret, eip191Digest(verified.userOpHash));
  const op = { type: "user-operation-v070", data: verified.userOp, chainId: verified.userOpChainId, signature: { type: "secp256k1", data: opSignature } };
  if (verified.authorization === null) return op;
  const { entry, digest } = verified.authorization;
  return { type: "array", data: [
    { type: "authorization", data: entry.data, chainId: entry.chainId, signature: { type: "secp256k1", data: signDigest(secret, digest) } },
    op,
  ] };
}

/* ---------- client ---------- */

export const DELEGATION_PREFIX = "0xef0100";

/** Status codes of `wallet_getCallsStatus`: 1xx pending, 200 confirmed, 115/116 and 4xx-6xx failed. */
export type SponsoredStatus = { readonly state: "pending" } | { readonly state: "confirmed"; readonly txHash: string } | { readonly state: "failed"; readonly status: number };

export class GasSponsor {
  private readonly fetchFn: (input: string, init: RequestInit) => Promise<Response>;
  constructor(readonly config: SponsorConfig, fetchFn?: (input: string, init: RequestInit) => Promise<Response>) {
    checkEvmAddress(config.entryPoint, "EntryPoint"); checkEvmAddress(config.delegate, "delegate");
    if (!Number.isSafeInteger(config.chainId) || config.chainId <= 0) throw new EvmError("sponsor chain id must be a positive integer");
    this.fetchFn = fetchFn ?? ((input, init) => fetch(input, init));
  }

  async call(method: string, params: unknown[]): Promise<unknown> {
    const response = await this.fetchFn(this.config.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    if (!response.ok) throw new EvmError(`gas sponsor ${method} failed: HTTP ${response.status}`);
    const body = await response.json() as { result?: unknown; error?: { message?: string } };
    if (body.error) throw new EvmError(`gas sponsor ${method} failed: ${body.error.message ?? "error"}`);
    return body.result;
  }

  /** Whether the staging account may be used: undelegated, or delegated to the pinned delegate. */
  async delegationNonce(rpc: EvmRpc, sender: string): Promise<bigint | null> {
    const code = checkHex(await rpc.call("eth_getCode", [sender, "latest"]), "account code");
    if (code === `${DELEGATION_PREFIX}${this.config.delegate.slice(2)}`) return null;
    if (code !== "0x") throw new EvmError("staging account is delegated to an unknown contract; refusing to use it");
    return quantity(await rpc.call("eth_getTransactionCount", [sender, "pending"]), "account nonce");
  }

  /** Prepare, verify, sign, and submit `calls` from the staging account. Returns the sponsor's call id. */
  async submit(rpc: EvmRpc, secret: Uint8Array, calls: readonly SponsoredCall[]): Promise<{ readonly callId: string; readonly userOpHash: string }> {
    const sender = stagingAddress(secret), callData = encodeExecuteBatch(calls);
    const authorizationNonce = await this.delegationNonce(rpc, sender);
    const result = await this.call("wallet_prepareCalls", [{
      from: sender, chainId: `0x${this.config.chainId.toString(16)}`,
      calls: calls.map((call) => ({ to: checkEvmAddress(call.to, "call target"), data: checkHex(call.data, "call data"), value: "0x0" })),
      capabilities: { eip7702Auth: true, ...(this.config.policyId ? { paymasterService: { policyId: this.config.policyId } } : {}) },
    }]);
    const verified = await verifyPreparedCalls(this.config, result, {
      sender, callData, authorizationNonce,
      accountSequence: async (key) => {
        const data = `0x${SPONSOR_ABI.getNonce}${addressWord(sender)}${word(key)}`;
        return quantity(await rpc.call("eth_call", [{ to: this.config.entryPoint, data }, "latest"]), "EntryPoint nonce") & ((1n << 64n) - 1n);
      },
    });
    const signed = signPreparedCalls(verified, secret);
    const sent = record(await this.call("wallet_sendPreparedCalls", [signed]), "send result");
    // `id` is current; `preparedCallIds` is the older (still returned) form.
    const id = typeof sent.id === "string" ? sent.id : Array.isArray(sent.preparedCallIds) ? sent.preparedCallIds[0] : undefined;
    if (typeof id !== "string" || id.length === 0) throw new EvmError("gas sponsor returned no call id");
    return { callId: id, userOpHash: verified.userOpHash };
  }

  async status(callId: string): Promise<SponsoredStatus> {
    const result = record(await this.call("wallet_getCallsStatus", [callId]), "call status");
    const status = typeof result.status === "number" ? result.status : Number.NaN;
    if (status === 200) {
      const receipts = Array.isArray(result.receipts) ? result.receipts : [];
      const hash = receipts[0] === undefined ? undefined : record(receipts[0], "receipt").transactionHash;
      if (typeof hash !== "string" || !HEX32.test(hash)) throw new EvmError("gas sponsor reported success without a transaction hash");
      return { state: "confirmed", txHash: hash.slice(2).toLowerCase() };
    }
    // 115/116 are failed preconfirmations; other 1xx (pending, preconfirmed) wait for 200.
    if (status >= 100 && status < 200 && status !== 115 && status !== 116) return { state: "pending" };
    return { state: "failed", status };
  }

  /** Poll until the sponsor reports inclusion; the caller still verifies the effect on chain. */
  async awaitInclusion(callId: string, options: { readonly intervalMs?: number; readonly timeoutMs?: number; readonly signal?: AbortSignal } = {}): Promise<string> {
    const deadline = Date.now() + (options.timeoutMs ?? 300_000);
    for (;;) {
      options.signal?.throwIfAborted();
      const status = await this.status(callId);
      if (status.state === "confirmed") return status.txHash;
      if (status.state === "failed") throw new EvmError(`gas sponsor reported failure (status ${status.status}) for call ${callId}`);
      if (Date.now() > deadline) throw new EvmError(`gas sponsor call ${callId} is still pending`);
      await new Promise((resolve) => setTimeout(resolve, options.intervalMs ?? 2_000));
    }
  }
}
