/**
 * RS-010 browser chain access: read the EVM chain over JSON-RPC and sign
 * through an injected EIP-1193 wallet. Only the Boltz ERC20Swap v6 surface
 * RillSwap uses is encoded here, by hand: every argument is a fixed 32-byte
 * word, so no ABI library is needed. Nothing here holds keys.
 */
import { keccak_256 } from "@noble/hashes/sha3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import artifact from "../generated/erc20SwapIdentity.json";

const encoder = new TextEncoder();
const ADDRESS = /^0x[0-9a-f]{40}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const MAX_LOG_RANGE = 10_000;

export class EvmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvmError";
  }
}

export function checkEvmAddress(value: unknown, what: string): string {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new EvmError(`${what} is not a lowercase 0x address`);
  return value;
}

const selector = (signature: string): string => bytesToHex(keccak_256(encoder.encode(signature))).slice(0, 8);
const word = (value: bigint): string => {
  if (value < 0n || value > MAX_UINT256) throw new EvmError("value does not fit uint256");
  return value.toString(16).padStart(64, "0");
};
const addressWord = (address: string): string => checkEvmAddress(address, "address").slice(2).padStart(64, "0");
const hashWord = (hex32: string): string => {
  if (!HEX32.test(hex32)) throw new EvmError("expected 32 bytes of lowercase hex");
  return hex32;
};
const wordAt = (data: string, index: number): string => {
  const body = data.startsWith("0x") ? data.slice(2) : data;
  const slice = body.slice(index * 64, index * 64 + 64);
  if (slice.length !== 64) throw new EvmError("short ABI data");
  return slice;
};
const wordAddress = (w: string): string => `0x${w.slice(24)}`;
const wordUint = (w: string): bigint => BigInt(`0x${w}`);

/** The exact lock the HTLC hashes (ERC20Swap v6 `hashValues`), all lowercase. */
export interface HtlcLock {
  readonly preimageHash: string; // 32 bytes hex, no 0x
  readonly amount: bigint; // token base units
  readonly token: string;
  readonly claimAddress: string;
  readonly refundAddress: string;
  readonly timelock: number; // absolute block number
}

export const ABI = Object.freeze({
  lock: selector("lock(bytes32,uint256,address,address,address,uint256)"),
  refund: selector("refund(bytes32,uint256,address,address,address,uint256)"),
  claim: selector("claim(bytes32,uint256,address,address,address,uint256)"),
  swaps: selector("swaps(bytes32)"),
  hashValues: selector("hashValues(bytes32,uint256,address,address,address,uint256)"),
  version: selector("version()"),
  approve: selector("approve(address,uint256)"),
  transfer: selector("transfer(address,uint256)"),
  allowance: selector("allowance(address,address)"),
  balanceOf: selector("balanceOf(address)"),
  lockupTopic: `0x${bytesToHex(keccak_256(encoder.encode("Lockup(bytes32,uint256,address,address,address,uint256)")))}`,
  claimTopic: `0x${bytesToHex(keccak_256(encoder.encode("Claim(bytes32,bytes32)")))}`,
  refundTopic: `0x${bytesToHex(keccak_256(encoder.encode("Refund(bytes32)")))}`,
  transferTopic: `0x${bytesToHex(keccak_256(encoder.encode("Transfer(address,address,uint256)")))}`,
});

const lockWords = (lock: HtlcLock): string =>
  hashWord(lock.preimageHash) + word(lock.amount) + addressWord(lock.token) +
  addressWord(lock.claimAddress) + addressWord(lock.refundAddress) + word(BigInt(lock.timelock));

export const encodeLock = (lock: HtlcLock): string => `0x${ABI.lock}${lockWords(lock)}`;
export const encodeRefund = (lock: HtlcLock): string => `0x${ABI.refund}${lockWords(lock)}`;
export const encodeClaim = (lock: HtlcLock, preimage: string): string =>
  `0x${ABI.claim}${hashWord(preimage)}${lockWords(lock).slice(64)}`;
export const encodeApprove = (spender: string, amount: bigint): string => `0x${ABI.approve}${addressWord(spender)}${word(amount)}`;
export const encodeTransfer = (to: string, amount: bigint): string => `0x${ABI.transfer}${addressWord(to)}${word(amount)}`;

/** keccak256 of the packed lock values: the key of the HTLC's `swaps` mapping. */
export function lockHash(lock: HtlcLock): string {
  return bytesToHex(keccak_256(hexToBytes(lockWords(lock))));
}

/** Compare executable code to the vendored artifact, masking only compiler-declared immutables. */
export function isErc20SwapCode(code: unknown): boolean {
  if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code) || code.length !== artifact.runtimeHexLength) return false;
  const bytes = hexToBytes(code.slice(2));
  for (const { start, length } of artifact.immutableRanges) bytes.fill(0, start, start + length);
  return bytesToHex(sha256(bytes)) === artifact.maskedRuntimeSha256;
}

export interface LockupLog {
  readonly txHash: string; // 32 bytes hex, no 0x
  readonly logIndex: number;
  readonly blockNumber: number;
  readonly lock: HtlcLock;
}

export interface ClaimLog {
  readonly txHash: string;
  readonly blockNumber: number;
  readonly preimage: string;
}

interface RawLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
  readonly transactionHash: string;
  readonly logIndex: string;
  readonly blockNumber: string;
  readonly removed?: boolean;
}

const hexInt = (value: unknown, what: string): number => {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,16}$/.test(value)) throw new EvmError(`${what} is not a hex quantity`);
  const parsed = Number.parseInt(value, 16);
  if (!Number.isSafeInteger(parsed)) throw new EvmError(`${what} is out of range`);
  return parsed;
};

/** Stateless JSON-RPC reads against one configured endpoint; never signs. */
export class EvmRpc {
  private readonly fetchFn: (input: string, init: RequestInit) => Promise<Response>;
  constructor(private readonly url: string, fetchFn?: (input: string, init: RequestInit) => Promise<Response>) {
    // A bare `fetch` reference loses its window binding ("Illegal invocation" in browsers).
    this.fetchFn = fetchFn ?? ((input, init) => fetch(input, init));
  }

  async call(method: string, params: unknown[]): Promise<unknown> {
    const response = await this.fetchFn(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    if (!response.ok) throw new EvmError(`EVM RPC ${method} failed: HTTP ${response.status}`);
    const body = await response.json() as { result?: unknown; error?: { message?: string } };
    if (body.error) throw new EvmError(`EVM RPC ${method} failed: ${body.error.message ?? "error"}`);
    return body.result;
  }

  async chainId(): Promise<number> { return hexInt(await this.call("eth_chainId", []), "chain id"); }
  async blockNumber(): Promise<number> { return hexInt(await this.call("eth_blockNumber", []), "block number"); }

  async verifyHtlc(htlc: string): Promise<void> {
    checkEvmAddress(htlc, "HTLC");
    if (!isErc20SwapCode(await this.call("eth_getCode", [htlc, "latest"]))) throw new EvmError("HTLC bytecode does not match the vendored ERC20Swap v6");
  }

  async nativeBalance(account: string): Promise<bigint> {
    const value = await this.call("eth_getBalance", [checkEvmAddress(account, "account"), "latest"]);
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new EvmError("invalid gas balance");
    return BigInt(value);
  }

  async gasPrice(): Promise<bigint> {
    const value = await this.call("eth_gasPrice", []);
    if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) throw new EvmError("invalid gas price");
    return BigInt(value);
  }

  private async read(to: string, data: string): Promise<string> {
    const result = await this.call("eth_call", [{ to, data }, "latest"]);
    if (typeof result !== "string" || !result.startsWith("0x")) throw new EvmError("eth_call returned no data");
    return result;
  }

  async htlcVersion(htlc: string): Promise<number> { return Number(wordUint(wordAt(await this.read(htlc, `0x${ABI.version}`), 0))); }

  /** Whether the exact lock is currently locked (neither claimed nor refunded). */
  async lockActive(htlc: string, lock: HtlcLock): Promise<boolean> {
    return wordUint(wordAt(await this.read(htlc, `0x${ABI.swaps}${lockHash(lock)}`), 0)) === 1n;
  }

  async allowance(token: string, owner: string, spender: string): Promise<bigint> {
    return wordUint(wordAt(await this.read(token, `0x${ABI.allowance}${addressWord(owner)}${addressWord(spender)}`), 0));
  }

  async balanceOf(token: string, owner: string): Promise<bigint> {
    return wordUint(wordAt(await this.read(token, `0x${ABI.balanceOf}${addressWord(owner)}`), 0));
  }

  private async logs(htlc: string, topics: (string | null)[], fromBlock: number, toBlock: number): Promise<RawLog[]> {
    const found: RawLog[] = [];
    for (let start = Math.max(0, fromBlock); start <= toBlock; start += MAX_LOG_RANGE) {
      const result = await this.call("eth_getLogs", [{
        address: htlc, topics, fromBlock: `0x${start.toString(16)}`, toBlock: `0x${Math.min(toBlock, start + MAX_LOG_RANGE - 1).toString(16)}`,
      }]);
      if (!Array.isArray(result)) throw new EvmError("eth_getLogs returned no list");
      found.push(...(result as RawLog[]).filter((log) => !log.removed && log.address.toLowerCase() === htlc));
    }
    return found;
  }

  /** Lockup logs for a payment hash; the caller matches the exact lock values. */
  async findLockups(htlc: string, preimageHash: string, fromBlock: number, toBlock: number): Promise<LockupLog[]> {
    const logs = await this.logs(htlc, [ABI.lockupTopic, `0x${hashWord(preimageHash)}`], fromBlock, toBlock);
    return logs.map((log) => ({
      txHash: log.transactionHash.slice(2).toLowerCase(),
      logIndex: hexInt(log.logIndex, "log index"),
      blockNumber: hexInt(log.blockNumber, "block number"),
      lock: {
        preimageHash: log.topics[1]!.slice(2).toLowerCase(),
        amount: wordUint(wordAt(log.data, 0)),
        token: wordAddress(wordAt(log.data, 1)),
        claimAddress: wordAddress(log.topics[2]!.slice(2).toLowerCase()),
        refundAddress: wordAddress(log.topics[3]!.slice(2).toLowerCase()),
        timelock: Number(wordUint(wordAt(log.data, 2))),
      },
    }));
  }

  async findClaim(htlc: string, preimageHash: string, fromBlock: number, toBlock: number): Promise<ClaimLog | null> {
    const [log] = await this.logs(htlc, [ABI.claimTopic, `0x${hashWord(preimageHash)}`], fromBlock, toBlock);
    if (!log) return null;
    return { txHash: log.transactionHash.slice(2).toLowerCase(), blockNumber: hexInt(log.blockNumber, "block number"), preimage: wordAt(log.data, 0) };
  }

  /** Null until mined; `status` is true on success. */
  async receipt(txHash: string): Promise<{ blockNumber: number; status: boolean } | null> {
    const result = await this.call("eth_getTransactionReceipt", [`0x${hashWord(txHash)}`]) as { blockNumber?: string; status?: string } | null;
    if (result === null || result === undefined) return null;
    return { blockNumber: hexInt(result.blockNumber, "block number"), status: result.status === "0x1" };
  }

  /** Token amount the mined transaction `txHash` transferred to `to` (sum of the token's Transfer logs). */
  async transferred(txHash: string, token: string, to: string): Promise<bigint> {
    const result = await this.call("eth_getTransactionReceipt", [`0x${hashWord(txHash)}`]) as { logs?: RawLog[] } | null;
    if (!result || !Array.isArray(result.logs)) throw new EvmError("transaction receipt unavailable");
    return result.logs.filter((log) => !log.removed && log.address.toLowerCase() === checkEvmAddress(token, "token") && log.topics[0] === ABI.transferTopic &&
      log.topics.length === 3 && wordAddress(log.topics[2]!.slice(2).toLowerCase()) === checkEvmAddress(to, "recipient"))
      .reduce((sum, log) => sum + wordUint(wordAt(log.data, 0)), 0n);
  }
}

/** The subset of EIP-1193 the swap needs. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export function injectedProvider(): Eip1193Provider | null {
  const candidate = (globalThis as { ethereum?: unknown }).ethereum;
  return candidate !== null && typeof candidate === "object" && typeof (candidate as Eip1193Provider).request === "function"
    ? candidate as Eip1193Provider : null;
}

/** Signs through the user's wallet; the wallet, not this page, holds the key. */
export class EvmWallet {
  constructor(private readonly provider: Eip1193Provider) {}

  /** Recheck without prompting or switching chains before disclosing a claim preimage. */
  async assertAccount(chainId: number, account: string): Promise<void> {
    const accounts = await this.provider.request({ method: "eth_accounts" });
    if (hexInt(await this.provider.request({ method: "eth_chainId" }), "wallet chain id") !== chainId ||
        !Array.isArray(accounts) || typeof accounts[0] !== "string" || accounts[0].toLowerCase() !== account) {
      throw new EvmError("Wallet account or chain changed; reconnect before claiming");
    }
  }

  /** Prompt for the account and make sure the wallet is on `chainId`. */
  async connect(chainId: number): Promise<string> {
    const accounts = await this.provider.request({ method: "eth_requestAccounts" }) as unknown;
    if (!Array.isArray(accounts) || typeof accounts[0] !== "string") throw new EvmError("wallet exposed no account");
    const current = hexInt(await this.provider.request({ method: "eth_chainId" }), "wallet chain id");
    if (current !== chainId) {
      await this.provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: `0x${chainId.toString(16)}` }] });
      if (hexInt(await this.provider.request({ method: "eth_chainId" }), "wallet chain id") !== chainId) {
        throw new EvmError(`wallet is not on chain ${chainId}`);
      }
    }
    return checkEvmAddress(accounts[0].toLowerCase(), "wallet account");
  }

  /** Returns the transaction hash (32 bytes hex, no 0x). */
  async send(from: string, to: string, data: string): Promise<string> {
    const hash = await this.provider.request({ method: "eth_sendTransaction", params: [{ from, to, data }] });
    if (typeof hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(hash)) throw new EvmError("wallet returned no transaction hash");
    return hash.slice(2).toLowerCase();
  }
}

/** Poll until `txHash` reaches the requested depth (including its block), or `signal` aborts. */
export async function awaitReceipt(
  rpc: EvmRpc, txHash: string, confirmations: number,
  options: { readonly intervalMs?: number; readonly signal?: AbortSignal; readonly timeoutMs?: number } = {},
): Promise<{ blockNumber: number; status: boolean }> {
  const interval = options.intervalMs ?? 2_000;
  const deadline = Date.now() + (options.timeoutMs ?? 600_000);
  for (;;) {
    if (options.signal?.aborted) throw new EvmError("aborted while waiting for the transaction");
    const receipt = await rpc.receipt(txHash);
    if (receipt !== null) {
      if (!receipt.status) return receipt;
      if (await rpc.blockNumber() - receipt.blockNumber + 1 >= confirmations) return receipt;
    }
    if (Date.now() > deadline) throw new EvmError(`transaction ${txHash} is still unconfirmed`);
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}
