/**
 * Minimal monerod + monero-wallet-rpc client for the local regtest receipt rail.
 * Only read methods plus `create_address`/`store` are used; nothing here spends.
 */

/** One incoming (txid, subaddress) entry as reported by `get_transfers`. */
export interface MoneroTransfer {
  readonly txid: string;
  /** "in" (confirmed), "pool" (mempool); other types (e.g. coinbase "block") never count. */
  readonly type: string;
  readonly amountAtomic: bigint;
  readonly height: number;
  readonly confirmations: number;
  readonly timestamp: number;
  readonly unlockTime: string;
  readonly locked: boolean;
  readonly doubleSpendSeen: boolean;
  readonly major: number;
  readonly minor: number;
  readonly address: string;
}
export interface MoneroSnapshot {
  readonly nettype: string;
  /** Daemon height read before the wallet refreshed. */
  readonly daemonHeight: number;
  readonly walletHeight: number;
  readonly anchorHash: string;
  readonly primaryAddress: string;
}
/** What the ledger needs from the wallet and its daemon (faked in tests). */
export interface MoneroRpc {
  /** Refreshes the wallet and reports the identity/height evidence to check. */
  snapshot(anchorHeight: number): Promise<MoneroSnapshot>;
  createSubaddress(label: string): Promise<{ readonly minor: number; readonly address: string }>;
  /** Persists the wallet file, so allocated subaddresses survive a crash. */
  store(): Promise<void>;
  /** Incoming confirmed and pool transfers of account 0 for these subaddress indices. */
  transfers(minors: readonly number[]): Promise<MoneroTransfer[]>;
}

/**
 * JSON.parse that keeps every integer literal as a decimal string. Monero
 * amounts are uint64 piconero and silently lose precision as JS numbers.
 */
export function parseJsonLossless(text: string): unknown {
  let out = "", index = 0;
  while (index < text.length) {
    const char = text[index]!;
    if (char === "\"") {
      let end = index + 1;
      while (end < text.length && text[end] !== "\"") end += text[end] === "\\" ? 2 : 1;
      out += text.slice(index, end + 1); index = end + 1;
    } else if (char === "-" || (char >= "0" && char <= "9")) {
      const token = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(index))?.[0];
      if (!token) throw new SyntaxError("Invalid JSON number");
      out += /^-?\d+$/.test(token) ? `"${token}"` : token; index += token.length;
    } else { out += char; index += 1; }
  }
  return JSON.parse(out);
}

const record = (value: unknown, what: string): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid Monero RPC ${what}`);
  return value as Record<string, unknown>;
};
const integer = (value: unknown, what: string): number => {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,15})$/.test(value) || !Number.isSafeInteger(Number(value))) throw new Error(`Invalid Monero RPC ${what}`);
  return Number(value);
};
const atomic = (value: unknown): bigint => {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) >= 1n << 64n) throw new Error("Invalid Monero RPC amount");
  return BigInt(value);
};
const text = (value: unknown, what: string): string => { if (typeof value !== "string") throw new Error(`Invalid Monero RPC ${what}`); return value; };
const flag = (value: unknown, what: string): boolean => { if (typeof value !== "boolean") throw new Error(`Invalid Monero RPC ${what}`); return value; };

/** Validates one raw (losslessly parsed) `get_transfers` entry. */
export function parseMoneroTransfer(input: unknown): MoneroTransfer {
  const entry = record(input, "transfer"), index = record(entry.subaddr_index, "subaddress index");
  return Object.freeze({
    txid: text(entry.txid, "txid"), type: text(entry.type, "transfer type"), amountAtomic: atomic(entry.amount),
    height: integer(entry.height, "height"), confirmations: integer(entry.confirmations ?? "0", "confirmations"), timestamp: integer(entry.timestamp, "timestamp"),
    unlockTime: text(entry.unlock_time, "unlock time"), locked: flag(entry.locked, "locked"), doubleSpendSeen: flag(entry.double_spend_seen, "double spend flag"),
    major: integer(index.major, "account"), minor: integer(index.minor, "subaddress"), address: text(entry.address, "address"),
  });
}

export interface MoneroRpcOptions {
  readonly walletUrl: string;
  readonly daemonUrl: string;
  /** Wallet file (no password) reopened if wallet-rpc restarted without one open. */
  readonly walletFile: string;
  readonly timeoutMs?: number;
}

/** JSON-RPC client for one wallet-rpc process and the monerod it is configured against. */
export function createMoneroRpc(options: MoneroRpcOptions): MoneroRpc {
  for (const url of [options.walletUrl, options.daemonUrl]) {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("Plain Monero RPC base URL required");
  }
  const timeout = options.timeoutMs ?? 60_000;
  const call = async (base: string, method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
    const response = await fetch(new URL("/json_rpc", base), { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "0", method, params }), signal: AbortSignal.timeout(timeout) });
    if (!response.ok) throw new Error(`Monero RPC ${method} HTTP ${response.status}`);
    const body = record(parseJsonLossless(await response.text()), "response");
    if (body.error !== undefined) {
      const error = record(body.error, "error");
      throw Object.assign(new Error(`Monero RPC ${method}: ${String(error.message)}`), { code: String(error.code) });
    }
    return record(body.result, "result");
  };
  const wallet = async (method: string, params: Record<string, unknown> = {}): Promise<Record<string, unknown>> => {
    try { return await call(options.walletUrl, method, params); } catch (error) {
      if ((error as { code?: string }).code !== "-13") throw error; // no wallet open
    }
    await call(options.walletUrl, "open_wallet", { filename: options.walletFile, password: "" });
    return call(options.walletUrl, method, params);
  };
  return {
    async snapshot(anchorHeight) {
      const info = await call(options.daemonUrl, "get_info");
      const daemonHeight = integer(info.height, "daemon height");
      const header = record((await call(options.daemonUrl, "get_block_header_by_height", { height: anchorHeight })).block_header, "block header");
      await wallet("refresh");
      const walletHeight = integer((await wallet("get_height")).height, "wallet height");
      const primary = await wallet("get_address", { account_index: 0, address_index: [0] });
      return { nettype: text(info.nettype, "nettype"), daemonHeight, walletHeight, anchorHash: text(header.hash, "block hash"), primaryAddress: text(primary.address, "address") };
    },
    async createSubaddress(label) {
      const result = await wallet("create_address", { account_index: 0, label, count: 1 });
      return { minor: integer(result.address_index, "subaddress index"), address: text(result.address, "address") };
    },
    async store() { await wallet("store"); },
    async transfers(minors) {
      if (!minors.length) return [];
      const result = await wallet("get_transfers", { in: true, pool: true, account_index: 0, subaddr_indices: [...minors] });
      return [...((result.in as unknown[] | undefined) ?? []), ...((result.pool as unknown[] | undefined) ?? [])].map(parseMoneroTransfer);
    },
  };
}
