/**
 * Find the user's deposit to a contract address through the explicitly trusted
 * chain API, so a plain wallet "send" can fund a swap without a PSBT.
 *
 * The API is asked for the address history (it learns the contract address,
 * which it would learn from the funding transaction anyway). A deposit counts
 * only once confirmed: a wallet may replace an unconfirmed transaction, and the
 * provider accepts exactly one binding (revision zero) per swap. The raw bytes
 * of the deposit and of every parent transaction are fetched and re-hashed, so
 * input values (the fee check) rest on verified bytes, not API metadata.
 */
import { hexToBytes } from "@noble/hashes/utils.js";

import { readBoundedChainText, type ChainFetch } from "./chainTip";
import { parseStrictEventJson } from "../strictEventJson";
import { type FinalizedFunding, MAX_TRANSACTION_BYTES, parseTransaction, TransactionRefusedError } from "./transaction";

const HEX32 = /^[0-9a-f]{64}$/;
const MAX_HISTORY_BYTES = 1024 * 1024;

export type DepositObservation =
  | { readonly status: "none" }
  /** Seen in the API's mempool; wait for confirmation before binding. */
  | { readonly status: "unconfirmed"; readonly txid: string }
  /** Exactly one confirmed deposit, with verified bytes and input values. */
  | { readonly status: "confirmed"; readonly funding: FinalizedFunding }
  /** Several confirmed deposits: never pick one automatically (RS-002 duplicate deposits). */
  | { readonly status: "ambiguous"; readonly txids: readonly string[] };

export interface DepositWatchTarget {
  readonly address: string;
  /** Contract output script, lowercase hex. */
  readonly script: string;
  readonly amountSat: bigint;
}

/**
 * One observation of `target` through `api` (a validated mempool-style base URL).
 * Throws on API or parsing failure (unknown, not "no deposit"); throws
 * `TransactionRefusedError` when the confirmed deposit's bytes cannot be verified.
 */
export async function observeDeposit(
  api: string,
  target: DepositWatchTarget,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<DepositObservation> {
  const transport = options.fetch ?? fetch;
  const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000);
  signal.throwIfAborted();
  const get = async (path: string, limit: number): Promise<string> => readBoundedChainText(await transport(`${api}/${path}`, {
    signal, method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  }), signal, limit);
  const history = parseStrictEventJson(await get(`address/${target.address}/txs`, MAX_HISTORY_BYTES), MAX_HISTORY_BYTES);
  if (!Array.isArray(history)) throw new Error("Chain API returned an unexpected address history");
  const candidates = history.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const { txid, vout, status } = item as { txid?: unknown; vout?: unknown; status?: unknown };
    if (typeof txid !== "string" || !HEX32.test(txid) || !Array.isArray(vout)) return [];
    const pays = vout.some((output) => output && typeof output === "object" &&
      (output as { scriptpubkey?: unknown }).scriptpubkey === target.script &&
      (output as { value?: unknown }).value === Number(target.amountSat));
    if (!pays) return [];
    const confirmed = !!status && typeof status === "object" && (status as { confirmed?: unknown }).confirmed === true;
    return [{ txid, confirmed }];
  });
  const confirmed = candidates.filter((candidate) => candidate.confirmed);
  if (confirmed.length > 1) return { status: "ambiguous", txids: confirmed.map((candidate) => candidate.txid) };
  if (confirmed.length === 0) {
    const pending = candidates[0];
    return pending ? { status: "unconfirmed", txid: pending.txid } : { status: "none" };
  }
  const txid = confirmed[0]!.txid;
  const fetchTransaction = async (id: string) => {
    const hex = await get(`tx/${id}/hex`, MAX_TRANSACTION_BYTES * 2);
    if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new TransactionRefusedError("chain API returned malformed transaction bytes");
    const transaction = parseTransaction(hexToBytes(hex));
    if (transaction.txid !== id) throw new TransactionRefusedError("chain API transaction bytes do not match their txid");
    return transaction;
  };
  const transaction = await fetchTransaction(txid);
  const inputValues: bigint[] = [];
  for (const input of transaction.inputs) {
    const parent = await fetchTransaction(input.txid);
    const spent = parent.outputs[input.vout];
    if (!spent) throw new TransactionRefusedError("deposit spends an unknown output");
    inputValues.push(spent.value);
  }
  return { status: "confirmed", funding: { transaction, inputValues } };
}
