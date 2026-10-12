import { describe, expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { scriptAddress } from "../src/swap/address";
import { observeDeposit } from "../src/swap/depositWatch";
import { authorizeFunding, type FundingTermsInput } from "../src/swap/funding";
import { parseTransaction, serializeTransaction, type Transaction, TransactionRefusedError } from "../src/swap/transaction";
import taproot from "./fixtures/taproot-cases-v1.json";

const vector = taproot.valid[0]!;
const terms = { ...vector.contract_terms, max_funding_fee_sat: "500" } as unknown as FundingTermsInput;
const script = vector.artifacts.script_pubkey;
const amount = BigInt(terms.economics.contract_amount_sat);
const address = scriptAddress(script, "regtest");
const API = "https://chain.example/api";
const CHANGE = `0014${"ab".repeat(20)}`;

type Shape = { version?: number; scriptSig?: Uint8Array; witness?: Uint8Array[]; change?: string; parentValue?: bigint };
/** A parent paying `parentValue` to a P2WPKH, and a deposit spending it into the contract plus change. */
function deposit(shape: Shape = {}): { parent: Transaction; tx: Transaction } {
  const coinbase = { txid: "11".repeat(32), vout: 0, scriptSig: new Uint8Array(), sequence: 0xffffffff, witness: [new Uint8Array([1])] };
  const parentValue = shape.parentValue ?? amount + 1_000n;
  const parentBytes = serializeTransaction({ version: 2, inputs: [coinbase], outputs: [{ value: parentValue, script: hexToBytes(CHANGE) }], locktime: 0 }, true);
  const parent = parseTransaction(parentBytes);
  const input = { txid: parent.txid, vout: 0, scriptSig: shape.scriptSig ?? new Uint8Array(), sequence: 0xfffffffd, witness: shape.witness ?? [new Uint8Array(64)] };
  const outputs = [{ value: amount, script: hexToBytes(script) }, { value: 800n, script: hexToBytes(shape.change ?? CHANGE) }];
  const bytes = serializeTransaction({ version: shape.version ?? 2, inputs: [input], outputs, locktime: 0 }, true);
  return { parent, tx: parseTransaction(bytes) };
}

function api(history: unknown[], transactions: readonly Transaction[], calls: string[] = []) {
  return async (input: RequestInfo | URL): Promise<Response> => {
    const path = new URL(String(input)).pathname.replace("/api/", "");
    calls.push(path);
    if (path === `address/${address}/txs`) return new Response(JSON.stringify(history));
    const hex = path.match(/^tx\/([0-9a-f]{64})\/hex$/);
    const found = hex && transactions.find((tx) => tx.txid === hex[1]);
    return found ? new Response(bytesToHex(found.raw)) : new Response("not found", { status: 404 });
  };
}

const entry = (tx: Transaction, confirmed: boolean) => ({
  txid: tx.txid, status: { confirmed },
  vout: tx.outputs.map((output) => ({ scriptpubkey: bytesToHex(output.script), value: Number(output.value) })),
});

describe("deposit discovery through the trusted chain API", () => {
  test("no payment, then an unconfirmed payment, then a confirmed one with verified parents", async () => {
    const { parent, tx } = deposit();
    const calls: string[] = [];
    expect(await observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([], [], calls) })).toEqual({ status: "none" });
    expect(await observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([entry(tx, false)], []) })).toEqual({ status: "unconfirmed", txid: tx.txid });
    const seen = await observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([entry(tx, true)], [tx, parent], calls) });
    if (seen.status !== "confirmed") throw new Error(seen.status);
    expect(seen.funding.inputValues).toEqual([amount + 1_000n]);
    expect(calls).toEqual([`address/${address}/txs`, `address/${address}/txs`, `tx/${tx.txid}/hex`, `tx/${parent.txid}/hex`]);
    const authorized = authorizeFunding(seen.funding, terms);
    expect(authorized.txid).toBe(tx.txid);
    expect(authorized.feeSat).toBe(200n);
    expect(authorized.anchor).toEqual({ txid: parent.txid, vout: 0 });
  });

  test("payments of another amount or to another script are ignored", async () => {
    const { tx } = deposit();
    const other = { ...entry(tx, true), vout: [{ scriptpubkey: script, value: Number(amount) + 1 }] };
    const elsewhere = { ...entry(tx, true), vout: [{ scriptpubkey: CHANGE, value: Number(amount) }] };
    expect(await observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([other, elsewhere], []) })).toEqual({ status: "none" });
  });

  test("two confirmed payments are reported as ambiguous, never chosen", async () => {
    const first = deposit().tx, second = deposit({ parentValue: amount + 2_000n }).tx;
    const seen = await observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([entry(first, true), entry(second, true)], []) });
    expect(seen).toEqual({ status: "ambiguous", txids: [first.txid, second.txid] });
  });

  test("bytes that do not hash to the announced txid, or a missing parent, are refused", async () => {
    const { parent, tx } = deposit();
    const forged = { ...entry(tx, true), txid: "22".repeat(32) };
    const lying = async (input: RequestInfo | URL): Promise<Response> =>
      String(input).endsWith(`tx/${"22".repeat(32)}/hex`) ? new Response(bytesToHex(tx.raw)) : api([forged], [parent])(input);
    await expect(observeDeposit(API, { address, script, amountSat: amount }, { fetch: lying })).rejects.toThrow(TransactionRefusedError);
    await expect(observeDeposit(API, { address, script, amountSat: amount }, { fetch: api([entry(tx, true)], [tx]) })).rejects.toThrow("Chain API");
  });

  test("a discovered deposit must satisfy the same rules as a PSBT", () => {
    const legacy = deposit({ scriptSig: new Uint8Array([0x00]), witness: [] });
    expect(() => authorizeFunding({ transaction: legacy.tx, inputValues: [amount + 1_000n] }, terms)).toThrow("native segwit");
    const wrapped = deposit({ change: `a914${"cd".repeat(20)}87` });
    expect(() => authorizeFunding({ transaction: wrapped.tx, inputValues: [amount + 1_000n] }, terms)).toThrow("P2WPKH or P2TR");
    const expensive = deposit({ parentValue: amount + 2_000n });
    expect(() => authorizeFunding({ transaction: expensive.tx, inputValues: [amount + 2_000n] }, terms)).toThrow("signed maximum");
    expect(() => authorizeFunding({ transaction: deposit().tx, inputValues: [] }, terms)).toThrow("native segwit");
  });
});
