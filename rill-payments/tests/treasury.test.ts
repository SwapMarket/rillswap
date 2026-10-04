import { afterEach, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Wallet, keccak256 } from "ethers";
import { Database } from "bun:sqlite";
import { TreasuryTransferJournal, type MerchantTransferSigner, type TreasuryTransferObservation } from "../src/treasury";

const cleanup: (() => void)[] = []; afterEach(() => { for (const close of cleanup.splice(0)) close(); });
function fixture() {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/treasury-")), path = directory + "/journal.sqlite";
  const wallet = new Wallet("0x" + "0".repeat(63) + "1"), recipient = "0x" + "2".repeat(40), token = "0x" + "3".repeat(40);
  const policy = { chainId: "11155111" as const, genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9" as const,
    wallet: wallet.address.toLowerCase(), token, approvedRecipients: [recipient], lifetimeTokenSpendCap: "2000000", lifetimeGasSpendCapWei: "2000000" };
  const journal = TreasuryTransferJournal.provision(path, policy); cleanup.push(() => { journal.close(); rmSync(directory, { recursive: true, force: true }); });
  const terms = { recipient, quantityBaseUnits: "1000000", nonce: 2, gasLimit: "50000", maxFeePerGasWei: "10", maxPriorityFeePerGasWei: "1" };
  const signer: MerchantTransferSigner = { identity: async () => ({ chainId: policy.chainId, genesisHash: policy.genesisHash, wallet: policy.wallet }),
    sign: async (request) => wallet.signTransaction({ type: 2, chainId: BigInt(request.chainId), nonce: request.nonce, to: request.to, value: 0n,
      data: request.data, gasLimit: BigInt(request.gasLimit), maxFeePerGas: BigInt(request.maxFeePerGasWei), maxPriorityFeePerGas: BigInt(request.maxPriorityFeePerGasWei), accessList: [] }) };
  const open = () => { const second = TreasuryTransferJournal.open(path, policy); cleanup.unshift(() => second.close()); return second; };
  const observation = (hash: string, state: TreasuryTransferObservation["state"] = "finalized_success") => ({ transactionHash: hash, chainId: policy.chainId, genesisHash: policy.genesisHash,
    wallet: policy.wallet, token, recipient, quantityBaseUnits: "1000000", state, gasPaidWei: "200000" });
  return { journal, policy, terms, signer, wallet, path, open, observation };
}
test("treasury ordinary open never creates or accepts missing/foreign policy", () => {
  const f = fixture(); expect(() => TreasuryTransferJournal.open(f.path + ".missing", f.policy)).toThrow();
  writeFileSync(f.path + ".partial", "", { mode: 0o600 }); expect(() => TreasuryTransferJournal.open(f.path + ".partial", f.policy)).toThrow();
  expect(() => TreasuryTransferJournal.open(f.path, { ...f.policy, lifetimeTokenSpendCap: "3000000" })).toThrow();
  expect(() => TreasuryTransferJournal.provision(f.path, f.policy)).toThrow();
});
test("transactional nonce and lifetime budgets remain reserved even after failure", async () => {
  const f = fixture(), second = f.open(); const first = f.journal.prepare(f.terms, "treasury_operation_01");
  expect(second.prepare(f.terms, "treasury_operation_01").id).toBe(first.id);
  expect(() => second.prepare({ ...f.terms, nonce: 3 }, "treasury_operation_01")).toThrow("Conflicting");
  expect(() => second.prepare(f.terms, "treasury_operation_02")).toThrow();
  second.prepare({ ...f.terms, nonce: 3 }, "treasury_operation_02");
  expect(() => f.journal.prepare({ ...f.terms, nonce: 4 }, "treasury_operation_03")).toThrow("cap exhausted");
  await expect(f.journal.sign(first.id, { ...f.signer, sign: async () => { throw new Error("signer response lost"); } })).rejects.toThrow();
  expect(second.get(first.id).state).toBe("signing");
  expect(() => second.prepare({ ...f.terms, nonce: 4 }, "treasury_operation_03")).toThrow("cap exhausted");
});
test("signer responses cannot widen destination, fees or authorization", async () => {
  for (const mutate of [
    (tx: Parameters<Wallet["signTransaction"]>[0]) => ({ ...tx, to: "0x" + "4".repeat(40) }),
    (tx: Parameters<Wallet["signTransaction"]>[0]) => ({ ...tx, maxFeePerGas: 11n }),
    (tx: Parameters<Wallet["signTransaction"]>[0]) => ({ ...tx, chainId: 1n }),
    (tx: Parameters<Wallet["signTransaction"]>[0]) => ({ ...tx, value: 1n }),
    (tx: Parameters<Wallet["signTransaction"]>[0]) => ({ ...tx, nonce: 3 }),
  ]) {
    const f = fixture(), op = f.journal.prepare(f.terms, "treasury_operation_01");
    const wrong: MerchantTransferSigner = { ...f.signer, sign: async (request) => f.wallet.signTransaction(mutate({ type: 2, chainId: 11155111n, to: request.to, nonce: 2,
      value: 0n, data: request.data, gasLimit: 50000n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, accessList: [] })) };
    await expect(f.journal.sign(op.id, wrong)).rejects.toThrow("unauthorized transaction"); expect(f.journal.get(op.id).transactionHash).toBeNull();
  }
});
test("signed transfer survives journal restart and ambiguous broadcast retries exactly once identity", async () => {
  const f = fixture(), op = f.journal.prepare(f.terms, "treasury_operation_01"); const signed = await f.journal.sign(op.id, f.signer);
  f.journal.close(); const reopened = f.open(); const sent: string[] = [];
  await expect(reopened.broadcast(op.id, { broadcast: async (raw) => { sent.push(raw); throw new Error("response lost after sent"); } })).rejects.toThrow();
  expect(reopened.get(op.id).state).toBe("dispatched"); reopened.close(); const restarted = f.open();
  await restarted.broadcast(op.id, { broadcast: async (raw) => { sent.push(raw); return keccak256(raw); } });
  expect(sent[0]).toBe(sent[1]); expect(keccak256(sent[0]!)).toBe(signed.transactionHash!);
  expect(JSON.stringify(restarted.get(op.id))).not.toContain(sent[0]!);
  const confirmed = await restarted.reconcile(op.id, { lookup: async (hash) => f.observation(hash) });
  expect(confirmed.state).toBe("confirmed"); expect(confirmed.gasPaidWei).toBe("200000");
  const count = sent.length; await restarted.broadcast(op.id, { broadcast: async (raw) => { sent.push(raw); return keccak256(raw); } }); expect(sent).toHaveLength(count);
});
test("failed payout requires intervention and cannot retry with a new nonce", async () => {
  const f = fixture(), op = f.journal.prepare(f.terms, "treasury_operation_01"); await f.journal.sign(op.id, f.signer);
  expect((await f.journal.reconcile(op.id, { lookup: async (hash) => f.observation(hash, "finalized_revert") })).state).toBe("intervention");
  await expect(f.journal.reconcile(op.id, { lookup: async (hash) => f.observation(hash) })).rejects.toThrow("Contradictory");
  expect(() => f.journal.prepare({ ...f.terms, nonce: 3 }, "treasury_operation_01")).toThrow("Conflicting");
  expect(f.journal.pending()).toHaveLength(0);
});
test("terminal reconciliation across journals survives an overlapping broadcast", async () => {
  const f = fixture(), second = f.open(), op = f.journal.prepare(f.terms, "treasury_operation_01"); await f.journal.sign(op.id, f.signer);
  let release!: () => void, entered!: () => void; const started = new Promise<void>((resolve) => { entered = resolve; }), blocked = new Promise<void>((resolve) => { release = resolve; });
  const sending = f.journal.broadcast(op.id, { broadcast: async (raw) => { entered(); await blocked; return keccak256(raw); } });
  await started; await second.reconcile(op.id, { lookup: async (hash) => f.observation(hash) }); release();
  expect((await sending).state).toBe("confirmed"); let called = false;
  expect((await f.journal.broadcast(op.id, { broadcast: async () => { called = true; throw new Error(); } })).state).toBe("confirmed"); expect(called).toBe(false);
  await expect(f.journal.reconcile(op.id, { lookup: async (hash) => f.observation(hash, "pending") })).rejects.toThrow("Contradictory");
});
test("schema-valid partial operation states reject on startup without signing or repair", () => {
  for (const update of ["state='signed'", "state='confirmed'", "fingerprint='wrong'", "nonce=4"]) {
    const f = fixture(); f.journal.prepare(f.terms, "treasury_operation_01"); f.journal.close(); const db = new Database(f.path);
    db.exec("UPDATE operations SET " + update); db.close();
    expect(() => TreasuryTransferJournal.open(f.path, f.policy)).toThrow("Inconsistent treasury operation");
  }
});
test("concurrent signing and lost signer response retain one nonce and exact transaction", async () => {
  const f = fixture(), second = f.open(), op = f.journal.prepare(f.terms, "treasury_operation_01");
  let durableRaw: string | null = null;
  await expect(f.journal.sign(op.id, { ...f.signer, sign: async (request) => { durableRaw = await f.signer.sign(request); throw new Error("response lost"); } })).rejects.toThrow();
  expect(second.get(op.id).state).toBe("signing");
  const results = await Promise.all([f.journal.sign(op.id, f.signer), second.sign(op.id, f.signer)]);
  expect(results[0]?.transactionHash).toBe(keccak256(durableRaw!)); expect(results[1]?.transactionHash).toBe(results[0]?.transactionHash!); expect(second.pending()).toHaveLength(1);
});
test("malformed observer facts cannot establish treasury settlement", async () => {
  const f = fixture(), op = f.journal.prepare(f.terms, "treasury_operation_01"); await f.journal.sign(op.id, f.signer);
  for (const patch of [{ gasPaidWei: "500001" }, { quantityBaseUnits: "1" }, { chainId: "1" }, { state: "SUCCESS" }, { gasPaidWei: 1 }]) {
    await expect(f.journal.reconcile(op.id, { lookup: async (hash) => ({ ...f.observation(hash), ...patch }) as TreasuryTransferObservation })).rejects.toThrow();
    expect(f.journal.get(op.id).state).toBe("signed");
  }
});
