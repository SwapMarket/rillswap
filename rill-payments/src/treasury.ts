import { Database } from "bun:sqlite";
import { Interface, Transaction } from "ethers";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { dirname } from "node:path";

const token = new Interface(["function transfer(address,uint256) returns(bool)"]);
export interface TreasuryPolicy {
  readonly chainId: "11155111";
  readonly genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9";
  readonly wallet: string;
  readonly token: string;
  readonly approvedRecipients: readonly string[];
  readonly lifetimeTokenSpendCap: string;
  readonly lifetimeGasSpendCapWei: string;
}
export interface TreasuryTransferTerms {
  readonly recipient: string;
  readonly quantityBaseUnits: string;
  readonly nonce: number;
  readonly gasLimit: string;
  readonly maxFeePerGasWei: string;
  readonly maxPriorityFeePerGasWei: string;
}
export interface TreasurySigningRequest extends TreasuryTransferTerms {
  readonly operationId: string;
  readonly chainId: string;
  readonly from: string;
  readonly to: string;
  readonly data: string;
  readonly value: "0";
}
/** External restricted wallet/process. It must persist operation identity and sign only these immutable terms. */
export interface MerchantTransferSigner {
  identity(): Promise<{ chainId: string; genesisHash: string; wallet: string }>;
  sign(request: TreasurySigningRequest): Promise<string>;
}
export interface MerchantTransferBroadcaster { broadcast(rawTransaction: string): Promise<string> }
export interface TreasuryTransferObservation {
  readonly transactionHash: string;
  readonly chainId: string;
  readonly genesisHash: string;
  readonly wallet: string;
  readonly token: string;
  readonly recipient: string;
  readonly quantityBaseUnits: string;
  readonly state: "pending" | "finalized_success" | "finalized_revert";
  readonly gasPaidWei: string;
}
/** Backend must authenticate canonical finality, code/receipt logs and gas independently. Never a browser hint. */
export interface MerchantTransferObserver { lookup(hash: string): Promise<TreasuryTransferObservation> }
export interface TreasuryOperation {
  readonly id: string;
  readonly terms: TreasuryTransferTerms;
  readonly state: "prepared" | "signing" | "signed" | "dispatched" | "confirmed" | "intervention";
  readonly transactionHash: string | null;
  readonly gasPaidWei: string | null;
}
const amount = (value: string, zero = false): bigint => {
  if (typeof value !== "string" || !(zero ? /^(0|[1-9][0-9]{0,77})$/ : /^[1-9][0-9]{0,77}$/).test(value) || BigInt(value) >= 1n << 256n) throw new Error("Invalid treasury quantity"); return BigInt(value);
};
const address = (value: string): boolean => /^0x[0-9a-f]{40}$/.test(value);
const sql = [
  "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "CREATE TABLE operations (id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, fingerprint TEXT NOT NULL, nonce INTEGER NOT NULL UNIQUE, terms TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','signing','signed','dispatched','confirmed','intervention')), raw TEXT, hash TEXT UNIQUE, gas_paid TEXT)",
] as const;
function privateStore(path: string): void {
  const file = lstatSync(path), directory = lstatSync(dirname(path));
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || (file.mode & 0o077) !== 0) throw new Error("Private treasury journal required");
}
function policyCopy(policy: TreasuryPolicy): TreasuryPolicy {
  if (policy.chainId !== "11155111" || policy.genesisHash !== "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9" || !address(policy.wallet) || !address(policy.token) ||
      policy.approvedRecipients.length === 0 || policy.approvedRecipients.some((recipient) => !address(recipient) || recipient === policy.wallet || recipient === policy.token)) throw new Error("Unsupported treasury policy");
  amount(policy.lifetimeTokenSpendCap); amount(policy.lifetimeGasSpendCapWei);
  return Object.freeze({ chainId: policy.chainId, genesisHash: policy.genesisHash, wallet: policy.wallet, token: policy.token,
    approvedRecipients: Object.freeze([...new Set(policy.approvedRecipients)].sort()), lifetimeTokenSpendCap: policy.lifetimeTokenSpendCap, lifetimeGasSpendCapWei: policy.lifetimeGasSpendCapWei });
}
function termsCopy(input: TreasuryTransferTerms): TreasuryTransferTerms {
  if (!address(input.recipient) || !Number.isSafeInteger(input.nonce) || input.nonce < 0) throw new Error("Invalid treasury debit");
  const quantity = amount(input.quantityBaseUnits), gas = amount(input.gasLimit), fee = amount(input.maxFeePerGasWei), tip = amount(input.maxPriorityFeePerGasWei, true);
  if (tip > fee || gas * fee >= 1n << 256n || quantity === 0n) throw new Error("Invalid treasury fee bounds");
  return Object.freeze({ recipient: input.recipient, quantityBaseUnits: input.quantityBaseUnits, nonce: input.nonce, gasLimit: input.gasLimit,
    maxFeePerGasWei: input.maxFeePerGasWei, maxPriorityFeePerGasWei: input.maxPriorityFeePerGasWei });
}
const fingerprintOf = (terms: TreasuryTransferTerms): string => createHash("sha256").update(JSON.stringify(terms)).digest("hex");
function checkedTransaction(policy: TreasuryPolicy, terms: TreasuryTransferTerms, raw: string): Transaction {
  const tx = Transaction.from(raw), data = token.encodeFunctionData("transfer", [terms.recipient, amount(terms.quantityBaseUnits)]);
  if (!tx.isSigned() || tx.type !== 2 || tx.chainId !== BigInt(policy.chainId) || tx.from?.toLowerCase() !== policy.wallet || tx.to?.toLowerCase() !== policy.token ||
      tx.nonce !== terms.nonce || tx.value !== 0n || tx.data.toLowerCase() !== data.toLowerCase() || tx.gasLimit !== amount(terms.gasLimit) || tx.maxFeePerGas !== amount(terms.maxFeePerGasWei) ||
      tx.maxPriorityFeePerGas !== amount(terms.maxPriorityFeePerGasWei, true) || tx.accessList?.length !== 0) throw new Error("Treasury signer returned unauthorized transaction");
  return tx;
}

/** Sepolia-only constrained payout foundation, not a swap/conversion adapter or inventory balance. */
export class TreasuryTransferJournal {
  private constructor(private readonly db: Database, readonly policy: TreasuryPolicy) {}
  static provision(path: string, input: TreasuryPolicy): TreasuryTransferJournal {
    const policy = policyCopy(input); const fd = openSync(path, "wx", 0o600); closeSync(fd); privateStore(path);
    const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try { db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;");
      db.transaction(() => { for (const table of sql) db.exec(table); db.query("INSERT INTO metadata VALUES ('version','1'),('policy',?)").run(JSON.stringify(policy)); }).immediate();
    } finally { db.close(); }
    return TreasuryTransferJournal.open(path, policy);
  }
  static open(path: string, input: TreasuryPolicy): TreasuryTransferJournal {
    const policy = policyCopy(input); privateStore(path); const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try {
      const declarations = (db.query("SELECT sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").all() as { sql: string }[]).map((row) => row.sql).sort();
      const metadata = db.query("SELECT key,value FROM metadata").all() as { key: string; value: string }[];
      if (JSON.stringify(declarations) !== JSON.stringify([...sql].sort()) || metadata.length !== 2 || metadata.find((row) => row.key === "version")?.value !== "1" ||
          metadata.find((row) => row.key === "policy")?.value !== JSON.stringify(policy) || (db.query("PRAGMA quick_check").get() as { quick_check: string }).quick_check !== "ok") throw new Error("Unsupported treasury journal state");
      let tokenReserved = 0n, gasReserved = 0n;
      const operations = db.query("SELECT * FROM operations").all() as { id: string; key: string; fingerprint: string; nonce: number; terms: string; state: TreasuryOperation["state"]; raw: string | null; hash: string | null; gas_paid: string | null }[];
      for (const row of operations) {
        const terms = termsCopy(JSON.parse(row.terms)); const terminal = ["confirmed", "intervention"].includes(row.state);
        if (!/^[A-Za-z0-9_-]{16,128}$/.test(row.id) || !/^[A-Za-z0-9_-]{16,128}$/.test(row.key) || row.nonce !== terms.nonce || row.fingerprint !== fingerprintOf(terms) || row.terms !== JSON.stringify(terms) ||
            !policy.approvedRecipients.includes(terms.recipient) || (row.raw === null) !== (row.hash === null) ||
            (row.raw === null && !["prepared", "signing"].includes(row.state)) || (row.raw !== null && ["prepared", "signing"].includes(row.state)) ||
            terminal !== (row.gas_paid !== null)) throw new Error("Inconsistent treasury operation");
        if (row.raw !== null && checkedTransaction(policy, terms, row.raw).hash !== row.hash) throw new Error("Treasury stored signature mismatch");
        const gas = amount(terms.gasLimit) * amount(terms.maxFeePerGasWei);
        if (row.gas_paid !== null && amount(row.gas_paid, true) > gas) throw new Error("Treasury stored fees exceed authorization");
        tokenReserved += amount(terms.quantityBaseUnits); gasReserved += gas;
      }
      if (tokenReserved > amount(policy.lifetimeTokenSpendCap) || gasReserved > amount(policy.lifetimeGasSpendCapWei)) throw new Error("Treasury stored reservations exceed policy");
      db.exec("PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;"); return new TreasuryTransferJournal(db, policy);
    } catch (error) { db.close(); throw error; }
  }
  close(): void { this.db.close(); }
  get(id: string): TreasuryOperation {
    const row = this.db.query("SELECT id,terms,state,hash,gas_paid FROM operations WHERE id=?").get(id) as { id: string; terms: string; state: TreasuryOperation["state"]; hash: string | null; gas_paid: string | null } | null;
    if (!row) throw new Error("Unknown treasury operation"); return Object.freeze({ id: row.id, terms: JSON.parse(row.terms), state: row.state, transactionHash: row.hash, gasPaidWei: row.gas_paid });
  }
  prepare(input: TreasuryTransferTerms, key: string): TreasuryOperation {
    const terms = termsCopy(input); if (!this.policy.approvedRecipients.includes(terms.recipient) || !/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new Error("Treasury transfer not authorized");
    const fingerprint = fingerprintOf(terms);
    return this.db.transaction(() => {
      const old = this.db.query("SELECT id,fingerprint FROM operations WHERE key=?").get(key) as { id: string; fingerprint: string } | null;
      if (old) { if (old.fingerprint !== fingerprint) throw new Error("Conflicting treasury idempotency key"); return this.get(old.id); }
      const reserved = (this.db.query("SELECT terms FROM operations").all() as { terms: string }[]).reduce((sum, row) => {
        const terms = termsCopy(JSON.parse(row.terms)); return { token: sum.token + amount(terms.quantityBaseUnits), gas: sum.gas + amount(terms.gasLimit) * amount(terms.maxFeePerGasWei) };
      }, { token: 0n, gas: 0n });
      // Failed or ambiguous operations retain their whole authorization budget.
      if (reserved.token + amount(terms.quantityBaseUnits) > amount(this.policy.lifetimeTokenSpendCap) || reserved.gas + amount(terms.gasLimit) * amount(terms.maxFeePerGasWei) > amount(this.policy.lifetimeGasSpendCapWei)) throw new Error("Treasury lifetime spend cap exhausted");
      const id = randomBytes(24).toString("base64url"); this.db.query("INSERT INTO operations VALUES (?,?,?,?,?,'prepared',NULL,NULL,NULL)").run(id, key, fingerprint, terms.nonce, JSON.stringify(terms)); return this.get(id);
    }).immediate();
  }
  async sign(id: string, signer: MerchantTransferSigner): Promise<TreasuryOperation> {
    const operation = this.get(id); if (operation.transactionHash) return operation;
    const identity = await signer.identity();
    if (identity.chainId !== this.policy.chainId || identity.genesisHash !== this.policy.genesisHash || identity.wallet !== this.policy.wallet) throw new Error("Treasury signer identity mismatch");
    this.db.query("UPDATE operations SET state='signing' WHERE id=? AND raw IS NULL").run(id);
    const terms = operation.terms, data = token.encodeFunctionData("transfer", [terms.recipient, amount(terms.quantityBaseUnits)]);
    const raw = await signer.sign({ ...terms, operationId: id, chainId: this.policy.chainId, from: this.policy.wallet, to: this.policy.token, data, value: "0" });
    const tx = checkedTransaction(this.policy, terms, raw);
    return this.db.transaction(() => {
      const current = this.get(id); if (current.transactionHash && current.transactionHash !== tx.hash) throw new Error("Treasury signer violated operation identity");
      if (!current.transactionHash) this.db.query("UPDATE operations SET raw=?,hash=?,state='signed' WHERE id=?").run(raw, tx.hash, id); return this.get(id);
    }).immediate();
  }
  async broadcast(id: string, broadcaster: MerchantTransferBroadcaster): Promise<TreasuryOperation> {
    const dispatch = this.db.transaction(() => {
      const operation = this.get(id); if (operation.state === "confirmed" || operation.state === "intervention") return null;
      const row = this.db.query("SELECT raw FROM operations WHERE id=?").get(id) as { raw: string | null };
      if (!row.raw || !operation.transactionHash) throw new Error("Treasury signature unresolved");
      if (checkedTransaction(this.policy, operation.terms, row.raw).hash !== operation.transactionHash) throw new Error("Treasury stored signature mismatch");
      this.db.query("UPDATE operations SET state='dispatched' WHERE id=?").run(id); // eligibility and durable marker are atomic
      return { raw: row.raw, hash: operation.transactionHash };
    }).immediate();
    if (!dispatch) return this.get(id);
    const reported = await broadcaster.broadcast(dispatch.raw);
    if (reported.toLowerCase() !== dispatch.hash) throw new Error("Treasury broadcast hash mismatch"); return this.get(id);
  }
  async reconcile(id: string, observer: MerchantTransferObserver): Promise<TreasuryOperation> {
    const operation = this.get(id); if (!operation.transactionHash) throw new Error("Treasury signature unresolved");
    const observation = await observer.lookup(operation.transactionHash), terms = operation.terms;
    if (observation.transactionHash !== operation.transactionHash || observation.chainId !== this.policy.chainId || observation.genesisHash !== this.policy.genesisHash || observation.wallet !== this.policy.wallet ||
        observation.token !== this.policy.token || observation.recipient !== terms.recipient || observation.quantityBaseUnits !== terms.quantityBaseUnits ||
        !["pending", "finalized_success", "finalized_revert"].includes(observation.state) || amount(observation.gasPaidWei, true) > amount(terms.gasLimit) * amount(terms.maxFeePerGasWei)) throw new Error("Unverified treasury reconciliation");
    if (observation.state === "pending") { const current = this.get(id); if (current.gasPaidWei !== null) throw new Error("Contradictory treasury settlement"); return current; }
    return this.db.transaction(() => {
      const current = this.get(id), state = observation.state === "finalized_success" ? "confirmed" : "intervention";
      if (current.gasPaidWei !== null && (current.gasPaidWei !== observation.gasPaidWei || current.state !== state)) throw new Error("Contradictory treasury settlement");
      this.db.query("UPDATE operations SET state=?,gas_paid=? WHERE id=?").run(state, observation.gasPaidWei, id); return this.get(id);
    }).immediate();
  }
  pending(): TreasuryOperation[] { return (this.db.query("SELECT id FROM operations WHERE state NOT IN ('confirmed','intervention') ORDER BY rowid").all() as { id: string }[]).map((row) => this.get(row.id)); }
}
