import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { invoiceBinding } from "./bolt11";
import { MAX_MSAT, parseTerms, type NativeLightningTerms, type Network } from "./contract";

export interface MerchantIdentity {
  readonly origin: string;
  readonly receiver: string;
  readonly network: Network;
  readonly issuerId: string;
}
export interface IssueOperation extends MerchantIdentity {
  readonly operationId: string;
  readonly amountMsat: string;
  readonly expiresAt: number;
}
/** create must return the same invoice for an operation, including after ambiguous RPC failure. */
export interface InvoiceIssuer {
  identity(): Promise<MerchantIdentity>;
  create(operation: IssueOperation): Promise<string>;
}
export interface ReceiptObservation {
  readonly receiver: string;
  readonly network: Network;
  readonly paymentHash: string;
  readonly invoiceAmountMsat: string;
  readonly paidMsat: string;
  readonly state: "OPEN" | "ACCEPTED" | "SETTLED" | "CANCELED";
  readonly settledAt: number | null;
}
export interface ReceiptObserver {
  identity(): Promise<MerchantIdentity>;
  lookup(paymentHash: string): Promise<ReceiptObservation>;
}
export interface Intent {
  id: string;
  order_ref: string;
  amount_msat: string;
  created_at: number;
  expires_at: number;
  status: "waiting" | "paid" | "reconciliation";
}
export interface Attempt {
  id: string;
  intent_id: string;
  operation_id: string;
  state: "prepared" | "unknown" | "ready";
  invoice: string | null;
  payment_hash: string | null;
}
export interface AcceptanceEvent {
  readonly version: "checkout-event/1";
  readonly id: string;
  readonly merchantOrigin: string;
  readonly type: "payment.accepted";
  readonly intentId: string;
  readonly attemptId: string;
  readonly paymentHash: string;
  readonly amountMsat: string;
  readonly acceptedAt: number;
}
const id = (): string => randomBytes(24).toString("base64url");
const fingerprint = (parts: unknown[]): string => createHash("sha256").update(JSON.stringify(parts)).digest("hex");
const clock = (now: number): void => { if (!Number.isSafeInteger(now) || now < 0) throw new Error("Invalid clock"); };
const readClock = (now: () => number): number => { const value = now(); clock(value); return value; };
const TABLES: Readonly<Record<string, string>> = {
  metadata: "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  intents: "CREATE TABLE intents (id TEXT PRIMARY KEY, order_ref TEXT NOT NULL UNIQUE, amount_msat TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('waiting','paid','reconciliation')))",
  idempotency: "CREATE TABLE idempotency (scope TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL, result_id TEXT NOT NULL, PRIMARY KEY(scope,key))",
  attempts: "CREATE TABLE attempts (id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES intents(id), operation_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL CHECK(state IN ('prepared','unknown','ready')), invoice TEXT, payment_hash TEXT UNIQUE)",
  receipts: "CREATE TABLE receipts (payment_hash TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id), payload TEXT NOT NULL)",
  outbox: "CREATE TABLE outbox (id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES intents(id), payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)",
};
const normalized = (sql: string): string => sql.trim().replace(/\s+/g, " ");
const quantity = (amount: string): void => {
  if (!/^[1-9][0-9]{0,18}$/.test(amount) || BigInt(amount) > MAX_MSAT || BigInt(amount) % 1000n !== 0n) throw new Error("Invalid whole-satoshi quantity");
};
function sameIdentity(actual: MerchantIdentity, expected: MerchantIdentity): boolean {
  return actual.origin === expected.origin && actual.receiver === expected.receiver && actual.network === expected.network && actual.issuerId === expected.issuerId;
}
function privateFile(path: string): void {
  const directory = lstatSync(dirname(path));
  const file = lstatSync(path);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 ||
      !file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0 || file.nlink !== 1) {
    throw new Error("Merchant store requires a private directory and private regular file");
  }
}

/** Dedicated merchant ledger. No LP custody, payer secrets or spending signer. */
export class MerchantLedger {
  private constructor(private readonly db: Database, readonly identity: MerchantIdentity) {}

  static provision(path: string, identity: MerchantIdentity): MerchantLedger {
    parseTerms({ version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: identity.origin,
      receiver: identity.receiver, network: identity.network, intentId: "provision_check_1", attemptId: "provision_check_2",
      amountMsat: "1000", buyerExtraMsat: "0", paymentHash: "0".repeat(64), expiresAt: 1 });
    if (identity.network === "mainnet" || !/^[A-Za-z0-9_-]{1,128}$/.test(identity.issuerId)) throw new Error("Unsupported merchant identity");
    const fd = openSync(path, "wx", 0o600);
    closeSync(fd);
    privateFile(path);
    const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try {
      db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      db.transaction(() => {
        for (const sql of Object.values(TABLES)) db.exec(sql);
        db.query("INSERT INTO metadata VALUES ('version','1'), ('identity',?)").run(JSON.stringify(identity));
      }).immediate();
    } finally { db.close(); }
    return MerchantLedger.open(path, identity);
  }

  static open(path: string, identity: MerchantIdentity): MerchantLedger {
    privateFile(path); // absent and partial state never create a new database
    const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try {
      const meta = db.query("SELECT key,value FROM metadata").all() as { key: string; value: string }[];
      if (meta.length !== 2 || meta.find((x) => x.key === "version")?.value !== "1" ||
          !sameIdentity(JSON.parse(meta.find((x) => x.key === "identity")?.value ?? "null"), identity)) throw new Error("Merchant store version or identity mismatch");
      if (identity.network === "mainnet") throw new Error("Mainnet remains disabled");
      db.exec("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      const schema = db.query("SELECT type,name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").all() as { type: string; name: string; sql: string }[];
      if (schema.length !== Object.keys(TABLES).length || schema.some((entry) => entry.type !== "table" ||
          !Object.hasOwn(TABLES, entry.name) || normalized(entry.sql) !== normalized(TABLES[entry.name]!))) throw new Error("Merchant store schema mismatch");
      if (db.query("PRAGMA foreign_key_check").all().length !== 0) throw new Error("Merchant store foreign key violation");
      const integrity = db.query("PRAGMA quick_check").get() as { quick_check: string };
      if (integrity.quick_check !== "ok") throw new Error("Merchant store is corrupt");
      return new MerchantLedger(db, Object.freeze({ ...identity }));
    } catch (error) { db.close(); throw error; }
  }

  close(): void { this.db.close(); }
  getIntent(intentId: string): Intent {
    const value = this.db.query("SELECT * FROM intents WHERE id=?").get(intentId) as Intent | null;
    if (!value) throw new Error("Unknown intent");
    return value;
  }
  getAttempt(attemptId: string): Attempt {
    const value = this.db.query("SELECT * FROM attempts WHERE id=?").get(attemptId) as Attempt | null;
    if (!value) throw new Error("Unknown attempt");
    return value;
  }
  private replay(scope: string, key: string, hash: string): string | null {
    if (typeof key !== "string" || key.length < 16 || key.length > 128) throw new Error("Invalid idempotency key");
    const old = this.db.query("SELECT fingerprint,result_id FROM idempotency WHERE scope=? AND key=?").get(scope, key) as { fingerprint: string; result_id: string } | null;
    if (old && old.fingerprint !== hash) throw new Error("Conflicting idempotency key reuse");
    return old?.result_id ?? null;
  }
  createIntent(orderRef: string, amountMsat: string, expiresAt: number, key: string, now: number): Intent {
    clock(now); clock(expiresAt); quantity(amountMsat);
    if (!orderRef || orderRef.length > 128) throw new Error("Invalid order terms");
    const hash = fingerprint([orderRef, amountMsat, expiresAt]);
    return this.db.transaction(() => {
      const replay = this.replay("intent", key, hash);
      if (replay) return this.getIntent(replay);
      const existing = this.db.query("SELECT * FROM intents WHERE order_ref=?").get(orderRef) as Intent | null;
      if (existing && (existing.amount_msat !== amountMsat || existing.expires_at !== expiresAt)) throw new Error("Order terms cannot be replaced");
      if (!existing && expiresAt <= now) throw new Error("Order expired");
      const result = existing ?? { id: id(), order_ref: orderRef, amount_msat: amountMsat, created_at: now, expires_at: expiresAt, status: "waiting" as const };
      if (!existing) this.db.query("INSERT INTO intents VALUES (?,?,?,?,?,?)").run(result.id, orderRef, amountMsat, now, expiresAt, result.status);
      this.db.query("INSERT INTO idempotency VALUES (?,?,?,?)").run("intent", key, hash, result.id);
      return result;
    }).immediate();
  }
  createAttempt(intentId: string, key: string, now: number): Attempt {
    clock(now);
    return this.db.transaction(() => {
      const replay = this.replay("attempt", key, fingerprint([intentId]));
      if (replay) return this.getAttempt(replay);
      const intent = this.getIntent(intentId);
      const old = this.db.query("SELECT * FROM attempts WHERE intent_id=?").get(intentId) as Attempt | null;
      if (!old && (intent.status !== "waiting" || now >= intent.expires_at)) throw new Error("Order is not payable");
      const result = old ?? { id: id(), intent_id: intentId, operation_id: id(), state: "prepared" as const, invoice: null, payment_hash: null };
      if (!old) this.db.query("INSERT INTO attempts VALUES (?,?,?,'prepared',NULL,NULL)").run(result.id, intentId, result.operation_id);
      this.db.query("INSERT INTO idempotency VALUES (?,?,?,?)").run("attempt", key, fingerprint([intentId]), result.id);
      return result;
    }).immediate();
  }
  async issue(attemptId: string, issuer: InvoiceIssuer, now: () => number): Promise<Attempt> {
    readClock(now);
    const attempt = this.getAttempt(attemptId);
    if (attempt.invoice) return attempt;
    if (!sameIdentity(await issuer.identity(), this.identity)) throw new Error("Issuer identity mismatch");
    const intent = this.getIntent(attempt.intent_id);
    if (readClock(now) >= intent.expires_at && attempt.state === "prepared") throw new Error("Unissued order expired");
    // Unknown is recorded before RPC so an interruption cannot appear never dispatched.
    this.db.query("UPDATE attempts SET state='unknown' WHERE id=? AND invoice IS NULL").run(attemptId);
    const invoice = await issuer.create({ ...this.identity, operationId: attempt.operation_id, amountMsat: intent.amount_msat, expiresAt: intent.expires_at });
    const binding = invoiceBinding(invoice, this.identity.network);
    if (binding.payment_hash === "0".repeat(64) || binding.amount_msat !== intent.amount_msat || binding.payee_compressed_pubkey !== this.identity.receiver || binding.created_at > readClock(now)) throw new Error("Issuer returned wrong invoice");
    return this.db.transaction(() => {
      const current = this.getAttempt(attemptId);
      if (current.invoice && current.invoice !== invoice) throw new Error("Issuer returned conflicting invoice");
      this.db.query("UPDATE attempts SET invoice=?,payment_hash=?,state='ready' WHERE id=?").run(invoice, binding.payment_hash, attemptId);
      return this.getAttempt(attemptId);
    }).immediate();
  }
  terms(attemptId: string): NativeLightningTerms {
    const attempt = this.getAttempt(attemptId);
    if (!attempt.invoice) throw new Error("Invoice issuance unresolved");
    const intent = this.getIntent(attempt.intent_id);
    const binding = invoiceBinding(attempt.invoice, this.identity.network);
    return parseTerms({ version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: this.identity.origin,
      receiver: this.identity.receiver, network: this.identity.network, intentId: intent.id, attemptId,
      amountMsat: intent.amount_msat, buyerExtraMsat: "0", paymentHash: binding.payment_hash, expiresAt: Math.min(intent.expires_at, binding.expires_at) });
  }
  async observe(attemptId: string, observer: ReceiptObserver, now: () => number): Promise<Intent> {
    readClock(now);
    if (!sameIdentity(await observer.identity(), this.identity)) throw new Error("Observer identity mismatch");
    const attempt = this.getAttempt(attemptId);
    if (!attempt.payment_hash) throw new Error("Unresolved invoice");
    const raw = await observer.lookup(attempt.payment_hash);
    // Explicit projection prevents accidental storage of preimages or adapter credentials.
    const receipt: ReceiptObservation = { receiver: raw.receiver, network: raw.network, paymentHash: raw.paymentHash,
      invoiceAmountMsat: raw.invoiceAmountMsat, paidMsat: raw.paidMsat, state: raw.state, settledAt: raw.settledAt };
    const intent = this.getIntent(attempt.intent_id);
    if (receipt.receiver !== this.identity.receiver || receipt.network !== this.identity.network || receipt.paymentHash !== attempt.payment_hash ||
        receipt.invoiceAmountMsat !== intent.amount_msat || typeof receipt.paidMsat !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(receipt.paidMsat) || BigInt(receipt.paidMsat) > MAX_MSAT ||
        !["OPEN", "ACCEPTED", "SETTLED", "CANCELED"].includes(receipt.state) ||
        (receipt.state !== "SETTLED" && receipt.settledAt !== null)) throw new Error("Inconsistent receiver observation");
    const previous = this.db.query("SELECT payload FROM receipts WHERE payment_hash=?").get(receipt.paymentHash) as { payload: string } | null;
    if (previous && previous.payload !== JSON.stringify(receipt)) throw new Error("Conflicting settled receipt");
    if (receipt.state !== "SETTLED") return intent;
    const observedAt = readClock(now);
    const binding = invoiceBinding(attempt.invoice!, this.identity.network);
    if (receipt.settledAt === null || !Number.isSafeInteger(receipt.settledAt) || receipt.settledAt < Math.max(intent.created_at, binding.created_at) || receipt.settledAt > observedAt) throw new Error("Invalid receiver settlement time");
    const payload = JSON.stringify(receipt);
    return this.db.transaction(() => {
      const previous = this.db.query("SELECT payload FROM receipts WHERE payment_hash=?").get(receipt.paymentHash) as { payload: string } | null;
      if (previous && previous.payload !== payload) throw new Error("Conflicting settled receipt");
      if (!previous) this.db.query("INSERT INTO receipts VALUES (?,?,?)").run(receipt.paymentHash, attemptId, payload);
      const current = this.getIntent(intent.id);
      if (current.status !== "waiting") return current;
      const timely = receipt.settledAt! < this.terms(attemptId).expiresAt;
      if (!timely || receipt.paidMsat !== intent.amount_msat) {
        this.db.query("UPDATE intents SET status='reconciliation' WHERE id=?").run(intent.id);
      } else {
        const event: AcceptanceEvent = { version: "checkout-event/1", id: id(), merchantOrigin: this.identity.origin, type: "payment.accepted",
          intentId: intent.id, attemptId, paymentHash: receipt.paymentHash, amountMsat: receipt.paidMsat, acceptedAt: observedAt };
        this.db.query("INSERT INTO outbox (id,intent_id,payload) VALUES (?,?,?)").run(event.id, intent.id, JSON.stringify(event));
        this.db.query("UPDATE intents SET status='paid' WHERE id=?").run(intent.id);
      }
      return this.getIntent(intent.id);
    }).immediate();
  }
  pendingAttempts(): Attempt[] { return this.db.query("SELECT * FROM attempts ORDER BY rowid").all() as Attempt[]; }
  /** Intent ID recorded for an exact intent idempotency key (provenance check), else null. */
  intentIdForKey(key: string): string | null {
    return (this.db.query("SELECT result_id FROM idempotency WHERE scope='intent' AND key=?").get(key) as { result_id: string } | null)?.result_id ?? null;
  }
  intentForOrder(orderRef: string): Intent | null { return this.db.query("SELECT * FROM intents WHERE order_ref=?").get(orderRef) as Intent | null; }
  attemptForIntent(intentId: string): Attempt | null { return this.db.query("SELECT * FROM attempts WHERE intent_id=?").get(intentId) as Attempt | null; }
  eventsForIntent(intentId: string): AcceptanceEvent[] {
    return (this.db.query("SELECT payload FROM outbox WHERE intent_id=? ORDER BY rowid").all(intentId) as { payload: string }[]).map((x) => JSON.parse(x.payload));
  }
  pendingEvents(): AcceptanceEvent[] {
    return (this.db.query("SELECT payload FROM outbox WHERE delivered=0 ORDER BY rowid").all() as { payload: string }[]).map((x) => JSON.parse(x.payload));
  }
  acknowledgeEvent(eventId: string): void { this.db.query("UPDATE outbox SET delivered=1 WHERE id=?").run(eventId); }
}
