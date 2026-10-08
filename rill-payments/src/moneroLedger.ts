import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { ATOMIC, PRIMARY_ADDRESS, SUBADDRESS, moneroReceiptKey, parseMoneroRegtestProfile, type MoneroReceipt, type MoneroReconciliationReason, type MoneroRegtestProfile } from "./moneroContract";
import type { MoneroRpc, MoneroSnapshot, MoneroTransfer } from "./moneroRpc";

export interface MoneroLedgerConfig {
  readonly origin: string;
  /** Wallet primary address (account 0, index 0); checked before every wallet use. */
  readonly primaryAddress: string;
  readonly network: MoneroRegtestProfile;
}
export interface MoneroIntent {
  readonly intentId: string;
  readonly orderRef: string;
  readonly address: string;
  readonly subaddressIndex: number;
  readonly amountAtomic: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly status: "waiting" | "paid" | "reconciliation";
  readonly reconciliation: MoneroReconciliationReason | null;
}
export interface MoneroAcceptance {
  readonly version: "monero-acceptance/1";
  readonly id: string;
  readonly intentId: string;
  readonly receiptKeys: readonly string[];
  readonly acceptedAt: number;
}
export interface MoneroProgress { readonly seenAtomic: string; readonly confirmedAtomic: string; readonly observedAt: number }
export type MoneroDecision =
  | { readonly kind: "waiting" }
  | { readonly kind: "paid"; readonly receipts: readonly MoneroReceipt[] }
  | { readonly kind: "reconciliation"; readonly reason: MoneroReconciliationReason; readonly receipts: readonly MoneroReceipt[] };
type Terms = Pick<MoneroIntent, "address" | "subaddressIndex" | "amountAtomic" | "createdAt" | "expiresAt">;

/** Confirmed incoming evidence: `in`, enough confirmations, unlocked, no unlock time, no double spend. */
export const qualifyingMoneroTransfer = (transfer: MoneroTransfer, network: MoneroRegtestProfile): boolean =>
  transfer.type === "in" && transfer.confirmations >= network.confirmations && !transfer.locked && transfer.unlockTime === "0" && !transfer.doubleSpendSeen;

/** Anchor block whose hash pins the chain instance (block 0 equals mainnet genesis). */
export const MONERO_ANCHOR_HEIGHT = 1;

/**
 * Decides one intent from a complete, caught-up wallet view of its subaddress.
 * Counts only confirmed incoming entries (`in`, enough confirmations, unlocked,
 * no unlock time, no double spend). Timely means the block timestamp is in
 * [createdAt, expiresAt). Exact timely sum: paid. Any late entry or a timely
 * overpayment: reconciliation. A short timely sum after expiry with nothing
 * pending: reconciliation. Otherwise keep waiting; expiry alone decides nothing.
 * Evidence timestamped after `now` defers the decision, so an acceptance is
 * never recorded before the blocks it cites.
 */
export function classifyMoneroPayment(terms: Terms, network: MoneroRegtestProfile, transfers: readonly MoneroTransfer[], now: number): { decision: MoneroDecision; progress: MoneroProgress } {
  const own = transfers.filter((transfer) => transfer.major === 0 && transfer.minor === terms.subaddressIndex && (transfer.type === "in" || transfer.type === "pool"));
  if (own.some((transfer) => transfer.address !== terms.address)) throw new Error("Monero subaddress mismatch");
  const confirmed = own.filter((transfer) => qualifyingMoneroTransfer(transfer, network));
  const pending = own.filter((transfer) => !confirmed.includes(transfer));
  const receipts = confirmed.map((transfer): MoneroReceipt => ({ key: moneroReceiptKey(network, terms.subaddressIndex, transfer.txid), txid: transfer.txid,
    amountAtomic: transfer.amountAtomic.toString(), height: transfer.height, timestamp: transfer.timestamp,
    timing: transfer.timestamp >= terms.createdAt && transfer.timestamp < terms.expiresAt ? "timely" : "late" }));
  if (new Set(receipts.map((receipt) => receipt.key)).size !== receipts.length) throw new Error("Duplicate Monero transfer entry");
  const timely = receipts.filter((receipt) => receipt.timing === "timely").reduce((sum, receipt) => sum + BigInt(receipt.amountAtomic), 0n), amount = BigInt(terms.amountAtomic);
  const progress = { seenAtomic: own.reduce((sum, transfer) => sum + transfer.amountAtomic, 0n).toString(), confirmedAtomic: timely.toString(), observedAt: now };
  const decision: MoneroDecision = receipts.some((receipt) => receipt.timestamp > now) ? { kind: "waiting" }
    : receipts.some((receipt) => receipt.timing === "late") ? { kind: "reconciliation", reason: "late", receipts }
    : timely > amount ? { kind: "reconciliation", reason: "overpaid", receipts }
    : timely === amount ? { kind: "paid", receipts }
    : now >= terms.expiresAt && timely > 0n && pending.length === 0 ? { kind: "reconciliation", reason: "underpaid", receipts }
    : { kind: "waiting" };
  return { decision, progress };
}

const id = (): string => randomBytes(24).toString("base64url");
const digest = (input: unknown): string => createHash("sha256").update(JSON.stringify(input)).digest("hex");
const timestamp = (input: number): void => { if (!Number.isSafeInteger(input) || input < 0) throw new Error("Invalid time"); };
const schema: readonly string[] = [
  "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "CREATE TABLE intents (id TEXT PRIMARY KEY, order_ref TEXT NOT NULL UNIQUE, subaddress_index INTEGER NOT NULL UNIQUE, address TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('waiting','paid','reconciliation')), reason TEXT CHECK(reason IN ('late','overpaid','underpaid')), CHECK((status='reconciliation') = (reason IS NOT NULL)))",
  "CREATE TABLE idempotency (scope TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL, result_id TEXT NOT NULL, PRIMARY KEY(scope,key))",
  "CREATE TABLE receipts (key TEXT PRIMARY KEY, intent_id TEXT NOT NULL REFERENCES intents(id), payload TEXT NOT NULL, impaired_at INTEGER)",
  "CREATE TABLE outbox (id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES intents(id), payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)",
];
const normalize = (sql: string): string => sql.trim().replace(/\s+/g, " ");
function privateStore(path: string): void {
  const directory = lstatSync(dirname(path)), file = lstatSync(path);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || (file.mode & 0o077) !== 0) throw new Error("Monero ledger requires private regular storage");
}
function configCopy(config: MoneroLedgerConfig): MoneroLedgerConfig {
  if (typeof config.origin !== "string" || new URL(config.origin).origin !== config.origin || !config.origin.startsWith("https://") ||
      typeof config.primaryAddress !== "string" || !PRIMARY_ADDRESS.test(config.primaryAddress)) throw new Error("Monero ledger requires an HTTPS origin and a primary address");
  return Object.freeze({ origin: config.origin, primaryAddress: config.primaryAddress, network: parseMoneroRegtestProfile(config.network) });
}

/**
 * Local regtest Monero receipt ledger: one subaddress per intent, decisions
 * from wallet-rpc evidence, acceptances in an outbox. Separate from the
 * Lightning merchant ledger. Wallet use is serialized: allocation and
 * observation never interleave, so no stale snapshot overwrites newer state.
 */
export class MoneroReceiptLedger {
  private queue: Promise<unknown> = Promise.resolve();
  private readonly progress = new Map<string, MoneroProgress>();
  private constructor(private readonly db: Database, readonly config: MoneroLedgerConfig) {}
  static provision(path: string, input: MoneroLedgerConfig): MoneroReceiptLedger {
    const config = configCopy(input); const fd = openSync(path, "wx", 0o600); closeSync(fd); privateStore(path);
    const db = new Database(realpathSync(path), { create: false, readwrite: true, strict: true });
    try {
      db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      db.transaction(() => { for (const sql of schema) db.exec(sql); db.query("INSERT INTO metadata VALUES ('version','1'), ('config',?)").run(JSON.stringify(config)); }).immediate();
    } finally { db.close(); }
    return MoneroReceiptLedger.open(path, config);
  }
  static open(path: string, input: MoneroLedgerConfig): MoneroReceiptLedger {
    const config = configCopy(input); privateStore(path); const db = new Database(realpathSync(path), { create: false, readwrite: true, strict: true });
    try {
      const objects = db.query("SELECT sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name").all() as { sql: string }[];
      if (JSON.stringify(objects.map((entry) => normalize(entry.sql)).sort()) !== JSON.stringify(schema.map(normalize).sort())) throw new Error("Monero ledger schema mismatch");
      const metadata = db.query("SELECT key,value FROM metadata").all() as { key: string; value: string }[];
      if (metadata.length !== 2 || metadata.find((entry) => entry.key === "version")?.value !== "1" || metadata.find((entry) => entry.key === "config")?.value !== JSON.stringify(config)) throw new Error("Monero ledger version/config mismatch");
      if ((db.query("PRAGMA quick_check").get() as { quick_check: string }).quick_check !== "ok" || db.query("PRAGMA foreign_key_check").all().length !== 0) throw new Error("Monero ledger integrity failure");
      db.exec("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      return new MoneroReceiptLedger(db, config);
    } catch (error) { db.close(); throw error; }
  }
  close(): void { this.db.close(); }

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const run = this.queue.then(work, work); this.queue = run.catch(() => undefined); return run;
  }
  /** Wallet evidence counts only from the pinned fakechain wallet after it caught up with its daemon. */
  private async verified(rpc: MoneroRpc): Promise<MoneroSnapshot> {
    const snapshot = await rpc.snapshot(MONERO_ANCHOR_HEIGHT);
    if (snapshot.nettype !== "fakechain") throw new Error("Monero daemon is not a regtest (fakechain) node");
    if (snapshot.anchorHash !== this.config.network.anchorHash) throw new Error("Monero chain differs from the provisioned chain");
    if (snapshot.primaryAddress !== this.config.primaryAddress) throw new Error("Monero wallet differs from the provisioned wallet");
    if (snapshot.walletHeight < snapshot.daemonHeight) throw new Error("Monero wallet has not caught up with its daemon");
    return snapshot;
  }
  private replay(scope: string, key: string, fingerprint: string): string | null {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new Error("Invalid idempotency key");
    const row = this.db.query("SELECT fingerprint,result_id FROM idempotency WHERE scope=? AND key=?").get(scope, key) as { fingerprint: string; result_id: string } | null;
    if (row && row.fingerprint !== fingerprint) throw new Error("Conflicting idempotency key"); return row?.result_id ?? null;
  }

  getIntent(intentId: string): MoneroIntent {
    const row = this.db.query("SELECT payload,status,reason FROM intents WHERE id=?").get(intentId) as { payload: string; status: MoneroIntent["status"]; reason: MoneroReconciliationReason | null } | null;
    if (!row) throw new Error("Unknown Monero intent"); return Object.freeze({ ...JSON.parse(row.payload), status: row.status, reconciliation: row.reason });
  }
  getReceipts(intentId: string): { receipts: MoneroReceipt[]; impaired: boolean } {
    const rows = this.db.query("SELECT payload,impaired_at FROM receipts WHERE intent_id=? ORDER BY rowid").all(intentId) as { payload: string; impaired_at: number | null }[];
    return { receipts: rows.map((row) => JSON.parse(row.payload)), impaired: rows.some((row) => row.impaired_at !== null) };
  }
  getAcceptance(intentId: string): MoneroAcceptance | null {
    const row = this.db.query("SELECT payload FROM outbox WHERE intent_id=?").get(intentId) as { payload: string } | null;
    return row ? JSON.parse(row.payload) : null;
  }
  getProgress(intentId: string): MoneroProgress | null { return this.progress.get(intentId) ?? null; }
  pendingEvents(): MoneroAcceptance[] { return (this.db.query("SELECT payload FROM outbox WHERE delivered=0 ORDER BY rowid").all() as { payload: string }[]).map((row) => JSON.parse(row.payload)); }
  acknowledgeEvent(eventId: string): void { this.db.query("UPDATE outbox SET delivered=1 WHERE id=?").run(eventId); }

  /**
   * Allocates a fresh subaddress for an order. A crashed wallet-rpc may hand
   * out an index again (unstored allocations are lost), so indices already in
   * the ledger are skipped, and the wallet is stored before the intent commits.
   * A subaddress allocated without a committed intent was never shown to anyone.
   */
  createIntent(orderRef: string, amountAtomic: string, expiresAt: number, key: string, rpc: MoneroRpc, now: () => number): Promise<MoneroIntent> {
    if (typeof amountAtomic !== "string" || !ATOMIC.test(amountAtomic) || BigInt(amountAtomic) >= 1n << 64n) throw new Error("Invalid Monero amount");
    timestamp(expiresAt); if (typeof orderRef !== "string" || !orderRef || orderRef.length > 128) throw new Error("Invalid order");
    const fingerprint = digest([orderRef, amountAtomic, expiresAt]);
    return this.serial(async () => {
      const replay = this.replay("intent", key, fingerprint); if (replay) return this.getIntent(replay);
      const old = this.db.query("SELECT id FROM intents WHERE order_ref=?").get(orderRef) as { id: string } | null;
      if (old) {
        const intent = this.getIntent(old.id); if (intent.amountAtomic !== amountAtomic || intent.expiresAt !== expiresAt) throw new Error("Order terms immutable");
        this.db.query("INSERT INTO idempotency VALUES ('intent',?,?,?)").run(key, fingerprint, old.id); return intent;
      }
      const createdAt = now(); timestamp(createdAt); if (createdAt >= expiresAt) throw new Error("Expired order");
      await this.verified(rpc);
      const intentId = id(), used = (minor: number): boolean => this.db.query("SELECT 1 FROM intents WHERE subaddress_index=?").get(minor) !== null;
      const limit = (this.db.query("SELECT count(*) AS n FROM intents").get() as { n: number }).n + 2;
      let subaddress = await rpc.createSubaddress(`rill:${intentId}`);
      for (let tries = 1; used(subaddress.minor); tries++) {
        if (tries >= limit) throw new Error("Monero wallet keeps returning allocated subaddresses");
        subaddress = await rpc.createSubaddress(`rill:${intentId}`);
      }
      if (!Number.isSafeInteger(subaddress.minor) || subaddress.minor < 1 || !SUBADDRESS.test(subaddress.address)) throw new Error("Invalid Monero subaddress");
      await rpc.store();
      const intent: MoneroIntent = { intentId, orderRef, address: subaddress.address, subaddressIndex: subaddress.minor, amountAtomic, createdAt, expiresAt, status: "waiting", reconciliation: null };
      const { status: _status, reconciliation: _reason, ...payload } = intent;
      this.db.transaction(() => {
        this.db.query("INSERT INTO intents VALUES (?,?,?,?,?,'waiting',NULL)").run(intentId, orderRef, subaddress.minor, subaddress.address, JSON.stringify(payload));
        this.db.query("INSERT INTO idempotency VALUES ('intent',?,?,?)").run(key, fingerprint, intentId);
      }).immediate();
      return this.getIntent(intentId);
    });
  }

  /**
   * One observation pass over waiting intents and unimpaired paid receipts.
   * Failed identity/catch-up checks or RPC errors change nothing. A recorded
   * receipt no longer backed by the same qualifying entry (same transaction,
   * amount, block and confirmations) in a caught-up view is latched as impaired;
   * the acceptance is kept and never issued again.
   */
  observe(rpc: MoneroRpc, now: () => number): Promise<{ readonly decided: number; readonly impaired: number }> {
    return this.serial(async () => {
      await this.verified(rpc);
      const waiting = (this.db.query("SELECT id FROM intents WHERE status='waiting' ORDER BY rowid").all() as { id: string }[]).map((row) => this.getIntent(row.id));
      const watched = this.db.query("SELECT r.key,r.payload,i.subaddress_index,i.address FROM receipts r JOIN intents i ON i.id=r.intent_id WHERE i.status='paid' AND r.impaired_at IS NULL")
        .all() as { key: string; payload: string; subaddress_index: number; address: string }[];
      const minors = [...new Set([...waiting.map((intent) => intent.subaddressIndex), ...watched.map((row) => row.subaddress_index)])];
      const transfers = await rpc.transfers(minors), time = now(); timestamp(time);
      let decided = 0, impaired = 0;
      const outcomes = waiting.map((intent) => ({ intent, ...classifyMoneroPayment(intent, this.config.network, transfers, time) }));
      this.db.transaction(() => {
        for (const { intent, decision, progress } of outcomes) {
          this.progress.set(intent.intentId, progress);
          if (decision.kind === "waiting") continue;
          decided += 1;
          for (const receipt of decision.receipts) this.db.query("INSERT INTO receipts VALUES (?,?,?,NULL)").run(receipt.key, intent.intentId, JSON.stringify(receipt));
          if (decision.kind === "reconciliation") {
            this.db.query("UPDATE intents SET status='reconciliation',reason=? WHERE id=? AND status='waiting'").run(decision.reason, intent.intentId);
            continue;
          }
          const acceptance: MoneroAcceptance = { version: "monero-acceptance/1", id: id(), intentId: intent.intentId, receiptKeys: decision.receipts.map((receipt) => receipt.key), acceptedAt: time };
          this.db.query("INSERT INTO outbox (id,intent_id,payload) VALUES (?,?,?)").run(acceptance.id, intent.intentId, JSON.stringify(acceptance));
          this.db.query("UPDATE intents SET status='paid' WHERE id=? AND status='waiting'").run(intent.intentId);
        }
        for (const row of watched) {
          const receipt = JSON.parse(row.payload) as MoneroReceipt;
          // The recorded evidence must still hold exactly: same block (height and
          // timestamp) and still qualifying. A re-mined transaction is impaired too.
          const present = transfers.some((transfer) => transfer.major === 0 && transfer.minor === row.subaddress_index && transfer.address === row.address &&
            transfer.txid === receipt.txid && transfer.amountAtomic.toString() === receipt.amountAtomic && transfer.height === receipt.height &&
            transfer.timestamp === receipt.timestamp && qualifyingMoneroTransfer(transfer, this.config.network));
          if (!present) { this.db.query("UPDATE receipts SET impaired_at=? WHERE key=?").run(time, row.key); impaired += 1; }
        }
      }).immediate();
      return { decided, impaired };
    });
  }
}
