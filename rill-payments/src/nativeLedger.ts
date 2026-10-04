import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { observeEvmReceipt, prepareEvmBinding, receiptBindingTypedData, type EvmReader, type EvmReceiptBinding, type EvmReceiptIntent, type EvmTokenAsset, type PreparedEvmBinding } from "./evmReceipt";

export interface NativeLedgerConfig {
  readonly origin: string;
  readonly recipient: string;
  readonly asset: EvmTokenAsset;
  readonly inventoryCapBaseUnits: string;
}
export interface NativeIntent extends EvmReceiptIntent {
  readonly orderRef: string;
  readonly status: "waiting" | "paid" | "reconciliation";
}
export interface NativeAcceptance {
  readonly version: "native-acceptance/1";
  readonly id: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly merchantOrigin: string;
  readonly assetId: string;
  readonly quantityBaseUnits: string;
  readonly receiptKey: string;
  readonly acceptedAt: number;
}
const id = (): string => randomBytes(24).toString("base64url");
const digest = (input: unknown): string => createHash("sha256").update(JSON.stringify(input)).digest("hex");
const quantity = (input: string): bigint => { if (typeof input !== "string" || !/^[1-9][0-9]{0,77}$/.test(input) || BigInt(input) >= 1n << 256n) throw new Error("Invalid asset quantity"); return BigInt(input); };
const timestamp = (input: number): void => { if (!Number.isSafeInteger(input) || input < 0) throw new Error("Invalid time"); };
const schema: readonly string[] = [
  "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "CREATE TABLE intents (id TEXT PRIMARY KEY, order_ref TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('waiting','paid','reconciliation')))",
  "CREATE TABLE idempotency (scope TEXT NOT NULL, key TEXT NOT NULL, fingerprint TEXT NOT NULL, result_id TEXT NOT NULL, PRIMARY KEY(scope,key))",
  "CREATE TABLE attempts (id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES intents(id), nonce_key TEXT NOT NULL UNIQUE, prepared TEXT NOT NULL, transaction_hash TEXT UNIQUE)",
  "CREATE TABLE reservations (attempt_id TEXT PRIMARY KEY REFERENCES attempts(id), quantity TEXT NOT NULL)",
  "CREATE TABLE receipts (key TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(id), payload TEXT NOT NULL, finality TEXT NOT NULL CHECK(finality IN ('finalized','reorged')))",
  "CREATE TABLE inventory_entries (id TEXT PRIMARY KEY, receipt_key TEXT NOT NULL UNIQUE REFERENCES receipts(key), quantity TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('held','impaired')))",
  "CREATE TABLE outbox (id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES intents(id), payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)",
];
const normalize = (sql: string): string => sql.trim().replace(/\s+/g, " ");
function privateStore(path: string): void {
  const directory = lstatSync(dirname(path)), file = lstatSync(path);
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0 || !file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || (file.mode & 0o077) !== 0) throw new Error("Native ledger requires private regular storage");
}
function configCopy(config: NativeLedgerConfig): NativeLedgerConfig {
  if (new URL(config.origin).origin !== config.origin || !config.origin.startsWith("https://") || !/^0x[0-9a-f]{40}$/.test(config.recipient) || config.asset.chainId !== "11155111") throw new Error("Native ledger is Sepolia-only");
  quantity(config.inventoryCapBaseUnits);
  const asset = config.asset;
  return Object.freeze({ origin: config.origin, recipient: config.recipient, inventoryCapBaseUnits: config.inventoryCapBaseUnits,
    asset: Object.freeze({ id: asset.id, chainId: asset.chainId, genesisHash: asset.genesisHash, token: asset.token, decimals: asset.decimals, behavior: asset.behavior,
      runtimeCodeHash: asset.runtimeCodeHash, implementation: asset.implementation === null ? null : Object.freeze({ ...asset.implementation }),
      historicalStateVerified: asset.historicalStateVerified, behaviorConformanceVerified: asset.behaviorConformanceVerified }) });
}

/** Separate native payment/inventory accounting. No signer, conversion, network rescan or provisioning on open. */
export class NativeReceiptLedger {
  private constructor(private readonly db: Database, readonly config: NativeLedgerConfig) {}
  static provision(path: string, input: NativeLedgerConfig): NativeReceiptLedger {
    const config = configCopy(input); const fd = openSync(path, "wx", 0o600); closeSync(fd); privateStore(path);
    const db = new Database(realpathSync(path), { create: false, readwrite: true, strict: true });
    try {
      db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      db.transaction(() => { for (const sql of schema) db.exec(sql); db.query("INSERT INTO metadata VALUES ('version','1'), ('config',?)").run(JSON.stringify(config)); }).immediate();
    } finally { db.close(); }
    return NativeReceiptLedger.open(path, config);
  }
  static open(path: string, input: NativeLedgerConfig): NativeReceiptLedger {
    const config = configCopy(input); privateStore(path); const db = new Database(realpathSync(path), { create: false, readwrite: true, strict: true });
    try {
      const objects = db.query("SELECT sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name").all() as { sql: string }[];
      if (JSON.stringify(objects.map((entry) => normalize(entry.sql)).sort()) !== JSON.stringify(schema.map(normalize).sort())) throw new Error("Native ledger schema mismatch");
      const metadata = db.query("SELECT key,value FROM metadata").all() as { key: string; value: string }[];
      if (metadata.length !== 2 || metadata.find((entry) => entry.key === "version")?.value !== "1" || metadata.find((entry) => entry.key === "config")?.value !== JSON.stringify(config)) throw new Error("Native ledger version/config mismatch");
      if ((db.query("PRAGMA quick_check").get() as { quick_check: string }).quick_check !== "ok" || db.query("PRAGMA foreign_key_check").all().length !== 0) throw new Error("Native ledger integrity failure");
      db.exec("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      return new NativeReceiptLedger(db, config);
    } catch (error) { db.close(); throw error; }
  }
  close(): void { this.db.close(); }
  private replay(scope: string, key: string, fingerprint: string): string | null {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new Error("Invalid idempotency key");
    const row = this.db.query("SELECT fingerprint,result_id FROM idempotency WHERE scope=? AND key=?").get(scope, key) as { fingerprint: string; result_id: string } | null;
    if (row && row.fingerprint !== fingerprint) throw new Error("Conflicting idempotency key"); return row?.result_id ?? null;
  }
  getIntent(intentId: string): NativeIntent {
    const row = this.db.query("SELECT payload,status FROM intents WHERE id=?").get(intentId) as { payload: string; status: NativeIntent["status"] } | null;
    if (!row) throw new Error("Unknown native intent"); return Object.freeze({ ...JSON.parse(row.payload), status: row.status });
  }
  createIntent(orderRef: string, amountBaseUnits: string, expiresAt: number, key: string, now: number): NativeIntent {
    quantity(amountBaseUnits); timestamp(expiresAt); timestamp(now); if (!orderRef || orderRef.length > 128) throw new Error("Invalid order");
    const fingerprint = digest([orderRef, amountBaseUnits, expiresAt]);
    return this.db.transaction(() => {
      const replay = this.replay("intent", key, fingerprint); if (replay) return this.getIntent(replay);
      const old = this.db.query("SELECT id FROM intents WHERE order_ref=?").get(orderRef) as { id: string } | null;
      if (old) { const intent = this.getIntent(old.id); if (intent.amountBaseUnits !== amountBaseUnits || intent.expiresAt !== expiresAt) throw new Error("Order terms immutable");
        this.db.query("INSERT INTO idempotency VALUES ('intent',?,?,?)").run(key, fingerprint, old.id); return intent; }
      if (now >= expiresAt) throw new Error("Expired order");
      const intentId = id(); const intent: NativeIntent = { merchantOrigin: this.config.origin, intentId, attemptId: id(), assetId: this.config.asset.id,
        recipient: this.config.recipient, amountBaseUnits, createdAt: now, expiresAt, orderRef, status: "waiting" };
      this.db.query("INSERT INTO intents VALUES (?,?,?,'waiting')").run(intentId, orderRef, JSON.stringify(intent));
      this.db.query("INSERT INTO idempotency VALUES ('intent',?,?,?)").run(key, fingerprint, intentId); return intent;
    }).immediate();
  }
  getPreparation(attemptId: string): PreparedEvmBinding {
    const row = this.db.query("SELECT prepared FROM attempts WHERE id=?").get(attemptId) as { prepared: string } | null;
    if (!row) throw new Error("Unknown native attempt"); return JSON.parse(row.prepared);
  }
  inventory(): { held: string; reserved: string; impaired: string } {
    const sum = (sql: string): string => (this.db.query(sql).all() as { quantity: string }[]).reduce((total, row) => total + quantity(row.quantity), 0n).toString();
    return { held: sum("SELECT quantity FROM inventory_entries WHERE status='held'"), reserved: sum("SELECT quantity FROM reservations"), impaired: sum("SELECT quantity FROM inventory_entries WHERE status='impaired'") };
  }
  async prepare(intentId: string, binding: EvmReceiptBinding, signature: string, key: string, provider: EvmReader, now: () => number): Promise<PreparedEvmBinding> {
    // Freeze buyer input before any await; replay never refreshes preparation provenance.
    const input = Object.freeze({ version: binding.version, ...receiptBindingTypedData(this.config.asset, binding).value });
    const fingerprint = digest([intentId, input, signature]);
    const replay = this.replay("attempt", key, fingerprint); if (replay) return this.getPreparation(replay);
    const intent = this.getIntent(intentId); if (intent.status !== "waiting") throw new Error("Order not payable");
    const prepared = await prepareEvmBinding(this.config.asset, intent, input, signature, provider, now);
    return this.db.transaction(() => {
      const raced = this.replay("attempt", key, fingerprint); if (raced) return this.getPreparation(raced);
      const old = this.db.query("SELECT prepared FROM attempts WHERE intent_id=?").get(intentId) as { prepared: string } | null;
      if (old) throw new Error("Native attempt already reserved");
      const time = now(); timestamp(time); if (time >= prepared.binding.validBefore || time < prepared.preparedAt) throw new Error("Preparation expired");
      const inventory = this.inventory();
      if (BigInt(inventory.impaired) !== 0n || BigInt(inventory.held) + BigInt(inventory.reserved) + quantity(intent.amountBaseUnits) > quantity(this.config.inventoryCapBaseUnits)) throw new Error("Native inventory capacity unavailable");
      const nonceKey = `${this.config.asset.chainId}:${this.config.asset.genesisHash}:${input.sourceWallet}:${input.sourceNonce}`;
      this.db.query("INSERT INTO attempts VALUES (?,?,?,?,NULL)").run(intent.attemptId, intentId, nonceKey, JSON.stringify(prepared));
      this.db.query("INSERT INTO reservations VALUES (?,?)").run(intent.attemptId, intent.amountBaseUnits);
      this.db.query("INSERT INTO idempotency VALUES ('attempt',?,?,?)").run(key, fingerprint, intent.attemptId); return prepared;
    }).immediate();
  }
  async observe(attemptId: string, transactionHash: string, provider: EvmReader, now: () => number): Promise<NativeIntent> {
    const row = this.db.query("SELECT intent_id,transaction_hash FROM attempts WHERE id=?").get(attemptId) as { intent_id: string; transaction_hash: string | null } | null;
    if (!row) throw new Error("Unknown native attempt");
    if (row.transaction_hash !== null && row.transaction_hash !== transactionHash) throw new Error("Native receipt already fixed");
    const intent = this.getIntent(row.intent_id), prepared = this.getPreparation(attemptId);
    const receipt = await observeEvmReceipt(this.config.asset, intent, prepared, transactionHash, provider);
    if (!receipt) return this.getIntent(row.intent_id);
    const acceptedAt = now(); timestamp(acceptedAt); if (acceptedAt < receipt.blockTimestamp) throw new Error("Receipt timestamp is in the future");
    return this.db.transaction(() => {
      const previous = this.db.query("SELECT payload,finality FROM receipts WHERE attempt_id=?").get(attemptId) as { payload: string; finality: string } | null;
      if (previous) { if (previous.payload !== JSON.stringify(receipt) || previous.finality !== "finalized") throw new Error("Native receipt requires reconciliation"); return this.getIntent(row.intent_id); }
      this.db.query("INSERT INTO receipts VALUES (?,?,?,'finalized')").run(receipt.deduplicationKey, attemptId, JSON.stringify(receipt));
      this.db.query("UPDATE attempts SET transaction_hash=? WHERE id=?").run(transactionHash, attemptId);
      this.db.query("INSERT INTO inventory_entries VALUES (?,?,?,'held')").run(id(), receipt.deduplicationKey, receipt.quantityBaseUnits);
      this.db.query("DELETE FROM reservations WHERE attempt_id=?").run(attemptId);
      if (receipt.timing === "late") this.db.query("UPDATE intents SET status='reconciliation' WHERE id=?").run(row.intent_id);
      else {
        const event: NativeAcceptance = { version: "native-acceptance/1", id: id(), intentId: intent.intentId, attemptId, merchantOrigin: this.config.origin,
          assetId: receipt.assetId, quantityBaseUnits: receipt.quantityBaseUnits, receiptKey: receipt.deduplicationKey, acceptedAt };
        this.db.query("INSERT INTO outbox (id,intent_id,payload) VALUES (?,?,?)").run(event.id, intent.intentId, JSON.stringify(event));
        this.db.query("UPDATE intents SET status='paid' WHERE id=?").run(intent.intentId);
      }
      return this.getIntent(intent.intentId);
    }).immediate();
  }
  /** Administrative evidence downgrade preserves acceptance/history; it never starts a rescan or spend. */
  recordReorg(receiptKey: string): void {
    this.db.transaction(() => {
      const receipt = this.db.query("SELECT key FROM receipts WHERE key=?").get(receiptKey); if (!receipt) throw new Error("Unknown native receipt");
      this.db.query("UPDATE receipts SET finality='reorged' WHERE key=?").run(receiptKey);
      this.db.query("UPDATE inventory_entries SET status='impaired' WHERE receipt_key=?").run(receiptKey);
    }).immediate();
  }
  pendingEvents(): NativeAcceptance[] { return (this.db.query("SELECT payload FROM outbox WHERE delivered=0 ORDER BY rowid").all() as { payload: string }[]).map((row) => JSON.parse(row.payload)); }
  acknowledgeEvent(eventId: string): void { this.db.query("UPDATE outbox SET delivered=1 WHERE id=?").run(eventId); }
}
