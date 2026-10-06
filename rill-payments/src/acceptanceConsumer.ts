import { Database } from "bun:sqlite";
import { closeSync, lstatSync, openSync, realpathSync } from "node:fs";
import { dirname } from "node:path";
import { MAX_MSAT, parseTerms, type NativeLightningTerms, type Network } from "./contract";
import { hasNontrivialAcceptanceKey, verifyAcceptance, type SignedAcceptance } from "./server";

export interface AcceptanceConsumerIdentity {
  readonly merchantOrigin: string;
  readonly merchantPublicKey: string;
  readonly receiver: string;
  readonly network: Network;
}
export interface BoundOrderStatus {
  readonly orderRef: string;
  readonly state: "waiting" | "accepted";
  readonly eventId: string | null;
}
interface OrderRow { order_ref: string; amount_msat: string; intent_id: string; attempt_id: string; payment_hash: string; terms: string }
interface AcceptanceRow { event_id: string; order_ref: string; envelope: string }
const TABLES: Readonly<Record<string, string>> = {
  metadata: "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  orders: "CREATE TABLE orders (order_ref TEXT PRIMARY KEY, amount_msat TEXT NOT NULL, intent_id TEXT NOT NULL UNIQUE, attempt_id TEXT NOT NULL UNIQUE, payment_hash TEXT NOT NULL UNIQUE, terms TEXT NOT NULL)",
  acceptances: "CREATE TABLE acceptances (event_id TEXT PRIMARY KEY, order_ref TEXT NOT NULL UNIQUE REFERENCES orders(order_ref), envelope TEXT NOT NULL)",
};
const EVENT_KEYS = "acceptedAt,amountMsat,attemptId,id,intentId,merchantOrigin,paymentHash,type,version";
const ENVELOPE_KEYS = "algorithm,event,publicKey,signature";
const TERM_KEYS = "amountMsat,attemptId,buyerExtraMsat,expiresAt,intentId,merchantOrigin,network,paymentHash,policyVersion,receiver,version";
const normalize = (sql: string) => sql.trim().replace(/\s+/g, " ");
function quantity(value: string): void {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value) || BigInt(value) > MAX_MSAT || BigInt(value) % 1000n !== 0n) throw new Error("Invalid order price");
}
function orderReference(value: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value)) throw new Error("Invalid order reference");
}
function clock(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid acceptance clock");
}
function termsSnapshot(input: NativeLightningTerms): Readonly<NativeLightningTerms> {
  if (!input || Object.keys(input).sort().join(",") !== TERM_KEYS) throw new Error("Invalid bound payment terms");
  return parseTerms({ version: input.version, policyVersion: input.policyVersion, merchantOrigin: input.merchantOrigin,
    intentId: input.intentId, attemptId: input.attemptId, network: input.network, amountMsat: input.amountMsat,
    paymentHash: input.paymentHash, receiver: input.receiver, expiresAt: input.expiresAt, buyerExtraMsat: input.buyerExtraMsat });
}
function consumerIdentity(input: AcceptanceConsumerIdentity): Readonly<AcceptanceConsumerIdentity> {
  if (!input) throw new Error("Missing acceptance identity");
  const identity = { merchantOrigin: input.merchantOrigin, merchantPublicKey: input.merchantPublicKey, receiver: input.receiver, network: input.network };
  parseTerms({ version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: identity.merchantOrigin,
    receiver: identity.receiver, network: identity.network, intentId: "consumer_check_1", attemptId: "consumer_check_2",
    amountMsat: "1000", buyerExtraMsat: "0", paymentHash: "0".repeat(64), expiresAt: 1 });
  if (identity.network === "mainnet" || typeof identity.merchantPublicKey !== "string" || !/^[0-9a-f]{64}$/.test(identity.merchantPublicKey) || !hasNontrivialAcceptanceKey(identity.merchantPublicKey)) throw new Error("Unsupported acceptance identity");
  return Object.freeze(identity);
}
function privateDirectory(path: string): void {
  const directory = lstatSync(dirname(path));
  if (!directory.isDirectory() || directory.isSymbolicLink() || (directory.mode & 0o077) !== 0) throw new Error("Acceptance store requires a private directory");
}
function privateFile(path: string): void {
  privateDirectory(path);
  const file = lstatSync(path);
  if (!file.isFile() || file.isSymbolicLink() || (file.mode & 0o077) !== 0 || file.nlink !== 1) throw new Error("Acceptance store requires a private regular file");
}
function envelopeSnapshot(input: SignedAcceptance): SignedAcceptance {
  if (!input || Object.keys(input).sort().join(",") !== ENVELOPE_KEYS) throw new Error("Invalid acceptance envelope");
  const event = input.event;
  if (!event || Object.keys(event).sort().join(",") !== EVENT_KEYS) throw new Error("Invalid acceptance event");
  // Authenticate the captured scalars, never caller-owned getters or extensions.
  const snapshot: SignedAcceptance = { algorithm: input.algorithm, publicKey: input.publicKey, signature: input.signature,
    event: { version: event.version, id: event.id, merchantOrigin: event.merchantOrigin, type: event.type,
      intentId: event.intentId, attemptId: event.attemptId, paymentHash: event.paymentHash, amountMsat: event.amountMsat, acceptedAt: event.acceptedAt } };
  if (snapshot.algorithm !== "Ed25519" || typeof snapshot.publicKey !== "string" || !/^[0-9a-f]{64}$/.test(snapshot.publicKey) ||
      typeof snapshot.signature !== "string" || !/^[0-9a-f]{128}$/.test(snapshot.signature) ||
      [snapshot.event.version, snapshot.event.id, snapshot.event.merchantOrigin, snapshot.event.type, snapshot.event.intentId, snapshot.event.attemptId, snapshot.event.paymentHash, snapshot.event.amountMsat].some((value) => typeof value !== "string")) throw new Error("Invalid acceptance scalars");
  return snapshot;
}

/** Backend-only bound acceptance ledger. No external fulfillment or spending. */
export class LightningAcceptanceConsumer {
  private constructor(private readonly db: Database, readonly identity: Readonly<AcceptanceConsumerIdentity>) {}

  static provision(path: string, input: AcceptanceConsumerIdentity): LightningAcceptanceConsumer {
    const identity = consumerIdentity(input); privateDirectory(path);
    const fd = openSync(path, "wx", 0o600); closeSync(fd); privateFile(path);
    const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try {
      db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      db.transaction(() => {
        for (const sql of Object.values(TABLES)) db.exec(sql);
        db.query("INSERT INTO metadata VALUES ('format','lightning-acceptance-consumer/1'), ('identity',?)").run(JSON.stringify(identity));
      }).immediate();
    } finally { db.close(); }
    return LightningAcceptanceConsumer.open(path, identity);
  }

  static open(path: string, input: AcceptanceConsumerIdentity): LightningAcceptanceConsumer {
    const identity = consumerIdentity(input); privateFile(path);
    const db = new Database(realpathSync(path), { readwrite: true, create: false, strict: true });
    try {
      const metadata = db.query("SELECT key,value FROM metadata").all() as { key: string; value: string }[];
      if (metadata.length !== 2 || metadata.find((entry) => entry.key === "format")?.value !== "lightning-acceptance-consumer/1" ||
          metadata.find((entry) => entry.key === "identity")?.value !== JSON.stringify(identity)) throw new Error("Acceptance store format or identity mismatch");
      const schema = db.query("SELECT type,name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").all() as { type: string; name: string; sql: string }[];
      if (schema.length !== Object.keys(TABLES).length || schema.some((entry) => entry.type !== "table" || !Object.hasOwn(TABLES, entry.name) || normalize(entry.sql) !== normalize(TABLES[entry.name]!))) throw new Error("Acceptance store schema mismatch");
      if (db.query("PRAGMA foreign_key_check").all().length !== 0 || (db.query("PRAGMA quick_check").get() as { quick_check: string }).quick_check !== "ok") throw new Error("Acceptance store is corrupt");
      db.exec("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
      return new LightningAcceptanceConsumer(db, identity);
    } catch (error) { db.close(); throw error; }
  }

  close(): void { this.db.close(); }
  private boundTerms(row: OrderRow): Readonly<NativeLightningTerms> {
    orderReference(row.order_ref); quantity(row.amount_msat);
    if (typeof row.terms !== "string" || row.terms.length > 4096) throw new Error("Invalid stored binding");
    const terms = termsSnapshot(JSON.parse(row.terms));
    if (JSON.stringify(terms) !== row.terms || terms.merchantOrigin !== this.identity.merchantOrigin || terms.receiver !== this.identity.receiver || terms.network !== this.identity.network ||
        terms.intentId !== row.intent_id || terms.attemptId !== row.attempt_id || terms.paymentHash !== row.payment_hash || terms.amountMsat !== row.amount_msat) throw new Error("Order binding is inconsistent");
    return terms;
  }
  private matchAcceptance(envelope: SignedAcceptance, row: OrderRow): void {
    const terms = this.boundTerms(row), event = envelope.event;
    if (!verifyAcceptance(envelope, this.identity.merchantPublicKey) || event.merchantOrigin !== this.identity.merchantOrigin || event.intentId !== terms.intentId ||
        event.attemptId !== terms.attemptId || event.paymentHash !== terms.paymentHash || event.amountMsat !== row.amount_msat) throw new Error("Acceptance differs from bound order");
    // acceptedAt is observation time. The trusted producer enforces settlement
    // timeliness; observations can legitimately occur after terms expire.
  }
  private readOrder(orderRef: string): { row: OrderRow; accepted: AcceptanceRow | null } {
    const row = this.db.query("SELECT * FROM orders WHERE order_ref=?").get(orderRef) as OrderRow | null;
    if (!row) throw new Error("Unknown bound order");
    this.boundTerms(row);
    const accepted = this.db.query("SELECT * FROM acceptances WHERE order_ref=?").get(orderRef) as AcceptanceRow | null;
    if (accepted) {
      if (typeof accepted.envelope !== "string" || accepted.envelope.length > 4096) throw new Error("Invalid stored acceptance");
      const envelope = envelopeSnapshot(JSON.parse(accepted.envelope));
      if (accepted.order_ref !== row.order_ref || envelope.event.id !== accepted.event_id || JSON.stringify(envelope) !== accepted.envelope) throw new Error("Stored acceptance is inconsistent");
      this.matchAcceptance(envelope, row);
    }
    return { row, accepted };
  }
  private status(orderRef: string, accepted: AcceptanceRow | null): Readonly<BoundOrderStatus> {
    return Object.freeze({ orderRef, state: accepted ? "accepted" : "waiting", eventId: accepted?.event_id ?? null });
  }
  private expectedBinding(orderRef: string, orderAmountMsat: string, input: NativeLightningTerms) {
    orderReference(orderRef); quantity(orderAmountMsat);
    const terms = termsSnapshot(input), payload = JSON.stringify(terms);
    if (terms.merchantOrigin !== this.identity.merchantOrigin || terms.receiver !== this.identity.receiver || terms.network !== this.identity.network || terms.amountMsat !== orderAmountMsat) throw new Error("Order terms differ from trusted identity or price");
    return { terms, payload };
  }

  /** Explicit trusted backend registration, after issuance, before buyer exposure.
   * Order price is independently authoritative, never a browser-supplied amount.
   */
  bindOrder(orderRef: string, orderAmountMsat: string, input: NativeLightningTerms): Readonly<BoundOrderStatus> {
    const { terms, payload } = this.expectedBinding(orderRef, orderAmountMsat, input);
    return this.db.transaction(() => {
      const exists = this.db.query("SELECT order_ref FROM orders WHERE order_ref=?").get(orderRef);
      if (exists) {
        const { row, accepted } = this.readOrder(orderRef);
        if (row.amount_msat !== orderAmountMsat || row.terms !== payload) throw new Error("Bound order terms cannot be replaced");
        return this.status(orderRef, accepted);
      }
      this.db.query("INSERT INTO orders VALUES (?,?,?,?,?,?)").run(orderRef, orderAmountMsat, terms.intentId, terms.attemptId, terms.paymentHash, payload);
      return this.status(orderRef, null);
    }).immediate();
  }

  /** Read-only full-term assertion. Missing state never creates a binding. */
  existingBinding(orderRef: string, orderAmountMsat: string, input: NativeLightningTerms): Readonly<BoundOrderStatus> | null {
    const { payload } = this.expectedBinding(orderRef, orderAmountMsat, input);
    return this.db.transaction(() => {
      if (!this.db.query("SELECT order_ref FROM orders WHERE order_ref=?").get(orderRef)) return null;
      const { row, accepted } = this.readOrder(orderRef);
      if (row.amount_msat !== orderAmountMsat || row.terms !== payload) throw new Error("Existing order binding differs from expected terms");
      return this.status(orderRef, accepted);
    }).deferred();
  }

  getOrder(orderRef: string): Readonly<BoundOrderStatus> {
    orderReference(orderRef);
    return this.db.transaction(() => this.status(orderRef, this.readOrder(orderRef).accepted)).deferred();
  }

  /** Verified acceptance facts for downstream fulfillment, or null while waiting.
   * Reads through the same provenance checks as getOrder; unknown orders throw. */
  acceptedOrder(orderRef: string): Readonly<{ orderRef: string; amountMsat: string; paymentHash: string; eventId: string }> | null {
    orderReference(orderRef);
    return this.db.transaction(() => {
      const { row, accepted } = this.readOrder(orderRef);
      return accepted ? Object.freeze({ orderRef: row.order_ref, amountMsat: row.amount_msat, paymentHash: row.payment_hash, eventId: accepted.event_id }) : null;
    }).deferred();
  }

  consume(input: SignedAcceptance, now: number): Readonly<BoundOrderStatus> {
    clock(now);
    const envelope = envelopeSnapshot(input);
    if (!verifyAcceptance(envelope, this.identity.merchantPublicKey) || envelope.event.merchantOrigin !== this.identity.merchantOrigin || envelope.event.acceptedAt > now) throw new Error("Acceptance event refused");
    const payload = JSON.stringify(envelope);
    return this.db.transaction(() => {
      const bound = this.db.query("SELECT order_ref FROM orders WHERE intent_id=?").get(envelope.event.intentId) as { order_ref: string } | null;
      if (!bound) throw new Error("Acceptance has no original order binding");
      const { row, accepted } = this.readOrder(bound.order_ref); this.matchAcceptance(envelope, row);
      const replay = this.db.query("SELECT * FROM acceptances WHERE event_id=?").get(envelope.event.id) as AcceptanceRow | null;
      if (replay) {
        // Validate provenance of the referenced row, not just its event marker.
        this.readOrder(replay.order_ref);
        if (replay.order_ref !== row.order_ref || replay.envelope !== payload) throw new Error("Conflicting acceptance event ID");
      }
      if (accepted && (accepted.event_id !== envelope.event.id || accepted.envelope !== payload)) throw new Error("Order acceptance cannot be replaced");
      if (!accepted) this.db.query("INSERT INTO acceptances VALUES (?,?,?)").run(envelope.event.id, row.order_ref, payload);
      return this.status(row.order_ref, accepted ?? { event_id: envelope.event.id, order_ref: row.order_ref, envelope: payload });
    }).immediate();
  }
}
