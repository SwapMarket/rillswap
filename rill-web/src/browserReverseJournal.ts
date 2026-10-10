/** Origin-local encrypted reverse snapshots and one-time side-effect elections. No networking or signing. */
import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { isSupportedRecoveryNetwork } from "./recoveryInspection";
import { checkReverseFirmQuoteRequest, type ReverseFirmQuoteRequest } from "./swap/wire";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { validateStoredHoldPlan, type BoundedHoldPlan } from "./swap/browserHoldPayer";

const DATABASE = "rillswap-reverse-execution";
const STORES = ["sessions", "payments", "claims"] as const;
const HEX = /^[0-9a-f]{64}$/;
const KEY = /^0[23][0-9a-f]{64}$/;
const MAX_CIPHER_BYTES = 512 * 1024;
const encoder = new TextEncoder();
export type ReverseStage = "secrets-ready" | "terms-ready" | "payment-unknown" | "funded" | "claim-ready" | "claim-unknown" | "accepted";
const SNAPSHOT_STAGES = ["secrets-ready", "terms-ready", "payment-unknown", "funded", "claim-ready"] as const;

export interface ReverseIntentContext {
  readonly networkIdentity: unknown;
  readonly sessionId: string;
  readonly clientSessionKey: string;
  readonly providerSessionKey: string;
  readonly providerIdentity: string;
  readonly request: ReverseFirmQuoteRequest;
  /** Original wall-clock authority, never renewed on restoration. */
  readonly deadlineAt: number;
}
interface Snapshot { readonly stage: typeof SNAPSHOT_STAGES[number]; readonly ciphertextHex: string; readonly digest: string }
interface PaymentIntent { readonly state: "submission-unknown"; readonly endpoint: string; readonly plan: BoundedHoldPlan }
export interface ReverseClaimIntent {
  readonly fundingTxid: string;
  readonly fundingVout: number;
  readonly txid: string;
  /** SHA256 of the exact signed bytes, verified privately before every exposure. */
  readonly signedDigest: string;
}
export interface ReverseJournalRecord {
  readonly id: string;
  readonly context: ReverseIntentContext;
  readonly stage: ReverseStage;
  readonly snapshots: readonly Snapshot[];
  /** Funding is independent evidence; this UNKNOWN attempt remains retained afterward. */
  readonly payment: PaymentIntent | null;
  readonly claim: ReverseClaimIntent | null;
  readonly digest: string;
}
interface Election { readonly id: string; readonly owner: string; readonly digest: string; readonly state: "submission-unknown" | "prepared" | "accepted" }

export class ReverseJournalRefusedError extends Error {
  constructor() { super("Reverse recovery state unavailable or conflicting. Preserve backups; no automatic retry or replacement is permitted."); this.name = "ReverseJournalRefusedError"; }
}
const require = (condition: boolean): void => { if (!condition) throw new ReverseJournalRefusedError(); };
function object(value: unknown, keys: readonly string[]): Record<string, unknown> {
  require(value !== null && typeof value === "object" && !Array.isArray(value));
  const o = value as Record<string, unknown>; require(Object.keys(o).length === keys.length && keys.every((key) => Object.hasOwn(o, key))); return o;
}
function freeze<T>(value: T): T { if (value && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }
function digest(value: unknown): string { const text = canonicalize(value); require(text !== undefined); return bytesToHex(sha256(encoder.encode(text!))); }
function contextSnapshot(value: unknown): ReverseIntentContext {
  const c = object(structuredClone(value), ["networkIdentity", "sessionId", "clientSessionKey", "providerSessionKey", "providerIdentity", "request", "deadlineAt"]);
  require(isSupportedRecoveryNetwork(c.networkIdentity));
  require((c.networkIdentity as { name: string }).name !== "mainnet");
  for (const key of [c.sessionId, c.clientSessionKey, c.providerSessionKey, c.providerIdentity]) require(typeof key === "string" && HEX.test(key));
  require(new Set([c.clientSessionKey, c.providerSessionKey, c.providerIdentity]).size === 3);
  checkReverseFirmQuoteRequest(c.request as ReverseFirmQuoteRequest);
  require(typeof c.deadlineAt === "number" && Number.isSafeInteger(c.deadlineAt) && c.deadlineAt > 0);
  return freeze(c as unknown as ReverseIntentContext);
}
function idFor(network: unknown, sessionId: string): string { require(isSupportedRecoveryNetwork(network) && typeof sessionId === "string" && HEX.test(sessionId)); return digest({ network, sessionId }); }
function snapshot(stage: Snapshot["stage"], value: Uint8Array): Snapshot {
  require(value instanceof Uint8Array && value.length > 32 && value.length <= MAX_CIPHER_BYTES);
  const bytes = Uint8Array.from(value);
  require(new TextDecoder().decode(bytes.slice(0, 22)) === "age-encryption.org/v1\n");
  return freeze({ stage, ciphertextHex: bytesToHex(bytes), digest: bytesToHex(sha256(bytes)) });
}
function recordSnapshot(value: unknown): ReverseJournalRecord {
  const o = object(structuredClone(value), ["id", "context", "stage", "snapshots", "payment", "claim", "digest"]);
  const context = contextSnapshot(o.context);
  require(o.id === idFor(context.networkIdentity, context.sessionId));
  const length = [...SNAPSHOT_STAGES, "claim-unknown", "accepted"].indexOf(o.stage as ReverseStage);
  require(length >= 0 && Array.isArray(o.snapshots) && o.snapshots.length === Math.min(length + 1, 5));
  for (const [index, item] of (o.snapshots as unknown[]).entries()) {
    const s = object(item, ["stage", "ciphertextHex", "digest"]);
    require(s.stage === SNAPSHOT_STAGES[index] && typeof s.ciphertextHex === "string" &&
      /^(?:[0-9a-f]{2})+$/.test(s.ciphertextHex) && s.ciphertextHex.length <= MAX_CIPHER_BYTES * 2);
    const bytes = hexToBytes(s.ciphertextHex as string);
    const verified = snapshot(SNAPSHOT_STAGES[index]!, bytes); require(verified.digest === s.digest);
  }
  if (length >= 2) {
    const payment = object(o.payment, ["state", "endpoint", "plan"]), plan = object(payment.plan, ["nodeIdentity", "networkIdentity", "paymentHash", "invoiceBinding", "route", "feeMsat", "limits"]);
    validateStoredHoldPlan(plan as unknown as BoundedHoldPlan);
    require(payment.state === "submission-unknown" && typeof payment.endpoint === "string" &&
      validateMempoolApi(payment.endpoint, (context.networkIdentity as { name: NetworkName }).name) === payment.endpoint);
    require(typeof plan.nodeIdentity === "string" && KEY.test(plan.nodeIdentity) && plan.paymentHash === context.request.payment_hash &&
      canonicalize(plan.networkIdentity) === canonicalize(context.networkIdentity));
    const binding = object(plan.invoiceBinding, ["bolt11_sha256", "payment_hash", "amount_msat", "payee_compressed_pubkey", "created_at", "expires_at", "min_final_cltv_delta"]);
    require(binding.payment_hash === context.request.payment_hash);
    const limits = object(plan.limits, ["feeLimitSat", "minFinalExpiryHeight", "maxExpiryHeight", "deadlineAt"]);
    require(typeof limits.deadlineAt === "number" && limits.deadlineAt <= context.deadlineAt);
    require(typeof limits.maxExpiryHeight === "number" && limits.maxExpiryHeight <= context.request.limits.max_incoming_htlc_expiry_height);
    // Route/invoice authorization belongs to the payer and authenticated document, not storage.
    require(plan.route !== null && typeof plan.route === "object" && !Array.isArray(plan.route) &&
      typeof plan.feeMsat === "string" && /^(0|[1-9][0-9]{0,18})$/.test(plan.feeMsat));
  } else require(o.payment === null);
  if (length >= 4) {
    const claim = object(o.claim, ["fundingTxid", "fundingVout", "txid", "signedDigest"]);
    for (const field of [claim.fundingTxid, claim.txid, claim.signedDigest]) require(typeof field === "string" && HEX.test(field));
    require(typeof claim.fundingVout === "number" && Number.isSafeInteger(claim.fundingVout) && claim.fundingVout >= 0 && claim.fundingVout <= 0xffffffff);
  } else require(o.claim === null);
  require(o.digest === digest({ id: o.id, context: o.context, stage: o.stage, snapshots: o.snapshots, payment: o.payment, claim: o.claim }));
  return freeze(o as unknown as ReverseJournalRecord);
}
function seal(record: Omit<ReverseJournalRecord, "digest">): ReverseJournalRecord {
  const fields = { id: record.id, context: record.context, stage: record.stage, snapshots: record.snapshots, payment: record.payment, claim: record.claim };
  return recordSnapshot({ ...fields, digest: digest(fields) });
}
function election(value: unknown): Election { const o = object(value, ["id", "owner", "digest", "state"]);
  require([o.id, o.owner, o.digest].every((field) => typeof field === "string" && HEX.test(field)) && ["prepared", "submission-unknown", "accepted"].includes(o.state as string)); return o as unknown as Election; }

export class BrowserReverseJournal {
  private constructor(private readonly database: IDBDatabase) {}
  static open(): Promise<BrowserReverseJournal> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DATABASE);
      request.onupgradeneeded = () => { for (const name of STORES) request.result.createObjectStore(name, { keyPath: "id" }); };
      request.onerror = request.onblocked = () => reject(new ReverseJournalRefusedError());
      request.onsuccess = () => {
        const db = request.result;
        try {
          require(db.objectStoreNames.length === STORES.length && STORES.every((name) => db.objectStoreNames.contains(name)));
          const tx = db.transaction([...STORES]);
          for (const name of STORES) { const store = tx.objectStore(name); require(store.keyPath === "id" && !store.autoIncrement && store.indexNames.length === 0); }
          db.onversionchange = () => db.close(); resolve(new BrowserReverseJournal(db));
        } catch { db.close(); reject(new ReverseJournalRefusedError()); }
      };
    });
  }
  close(): void { this.database.close(); }
  #checkElections(tx: IDBTransaction, record: ReverseJournalRecord, complete: () => void): void {
    const checks: { store: "payments" | "claims"; expected: Election }[] = [];
    if (record.payment) checks.push({ store: "payments", expected: this.#paymentElection(record) });
    if (record.claim) checks.push({ store: "claims", expected: this.#claimElection(record,
      record.stage === "claim-ready" ? "prepared" : record.stage === "accepted" ? "accepted" : "submission-unknown") });
    let remaining = checks.length;
    if (remaining === 0) { complete(); return; }
    for (const { store, expected } of checks) {
      const request = tx.objectStore(store).get(expected.id);
      request.onsuccess = () => { try {
        require(canonicalize(election(request.result)) === canonicalize(expected));
        remaining -= 1; if (remaining === 0) complete();
      } catch { tx.abort(); } };
    }
  }
  async get(network: unknown, sessionId: string): Promise<ReverseJournalRecord | undefined> {
    const id = idFor(network, sessionId);
    return new Promise((resolve, reject) => {
      const tx = this.database.transaction([...STORES]), request = tx.objectStore("sessions").get(id); let result: ReverseJournalRecord | undefined;
      request.onsuccess = () => { try {
        if (request.result === undefined) return;
        result = recordSnapshot(request.result); require(result.id === id);
        this.#checkElections(tx, result, () => {});
      } catch { tx.abort(); } };
      tx.oncomplete = () => resolve(result); tx.onabort = tx.onerror = () => reject(new ReverseJournalRefusedError());
    });
  }
  async #write(expected: ReverseJournalRecord | null, next: ReverseJournalRecord,
    unique?: { store: "payments" | "claims"; entry: Election; previous: Election["state"] | null }): Promise<ReverseJournalRecord> {
    await new Promise<void>((resolve, reject) => {
      let tx: IDBTransaction;
      try { tx = this.database.transaction([...STORES], "readwrite", { durability: "strict" });
        require(tx.durability === "strict"); } catch { reject(new ReverseJournalRefusedError()); return; }
      tx.oncomplete = () => resolve(); tx.onabort = tx.onerror = () => reject(new ReverseJournalRefusedError());
      const sessions = tx.objectStore("sessions"), request = sessions.get(next.id);
      request.onsuccess = () => {
        try {
          if (expected === null) require(request.result === undefined);
          else require(request.result !== undefined && recordSnapshot(request.result).digest === expected.digest);
          const save = (): void => { if (expected === null) sessions.add(next); else sessions.put(next); };
          const mutate = (): void => {
            if (!unique) { save(); return; }
            const store = tx.objectStore(unique.store), check = store.get(unique.entry.id);
            check.onsuccess = () => { try {
              if (unique.previous === null) require(check.result === undefined);
              else { const existing = election(check.result); require(existing.id === unique.entry.id && existing.owner === next.id &&
                existing.digest === unique.entry.digest && existing.state === unique.previous); }
              if (unique.previous === null) store.add(unique.entry); else store.put(unique.entry);
              save();
            } catch { tx.abort(); } };
          };
          if (expected) this.#checkElections(tx, recordSnapshot(request.result), mutate);
          else mutate();
        } catch { tx.abort(); }
      };
    });
    const loaded = await this.get(next.context.networkIdentity, next.context.sessionId);
    require(loaded !== undefined && loaded.digest === next.digest); return loaded!;
  }
  /** Only fresh locally generated sessions, never an import or restoration fallback. */
  async createFresh(context: ReverseIntentContext, ciphertext: Uint8Array): Promise<ReverseJournalRecord> {
    const c = contextSnapshot(context), next = seal({ id: idFor(c.networkIdentity, c.sessionId), context: c, stage: "secrets-ready",
      snapshots: [snapshot("secrets-ready", ciphertext)], payment: null, claim: null });
    return this.#write(null, next);
  }
  async saveTerms(expected: ReverseJournalRecord, ciphertext: Uint8Array): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "secrets-ready");
    return this.#write(old, seal({ ...old, stage: "terms-ready", snapshots: [...old.snapshots, snapshot("terms-ready", ciphertext)] }));
  }
  async beginPayment(expected: ReverseJournalRecord, endpoint: string, plan: BoundedHoldPlan, ciphertext: Uint8Array): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "terms-ready");
    const payment = structuredClone({ state: "submission-unknown" as const, endpoint, plan });
    const next = seal({ ...old, stage: "payment-unknown", payment, snapshots: [...old.snapshots, snapshot("payment-unknown", ciphertext)] });
    return this.#write(old, next, { store: "payments", previous: null, entry: this.#paymentElection(next) });
  }
  #paymentElection(record: ReverseJournalRecord): Election {
    require(record.payment !== null);
    const payment = record.payment!;
    return { id: digest({ network: record.context.networkIdentity, payer: payment.plan.nodeIdentity, paymentHash: record.context.request.payment_hash }),
      owner: record.id, digest: digest(payment), state: "submission-unknown" };
  }
  async saveFunding(expected: ReverseJournalRecord, ciphertext: Uint8Array): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "payment-unknown");
    return this.#write(old, seal({ ...old, stage: "funded", snapshots: [...old.snapshots, snapshot("funded", ciphertext)] }));
  }
  #claimElection(record: ReverseJournalRecord, state: Election["state"]): Election {
    require(record.claim !== null); const claim = record.claim!;
    return { id: digest({ network: record.context.networkIdentity, fundingTxid: claim.fundingTxid, fundingVout: claim.fundingVout }),
      owner: record.id, digest: digest(claim), state };
  }
  async prepareClaim(expected: ReverseJournalRecord, claim: ReverseClaimIntent, ciphertext: Uint8Array): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "funded");
    const next = seal({ ...old, stage: "claim-ready", claim: structuredClone(claim), snapshots: [...old.snapshots, snapshot("claim-ready", ciphertext)] });
    return this.#write(old, next, { store: "claims", previous: null, entry: this.#claimElection(next, "prepared") });
  }
  async beginClaimExposure(expected: ReverseJournalRecord): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "claim-ready");
    return this.#write(old, seal({ ...old, stage: "claim-unknown" }), { store: "claims", previous: "prepared", entry: this.#claimElection(old, "submission-unknown") });
  }
  async markAccepted(expected: ReverseJournalRecord, txid: string): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "claim-unknown" && txid === old.claim?.txid);
    return this.#write(old, seal({ ...old, stage: "accepted" }), { store: "claims", previous: "submission-unknown", entry: this.#claimElection(old, "accepted") });
  }
  /** Gives no POST permission. The caller must privately reauthenticate before plaintext export. */
  async reexportIdentical(expected: ReverseJournalRecord): Promise<ReverseJournalRecord> {
    const old = recordSnapshot(expected); require(old.stage === "claim-unknown" || old.stage === "accepted");
    const loaded = await this.get(old.context.networkIdentity, old.context.sessionId); require(loaded?.digest === old.digest); return loaded!;
  }
}
