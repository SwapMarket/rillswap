import { invoiceBinding } from "./bolt11";
import { parseTerms, type NativeLightningTerms } from "./contract";
import { evaluateNative, type NativePolicy } from "./policy";

export interface IntentView {
  readonly version: "checkout-view/1";
  readonly id: string;
  readonly status: "waiting" | "paid" | "reconciliation";
  readonly attempt: { readonly terms: NativeLightningTerms; readonly invoice: string } | null;
}
export interface CheckoutCheckpoint {
  readonly version: "checkout-checkpoint/1";
  readonly attemptId: string;
  readonly intentId: string;
  readonly invoice: string;
  readonly terms: NativeLightningTerms;
  readonly stage: "dispatched" | "ambiguous" | "observing";
  /** Public routing references only; absent metadata never authorizes another dispatch. */
  readonly route?: {
    readonly adapter: "rillswap-btc-ln/1";
    readonly providerId: string;
    readonly recoveryRef?: string;
    readonly swapId?: string;
    readonly fundingTxid?: string;
  };
}
/** begin must atomically reserve one dispatch per attempt, including across tabs. */
export interface CheckoutStore<Checkpoint extends { readonly attemptId: string } = CheckoutCheckpoint> {
  load(attemptId: string): Promise<Checkpoint | null>;
  begin(record: Checkpoint): Promise<boolean>;
  update(record: Checkpoint): Promise<void>;
}
export interface LightningWallet {
  readonly canLimitFees: true;
  payInvoice(invoice: string, maxFeeMsat: string): Promise<void>;
}
export type CheckoutProgress = { readonly state: "ready" | "observing" | "action_required" | "merchant_paid" | "reconciliation"; readonly attemptId: string | null };
export interface CheckoutOptions {
  readonly intentUrl: string;
  readonly statusToken: string;
  readonly policy: NativePolicy;
  readonly wallet: LightningWallet;
  readonly recoveryStore: CheckoutStore;
  /** Trusted transport: authenticate the pinned HTTPS origin and honor request
   * policy. Server adapters also own DNS/egress controls. Response URL checks
   * cannot authenticate a privileged injected implementation.
   */
  readonly fetch?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  /** Header/body/decode budget, not wallet payment or settlement lifetime. */
  readonly merchantReadTimeoutMs?: number;
  readonly now?: () => number;
}

/** A small native checkout client. Wallet results are hints; only pinned merchant reads report paid. */
export function createCheckout(options: CheckoutOptions) {
  const endpoint = new URL(options.intentUrl);
  if (endpoint.protocol !== "https:" || endpoint.origin !== options.policy.merchantOrigin || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      !/^\/v1\/intents\/[A-Za-z0-9_-]{16,128}$/.test(endpoint.pathname) || !/^[A-Za-z0-9_-]{32,128}$/.test(options.statusToken)) throw new Error("Untrusted intent URL or token");
  const intentId = endpoint.pathname.split("/").at(-1)!;
  const suppliedFetch = options.fetch, suppliedReadBudget = options.merchantReadTimeoutMs;
  if (suppliedFetch !== undefined && typeof suppliedFetch !== "function") throw new Error("Invalid merchant transport");
  const intentHref = endpoint.href, injectedTransport = suppliedFetch !== undefined;
  const request = suppliedFetch ?? fetch;
  const merchantReadTimeoutMs = suppliedReadBudget === undefined ? 10_000 : suppliedReadBudget;
  if (!Number.isSafeInteger(merchantReadTimeoutMs) || merchantReadTimeoutMs < 1 || merchantReadTimeoutMs > 30_000) throw new Error("Invalid merchant read budget");
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const listeners = new Set<(progress: CheckoutProgress) => void>();
  let current: IntentView | null = null;
  let paying = false;
  const emit = (state: CheckoutProgress["state"]): void => {
    const progress = Object.freeze({ state, attemptId: current?.attempt?.terms.attemptId ?? null });
    for (const listener of listeners) listener(progress);
  };
  const validateInvoice = (terms: NativeLightningTerms, invoice: string): void => {
    const binding = invoiceBinding(invoice, terms.network);
    if (binding.payment_hash !== terms.paymentHash || binding.amount_msat !== terms.amountMsat || binding.payee_compressed_pubkey !== terms.receiver ||
        binding.expires_at < terms.expiresAt || binding.created_at > now()) throw new Error("Invoice differs from merchant terms");
  };
  const load = async (): Promise<IntentView> => {
    const controller = new AbortController(), started = performance.now();
    let terminal = false, succeeded = false, timer: ReturnType<typeof setTimeout> | undefined;
    let body: ReadableStream<Uint8Array> | null = null, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const stop = () => {
      try { controller.abort(); } catch {}
      try { const canceled = reader ? reader.cancel() : body?.cancel(); void canceled?.catch(() => {}); } catch {}
    };
    const checkBudget = () => {
      if (terminal || performance.now() - started >= merchantReadTimeoutMs) { terminal = true; throw new Error("Merchant status unavailable"); }
    };
    const acquire = async (): Promise<IntentView> => {
      const response = await request(new URL(intentHref), { headers: { Authorization: `Bearer ${options.statusToken}`, Accept: "application/json" },
        redirect: "error", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer", signal: controller.signal });
      body = response.body;
      if (terminal) { stop(); throw new Error("Merchant status unavailable"); }
      checkBudget();
      if (response.status !== 200 || response.redirected || (response.url ? response.url !== intentHref : !injectedTransport) ||
          response.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json" || !body) throw new Error("Merchant status unavailable");
      reader = body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      while (true) {
        const next = await reader.read(); checkBudget(); if (next.done) break;
        if (!(next.value instanceof Uint8Array) || (size += next.value.byteLength) > 8192) throw new Error("Merchant status unavailable");
        if (next.value.byteLength === 0) continue;
        chunks.push(new Uint8Array(next.value));
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as IntentView;
      checkBudget(); return raw;
    };
    let raw: IntentView;
    try {
      const deadline = new Promise<never>((_, reject) => { timer = setTimeout(() => { terminal = true; reject(new Error("Merchant status unavailable")); stop(); }, merchantReadTimeoutMs); });
      raw = await Promise.race([acquire(), deadline]); checkBudget(); succeeded = true;
    } catch { throw new Error("Merchant status unavailable"); }
    finally {
      terminal = true; clearTimeout(timer); if (!succeeded) stop();
      try { reader?.releaseLock(); } catch {}
    }
    if (raw.version !== "checkout-view/1" || raw.id !== intentId || !["waiting", "paid", "reconciliation"].includes(raw.status)) throw new Error("Invalid merchant view");
    let attempt: IntentView["attempt"] = null;
    if (raw.attempt) {
      const terms = parseTerms(raw.attempt.terms);
      if (terms.intentId !== intentId || terms.merchantOrigin !== options.policy.merchantOrigin || terms.receiver !== options.policy.receiver || terms.network !== options.policy.network) throw new Error("Merchant view binding mismatch");
      validateInvoice(terms, raw.attempt.invoice);
      attempt = Object.freeze({ terms, invoice: raw.attempt.invoice });
    }
    current = Object.freeze({ version: "checkout-view/1", id: intentId, status: raw.status, attempt });
    return current;
  };
  const verifyCheckpoint = (record: CheckoutCheckpoint, view: NonNullable<IntentView["attempt"]>): void => {
    if (record.version !== "checkout-checkpoint/1" || record.attemptId !== view.terms.attemptId || record.intentId !== intentId || record.invoice !== view.invoice ||
        JSON.stringify(parseTerms(record.terms)) !== JSON.stringify(view.terms) || !["dispatched", "ambiguous", "observing"].includes(record.stage)) throw new Error("Recovery checkpoint conflicts with merchant terms");
  };
  return {
    on(event: "progress", listener: (progress: CheckoutProgress) => void): () => void {
      if (event !== "progress") throw new Error("Unknown checkout event"); listeners.add(listener); return () => listeners.delete(listener);
    },
    async open(): Promise<IntentView> {
      const view = await load();
      if (view.status === "paid") emit("merchant_paid");
      else if (view.status === "reconciliation") emit("reconciliation");
      else if (!view.attempt) emit("action_required");
      else {
        const record = await options.recoveryStore.load(view.attempt.terms.attemptId);
        if (record) { verifyCheckpoint(record, view.attempt); emit(record.stage === "ambiguous" ? "action_required" : "observing"); }
        else emit(evaluateNative(view.attempt.terms, options.policy, now()).eligible ? "ready" : "action_required");
      }
      return view;
    },
    async pay(): Promise<void> {
      if (paying) throw new Error("Payment already in progress"); paying = true;
      try {
        const view = await load();
        if (view.status !== "waiting" || !view.attempt) throw new Error("Order is not payable");
        const { terms, invoice } = view.attempt;
        const result = evaluateNative(terms, options.policy, now());
        if (!result.eligible || options.wallet.canLimitFees !== true) throw new Error(`Payment unavailable: ${result.reason}`);
        const record: CheckoutCheckpoint = { version: "checkout-checkpoint/1", attemptId: terms.attemptId, intentId, invoice, terms, stage: "dispatched" };
        if (!await options.recoveryStore.begin(record)) throw new Error("Attempt already dispatched; monitor it rather than paying again");
        // Recheck after durable checkpoint publication and immediately before wallet authorization.
        const final = evaluateNative(terms, options.policy, now());
        if (!final.eligible) { await options.recoveryStore.update({ ...record, stage: "ambiguous" }); emit("action_required"); throw new Error(`Payment unavailable: ${final.reason}`); }
        const absolute = BigInt(options.policy.maxBuyerExtraMsat);
        const relative = BigInt(terms.amountMsat) * BigInt(options.policy.maxBuyerExtraBps) / 10000n;
        try {
          await options.wallet.payInvoice(invoice, (absolute < relative ? absolute : relative).toString());
          await options.recoveryStore.update({ ...record, stage: "observing" }); emit("observing");
        } catch (error) {
          await options.recoveryStore.update({ ...record, stage: "ambiguous" }); emit("action_required"); throw error;
        }
      } finally { paying = false; }
    },
  };
}

/** IndexedDB uniqueness is the cross-tab dispatch guard; no erased-store recovery guarantee. */
export function indexedDbCheckoutStore<Checkpoint extends { readonly attemptId: string } = CheckoutCheckpoint>(databaseName: string): CheckoutStore<Checkpoint> {
  const open = (): Promise<IDBDatabase> => new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("attempts", { keyPath: "attemptId" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const write = async (record: Checkpoint, first: boolean): Promise<boolean> => {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("attempts", "readwrite");
      const store = tx.objectStore("attempts");
      const request = first ? store.add(record) : store.put(record);
      let duplicate = false;
      request.onerror = (event) => { if (first && request.error?.name === "ConstraintError") { duplicate = true; event.preventDefault(); event.stopPropagation(); } };
      tx.oncomplete = () => { db.close(); resolve(!duplicate); };
      tx.onabort = tx.onerror = () => { const error = tx.error; db.close(); reject(error ?? new Error("Recovery write failed")); };
    });
  };
  return {
    async load(attemptId) {
      const db = await open();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("attempts", "readonly"); const request = tx.objectStore("attempts").get(attemptId);
        tx.oncomplete = () => { db.close(); resolve(request.result ?? null); };
        tx.onabort = tx.onerror = () => { const error = tx.error; db.close(); reject(error); };
      });
    },
    begin: (record) => write(record, true),
    async update(record) { await write(record, false); },
  };
}
