import { createHash, timingSafeEqual } from "node:crypto";
import { MAX_MSAT } from "./contract";

/** Price authority read from the merchant's WooCommerce store (REST API v3).
 * The order total comes from the store, never from the buyer. Only pending,
 * BTC-denominated orders whose order key matches are payable. The adapter grants
 * no fulfillment: it never writes to the store and never marks an order paid.
 */
export interface WooCommerceOrderPrice {
  readonly orderRef: string;
  readonly amountMsat: string;
}
export interface WooCommerceOrderSource {
  readonly storeOrigin: string;
  readPayableOrder(orderId: string, orderKey: string): Promise<WooCommerceOrderPrice>;
}
export interface WooCommerceOrderSourceOptions {
  /** HTTPS origin of the store, e.g. https://shop.example (no path). */
  readonly storeOrigin: string;
  /** REST API key with read access to orders. */
  readonly consumerKey: string;
  readonly consumerSecret: string;
  readonly fetch?: (input: string, init: RequestInit) => Promise<Response>;
  /** Total budget for one order read, 1 to 30000 ms (default 10000). */
  readonly timeoutMs?: number;
}
/** not_found also covers a wrong order key, so callers cannot probe order IDs. */
export type WooCommerceRefusal = "not_found" | "not_payable" | "unavailable";
export class WooCommerceOrderRefused extends Error {
  constructor(readonly reason: WooCommerceRefusal) { super("WooCommerce order refused"); }
}

export const WOOCOMMERCE_ORDER_ID = /^[1-9][0-9]{0,15}$/;
const ORDER_KEY = /^wc_order_[A-Za-z0-9]{1,64}$/;
const BTC_TOTAL = /^(0|[1-9][0-9]{0,7})(?:\.([0-9]{1,8}))?$/;
const MAX_BODY = 256 * 1024;
const refuse = (reason: WooCommerceRefusal): never => { throw new WooCommerceOrderRefused(reason); };
const same = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/** Exact BTC decimal (at most 8 places) to millisatoshis; zero is refused. */
export function btcTotalToMsat(total: string): string {
  const match = BTC_TOTAL.exec(total);
  if (!match) throw new Error("Invalid BTC total");
  const sats = BigInt(match[1]!) * 100_000_000n + BigInt((match[2] ?? "").padEnd(8, "0"));
  if (sats <= 0n || sats * 1000n > MAX_MSAT) throw new Error("Invalid BTC total");
  return (sats * 1000n).toString();
}

/** Every await races one hard deadline, so an uncooperative transport or body
 * stream cannot hold the request open, and late completion is discarded. */
async function readOrder(request: () => Promise<Response>, url: string, injected: boolean, timeoutMs: number, controller: AbortController): Promise<unknown> {
  let timer: ReturnType<typeof setTimeout> | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined, response: Response | undefined;
  let abandoned = false;
  const expires = performance.now() + timeoutMs;
  const checkDeadline = (): void => { if (performance.now() >= expires) refuse("unavailable"); };
  const cancelBody = (value: Response): void => { try { if (!value.bodyUsed) void value.body?.cancel().catch(() => {}); } catch {} };
  const deadline = new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new WooCommerceOrderRefused("unavailable")), timeoutMs); });
  const bounded = <T>(work: Promise<T>): Promise<T> => { work.catch(() => {}); return Promise.race([work, deadline]); };
  try {
    const delivery = Promise.resolve().then(request).then((value) => {
      if (abandoned && value instanceof Response) cancelBody(value);
      return value;
    });
    try { response = await bounded(delivery); } catch { return refuse("unavailable"); }
    checkDeadline();
    // Default fetch must report the exact URL; injected transports may omit it.
    if (!(response instanceof Response) || response.redirected || (response.url !== url && !(injected && response.url === ""))) return refuse("unavailable");
    if (response.status === 404) return refuse("not_found");
    if (response.status !== 200 || !response.body || response.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") return refuse("unavailable");
    reader = response.body.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) {
      let next: Awaited<ReturnType<typeof reader.read>>;
      try { next = await bounded(reader.read()); } catch { return refuse("unavailable"); }
      checkDeadline();
      if (next.done) break;
      size += next.value.length; if (size > MAX_BODY) return refuse("unavailable");
      chunks.push(next.value);
    }
    try {
      const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
      checkDeadline(); return value;
    }
    catch { return refuse("unavailable"); }
  } finally {
    abandoned = true;
    clearTimeout(timer); controller.abort();
    // Best-effort cancellation without awaiting a possibly hung adapter.
    try { if (reader) void reader.cancel().catch(() => {}); else if (response instanceof Response) cancelBody(response); } catch {}
  }
}

/** Validated store origin and credentials plus exact-URL order GET/PUT. */
function storeClient(options: WooCommerceOrderSourceOptions) {
  let origin: URL;
  try { origin = new URL(options.storeOrigin); } catch { throw new Error("Invalid WooCommerce store origin"); }
  if (origin.protocol !== "https:" || origin.origin !== options.storeOrigin) throw new Error("Invalid WooCommerce store origin");
  if (typeof options.consumerKey !== "string" || !/^ck_[A-Za-z0-9]{8,128}$/.test(options.consumerKey) ||
      typeof options.consumerSecret !== "string" || !/^cs_[A-Za-z0-9]{8,128}$/.test(options.consumerSecret)) throw new Error("Invalid WooCommerce credentials");
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) throw new Error("Invalid WooCommerce timeout");
  const injected = options.fetch !== undefined, request = options.fetch ?? fetch;
  const authorization = "Basic " + Buffer.from(options.consumerKey + ":" + options.consumerSecret, "utf8").toString("base64");
  const storeOrigin = options.storeOrigin;
  // Store-bound reference: another store's order with the same ID never maps here.
  const storeTag = createHash("sha256").update("woocommerce-store/1:" + storeOrigin).digest("hex").slice(0, 32);
  const exchange = async (orderId: string, method: "GET" | "PUT", body?: string): Promise<Record<string, unknown>> => {
    const url = `${storeOrigin}/wp-json/wc/v3/orders/${orderId}`;
    const controller = new AbortController();
    const headers: Record<string, string> = { Accept: "application/json", Authorization: authorization };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const order = await readOrder(() => request(url, { method, body, redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store",
      headers, signal: controller.signal }), url, injected, timeoutMs, controller);
    if (!order || typeof order !== "object" || Array.isArray(order)) return refuse("unavailable");
    const value = order as Record<string, unknown>;
    if (value.id !== Number(orderId)) return refuse("unavailable");
    return value;
  };
  return { storeOrigin, storeTag, exchange };
}
const validOrderId = (orderId: unknown): orderId is string => typeof orderId === "string" && WOOCOMMERCE_ORDER_ID.test(orderId) && Number.isSafeInteger(Number(orderId));

export function createWooCommerceOrderSource(options: WooCommerceOrderSourceOptions): WooCommerceOrderSource {
  const { storeOrigin, storeTag, exchange } = storeClient(options);
  return Object.freeze({
    storeOrigin,
    async readPayableOrder(orderId: string, orderKey: string): Promise<WooCommerceOrderPrice> {
      if (!validOrderId(orderId) || typeof orderKey !== "string" || !ORDER_KEY.test(orderKey)) return refuse("not_found");
      const value = await exchange(orderId, "GET");
      if (typeof value.order_key !== "string") return refuse("unavailable");
      if (!same(value.order_key, orderKey)) return refuse("not_found");
      if (value.status !== "pending" || value.currency !== "BTC" || typeof value.total !== "string") return refuse("not_payable");
      let amountMsat: string;
      try { amountMsat = btcTotalToMsat(value.total); } catch { return refuse("not_payable"); }
      return Object.freeze({ orderRef: `woocommerce:${storeTag}:${orderId}`, amountMsat });
    },
  });
}

/** Verified acceptance facts the fulfillment needs (see LightningAcceptanceConsumer.acceptedOrder). */
export interface AcceptedOrderSource {
  acceptedOrder(orderRef: string): Readonly<{ orderRef: string; amountMsat: string; paymentHash: string; eventId: string }> | null;
}
export interface WooCommerceFulfillmentOptions extends WooCommerceOrderSourceOptions {
  readonly acceptances: AcceptedOrderSource;
  /** Acceptances come from regtest/signet only; never point this at a production store. */
  readonly testStoreOnly: true;
}
export type WooCommerceFulfillmentResult = Readonly<
  | { outcome: "fulfilled"; orderRef: string; transactionId: string; wrote: boolean }
  | { outcome: "not_accepted"; orderRef: string }
  /** Store state differs from the verified acceptance; nothing was written by this call. */
  | { outcome: "reconciliation_required"; orderRef: string; reason: "missing" | "status" | "price" | "transaction" }
  /** The read-back after this call's write did not prove payment completion. */
  | { outcome: "write_unconfirmed"; orderRef: string }
  /** The store could not be read; nothing was written by this call. */
  | { outcome: "unavailable"; orderRef: string }
  /** A write was dispatched and may have committed or still be executing. Resolve before retrying. */
  | { outcome: "unknown"; orderRef: string }
>;
export interface WooCommerceFulfillment {
  readonly storeOrigin: string;
  fulfill(orderRef: string): Promise<WooCommerceFulfillmentResult>;
}

const PAID_AT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$/;
function exactBtcTotal(value: Record<string, unknown>, amountMsat: string): boolean {
  if (value.currency !== "BTC" || typeof value.total !== "string") return false;
  try { return btcTotalToMsat(value.total) === amountMsat; } catch { return false; }
}
function paidBy(value: Record<string, unknown>, amountMsat: string, transactionId: string): boolean {
  return (value.status === "processing" || value.status === "completed") && value.transaction_id === transactionId &&
    exactBtcTotal(value, amountMsat) && typeof value.date_paid_gmt === "string" && PAID_AT.test(value.date_paid_gmt) &&
    Number.isFinite(Date.parse(value.date_paid_gmt + "Z"));
}

/** Best-effort, caller-driven writeback of verified acceptances to a TEST store.
 * WooCommerce has no conditional update, so read-before-write cannot make the
 * checked status/price atomic with payment completion; read-back only detects
 * damage after store hooks ran. Writes only `set_paid` and `transaction_id`
 * (the payment hash), never `status`, and only for a pending, exact-price BTC
 * order without a transaction ID. Nothing is persisted locally: no startup,
 * tick or delivery callback calls this. After `unknown` or `write_unconfirmed`
 * the earlier write may still be executing: do not call again for that order
 * until an operator has resolved it.
 */
export function createWooCommerceFulfillment(options: WooCommerceFulfillmentOptions): WooCommerceFulfillment {
  if (!options || options.testStoreOnly !== true || typeof options.acceptances?.acceptedOrder !== "function") throw new Error("Invalid WooCommerce fulfillment options");
  const { storeOrigin, storeTag, exchange } = storeClient(options);
  const acceptedOrder = options.acceptances.acceptedOrder.bind(options.acceptances);
  const prefix = `woocommerce:${storeTag}:`;
  const inFlight = new Map<string, Promise<WooCommerceFulfillmentResult>>();

  async function run(orderRef: string, orderId: string): Promise<WooCommerceFulfillmentResult> {
    const accepted = acceptedOrder(orderRef);
    if (!accepted) return Object.freeze({ outcome: "not_accepted", orderRef });
    const amountMsat = accepted.amountMsat, transactionId = accepted.paymentHash;
    if (accepted.orderRef !== orderRef || typeof amountMsat !== "string" || typeof transactionId !== "string" || !/^[0-9a-f]{64}$/.test(transactionId)) throw new Error("Invalid accepted order");
    let current: Record<string, unknown>;
    try { current = await exchange(orderId, "GET"); }
    catch (error) {
      if (error instanceof WooCommerceOrderRefused && error.reason === "not_found") return Object.freeze({ outcome: "reconciliation_required", orderRef, reason: "missing" });
      return Object.freeze({ outcome: "unavailable", orderRef });
    }
    if (paidBy(current, amountMsat, transactionId)) return Object.freeze({ outcome: "fulfilled", orderRef, transactionId, wrote: false });
    if (current.status !== "pending") return Object.freeze({ outcome: "reconciliation_required", orderRef, reason: "status" });
    if (!exactBtcTotal(current, amountMsat)) return Object.freeze({ outcome: "reconciliation_required", orderRef, reason: "price" });
    if (current.transaction_id !== "") return Object.freeze({ outcome: "reconciliation_required", orderRef, reason: "transaction" });
    // From dispatch on, every failure is potentially committed.
    try { await exchange(orderId, "PUT", JSON.stringify({ set_paid: true, transaction_id: transactionId })); }
    catch { return Object.freeze({ outcome: "unknown", orderRef }); }
    let after: Record<string, unknown>;
    try { after = await exchange(orderId, "GET"); } catch { return Object.freeze({ outcome: "unknown", orderRef }); }
    return paidBy(after, amountMsat, transactionId)
      ? Object.freeze({ outcome: "fulfilled", orderRef, transactionId, wrote: true })
      : Object.freeze({ outcome: "write_unconfirmed", orderRef });
  }

  return Object.freeze({
    storeOrigin,
    fulfill(orderRef: string): Promise<WooCommerceFulfillmentResult> {
      if (typeof orderRef !== "string" || !orderRef.startsWith(prefix) || !validOrderId(orderRef.slice(prefix.length))) {
        return Promise.reject(new Error("Order reference does not belong to this store"));
      }
      // Concurrent calls for one order on this adapter instance share one attempt.
      // Other instances and processes are not serialized.
      const existing = inFlight.get(orderRef);
      if (existing) return existing;
      const attempt = run(orderRef, orderRef.slice(prefix.length)).finally(() => inFlight.delete(orderRef));
      inFlight.set(orderRef, attempt);
      return attempt;
    },
  });
}
