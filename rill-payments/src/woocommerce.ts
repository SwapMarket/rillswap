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

export function createWooCommerceOrderSource(options: WooCommerceOrderSourceOptions): WooCommerceOrderSource {
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
  return Object.freeze({
    storeOrigin,
    async readPayableOrder(orderId: string, orderKey: string): Promise<WooCommerceOrderPrice> {
      if (typeof orderId !== "string" || !WOOCOMMERCE_ORDER_ID.test(orderId) || !Number.isSafeInteger(Number(orderId)) || typeof orderKey !== "string" || !ORDER_KEY.test(orderKey)) return refuse("not_found");
      const url = `${storeOrigin}/wp-json/wc/v3/orders/${orderId}`;
      const controller = new AbortController();
      const order = await readOrder(() => request(url, { method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store",
        headers: { Accept: "application/json", Authorization: authorization }, signal: controller.signal }), url, injected, timeoutMs, controller);
      if (!order || typeof order !== "object" || Array.isArray(order)) return refuse("unavailable");
      const value = order as Record<string, unknown>;
      if (value.id !== Number(orderId) || typeof value.order_key !== "string") return refuse("unavailable");
      if (!same(value.order_key, orderKey)) return refuse("not_found");
      if (value.status !== "pending" || value.currency !== "BTC" || typeof value.total !== "string") return refuse("not_payable");
      let amountMsat: string;
      try { amountMsat = btcTotalToMsat(value.total); } catch { return refuse("not_payable"); }
      return Object.freeze({ orderRef: `woocommerce:${storeTag}:${orderId}`, amountMsat });
    },
  });
}
