// Demo storefront for the regtest dev stack (see DEVELOPMENT.md). Not a
// production integration: prices use a fixed demo rate and orders live in a
// JSON file. The backend owns the merchant admin tokens and is the only thing
// that talks to the merchant services; the browser only talks to this server.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { SignedAcceptance } from "../../src/server";
import { DEMO_USD_PER_BTC, findAcceptance, priceSat, readOrderHistory } from "./checkout";
import { STABLECOINS, startStablecoins, tokenBaseUnits, type NativeCheckout, type StablecoinRail, type TokenRail } from "./native";
import { DEMO_USD_PER_XMR, formatXmr, startMonero, xmrAtomic, type MoneroCheckout, type MoneroRail } from "./monero";
import { demoPaymentMethods } from "./paymentOptions";

const STATE = process.env.RILL_DEV_STATE ?? "/state";
const MERCHANT_API = process.env.RILL_DEV_MERCHANT_API ?? "http://127.0.0.1:8787";
const ANVIL_RPC = process.env.RILL_DEV_ANVIL_RPC ?? "http://127.0.0.1:8545";
const MONERO_WALLET_RPC = process.env.RILL_DEV_MONERO_WALLET_RPC ?? "http://127.0.0.1:18082";
const MONEROD_RPC = process.env.RILL_DEV_MONEROD_RPC ?? "http://127.0.0.1:18081";
const PORT = Number(process.env.RILL_DEV_SHOP_LISTEN ?? 8090);
const SWAP_PAGE = `http://127.0.0.1:${process.env.RILL_DEV_WEB_PORT ?? 5273}/swap.html`;
const ORDERS_FILE = `${STATE}/shop/orders.json`;
const ORDER_SECONDS = 3600;
const ORIGIN = "https://shop.rillswap.test";

const PRODUCTS = [
  { id: "stickers", name: "Rill sticker pack", usdCents: 200 },
  { id: "tshirt", name: "RillSwap T-shirt", usdCents: 2_500 },
  { id: "node-kit", name: "Lightning node kit", usdCents: 12_000 },
] as const;

type LightningRail = "lightning" | "btc-swap";
type Rail = LightningRail | StablecoinRail | "monero";

interface Order {
  id: string;
  productId: string;
  productName: string;
  rail: Rail;
  usdCents: number;
  amountSat: number | null;
  amountLabel: string;
  createdAt: number;
  intentId: string;
  invoice: string | null;
  native: NativeCheckout | null;
  monero: MoneroCheckout | null;
  /** Latest unconfirmed observation, for display only. */
  progress: string | null;
  status: "waiting" | "paid" | "reconciliation";
  acceptance: { eventId: string; acceptedAt: number; publicKey: string; detail: string } | null;
}

const adminToken = readFileSync(`${STATE}/merchant/admin.token`, "utf8").trim();
// Pinned independently of anything the merchant API returns.
const acceptanceKey = bytesToHex(ed25519.getPublicKey(readFileSync(`${STATE}/merchant/event.key`)));
const tokenRails = await startStablecoins(STATE, ANVIL_RPC, ORIGIN).catch((error: Error): TokenRail[] => {
  console.error(`stablecoin rails unavailable (Anvil at ${ANVIL_RPC}): ${error.message}`);
  return [];
});
const tokens = new Map<StablecoinRail, TokenRail>(tokenRails.map((rail) => [rail.rail, rail]));
const history = loadOrders();
const orders: Map<string, Order> = new Map(history.orders.map((order) => [order.id, order]));
const monero = await startMonero(STATE, { walletUrl: MONERO_WALLET_RPC, daemonUrl: MONEROD_RPC, origin: ORIGIN,
  priorOrders: !history.known ? "unknown" : history.orders.some((order) => order.monero) ? "some" : "none" }).catch((error: Error): null => {
  console.error(`Monero rail unavailable (wallet-rpc ${MONERO_WALLET_RPC}): ${error.message}`);
  return null;
});

const RAILS: Record<Rail, { label: string; available: boolean }> = {
  lightning: { label: "Lightning (BTC)", available: true },
  "btc-swap": { label: "Bitcoin on-chain (via a RillSwap maker)", available: true },
  ...Object.fromEntries(STABLECOINS.map((spec) => [spec.rail, { label: `${spec.symbol} on Anvil (fake stablecoin)`, available: tokens.has(spec.rail) }])),
  monero: { label: "Monero (local regtest chain)", available: monero !== null },
} as Record<Rail, { label: string; available: boolean }>;

let checkoutBundle: ReturnType<typeof Bun.build> | undefined;

function loadOrders(): { orders: Order[]; known: boolean } {
  const history = readOrderHistory<Order & { acceptance: { paymentHash?: string } | null }>(ORDERS_FILE);
  // Older orders lack the label, native, monero, progress or detail fields.
  return { known: history.known, orders: history.orders.map((order) => ({
    ...order,
    amountLabel: order.amountLabel ?? `${order.amountSat?.toLocaleString("en-US")} sat`,
    native: order.native ?? null,
    monero: order.monero ?? null,
    progress: order.progress ?? null,
    acceptance: order.acceptance && { ...order.acceptance, detail: order.acceptance.detail ?? `payment hash ${order.acceptance.paymentHash}` },
  })) };
}

function saveOrders(): void {
  mkdirSync(`${STATE}/shop`, { recursive: true });
  writeFileSync(`${ORDERS_FILE}.tmp`, JSON.stringify([...orders.values()], null, 1));
  renameSync(`${ORDERS_FILE}.tmp`, ORDERS_FILE);
}

async function merchant(path: string, init: { method?: string; body?: unknown; idempotencyKey?: string } = {}) {
  const headers: Record<string, string> = { Authorization: `Bearer ${adminToken}` };
  if (init.body !== undefined) headers["Content-Type"] = "application/json";
  if (init.idempotencyKey) headers["Idempotency-Key"] = init.idempotencyKey;
  const response = await fetch(MERCHANT_API + path, {
    method: init.method ?? "GET",
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!response.ok) throw new Error(`merchant ${init.method ?? "GET"} ${path}: HTTP ${response.status}`);
  return { status: response.status, json: (await response.json()) as Record<string, any> };
}

async function createOrder(productId: string, rail: Rail): Promise<Order> {
  const product = PRODUCTS.find((item) => item.id === productId);
  if (!product) throw new Error("unknown product");
  const id = randomBytes(8).toString("hex");
  const expiresAt = Math.floor(Date.now() / 1000) + ORDER_SECONDS;
  const base = { id, productId, productName: product.name, rail, usdCents: product.usdCents, createdAt: Date.now(), acceptance: null,
    native: null, monero: null, progress: null };
  let order: Order;
  const token = tokens.get(rail as StablecoinRail);
  if (token) {
    const amount = tokenBaseUnits(product.usdCents);
    const native = await token.create(id, amount, expiresAt);
    order = { ...base, amountSat: null, amountLabel: `${(product.usdCents / 100).toFixed(2)} ${token.symbol}`,
      intentId: native.intentId, invoice: null, native, status: "waiting" };
  } else if (rail === "monero" && monero) {
    const checkout = await monero.create(id, xmrAtomic(product.usdCents), expiresAt);
    order = { ...base, amountSat: null, amountLabel: `${formatXmr(checkout.terms.amountAtomic)} XMR`,
      intentId: checkout.intentId, invoice: null, monero: checkout, status: "waiting" };
  } else if (rail === "lightning" || rail === "btc-swap") {
    const amountSat = priceSat(product.usdCents);
    const intent = await merchant("/v1/intents", {
      method: "POST",
      idempotencyKey: `${id}-intent`,
      body: { orderRef: id, amountMsat: String(amountSat * 1000), expiresAt },
    });
    const attempt = await merchant(`/v1/intents/${intent.json.id}/attempts`, { method: "POST", idempotencyKey: `${id}-attempt`, body: {} });
    order = { ...base, amountSat, amountLabel: `${amountSat.toLocaleString("en-US")} sat`, intentId: intent.json.id,
      invoice: attempt.json.attempt?.invoice ?? null, status: attempt.json.status };
  } else {
    throw new Error("payment method unavailable");
  }
  orders.set(id, order);
  saveOrders();
  return order;
}

async function refresh(order: Order): Promise<Order> {
  // Monero acceptances stay watched: a reorg can later impair their evidence.
  if (order.acceptance && !order.monero) return order;
  const token = order.native && tokens.get(order.rail as StablecoinRail);
  if (order.native && token) {
    const { view, verified } = await token.view(order.native);
    order.status = view.status === "awaiting_funds" ? "waiting" : view.status === "sandbox_receipt_recorded" ? "paid" : "reconciliation";
    if (verified && view.event) {
      order.acceptance = { eventId: view.event.event.id, acceptedAt: view.event.event.recordedAt, publicKey: token.publicKey,
        detail: `tx ${view.event.event.receipt.transactionHash} (${view.event.event.receipt.timing}, local sandbox confirmations)` };
    }
  } else if (order.monero && monero) {
    const { view, verified } = await monero.view(order.monero);
    order.status = view.status === "awaiting_funds" || view.status === "expired" ? "waiting" : view.status === "regtest_receipt_recorded" ? "paid" : "reconciliation";
    if (verified && view.event && !order.acceptance) {
      const receipts = view.event.event.receipts;
      order.acceptance = { eventId: view.event.event.id, acceptedAt: view.event.event.recordedAt, publicKey: monero.publicKey,
        detail: `${receipts.length} tx (${receipts.map((receipt) => receipt.txid.slice(0, 16)).join(", ")}...), ${view.terms.network.confirmations}+ local regtest confirmations` };
    }
    order.progress = view.status === "regtest_evidence_impaired" ? "evidence impaired: a paid transaction left the chain (reorg); acceptance kept"
      : view.reconciliation ? `reconciliation: ${view.reconciliation}` : order.acceptance ? null : view.status === "expired" ? "expired; on-time payments still confirm"
      : view.progress && view.progress.seenAtomic !== "0" ? `seen ${formatXmr(view.progress.seenAtomic)} XMR, ${formatXmr(view.progress.confirmedAtomic)} XMR with ${view.terms.network.confirmations} confirmations` : null;
  } else if (order.amountSat !== null) {
    const view = await merchant(`/v1/intents/${order.intentId}`);
    order.status = view.json.status;
    if (order.status === "paid") {
      const events = (await merchant(`/v1/intents/${order.intentId}/events`)).json as unknown as SignedAcceptance[];
      const accepted = findAcceptance(events, acceptanceKey, order.intentId, order.amountSat);
      if (accepted) {
        order.acceptance = { eventId: accepted.event.id, acceptedAt: accepted.event.acceptedAt, publicKey: acceptanceKey,
          detail: `payment hash ${accepted.event.paymentHash}` };
      }
    }
  }
  saveOrders();
  return order;
}

const json = (value: unknown, status = 200) => Response.json(value, { status });

Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,
  async fetch(request) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/" && request.method === "GET") {
        return new Response(Bun.file(new URL("./index.html", import.meta.url).pathname));
      }
      if (url.pathname === "/rillpay.js" && request.method === "GET") {
        checkoutBundle ??= Bun.build({ entrypoints: [new URL("../../src/rillPay.ts", import.meta.url).pathname], target: "browser", format: "esm" });
        const bundle = await checkoutBundle;
        if (!bundle.success) throw new Error("RillPay browser bundle could not be built");
        return new Response(bundle.outputs[0], { headers: { "Content-Type": "text/javascript", "Cache-Control": "no-cache" } });
      }
      if (url.pathname === "/api/catalog") {
        return json({
          products: PRODUCTS.map((product) => ({ ...product, sat: priceSat(product.usdCents), methods: demoPaymentMethods(product.usdCents,
            Object.fromEntries(Object.entries(RAILS).map(([id, rail]) => [id, rail.available]))) })),
          rails: RAILS,
          tokens: Object.fromEntries([...tokens.values()].map((token) => [token.rail, { symbol: token.symbol, address: token.token }])),
          demoUsdPerBtc: DEMO_USD_PER_BTC,
          demoUsdPerXmr: DEMO_USD_PER_XMR,
          swapPage: SWAP_PAGE,
          acceptanceKey,
        });
      }
      if (url.pathname === "/api/orders" && request.method === "POST") {
        const input = (await request.json()) as { productId?: string; rail?: string };
        if (typeof input.rail !== "string" || !RAILS[input.rail as Rail]?.available) return json({ error: "unknown payment method" }, 400);
        return json(await createOrder(String(input.productId), input.rail as Rail), 201);
      }
      if (url.pathname === "/api/orders" && request.method === "GET") {
        return json([...orders.values()].sort((a, b) => b.createdAt - a.createdAt));
      }
      const match = /^\/api\/orders\/([0-9a-f]{16})$/.exec(url.pathname);
      if (match && request.method === "GET") {
        const order = orders.get(match[1]!);
        return order ? json(await refresh(order)) : json({ error: "no such order" }, 404);
      }
      return json({ error: "not found" }, 404);
    } catch (error) {
      console.error(error);
      return json({ error: (error as Error).message }, 502);
    }
  },
});
console.log(`demo shop on :${PORT} (merchant API ${MERCHANT_API}, acceptance key ${acceptanceKey})`);
