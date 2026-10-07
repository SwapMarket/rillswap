// Demo storefront for the regtest dev stack (see DEVELOPMENT.md). Not a
// production integration: prices use a fixed demo rate and orders live in a
// JSON file. The backend owns the merchant admin tokens and is the only thing
// that talks to the merchant services; the browser only talks to this server.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { SignedAcceptance } from "../../src/server";
import { DEMO_USD_PER_BTC, findAcceptance, priceSat } from "./checkout";
import { STABLECOINS, startStablecoins, tokenBaseUnits, type NativeCheckout, type StablecoinRail, type TokenRail } from "./native";

const STATE = process.env.RILL_DEV_STATE ?? "/state";
const MERCHANT_API = process.env.RILL_DEV_MERCHANT_API ?? "http://127.0.0.1:8787";
const ANVIL_RPC = process.env.RILL_DEV_ANVIL_RPC ?? "http://127.0.0.1:8545";
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
type Rail = LightningRail | StablecoinRail;

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

const RAILS: Record<Rail, { label: string; available: boolean }> = {
  lightning: { label: "Lightning (BTC)", available: true },
  "btc-swap": { label: "Bitcoin on-chain (via a RillSwap maker)", available: true },
  ...Object.fromEntries(STABLECOINS.map((spec) => [spec.rail, { label: `${spec.symbol} on Anvil (fake stablecoin)`, available: tokens.has(spec.rail) }])),
} as Record<Rail, { label: string; available: boolean }>;

const orders: Map<string, Order> = new Map(loadOrders().map((order) => [order.id, order]));

function loadOrders(): Order[] {
  try {
    // Orders from before the stablecoin rails had no label, native or detail.
    return (JSON.parse(readFileSync(ORDERS_FILE, "utf8")) as (Order & { acceptance: { paymentHash?: string } | null })[]).map((order) => ({
      ...order,
      amountLabel: order.amountLabel ?? `${order.amountSat?.toLocaleString("en-US")} sat`,
      native: order.native ?? null,
      acceptance: order.acceptance && { ...order.acceptance, detail: order.acceptance.detail ?? `payment hash ${order.acceptance.paymentHash}` },
    }));
  } catch {
    return [];
  }
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
  const base = { id, productId, productName: product.name, rail, usdCents: product.usdCents, createdAt: Date.now(), acceptance: null };
  let order: Order;
  const token = tokens.get(rail as StablecoinRail);
  if (token) {
    const amount = tokenBaseUnits(product.usdCents);
    const native = await token.create(id, amount, expiresAt);
    order = { ...base, amountSat: null, amountLabel: `${(product.usdCents / 100).toFixed(2)} ${token.symbol}`,
      intentId: native.intentId, invoice: null, native, status: "waiting" };
  } else if (rail === "lightning" || rail === "btc-swap") {
    const amountSat = priceSat(product.usdCents);
    const intent = await merchant("/v1/intents", {
      method: "POST",
      idempotencyKey: `${id}-intent`,
      body: { orderRef: id, amountMsat: String(amountSat * 1000), expiresAt },
    });
    const attempt = await merchant(`/v1/intents/${intent.json.id}/attempts`, { method: "POST", idempotencyKey: `${id}-attempt`, body: {} });
    order = { ...base, amountSat, amountLabel: `${amountSat.toLocaleString("en-US")} sat`, intentId: intent.json.id,
      invoice: attempt.json.attempt?.invoice ?? null, native: null, status: attempt.json.status };
  } else {
    throw new Error("payment method unavailable");
  }
  orders.set(id, order);
  saveOrders();
  return order;
}

async function refresh(order: Order): Promise<Order> {
  if (order.acceptance) return order;
  const token = order.native && tokens.get(order.rail as StablecoinRail);
  if (order.native && token) {
    const { view, verified } = await token.view(order.native);
    order.status = view.status === "awaiting_funds" ? "waiting" : view.status === "sandbox_receipt_recorded" ? "paid" : "reconciliation";
    if (verified && view.event) {
      order.acceptance = { eventId: view.event.event.id, acceptedAt: view.event.event.recordedAt, publicKey: token.publicKey,
        detail: `tx ${view.event.event.receipt.transactionHash} (${view.event.event.receipt.timing}, local sandbox confirmations)` };
    }
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
      if (url.pathname === "/api/catalog") {
        return json({
          products: PRODUCTS.map((product) => ({ ...product, sat: priceSat(product.usdCents) })),
          rails: RAILS,
          tokens: Object.fromEntries([...tokens.values()].map((token) => [token.rail, { symbol: token.symbol, address: token.token }])),
          demoUsdPerBtc: DEMO_USD_PER_BTC,
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
