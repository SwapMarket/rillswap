// Demo storefront for the regtest dev stack (see DEVELOPMENT.md). Not a
// production integration: prices use a fixed demo rate and orders live in a
// JSON file. The backend owns the merchant admin token and is the only thing
// that talks to the merchant API; the browser only talks to this server.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { SignedAcceptance } from "../../src/server";
import { DEMO_USD_PER_BTC, findAcceptance, priceSat } from "./checkout";

const STATE = process.env.RILL_DEV_STATE ?? "/state";
const MERCHANT_API = process.env.RILL_DEV_MERCHANT_API ?? "http://127.0.0.1:8787";
const PORT = Number(process.env.RILL_DEV_SHOP_LISTEN ?? 8090);
const SWAP_PAGE = `http://127.0.0.1:${process.env.RILL_DEV_WEB_PORT ?? 5273}/swap.html`;
const ORDERS_FILE = `${STATE}/shop/orders.json`;
const ORDER_SECONDS = 3600;

const PRODUCTS = [
  { id: "stickers", name: "Rill sticker pack", usdCents: 200 },
  { id: "tshirt", name: "RillSwap T-shirt", usdCents: 2_500 },
  { id: "node-kit", name: "Lightning node kit", usdCents: 12_000 },
] as const;

const RAILS = {
  lightning: { label: "Lightning (BTC)" },
  "btc-swap": { label: "Bitcoin on-chain (via a RillSwap maker)" },
} as const;
type Rail = keyof typeof RAILS;

interface Order {
  id: string;
  productId: string;
  productName: string;
  rail: Rail;
  usdCents: number;
  amountSat: number;
  createdAt: number;
  intentId: string;
  invoice: string | null;
  status: "waiting" | "paid" | "reconciliation";
  acceptance: { eventId: string; paymentHash: string; acceptedAt: number; publicKey: string } | null;
}

const adminToken = readFileSync(`${STATE}/merchant/admin.token`, "utf8").trim();
// Pinned independently of anything the merchant API returns.
const acceptanceKey = bytesToHex(ed25519.getPublicKey(readFileSync(`${STATE}/merchant/event.key`)));

const orders: Map<string, Order> = new Map(loadOrders().map((order) => [order.id, order]));

function loadOrders(): Order[] {
  try {
    return JSON.parse(readFileSync(ORDERS_FILE, "utf8")) as Order[];
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
  const amountSat = priceSat(product.usdCents);
  const intent = await merchant("/v1/intents", {
    method: "POST",
    idempotencyKey: `${id}-intent`,
    body: { orderRef: id, amountMsat: String(amountSat * 1000), expiresAt: Math.floor(Date.now() / 1000) + ORDER_SECONDS },
  });
  const attempt = await merchant(`/v1/intents/${intent.json.id}/attempts`, {
    method: "POST",
    idempotencyKey: `${id}-attempt`,
    body: {},
  });
  const order: Order = {
    id,
    productId,
    productName: product.name,
    rail,
    usdCents: product.usdCents,
    amountSat,
    createdAt: Date.now(),
    intentId: intent.json.id,
    invoice: attempt.json.attempt?.invoice ?? null,
    status: attempt.json.status,
    acceptance: null,
  };
  orders.set(id, order);
  saveOrders();
  return order;
}

async function refresh(order: Order): Promise<Order> {
  if (order.acceptance) return order;
  const view = await merchant(`/v1/intents/${order.intentId}`);
  order.status = view.json.status;
  if (order.status === "paid") {
    const events = (await merchant(`/v1/intents/${order.intentId}/events`)).json as unknown as SignedAcceptance[];
    const accepted = findAcceptance(events, acceptanceKey, order.intentId, order.amountSat);
    if (accepted) {
      order.acceptance = {
        eventId: accepted.event.id,
        paymentHash: accepted.event.paymentHash,
        acceptedAt: accepted.event.acceptedAt,
        publicKey: acceptanceKey,
      };
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
          products: PRODUCTS.map((product) => ({
            ...product,
            sat: priceSat(product.usdCents),
          })),
          rails: RAILS,
          demoUsdPerBtc: DEMO_USD_PER_BTC,
          swapPage: SWAP_PAGE,
          acceptanceKey,
        });
      }
      if (url.pathname === "/api/orders" && request.method === "POST") {
        const input = (await request.json()) as { productId?: string; rail?: string };
        if (typeof input.rail !== "string" || !(input.rail in RAILS)) return json({ error: "unknown payment method" }, 400);
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
