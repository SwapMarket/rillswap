// Monero rail for the demo shop on the dev stack's private regtest chain, using
// the rill-payments Monero regtest receipt rail. The merchant wallet lives in
// its own monero-wallet-rpc; the service is mounted on a loopback port because
// it only accepts a numeric loopback transport besides the exact merchant origin.
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MONERO_ANCHOR_HEIGHT, MoneroReceiptLedger, type MoneroLedgerConfig } from "../../src/moneroLedger";
import { createMoneroRpc } from "../../src/moneroRpc";
import { createMoneroRegtestService } from "../../src/moneroServer";
import { verifyMoneroRegtestReceipt, type MoneroRegtestTerms, type MoneroRegtestView } from "../../src/moneroContract";

/** Demo rate: 1 XMR = 200 USD. */
export const DEMO_USD_PER_XMR = 200;
const PICONERO_PER_XMR = 10n ** 12n;
const PORT = 8793;
const TICK_MS = 3000;

/** Price in piconero for a USD price at the demo rate. */
export const xmrAtomic = (usdCents: number): string => ((BigInt(usdCents) * PICONERO_PER_XMR) / BigInt(DEMO_USD_PER_XMR * 100)).toString();
/** Piconero as a decimal XMR string without trailing zeros. */
export const formatXmr = (atomic: string): string => {
  const value = BigInt(atomic), fraction = (value % PICONERO_PER_XMR).toString().padStart(12, "0").replace(/0+$/, "");
  return `${value / PICONERO_PER_XMR}${fraction ? `.${fraction}` : ""}`;
};

/** What the shop keeps per order; the read capability is the order's credential. */
export interface MoneroCheckout {
  readonly transportOrigin: string;
  readonly intentId: string;
  readonly readCapability: string;
  readonly terms: MoneroRegtestTerms;
}
export interface MoneroRail {
  readonly publicKey: string;
  readonly primaryAddress: string;
  create(orderRef: string, amountAtomic: string, expiresAt: number): Promise<MoneroCheckout>;
  /** The service's view, and whether its signed receipt event verifies. */
  view(checkout: MoneroCheckout): Promise<{ view: MoneroRegtestView; verified: boolean }>;
}

const KEYS = ["admin.token", "capability.key", "event.key"] as const;

function privateFile(path: string, create: () => string | Uint8Array): Buffer {
  if (!existsSync(path)) writeFileSync(path, create(), { mode: 0o600, flag: "wx" });
  return readFileSync(path);
}

/**
 * State in `<state>/shop/monero/`: keys, config.json (written once, pinning
 * the wallet primary address and the chain's block-1 hash) and ledger.sqlite.
 * Only an empty directory, with order history readable and free of Monero
 * orders, is initialized.
 * Partial state, a different wallet or a reset chain disable the rail; nothing
 * is replaced.
 */
export async function startMonero(state: string, options: {
  walletUrl: string; daemonUrl: string; origin: string;
  /** Monero orders in the shop's history; "unknown" if it could not be read. */
  priorOrders: "none" | "some" | "unknown";
}): Promise<MoneroRail> {
  const home = `${state}/shop/monero`, configPath = `${home}/config.json`, ledgerPath = `${home}/ledger.sqlite`;
  mkdirSync(home, { recursive: true, mode: 0o700 }); chmodSync(home, 0o700);
  // Any file at all (even an unknown or SQLite sidecar one) means not fresh.
  const fresh = readdirSync(home).length === 0;
  const missing = [configPath, ledgerPath, ...KEYS.map((name) => `${home}/${name}`)].filter((path) => !existsSync(path));
  if (fresh && options.priorOrders !== "none") throw new Error(`${home} is empty but Monero orders exist or the order history is unreadable; reset the stack (dev/devctl reset)`);
  if (!fresh && missing.length) throw new Error(`${home} is incomplete (missing ${missing.map((path) => path.slice(home.length + 1)).join(", ")}); reset the stack (dev/devctl reset)`);
  const rpc = createMoneroRpc({ walletUrl: options.walletUrl, daemonUrl: options.daemonUrl, walletFile: "merchant" });
  // Read the wallet and chain before writing anything, so an unreachable
  // wallet-rpc on first start leaves the directory empty (retried next start).
  const snapshot = fresh ? await rpc.snapshot(MONERO_ANCHOR_HEIGHT) : null;
  if (snapshot && snapshot.nettype !== "fakechain") throw new Error(`monerod reports ${snapshot.nettype}, not a regtest chain`);
  const adminToken = privateFile(`${home}/admin.token`, () => randomBytes(32).toString("base64url")).toString().trim();
  const capabilityKey = new Uint8Array(privateFile(`${home}/capability.key`, () => randomBytes(32)));
  const eventKey = new Uint8Array(privateFile(`${home}/event.key`, () => randomBytes(32)));
  if (snapshot) {
    const config: MoneroLedgerConfig = { origin: options.origin, primaryAddress: snapshot.primaryAddress,
      network: { version: "monero-regtest/1", namespace: randomBytes(12).toString("hex"), confirmations: 10, anchorHash: snapshot.anchorHash } };
    writeFileSync(configPath, JSON.stringify(config, null, 1) + "\n", { mode: 0o600, flag: "wx" });
    MoneroReceiptLedger.provision(ledgerPath, config).close();
  }
  const ledger = MoneroReceiptLedger.open(ledgerPath, JSON.parse(readFileSync(configPath, "utf8")) as MoneroLedgerConfig);
  const transportOrigin = `http://127.0.0.1:${PORT}`, publicKey = bytesToHex(ed25519.getPublicKey(eventKey));
  const service = createMoneroRegtestService({ ledger, rpc, adminToken, capabilityKey, eventSigningKey: eventKey, transportOrigin });
  await service.tick(); // refuses (disabling the rail) on a different wallet or chain
  Bun.serve({ hostname: "127.0.0.1", port: PORT, fetch: (request) => service.fetch(request) });
  let lastError = "";
  setInterval(() => {
    service.tick().then(() => { if (lastError) console.log("Monero observation recovered"); lastError = ""; }, (error: Error) => {
      if (error.message !== lastError) console.error(`Monero observation skipped: ${error.message}`);
      lastError = error.message;
    });
  }, TICK_MS);
  const call = async (path: string, bearer: string, body?: unknown, idempotencyKey?: string) => {
    const headers: Record<string, string> = { Authorization: `Bearer ${bearer}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
    const response = await fetch(transportOrigin + path, { method: body === undefined ? "GET" : "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) throw new Error(`Monero service ${path}: HTTP ${response.status}`);
    return (await response.json()) as Record<string, any>;
  };
  console.log(`Monero rail ready: wallet ${ledger.config.primaryAddress.slice(0, 12)}..., service ${transportOrigin}`);
  return {
    publicKey, primaryAddress: ledger.config.primaryAddress,
    async create(orderRef, amountAtomic, expiresAt) {
      const created = await call("/v1/monero-regtest/intents", adminToken, { orderRef, amountAtomic, expiresAt }, `${orderRef}-monero-intent`);
      const terms = created.view.terms as MoneroRegtestTerms;
      return { transportOrigin, intentId: terms.intentId, readCapability: created.readCapability, terms };
    },
    async view(checkout) {
      const view = (await call(`/v1/monero-regtest/intents/${checkout.intentId}`, checkout.readCapability)) as MoneroRegtestView;
      return { view, verified: view.event !== null && verifyMoneroRegtestReceipt(view.event, publicKey, checkout.terms) };
    },
  };
}
