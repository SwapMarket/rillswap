import { createHmac, timingSafeEqual } from "node:crypto";
import { parseMoneroRegtestTerms, signMoneroRegtestReceipt, type MoneroRegtestTerms, type MoneroRegtestView } from "./moneroContract";
import type { MoneroReceiptLedger } from "./moneroLedger";
import type { MoneroRpc } from "./moneroRpc";

export interface MoneroRegtestServiceOptions {
  readonly ledger: MoneroReceiptLedger;
  readonly rpc: MoneroRpc;
  readonly adminToken: string;
  readonly capabilityKey: Uint8Array;
  readonly eventSigningKey: Uint8Array;
  /** Exact mounted origin. Only an explicitly configured numeric loopback HTTP override is allowed. */
  readonly transportOrigin?: string;
  readonly now?: () => number;
}
class HttpError extends Error { constructor(readonly status: number) { super("Monero regtest request refused"); } }
const equal = (first: string, second: string): boolean => {
  const a = Buffer.from(first), b = Buffer.from(second); return a.length === b.length && timingSafeEqual(a, b);
};
async function jsonBody(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json" || !request.body) throw new HttpError(400);
  const reader = request.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  while (true) { const item = await reader.read(); if (item.done) break; size += item.value.length;
    if (size > 8192) { await reader.cancel(); throw new HttpError(413); } chunks.push(item.value); }
  let parsed: unknown; try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new HttpError(400); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(400); return parsed as Record<string, unknown>;
}

/**
 * Local Monero regtest checkout service. Admin creates intents (one fresh
 * subaddress each); admin or the per-intent read capability reads the view.
 * Buyers never write: payment evidence comes only from `tick()`, which the
 * host calls periodically.
 */
export function createMoneroRegtestService(options: MoneroRegtestServiceOptions) {
  const { ledger, rpc } = options;
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(options.adminToken) || !(options.capabilityKey instanceof Uint8Array) || !(options.eventSigningKey instanceof Uint8Array) ||
      options.capabilityKey.length !== 32 || options.eventSigningKey.length !== 32) throw new Error("Persistent private keys required");
  const adminToken = options.adminToken, capabilityKey = Uint8Array.from(options.capabilityKey), signingKey = Uint8Array.from(options.eventSigningKey);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000)), transportOrigin = options.transportOrigin ?? ledger.config.origin;
  const transport = new URL(transportOrigin), network = ledger.config.network;
  if (transport.origin !== transportOrigin || transport.username || transport.password || (transportOrigin !== ledger.config.origin &&
      (transport.protocol !== "http:" || transport.hostname !== "127.0.0.1"))) throw new Error("Exact merchant HTTPS or explicit numeric loopback transport required");
  const capability = (intentId: string): string => createHmac("sha256", capabilityKey)
    .update(`monero-regtest-read/1:${ledger.config.origin}:${network.namespace}:${network.anchorHash}:${intentId}`).digest("base64url");
  const termsFor = (intentId: string): MoneroRegtestTerms => {
    const intent = ledger.getIntent(intentId);
    return parseMoneroRegtestTerms({ version: "monero-regtest-checkout/1", merchantOrigin: ledger.config.origin, intentId: intent.intentId, network,
      address: intent.address, subaddressIndex: intent.subaddressIndex, amountAtomic: intent.amountAtomic, createdAt: intent.createdAt, expiresAt: intent.expiresAt });
  };
  const view = (intentId: string): MoneroRegtestView => {
    const terms = termsFor(intentId), intent = ledger.getIntent(intentId), { receipts, impaired } = ledger.getReceipts(intentId), acceptance = ledger.getAcceptance(intentId);
    const status = impaired ? "regtest_evidence_impaired" : intent.status === "paid" ? "regtest_receipt_recorded" : intent.status === "reconciliation" ? "regtest_reconciliation"
      : now() >= intent.expiresAt ? "expired" : "awaiting_funds";
    const progress = ledger.getProgress(intentId);
    return { version: "monero-regtest-view/1", terms, status, reconciliation: intent.reconciliation, progress, receipts,
      event: acceptance ? signMoneroRegtestReceipt({ version: "monero-regtest-event/1", type: "regtest.receipt_recorded", scope: "local_regtest_only", id: acceptance.id,
        terms, receipts: receipts.filter((receipt) => acceptance.receiptKeys.includes(receipt.key)), recordedAt: acceptance.acceptedAt }, signingKey) : null };
  };
  const response = (value: unknown, status = 200): Response => Response.json(value, { status, headers: {
    "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
  } });
  return {
    /** One observation pass; rejects (changing nothing) when the wallet evidence is unusable. */
    tick: () => ledger.observe(rpc, now),
    async fetch(request: Request): Promise<Response> {
      try {
        const url = new URL(request.url);
        if (url.origin !== transportOrigin || url.search || url.hash || (request.headers.has("Origin") && request.headers.get("Origin") !== transportOrigin)) throw new HttpError(403);
        const authorization = request.headers.get("Authorization") ?? "";
        if (!/^Bearer [A-Za-z0-9_-]{32,128}$/.test(authorization)) throw new HttpError(401);
        const bearer = authorization.slice(7), admin = equal(bearer, adminToken);
        if (url.pathname === "/v1/monero-regtest/intents") {
          if (!admin) throw new HttpError(401); if (request.method !== "POST") throw new HttpError(405);
          const key = request.headers.get("Idempotency-Key") ?? ""; if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) throw new HttpError(400);
          const body = await jsonBody(request);
          if (Object.keys(body).sort().join(",") !== "amountAtomic,expiresAt,orderRef" || typeof body.orderRef !== "string" || typeof body.amountAtomic !== "string" ||
              typeof body.expiresAt !== "number") throw new HttpError(400);
          const intent = await ledger.createIntent(body.orderRef, body.amountAtomic, body.expiresAt, key, rpc, now);
          return response({ view: view(intent.intentId), readCapability: capability(intent.intentId) }, 201);
        }
        const match = /^\/v1\/monero-regtest\/intents\/([A-Za-z0-9_-]{16,128})$/.exec(url.pathname);
        if (!match) throw new HttpError(404); const intentId = match[1]!;
        if (!admin && !equal(bearer, capability(intentId))) throw new HttpError(404);
        if (request.method !== "GET") throw new HttpError(405);
        return response(view(intentId));
      } catch (error) { return response({ error: "monero_regtest_request_refused" }, error instanceof HttpError ? error.status : 409); }
    },
  };
}
