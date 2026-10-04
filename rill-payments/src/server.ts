import { createHmac, timingSafeEqual } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { AcceptanceEvent, InvoiceIssuer, MerchantLedger, ReceiptObserver } from "./merchant";
import type { IntentView } from "./sdk";

export interface SignedAcceptance {
  readonly algorithm: "Ed25519";
  readonly publicKey: string;
  readonly event: AcceptanceEvent;
  readonly signature: string;
}
const eventBytes = (event: AcceptanceEvent): Uint8Array => new TextEncoder().encode(JSON.stringify([
  "rillswap-payment-event/1", event.version, event.id, event.merchantOrigin, event.type, event.intentId,
  event.attemptId, event.paymentHash, event.amountMsat, event.acceptedAt,
]));
export function signAcceptance(event: AcceptanceEvent, key: Uint8Array): SignedAcceptance {
  return { algorithm: "Ed25519", publicKey: bytesToHex(ed25519.getPublicKey(key)), event,
    signature: bytesToHex(ed25519.sign(eventBytes(event), key)) };
}
/** Verify against an independently pinned merchant key, then deduplicate the stable event ID. */
export function verifyAcceptance(envelope: SignedAcceptance, expectedPublicKey: string): boolean {
  try {
    const event = envelope.event;
    return envelope.algorithm === "Ed25519" && envelope.publicKey === expectedPublicKey && event.version === "checkout-event/1" && event.type === "payment.accepted" &&
      Object.keys(event).sort().join(",") === "acceptedAt,amountMsat,attemptId,id,intentId,merchantOrigin,paymentHash,type,version" &&
      [event.id, event.intentId, event.attemptId].every((id) => /^[A-Za-z0-9_-]{16,128}$/.test(id)) &&
      new URL(event.merchantOrigin).origin === event.merchantOrigin && event.merchantOrigin.startsWith("https://") &&
      /^[0-9a-f]{64}$/.test(event.paymentHash) && /^[1-9][0-9]{0,18}$/.test(event.amountMsat) && Number.isSafeInteger(event.acceptedAt) && event.acceptedAt >= 0 &&
      ed25519.verify(hexToBytes(envelope.signature), eventBytes(event), hexToBytes(expectedPublicKey));
  } catch { return false; }
}
export interface MerchantServiceOptions {
  readonly ledger: MerchantLedger;
  readonly issuer: InvoiceIssuer;
  readonly observer: ReceiptObserver;
  readonly adminToken: string;
  readonly statusKey: Uint8Array;
  readonly eventSigningKey: Uint8Array;
  readonly now?: () => number;
}
class HttpError extends Error { constructor(readonly status: number) { super("Checkout request refused"); } }
const equal = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
async function body(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get("Content-Type")?.split(";")[0] !== "application/json" || !request.body) throw new HttpError(400);
  const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  while (true) { const next = await reader.read(); if (next.done) break; size += next.value.length;
    if (size > 8192) { await reader.cancel(); throw new HttpError(413); } chunks.push(next.value); }
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new HttpError(400);
  return value;
}

/** Runnable fetch handler plus durable-job tick; mounting and scheduling are explicit. */
export function createMerchantService(options: MerchantServiceOptions) {
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(options.adminToken) || options.statusKey.length !== 32 || options.eventSigningKey.length !== 32) throw new Error("Persistent merchant authentication keys required");
  const { ledger } = options;
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const token = (intentId: string): string => createHmac("sha256", options.statusKey).update("checkout-status/1:" + ledger.identity.origin + ":" + intentId).digest("base64url");
  const snapshot = (intentId: string): IntentView => {
    const intent = ledger.getIntent(intentId); const attempt = ledger.attemptForIntent(intentId);
    return { version: "checkout-view/1", id: intent.id, status: intent.status,
      attempt: attempt?.invoice ? { terms: ledger.terms(attempt.id), invoice: attempt.invoice } : null };
  };
  const response = (value: unknown, status = 200): Response => Response.json(value, { status, headers: {
    "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
  } });
  const health = async (): Promise<void> => {
    for (const backend of [options.issuer, options.observer]) {
      const actual = await backend.identity();
      if (actual.origin !== ledger.identity.origin || actual.receiver !== ledger.identity.receiver || actual.network !== ledger.identity.network || actual.issuerId !== ledger.identity.issuerId) throw new HttpError(503);
    }
  };
  return {
    async fetch(request: Request): Promise<Response> {
      try {
        const url = new URL(request.url);
        if (url.search || url.hash || (request.headers.has("Origin") && request.headers.get("Origin") !== ledger.identity.origin)) throw new HttpError(403);
        const authorization = request.headers.get("Authorization") ?? "";
        const admin = equal(authorization, `Bearer ${options.adminToken}`);
        if (url.pathname === "/v1/intents" && request.method === "POST") {
          if (!admin) throw new HttpError(401);
          const input = await body(request);
          if (Object.keys(input).sort().join(",") !== "amountMsat,expiresAt,orderRef" || typeof input.orderRef !== "string" || typeof input.amountMsat !== "string" || typeof input.expiresAt !== "number") throw new HttpError(400);
          await health();
          const intent = ledger.createIntent(input.orderRef, input.amountMsat, input.expiresAt, request.headers.get("Idempotency-Key") ?? "", now());
          return response({ ...snapshot(intent.id), statusToken: token(intent.id) }, 201);
        }
        const match = /^\/v1\/intents\/([A-Za-z0-9_-]{16,128})(?:\/(attempts|events|evidence))?$/.exec(url.pathname);
        if (!match) throw new HttpError(404);
        const intentId = match[1]!, operation = match[2];
        if (!admin && !equal(authorization, `Bearer ${token(intentId)}`)) throw new HttpError(404);
        ledger.getIntent(intentId);
        if (!operation && request.method === "GET") {
          if (ledger.getIntent(intentId).status === "waiting") await health();
          return response(snapshot(intentId));
        }
        if (operation === "events" && request.method === "GET") return response(ledger.eventsForIntent(intentId).map((event) => signAcceptance(event, options.eventSigningKey)));
        if (operation === "attempts" && request.method === "POST") {
          if (!admin) throw new HttpError(403); // Read-only status capabilities cannot mutate order terms.
          const input = await body(request); if (Object.keys(input).length !== 0) throw new HttpError(400);
          await health();
          const attempt = ledger.createAttempt(intentId, request.headers.get("Idempotency-Key") ?? "", now());
          try { await ledger.issue(attempt.id, options.issuer, now); } catch { return response({ ...snapshot(intentId), actionRequired: "issuance_reconciliation" }, 202); }
          return response(snapshot(intentId), 201);
        }
        if (operation === "evidence" && request.method === "POST") {
          // Native Lightning has no buyer-submitted receipt that can be authenticated here.
          await body(request); return response({ authoritative: false, accepted: false }, 202);
        }
        throw new HttpError(405);
      } catch (error) { return response({ error: "Checkout request refused" }, error instanceof HttpError ? error.status : 400); }
    },
    async tick(): Promise<{ failedAttemptIds: string[] }> {
      const failedAttemptIds: string[] = [];
      for (const attempt of ledger.pendingAttempts()) {
        if (ledger.getIntent(attempt.intent_id).status !== "waiting") continue;
        try {
          const ready = attempt.invoice ? attempt : await ledger.issue(attempt.id, options.issuer, now);
          if (ready.invoice) await ledger.observe(attempt.id, options.observer, now);
        } catch { failedAttemptIds.push(attempt.id); }
      }
      return { failedAttemptIds };
    },
    async deliverEvents(deliver: (event: SignedAcceptance) => Promise<void>): Promise<void> {
      for (const event of ledger.pendingEvents()) {
        await deliver(signAcceptance(event, options.eventSigningKey));
        ledger.acknowledgeEvent(event.id);
      }
    },
  };
}
