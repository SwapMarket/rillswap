import { createHmac, timingSafeEqual } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { AcceptanceEvent, InvoiceIssuer, MerchantLedger, ReceiptObserver } from "./merchant";
import type { IntentView } from "./sdk";
import type { LightningAcceptanceConsumer } from "./acceptanceConsumer";
import { createNativeLightningMerchantManifest } from "./manifest";
import { WooCommerceOrderRefused, type WooCommerceOrderSource } from "./woocommerce";
import { MAX_MSAT } from "./contract";
import { invoiceBinding } from "./bolt11";

export interface SignedAcceptance {
  readonly algorithm: "Ed25519";
  readonly publicKey: string;
  readonly event: AcceptanceEvent;
  readonly signature: string;
}
const EVENT_FIELDS = "acceptedAt,amountMsat,attemptId,id,intentId,merchantOrigin,paymentHash,type,version";
const eventBytes = (event: AcceptanceEvent): Uint8Array => new TextEncoder().encode(JSON.stringify([
  "rillswap-payment-event/1", event.version, event.id, event.merchantOrigin, event.type, event.intentId,
  event.attemptId, event.paymentHash, event.amountMsat, event.acceptedAt,
]));
function validEvent(event: AcceptanceEvent): boolean {
  return event.version === "checkout-event/1" && event.type === "payment.accepted" &&
    Object.keys(event).sort().join(",") === EVENT_FIELDS &&
    [event.id, event.intentId, event.attemptId].every((id) => /^[A-Za-z0-9_-]{16,128}$/.test(id)) &&
    new URL(event.merchantOrigin).origin === event.merchantOrigin && event.merchantOrigin.startsWith("https://") &&
    /^[0-9a-f]{64}$/.test(event.paymentHash) && /^[1-9][0-9]{0,18}$/.test(event.amountMsat) && Number.isSafeInteger(event.acceptedAt) && event.acceptedAt >= 0;
}
export function signAcceptance(event: AcceptanceEvent, key: Uint8Array): SignedAcceptance {
  return { algorithm: "Ed25519", publicKey: bytesToHex(ed25519.getPublicKey(key)), event,
    signature: bytesToHex(ed25519.sign(eventBytes(event), key)) };
}
/** Additional acceptance-key restriction atop legacy ZIP-215 verification.
 * Mixed-order and noncanonical ZIP-215 points remain supported; a small-order
 * point has no nonzero prime-order component and cannot authenticate a signer.
 * The custom RFC 8032 signer has a separate, stricter key contract below.
 */
export function hasNontrivialAcceptanceKey(publicKey: unknown): boolean {
  try { return typeof publicKey === "string" && !ed25519.Point.fromBytes(hexToBytes(publicKey), true).isSmallOrder(); }
  catch { return false; }
}
/** Verify against an independently pinned merchant key, then deduplicate the stable event ID. */
export function verifyAcceptance(envelope: SignedAcceptance, expectedPublicKey: string): boolean {
  try {
    const event = envelope.event;
    return envelope.algorithm === "Ed25519" && envelope.publicKey === expectedPublicKey && validEvent(event) && hasNontrivialAcceptanceKey(expectedPublicKey) &&
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
  readonly acceptanceSigner?: never;
  readonly now?: () => number;
  readonly acceptanceConsumer?: LightningAcceptanceConsumer;
  readonly publishManifest?: boolean;
  /** Buyer-initiated checkout priced by the store; the buyer supplies only the order key. */
  /** `orderKeyGrantsStatusAccess: true` acknowledges the pay-by-link policy: anyone
   * holding an order ID and key receives an enduring status/events capability. */
  readonly wooCommerce?: {
    readonly source: WooCommerceOrderSource;
    readonly intentTtlSeconds: number;
    readonly orderKeyGrantsStatusAccess: true;
    /** Opt-in backend authorization from a fresh store read, never from missing state. */
    readonly bindVerifiedOrders?: boolean;
  };
}
/** Dedicated acceptance key, not a wallet/spending signer. Implementations MUST
 * produce standard RFC 8032 deterministic Ed25519 signatures for identical
 * canonical bytes across retries, concurrency and restarts. Validity alone
 * cannot prove this requirement; provider conformance is independently required.
 */
export interface AcceptanceSigner {
  readonly publicKey: string;
  sign(canonicalBytes: Uint8Array): Promise<Uint8Array>;
}
export type KeylessMerchantServiceOptions = Omit<MerchantServiceOptions, "eventSigningKey" | "acceptanceSigner"> & {
  readonly eventSigningKey?: never;
  readonly acceptanceSigner: AcceptanceSigner;
};
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
export function createMerchantService(options: MerchantServiceOptions | KeylessMerchantServiceOptions) {
  const configuredSigner = "acceptanceSigner" in options;
  const rawKey = options.eventSigningKey, signer = configuredSigner ? options.acceptanceSigner : undefined;
  if (configuredSigner ? rawKey !== undefined || signer === undefined || signer === null : rawKey === undefined) throw new Error("Exactly one acceptance signing source required");
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(options.adminToken) || options.statusKey.length !== 32 || (rawKey !== undefined && rawKey.length !== 32)) throw new Error("Persistent merchant authentication keys required");
  const signerPublicKey = signer?.publicKey, signerMethod = signer?.sign;
  if (signer !== undefined && (typeof signerPublicKey !== "string" || !/^[0-9a-f]{64}$/.test(signerPublicKey) || typeof signerMethod !== "function")) throw new Error("Invalid acceptance signer");
  if (signer !== undefined) {
    try {
      const point = ed25519.Point.fromBytes(hexToBytes(signerPublicKey!));
      // ZIP-215 verification accepts small-order keys. External dedicated keys
      // must instead be canonical, nonidentity, prime-subgroup signing keys.
      if (point.isSmallOrder() || !point.isTorsionFree() || bytesToHex(point.toBytes()) !== signerPublicKey) throw new Error();
    } catch { throw new Error("Invalid acceptance signer"); }
  }
  const customSign = signerMethod?.bind(signer);
  const { ledger } = options;
  const consumer = options.acceptanceConsumer;
  const publication = options.publishManifest;
  if (publication !== undefined && typeof publication !== "boolean") throw new Error("Invalid manifest publication option");
  const publishing = publication === true;
  if (publishing && ledger.identity.network !== "regtest") throw new Error("Manifest publication is regtest only");
  // Opt-in pins the event key as well as binding identity. Default key behavior
  // remains unchanged; caller mutation cannot rotate an opted-in signing key.
  const eventSigningKey = rawKey === undefined ? undefined : consumer || publishing ? new Uint8Array(rawKey) : rawKey;
  const pinnedPublicKey = signerPublicKey ?? (consumer || publishing ? bytesToHex(ed25519.getPublicKey(eventSigningKey!)) : undefined);
  if (consumer && (consumer.identity.merchantOrigin !== ledger.identity.origin || consumer.identity.receiver !== ledger.identity.receiver ||
      consumer.identity.network !== ledger.identity.network || consumer.identity.merchantPublicKey !== pinnedPublicKey)) throw new Error("Acceptance consumer identity mismatch");
  const manifest = publishing ? createNativeLightningMerchantManifest(ledger.identity.origin, ledger.identity.receiver, pinnedPublicKey!) : null;
  const signedEvent = async (event: AcceptanceEvent): Promise<SignedAcceptance> => {
    // Legacy raw mode deliberately retains the original mutable-key behavior.
    if (!customSign) return signAcceptance(event, eventSigningKey!);
    try {
      if (Object.keys(event).sort().join(",") !== EVENT_FIELDS) throw new Error();
      const captured = Object.freeze({ version: event.version, id: event.id, merchantOrigin: event.merchantOrigin, type: event.type,
        intentId: event.intentId, attemptId: event.attemptId, paymentHash: event.paymentHash, amountMsat: event.amountMsat, acceptedAt: event.acceptedAt });
      if ([captured.version, captured.id, captured.merchantOrigin, captured.type, captured.intentId, captured.attemptId, captured.paymentHash, captured.amountMsat].some((value) => typeof value !== "string") || !validEvent(captured)) throw new Error();
      // The delegated signer receives its own byte copy, never the event object.
      const signature = await customSign(eventBytes(captured));
      if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new Error();
      const envelope: SignedAcceptance = { algorithm: "Ed25519", publicKey: signerPublicKey!, event: captured, signature: bytesToHex(new Uint8Array(signature)) };
      if (!verifyAcceptance(envelope, signerPublicKey!)) throw new Error();
      return Object.freeze(envelope);
    } catch { throw new Error("Acceptance signing refused"); }
  };
  const configuredCommerce = options.wooCommerce;
  if (configuredCommerce !== undefined && (!configuredCommerce || typeof configuredCommerce.source?.readPayableOrder !== "function" ||
      !Number.isSafeInteger(configuredCommerce.intentTtlSeconds) || configuredCommerce.intentTtlSeconds < 60 || configuredCommerce.intentTtlSeconds > 86_400 ||
      configuredCommerce.orderKeyGrantsStatusAccess !== true ||
      (configuredCommerce.bindVerifiedOrders !== undefined && typeof configuredCommerce.bindVerifiedOrders !== "boolean") ||
      (configuredCommerce.bindVerifiedOrders === true && !consumer))) throw new Error("Invalid WooCommerce checkout options");
  const commerce = configuredCommerce === undefined ? undefined : Object.freeze({
    readPayableOrder: configuredCommerce.source.readPayableOrder.bind(configuredCommerce.source),
    intentTtlSeconds: configuredCommerce.intentTtlSeconds, bindVerifiedOrders: configuredCommerce.bindVerifiedOrders === true,
  });
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const token = (intentId: string): string => createHmac("sha256", options.statusKey).update("checkout-status/1:" + ledger.identity.origin + ":" + intentId).digest("base64url");
  const snapshot = (intentId: string): IntentView => {
    const intent = ledger.getIntent(intentId); const attempt = ledger.attemptForIntent(intentId);
    let admitted = true;
    if (consumer && attempt?.invoice) {
      try { admitted = consumer.existingBinding(intent.order_ref, intent.amount_msat, ledger.terms(attempt.id)) !== null; }
      catch { throw new HttpError(503); } // Corrupt/conflicting provenance is not a missing binding.
    }
    return { version: "checkout-view/1", id: intent.id, status: intent.status,
      attempt: admitted && attempt?.invoice ? { terms: ledger.terms(attempt.id), invoice: attempt.invoice } : null };
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
        if (url.pathname === "/v1/manifest") {
          if (!manifest) throw new HttpError(404);
          if (request.method !== "GET") throw new HttpError(405);
          return response(manifest);
        }
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
        const wooOrder = /^\/v1\/woocommerce\/orders\/([1-9][0-9]{0,15})\/checkout$/.exec(url.pathname);
        if (wooOrder) {
          if (!commerce) throw new HttpError(404);
          if (request.method !== "POST") throw new HttpError(405);
          const input = await body(request);
          if (Object.keys(input).join(",") !== "orderKey" || typeof input.orderKey !== "string") throw new HttpError(400);
          let price: Readonly<{ orderRef: string; amountMsat: string }>;
          try {
            const raw = await commerce.readPayableOrder(wooOrder[1]!, input.orderKey);
            const orderRef = raw.orderRef, amountMsat = raw.amountMsat;
            if (typeof orderRef !== "string" || orderRef.length === 0 || orderRef.length > 128 || /[\u0000-\u001f\u007f]/.test(orderRef) ||
                typeof amountMsat !== "string" || !/^[1-9][0-9]{0,18}$/.test(amountMsat) || BigInt(amountMsat) > MAX_MSAT || BigInt(amountMsat) % 1000n !== 0n) throw new Error("Invalid store price");
            // A privileged custom source may retain/mutate its returned object.
            // Capture validated scalars before health/issuance awaits.
            price = Object.freeze({ orderRef, amountMsat });
          }
          catch (error) { throw new HttpError(error instanceof WooCommerceOrderRefused ? { not_found: 404, not_payable: 409, unavailable: 503 }[error.reason] : 503); }
          await health(); // only after store admission, so unauthenticated probes cause no backend work
          // The store total is authoritative. An existing intent is used only if this
          // route-specific key matches; never adopted by reference/amount alone.
          // Admins can deliberately supply this key and already have binding authority.
          const key = "woocommerce-intent:" + price.orderRef;
          let intent = ledger.intentForOrder(price.orderRef);
          if (!intent) {
            const at = now();
            try { intent = ledger.createIntent(price.orderRef, price.amountMsat, at + commerce.intentTtlSeconds, key, at); }
            catch { intent = ledger.intentForOrder(price.orderRef); } // concurrent first request
          }
          if (intent && ledger.intentIdForKey(key) !== intent.id) throw new HttpError(409);
          if (!intent || intent.amount_msat !== price.amountMsat) throw new HttpError(409);
          let attempt = ledger.attemptForIntent(intent.id);
          if (!attempt && intent.status === "waiting" && now() < intent.expires_at) {
            try { attempt = ledger.createAttempt(intent.id, "woocommerce-attempt:" + intent.id, now()); } catch { attempt = ledger.attemptForIntent(intent.id); }
          }
          if (attempt && !attempt.invoice && intent.status === "waiting") {
            try { attempt = await ledger.issue(attempt.id, options.issuer, now); }
            catch { return response({ ...snapshot(intent.id), statusToken: token(intent.id), actionRequired: "issuance_reconciliation" }, 202); }
          }
          if (commerce.bindVerifiedOrders && attempt?.invoice) {
            try {
              const terms = ledger.terms(attempt.id), binding = invoiceBinding(attempt.invoice, ledger.identity.network), at = now();
              if (!Number.isSafeInteger(at) || at < 0 || binding.payment_hash !== attempt.payment_hash || binding.payment_hash === "0".repeat(64) ||
                  binding.amount_msat !== price.amountMsat || binding.payee_compressed_pubkey !== ledger.identity.receiver || binding.created_at > at) throw new Error("Stored invoice differs from store authorization");
              // Existing bindings replay. New ones require a currently waiting,
              // unexpired invoice, never observed historical paid/reconciliation state.
              if (!consumer!.existingBinding(price.orderRef, price.amountMsat, terms) &&
                  (ledger.getIntent(intent.id).status !== "waiting" || at >= terms.expiresAt)) throw new HttpError(409);
              consumer!.bindOrder(price.orderRef, price.amountMsat, terms);
            } catch (error) { throw error instanceof HttpError ? error : new HttpError(503); }
          }
          return response({ ...snapshot(intent.id), statusToken: token(intent.id) });
        }
        const match = /^\/v1\/intents\/([A-Za-z0-9_-]{16,128})(?:\/(attempts|events|evidence|order-binding))?$/.exec(url.pathname);
        if (!match) throw new HttpError(404);
        const intentId = match[1]!, operation = match[2];
        if (!admin && !equal(authorization, `Bearer ${token(intentId)}`)) throw new HttpError(404);
        ledger.getIntent(intentId);
        if (!operation && request.method === "GET") {
          if (ledger.getIntent(intentId).status === "waiting") await health();
          return response(snapshot(intentId));
        }
        if (operation === "order-binding") {
          if (!consumer) throw new HttpError(404);
          if (request.method !== "PUT") throw new HttpError(405);
          if (!admin) throw new HttpError(403);
          const input = await body(request), intent = ledger.getIntent(intentId);
          if (Object.keys(input).sort().join(",") !== "amountMsat,orderRef" || typeof input.orderRef !== "string" || typeof input.amountMsat !== "string" ||
              input.orderRef !== intent.order_ref || input.amountMsat !== intent.amount_msat) throw new HttpError(400);
          const attempt = ledger.attemptForIntent(intentId);
          if (!attempt?.invoice) throw new HttpError(409);
          // Affirmative backend authorization, never a passive missing-state
          // backfill. Resource-level exact replay, not an idempotency-key map.
          consumer.bindOrder(input.orderRef, input.amountMsat, ledger.terms(attempt.id));
          return response(snapshot(intentId));
        }
        if (operation === "events" && request.method === "GET") {
          const signed: SignedAcceptance[] = [];
          for (const event of ledger.eventsForIntent(intentId)) signed.push(await signedEvent(event));
          return response(signed);
        }
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
        await deliver(await signedEvent(event));
        ledger.acknowledgeEvent(event.id);
      }
    },
  };
}
