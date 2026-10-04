import { createHmac, timingSafeEqual } from "node:crypto";
import { evmReceiptScope, validateEvmAsset, type EvmReader, type EvmReceiptBinding } from "./evmReceipt";
import { parseNativeSandboxTerms, signNativeSandboxReceipt, type NativeSandboxTerms, type NativeSandboxView } from "./nativeContract";
import type { NativeReceiptLedger } from "./nativeLedger";

export interface NativeSandboxServiceOptions {
  readonly ledger: NativeReceiptLedger;
  readonly provider: EvmReader;
  readonly adminToken: string;
  readonly capabilityKey: Uint8Array;
  readonly eventSigningKey: Uint8Array;
  /** Exact mounted origin. Only an explicitly configured numeric loopback HTTP override is allowed. */
  readonly transportOrigin?: string;
  readonly now?: () => number;
}
class HttpError extends Error { constructor(readonly status: number) { super("Sandbox checkout request refused"); } }
const exactFields = (input: Record<string, unknown>, names: string): void => { if (Object.keys(input).sort().join(",") !== names) throw new HttpError(400); };
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

/** Separate manually mounted handler. No provisioning, background scan, wallet, delivery worker or production rail. */
export function createNativeSandboxService(options: NativeSandboxServiceOptions) {
  const { ledger, provider } = options, asset = ledger.config.asset; validateEvmAsset(asset);
  if (asset.chainId !== "31337" || !asset.localSandbox || asset.implementation !== null || !/^[A-Za-z0-9_-]{32,128}$/.test(options.adminToken) ||
      !(options.capabilityKey instanceof Uint8Array) || !(options.eventSigningKey instanceof Uint8Array) || options.capabilityKey.length !== 32 || options.eventSigningKey.length !== 32) throw new Error("Explicit sandbox ledger and persistent private keys required");
  const adminToken = options.adminToken, capabilityKey = Uint8Array.from(options.capabilityKey), signingKey = Uint8Array.from(options.eventSigningKey);
  const now = options.now ?? (() => Math.floor(Date.now() / 1000)), transportOrigin = options.transportOrigin ?? ledger.config.origin;
  const transport = new URL(transportOrigin);
  if (transport.origin !== transportOrigin || transport.username || transport.password || (transportOrigin !== ledger.config.origin &&
      (transport.protocol !== "http:" || transport.hostname !== "127.0.0.1"))) throw new Error("Exact merchant HTTPS or explicit numeric loopback transport required");
  const capability = (role: "read" | "payment", intentId: string): string => createHmac("sha256", capabilityKey)
    .update(`native-sandbox-${role}/1:${ledger.config.origin}:${evmReceiptScope(asset)}:${intentId}`).digest("base64url");
  const termsFor = (intentId: string): NativeSandboxTerms => {
    const intent = ledger.getIntent(intentId);
    return parseNativeSandboxTerms({ version: "native-sandbox-checkout/1", merchantOrigin: ledger.config.origin, intentId: intent.intentId, attemptId: intent.attemptId,
      asset, recipient: intent.recipient, amountBaseUnits: intent.amountBaseUnits, createdAt: intent.createdAt, expiresAt: intent.expiresAt });
  };
  const snapshot = (intentId: string): NativeSandboxView => {
    const terms = termsFor(intentId), record = ledger.getReceiptRecord(intentId), acceptance = record?.acceptance;
    return { version: "native-sandbox-view/1", terms,
      status: record?.allocationState === "reorged" ? "sandbox_evidence_impaired" : acceptance ? "sandbox_receipt_recorded" : record ? "sandbox_reconciliation" : "awaiting_funds",
      evidence: record?.allocationState === "reorged" ? "recorded_impairment" : record ? "recorded_local_confirmations" : "none_recorded",
      receipt: record?.receipt ?? null,
      event: acceptance ? signNativeSandboxReceipt({ version: "native-sandbox-event/1", type: "sandbox.receipt_recorded", scope: "local_sandbox_only", id: acceptance.id,
        terms, receipt: record!.receipt, recordedAt: acceptance.acceptedAt }, signingKey) : null };
  };
  const response = (value: unknown, status = 200): Response => Response.json(value, { status, headers: {
    "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
  } });
  return {
    async fetch(request: Request): Promise<Response> {
      try {
        const url = new URL(request.url);
        if (url.origin !== transportOrigin || url.search || url.hash || (request.headers.has("Origin") && request.headers.get("Origin") !== transportOrigin)) throw new HttpError(403);
        const authorization = request.headers.get("Authorization") ?? "";
        if (!/^Bearer [A-Za-z0-9_-]{32,128}$/.test(authorization)) throw new HttpError(401);
        const bearer = authorization.slice(7), admin = equal(bearer, adminToken);
        const key = (): string => { const value = request.headers.get("Idempotency-Key") ?? ""; if (!/^[A-Za-z0-9_-]{16,128}$/.test(value)) throw new HttpError(400); return value; };
        if (url.pathname === "/v1/native-sandbox/intents") {
          if (!admin) throw new HttpError(401); if (request.method !== "POST") throw new HttpError(405);
          const body = await jsonBody(request); exactFields(body, "amountBaseUnits,expiresAt,orderRef");
          if (typeof body.orderRef !== "string" || typeof body.amountBaseUnits !== "string" || typeof body.expiresAt !== "number") throw new HttpError(400);
          const intent = ledger.createIntent(body.orderRef, body.amountBaseUnits, body.expiresAt, key(), now());
          return response({ view: snapshot(intent.intentId), readCapability: capability("read", intent.intentId), paymentCapability: capability("payment", intent.intentId) }, 201);
        }
        const match = /^\/v1\/native-sandbox\/intents\/([A-Za-z0-9_-]{16,128})(?:\/(prepare|observe))?$/.exec(url.pathname);
        if (!match) throw new HttpError(404); const intentId = match[1]!, action = match[2];
        const payment = equal(bearer, capability("payment", intentId)), read = equal(bearer, capability("read", intentId));
        if (!admin && !payment && !read) throw new HttpError(404);
        if (!action) {
          if (request.method !== "GET") throw new HttpError(405); return response(snapshot(intentId));
        }
        if (!payment) throw new HttpError(403); if (request.method !== "POST") throw new HttpError(405);
        const intent = ledger.getIntent(intentId), body = await jsonBody(request);
        if (action === "prepare") {
          exactFields(body, "binding,signature");
          if (!body.binding || typeof body.binding !== "object" || Array.isArray(body.binding) || typeof body.signature !== "string") throw new HttpError(400);
          exactFields(body.binding as Record<string, unknown>, "amountBaseUnits,assetId,attemptId,intentId,merchantOrigin,recipient,sourceNonce,sourceWallet,validAfter,validBefore,version");
          const binding = body.binding as Record<string, unknown>;
          if (Object.entries(binding).some(([name, value]) => typeof value !== (name === "validAfter" || name === "validBefore" ? "number" : "string"))) throw new HttpError(400);
          const prepared = await ledger.prepare(intentId, body.binding as EvmReceiptBinding, body.signature, key(), provider, now);
          return response({ version: "native-sandbox-preparation/1", terms: termsFor(intentId), prepared }, 201);
        }
        exactFields(body, "txHash"); if (typeof body.txHash !== "string" || !/^0x[0-9a-f]{64}$/.test(body.txHash)) throw new HttpError(400);
        await ledger.observe(intent.attemptId, body.txHash, provider, now); return response(snapshot(intentId));
      } catch (error) { return response({ error: "sandbox_request_refused" }, error instanceof HttpError ? error.status : 409); }
    },
  };
}
