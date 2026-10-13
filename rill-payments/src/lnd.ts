import { createHash, createHmac } from "node:crypto";
import { request } from "node:https";
import { invoiceBinding } from "./bolt11";
import type { InvoiceIssuer, IssueOperation, MerchantIdentity, ReceiptObserver, ReceiptObservation } from "./merchant";

type Json = Record<string, unknown>;
export interface LndTransport { call(method: "GET" | "POST", path: string, body?: Json): Promise<Json> }
export class LndNotFound extends Error {}

/** TLS-verified numeric loopback transport. Never resolves customer URLs or follows redirects. */
export function lndRestTransport(endpoint: string, certificate: Uint8Array, macaroon: Uint8Array): LndTransport {
  const base = new URL(endpoint);
  if (base.protocol !== "https:" || !["127.0.0.1", "[::1]"].includes(base.hostname) || base.pathname !== "/" || base.search || base.hash || base.username || base.password || certificate.length === 0 || macaroon.length === 0) throw new Error("Invalid local LND endpoint or credentials");
  return {
    call(method, path, body) {
      if (!/^\/v1\/(getinfo|invoices|invoice\/[0-9a-f]{64})$/.test(path)) throw new Error("Unsupported LND operation");
      return new Promise((resolve, reject) => {
        const req = request(new URL(path, base), { method, ca: Buffer.from(certificate), rejectUnauthorized: true,
          headers: { "Grpc-Metadata-macaroon": Buffer.from(macaroon).toString("hex"), "Content-Type": "application/json" } }, (res) => {
          const chunks: Buffer[] = []; let size = 0;
          res.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 262144) req.destroy(new Error("LND response exceeds limit")); else chunks.push(chunk); });
          res.on("error", reject);
          res.on("end", () => {
            try {
              const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Json;
              if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
              if (res.statusCode !== 200) {
                if (value.code === 5) throw new LndNotFound("Invoice not found");
                throw new Error("LND request failed"); // Never propagate raw backend messages or invoice secrets.
              }
              resolve(value);
            } catch (error) { reject(error instanceof LndNotFound ? error : new Error("LND response refused")); }
          });
        });
        req.on("error", () => reject(new Error("LND transport failed")));
        req.setTimeout(10000, () => req.destroy());
        req.end(body === undefined ? undefined : JSON.stringify(body));
      });
    },
  };
}
const hash = (value: Uint8Array): string => createHash("sha256").update(value).digest("hex");

/** Recoverable ordinary BOLT11 issuance, no outgoing-payment permission or merchant spending keys. */
export class LndInvoiceBackend implements InvoiceIssuer, ReceiptObserver {
  readonly configuredIdentity: MerchantIdentity;
  private readonly issuanceKey: Buffer;
  constructor(private readonly transport: LndTransport, identity: Omit<MerchantIdentity, "issuerId">, issuanceKey: Uint8Array, private readonly now = () => Math.floor(Date.now() / 1000)) {
    if (identity.network !== "regtest" || issuanceKey.length !== 32) throw new Error("LND checkout backend is regtest-only and requires a persistent 32-byte issuance key");
    this.issuanceKey = Buffer.from(issuanceKey);
    this.configuredIdentity = Object.freeze({ ...identity, issuerId: "lnd_" + hash(issuanceKey) });
  }
  async identity(): Promise<MerchantIdentity> {
    const info = await this.transport.call("GET", "/v1/getinfo");
    const chains = info.chains as { chain: string; network: string }[];
    const reason = info.identity_pubkey !== this.configuredIdentity.receiver ? "receiver_mismatch"
      : !Array.isArray(chains) || chains.length !== 1 || chains[0]?.chain !== "bitcoin" || chains[0]?.network !== this.configuredIdentity.network ? "chain_mismatch"
      : info.synced_to_chain !== true ? "not_synced" : null;
    if (reason) {
      // Fixed reasons only, never backend identities, credentials or responses.
      console.error(JSON.stringify({ diagnostic: "lnd_identity_refused", reason }));
      throw new Error("LND receiver identity, chain or freshness mismatch");
    }
    return this.configuredIdentity;
  }
  private validate(raw: Json, expectedHash: string, operation?: IssueOperation): string {
    if (typeof raw.payment_request !== "string") throw new Error("Missing LND payment request");
    const binding = invoiceBinding(raw.payment_request, this.configuredIdentity.network);
    if (binding.payment_hash !== expectedHash || binding.payee_compressed_pubkey !== this.configuredIdentity.receiver ||
        raw.r_hash !== Buffer.from(expectedHash, "hex").toString("base64") || raw.value_msat !== binding.amount_msat ||
        (operation && binding.amount_msat !== operation.amountMsat)) throw new Error("LND invoice does not match operation");
    return raw.payment_request;
  }
  async create(operation: IssueOperation): Promise<string> {
    if (operation.issuerId !== this.configuredIdentity.issuerId || operation.origin !== this.configuredIdentity.origin || operation.receiver !== this.configuredIdentity.receiver || operation.network !== this.configuredIdentity.network ||
        !/^[A-Za-z0-9_-]{16,128}$/.test(operation.operationId) || !/^[1-9][0-9]{0,18}$/.test(operation.amountMsat) || !Number.isSafeInteger(operation.expiresAt)) throw new Error("LND issuance operation mismatch");
    await this.identity();
    // Bind the secret to all immutable terms, not merely the public operation ID.
    const preimage = createHmac("sha256", this.issuanceKey).update(JSON.stringify(["checkout-issuance/1", operation.operationId, operation.origin, operation.receiver, operation.network, operation.amountMsat, operation.expiresAt])).digest();
    const paymentHash = hash(preimage);
    const lookup = async (): Promise<string> => this.validate(await this.transport.call("GET", `/v1/invoice/${paymentHash}`), paymentHash, operation);
    try { return await lookup(); } catch (error) { if (!(error instanceof LndNotFound)) throw error; }
    const expiry = operation.expiresAt - this.now();
    if (!Number.isSafeInteger(expiry) || expiry <= 0) throw new Error("Unissued LND operation expired");
    try {
      await this.transport.call("POST", "/v1/invoices", { r_preimage: preimage.toString("base64"), value_msat: operation.amountMsat, expiry: String(expiry), memo: "RillSwap checkout" });
    } catch {
      // Creation can have succeeded even on transport errors or duplicate-hash errors.
      // A missing reconciliation result propagates; never choose another preimage.
      return await lookup();
    }
    return await lookup();
  }
  async lookup(paymentHash: string): Promise<ReceiptObservation> {
    if (!/^[0-9a-f]{64}$/.test(paymentHash)) throw new Error("Invalid payment hash");
    await this.identity();
    const raw = await this.transport.call("GET", `/v1/invoice/${paymentHash}`);
    const invoice = this.validate(raw, paymentHash);
    const binding = invoiceBinding(invoice, this.configuredIdentity.network);
    if (raw.is_amp || raw.is_keysend || raw.is_blinded || typeof raw.amt_paid_msat !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(raw.amt_paid_msat) ||
        !["OPEN", "ACCEPTED", "SETTLED", "CANCELED"].includes(raw.state as string)) throw new Error("Unsupported LND receipt");
    const settledAt = raw.state === "SETTLED" ? Number(raw.settle_date) : null;
    if (settledAt !== null && (!Number.isSafeInteger(settledAt) || settledAt <= 0)) throw new Error("Missing LND settlement time");
    return { receiver: this.configuredIdentity.receiver, network: this.configuredIdentity.network, paymentHash,
      invoiceAmountMsat: binding.amount_msat, paidMsat: raw.amt_paid_msat, state: raw.state as ReceiptObservation["state"], settledAt };
  }
}
