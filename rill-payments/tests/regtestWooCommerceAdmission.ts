// Executed in a child with the disposable store's CA (or deliberately no trust).
// The default production fetch is used, not an injected transport.
import { readFileSync } from "node:fs";
import { createWooCommerceOrderSource, WooCommerceOrderRefused } from "../src/woocommerce";
import { MerchantLedger } from "../src/merchant";
import { createMerchantService } from "../src/server";
import { LightningAcceptanceConsumer } from "../src/acceptanceConsumer";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { receiver, testInvoice } from "./helpers";

const input = JSON.parse(readFileSync(process.argv[2]!, "utf8")) as {
  origin: string; consumerKey: string; consumerSecret: string; orderId: string; orderKey: string; ledgerPath: string;
};
const origin = process.env.RILLSWAP_WOO_PROBE_ORIGIN ?? input.origin;
const secret = process.argv[3] === "auth-refusal" ? "cs_invalidFixtureSecret00000" : input.consumerSecret;
const source = createWooCommerceOrderSource({ storeOrigin: origin, consumerKey: input.consumerKey, consumerSecret: secret });
const url = `${origin}/wp-json/wc/v3/orders/${input.orderId}`;
const rawRead = () => fetch(url, { method: "GET", redirect: "error", credentials: "omit", signal: AbortSignal.timeout(5000),
  headers: { Authorization: "Basic " + Buffer.from(input.consumerKey + ":" + secret).toString("base64") } });
if (process.argv[3] === "refusal" || process.argv[3] === "auth-refusal") {
  try { await source.readPayableOrder(input.orderId, input.orderKey); throw new Error("Untrusted fixture was admitted"); }
  catch (error) { if (!(error instanceof WooCommerceOrderRefused) || error.reason !== "unavailable") throw error; }
  if (process.argv[3] === "auth-refusal") {
    const response = await rawRead();
    if (response.status !== 401) throw new Error("Invalid REST credential did not receive unauthorized");
    void response.body?.cancel(); console.log(JSON.stringify({ refused: true, httpStatus: response.status }));
  } else {
    let tlsCode: string | undefined;
    try { const response = await rawRead(); void response.body?.cancel(); }
    catch (error) { tlsCode = (error as { code?: string; cause?: { code?: string } }).code ?? (error as { cause?: { code?: string } }).cause?.code; }
    if (!tlsCode) throw new Error("Fixture refusal was not attributed to a TLS error");
    console.log(JSON.stringify({ refused: true, tlsCode }));
  }
} else {
  const identity = { origin: "https://merchant.example", receiver, network: "regtest" as const, issuerId: "synthetic_woo_fixture" };
  const ledger = MerchantLedger.provision(input.ledgerPath, identity);
  const eventKey = new Uint8Array(32).fill(3);
  const consumer = LightningAcceptanceConsumer.provision(input.ledgerPath + ".consumer", { merchantOrigin: identity.origin, receiver,
    network: identity.network, merchantPublicKey: bytesToHex(ed25519.getPublicKey(eventKey)) });
  let issued = 0;
  const issuer = { identity: async () => identity, create: async (operation: { operationId: string; amountMsat: string }) => {
    issued++; return testInvoice(operation.operationId, operation.amountMsat);
  } };
  const observer = { identity: async () => identity, lookup: async () => { throw new Error("No settlement authority in store diagnostic"); } };
  const service = createMerchantService({ ledger, issuer, observer, adminToken: "fixture_woo_admin_token_0000000000001",
    statusKey: new Uint8Array(32).fill(2), eventSigningKey: eventKey, now: () => 1200, acceptanceConsumer: consumer,
    wooCommerce: { source, intentTtlSeconds: 600, orderKeyGrantsStatusAccess: true, bindVerifiedOrders: true } });
  const request = (key: string) => service.fetch(new Request(`${identity.origin}/v1/woocommerce/orders/${input.orderId}/checkout`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ orderKey: key }),
  }));
  try {
    const wrong = await request("wc_order_wrong_fixture_key");
    if (wrong.status !== 404) throw new Error("Wrong store key accepted");
    const first = await request(input.orderKey), second = await request(input.orderKey);
    const a = await first.json() as { id: string; status: string; attempt: { invoice: string; terms: { amountMsat: string } } };
    const b = await second.json() as typeof a;
    if (first.status !== 200 || second.status !== 200 || a.id !== b.id || a.attempt.invoice !== b.attempt.invoice ||
        a.attempt.terms.amountMsat !== "12345000" || b.attempt.terms.amountMsat !== "12345000" || issued !== 1 ||
        a.status !== "waiting" || b.status !== "waiting" || ledger.getIntent(a.id).status !== "waiting" ||
        ledger.pendingEvents().length !== 0) throw new Error("Real store admission mismatch");
    if (consumer.getOrder(ledger.getIntent(a.id).order_ref).state !== "waiting") throw new Error("Verified store price was not bound");
    console.log(JSON.stringify({ admitted: true, amountMsat: a.attempt.terms.amountMsat, replayed: true, issued,
      fulfilled: ledger.getIntent(a.id).status === "paid" }));
  } finally { consumer.close(); ledger.close(); }
}
