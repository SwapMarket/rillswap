// Buyer wallet stand-in for the demo shop's fake stablecoin orders. Runs in
// the shop container (the sandbox services listen on its loopback):
//
//   bun pay-token.ts <order-id>              pay an existing fUSDC/fUSDT order
//   bun pay-token.ts --new <fusdc|fusdt>     buy stickers and pay (smoke test)
//
// Flow, as in the rill-payments native sandbox test: sign the EIP-712 receipt
// binding for the next nonce, prepare it with the merchant, send the exact
// ERC20 transfer with that nonce, wait six confirmations, submit the
// transaction hash, then wait for the shop to verify the signed receipt.
import { Interface } from "ethers";
import { receiptBindingTypedData, type EvmReceiptBinding } from "../../src/evmReceipt";
import { anvilAccount, anvilProvider, type NativeCheckout } from "./native";

const SHOP = `http://127.0.0.1:${process.env.RILL_DEV_SHOP_LISTEN ?? 8090}`;
const rpc = anvilProvider(process.env.RILL_DEV_ANVIL_RPC ?? "http://127.0.0.1:8545");
const buyer = anvilAccount(1).connect(rpc);
const erc20 = new Interface(["function transfer(address to, uint256 amount) returns (bool)"]);
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

async function shop(path: string, body?: unknown): Promise<Record<string, any>> {
  const response = await fetch(SHOP + path, body === undefined ? undefined : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const value = (await response.json()) as Record<string, any>;
  if (!response.ok) throw new Error(`shop ${path}: ${value.error ?? response.status}`);
  return value;
}

async function sandbox(checkout: NativeCheckout, action: "prepare" | "observe", body: unknown, idempotencyKey?: string) {
  const headers: Record<string, string> = { Authorization: `Bearer ${checkout.paymentCapability}`, "Content-Type": "application/json" };
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const response = await fetch(`${checkout.transportOrigin}/v1/native-sandbox/intents/${checkout.intentId}/${action}`, {
    method: "POST", headers, body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${action} refused: HTTP ${response.status}`);
  return (await response.json()) as Record<string, any>;
}

const args = process.argv.slice(2);
let orderId = args[0];
if (orderId === "--new") {
  const order = await shop("/api/orders", { productId: "stickers", rail: args[1] });
  console.log(`order ${order.id}: ${order.amountLabel}`);
  orderId = order.id;
}
if (!orderId) throw new Error("usage: pay-token.ts <order-id> | --new <fusdc|fusdt>");
const order = await shop(`/api/orders/${orderId}`);
const checkout = order.native as NativeCheckout | null;
if (!checkout) throw new Error(`order ${orderId} is not a stablecoin order`);
if (order.status !== "waiting") throw new Error(`order ${orderId} is ${order.status}`);
const terms = checkout.terms;

const nonce = await rpc.getTransactionCount(buyer.address, "pending");
const binding: EvmReceiptBinding = {
  version: "evm-receipt-binding/1", merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, attemptId: terms.attemptId,
  assetId: terms.asset.id, sourceWallet: buyer.address.toLowerCase(), sourceNonce: nonce.toString(), recipient: terms.recipient,
  amountBaseUnits: terms.amountBaseUnits, validAfter: terms.createdAt, validBefore: terms.expiresAt,
};
const typed = receiptBindingTypedData(terms.asset, binding);
const signature = await buyer.signTypedData(typed.domain, typed.types, typed.value);
await sandbox(checkout, "prepare", { binding, signature }, `${orderId}-prepare-${nonce}`);
console.log(`prepared: ${buyer.address} nonce ${nonce} pays ${terms.amountBaseUnits} base units to ${terms.recipient}`);

const sent = await buyer.sendTransaction({
  to: terms.asset.token, nonce, value: 0n, gasLimit: 100_000n,
  data: erc20.encodeFunctionData("transfer", [terms.recipient, BigInt(terms.amountBaseUnits)]),
});
const receipt = await sent.wait();
if (!receipt || receipt.status !== 1) throw new Error(`transfer ${sent.hash} failed`);
console.log(`transfer ${sent.hash} mined in block ${receipt.blockNumber}; waiting for 6 confirmations`);

const deadline = Date.now() + 120_000;
while (Date.now() < deadline) {
  if ((await rpc.getBlockNumber()) >= receipt.blockNumber + 5) {
    const view = await sandbox(checkout, "observe", { txHash: sent.hash });
    if (view.status !== "awaiting_funds") {
      console.log(`merchant status: ${view.status}`);
      break;
    }
  }
  await sleep(2000);
}
while (Date.now() < deadline) {
  const current = await shop(`/api/orders/${orderId}`);
  if (current.acceptance) {
    console.log(`order ${orderId} paid, signed receipt ${current.acceptance.eventId} verified`);
    process.exit(0);
  }
  if (current.status === "reconciliation") throw new Error(`order ${orderId} needs reconciliation`);
  await sleep(2000);
}
throw new Error(`order ${orderId}: no verified receipt within 120 s`);
