import { createCheckout, indexedDbCheckoutStore } from "../src/sdk";
import { mountTracking } from "../src/tracking";
import { discoverLightningAddress, validateLnurlPayInvoice, requestLnurlPayInvoice } from "../src/lnurlPay";
import { createNativeLightningMerchantManifest, parseNativeLightningMerchantManifest } from "../src/manifest";
import { invoiceBinding } from "../src/bolt11";
import { receiver, testInvoice } from "../tests/helpers";
import { createNativeSandboxCheckout, type NativeSandboxCheckpoint } from "../src/nativeSdk";
import { parseNativeSandboxTerms } from "../src/nativeContract";
import { Wallet } from "ethers";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

declare global { interface Window { checkoutPay(): Promise<string>; checkoutCalls(): number; checkoutReady: boolean;
  discoverLightningAddress: typeof discoverLightningAddress; validateLnurlPayInvoice: typeof validateLnurlPayInvoice;
  requestLnurlPayInvoice: typeof requestLnurlPayInvoice;
  createNativeLightningMerchantManifest: typeof createNativeLightningMerchantManifest;
  parseNativeLightningMerchantManifest: typeof parseNativeLightningMerchantManifest;
  lnurlFixture: { receiver: string; invoice: string; hashedInvoice: string; metadata: string } } }
window.discoverLightningAddress = discoverLightningAddress;
window.validateLnurlPayInvoice = validateLnurlPayInvoice;
window.requestLnurlPayInvoice = requestLnurlPayInvoice;
window.createNativeLightningMerchantManifest = createNativeLightningMerchantManifest;
window.parseNativeLightningMerchantManifest = parseNativeLightningMerchantManifest;

const invoice = testInvoice("browser_fixture"); const binding = invoiceBinding(invoice, "regtest");
const lnurlMetadata = '[["text/plain","Receiver"],["text/identifier","buyer@receiver.example"]]';
window.lnurlFixture = { receiver, invoice, metadata: lnurlMetadata,
  hashedInvoice: testInvoice("browser_hash", "1000000", 1000, 2000, "bcrt", undefined, lnurlMetadata) };
const terms = { version: "checkout/0.1" as const, policyVersion: "native-lightning/1" as const, merchantOrigin: "https://merchant.example",
  intentId: "browser_intent_0001", attemptId: "browser_attempt_001", receiver, network: "regtest" as const,
  amountMsat: binding.amount_msat, paymentHash: binding.payment_hash, expiresAt: 2000, buyerExtraMsat: "0" };
let calls = 0;
const checkout = createCheckout({ intentUrl: "https://merchant.example/v1/intents/" + terms.intentId, statusToken: "s".repeat(43),
  policy: { version: "native-lightning/1", merchantOrigin: terms.merchantOrigin, receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000 },
  wallet: { canLimitFees: true, payInvoice: async () => { calls++; } },
  recoveryStore: indexedDbCheckoutStore("checkout_fixture_" + new URL(location.href).searchParams.get("case")), now: () => 1200,
  fetch: async () => Response.json({ version: "checkout-view/1", id: terms.intentId, status: "waiting", attempt: { terms, invoice } }) });
if (new URL(location.href).searchParams.get("kind") === "native") {
  document.getElementById("tracking")!.setAttribute("role", "status");
  const payer = new Wallet("0x" + "0".repeat(63) + "1"), recipient = "0x" + "2".repeat(40), token = "0x" + "1".repeat(40), genesis = "0x" + "0".repeat(64);
  const nativeTerms = parseNativeSandboxTerms({ version: "native-sandbox-checkout/1", merchantOrigin: "https://sandbox.invalid", intentId: "native_browser_intent_01", attemptId: terms.attemptId,
    asset: { id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash: genesis, token, decimals: 6, behavior: "standard_erc20", runtimeCodeHash: "0x" + "3".repeat(64), implementation: null,
      historicalStateVerified: true, behaviorConformanceVerified: true, localSandbox: { version: "anvil-local/1", namespace: "native_browser_fixture", confirmations: 6 } }, recipient, amountBaseUnits: "1000000", createdAt: 1000, expiresAt: 2000 });
  const native = createNativeSandboxCheckout({ intentUrl: nativeTerms.merchantOrigin + "/v1/native-sandbox/intents/" + nativeTerms.intentId,
    paymentCapability: "native_browser_payment_capability_00001", terms: nativeTerms, merchantPublicKey: bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(5))),
    maxTokenBaseUnits: "1000000", gasLimit: "100000", maxFeePerGasWei: "1", maxPriorityFeePerGasWei: "0", maxGasCostWei: "100000", now: () => 1200,
    recoveryStore: indexedDbCheckoutStore<NativeSandboxCheckpoint>("checkout_fixture_" + new URL(location.href).searchParams.get("case")),
    // Browser fixture stub only, not a conformant deployed wallet or private recovery implementation.
    wallet: { version: "native-sandbox-wallet/1", durableOperationIdentity: true, guardedFeeCaps: true,
      identity: async () => ({ chainId: "31337", genesisHash: genesis, sourceWallet: payer.address.toLowerCase(), sourceNonce: "0" }),
      signBinding: async (_id, _binding, typed) => payer.signTypedData(typed.domain, typed.types, typed.value),
      dispatch: async (_id, _request, guard) => { await guard("sign"); await guard("broadcast"); calls++; return "0x" + "8".repeat(64); }, lookup: async () => null },
    fetch: async (input, init) => String(input).endsWith("/prepare") ? Response.json({ version: "native-sandbox-preparation/1", terms: nativeTerms,
      prepared: { ...JSON.parse(init!.body as string), preparedAt: 1200, preparedBlockNumber: 40, preparedBlockHash: "0x" + "4".repeat(64) } }) :
      Response.json({ version: "native-sandbox-view/1", terms: nativeTerms, status: "awaiting_funds", evidence: "none_recorded", receipt: null, event: null }),
  });
  const refresh = async () => { try { const result = await native.open(); document.getElementById("tracking")!.textContent = result.recovery === "tracking" ? "Native receipt observation only" : "Native action required"; }
    catch { document.getElementById("tracking")!.textContent = "Native action required"; } };
  Object.assign(window, { checkoutPay: async () => { try { await native.pay(); await refresh(); return "sent"; } catch { await refresh(); return "refused"; } }, checkoutCalls: () => calls });
  await refresh(); window.checkoutReady = true;
} else {
  mountTracking(document.getElementById("tracking")!, checkout);
  Object.assign(window, { checkoutPay: async () => { try { await checkout.pay(); return "sent"; } catch { return "refused"; } }, checkoutCalls: () => calls, checkoutReady: true });
}
