import validate from "./generated/native-lightning-manifest.js";
import { NETWORKS, type Network } from "./contract";

interface NativeLightningAsset {
  readonly id: `LN_BTC_${Uppercase<Network>}`;
  readonly rail: "lightning";
  readonly network: Network;
  readonly amountUnit: "msat";
  /** BTC-relative decimal places; this checkout only accepts whole satoshis. */
  readonly decimals: 11;
  readonly quantum: "1000";
  readonly tokenBehavior: "not_applicable";
}
export interface NativeLightningMerchantManifest {
  readonly version: "merchant-manifest/native-lightning/1";
  readonly merchantOrigin: string;
  readonly intentApi: string;
  readonly receiptVerification: Readonly<{ version: "checkout-event/1"; algorithm: "Ed25519"; publicKey: string; eventPathTemplate: "/v1/intents/{id}/events" }>;
  readonly allowedPayerAssets: readonly NativeLightningAsset[];
  readonly acceptedReceiptAssets: readonly NativeLightningAsset[];
  readonly publicPolicy: Readonly<{ version: "native-lightning/1"; receiver: string; network: Network; maxBuyerExtraMsat: "0"; maxBuyerExtraBps: 0 }>;
  readonly routingProfiles: readonly Readonly<{ id: "native-lightning/1"; routeClass: "native" }>[];
  readonly approvedAdapters: readonly Readonly<{ id: "native-lightning"; version: "native-lightning/1" }>[];
}
function pinnedOrigin(origin: string): void {
  if (typeof origin !== "string" || origin.length > 255) throw new Error("Invalid manifest origin");
  const url = new URL(origin);
  if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password) throw new Error("Invalid manifest origin");
}
function pinnedKey(key: string): void {
  if (typeof key !== "string" || !/^[0-9a-f]{64}$/.test(key)) throw new Error("Invalid manifest key");
}
// Ordinary parsed JSON data only. Property getters/toJSON are refused; Proxy
// introspection traps are not isolated. Bound transport bytes before decoding.
// Bounds are local to this closed profile, not a general serialization API.
function snapshot(input: unknown, depth = 0, budget = { left: 200 }): unknown {
  if (--budget.left < 0 || depth > 8) throw new Error("Manifest data exceeds bounds");
  if (input === null || typeof input === "boolean" || (typeof input === "number" && Number.isFinite(input))) return input;
  if (typeof input === "string" && input.length <= 1024) return input;
  if (!input || typeof input !== "object") throw new Error("Invalid manifest data");
  const array = Array.isArray(input), prototype = Object.getPrototypeOf(input);
  if ((!array && prototype !== Object.prototype && prototype !== null) || (array && prototype !== Array.prototype)) throw new Error("Manifest must be JSON data");
  const descriptors = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string")) throw new Error("Invalid manifest fields");
  const length = array ? descriptors.length?.value : undefined;
  if ((array && (!Number.isSafeInteger(length) || length < 0 || length > 8 || keys.length !== length + 1)) || (!array && keys.length > 16)) throw new Error("Invalid manifest fields");
  const output: Record<string, unknown> | unknown[] = array ? [] : Object.create(null);
  for (const key of keys as string[]) {
    if (array && key === "length") continue;
    const field = descriptors[key]!;
    if (!Object.hasOwn(field, "value") || !field.enumerable || (array && !/^(0|[1-9][0-9]*)$/.test(key))) throw new Error("Manifest accessors or hidden fields refused");
    Object.defineProperty(output, key, { value: snapshot(field.value, depth + 1, budget), enumerable: true, configurable: true, writable: true });
  }
  return Object.freeze(output);
}
/** Caller must authenticate HTTPS delivery from the independently expected
 * origin. Public pin comparisons do not authenticate an unsigned manifest.
 * Advertised receiver/capabilities never replace invoice/order authorization.
 */
export function parseNativeLightningMerchantManifest(input: unknown, expectedOrigin: string, expectedPublicKey: string): Readonly<NativeLightningMerchantManifest> {
  try {
    pinnedOrigin(expectedOrigin); pinnedKey(expectedPublicKey);
    const captured = snapshot(input);
    if (!validate(captured)) throw new Error("Invalid manifest structure");
    const manifest = captured as NativeLightningMerchantManifest;
    if (manifest.merchantOrigin !== expectedOrigin || manifest.receiptVerification.publicKey !== expectedPublicKey || manifest.intentApi !== expectedOrigin + "/v1/intents") throw new Error("Manifest pins differ");
    if ([...manifest.allowedPayerAssets, ...manifest.acceptedReceiptAssets].some((asset) => asset.network !== manifest.publicPolicy.network || asset.id !== `LN_BTC_${manifest.publicPolicy.network.toUpperCase()}`)) throw new Error("Manifest network differs");
    return manifest;
  } catch { throw new Error("Native Lightning merchant manifest refused"); }
}

export function createNativeLightningMerchantManifest(origin: string, receiver: string, publicKey: string, network: Network): Readonly<NativeLightningMerchantManifest> {
  if (!NETWORKS.includes(network)) throw new Error("Unsupported manifest network");
  const asset = { id: `LN_BTC_${network.toUpperCase()}`, rail: "lightning", network, amountUnit: "msat", decimals: 11, quantum: "1000", tokenBehavior: "not_applicable" };
  return parseNativeLightningMerchantManifest({ version: "merchant-manifest/native-lightning/1", merchantOrigin: origin, intentApi: origin + "/v1/intents",
    receiptVerification: { version: "checkout-event/1", algorithm: "Ed25519", publicKey, eventPathTemplate: "/v1/intents/{id}/events" },
    allowedPayerAssets: [asset], acceptedReceiptAssets: [asset],
    publicPolicy: { version: "native-lightning/1", receiver, network, maxBuyerExtraMsat: "0", maxBuyerExtraBps: 0 },
    routingProfiles: [{ id: "native-lightning/1", routeClass: "native" }], approvedAdapters: [{ id: "native-lightning", version: "native-lightning/1" }] }, origin, publicKey);
}
