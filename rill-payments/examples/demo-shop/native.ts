// Fake stablecoin rails (fUSDC, fUSDT) for the demo shop on the dev stack's
// Anvil chain, using the rill-payments native sandbox receipt rail. Each token
// gets its own ledger and service (one asset per store), mounted on its own
// loopback port because the service only accepts a numeric loopback transport.
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ContractFactory, FetchRequest, HDNodeWallet, JsonRpcProvider, keccak256 } from "ethers";
import { NativeReceiptLedger, type NativeLedgerConfig } from "../../src/nativeLedger";
import { createNativeSandboxService } from "../../src/nativeServer";
import { verifyNativeSandboxReceipt, type NativeSandboxTerms, type NativeSandboxView } from "../../src/nativeContract";

export const ANVIL_MNEMONIC = "test test test test test test test test test test test junk";
/** Anvil dev accounts: 0 deploys the tokens, 1 is the buyer, 2 receives shop revenue. */
export const anvilAccount = (index: number): HDNodeWallet =>
  HDNodeWallet.fromPhrase(ANVIL_MNEMONIC, undefined, `m/44'/60'/0'/0/${index}`);

export const STABLECOINS = [
  { rail: "fusdc", symbol: "fUSDC", name: "Fake USD Coin", port: 8791 },
  { rail: "fusdt", symbol: "fUSDT", name: "Fake Tether USD", port: 8792 },
] as const;
export type StablecoinRail = (typeof STABLECOINS)[number]["rail"];

const DECIMALS = 6;
const BUYER_GRANT = 1_000_000n * 10n ** BigInt(DECIMALS); // one million tokens
const INVENTORY_CAP = (10_000_000_000n * 10n ** BigInt(DECIMALS)).toString();

/** Everything a payer needs; the capabilities are the buyer's credentials. */
export interface NativeCheckout {
  readonly transportOrigin: string;
  readonly intentId: string;
  readonly readCapability: string;
  readonly paymentCapability: string;
  readonly terms: NativeSandboxTerms;
}

export interface TokenRail {
  readonly rail: StablecoinRail;
  readonly symbol: string;
  readonly token: string;
  readonly publicKey: string;
  create(orderRef: string, amountBaseUnits: string, expiresAt: number): Promise<NativeCheckout>;
  /** The service's view, and its signed receipt event only if it verifies. */
  view(checkout: NativeCheckout): Promise<{ view: NativeSandboxView; verified: boolean }>;
}

/** Token amount in base units for a USD price (1 token = 1 USD). */
export const tokenBaseUnits = (usdCents: number): string => (BigInt(usdCents) * 10n ** BigInt(DECIMALS - 2)).toString();

export function anvilProvider(url: string): JsonRpcProvider {
  const request = new FetchRequest(url);
  request.timeout = 10_000;
  return new JsonRpcProvider(request, undefined, { cacheTimeout: -1, batchMaxCount: 1, staticNetwork: true });
}

function privateDir(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
}

/** Read a private file, creating it once with `create()` if absent. */
function privateFile(path: string, create: () => string | Uint8Array): Buffer {
  if (!existsSync(path)) writeFileSync(path, create(), { mode: 0o600, flag: "wx" });
  return readFileSync(path);
}

async function deployToken(rpc: JsonRpcProvider, spec: (typeof STABLECOINS)[number], artifact: { abi: unknown[]; bytecode: string }) {
  const deployer = anvilAccount(0).connect(rpc);
  const factory = new ContractFactory(artifact.abi as never, artifact.bytecode, deployer);
  const contract = await factory.deploy(spec.name, spec.symbol);
  await contract.waitForDeployment();
  const token = (await contract.getAddress()).toLowerCase();
  const minted = await deployer.sendTransaction({
    to: token,
    data: factory.interface.encodeFunctionData("mint", [anvilAccount(1).address, BUYER_GRANT]),
  });
  await minted.wait();
  console.log(`deployed ${spec.symbol} at ${token}, granted ${BUYER_GRANT / 10n ** BigInt(DECIMALS)} to the buyer`);
  return token;
}

/**
 * Sets up both token rails. State per token in `<state>/shop/native/<rail>/`:
 * config.json (written once after the token deploys) and ledger.sqlite
 * (provisioned right after). A token with neither file is set up; partial
 * state, missing keys or a chain that no longer matches the config disable
 * the rail. Nothing is ever redeployed or reprovisioned over existing state.
 */
export async function startStablecoins(state: string, rpcUrl: string, origin: string): Promise<TokenRail[]> {
  const home = `${state}/shop/native`;
  privateDir(home);
  // Keys are created only before any token exists: replacing them later would
  // orphan existing capabilities and receipt signatures.
  const initialized = STABLECOINS.some((spec) =>
    existsSync(`${home}/${spec.rail}/config.json`) || existsSync(`${home}/${spec.rail}/ledger.sqlite`));
  const missingKeys = ["admin.token", "capability.key", "event.key"].filter((name) => !existsSync(`${home}/${name}`));
  if (initialized && missingKeys.length) {
    throw new Error(`${missingKeys.join(", ")} missing from initialized ${home}; reset the stack (dev/devctl reset)`);
  }
  const adminToken = privateFile(`${home}/admin.token`, () => randomBytes(32).toString("base64url")).toString().trim();
  const capabilityKey = new Uint8Array(privateFile(`${home}/capability.key`, () => randomBytes(32)));
  const eventKey = new Uint8Array(privateFile(`${home}/event.key`, () => randomBytes(32)));
  const publicKey = bytesToHex(ed25519.getPublicKey(eventKey));
  const artifact = JSON.parse(readFileSync(new URL("./dev-stablecoin.json", import.meta.url), "utf8")) as {
    abi: unknown[]; bytecode: string; runtimeBytecode: string;
  };
  const rpc = anvilProvider(rpcUrl);
  const genesisHash = (await rpc.getBlock(0))!.hash!.toLowerCase();
  const rails: TokenRail[] = [];
  for (const spec of STABLECOINS) {
    try {
      const dir = `${home}/${spec.rail}`;
      privateDir(dir);
      const configPath = `${dir}/config.json`;
      const ledgerPath = `${dir}/ledger.sqlite`;
      const [hasConfig, hasLedger] = [existsSync(configPath), existsSync(ledgerPath)];
      // Only a token with neither file is set up; any partial state could hide
      // a lost ledger, so it disables the rail instead of replacing anything.
      if (hasConfig !== hasLedger) {
        throw new Error(`${hasConfig ? ledgerPath : configPath} is missing; reset the stack (dev/devctl reset)`);
      }
      if (!hasConfig) {
        const token = await deployToken(rpc, spec, artifact);
        const config: NativeLedgerConfig = {
          origin,
          recipient: anvilAccount(2).address.toLowerCase(),
          inventoryCapBaseUnits: INVENTORY_CAP,
          asset: {
            id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash, token, decimals: DECIMALS,
            behavior: "standard_erc20", runtimeCodeHash: keccak256(artifact.runtimeBytecode), implementation: null,
            historicalStateVerified: true, behaviorConformanceVerified: true,
            localSandbox: { version: "anvil-local/1", namespace: randomBytes(24).toString("base64url"), confirmations: 6 },
          },
        };
        writeFileSync(configPath, JSON.stringify(config, null, 1) + "\n", { mode: 0o600, flag: "wx" });
      }
      const config = JSON.parse(readFileSync(configPath, "utf8")) as NativeLedgerConfig;
      if (config.asset.genesisHash !== genesisHash || keccak256(await rpc.getCode(config.asset.token)) !== config.asset.runtimeCodeHash) {
        throw new Error(`Anvil chain no longer matches ${configPath}; reset the stack (dev/devctl reset)`);
      }
      const ledger = hasLedger ? NativeReceiptLedger.open(ledgerPath, config) : NativeReceiptLedger.provision(ledgerPath, config);
      const transportOrigin = `http://127.0.0.1:${spec.port}`;
      const service = createNativeSandboxService({ ledger, provider: rpc, adminToken, capabilityKey, eventSigningKey: eventKey, transportOrigin });
      Bun.serve({ hostname: "127.0.0.1", port: spec.port, fetch: (request) => service.fetch(request) });
      const call = async (path: string, bearer: string, body?: unknown, idempotencyKey?: string) => {
        const headers: Record<string, string> = { Authorization: `Bearer ${bearer}` };
        if (body !== undefined) headers["Content-Type"] = "application/json";
        if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
        const response = await fetch(transportOrigin + path, { method: body === undefined ? "GET" : "POST", headers, body: body === undefined ? undefined : JSON.stringify(body) });
        if (!response.ok) throw new Error(`${spec.symbol} service ${path}: HTTP ${response.status}`);
        return (await response.json()) as Record<string, any>;
      };
      rails.push({
        rail: spec.rail, symbol: spec.symbol, token: config.asset.token, publicKey,
        async create(orderRef, amountBaseUnits, expiresAt) {
          const created = await call("/v1/native-sandbox/intents", adminToken, { orderRef, amountBaseUnits, expiresAt }, `${orderRef}-native-intent`);
          const terms = created.view.terms as NativeSandboxTerms;
          return { transportOrigin, intentId: terms.intentId, readCapability: created.readCapability, paymentCapability: created.paymentCapability, terms };
        },
        async view(checkout) {
          const view = (await call(`/v1/native-sandbox/intents/${checkout.intentId}`, checkout.readCapability)) as NativeSandboxView;
          return { view, verified: view.event !== null && verifyNativeSandboxReceipt(view.event, publicKey, checkout.terms) };
        },
      });
      console.log(`${spec.symbol} rail ready: token ${config.asset.token}, service ${transportOrigin}`);
    } catch (error) {
      console.error(`${spec.symbol} rail unavailable: ${(error as Error).message}`);
    }
  }
  return rails;
}
