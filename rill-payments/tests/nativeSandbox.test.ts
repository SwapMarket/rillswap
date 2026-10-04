import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Database } from "bun:sqlite";
import { ContractFactory, FetchRequest, HDNodeWallet, Interface, JsonRpcProvider, keccak256 } from "ethers";
import { NativeReceiptLedger, type NativeIntent, type NativeLedgerConfig } from "../src/nativeLedger";
import { observeEvmReceipt, prepareEvmBinding, receiptBindingTypedData, type EvmReceiptBinding } from "../src/evmReceipt";
import { createNativeSandboxService } from "../src/nativeServer";
import { verifyNativeSandboxReceipt, type NativeSandboxView } from "../src/nativeContract";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { createNativeSandboxCheckout, type NativeSandboxCheckpoint, type NativeSandboxTransfer, type NativeSandboxWallet } from "../src/nativeSdk";
import type { CheckoutStore } from "../src/sdk";
import artifact from "./fixtures/sandbox-token.json";

const ANVIL_SHA256 = "be5129d636ea18440d43908536f13ba6578859b695f2ca33f1f09a00aa9dc176";
const ANVIL_COMMIT = "50af4efe189dc64bad2b75ed6990b835de66c4ae";
const MNEMONIC = "test test test test test test test test test test test junk"; // Public, disposable wallets only.
const sandboxTest = process.env.RILLSWAP_RUN_NATIVE_SANDBOX === "1" ? test : test.skip;

async function startSandbox(directory: string) {
  if (process.platform !== "linux" || process.arch !== "x64") throw new Error("Pinned native sandbox currently requires Linux amd64");
  const executable = resolve(import.meta.dir, "../../tmp/toolchains/foundry-v1.8.4/anvil");
  if (createHash("sha256").update(readFileSync(executable)).digest("hex") !== ANVIL_SHA256) throw new Error("Anvil binary checksum mismatch; install the pinned archive");
  const version = Bun.spawnSync([executable, "--version"]);
  if (version.exitCode !== 0 || !version.stdout.toString().includes("anvil Version: 1.8.4\n") || !version.stdout.toString().includes(ANVIL_COMMIT)) throw new Error("Anvil version mismatch");
  const child = spawn(executable, ["--host", "127.0.0.1", "--port", "0", "--chain-id", "31337", "--hardfork", "prague", "--timestamp", "1700000000",
    "--accounts", "2", "--balance", "10000", "--mnemonic", MNEMONIC, "--gas-price", "0", "--base-fee", "0", "--disable-min-priority-fee", "--no-mining",
    "--max-persisted-states", "0", "--cache-path", directory + "/cache"],
  { env: { HOME: directory, XDG_CACHE_HOME: directory, NO_COLOR: "1", RUST_LOG: "off" }, stdio: ["ignore", "pipe", "pipe"] });
  let exited = false;
  const finished = new Promise<void>((done) => child.once("close", () => { exited = true; done(); }));
  const stop = async () => {
    if (!exited) {
      child.kill("SIGTERM");
      const timer = setTimeout(() => { if (!exited) child.kill("SIGKILL"); }, 2000);
      try { await finished; } finally { clearTimeout(timer); }
    }
  };
  try {
    const port = await new Promise<number>((done, fail) => {
      let output = "";
      const timer = setTimeout(() => fail(new Error("Anvil loopback startup timed out")), 10000);
      child.once("error", (error) => { clearTimeout(timer); fail(error); });
      child.once("exit", () => { clearTimeout(timer); fail(new Error("Owned Anvil exited before readiness")); });
      child.stderr.on("data", (chunk: Buffer) => appendFileSync(directory + "/anvil.log", chunk));
      child.stdout.on("data", (chunk: Buffer) => {
        appendFileSync(directory + "/anvil.log", chunk);
        if (output.length > 65536) return;
        output += chunk.toString();
        const match = /^Listening on 127\.0\.0\.1:([0-9]+)\r?$/m.exec(output);
        if (match) { clearTimeout(timer); const port = Number(match[1]); if (port > 0 && port < 65536) done(port); else fail(new Error("Invalid owned loopback listener")); }
      });
    });
    const request = new FetchRequest(`http://127.0.0.1:${port}`); request.timeout = 5000;
    const provider = new JsonRpcProvider(request, undefined, { cacheTimeout: -1, batchMaxCount: 1 });
    try {
      if (exited || await provider.send("eth_chainId", []) !== "0x7a69") throw new Error("Owned sandbox identity mismatch");
      return { provider, stop: async () => { provider.destroy(); await stop(); } };
    } catch (error) { provider.destroy(); throw error; }
  } catch (error) { await stop(); throw error; }
}

sandboxTest("real disposable ERC20 debit, local confirmation boundary, ledger restart and reorg impairment", async () => {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/native-sandbox-"));
  let sandbox: Awaited<ReturnType<typeof startSandbox>> | undefined, ledger: NativeReceiptLedger | undefined;
  try {
    sandbox = await startSandbox(directory); const { provider } = sandbox;
    const payer = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/0");
    const recipient = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/1").address.toLowerCase();
    const tokenAbi = new Interface(artifact.abi);
    const factory = new ContractFactory(artifact.abi, artifact.bytecode);
    const deployment = await factory.getDeployTransaction(10_000_000n);
    const rawDeploy = await payer.signTransaction({ ...deployment, chainId: 31337n, nonce: 0, type: 2, gasLimit: 2_000_000n, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
    const deployed = await provider.broadcastTransaction(rawDeploy); await provider.send("evm_mine", []);
    const deploymentReceipt = await provider.getTransactionReceipt(deployed.hash);
    expect(deploymentReceipt?.status).toBe(1); if (!deploymentReceipt?.contractAddress) throw new Error("Missing disposable token deployment");
    const token = deploymentReceipt.contractAddress.toLowerCase();
    const genesis = await provider.getBlock(0); if (!genesis?.hash) throw new Error("Missing local genesis");
    expect(await provider.getCode(token, 0)).toBe("0x");
    expect(await provider.getCode(token, deploymentReceipt.blockNumber)).toBe(artifact.runtimeBytecode);
    const config: NativeLedgerConfig = { origin: "https://sandbox.invalid", recipient, inventoryCapBaseUnits: "10000000", asset: {
      id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash: genesis.hash.toLowerCase(), token, decimals: 6, behavior: "standard_erc20",
      runtimeCodeHash: keccak256(artifact.runtimeBytecode), implementation: null, historicalStateVerified: true, behaviorConformanceVerified: true,
      localSandbox: { version: "anvil-local/1", namespace: randomBytes(24).toString("base64url"), confirmations: 6 },
    } };
    const path = directory + "/native.sqlite";
    expect(() => NativeReceiptLedger.open(path, config)).toThrow(); ledger = NativeReceiptLedger.provision(path, config);
    expect(Object.isFrozen(ledger.config.asset.localSandbox)).toBe(true);
    const wrongNamespace = { ...config, asset: { ...config.asset, localSandbox: { ...config.asset.localSandbox!, namespace: "another_sandbox_namespace" } } };
    expect(() => NativeReceiptLedger.open(path, wrongNamespace)).toThrow("config mismatch");

    let now = (await provider.getBlock("latest"))!.timestamp;
    const sign = async (intent: NativeIntent) => {
      const nonce = await provider.getTransactionCount(payer.address, "pending");
      const binding: EvmReceiptBinding = { version: "evm-receipt-binding/1", merchantOrigin: config.origin, intentId: intent.intentId, attemptId: intent.attemptId, assetId: config.asset.id,
        sourceWallet: payer.address.toLowerCase(), sourceNonce: nonce.toString(), recipient, amountBaseUnits: intent.amountBaseUnits, validAfter: intent.createdAt, validBefore: intent.expiresAt };
      const typed = receiptBindingTypedData(config.asset, binding); return { binding, signature: await payer.signTypedData(typed.domain, typed.types, typed.value) };
    };
    const send = async (binding: EvmReceiptBinding, mineAt: number) => {
      const raw = await payer.signTransaction({ to: token, data: tokenAbi.encodeFunctionData("transfer", [recipient, BigInt(binding.amountBaseUnits)]), nonce: Number(binding.sourceNonce),
        chainId: 31337n, type: 2, value: 0n, gasLimit: 100000n, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
      const sent = await provider.broadcastTransaction(raw);
      await provider.send("evm_setNextBlockTimestamp", [mineAt]); await provider.send("evm_mine", []); now = mineAt;
      return sent.hash;
    };
    const intent = ledger.createIntent("sandbox-order-one", "1000000", now + 3600, "sandbox_intent_key_01", now), signed = await sign(intent);
    await expect(prepareEvmBinding({ ...config.asset, genesisHash: "0x" + "f".repeat(64) }, intent, signed.binding, signed.signature, provider, () => now)).rejects.toThrow("Wrong receipt network");
    const canonicalAsset = { ...config.asset, id: `eip155:11155111/erc20:${token}`, chainId: "11155111", genesisHash: "0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9", localSandbox: undefined };
    const canonicalBinding = { ...signed.binding, assetId: canonicalAsset.id }, canonicalTyped = receiptBindingTypedData(canonicalAsset, canonicalBinding);
    await expect(prepareEvmBinding(canonicalAsset, { ...intent, assetId: canonicalAsset.id }, canonicalBinding,
      await payer.signTypedData(canonicalTyped.domain, canonicalTyped.types, canonicalTyped.value), provider, () => now)).rejects.toThrow("Wrong receipt network");
    const prepared = await ledger.prepare(intent.intentId, signed.binding, signed.signature, "sandbox_attempt_key_01", provider, () => now);
    expect(ledger.inventory().reserved).toBe("1000000");
    // All connections close before a real send. Preparation provenance survives.
    ledger.close(); ledger = NativeReceiptLedger.open(path, config); expect(ledger.getPreparation(intent.attemptId)).toEqual(prepared);
    const hash = await send(signed.binding, now + 1);
    const actualReceipt = await provider.getTransactionReceipt(hash); if (!actualReceipt) throw new Error("Missing actual sandbox debit");
    const balanceAt = async (blockTag: number) => BigInt(tokenAbi.decodeFunctionResult("balanceOf", await provider.call({ to: token, data: tokenAbi.encodeFunctionData("balanceOf", [recipient]), blockTag }))[0]);
    expect(await balanceAt(deploymentReceipt.blockNumber)).toBe(0n); expect(await balanceAt(actualReceipt.blockNumber)).toBe(1000000n);
    expect((await ledger.observe(intent.attemptId, hash, provider, () => now)).status).toBe("waiting");
    expect(ledger.pendingEvents()).toHaveLength(0);
    await provider.send("anvil_mine", ["0x4", "0x1"]); now += 4;
    expect((await ledger.observe(intent.attemptId, hash, provider, () => now)).status).toBe("waiting");
    await provider.send("anvil_mine", ["0x1", "0x1"]); now++;
    const verified = await observeEvmReceipt(config.asset, intent, prepared, hash, provider);
    expect(verified?.finality).toBe("local_sandbox_confirmed"); expect(verified?.deduplicationKey).toContain(":sandbox:" + config.asset.localSandbox!.namespace + ":");
    expect((await ledger.observe(intent.attemptId, hash, provider, () => now)).status).toBe("paid");
    const acceptance = ledger.pendingEvents()[0]!; expect(ledger.inventory()).toEqual({ held: "1000000", reserved: "0", impaired: "0" });
    ledger.close(); ledger = NativeReceiptLedger.open(path, config);
    expect(ledger.pendingEvents()).toEqual([acceptance]); await ledger.observe(intent.attemptId, hash, provider, () => now); expect(ledger.pendingEvents()).toEqual([acceptance]);
    expect(BigInt(tokenAbi.decodeFunctionResult("balanceOf", await provider.call({ to: token, data: tokenAbi.encodeFunctionData("balanceOf", [recipient]) }))[0])).toBe(1000000n);

    const lateIntent = ledger.createIntent("sandbox-late", "1000000", now + 10, "sandbox_late_intent_01", now), lateSigned = await sign(lateIntent);
    await ledger.prepare(lateIntent.intentId, lateSigned.binding, lateSigned.signature, "sandbox_late_attempt_01", provider, () => now);
    const lateHash = await send(lateSigned.binding, lateIntent.expiresAt); await provider.send("anvil_mine", ["0x5", "0x1"]); now += 5;
    expect((await ledger.observe(lateIntent.attemptId, lateHash, provider, () => now)).status).toBe("reconciliation");
    expect(ledger.inventory().held).toBe("2000000"); expect(ledger.pendingEvents()).toEqual([acceptance]);

    const reorgIntent = ledger.createIntent("sandbox-reorg", "1000000", now + 3600, "sandbox_reorg_intent_01", now), reorgSigned = await sign(reorgIntent);
    const reorgPrepared = await ledger.prepare(reorgIntent.intentId, reorgSigned.binding, reorgSigned.signature, "sandbox_reorg_attempt_01", provider, () => now);
    const snapshot = await provider.send("evm_snapshot", []), reorgHash = await send(reorgSigned.binding, now + 1);
    await provider.send("anvil_mine", ["0x5", "0x1"]); now += 5;
    expect((await ledger.observe(reorgIntent.attemptId, reorgHash, provider, () => now)).status).toBe("paid");
    const originalReceipt = await provider.getTransactionReceipt(reorgHash); if (!originalReceipt) throw new Error("Missing pre-reorg transfer");
    expect(await provider.send("evm_revert", [snapshot])).toBe(true);
    await provider.send("evm_setNextBlockTimestamp", [now + 100]); await provider.send("evm_mine", []);
    expect((await provider.getBlock(originalReceipt.blockNumber))?.hash).not.toBe(originalReceipt.blockHash);
    // An orphaned transaction is absent or unconfirmed, never independently verifiable credit.
    expect(await observeEvmReceipt(config.asset, reorgIntent, reorgPrepared, reorgHash, provider)).toBeNull();
    const reorgEvent = ledger.pendingEvents().find((event) => event.intentId === reorgIntent.intentId)!;
    ledger.recordReorg(reorgEvent.receiptKey); expect(ledger.getIntent(reorgIntent.intentId).status).toBe("paid");
    expect(ledger.inventory()).toEqual({ held: "2000000", reserved: "0", impaired: "1000000" });
    const db = new Database(path, { readonly: true });
    try { const row = db.query("SELECT payload FROM receipts WHERE key=?").get(acceptance.receiptKey) as { payload: string };
      expect(JSON.parse(row.payload).finality).toBe("local_sandbox_confirmed"); } finally { db.close(); }
    expect(BigInt(tokenAbi.decodeFunctionResult("balanceOf", await provider.call({ to: token, data: tokenAbi.encodeFunctionData("balanceOf", [recipient]) }))[0])).toBe(2000000n);
  } finally {
    ledger?.close(); if (sandbox) await sandbox.stop(); rmSync(directory, { recursive: true, force: true });
  }
}, 90000);

sandboxTest("sandbox-only native HTTP API records actual token receipt and stable signed event across restart", async () => {
  mkdirSync("tmp", { recursive: true }); const directory = mkdtempSync(resolve("tmp/native-http-"));
  let sandbox: Awaited<ReturnType<typeof startSandbox>> | undefined, ledger: NativeReceiptLedger | undefined, listener: { stop(closeActiveConnections?: boolean): void } | undefined;
  try {
    sandbox = await startSandbox(directory); const { provider } = sandbox;
    const payer = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/0"), recipient = HDNodeWallet.fromPhrase(MNEMONIC, undefined, "m/44'/60'/0'/0/1").address.toLowerCase();
    const factory = new ContractFactory(artifact.abi, artifact.bytecode), abi = new Interface(artifact.abi);
    const deploy = await factory.getDeployTransaction(10_000_000n);
    const deployed = await provider.broadcastTransaction(await payer.signTransaction({ ...deploy, type: 2, chainId: 31337n, nonce: 0, gasLimit: 2_000_000n, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n }));
    await provider.send("evm_mine", []); const receipt = await provider.getTransactionReceipt(deployed.hash);
    expect(receipt?.status).toBe(1); if (!receipt?.contractAddress) throw new Error("Missing HTTP fixture deployment");
    const token = receipt.contractAddress.toLowerCase(), genesis = await provider.getBlock(0); if (!genesis?.hash) throw new Error("Missing HTTP fixture genesis");
    const config: NativeLedgerConfig = { origin: "https://sandbox.invalid", recipient, inventoryCapBaseUnits: "10000000", asset: {
      id: `eip155:31337/erc20:${token}`, chainId: "31337", genesisHash: genesis.hash.toLowerCase(), token, decimals: 6, behavior: "standard_erc20", runtimeCodeHash: keccak256(artifact.runtimeBytecode),
      implementation: null, historicalStateVerified: true, behaviorConformanceVerified: true, localSandbox: { version: "anvil-local/1", namespace: randomBytes(24).toString("base64url"), confirmations: 6 },
    } };
    const path = directory + "/native.sqlite"; ledger = NativeReceiptLedger.provision(path, config); let now = (await provider.getBlock("latest"))!.timestamp;
    const adminToken = "native_sandbox_http_admin_fixture_01", capabilityKey = new Uint8Array(32).fill(3), eventSigningKey = new Uint8Array(32).fill(4);
    const expectedPublicKey = bytesToHex(ed25519.getPublicKey(eventSigningKey));
    let mountedOrigin = "";
    const mount = () => {
      let service: ReturnType<typeof createNativeSandboxService> | undefined;
      const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: (request) => service ? service.fetch(request) : new Response(null, { status: 503 }) }); listener = server;
      const origin = `http://127.0.0.1:${server.port}`;
      mountedOrigin = origin;
      service = createNativeSandboxService({ ledger: ledger!, provider, adminToken, capabilityKey, eventSigningKey, transportOrigin: origin, now: () => now });
      return async (route: string, bearer: string, method = "GET", body?: unknown, key?: string) => fetch(origin + route, { method,
        headers: { Authorization: "Bearer " + bearer, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...(key ? { "Idempotency-Key": key } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body) });
    };
    let request = mount(); const created = await request("/v1/native-sandbox/intents", adminToken, "POST", { orderRef: "http-sandbox-order", amountBaseUnits: "1000000", expiresAt: now + 3600 }, "native_http_intent_01");
    expect(created.status).toBe(201); const checkout = await created.json() as { view: NativeSandboxView; readCapability: string; paymentCapability: string };
    const terms = checkout.view.terms, route = "/v1/native-sandbox/intents/" + terms.intentId;
    expect((await request(route + "/prepare", checkout.readCapability, "POST", {})).status).toBe(403);
    const binding: EvmReceiptBinding = { version: "evm-receipt-binding/1", merchantOrigin: terms.merchantOrigin, intentId: terms.intentId, attemptId: terms.attemptId, assetId: terms.asset.id,
      sourceWallet: payer.address.toLowerCase(), sourceNonce: (await provider.getTransactionCount(payer.address, "pending")).toString(), recipient, amountBaseUnits: terms.amountBaseUnits, validAfter: terms.createdAt, validBefore: terms.expiresAt };
    const typed = receiptBindingTypedData(terms.asset, binding), signature = await payer.signTypedData(typed.domain, typed.types, typed.value);
    expect((await request(route + "/prepare", checkout.paymentCapability, "POST", { binding, signature }, "native_http_prepare_01")).status).toBe(201);
    const preparation = ledger.getPreparation(terms.attemptId); listener!.stop(true); ledger.close(); ledger = NativeReceiptLedger.open(path, config); request = mount();
    expect(ledger.getPreparation(terms.attemptId)).toEqual(preparation);
    const raw = await payer.signTransaction({ type: 2, chainId: 31337n, to: token, value: 0n, nonce: Number(binding.sourceNonce), data: abi.encodeFunctionData("transfer", [recipient, 1000000n]), gasLimit: 100000n, maxFeePerGas: 0n, maxPriorityFeePerGas: 0n });
    const sent = await provider.broadcastTransaction(raw); await provider.send("evm_setNextBlockTimestamp", [now + 1]); await provider.send("evm_mine", []); now++;
    const pending = await (await request(route + "/observe", checkout.paymentCapability, "POST", { txHash: sent.hash })).json() as NativeSandboxView;
    expect(pending.status).toBe("awaiting_funds"); expect(pending.event).toBeNull();
    await provider.send("anvil_mine", ["0x5", "0x1"]); now += 5;
    const observed = await request(route + "/observe", checkout.paymentCapability, "POST", { txHash: sent.hash }); expect(observed.status).toBe(200);
    const recorded = await observed.json() as NativeSandboxView;
    expect(recorded.status).toBe("sandbox_receipt_recorded"); expect(recorded.event?.event.scope).toBe("local_sandbox_only");
    expect(verifyNativeSandboxReceipt(recorded.event!, expectedPublicKey, terms)).toBe(true);
    expect(ledger.inventory()).toEqual({ held: "1000000", reserved: "0", impaired: "0" });
    listener!.stop(true); ledger.close(); ledger = NativeReceiptLedger.open(path, config); request = mount();
    const reopened = await (await request(route, checkout.readCapability)).json() as NativeSandboxView; expect(reopened.event).toEqual(recorded.event);
    expect(JSON.stringify(reopened)).not.toContain(checkout.paymentCapability); expect(JSON.stringify(reopened)).not.toContain(signature);

    const sdkCreated = await request("/v1/native-sandbox/intents", adminToken, "POST", { orderRef: "http-sdk-order", amountBaseUnits: "1000000", expiresAt: now + 3600 }, "native_http_sdk_intent_01");
    expect(sdkCreated.status).toBe(201); const sdkCheckout = await sdkCreated.json() as typeof checkout;
    const operations = directory + "/payer-operations"; mkdirSync(operations, { mode: 0o700 }); let broadcasts = 0;
    const privateOperation = (id: string) => operations + "/" + id + ".json";
    const wallet: NativeSandboxWallet = { version: "native-sandbox-wallet/1", durableOperationIdentity: true, guardedFeeCaps: true,
      identity: async () => ({ chainId: (await provider.getNetwork()).chainId.toString(), genesisHash: (await provider.getBlock(0))!.hash!.toLowerCase(),
        sourceWallet: payer.address.toLowerCase(), sourceNonce: (await provider.getTransactionCount(payer.address, "pending")).toString() }),
      signBinding: async (_id, _binding, value) => payer.signTypedData(value.domain, value.types, value.value),
      dispatch: async (id, planned, guard) => {
        await guard("sign"); const raw = await payer.signTransaction({ type: 2, chainId: BigInt(planned.chainId), from: planned.from, to: planned.to, value: 0n, nonce: planned.nonce,
          data: planned.data, gasLimit: BigInt(planned.gasLimit), maxFeePerGas: BigInt(planned.maxFeePerGasWei), maxPriorityFeePerGas: BigInt(planned.maxPriorityFeePerGasWei) });
        const record = { request: planned, raw, hash: keccak256(raw) };
        if (existsSync(privateOperation(id))) { const previous = JSON.parse(readFileSync(privateOperation(id), "utf8")) as typeof record;
          if (JSON.stringify(previous) !== JSON.stringify(record)) throw new Error("Immutable wallet operation changed"); }
        else writeFileSync(privateOperation(id), JSON.stringify(record), { mode: 0o600, flag: "wx" });
        await guard("broadcast"); await provider.broadcastTransaction(raw); broadcasts++;
        throw new Error("simulated lost actual broadcast response");
      }, lookup: async (id) => existsSync(privateOperation(id)) ? (JSON.parse(readFileSync(privateOperation(id), "utf8")) as { hash: string }).hash : null,
    };
    const checkpointPath = directory + "/browser-checkpoint.json";
    const store: CheckoutStore<NativeSandboxCheckpoint> = {
      load: async () => existsSync(checkpointPath) ? JSON.parse(readFileSync(checkpointPath, "utf8")) : null,
      begin: async (record) => { try { writeFileSync(checkpointPath, JSON.stringify(record), { mode: 0o600, flag: "wx" }); return true; }
        catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") return false; throw error; } },
      update: async (record) => writeFileSync(checkpointPath, JSON.stringify(record), { mode: 0o600 }),
    };
    const sdkOrigin = mountedOrigin;
    const sdkOptions = { intentUrl: sdkOrigin + "/v1/native-sandbox/intents/" + sdkCheckout.view.terms.intentId, transportOrigin: sdkOrigin,
      paymentCapability: sdkCheckout.paymentCapability, terms: sdkCheckout.view.terms, merchantPublicKey: expectedPublicKey, maxTokenBaseUnits: "1000000", gasLimit: "100000",
      maxFeePerGasWei: "1", maxPriorityFeePerGasWei: "0", maxGasCostWei: "100000", wallet, recoveryStore: store, now: () => now };
    await expect(createNativeSandboxCheckout(sdkOptions).pay()).rejects.toThrow("lost actual broadcast");
    const checkpoint = await store.load(sdkOptions.terms.attemptId); expect(checkpoint?.stage).toBe("ambiguous"); expect(checkpoint?.transactionHash).toBeNull();
    const privateRecord = JSON.parse(readFileSync(privateOperation(checkpoint!.operationId), "utf8")) as { request: NativeSandboxTransfer; raw: string; hash: string };
    expect(JSON.stringify(checkpoint)).not.toContain(privateRecord.raw); expect(JSON.stringify(checkpoint)).not.toContain(sdkCheckout.paymentCapability);
    expect(await provider.getTransactionCount(payer.address, "pending")).toBe(Number(checkpoint!.binding!.sourceNonce) + 1);
    const recoveredClient = createNativeSandboxCheckout(sdkOptions); expect((await recoveredClient.open()).recovery).toBe("tracking"); expect(broadcasts).toBe(1);
    await provider.send("evm_setNextBlockTimestamp", [now + 1]); await provider.send("evm_mine", []); await provider.send("anvil_mine", ["0x5", "0x1"]); now += 6;
    expect((await recoveredClient.open()).view.status).toBe("sandbox_receipt_recorded");
    await expect(recoveredClient.pay()).rejects.toThrow("not payable"); expect(broadcasts).toBe(1);
    expect(ledger.inventory()).toEqual({ held: "2000000", reserved: "0", impaired: "0" });
  } finally { listener?.stop(true); ledger?.close(); if (sandbox) await sandbox.stop(); rmSync(directory, { recursive: true, force: true }); }
}, 90000);
