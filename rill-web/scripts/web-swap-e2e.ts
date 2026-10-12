/**
 * Drive the browser BTC to LN client (runSwap) against the disposable
 * regtest stack from scripts/regtest_e2e.py --web. Core's user wallet plays
 * the user's own wallet: it creates and finalizes the funding PSBT and
 * broadcasts; recovery files land in --out. Regtest only.
 */
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";

import { addressScript, scriptAddress } from "../src/swap/address";
import { RelayConnection } from "../src/swap/relay";
import { runSwap } from "../src/swap/swap";
import { memoryCosigner } from "./memoryCosigner";
import { executeMerchantSwap } from "../src/swap/merchantCheckout";
import { parseTerms } from "@rillswap/payments";
import type { CheckoutCheckpoint, CheckoutStore } from "@rillswap/payments/sdk";

async function main(): Promise<void> {
const { values } = parseArgs({
  options: {
    relay: { type: "string" },
    provider: { type: "string" },
    network: { type: "string" },
    invoice: { type: "string" },
    "core-port": { type: "string" },
    "core-cookie": { type: "string" },
    wallet: { type: "string" },
    recipient: { type: "string" },
    out: { type: "string" },
    "merchant-checkout": { type: "string" },
    "settle-timeout": { type: "string", default: "600" },
  },
});
const need = (name: keyof typeof values): string => {
  const value = values[name];
  if (typeof value !== "string" || value === "") throw new Error(`--${name} is required`);
  return value;
};

const network = JSON.parse(readFileSync(need("network"), "utf8")) as { name: string } & Record<string, unknown>;
if (network.name !== "regtest") throw new Error("the web e2e driver is regtest only");
const auth = `Basic ${btoa(readFileSync(need("core-cookie"), "utf8").trim())}`;
const walletUrl = `http://127.0.0.1:${need("core-port")}/wallet/${need("wallet")}`;

async function rpc<T>(method: string, params: unknown[] = []): Promise<T> {
  const response = await fetch(walletUrl, {
    method: "POST",
    headers: { authorization: auth, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "1.0", id: method, method, params }),
  });
  const body = (await response.json()) as { result: T; error: { message: string } | null };
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

const out = need("out");
const tipHeight = await rpc<number>("getblockcount");
const refundScript = addressScript(await rpc<string>("getnewaddress", ["", "bech32m"]), "regtest");
const relay = await RelayConnection.open(need("relay"));
const btc = (sats: bigint): string => `${sats / 100_000_000n}.${(sats % 100_000_000n).toString().padStart(8, "0")}`;
try {
  const request = {
      identity: need("provider"),
      network,
      invoice: need("invoice"),
      refundScript,
      tipHeight,
      ageRecipient: need("recipient"),
      limits: {
        maxSuccessFeeSat: 2000n,
        maxFundingFeeSat: 5000n,
        maxClaimFeeSat: 5000n,
        maxRefundFeeSat: 5000n,
        maxRefundDelayBlocks: 288,
      },
    };
  const hooks: Parameters<typeof runSwap>[2] = {
      report: (line) => { if (!values["merchant-checkout"]) console.error(`web: ${line}`); },
      saveRecovery: async (file, stage) => writeFileSync(join(out, `web-recovery-${stage}.age`), file, { mode: 0o600 }),
      fundingSource: async (request) => {
        const address = scriptAddress(request.contractScript, "regtest");
        const funded = await rpc<{ psbt: string }>("walletcreatefundedpsbt", [
          [],
          [{ [address]: btc(request.amountSat) }],
          0,
          { fee_rate: 2, change_type: "bech32" },
        ]);
        const signed = await rpc<{ psbt: string; complete: boolean }>("walletprocesspsbt", [funded.psbt, true]);
        if (!signed.complete) throw new Error("wallet did not finalize the PSBT");
        return { psbt: signed.psbt };
      },
      broadcast: async (raw, txid) => {
        const sent = await rpc<string>("sendrawtransaction", [raw]);
        if (sent !== txid) throw new Error("Core broadcast another transaction");
      },
      cosigner: memoryCosigner(),
    };
  if (values["merchant-checkout"]) {
    const checkout = JSON.parse(readFileSync(values["merchant-checkout"], "utf8")) as { id: string; status: string; attempt: { terms: unknown; invoice: string } };
    const terms = parseTerms(checkout.attempt.terms);
    if (checkout.id !== terms.intentId || checkout.status !== "waiting" || checkout.attempt.invoice !== request.invoice || terms.merchantOrigin !== "https://merchant.invalid" || terms.amountMsat !== "50000000") throw new Error("Diagnostic checkout mismatch");
    const checkpointPath = join(out, "merchant-checkpoint.json");
    const syncDirectory = () => { const fd = openSync(out, "r"); try { fsyncSync(fd); } finally { closeSync(fd); } };
    const write = (path: string, record: CheckoutCheckpoint) => {
      const fd = openSync(path, "wx", 0o600);
      try { writeFileSync(fd, JSON.stringify(record)); fsyncSync(fd); } finally { closeSync(fd); }
    };
    const store: CheckoutStore = {
      load: async () => existsSync(checkpointPath) ? JSON.parse(readFileSync(checkpointPath, "utf8")) : null,
      begin: async (record) => { try { write(checkpointPath, record); syncDirectory(); return true; }
        catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") return false; throw error; } },
      update: async (record) => {
        const old = JSON.parse(readFileSync(checkpointPath, "utf8")) as CheckoutCheckpoint;
        if (old.attemptId !== record.attemptId || old.intentId !== record.intentId) throw new Error("Diagnostic checkpoint identity changed");
        const path = checkpointPath + "." + crypto.randomUUID(); write(path, record); renameSync(path, checkpointPath); syncDirectory();
      },
    };
    const progress = await executeMerchantSwap({ terms, invoice: request.invoice, relay, request,
      policy: { version: "native-lightning/1", merchantOrigin: terms.merchantOrigin, receiver: terms.receiver, network: "regtest", maxBuyerExtraMsat: "17000000", maxBuyerExtraBps: 3400, approvedRillProviders: [request.identity] },
      hooks, recoveryStore: store,
      savePayerRecovery: async (file, stage) => {
        const name = `web-recovery-${stage === "provider_complete" ? "paid" : stage}.age`;
        const fd = openSync(join(out, name), "wx", 0o600);
        try { writeFileSync(fd, file); fsyncSync(fd); } finally { closeSync(fd); } syncDirectory(); return name;
      },
    });
    console.log(JSON.stringify(progress)); return;
  }
  const outcome = await runSwap(
    relay, request, hooks,
    { replyMs: 60_000, settleMs: Number(values["settle-timeout"]) * 1000 },
  );
  writeFileSync(join(out, "web-recovery-paid.age"), outcome.paidRecovery, { mode: 0o600 });
  const { paidRecovery: _paid, ...summary } = outcome;
  console.log(JSON.stringify(summary));
} finally {
  relay.close();
}
}
try { await main(); } catch (error) {
  if (!process.argv.some((arg) => arg === "--merchant-checkout" || arg.startsWith("--merchant-checkout="))) throw error;
  console.error("Merchant swap diagnostic refused"); process.exitCode = 1;
}
