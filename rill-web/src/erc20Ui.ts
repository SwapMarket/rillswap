/**
 * RS-010 browser UI pieces: token amount formatting, the wallet-driven lock
 * (approve, then lock), and the recovery view with a wallet refund after the
 * timelock. The injected wallet signs; this page only reads the chain.
 */
import { type Erc20SwapOutcome, type EvmRecoveryRecord, parseEvmRecovery, type PreparedErc20Swap } from "./swap/erc20Swap";
import {
  awaitReceipt, encodeApprove, encodeLock, encodeRefund, EvmError, EvmRpc, EvmWallet, type HtlcLock, injectedProvider,
} from "./swap/evmHtlc";
import type { EvmAssetIdentity } from "./manualProviderAdvertisement";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", id = ""): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag); e.textContent = text; if (id) e.id = id; return e;
}

/** `1005000` with 6 decimals is `1.005`; trailing zeros are dropped. */
export function formatTokenAmount(base: bigint, decimals: number): string {
  const unit = 10n ** BigInt(decimals);
  const whole = base / unit, fraction = (base % unit).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}

/** Decimal token text to base units; more fraction digits than the token has are refused. */
export function parseTokenAmount(text: string, decimals: number, what: string): bigint {
  const match = /^(0|[1-9][0-9]{0,17})(?:\.([0-9]{1,18}))?$/.exec(text.trim());
  if (!match || (match[2] ?? "").length > decimals) throw new Error(`${what} must be a decimal amount with at most ${decimals} fraction digits`);
  return BigInt(match[1]!) * 10n ** BigInt(decimals) + BigInt((match[2] ?? "").padEnd(decimals, "0") || "0");
}

export const tokenLabel = (base: bigint, asset: EvmAssetIdentity): string =>
  `${formatTokenAmount(base, asset.token_decimals)} ${asset.token_symbol}`;

export class WalletRefusedError extends Error {
  constructor(message: string) { super(message); this.name = "WalletRefusedError"; }
}

/** Connect the injected wallet on the asset's chain; the RPC must agree on the chain id. */
export async function connectEvmWallet(rpc: EvmRpc, asset: EvmAssetIdentity): Promise<{ wallet: EvmWallet; account: string }> {
  const provider = injectedProvider();
  if (provider === null) throw new WalletRefusedError("No EVM wallet found in this browser. Install a wallet extension (MetaMask or similar) and reload.");
  const rpcChain = await rpc.chainId();
  if (rpcChain !== asset.chain_id) {
    throw new WalletRefusedError(`The configured EVM RPC serves chain ${rpcChain}, but ${asset.token_symbol} is on ${asset.name} (chain ${asset.chain_id}). Change it in Settings.`);
  }
  const wallet = new EvmWallet(provider);
  try {
    return { wallet, account: await wallet.connect(asset.chain_id) };
  } catch (error) {
    throw new WalletRefusedError(`Wallet connection refused: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

export interface Erc20ExecutionOptions {
  readonly prepared: PreparedErc20Swap;
  readonly asset: EvmAssetIdentity;
  readonly rpc: EvmRpc;
  readonly wallet: EvmWallet;
  readonly account: string;
  readonly ageRecipient: string;
  readonly status: (message: string, step: number, state?: string) => void;
  readonly report: (line: string) => void;
  readonly download: (root: HTMLElement, file: Uint8Array, name: string) => void;
  readonly signal?: AbortSignal;
}

/** Approve (if needed) and lock through the wallet, then wait for the provider's payment. */
export async function mountErc20Execution(panel: HTMLElement, options: Erc20ExecutionOptions): Promise<Erc20SwapOutcome> {
  const { prepared, asset, rpc, wallet, account, report, status } = options;
  const files = node("section", "", "swap-erc20-files");
  const message = node("p", "", "swap-erc20-message");
  panel.replaceChildren(message, files);
  const say = (text: string, step: number, state?: string): void => { message.textContent = text; status(text, step, state); };
  const lock = async (terms: HtlcLock, htlc: string): Promise<string> => {
    const balance = await rpc.balanceOf(terms.token, account);
    if (balance < terms.amount) {
      throw new WalletRefusedError(`Your wallet holds ${tokenLabel(balance, asset)}; the lock needs ${tokenLabel(terms.amount, asset)}. Nothing was locked.`);
    }
    if (await rpc.allowance(terms.token, account, htlc) < terms.amount) {
      say(`Approve ${tokenLabel(terms.amount, asset)} for the swap contract in your wallet`, 2);
      const approval = await wallet.send(account, terms.token, encodeApprove(htlc, terms.amount));
      report(`approval ${approval} submitted`);
      const receipt = await awaitReceipt(rpc, approval, 1, options.signal ? { signal: options.signal } : {});
      if (!receipt.status) throw new EvmError("the approval transaction reverted; nothing was locked");
    }
    say(`Confirm the lock of ${tokenLabel(terms.amount, asset)} in your wallet`, 2);
    return wallet.send(account, htlc, encodeLock(terms));
  };
  const outcome = await prepared.execute({
    rpc,
    ...(options.signal ? { signal: options.signal } : {}),
    report: (line) => {
      report(line);
      if (line.startsWith("lock ") && line.includes("submitted")) say("Lock submitted; waiting for confirmation", 3);
      else if (line.startsWith("lock confirmed")) say("Locked. Waiting for the provider to pay your invoice", 3);
    },
    saveRecovery: async (file, stage) => {
      options.download(files, file, `rillswap-${asset.token_symbol.toLowerCase()}-to-ln-${stage}.age`);
      report(`recovery record saved (${stage})`);
    },
    lock,
  });
  options.download(files, outcome.paidRecovery, `rillswap-${asset.token_symbol.toLowerCase()}-to-ln-paid.age`);
  say("Lightning invoice paid", 4, "success");
  panel.append(node("p", `Preimage ${outcome.preimage}. Lock ${outcome.lockTxHash}.`, "swap-erc20-paid"));
  return outcome;
}

export interface EvmRecoveryOptions {
  readonly plaintext: Uint8Array;
  readonly network: unknown;
  readonly evmRpc: () => string;
  readonly assertCurrent: () => void;
  readonly rpcFactory?: (url: string) => EvmRpc;
}

/** Reopen an RS-010 record: show the signed lock, check it on request, and refund through the wallet after the timelock. */
export function evmRecoveryControls(root: HTMLElement, options: EvmRecoveryOptions): () => void {
  let disposed = false, busy = false;
  const current = (): void => { if (disposed) throw new Error("Selection changed"); options.assertCurrent(); };
  let record: EvmRecoveryRecord;
  try {
    record = parseEvmRecovery(Uint8Array.from(options.plaintext), options.network, Math.floor(Date.now() / 1000));
  } catch {
    root.replaceChildren(node("p", "Could not verify this recovery file for the selected network. Keep your backups; nothing was changed or uploaded."));
    return () => { disposed = true; };
  }
  const { terms, lock } = record;
  const asset = terms.evm_asset;
  const message = node("p", "", "swap-evm-recovery-message");
  const check = node("button", "Check lock status", "swap-evm-recovery-check"); check.type = "button";
  const refund = node("button", `Refund ${tokenLabel(lock.amount, asset)} with your wallet`, "swap-evm-recovery-refund"); refund.type = "button";
  refund.disabled = true;
  root.replaceChildren(
    node("h3", `${asset.token_symbol} to Lightning recovery verified`),
    node("p", `${asset.name} (chain ${asset.chain_id}) · ${tokenLabel(lock.amount, asset)} locked for ${terms.economics.lightning_principal_sat} sat. ` +
      `Refund address ${lock.refundAddress}. Refundable from block ${lock.timelock}.` +
      (record.lockTxHash ? ` Lock transaction ${record.lockTxHash}.` : " No lock transaction recorded.") +
      (record.preimage ? " The provider paid; the preimage is known." : "")),
    node("p", "Verified locally against the provider's signature. Checking the chain and refunding connect to the configured EVM RPC and your wallet only when you ask."),
    message, check, refund,
  );
  const openRpc = (): EvmRpc => (options.rpcFactory ?? ((url) => new EvmRpc(url)))(options.evmRpc());
  const inspect = async (): Promise<{ active: boolean; tip: number }> => {
    const rpc = openRpc();
    if (await rpc.chainId() !== asset.chain_id) throw new Error(`The configured EVM RPC is not chain ${asset.chain_id}`);
    const tip = await rpc.blockNumber();
    const active = await rpc.lockActive(asset.htlc_contract, lock);
    current();
    if (active) {
      message.textContent = tip >= lock.timelock
        ? `Still locked at block ${tip}. The timelock (${lock.timelock}) has passed: you can refund.`
        : `Still locked at block ${tip}. Refund possible from block ${lock.timelock} (${lock.timelock - tip} blocks, about ${Math.ceil((lock.timelock - tip) * asset.block_seconds / 60)} min).`;
    } else {
      const claim = await rpc.findClaim(asset.htlc_contract, lock.preimageHash, Math.max(0, tip - 10_000), tip).catch(() => null);
      message.textContent = claim ? `Claimed by the provider in ${claim.txHash}; the invoice was paid. Nothing to refund.`
        : "Not locked: either refunded already or never locked. Nothing to refund.";
    }
    refund.disabled = !(active && tip >= lock.timelock);
    return { active, tip };
  };
  check.onclick = () => {
    if (busy) return;
    busy = true; check.disabled = true;
    message.textContent = "Checking the lock on the configured EVM RPC...";
    void inspect().catch((error: unknown) => { message.textContent = `Could not check: ${error instanceof Error ? error.message : "unknown error"}`; })
      .finally(() => { busy = false; check.disabled = false; });
  };
  refund.onclick = () => {
    if (busy) return;
    busy = true; check.disabled = refund.disabled = true;
    void (async () => {
      const rpc = openRpc();
      const { wallet, account } = await connectEvmWallet(rpc, asset);
      if (account !== lock.refundAddress) throw new Error(`Connect the wallet account ${lock.refundAddress}; the refund pays only that address`);
      current();
      message.textContent = "Confirm the refund in your wallet...";
      const txHash = await wallet.send(account, asset.htlc_contract, encodeRefund(lock));
      message.textContent = `Refund ${txHash} submitted; waiting for confirmation...`;
      const receipt = await awaitReceipt(rpc, txHash, 1);
      message.textContent = receipt.status ? `Refunded in ${txHash}. ${tokenLabel(lock.amount, asset)} returned to ${account}.`
        : `Refund ${txHash} reverted. Check the lock status again; the timelock or the lock state may have changed.`;
    })().catch((error: unknown) => { message.textContent = `Refund stopped: ${error instanceof Error ? error.message : "unknown error"}`; refund.disabled = false; })
      .finally(() => { busy = false; check.disabled = false; });
  };
  return () => { disposed = true; };
}
