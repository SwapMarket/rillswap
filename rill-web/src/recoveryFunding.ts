/** Explicit, trusted-API funding observations. No signing, storage, retries, or broadcast. */
import { hexToBytes } from "@noble/hashes/utils.js";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";
import { checkSelectedRecoveryFundingTransaction, inspectRecoveryPlaintext, isSupportedRecoveryNetwork, type RecoveryFundingSelection } from "./recoveryInspection";
import { parseStrictEventJson } from "./strictEventJson";
import { readBoundedChainText, readChainTip, type ChainFetch } from "./swap/chainTip";
import { validateMempoolApi, type NetworkName } from "./swap/config";
import { MAX_TRANSACTION_BYTES } from "./swap/transaction";

export interface RecoveryFundingObservation {
  readonly observation: "trusted-api";
  readonly networkName: string;
  readonly fundingTxid: string;
  readonly fundingVout: number;
  readonly fundingBlockHeight: number;
  readonly fundingBlockHash: string;
  readonly confirmations: number;
  readonly tipHeight: number;
  readonly tipHash: string;
  readonly refundLockHeight: number;
  /** Height comparison only, NOT permission to sign or independent chain proof. */
  readonly refundMatureAtObservedTip: boolean;
}

export class RecoveryFundingUnavailableError extends Error {
  constructor() {
    super("Funding observation unavailable. Check the network, API, and selected revision, then try again.");
    this.name = "RecoveryFundingUnavailableError";
  }
}

const HEX32 = /^[0-9a-f]{64}$/;
function require(condition: boolean): void { if (!condition) throw new RecoveryFundingUnavailableError(); }

function jsonObject(text: string): Record<string, unknown> {
  const object = parseStrictEventJson(text, 2048);
  require(object !== null && typeof object === "object" && !Array.isArray(object));
  return object as Record<string, unknown>;
}

/**
 * Matching/repeated responses are consistency checks on ONE explicitly trusted
 * API, not cryptographic inclusion or a global mempool view. This report grants
 * no signing or broadcast authority. Authenticate before revealing any outpoint.
 */
export async function observeRecoveryFunding(
  plaintext: Uint8Array,
  independentlySelectedNetwork: { readonly name: NetworkName; readonly genesis_hash: string },
  selection: RecoveryFundingSelection,
  base: string,
  options: { readonly signal?: AbortSignal; readonly fetch?: ChainFetch } = {},
): Promise<RecoveryFundingObservation> {
  let snapshot: Uint8Array | undefined;
  try {
    require(plaintext instanceof Uint8Array && plaintext.length > 0 && plaintext.length <= MAX_RECOVERY_PLAINTEXT_BYTES);
    snapshot = Uint8Array.from(plaintext);
    const network = structuredClone(independentlySelectedNetwork);
    require(isSupportedRecoveryNetwork(network));
    const chosen = { fundingAttemptId: selection.fundingAttemptId, bindingRevision: selection.bindingRevision };
    require(typeof chosen.fundingAttemptId === "string" && HEX32.test(chosen.fundingAttemptId));
    require(Number.isSafeInteger(chosen.bindingRevision) && chosen.bindingRevision >= 0 && chosen.bindingRevision < 64);
    const api = validateMempoolApi(base, network.name);
    const report = inspectRecoveryPlaintext(snapshot, network);
    const matches = report.fundingHistory.filter((binding) => binding.funding_attempt_id === chosen.fundingAttemptId && binding.binding_revision === chosen.bindingRevision);
    require(matches.length === 1);
    const binding = matches[0]!;
    const transport = options.fetch ?? fetch;
    const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000);
    signal.throwIfAborted();
    const get = async (path: string, limit = 2048): Promise<string> => readBoundedChainText(await transport(`${api}/${path}`, {
      signal, method: "GET", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
    }), signal, limit);
    const tip = await readChainTip(api, network, { signal, fetch: transport });
    let inclusion: { height: number; hash: string } | undefined;
    let rawHex: string | undefined;
    for (let pass = 0; pass < 2; pass++) {
      const text = await get(`tx/${binding.funding_txid}/hex`, MAX_TRANSACTION_BYTES * 2);
      require(/^(?:[0-9a-f]{2})+$/.test(text));
      if (rawHex !== undefined) require(text === rawHex);
      // Establish actual output existence BEFORE interpreting any outspend flag.
      checkSelectedRecoveryFundingTransaction(snapshot, network, chosen, hexToBytes(text));
      rawHex = text;
      const status = jsonObject(await get(`tx/${binding.funding_txid}/status`));
      require(status.confirmed === true && typeof status.block_height === "number" && Number.isSafeInteger(status.block_height) && status.block_height >= 0 && status.block_height <= tip.height);
      require(typeof status.block_hash === "string" && HEX32.test(status.block_hash));
      const height = status.block_height as number, hash = status.block_hash as string;
      if (height === tip.height) require(hash === tip.hash);
      if (height === 0) require(hash === network.genesis_hash);
      require(await get(`block-height/${height}`, 128) === hash);
      if (inclusion) require(inclusion.height === height && inclusion.hash === hash);
      inclusion = { height, hash };
      const outspend = jsonObject(await get(`tx/${binding.funding_txid}/outspend/${binding.contract_vout}`));
      require(outspend.spent === false);
    }
    const after = await readChainTip(api, network, { signal, fetch: transport });
    require(after.height === tip.height && after.hash === tip.hash);
    signal.throwIfAborted();
    return Object.freeze({ observation: "trusted-api", networkName: network.name,
      fundingTxid: binding.funding_txid, fundingVout: binding.contract_vout,
      fundingBlockHeight: inclusion!.height, fundingBlockHash: inclusion!.hash,
      confirmations: tip.height - inclusion!.height + 1, tipHeight: tip.height, tipHash: tip.hash,
      refundLockHeight: report.refundLockHeight, refundMatureAtObservedTip: tip.height > report.refundLockHeight });
  } catch { /* Never expose document, parser, endpoint response, or nested error details. */ }
  finally { snapshot?.fill(0); }
  throw new RecoveryFundingUnavailableError();
}
