/** Native reverse claims shared by live execution and explicit browser Resume. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { BrowserReverseJournal, ReverseJournalRecord } from "../browserReverseJournal";
import { parseRecoveryPlaintext } from "../recoveryDocument";
import { inspectReverseRecoveryPlaintext, constructSelectedReverseClaim, appendReverseClaimFallback,
  verifySelectedReverseClaim, REVERSE_FALLBACK_EXTENSION } from "../recoveryInspection";
import { observeReverseRecoveryFunding } from "../recoveryFunding";
import { validateMempoolApi, type NetworkName } from "./config";
import { readBoundedChainText } from "./chainTip";

interface ClaimContext {
  readonly plaintext: Uint8Array;
  readonly record: ReverseJournalRecord;
  readonly journal: BrowserReverseJournal;
  readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly assertCurrent: () => void;
}
const require = (ok: boolean): void => { if (!ok) throw new Error("Reverse claim refused. Preserve backups; unknown submissions are never retried."); };

export async function observeJournaledReverseFunding(context: ClaimContext, api: string) {
  context.assertCurrent();
  const report = inspectReverseRecoveryPlaintext(context.plaintext, context.network), binding = report.fundingHistory.at(-1);
  require(binding !== undefined);
  const observation = await observeReverseRecoveryFunding(context.plaintext, context.network,
    { fundingAttemptId: binding!.funding_attempt_id, bindingRevision: binding!.binding_revision }, validateMempoolApi(api, context.network.name));
  context.assertCurrent();
  return { report, binding: binding!, observation };
}

export async function prepareJournaledReverseClaim(context: ClaimContext, api: string, feeSat: bigint,
  encrypt: (plaintext: Uint8Array) => Promise<Uint8Array>) {
  context.assertCurrent(); require(context.record.stage === "funded");
  const { report, binding, observation } = await observeJournaledReverseFunding(context, api);
  require(observation.confirmations >= report.minFundingDepth && observation.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
  context.assertCurrent();
  const claim = constructSelectedReverseClaim(context.plaintext, context.network, {
    fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision,
    rawFundingTransaction: hexToBytes(observation.rawFundingTransactionHex), sampledTipHeight: observation.tipHeight,
    confirmations: observation.confirmations, feeSat,
  });
  const fallback = appendReverseClaimFallback(context.plaintext, context.network, hexToBytes(claim.transactionHex));
  try {
    const recoveryFile = await encrypt(fallback); context.assertCurrent();
    const record = await context.journal.prepareClaim(context.record, { fundingTxid: claim.fundingTxid, fundingVout: claim.fundingVout,
      txid: claim.txid, signedDigest: bytesToHex(sha256(hexToBytes(claim.transactionHex))) }, recoveryFile);
    context.assertCurrent();
    const { transactionHex: _privateWitness, ...publicClaim } = claim;
    return { record, plaintext: Uint8Array.from(fallback), claim: Object.freeze(publicClaim), recoveryFile };
  } finally { fallback.fill(0); }
}

export interface ReverseClaimExposure {
  readonly outcome: "exported" | "accepted" | "unknown";
  readonly txid: string;
  readonly transactionHex?: string;
}

/** The durable digest always binds the unilateral fallback, even if a live cooperative witness is used later. */
export async function exposeJournaledReverseClaim(context: ClaimContext, api: string, broadcastApi: string,
  action: "download" | "broadcast"): Promise<{ readonly record: ReverseJournalRecord; readonly exposure: ReverseClaimExposure }> {
  context.assertCurrent();
  const report = inspectReverseRecoveryPlaintext(context.plaintext, context.network), doc = parseRecoveryPlaintext(context.plaintext).document;
  const fallback = (doc.extensions as Record<string, unknown>)[REVERSE_FALLBACK_EXTENSION] as { transaction: string };
  require(report.fallbackTxid !== null && report.fallbackTxid === context.record.claim?.txid &&
    bytesToHex(sha256(hexToBytes(fallback.transaction))) === context.record.claim?.signedDigest);
  const txid = report.fallbackTxid!, broadcast = validateMempoolApi(broadcastApi, context.network.name);
  let record = context.record;
  if (record.stage === "claim-unknown" || record.stage === "accepted") {
    require(action === "download"); record = await context.journal.reexportIdentical(record); context.assertCurrent();
    return { record, exposure: { outcome: "exported", txid, transactionHex: fallback.transaction } };
  }
  require(record.stage === "claim-ready");
  const { binding, observation } = await observeJournaledReverseFunding(context, api);
  require(observation.confirmations >= report.minFundingDepth && observation.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
  verifySelectedReverseClaim(context.plaintext, context.network, { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision },
    hexToBytes(observation.rawFundingTransactionHex), hexToBytes(fallback.transaction));
  context.assertCurrent(); record = await context.journal.beginClaimExposure(record);
  // A committed election (including a rejected readback) never renews POST authority.
  try {
    context.assertCurrent();
    if (action === "download") return { record, exposure: { outcome: "exported", txid, transactionHex: fallback.transaction } };
    const signal = AbortSignal.timeout(15000), response = await fetch(`${broadcast}/tx`, { signal, method: "POST", body: fallback.transaction,
      headers: { "Content-Type": "text/plain" }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
    require(await readBoundedChainText(response, signal) === txid);
    record = await context.journal.markAccepted(record, txid);
    return { record, exposure: { outcome: "accepted", txid } };
  } catch { return { record, exposure: { outcome: "unknown", txid } }; }
}
