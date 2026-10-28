/** Native reverse claims shared by live execution and explicit browser Resume. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import type { BrowserReverseJournal, ReverseJournalRecord } from "../browserReverseJournal";
import { parseRecoveryPlaintext } from "../recoveryDocument";
import { inspectReverseRecoveryPlaintext, constructSelectedReverseClaim, appendReverseClaimFallback,
  verifySelectedReverseClaim, REVERSE_FALLBACK_EXTENSION } from "../recoveryInspection";
import { observeReverseRecoveryFunding, RecoveryFundingSpentError, RecoveryFundingUnavailableError } from "../recoveryFunding";
import { validateMempoolApi, type NetworkName } from "./config";
import { readBoundedChainText } from "./chainTip";
import { buildCooperativeClaimPlan, finalizeCooperativeClaim } from "./cooperative";
import { parseTransaction } from "./transaction";
import type { LnToBtcTerms } from "./wire";

interface ClaimContext {
  readonly plaintext: Uint8Array;
  readonly record: ReverseJournalRecord;
  readonly journal: BrowserReverseJournal;
  readonly network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly assertCurrent: () => void;
  /** Funding confirmations this claim waits for, the client's choice (0: mempool). Absent: the signed depth. */
  readonly claimDepth?: number;
}
const require = (ok: boolean): void => { if (!ok) throw new Error("Reverse claim refused. Preserve backups; unknown submissions are never retried."); };

/**
 * The depth a claim waits for: a lower client choice, never more than the signed funding depth.
 * Below it the claim reveals the preimage while the provider can still double-spend its funding.
 */
export function effectiveClaimDepth(signed: number, requested?: number): number {
  require(Number.isSafeInteger(signed) && signed >= 1 && (requested === undefined || (Number.isSafeInteger(requested) && requested >= 0)));
  return requested === undefined ? signed : Math.min(requested, signed);
}

/** Funding reads after cooperation; a block landing mid-read (at depth 0, the funding confirming) is retried. */
export const FRESH_READ_ATTEMPTS = 3;
const FRESH_READ_PAUSE_MS = 500;

/**
 * Re-read the funding before exposing a cooperative claim. Only an unknown read is
 * retried, so the signed cooperative claim survives a transient failure; a spend,
 * a stale context, or any other refusal fails at once.
 */
async function freshFundingObservation(context: ClaimContext, api: string) {
  for (let attempt = 1; ; attempt++) {
    try { return (await observeJournaledReverseFunding(context, api)).observation; } catch (error) {
      if (attempt >= FRESH_READ_ATTEMPTS || !(error instanceof RecoveryFundingUnavailableError) || error instanceof RecoveryFundingSpentError) throw error;
    }
    context.assertCurrent();
    await new Promise((resolve) => setTimeout(resolve, FRESH_READ_PAUSE_MS));
  }
}

export async function observeJournaledReverseFunding(context: ClaimContext, api: string) {
  context.assertCurrent();
  const report = inspectReverseRecoveryPlaintext(context.plaintext, context.network), binding = report.fundingHistory.at(-1);
  require(binding !== undefined);
  const depth = effectiveClaimDepth(report.minFundingDepth, context.claimDepth);
  const observation = await observeReverseRecoveryFunding(context.plaintext, context.network,
    { fundingAttemptId: binding!.funding_attempt_id, bindingRevision: binding!.binding_revision }, validateMempoolApi(api, context.network.name),
    { allowUnconfirmed: depth === 0 });
  context.assertCurrent();
  return { report, binding: binding!, observation, depth };
}

export async function prepareJournaledReverseClaim(context: ClaimContext, api: string, feeSat: bigint,
  encrypt: (plaintext: Uint8Array) => Promise<Uint8Array>, beforeSign: () => void) {
  context.assertCurrent(); require(context.record.stage === "funded");
  const { report, binding, observation, depth } = await observeJournaledReverseFunding(context, api);
  require(observation.confirmations >= depth && observation.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
  context.assertCurrent();
  beforeSign();
  const claim = constructSelectedReverseClaim(context.plaintext, context.network, {
    fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision,
    rawFundingTransaction: hexToBytes(observation.rawFundingTransactionHex), sampledTipHeight: observation.tipHeight,
    confirmations: observation.confirmations, minFundingConfirmations: depth, feeSat,
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
  action: "download" | "broadcast", beforeExposure: () => void,
  cooperate?: (tipHeight: number) => Promise<{ readonly raw: string; readonly txid: string } | null>): Promise<{ readonly record: ReverseJournalRecord; readonly exposure: ReverseClaimExposure }> {
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
  const { binding, observation, depth } = await observeJournaledReverseFunding(context, api);
  require(observation.confirmations >= depth && observation.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
  verifySelectedReverseClaim(context.plaintext, context.network, { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision },
    hexToBytes(observation.rawFundingTransactionHex), hexToBytes(fallback.transaction));
  let transaction = fallback.transaction;
  if (action === "broadcast" && cooperate) {
    try {
      const candidate = await cooperate(observation.tipHeight); context.assertCurrent();
      if (candidate) {
        const parsed = parseTransaction(hexToBytes(candidate.raw));
        const terms = doc.contract_terms as unknown as LnToBtcTerms;
        const plan = buildCooperativeClaimPlan(terms, binding, BigInt(report.fallbackFeeSat!));
        const checked = finalizeCooperativeClaim(plan, parsed.inputs[0]?.witness[0] ?? new Uint8Array(), terms, binding);
        require(candidate.txid === txid && checked.txid === txid && checked.raw === candidate.raw);
        transaction = candidate.raw;
      }
    } catch { context.assertCurrent(); /* Invalid/refused cooperation uses the already-durable fallback. */ }
    const fresh = await freshFundingObservation(context, api);
    require(fresh.confirmations >= depth && fresh.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
  }
  context.assertCurrent(); beforeExposure(); record = await context.journal.beginClaimExposure(record);
  // A committed election (including a rejected readback) never renews POST authority.
  try {
    context.assertCurrent();
    if (action === "download") return { record, exposure: { outcome: "exported", txid, transactionHex: fallback.transaction } };
    const signal = AbortSignal.timeout(15000), response = await fetch(`${broadcast}/tx`, { signal, method: "POST", body: transaction,
      headers: { "Content-Type": "text/plain" }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
    require(await readBoundedChainText(response, signal) === txid);
    record = await context.journal.markAccepted(record, txid);
    return { record, exposure: { outcome: "accepted", txid } };
  } catch { return { record, exposure: { outcome: "unknown", txid } }; }
}
