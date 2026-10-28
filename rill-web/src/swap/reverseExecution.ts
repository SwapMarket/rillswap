/** One explicitly chosen reverse execution. No startup, automatic repayment, or preimage messages. */
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { Encrypter } from "age-encryption";
import { jcs, clientAcceptanceHash } from "./hashes";
import { schnorr } from "@noble/curves/secp256k1.js";
import { newKeyPair, type Handshake } from "./handshake";
import { invoiceBinding } from "./bolt11";
import { Session, SwapError } from "./session";
import { checkReverseFirmQuoteRequest, checkReverseTermsOffer, requireShape, type ReverseTermsOffer, type LnToBtcTerms } from "./wire";
import { recoveryDocument, type RecoveryParts } from "./recovery";
import { encryptCanonicalRecoveryForRecipient } from "../recoveryAgeContainer";
import { inspectReverseRecoveryPlaintext, checkSelectedReverseFundingTransaction, type RecoveryFundingBinding, type ConstructedReverseClaim } from "../recoveryInspection";
import type { BrowserReverseJournal, ReverseJournalRecord } from "../browserReverseJournal";
import type { BrowserHoldPayer, BoundedHoldPlan, HoldPaymentStatus } from "./browserHoldPayer";
import { validateMempoolApi, type NetworkName } from "./config";
import { effectiveClaimDepth, observeJournaledReverseFunding, prepareJournaledReverseClaim, exposeJournaledReverseClaim } from "./reverseClaim";
import { reverseCooperativeClaim } from "./reverseCooperativeClaim";
import type { Cosigner } from "./cooperative";
import { COOPERATIVE_CLAIM_FEATURE } from "./wire";
import type { ReverseSwapRequest } from "./reverseSwap";

const require = (ok: boolean): void => { if (!ok) throw new SwapError("Reverse execution refused. Keep backups; no payment or exposure is retried."); };

/**
 * The least claim fee reserve to ask for: the larger script-path claim at the next-block rate,
 * so either claim path pays at least that rate, the claim pays exactly the reserve, and the
 * destination receives exactly the payout. One Taproot script-path input (signature, preimage,
 * claim script, control block) and one output: 121 vB plus the destination script (143 P2WPKH,
 * 155 P2TR), as rill_core.settlement.claim_vsizes.
 */
export function minimumClaimFeeReserveSat(destinationScript: string, rateSatKvb: number, configuredSat: bigint): bigint {
  if (!/^(?:[0-9a-f]{2}){1,80}$/.test(destinationScript) || !Number.isSafeInteger(rateSatKvb) || rateSatKvb <= 0) {
    throw new SwapError("Invalid claim fee inputs");
  }
  const vsize = BigInt(121 + destinationScript.length / 2), nextBlock = (vsize * BigInt(rateSatKvb) + 999n) / 1000n;
  return nextBlock > configuredSat ? nextBlock : configuredSat;
}
const sign = (digest: Uint8Array, key: Uint8Array): string => bytesToHex(schnorr.sign(digest, key, randomBytes(32)));
export interface ReverseExecutionConfiguration {
  readonly destinationScript: string;
  readonly tipHeight: number;
  /** Next-block fee rate (sat/kvB) from the trusted chain API; the claim reserve must pay at least this. */
  readonly claimFeeRateSatKvb: number;
  readonly ageRecipient: string;
  readonly journal: BrowserReverseJournal;
  readonly cooperation?: Cosigner;
  /**
   * Claim after this many confirmations of the provider's funding (0: from the mempool) when
   * below the signed depth; absent waits for the signed depth. This session only (never
   * stored): Resume and recovery wait for the signed depth unless lowered there again.
   */
  readonly claimConfirmations?: number;
  /** Fixed, secret-free swap log lines (why the cooperative claim did or did not happen). */
  readonly report?: (line: string) => void;
  /** Recheck original UI selection, wallet identity, cancellation and network after awaits. */
  readonly assertCurrent: () => void;
}
export interface PreparedReverseExecution {
  readonly terms: LnToBtcTerms;
  readonly deadlineAt: number;
  readonly recoveryFile: Uint8Array;
  readonly record: ReverseJournalRecord;
  readonly claimFeeSat: string | null;
  /** Funding confirmations this session claims at: the client's lower choice or the signed depth. */
  readonly claimDepth: number;
  /**
   * Claim at fewer confirmations from now on (0: from the mempool), for this session only, while
   * the claim is not yet exposed (stage funded or claim-ready). Only ever lowers; the caller owns
   * the user's explicit acceptance of the double-spend risk.
   */
  lowerClaimDepth(depth: number): void;
  accept(acknowledgeRecovery: () => void): Promise<void>;
  planPayment(payer: BrowserHoldPayer, endpoint: string, feeLimitSat: bigint, approve: () => void): Promise<BoundedHoldPlan>;
  pay(payer: BrowserHoldPayer, plan: BoundedHoldPlan, endpoint: string, approve: () => void): Promise<HoldPaymentStatus>;
  /**
   * Default payment path: journal the exposure, then return the authenticated hold invoice
   * for any Lightning wallet to pay. The wallet owns routing fees and HTLC expiry from here;
   * the payment is UNKNOWN to this page until the provider's signed funding arrives.
   */
  exposeInvoice(approve: () => void): Promise<{ readonly bolt11: string; readonly expiresAt: number }>;
  receiveFunding(timeoutMs?: number): Promise<Uint8Array>;
  /** The provider's signed funding output, once received. */
  readonly funding: { readonly txid: string; readonly vout: number } | null;
  /** Confirmations of the signed funding on the trusted chain API. Read-only; throws until it confirms (with claimDepth 0, until the mempool has it). */
  fundingDepth(chainApi: string): Promise<number>;
  prepareClaim(chainApi: string, feeSat: bigint, approve: () => void): Promise<{ readonly claim: Omit<ConstructedReverseClaim, "transactionHex">; readonly recoveryFile: Uint8Array }>;
  exposeClaim(chainApi: string, broadcastApi: string, action: "download" | "broadcast", approve: () => void): Promise<{ readonly outcome: "exported" | "accepted" | "unknown"; readonly txid: string; readonly transactionHex?: string }>;
  dispose(): void;
}

/** Called once from a selected indicative session. Secrets are persisted BEFORE the firm request. */
export async function prepareReverseExecution(session: Session, handshake: Handshake, request: ReverseSwapRequest,
  configuration: ReverseExecutionConfiguration, clock: () => number = Date.now): Promise<PreparedReverseExecution> {
  request = structuredClone(request);
  const { init, accept, acceptSignature, transcript } = handshake;
  const config = { ...configuration }, network = structuredClone(request.network), name = network.name as NetworkName;
  const current = (): void => { config.assertCurrent(); require(!disposed); };
  const seconds = (): number => Math.floor(clock() / 1000);
  const contract = newKeyPair(), authorization = newKeyPair(), preimage = randomBytes(32);
  authorization.secret.fill(0);
   let disposed = false, document: Uint8Array | undefined;
   let selection: { fundingAttemptId: string; bindingRevision: number } | undefined;
  let accepted = false, acceptanceStarted = false, paying = false, claiming = false, exposing = false;
   const dispose = (): void => { disposed = true; contract.secret.fill(0); preimage.fill(0); session.secret.fill(0); document?.fill(0); };
  try {
    current(); require(init.profile_id === "ln-to-btc/v1" && session.profile === init.profile_id &&
      Number.isSafeInteger(config.tipHeight) && config.tipHeight > 0 && config.tipHeight < 500000000 &&
      (config.claimConfirmations === undefined || (Number.isSafeInteger(config.claimConfirmations) && config.claimConfirmations >= 0)));
    const limits = request.limits;
    const minimumReserve = minimumClaimFeeReserveSat(config.destinationScript, config.claimFeeRateSatKvb, limits.minClaimFeeReserveSat);
    if (minimumReserve > limits.maxClaimFeeSat) {
      throw new SwapError(`The minimum claim fee reserve (${minimumReserve} sat, at least the next-block fee) exceeds your maximum claim fee (${limits.maxClaimFeeSat} sat)`);
    }
    const firm = checkReverseFirmQuoteRequest({ kind: "ln-to-btc", mode: "firm", nominal_payout_sat: request.payoutSat.toString(),
      payment_hash: bytesToHex(sha256(preimage)), client_contract_compressed_key: contract.compressed, recovery_authorization_xonly_key: authorization.xonly,
      client_destination_script: config.destinationScript, limits: { max_success_fee_sat: limits.maxSuccessFeeSat.toString(), min_claim_fee_reserve_sat: minimumReserve.toString(),
        max_claim_fee_sat: limits.maxClaimFeeSat.toString(), min_refund_lock_height: config.tipHeight + limits.minRefundDelayBlocks,
        max_incoming_htlc_expiry_height: config.tipHeight + limits.maxIncomingHtlcDelayBlocks }, extensions: {} });
    const initialDeadline = seconds() + 600;
    const encrypt = (bytes: Uint8Array): Promise<Uint8Array> => encryptCanonicalRecoveryForRecipient(bytes, config.ageRecipient);
    const secrets = jcs({ format: "rillswap-reverse-secrets", network_identity: network, session_id: session.sessionId, handshake_init: init, handshake_accept: accept,
      provider_identity_signature: acceptSignature, client_session_secret: bytesToHex(session.secret), contract_secret: bytesToHex(contract.secret), preimage: bytesToHex(preimage), request: firm });
    let secretFile: Uint8Array;
    try {
      // Pre-terms intent is deliberately not mislabeled as native RS-007.
      const encrypter = new Encrypter(); encrypter.addRecipient(config.ageRecipient);
      secretFile = await encrypter.encrypt(secrets);
    } finally { secrets.fill(0); }
    current(); let record = await config.journal.createFresh({ networkIdentity: network, sessionId: session.sessionId, clientSessionKey: session.key,
      providerSessionKey: session.providerKey!, providerIdentity: request.identity, request: firm, deadlineAt: initialDeadline }, secretFile);
    current(); require(seconds() < initialDeadline);
    const envelope = session.envelope("quote_request", firm as unknown as Record<string, unknown>);
    await session.send(envelope, session.providerKey!, () => { current(); require(seconds() < initialDeadline); });
    const answer = await session.replyTo(envelope, "terms_offer"); current();
    const { terms, holdInvoice } = checkReverseTermsOffer(answer.payload, { request: firm, transcript, envelopeContractHash: answer.contract_hash,
      identity: request.identity, network, now: seconds(), handshakeInit: init, handshakeAccept: accept, decodeInvoice: (value) => invoiceBinding(value, name) });
    const deadlineAt = Math.min(initialDeadline, terms.terms_expiry, terms.invoice_binding.expires_at);
    let claimDepth = effectiveClaimDepth(terms.funding_confirmations, config.claimConfirmations);
    const live = (): void => { current(); require(seconds() < deadlineAt); };
    const acceptance = { contract_hash: answer.contract_hash!, handshake_hash: transcript, session_id: session.sessionId,
      client_session_xonly_key: session.key, provider_session_xonly_key: session.providerKey! };
    const acceptanceSignature = sign(clientAcceptanceHash(acceptance), session.secret), createdAt = seconds();
    let parts: RecoveryParts = { network, profile: "ln-to-btc/v1", init, accept, acceptSignature, offer: answer.payload as unknown as ReverseTermsOffer,
      acceptanceSignature, clientSessionKey: session.key, contractSecret: contract.secret, birthday: config.tipHeight, createdAt, updatedAt: createdAt, funding: [], preimage: bytesToHex(preimage),
      extensions: { "rillswap/browser-reverse-session": { client_session_secret: bytesToHex(session.secret), original_deadline_at: deadlineAt } } };
    document = recoveryDocument(parts); inspectReverseRecoveryPlaintext(document, network);
    const recoveryFile = await encrypt(document); live(); record = await config.journal.saveTerms(record, recoveryFile); live();
    const claimContext = (approve: () => void) => ({ plaintext: document!, record, journal: config.journal,
      network: network as { name: NetworkName; genesis_hash: string }, assertCurrent: () => { current(); approve(); }, claimDepth });
    const freeze = (value: unknown): void => { if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } };
    freeze(terms);
    return Object.freeze({ terms, deadlineAt, get claimDepth() { return claimDepth; },
      lowerClaimDepth(depth: number): void {
        current(); require((record.stage === "funded" || record.stage === "claim-ready") && !exposing && Number.isSafeInteger(depth) && depth >= 0 && depth < claimDepth);
        claimDepth = depth;
      },
      get recoveryFile() { return Uint8Array.from(recoveryFile); }, get record() { return record; }, dispose,
      get claimFeeSat() { return inspectReverseRecoveryPlaintext(document!, network).fallbackFeeSat; },
      get funding() {
        const binding = parts.funding[0]?.binding as RecoveryFundingBinding | undefined;
        return binding && selection ? Object.freeze({ txid: binding.funding_txid, vout: binding.contract_vout }) : null;
      },
      async fundingDepth(chainApi: string): Promise<number> {
        current(); require(document !== undefined && selection !== undefined);
        return (await observeJournaledReverseFunding(claimContext(current), chainApi)).observation.confirmations;
      },
      async accept(acknowledgeRecovery: () => void): Promise<void> {
        require(!acceptanceStarted && record.stage === "terms-ready"); live(); acknowledgeRecovery(); live(); acceptanceStarted = true;
        const acceptedEnvelope = session.envelope("terms_accept", { acceptance, client_acceptance_signature: acceptanceSignature }, { inReplyTo: answer.message_id, contract: answer.contract_hash! });
        await session.send(acceptedEnvelope, session.providerKey!, () => { live(); acknowledgeRecovery(); });
        await session.replyTo(acceptedEnvelope, "ack"); live(); accepted = true;
      },
      async planPayment(payer: BrowserHoldPayer, endpoint: string, feeLimitSat: bigint, approve: () => void): Promise<BoundedHoldPlan> {
        require(accepted && !paying && record.stage === "terms-ready"); live(); approve();
        require(payer.endpoint === validateMempoolApi(endpoint, name));
        const plan = await payer.plan(holdInvoice, terms.invoice_binding, { feeLimitSat, minFinalExpiryHeight: terms.timing_policy.min_incoming_htlc_expiry_height,
          maxExpiryHeight: firm.limits.max_incoming_htlc_expiry_height, deadlineAt });
        live(); approve(); return plan;
      },
      async pay(payer: BrowserHoldPayer, plan: BoundedHoldPlan, endpoint: string, approve: () => void): Promise<HoldPaymentStatus> {
        require(accepted && !paying && record.stage === "terms-ready"); live(); approve();
        require(payer.endpoint === validateMempoolApi(endpoint, name)); paying = true;
        require(plan.paymentHash === firm.payment_hash && plan.limits.deadlineAt <= deadlineAt && plan.limits.minFinalExpiryHeight >= terms.timing_policy.min_incoming_htlc_expiry_height &&
          plan.limits.maxExpiryHeight <= firm.limits.max_incoming_htlc_expiry_height && canonicalize(plan.invoiceBinding) === canonicalize(terms.invoice_binding) &&
          canonicalize(plan.networkIdentity) === canonicalize(network));
        return payer.pay(plan, async () => {
          live(); approve(); const file = await encrypt(document!); live(); approve();
          record = await config.journal.beginPayment(record, payer.endpoint, plan, file);
          live(); approve();
        }, () => { live(); approve(); });
      },
      async exposeInvoice(approve: () => void): Promise<{ readonly bolt11: string; readonly expiresAt: number }> {
        require(accepted && !paying && record.stage === "terms-ready"); live(); approve(); paying = true;
        const file = await encrypt(document!); live(); approve();
        record = await config.journal.exposeInvoice(record, terms.invoice_binding, file, holdInvoice); live();
        return { bolt11: holdInvoice, expiresAt: terms.invoice_binding.expires_at };
      },
      async receiveFunding(timeoutMs = 30000): Promise<Uint8Array> {
        current(); require(record.stage === "payment-unknown");
        const event = await session.receive((item) => item.message_type === "funding_binding" && item.contract_hash === answer.contract_hash, timeoutMs); current();
        require(event.sender_session_key === session.providerKey && event.contract_hash === answer.contract_hash && event.in_reply_to === null);
        const payload = requireShape<{ binding: RecoveryFundingBinding; funding_binding_signature: string; funding_transaction: string }>("validateFundingBindingMessage", event.payload);
        require(payload.binding.funder_role === "provider" && payload.binding.binding_revision === 0 && payload.binding.replaces_txid === null);
        const nextParts = { ...parts, updatedAt: seconds(), funding: [{ binding: payload.binding, signature: payload.funding_binding_signature }] };
        const next = recoveryDocument(nextParts), chosen = { fundingAttemptId: payload.binding.funding_attempt_id, bindingRevision: payload.binding.binding_revision };
        try {
          checkSelectedReverseFundingTransaction(next, network, chosen, hexToBytes(payload.funding_transaction));
          const file = await encrypt(next); current(); record = await config.journal.saveFunding(record, file); current();
           document?.fill(0); document = next; parts = nextParts; selection = chosen;
          return file;
        } catch (error) { next.fill(0); throw error; }
      },
      async prepareClaim(chainApi: string, feeSat: bigint, approve: () => void) {
        current(); approve(); require(record.stage === "funded" && !claiming && typeof feeSat === "bigint" && feeSat >= 0n &&
          feeSat <= BigInt(terms.max_claim_fee_sat) && feeSat <= BigInt(terms.economics.claim_fee_reserve_sat));
        // One signing attempt. Any storage ambiguity blocks this object from re-signing.
        const prepared = await prepareJournaledReverseClaim(claimContext(approve), chainApi, feeSat, encrypt,
          () => { require(!claiming); claiming = true; });
        record = prepared.record; document?.fill(0); document = prepared.plaintext;
        return Object.freeze({ claim: prepared.claim, recoveryFile: prepared.recoveryFile });
      },
      async exposeClaim(chainApi: string, broadcastApi: string, action: "download" | "broadcast", approve: () => void) {
        current(); approve();
        if (record.stage === "claim-ready") require(!exposing);
        const cooperative = config.cooperation && terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) ? (tipHeight: number) => reverseCooperativeClaim({
          session, init, accept, terms, binding: parts.funding.at(-1)!.binding as RecoveryFundingBinding, contractSecret: contract.secret, preimage,
          feeSat: BigInt(inspectReverseRecoveryPlaintext(document!, network).fallbackFeeSat!), expectedTxid: record.claim!.txid,
          tipHeight, capabilities: config.cooperation!, assertCurrent: () => { current(); approve(); },
          ...(config.report ? { report: config.report } : {}),
        }) : undefined;
        const result = await exposeJournaledReverseClaim(claimContext(approve), chainApi, broadcastApi, action,
          () => { require(!exposing); exposing = true; }, cooperative);
        record = result.record; return Object.freeze(result.exposure);
      },
    });
  } catch (error) { dispose(); throw error; }
}
