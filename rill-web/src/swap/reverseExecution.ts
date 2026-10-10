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
import { inspectReverseRecoveryPlaintext, checkSelectedReverseFundingTransaction, constructSelectedReverseClaim, appendReverseClaimFallback,
  verifySelectedReverseClaim, type RecoveryFundingBinding, type ConstructedReverseClaim } from "../recoveryInspection";
import { observeReverseRecoveryFunding } from "../recoveryFunding";
import type { BrowserReverseJournal, ReverseJournalRecord } from "../browserReverseJournal";
import type { BrowserHoldPayer, BoundedHoldPlan, HoldPaymentStatus } from "./browserHoldPayer";
import { validateMempoolApi, type NetworkName } from "./config";
import { readBoundedChainText } from "./chainTip";
import type { ReverseSwapRequest } from "./reverseSwap";

const require = (ok: boolean): void => { if (!ok) throw new SwapError("Reverse execution refused. Keep backups; no payment or exposure is retried."); };
const sign = (digest: Uint8Array, key: Uint8Array): string => bytesToHex(schnorr.sign(digest, key, randomBytes(32)));
export interface ReverseExecutionConfiguration {
  readonly destinationScript: string;
  readonly tipHeight: number;
  readonly ageRecipient: string;
  readonly journal: BrowserReverseJournal;
  /** Recheck original UI selection, wallet identity, cancellation and network after awaits. */
  readonly assertCurrent: () => void;
}
export interface PreparedReverseExecution {
  readonly terms: LnToBtcTerms;
  readonly deadlineAt: number;
  readonly recoveryFile: Uint8Array;
  readonly record: ReverseJournalRecord;
  accept(acknowledgeRecovery: () => void): Promise<void>;
  planPayment(payer: BrowserHoldPayer, endpoint: string, feeLimitSat: bigint, approve: () => void): Promise<BoundedHoldPlan>;
  pay(payer: BrowserHoldPayer, plan: BoundedHoldPlan, endpoint: string, approve: () => void): Promise<HoldPaymentStatus>;
  receiveFunding(timeoutMs?: number): Promise<Uint8Array>;
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
  let disposed = false, document: Uint8Array | undefined, fallback: Uint8Array | undefined;
  let claim: ConstructedReverseClaim | undefined, fundedRaw: string | undefined, selection: { fundingAttemptId: string; bindingRevision: number } | undefined;
  let accepted = false, acceptanceStarted = false, paying = false, claiming = false, exposing = false;
  const dispose = (): void => { disposed = true; contract.secret.fill(0); preimage.fill(0); session.secret.fill(0); document?.fill(0); fallback?.fill(0); };
  try {
    current(); require(name !== "mainnet" && init.profile_id === "ln-to-btc/v1" && session.profile === init.profile_id &&
      Number.isSafeInteger(config.tipHeight) && config.tipHeight > 0 && config.tipHeight < 500000000);
    const limits = request.limits;
    const firm = checkReverseFirmQuoteRequest({ kind: "ln-to-btc", mode: "firm", nominal_payout_sat: request.payoutSat.toString(),
      payment_hash: bytesToHex(sha256(preimage)), client_contract_compressed_key: contract.compressed, recovery_authorization_xonly_key: authorization.xonly,
      client_destination_script: config.destinationScript, limits: { max_success_fee_sat: limits.maxSuccessFeeSat.toString(), min_claim_fee_reserve_sat: limits.minClaimFeeReserveSat.toString(),
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
    const live = (): void => { current(); require(seconds() < deadlineAt); };
    const acceptance = { contract_hash: answer.contract_hash!, handshake_hash: transcript, session_id: session.sessionId,
      client_session_xonly_key: session.key, provider_session_xonly_key: session.providerKey! };
    const acceptanceSignature = sign(clientAcceptanceHash(acceptance), session.secret), createdAt = seconds();
    let parts: RecoveryParts = { network, profile: "ln-to-btc/v1", init, accept, acceptSignature, offer: answer.payload as unknown as ReverseTermsOffer,
      acceptanceSignature, clientSessionKey: session.key, contractSecret: contract.secret, birthday: config.tipHeight, createdAt, updatedAt: createdAt, funding: [], preimage: bytesToHex(preimage),
      extensions: { "rillswap/browser-reverse-session": { client_session_secret: bytesToHex(session.secret), original_deadline_at: deadlineAt } } };
    document = recoveryDocument(parts); inspectReverseRecoveryPlaintext(document, network);
    const recoveryFile = await encrypt(document); live(); record = await config.journal.saveTerms(record, recoveryFile); live();
    const selected = (): { fundingAttemptId: string; bindingRevision: number } => { require(selection !== undefined); return { ...selection! }; };
    const freshFunding = async (api: string) => {
      current(); const observation = await observeReverseRecoveryFunding(document!, network as { name: NetworkName; genesis_hash: string }, selected(), validateMempoolApi(api, name));
      current(); require(observation.confirmations >= terms.funding_confirmations && observation.tipHeight + terms.timing_policy.claim_confirmation_blocks < terms.refund_lock_height + 1);
      require(observation.rawFundingTransactionHex === fundedRaw); return observation;
    };
    const reauthorize = (): void => {
      require(claim !== undefined && fundedRaw !== undefined && document !== undefined);
      const checked = verifySelectedReverseClaim(document!, network, selected(), hexToBytes(fundedRaw!), hexToBytes(claim!.transactionHex));
      require(checked.txid === claim!.txid && checked.transactionHex === claim!.transactionHex && record.claim?.signedDigest === bytesToHex(sha256(hexToBytes(claim!.transactionHex))));
    };
    const freeze = (value: unknown): void => { if (value !== null && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } };
    freeze(terms);
    return Object.freeze({ terms, deadlineAt, get recoveryFile() { return Uint8Array.from(recoveryFile); }, get record() { return record; }, dispose,
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
          document?.fill(0); document = next; parts = nextParts; fundedRaw = payload.funding_transaction; selection = chosen;
          return file;
        } catch (error) { next.fill(0); throw error; }
      },
      async prepareClaim(chainApi: string, feeSat: bigint, approve: () => void) {
        current(); approve(); require(record.stage === "funded" && !claiming && typeof feeSat === "bigint" && feeSat >= 0n &&
          feeSat <= BigInt(terms.max_claim_fee_sat) && feeSat <= BigInt(terms.economics.claim_fee_reserve_sat));
        const observation = await freshFunding(chainApi); current(); approve();
        require(!claiming); claiming = true;
        // One signing attempt. Any storage ambiguity blocks this object from re-signing.
        claim = constructSelectedReverseClaim(document!, network, { ...selected(), rawFundingTransaction: hexToBytes(observation.rawFundingTransactionHex), sampledTipHeight: observation.tipHeight, confirmations: observation.confirmations, feeSat });
        fallback = appendReverseClaimFallback(document!, network, hexToBytes(claim.transactionHex));
        const file = await encrypt(fallback); current(); approve();
        record = await config.journal.prepareClaim(record, { fundingTxid: claim.fundingTxid, fundingVout: claim.fundingVout, txid: claim.txid, signedDigest: bytesToHex(sha256(hexToBytes(claim.transactionHex))) }, file);
        current(); const { transactionHex: _privateWitness, ...publicClaim } = claim;
        return Object.freeze({ claim: Object.freeze(publicClaim), recoveryFile: file });
      },
      async exposeClaim(chainApi: string, broadcastApi: string, action: "download" | "broadcast", approve: () => void) {
        current(); approve(); require(claim !== undefined); reauthorize();
        const api = validateMempoolApi(broadcastApi, name);
        if (record.stage === "claim-unknown" || record.stage === "accepted") {
          require(action === "download"); record = await config.journal.reexportIdentical(record); current(); approve(); reauthorize();
          return Object.freeze({ outcome: "exported" as const, txid: claim!.txid, transactionHex: claim!.transactionHex });
        }
        require(record.stage === "claim-ready" && !exposing); await freshFunding(chainApi); current(); approve(); reauthorize();
        exposing = true; record = await config.journal.beginClaimExposure(record);
        // Irreversible boundary. A failure from here never renews POST authority.
        try {
          current(); approve(); reauthorize();
          if (action === "download") return Object.freeze({ outcome: "exported" as const, txid: claim!.txid, transactionHex: claim!.transactionHex });
          const signal = AbortSignal.timeout(15000), response = await fetch(`${api}/tx`, { method: "POST", body: claim!.transactionHex,
            headers: { "Content-Type": "text/plain" }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal });
          const txid = await readBoundedChainText(response, signal); require(txid === claim!.txid);
          record = await config.journal.markAccepted(record, txid);
          return Object.freeze({ outcome: "accepted" as const, txid });
        } catch { return Object.freeze({ outcome: "unknown" as const, txid: claim!.txid }); }
      },
    });
  } catch (error) { dispose(); throw error; }
}
