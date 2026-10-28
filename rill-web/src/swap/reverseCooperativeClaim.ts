/** One live reverse claimant attempt. Recovery never calls this module. */
import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { buildCooperativeClaimPlan, finalizeCooperativeClaim, type Cosigner } from "./cooperative";
import { contractHash } from "./hashes";
import type { Musig, MusigAttempt } from "./musig";
import type { Session } from "./session";
import { reconstructTaprootContract } from "./taproot";
import { parseTransaction } from "./transaction";
import { COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE, type HandshakeInit, type HandshakeAccept, type LnToBtcTerms } from "./wire";
import type { RecoveryFundingBinding } from "../recoveryInspection";

interface ReverseCooperationOptions {
  readonly session: Session;
  readonly init: HandshakeInit;
  readonly accept: HandshakeAccept;
  readonly terms: LnToBtcTerms;
  readonly binding: RecoveryFundingBinding;
  readonly contractSecret: Uint8Array;
  readonly preimage: Uint8Array;
  readonly feeSat: bigint;
  readonly expectedTxid: string;
  readonly tipHeight: number;
  readonly capabilities: Cosigner;
  readonly assertCurrent: () => void;
  readonly monotonicClock?: () => number;
}
const require = (ok: boolean): void => { if (!ok) throw new Error("Reverse cooperation refused"); };
const exact = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

/** Caller has already durably acknowledged its signed unilateral fallback at this exact fee. */
export async function reverseCooperativeClaim(options: ReverseCooperationOptions): Promise<{ readonly raw: string; readonly txid: string } | null> {
  const { session, terms, binding } = options;
  const monotonic = options.monotonicClock ?? (() => performance.now());
  // Preparation, storage, publication and signing all spend this one nonrenewing 30 s window. The
  // quote deadline does not bound it: the lockup confirms long after the terms expire, and the
  // claim height cutoff below is what keeps the unilateral fallback safe.
  const started = monotonic(), wallStart = session.clock(); let wallHighWater = wallStart;
  const deadlineAt = Math.floor((wallStart + 30000) / 1000);
  const deadlineMono = started + deadlineAt * 1000 - wallStart;
  const remaining = (): number => {
    options.assertCurrent();
    const now = monotonic(), wall = session.clock();
    require(Number.isFinite(now) && Number.isFinite(wall) && now >= started);
    wallHighWater = Math.max(wallHighWater, wall);
    const budget = Math.min(deadlineMono - now, deadlineAt * 1000 - wallHighWater);
    require(budget > 0); return budget;
  };
  const live = (): void => { remaining(); };
  const bounded = async <T>(work: () => Promise<T>): Promise<T> => {
    const budget = remaining(); let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([work(), new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("Cooperation timed out")), budget);
      })]);
    } finally { clearTimeout(timer); }
  };
  let musig: Musig | undefined, attempt: MusigAttempt | undefined, finished = false;
  try {
    live();
    const hash = bytesToHex(contractHash(terms));
    require(terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE) && options.init.required_features.includes(COOPERATIVE_CLAIM_FEATURE) &&
      options.accept.required_features.includes(COOPERATIVE_CLAIM_FEATURE) && session.profile === "ln-to-btc/v1" &&
      options.init.session_id === session.sessionId && options.accept.session_id === session.sessionId &&
      options.init.client_session_xonly_key === session.key && options.accept.provider_session_xonly_key === session.providerKey &&
      canonicalize(session.network) === canonicalize(terms.network_identity) && binding.contract_hash === hash && binding.funder_role === "provider");
    require(options.preimage.length === 32 && bytesToHex(sha256(options.preimage)) === terms.invoice_binding.payment_hash);
    const deadlineHeight = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks;
    require(Number.isSafeInteger(options.tipHeight) && options.tipHeight > 0 && options.tipHeight <= deadlineHeight);
    const plan = buildCooperativeClaimPlan(terms, binding, options.feeSat), contract = reconstructTaprootContract(terms);
    require(parseTransaction(plan.baseTransaction).txid === options.expectedTxid);
    const id = randomBytes(32), cooperationId = bytesToHex(id);
    const completed = await bounded(() => options.capabilities.reserve(hash, { contract_hash: hash, cooperation_id: cooperationId,
      signature_hash: bytesToHex(plan.signatureHash), created_at: Math.floor(wallHighWater / 1000) }, async () => {
      live(); musig = await bounded(async () => {
        const loaded = await options.capabilities.loadMusig();
        if (finished) { loaded.destroy(); throw new Error("Cooperation ended while loading"); }
        return loaded;
      }); live();
      const transcript = { clientKey: hexToBytes(terms.client_contract_compressed_key), providerKey: hexToBytes(terms.provider_contract_compressed_key),
        tapTweak: hexToBytes(contract.tap_tweak), message: plan.signatureHash };
      // reserve() has durably burned this contract before any nonce allocation.
      attempt = musig.begin(transcript, options.contractSecret, id); live();
      const proposal = session.envelope("action_request", { action: "cooperative_claim_propose", cooperation_id: cooperationId,
        unsigned_transaction: bytesToHex(plan.baseTransaction), payment_preimage: bytesToHex(options.preimage), public_nonce: bytesToHex(attempt.publicNonce),
        deadline_at: deadlineAt, deadline_height: deadlineHeight }, { contract: hash, requiredFeatures: [COOPERATIVE_CLAIM_FEATURE] });
      await bounded(() => session.send(proposal, session.providerKey!, live)); live();
      const reply = await bounded(() => session.replyTo(proposal, "action_result", remaining())); live();
      require(reply.sender_session_key === session.providerKey && reply.session_id === session.sessionId && reply.profile_id === session.profile &&
        canonicalize(reply.network_identity) === canonicalize(session.network) && reply.contract_hash === hash && reply.message_type === "action_result" &&
        reply.in_reply_to === proposal.message_id && reply.required_features.includes(COOPERATIVE_CLAIM_FEATURE) &&
        reply.required_features.every((feature) => feature === COOPERATIVE_CLAIM_FEATURE || feature === EPOCH_SESSION_FEATURE));
      const payload = reply.payload;
      require(payload.action === "cooperative_claim_propose" && payload.cooperation_id === cooperationId);
      if (payload.status === "declined") { require(exact(payload, ["action", "cooperation_id", "status"])); return null; }
      require(payload.status === "signed" && exact(payload, ["action", "cooperation_id", "status", "public_nonce", "partial_signature"]) &&
        typeof payload.public_nonce === "string" && /^[0-9a-f]{132}$/.test(payload.public_nonce) &&
        typeof payload.partial_signature === "string" && /^[0-9a-f]{64}$/.test(payload.partial_signature));
      const providerNonce = hexToBytes(payload.public_nonce as string), providerPartial = hexToBytes(payload.partial_signature as string);
      require(musig!.validateNonce(providerNonce) && musig!.verifyPartial(transcript, attempt!.publicNonce, providerNonce, "provider", providerPartial));
      live(); const ownPartial = attempt!.signOnce(providerNonce); live();
      const signature = musig!.aggregate(transcript, attempt!.publicNonce, providerNonce, ownPartial, providerPartial);
      const claim = finalizeCooperativeClaim(plan, signature, terms, binding); require(claim.txid === options.expectedTxid); live();
      const complete = session.envelope("action_request", { action: "cooperative_claim_complete", cooperation_id: cooperationId,
        partial_signature: bytesToHex(ownPartial) }, { contract: hash, requiredFeatures: [COOPERATIVE_CLAIM_FEATURE] });
      live(); return { claim, complete };
    }));
    if (!completed) return null;
    // Receipt is informational. Even a failed completion delivery does not invalidate this verified claim.
    try { await bounded(() => session.send(completed.complete, session.providerKey!, live)); } catch { /* Keep the verified key-path spend. */ }
    return completed.claim;
  } catch { return null; }
  finally { finished = true; attempt?.destroy(); musig?.destroy(); }
}
