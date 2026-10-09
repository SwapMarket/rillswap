/**
 * One browser BTC to LN swap (port of rill-cli live_swap.run_swap).
 *
 * Order: decode the invoice, discover the provider, handshake, request firm
 * terms within the user's limits, check and sign them, hand the user the
 * terms recovery file, accept, authorize the user's finalized funding PSBT,
 * hand the user the funded recovery file, bind, let the user broadcast, and
 * wait for the preimage. No key or record leaves memory except through the
 * user's own downloads; refunds use `rill recover watch-refund --chain-only`.
 */
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

import type { AnnouncementCandidate } from "../nostrProviderAnnouncement";
import { invoiceBinding } from "./bolt11";
import { COOPERATIVE_RESERVATION_EXTENSION, type Cosigner, settle } from "./cooperative";
import { type AnnouncementSource, discoverProvider } from "./discovery";
import { type AuthorizedFunding, authorizeFundingPsbt, type FundingBinding, fundingBinding } from "./funding";
import { clientAcceptanceHash, epochBoundSessionId, fundingBindingHash, handshakeHash } from "./hashes";
import { encryptRecovery, type RecoveryParts } from "./recovery";
import { type RelayLink, Session, SwapError } from "./session";
import { verifyNostrProviderAnnouncement } from "../nostrProviderAnnouncement";
import { reconstructTaprootContract } from "./taproot";
import {
  type BtcToLnTerms,
  checkHandshakeAccept,
  checkTermsOffer,
  COOPERATIVE_CLAIM_FEATURE,
  EPOCH_SESSION_EXTENSION,
  EPOCH_SESSION_FEATURE,
  type FirmQuoteRequest,
  type HandshakeInit,
  requireShape,
  type TermsOffer,
} from "./wire";

export const PROFILE = "btc-to-ln/v1";
// The same selection rill-cli requests; the suite name is a label for NIP-59 delivery.
const ENCRYPTION_SUITES = ["noise-xk-secp256k1-chachapoly-sha256/v1"];
const CAPABILITIES = ["core/v1", "recovery/v1"];
/** Seconds an invoice must stay valid at quote time (the provider needs time to pay). */
const MIN_INVOICE_REMAINING_SECONDS = 600;

export interface UserLimits {
  readonly maxSuccessFeeSat: bigint;
  readonly maxFundingFeeSat: bigint;
  readonly maxClaimFeeSat: bigint;
  readonly maxRefundFeeSat: bigint;
  readonly maxRefundDelayBlocks: number;
}

export interface SwapRequest {
  readonly identity: string;
  readonly network: { readonly name: string } & Record<string, unknown>;
  readonly invoice: string;
  readonly refundScript: string;
  readonly tipHeight: number;
  readonly ageRecipient: string;
  readonly limits: UserLimits;
  /** A merchant checkout can expire earlier than the invoice. */
  readonly checkoutExpiresAt?: number;
}

export interface FundingRequest {
  readonly contractScript: string;
  readonly amountSat: bigint;
  readonly maxFundingFeeSat: bigint;
  readonly refundLockHeight: number;
  readonly successFeeSat: bigint;
  readonly termsExpiry?: number;
}

/** Every step that needs the user; each promise resolves once the user acted. */
export interface SwapHooks {
  report(line: string): void;
  /** Offer the age file for download; resolve after the user saved it. */
  saveRecovery(file: Uint8Array, stage: "terms" | "funded"): Promise<void>;
  /** Show the contract output; resolve with the wallet's finalized PSBT. */
  fundingPsbt(request: FundingRequest): Promise<string>;
  /** Show the signed transaction; resolve once the user broadcast it. */
  broadcast(rawTransaction: string, txid: string): Promise<void>;
  /** Persist public references before releasing a signed transaction to the provider. */
  beforeFundingCommit?(txid: string, termsExpiry: number): Promise<void>;
  /** The MuSig2 signer and cross-tab reservation journal for the key-path claim. */
  readonly cosigner: Cosigner;
}

export interface SwapOutcome {
  readonly sessionId: string;
  readonly contractHash: string;
  readonly fundingTxid: string;
  readonly preimage: string;
  readonly refundLockHeight: number;
  /** "verified": the provider holds a private key-path claim; "abandoned": it claims with the preimage. */
  readonly cooperation: "verified" | "abandoned";
  readonly claimTxid: string | null;
  /** Optional paid recovery file (age-encrypted): preimage and any cooperative reservation. */
  readonly paidRecovery: Uint8Array;
}

export interface SwapTimeouts {
  readonly replyMs: number;
  readonly settleMs: number;
}

interface Handshake {
  readonly init: HandshakeInit;
  readonly accept: ReturnType<typeof checkHandshakeAccept>;
  readonly acceptSignature: string;
  readonly transcript: string;
}

async function handshake(session: Session, provider: AnnouncementCandidate, identity: string): Promise<Handshake> {
  const epoch = provider.advertisedEpochInboxKeys[0]!;
  if (provider.requiresEpochBinding) {
    session.sessionId = bytesToHex(epochBoundSessionId(session.network, identity, epoch, session.key));
  }
  const init: HandshakeInit = {
    protocol: "rillswap",
    wire_version: "1",
    profile_id: PROFILE,
    network_identity: session.network,
    session_id: session.sessionId,
    client_challenge: bytesToHex(randomBytes(32)),
    client_session_xonly_key: session.key,
    expected_provider_identity_xonly_key: identity,
    requested_encryption_suites: ENCRYPTION_SUITES,
    requested_capabilities: CAPABILITIES,
    // Cooperative claims are mandatory; features are sorted like every signed list.
    required_features: provider.requiresEpochBinding
      ? [COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_FEATURE]
      : [COOPERATIVE_CLAIM_FEATURE],
    extensions: provider.requiresEpochBinding ? { [EPOCH_SESSION_EXTENSION]: { epoch_inbox_xonly_key: epoch } } : {},
  };
  const request = session.envelope("handshake_init", init as unknown as Record<string, unknown>, { signed: false });
  await session.listen();
  await session.send(request, epoch);
  const answer = await session.replyTo(request, "handshake_accept");
  const accept = checkHandshakeAccept(answer.payload, init, answer.sender_session_key);
  session.providerKey = answer.sender_session_key;
  const transcript = bytesToHex(handshakeHash(init, accept));
  const confirm = session.envelope(
    "handshake_confirm",
    {
      handshake_hash: transcript,
      session_id: session.sessionId,
      client_session_xonly_key: session.key,
      provider_session_xonly_key: session.providerKey,
    },
    { inReplyTo: answer.message_id },
  );
  await session.send(confirm, session.providerKey);
  const signature = (answer.payload as { provider_identity_signature: string }).provider_identity_signature;
  return { init, accept, acceptSignature: signature, transcript };
}

function newKeyPair(): { secret: Uint8Array; compressed: string; xonly: string } {
  const secret = secp256k1.utils.randomSecretKey();
  const compressed = bytesToHex(secp256k1.getPublicKey(secret, true));
  return { secret, compressed, xonly: compressed.slice(2) };
}

const sign = (digest: Uint8Array, secret: Uint8Array): string => bytesToHex(schnorr.sign(digest, secret, randomBytes(32)));

function checkRequest(request: SwapRequest, now: number): ReturnType<typeof invoiceBinding> {
  if (request.network.name === "mainnet") {
    throw new SwapError("mainnet is not release-accepted; the web client refuses it");
  }
  if (!Number.isSafeInteger(request.tipHeight) || request.tipHeight <= 0) throw new SwapError("tip height invalid");
  if (!Number.isSafeInteger(request.limits.maxRefundDelayBlocks) || request.limits.maxRefundDelayBlocks <= 0) {
    throw new SwapError("maximum refund delay invalid");
  }
  const binding = invoiceBinding(request.invoice, request.network.name);
  if (binding.expires_at < now + MIN_INVOICE_REMAINING_SECONDS) {
    throw new SwapError("invoice expires too soon; ask the recipient for a fresh one");
  }
  return binding;
}

export interface PreparedQuote {
  readonly providerIdentity: string;
  readonly providerSlot: string;
  readonly contractHash: string;
  readonly contractAmountSat: bigint;
  readonly successFeeSat: bigint;
  readonly refundLockHeight: number;
  readonly expiresAt: number;
}

/** Holds one exact authenticated offer. Preparation does not accept or fund it. */
export interface PreparedSwap {
  readonly quote: PreparedQuote;
  execute(hooks: SwapHooks): Promise<SwapOutcome>;
  /** Discards an unused offer; never interrupts execution or rolls back funding. */
  dispose(): void;
}

interface PreparationOptions {
  readonly timeouts?: SwapTimeouts;
  readonly clock?: () => number;
  /** Reverified here, preserving the exact directory-selected slot/revision. */
  readonly announcement?: string;
}

export async function prepareSwap(
  relay: RelayLink & AnnouncementSource,
  request: SwapRequest,
  report: SwapHooks["report"],
  options: PreparationOptions = {},
): Promise<PreparedSwap> {
  request = { ...request, network: structuredClone(request.network), limits: { ...request.limits } };
  const timeouts = { ...(options.timeouts ?? { replyMs: 60_000, settleMs: 600_000 }) };
  const clock = options.clock ?? Date.now;
  const seconds = (): number => Math.floor(clock() / 1000);
  const invoice = checkRequest(request, seconds());
  const checkoutExpiry = request.checkoutExpiresAt ?? invoice.expires_at;
  if (!Number.isSafeInteger(checkoutExpiry) || checkoutExpiry <= seconds()) throw new SwapError("checkout expiry invalid");
  const { identity, network } = request;
  const provider = options.announcement === undefined
    ? await discoverProvider(relay, identity, network, PROFILE)
    : verifyNostrProviderAnnouncement(options.announcement, identity, network, PROFILE);
  report(`provider found (revision ${provider.revision})`);
  const session = new Session(relay, network, PROFILE, timeouts.replyMs, clock);
  let contractSecret: Uint8Array | null = null;
  try {
    const { init, accept, acceptSignature, transcript } = await handshake(session, provider, identity);
    const providerKey = session.providerKey!;
    report(`session ${session.sessionId.slice(0, 16)} confirmed`);

    const contract = newKeyPair();
    contractSecret = contract.secret;
    const recoveryKey = newKeyPair(); // authorization key; its secret is never needed
    recoveryKey.secret.fill(0);
    const limits = request.limits;
    const quote: FirmQuoteRequest = {
      kind: "btc-to-ln",
      mode: "firm",
      lightning_principal_sat: (BigInt(invoice.amount_msat) / 1000n).toString(),
      invoice: request.invoice,
      client_contract_compressed_key: contract.compressed,
      recovery_authorization_xonly_key: recoveryKey.xonly,
      client_destination_script: request.refundScript,
      limits: {
        max_success_fee_sat: limits.maxSuccessFeeSat.toString(),
        max_funding_fee_sat: limits.maxFundingFeeSat.toString(),
        max_claim_fee_sat: limits.maxClaimFeeSat.toString(),
        max_refund_fee_sat: limits.maxRefundFeeSat.toString(),
        max_refund_lock_height: request.tipHeight + limits.maxRefundDelayBlocks,
      },
      extensions: {},
    };
    requireShape("validateFirmQuoteRequest", quote);
    const quoteEnvelope = session.envelope("quote_request", quote as unknown as Record<string, unknown>);
    await session.send(quoteEnvelope, providerKey);
    const answer = await session.replyTo(quoteEnvelope, "terms_offer");
    const terms: BtcToLnTerms = checkTermsOffer(answer.payload, {
      request: quote,
      invoiceBinding: invoice,
      transcript,
      envelopeContractHash: answer.contract_hash,
      identity,
      network,
      now: seconds(),
    });
    if (terms.refund_lock_height <= request.tipHeight) throw new SwapError("offered refund height is already reached");
    const offer = answer.payload as unknown as TermsOffer;
    const contractHash = offer.terms.contract_hash;
    const economics = terms.economics;
    report(`terms: fund ${economics.contract_amount_sat} sat, refund after block ${terms.refund_lock_height}`);

    let state: "ready" | "executing" | "disposed" | "done" = "ready";
    const release = (): void => { session.secret.fill(0); contract.secret.fill(0); };
    return Object.freeze({
      quote: Object.freeze({
        providerIdentity: identity,
        providerSlot: provider.slot,
        contractHash,
        contractAmountSat: BigInt(economics.contract_amount_sat),
        successFeeSat: BigInt(economics.success_fee_sat),
        refundLockHeight: terms.refund_lock_height,
        expiresAt: Math.min(terms.terms_expiry, invoice.expires_at, checkoutExpiry),
      }),
      dispose: () => {
        if (state === "ready") { state = "disposed"; release(); }
      },
      execute: async (hooks: SwapHooks): Promise<SwapOutcome> => {
        if (state !== "ready") throw new SwapError("quote is already used or discarded; request a fresh quote");
        state = "executing";
        try {
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          const acceptance = {
            contract_hash: contractHash,
            handshake_hash: transcript,
            session_id: session.sessionId,
            client_session_xonly_key: session.key,
            provider_session_xonly_key: providerKey,
          };
          const acceptanceSignature = sign(clientAcceptanceHash(acceptance), session.secret);
          const createdAt = seconds();
          const record: RecoveryParts = {
            network, profile: PROFILE, init, accept, acceptSignature, offer, acceptanceSignature,
            clientSessionKey: session.key, contractSecret: contract.secret,
            birthday: request.tipHeight, createdAt, updatedAt: createdAt, funding: [], preimage: null,
          };
          await hooks.saveRecovery(await encryptRecovery(record, request.ageRecipient), "terms");
          hooks.report("recovery file saved (terms, no funding yet)");
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          const accepted = session.envelope(
            "terms_accept",
            { acceptance, client_acceptance_signature: acceptanceSignature },
            { inReplyTo: answer.message_id, contract: contractHash },
          );
          await session.send(accepted, providerKey,
            () => assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry));
          await session.replyTo(accepted, "ack");

          const funding = await authorizeUserFunding(terms, hooks);
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          const binding = fundingBinding(contractHash, funding, bytesToHex(randomBytes(32)), seconds());
          const bindingSignature = sign(fundingBindingHash(binding), session.secret);
          const funded = { ...record, updatedAt: seconds(), funding: [{ binding, signature: bindingSignature }] };
          await hooks.saveRecovery(await encryptRecovery(funded, request.ageRecipient), "funded");
          hooks.report(`funded recovery file saved (funding ${funding.txid}, attempt ${binding.funding_attempt_id} revision 0)`);
          const bound = session.envelope(
            "funding_binding",
            { binding, funding_binding_signature: bindingSignature, funding_transaction: funding.raw },
            { contract: contractHash },
          );
          // Sharing a signed transaction can commit funds before a broadcast acknowledgment.
          await hooks.beforeFundingCommit?.(funding.txid, terms.terms_expiry);
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          await session.send(bound, providerKey,
            () => assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry));
          await session.replyTo(bound, "ack");
          assertFundingWindow(terms.terms_expiry, invoice.expires_at, seconds(), checkoutExpiry);
          await hooks.broadcast(funding.raw, funding.txid);
          hooks.report(`funding ${funding.txid} broadcast; waiting for the provider to pay`);
          const hint =
            `funds are committed; after block ${terms.refund_lock_height} refund with rill-cli and your own ` +
            `Bitcoin Core: \`rill recover watch-refund --chain-only --funding-attempt-id ${binding.funding_attempt_id} ` +
            "--binding-revision 0` on the funded recovery file (see the rill-web README for the full command)";
          const settled = await settle(
            { session, providerKey, terms, contractHash, binding, contractSecret: contract.secret,
              tipHeight: request.tipHeight, settleMs: timeouts.settleMs, cosigner: hooks.cosigner, report: hooks.report },
            hint,
          );
          hooks.report(settled.cooperation === "verified"
            ? `cooperative key-path claim ${settled.claimTxid} verified; the provider claims privately`
            : "cooperation skipped; the provider claims with the preimage");
          const reserved = settled.reservation;
          const paid: RecoveryParts = {
            ...funded,
            // A reservation is dated when journaled, before its proposal deadline.
            updatedAt: Math.max(funded.updatedAt, reserved?.recordedAt ?? seconds()),
            preimage: settled.preimage,
            extensions: reserved === null ? {} : {
              [COOPERATIVE_RESERVATION_EXTENSION]: {
                version: 1, proposal: reserved.proposal, signature_hash: reserved.signature_hash,
              },
            },
          };
          return {
            sessionId: session.sessionId, contractHash, fundingTxid: funding.txid,
            preimage: settled.preimage, refundLockHeight: terms.refund_lock_height,
            cooperation: settled.cooperation, claimTxid: settled.claimTxid,
            paidRecovery: await encryptRecovery(paid, request.ageRecipient),
          };
        } finally {
          state = "done";
          release();
        }
      },
    });
  } catch (error) {
    session.secret.fill(0);
    contractSecret?.fill(0);
    throw error;
  }
}

/** Compatibility entrypoint: prepares and immediately executes one pinned-provider swap. */
export async function runSwap(
  relay: RelayLink & AnnouncementSource,
  request: SwapRequest,
  hooks: SwapHooks,
  timeouts: SwapTimeouts = { replyMs: 60_000, settleMs: 600_000 },
  clock: () => number = Date.now,
): Promise<SwapOutcome> {
  const prepared = await prepareSwap(relay, request, hooks.report, { timeouts, clock });
  return prepared.execute(hooks);
}

const MAX_FUNDING_ATTEMPTS = 5;

/** Never fund expired terms after a wallet, recovery or provider prompt. */
export function assertFundingWindow(termsExpiry: number, invoiceExpiry: number, now: number, checkoutExpiry = invoiceExpiry): void {
  if (![termsExpiry, invoiceExpiry, checkoutExpiry, now].every(Number.isSafeInteger) || now >= termsExpiry || now >= invoiceExpiry || now >= checkoutExpiry) {
    throw new SwapError("funding deadline exceeded; retain recovery and monitor any transaction already shared with the provider");
  }
}

/** Ask for the wallet's finalized PSBT until one passes authorization. */
async function authorizeUserFunding(terms: BtcToLnTerms, hooks: SwapHooks): Promise<AuthorizedFunding> {
  const request: FundingRequest = {
    contractScript: reconstructTaprootContract(terms).script_pubkey,
    amountSat: BigInt(terms.economics.contract_amount_sat),
    maxFundingFeeSat: BigInt(terms.max_funding_fee_sat),
    refundLockHeight: terms.refund_lock_height,
    successFeeSat: BigInt(terms.economics.success_fee_sat),
    termsExpiry: terms.terms_expiry,
  };
  for (let attempt = 1; ; attempt += 1) {
    const psbt = await hooks.fundingPsbt(request);
    try {
      return authorizeFundingPsbt(psbt, terms);
    } catch (error) {
      if (attempt >= MAX_FUNDING_ATTEMPTS) throw new SwapError("no acceptable funding transaction; nothing was funded");
      hooks.report(`${(error as Error).message}; nothing was sent, try again`);
    }
  }
}
