/**
 * RS-001/RS-003 message checks for the browser swap client.
 *
 * Structure comes from the build-time generated schema validators; the
 * semantic rules below port rill-core's model validators and the CLI's
 * offer checks (messages.py, quotes.py check_terms_offer, live_swap.py).
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import * as generated from "../generated/wireValidators.js";
import type { InvoiceBinding } from "./bolt11";
import { contractHash, handshakeInitHash, handshakeAcceptHash, handshakeHash, jcs, providerTermsHash } from "./hashes";

export const EPOCH_SESSION_FEATURE = "epoch-bound-session/v1";
export const EPOCH_SESSION_EXTENSION = "rillswap/epoch-bound-session";
/** Negotiated commitment to a MuSig2 attempt, mandatory for new forward swaps. */
export const COOPERATIVE_CLAIM_FEATURE = "cooperative-claim/v1";
export const MAX_SATS = 2_100_000_000_000_000n;

export class ProtocolError extends Error {
  constructor(reason: string) {
    super(`Provider message refused: ${reason}`);
    this.name = "ProtocolError";
  }
}

type Validator = (document: unknown) => boolean;

/** Refuse `document` unless the named generated schema validator accepts it. */
export function requireShape<T>(name: keyof typeof generated, document: unknown): T {
  if (!(generated[name] as Validator)(document)) throw new ProtocolError(`${name} failed`);
  return document as T;
}

const same = (a: unknown, b: unknown): boolean => bytesToHex(jcs(a)) === bytesToHex(jcs(b));

export function sats(value: string, what: string, positive = false): bigint {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(value)) throw new ProtocolError(`${what} malformed`);
  const amount = BigInt(value);
  if (amount > MAX_SATS || (positive && amount === 0n)) throw new ProtocolError(`${what} out of range`);
  return amount;
}

export function verifySchnorr(key: string, digest: Uint8Array, signature: string, what: string): void {
  let ok = false;
  try {
    ok = schnorr.verify(hexToBytes(signature), digest, hexToBytes(key));
  } catch {
    ok = false;
  }
  if (!ok) throw new ProtocolError(`${what} signature invalid`);
}

export interface HandshakeInit {
  readonly protocol: "rillswap";
  readonly wire_version: "1";
  readonly profile_id: string;
  readonly network_identity: unknown;
  readonly session_id: string;
  readonly client_challenge: string;
  readonly client_session_xonly_key: string;
  readonly expected_provider_identity_xonly_key: string;
  readonly requested_encryption_suites: readonly string[];
  readonly requested_capabilities: readonly string[];
  readonly required_features: readonly string[];
  readonly extensions: Record<string, unknown>;
}

export interface HandshakeAccept {
  readonly handshake_init_hash: string;
  readonly session_id: string;
  readonly client_challenge: string;
  readonly provider_challenge: string;
  readonly client_session_xonly_key: string;
  readonly provider_session_xonly_key: string;
  readonly provider_identity_xonly_key: string;
  readonly selected_encryption_suite: string;
  readonly selected_capabilities: readonly string[];
  readonly transport_endpoints: readonly string[];
  readonly required_features: readonly string[];
  readonly [field: string]: unknown;
}

/**
 * Validate an accept payload against our init and the provider identity
 * (HandshakeAccept model rules, validate_against, identity signature).
 */
export function checkHandshakeAccept(payload: unknown, init: HandshakeInit, senderKey: string): HandshakeAccept {
  const { accept, provider_identity_signature: signature } = requireShape<{
    accept: HandshakeAccept;
    provider_identity_signature: string;
  }>("validateHandshakeAcceptPayload", payload);
  const roles = new Set([
    accept.client_session_xonly_key,
    accept.provider_session_xonly_key,
    accept.provider_identity_xonly_key,
  ]);
  const endpoints = accept.transport_endpoints;
  if (
    roles.size !== 3 ||
    [accept.session_id, accept.client_challenge].includes(accept.provider_challenge) ||
    new Set(endpoints).size !== endpoints.length ||
    endpoints.some((endpoint) => endpoint.length === 0)
  ) {
    throw new ProtocolError("handshake accept keys, challenge, or endpoints");
  }
  const echoed = ["protocol", "wire_version", "profile_id", "network_identity", "session_id", "client_challenge",
    "client_session_xonly_key"] as const;
  if (echoed.some((field) => !same(accept[field], init[field]))) {
    throw new ProtocolError("handshake accept does not echo the initiation");
  }
  if (accept.handshake_init_hash !== bytesToHex(handshakeInitHash(init))) {
    throw new ProtocolError("handshake_init_hash mismatch");
  }
  if (accept.provider_identity_xonly_key !== init.expected_provider_identity_xonly_key) {
    throw new ProtocolError("provider identity mismatch");
  }
  if (
    !init.requested_encryption_suites.includes(accept.selected_encryption_suite) ||
    !accept.selected_capabilities.every((item) => init.requested_capabilities.includes(item))
  ) {
    throw new ProtocolError("provider selected something that was not requested");
  }
  const required = new Set([...init.required_features, ...accept.required_features]);
  if ([...required].some((feature) => feature !== EPOCH_SESSION_FEATURE && feature !== COOPERATIVE_CLAIM_FEATURE)) {
    throw new ProtocolError("handshake requires an unknown feature");
  }
  if (init.required_features.includes(COOPERATIVE_CLAIM_FEATURE) !== accept.required_features.includes(COOPERATIVE_CLAIM_FEATURE) ||
    (init.profile_id !== "ln-to-btc/v1" && !init.required_features.includes(COOPERATIVE_CLAIM_FEATURE))) {
    throw new ProtocolError("cooperative claim must be jointly negotiated");
  }
  if (required.has(EPOCH_SESSION_FEATURE)) {
    const epoch = (init.extensions[EPOCH_SESSION_EXTENSION] as { epoch_inbox_xonly_key?: string } | undefined)
      ?.epoch_inbox_xonly_key;
    if (
      !init.required_features.includes(EPOCH_SESSION_FEATURE) ||
      !accept.required_features.includes(EPOCH_SESSION_FEATURE) ||
      accept.provider_session_xonly_key === epoch
    ) {
      throw new ProtocolError("epoch-bound admission must be jointly negotiated");
    }
  }
  verifySchnorr(init.expected_provider_identity_xonly_key, handshakeAcceptHash(accept), signature, "handshake");
  if (accept.provider_session_xonly_key !== senderKey) {
    throw new ProtocolError("handshake accept names another provider session key");
  }
  return accept;
}

export interface SwapLimits {
  readonly max_success_fee_sat: string;
  readonly max_funding_fee_sat: string;
  readonly max_claim_fee_sat: string;
  readonly max_refund_fee_sat: string;
  readonly max_refund_lock_height: number;
}

export interface FirmQuoteRequest {
  readonly kind: "btc-to-ln";
  readonly mode: "firm";
  readonly lightning_principal_sat: string;
  readonly invoice: string;
  readonly client_contract_compressed_key: string;
  readonly recovery_authorization_xonly_key: string;
  readonly client_destination_script: string;
  readonly limits: SwapLimits;
  readonly extensions: Record<string, never>;
}

export interface BtcToLnTerms {
  readonly protocol: "rillswap";
  readonly contract_version: "1";
  readonly profile_id: "btc-to-ln/v1";
  readonly network_identity: unknown;
  readonly provider_identity_key: string;
  readonly client_contract_compressed_key: string;
  readonly provider_contract_compressed_key: string;
  readonly claimant: "provider";
  readonly refund_party: "client";
  readonly invoice_binding: InvoiceBinding;
  readonly economics: {
    readonly kind: "btc-to-ln";
    readonly lightning_principal_sat: string;
    readonly success_fee_sat: string;
    readonly contract_amount_sat: string;
  };
  readonly refund_lock_height: number;
  readonly funding_confirmations: number;
  readonly settlement_confirmations: number;
  readonly refund_resolution_confirmations: number;
  readonly max_funding_fee_sat: string;
  readonly max_claim_fee_sat: string;
  readonly max_refund_fee_sat: string;
  readonly client_destination_script: string;
  readonly provider_destination_script: string;
  readonly recovery_authorization_xonly_key: string;
  readonly terms_expiry: number;
  readonly timing_policy: {
    readonly kind: "btc-to-ln";
    readonly max_outgoing_htlc_expiry_height: number;
    readonly learn_and_claim_blocks: number;
    readonly client_response_blocks: number;
    readonly claim_confirmation_blocks: number;
  };
  readonly required_features: readonly string[];
  readonly extensions: Record<string, unknown>;
}

export interface TermsOffer {
  readonly terms: { readonly contract_hash: string; readonly contract_terms: BtcToLnTerms; readonly handshake_hash: string };
  readonly provider_terms_signature: string;
}

const DESTINATION = /^(0014[0-9a-f]{40}|5120[0-9a-f]{64})$/;

/** ContractTerms model rules for the BTC to LN profile (messages.py). */
export function checkBtcToLnTerms(terms: BtcToLnTerms): void {
  requireShape("validateContractTerms", terms);
  const economics = terms.economics;
  const timing = terms.timing_policy;
  if (terms.profile_id !== "btc-to-ln/v1" || economics.kind !== "btc-to-ln" || timing.kind !== "btc-to-ln") {
    throw new ProtocolError("terms are not BTC to LN");
  }
  if (terms.claimant !== "provider" || terms.refund_party !== "client") throw new ProtocolError("roles reversed");
  const principal = sats(economics.lightning_principal_sat, "principal", true);
  const fee = sats(economics.success_fee_sat, "success fee");
  if (principal + fee !== sats(economics.contract_amount_sat, "contract amount", true)) {
    throw new ProtocolError("economics must satisfy V = L + S");
  }
  for (const [value, what] of [
    [terms.max_funding_fee_sat, "max funding fee"],
    [terms.max_claim_fee_sat, "max claim fee"],
    [terms.max_refund_fee_sat, "max refund fee"],
  ] as const) {
    sats(value, what);
  }
  if (!DESTINATION.test(terms.client_destination_script) || !DESTINATION.test(terms.provider_destination_script)) {
    throw new ProtocolError("destination scripts must be P2WPKH or P2TR");
  }
  const purposes = new Set([
    terms.provider_identity_key,
    terms.client_contract_compressed_key.slice(2),
    terms.provider_contract_compressed_key.slice(2),
    terms.recovery_authorization_xonly_key,
  ]);
  if (purposes.size !== 4) throw new ProtocolError("keys assigned to distinct purposes must be distinct");
  const binding = terms.invoice_binding;
  if (BigInt(binding.amount_msat) !== principal * 1000n || binding.expires_at <= binding.created_at) {
    throw new ProtocolError("invoice does not equal the principal");
  }
  if (timing.max_outgoing_htlc_expiry_height + timing.learn_and_claim_blocks >= terms.refund_lock_height + 1) {
    throw new ProtocolError("outgoing HTLC exposure does not fit before refund");
  }
  // Both handshake halves already carry the feature (checkHandshakeAccept).
  if (terms.required_features.length !== 1 || terms.required_features[0] !== COOPERATIVE_CLAIM_FEATURE) {
    throw new ProtocolError("terms offer does not commit to cooperative claims");
  }
}

export interface OfferContext {
  readonly request: FirmQuoteRequest;
  readonly invoiceBinding: InvoiceBinding;
  readonly transcript: string;
  readonly envelopeContractHash: string | null;
  readonly identity: string;
  readonly network: unknown;
  readonly now: number;
}

/** check_terms_offer plus the CLI's identity, network, and time binding. */
export function checkTermsOffer(payload: unknown, context: OfferContext): BtcToLnTerms {
  const offer = requireShape<TermsOffer>("validateTermsOffer", payload);
  const terms = offer.terms.contract_terms;
  checkBtcToLnTerms(terms);
  const { request, invoiceBinding, identity } = context;
  const limits = request.limits;
  const economics = terms.economics;
  const checks: [boolean, string][] = [
    [offer.terms.handshake_hash === context.transcript, "handshake hash"],
    [same(terms.invoice_binding, invoiceBinding), "invoice binding"],
    [terms.client_contract_compressed_key === request.client_contract_compressed_key, "client contract key"],
    [terms.recovery_authorization_xonly_key === request.recovery_authorization_xonly_key, "recovery key"],
    [terms.client_destination_script === request.client_destination_script, "destination"],
    [economics.lightning_principal_sat === request.lightning_principal_sat, "principal"],
    [invoiceBinding.amount_msat === (BigInt(request.lightning_principal_sat) * 1000n).toString(), "invoice amount"],
    [terms.refund_lock_height <= limits.max_refund_lock_height, "refund lock height"],
    [BigInt(economics.success_fee_sat) <= BigInt(limits.max_success_fee_sat), "success fee"],
    [BigInt(terms.max_funding_fee_sat) <= BigInt(limits.max_funding_fee_sat), "funding fee"],
    [BigInt(terms.max_claim_fee_sat) <= BigInt(limits.max_claim_fee_sat), "claim fee"],
    [BigInt(terms.max_refund_fee_sat) <= BigInt(limits.max_refund_fee_sat), "refund fee"],
  ];
  for (const [ok, what] of checks) {
    if (!ok) throw new ProtocolError(`terms offer does not honor request: ${what}`);
  }
  checkSignedOfferBinding(offer, context);
  return terms;
}

interface SignedTerms {
  readonly terms: {
    readonly contract_hash: string;
    readonly contract_terms: { readonly provider_identity_key: string; readonly network_identity: unknown; readonly terms_expiry: number };
    readonly handshake_hash: string;
  };
  readonly provider_terms_signature: string;
}

/** Both directions: the identity signs these exact terms, for this network, before they expire. */
function checkSignedOfferBinding(
  offer: SignedTerms,
  context: Pick<OfferContext, "identity" | "envelopeContractHash" | "network" | "now">,
): void {
  const terms = offer.terms.contract_terms;
  verifySchnorr(context.identity, providerTermsHash(offer.terms), offer.provider_terms_signature, "provider terms");
  const hash = bytesToHex(contractHash(offer.terms.contract_terms));
  if (
    hash !== offer.terms.contract_hash ||
    hash !== context.envelopeContractHash ||
    terms.provider_identity_key !== context.identity ||
    !same(terms.network_identity, context.network) ||
    context.now >= terms.terms_expiry
  ) {
    throw new ProtocolError("terms offer is not bound to this provider, network, or time");
  }
}

// RS-004 LN to BTC: the client is claimant, the provider funds and may refund.

export interface ReverseLimits {
  readonly max_success_fee_sat: string;
  readonly min_claim_fee_reserve_sat: string;
  readonly max_claim_fee_sat: string;
  readonly min_refund_lock_height: number;
  readonly max_incoming_htlc_expiry_height: number;
}

export interface ReverseFirmQuoteRequest {
  readonly kind: "ln-to-btc";
  readonly mode: "firm";
  readonly nominal_payout_sat: string;
  readonly payment_hash: string;
  readonly client_contract_compressed_key: string;
  readonly recovery_authorization_xonly_key: string;
  readonly client_destination_script: string;
  readonly limits: ReverseLimits;
  readonly extensions: Record<string, never>;
}

export interface LnToBtcTerms extends Omit<BtcToLnTerms, "profile_id" | "claimant" | "refund_party" | "economics" | "timing_policy"> {
  readonly profile_id: "ln-to-btc/v1";
  readonly claimant: "client";
  readonly refund_party: "provider";
  readonly economics: {
    readonly kind: "ln-to-btc";
    readonly contract_amount_sat: string;
    readonly nominal_payout_sat: string;
    readonly claim_fee_reserve_sat: string;
    readonly success_fee_sat: string;
    readonly mining_prepayment_sat: string;
    readonly hold_invoice_sat: string;
  };
  readonly timing_policy: {
    readonly kind: "ln-to-btc";
    readonly min_incoming_htlc_expiry_height: number;
    readonly refund_and_ln_resolution_blocks: number;
    readonly client_response_blocks: number;
    readonly claim_confirmation_blocks: number;
  };
}

export interface ReverseTermsOffer {
  readonly terms: { readonly contract_hash: string; readonly contract_terms: LnToBtcTerms; readonly handshake_hash: string };
  readonly provider_terms_signature: string;
  readonly hold_invoice: string;
}

/** Refuse a request the browser would build wrongly before it reaches any relay. */
export function checkReverseFirmQuoteRequest(request: ReverseFirmQuoteRequest): ReverseFirmQuoteRequest {
  requireShape("validateReverseFirmQuoteRequest", request);
  sats(request.nominal_payout_sat, "payout", true);
  for (const value of [request.limits.max_success_fee_sat, request.limits.min_claim_fee_reserve_sat, request.limits.max_claim_fee_sat]) {
    sats(value, "limit");
  }
  if (!DESTINATION.test(request.client_destination_script)) throw new ProtocolError("destination must be P2WPKH or P2TR");
  return request;
}

/** ContractTerms model rules for the LN to BTC profile (messages.py _validate_ln_to_btc). */
export function checkLnToBtcTerms(terms: LnToBtcTerms): void {
  requireShape("validateContractTerms", terms);
  const { economics, timing_policy: timing } = terms;
  if (terms.profile_id !== "ln-to-btc/v1" || economics.kind !== "ln-to-btc" || timing.kind !== "ln-to-btc") {
    throw new ProtocolError("terms are not LN to BTC");
  }
  if (terms.claimant !== "client" || terms.refund_party !== "provider") throw new ProtocolError("roles reversed");
  const contract = sats(economics.contract_amount_sat, "contract amount", true);
  const payout = sats(economics.nominal_payout_sat, "payout", true);
  const reserve = sats(economics.claim_fee_reserve_sat, "claim fee reserve");
  const fee = sats(economics.success_fee_sat, "success fee");
  const prepayment = sats(economics.mining_prepayment_sat, "mining prepayment");
  const hold = sats(economics.hold_invoice_sat, "hold invoice", true);
  if (payout + reserve !== contract) throw new ProtocolError("economics must satisfy V = D + C");
  if (prepayment > fee || contract + fee > MAX_SATS || contract + fee - prepayment !== hold) {
    throw new ProtocolError("economics must satisfy H = V + S - M");
  }
  // Prepayment needs a feature this client never negotiates (checkHandshakeAccept).
  if (prepayment !== 0n) throw new ProtocolError("mining prepayment is not supported");
  for (const value of [terms.max_funding_fee_sat, terms.max_claim_fee_sat, terms.max_refund_fee_sat]) sats(value, "fee cap");
  if (!DESTINATION.test(terms.client_destination_script) || !DESTINATION.test(terms.provider_destination_script)) {
    throw new ProtocolError("destination scripts must be P2WPKH or P2TR");
  }
  const purposes = new Set([terms.provider_identity_key, terms.client_contract_compressed_key.slice(2),
    terms.provider_contract_compressed_key.slice(2), terms.recovery_authorization_xonly_key]);
  if (purposes.size !== 4) throw new ProtocolError("keys assigned to distinct purposes must be distinct");
  const binding = terms.invoice_binding;
  if (BigInt(binding.amount_msat) !== hold * 1000n || binding.expires_at <= binding.created_at) {
    throw new ProtocolError("invoice does not equal the held amount");
  }
  if (terms.refund_lock_height + 1 + timing.refund_and_ln_resolution_blocks >= timing.min_incoming_htlc_expiry_height) {
    throw new ProtocolError("incoming HTLC exposure does not cover refund resolution");
  }
  if (terms.required_features.some((feature) => feature !== COOPERATIVE_CLAIM_FEATURE)) throw new ProtocolError("reverse terms require an unsupported feature");
}

export interface ReverseOfferContext extends Omit<OfferContext, "request" | "invoiceBinding"> {
  readonly request: ReverseFirmQuoteRequest;
  readonly handshakeInit: HandshakeInit;
  readonly handshakeAccept: HandshakeAccept;
  /** Decode the provider's hold invoice for this network; throws on anything unacceptable. */
  readonly decodeInvoice: (invoice: string) => InvoiceBinding;
}

/** check_reverse_terms_offer plus identity, network, and time binding. Run before paying anything. */
export function checkReverseTermsOffer(payload: unknown, context: ReverseOfferContext): { terms: LnToBtcTerms; holdInvoice: string } {
  const offer = requireShape<ReverseTermsOffer>("validateReverseTermsOffer", payload);
  const terms = offer.terms.contract_terms;
  checkLnToBtcTerms(terms);
  const { handshakeInit: init, handshakeAccept: accept } = context;
  if (!same(init.network_identity, context.network) || !same(accept.network_identity, context.network)) throw new ProtocolError("terms offer is not bound to this provider (reverse handshake network)");
  if (init.profile_id !== "ln-to-btc/v1" || accept.profile_id !== init.profile_id ||
    bytesToHex(handshakeHash(init, accept)) !== context.transcript) throw new ProtocolError("reverse handshake hash or profile mismatch");
  const cooperation = init.required_features.includes(COOPERATIVE_CLAIM_FEATURE);
  if (cooperation !== accept.required_features.includes(COOPERATIVE_CLAIM_FEATURE) ||
    cooperation !== terms.required_features.includes(COOPERATIVE_CLAIM_FEATURE)) throw new ProtocolError("reverse cooperation commitment mismatch");
  if (cooperation) throw new ProtocolError("browser reverse execution requires unilateral terms");
  let binding: InvoiceBinding;
  try {
    binding = context.decodeInvoice(offer.hold_invoice);
  } catch {
    throw new ProtocolError("hold invoice unacceptable");
  }
  const { request } = context;
  const { limits } = request;
  const { economics } = terms;
  const checks: [boolean, string][] = [
    [offer.terms.handshake_hash === context.transcript, "handshake hash"],
    [same(terms.invoice_binding, binding), "invoice binding"],
    [binding.payment_hash === request.payment_hash, "payment hash"],
    [terms.client_contract_compressed_key === request.client_contract_compressed_key, "client contract key"],
    [terms.recovery_authorization_xonly_key === request.recovery_authorization_xonly_key, "recovery key"],
    [terms.client_destination_script === request.client_destination_script, "destination"],
    [economics.nominal_payout_sat === request.nominal_payout_sat, "payout"],
    [binding.amount_msat === (BigInt(economics.hold_invoice_sat) * 1000n).toString(), "hold invoice amount"],
    [terms.refund_lock_height >= limits.min_refund_lock_height, "refund lock height"],
    [terms.timing_policy.min_incoming_htlc_expiry_height <= limits.max_incoming_htlc_expiry_height, "incoming HTLC expiry"],
    [BigInt(economics.success_fee_sat) <= BigInt(limits.max_success_fee_sat), "success fee"],
    [BigInt(economics.claim_fee_reserve_sat) >= BigInt(limits.min_claim_fee_reserve_sat), "claim fee reserve"],
    [BigInt(terms.max_claim_fee_sat) <= BigInt(limits.max_claim_fee_sat), "claim fee"],
  ];
  for (const [ok, what] of checks) {
    if (!ok) throw new ProtocolError(`terms offer does not honor request: ${what}`);
  }
  checkSignedOfferBinding(offer, context);
  return { terms, holdInvoice: offer.hold_invoice };
}
