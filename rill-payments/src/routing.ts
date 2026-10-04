import { evaluateNative, type NativePolicy } from "./policy";
import { parseTerms } from "./contract";

export type RouteClass = "direct_swap" | "bridge_to_native" | "bridge_hub_swap" | "sequential_swaps";
export interface RouteCapability {
  readonly version: "route-capability/1";
  readonly id: string;
  readonly adapterVersion: string;
  readonly deploymentId: string;
  readonly kind: "bridge" | "swap";
  readonly stepAtomicity: "atomic_swap" | "transport_only";
  readonly sourceAssetId: string;
  readonly destinationAssetId: string;
  readonly independentlyVerified: true;
  readonly operationalConformanceVerified: true;
  readonly sourceOwner: "payer" | "merchant";
  readonly destinationOwner: "payer" | "merchant";
  readonly sourceSigner: string;
  readonly destinationSigner: string | null;
  readonly recovery: { readonly action: "protocol_refund" | "delivery_retry" | "manual_intervention"; readonly assetId: string; readonly owner: "payer" | "merchant" };
}
export interface FrozenRouteOffer {
  readonly version: "route-offer/1";
  readonly id: string;
  readonly intentId: string;
  readonly attemptId: string;
  readonly paymentHash: string;
  readonly steps: readonly { readonly capabilityId: string; readonly quoteId: string; readonly expiresAt: number }[];
  readonly totalBuyerExtraMsat: string;
  readonly allCostsKnown: true;
  readonly quoteType: "firm";
}
export interface RoutePolicy extends NativePolicy {
  readonly allowedRouteClasses: readonly RouteClass[];
  readonly maxSteps: number;
  readonly maxSwaps: number;
  readonly signerIds: readonly string[];
  readonly gasAssetIdsWithApprovedBudget: readonly string[];
  readonly intermediateAssetIds: readonly string[];
}
export interface RegisteredRouteCapability extends RouteCapability {
  readonly gasAssetIds: readonly string[];
}
export type RouteAdmission = { readonly eligible: false; readonly reason: string } | {
  readonly eligible: true; readonly routeClass: RouteClass; readonly atomicity: "single_atomic_swap" | "sequential_nonatomic";
  readonly steps: readonly RegisteredRouteCapability[];
};

/** Evaluates merchant-configured routes only; discovery catalog data cannot populate this registry. */
export function evaluateRoute(termsInput: unknown, offer: FrozenRouteOffer, registry: readonly RegisteredRouteCapability[], policy: RoutePolicy, now: number): RouteAdmission {
  const refuse = (reason: string): RouteAdmission => ({ eligible: false, reason });
  let terms: ReturnType<typeof parseTerms>;
  try { terms = parseTerms(termsInput); } catch { return refuse("invalid_terms"); }
  if (offer.version !== "route-offer/1" || offer.intentId !== terms.intentId || offer.attemptId !== terms.attemptId || offer.paymentHash !== terms.paymentHash ||
      typeof offer.id !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(offer.id) || offer.allCostsKnown !== true || offer.quoteType !== "firm" ||
      !Number.isSafeInteger(policy.maxSteps) || policy.maxSteps < 1 || policy.maxSteps > 4 || !Number.isSafeInteger(policy.maxSwaps) || policy.maxSwaps < 1 || policy.maxSwaps > 2 ||
      !Array.isArray(offer.steps) || offer.steps.length < 1 || offer.steps.length > policy.maxSteps) return refuse("invalid_or_incomplete_offer");
  const native = evaluateNative({ ...terms, buyerExtraMsat: offer.totalBuyerExtraMsat }, policy, now);
  if (!native.eligible) return refuse(native.reason);
  if (new Set(registry.map((capability) => capability.id)).size !== registry.length) return refuse("ambiguous_registry");
  const steps: RegisteredRouteCapability[] = [];
  for (const step of offer.steps) {
    const capability = registry.find((entry) => entry.id === step.capabilityId);
    if (!capability || capability.version !== "route-capability/1" || capability.independentlyVerified !== true || capability.operationalConformanceVerified !== true ||
        !capability.adapterVersion || !capability.deploymentId || !["bridge", "swap"].includes(capability.kind) || capability.stepAtomicity !== (capability.kind === "swap" ? "atomic_swap" : "transport_only") ||
        !capability.sourceAssetId || !capability.destinationAssetId || ![capability.sourceOwner, capability.destinationOwner, capability.recovery.owner].every((owner) => ["payer", "merchant"].includes(owner)) ||
        !capability.recovery.assetId || !["protocol_refund", "delivery_retry", "manual_intervention"].includes(capability.recovery.action) ||
        typeof step.quoteId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(step.quoteId) || !Number.isSafeInteger(step.expiresAt) || step.expiresAt <= now || step.expiresAt > terms.expiresAt) return refuse("capability_or_quote_unverified");
    if (!policy.signerIds.includes(capability.sourceSigner) || (capability.destinationSigner !== null && !policy.signerIds.includes(capability.destinationSigner)) ||
        capability.gasAssetIds.some((assetId) => !policy.gasAssetIdsWithApprovedBudget.includes(assetId))) return refuse("signer_or_gas_unavailable");
    const previous = steps.at(-1);
    if (previous && (previous.destinationAssetId !== capability.sourceAssetId || previous.destinationOwner !== capability.sourceOwner ||
        !policy.intermediateAssetIds.includes(capability.sourceAssetId))) return refuse("incompatible_intermediate_ownership");
    steps.push(capability);
  }
  const swaps = steps.filter((step) => step.kind === "swap").length, bridges = steps.length - swaps;
  if (swaps > policy.maxSwaps || bridges > 1) return refuse("composition_limit");
  const routeClass: RouteClass = bridges === 0 ? (swaps === 1 ? "direct_swap" : "sequential_swaps") : swaps === 0 ? "bridge_to_native" : "bridge_hub_swap";
  if (!policy.allowedRouteClasses.includes(routeClass)) return refuse("route_class_disabled");
  // Bridging native receipt needs its own order-binding/finality profile, not the direct EOA transfer observer.
  if (steps.at(-1)?.destinationAssetId !== `lightning:${terms.network}:${terms.receiver}`) return refuse("destination_observer_profile_unavailable");
  if (steps[0]?.sourceOwner !== "payer" || steps.at(-1)?.destinationOwner !== "merchant") return refuse("checkout_ownership_mismatch");
  return Object.freeze({ eligible: true, routeClass, atomicity: steps.length === 1 && swaps === 1 ? "single_atomic_swap" : "sequential_nonatomic", steps: Object.freeze(steps.map((step) => Object.freeze({ ...step,
    recovery: Object.freeze({ ...step.recovery }), gasAssetIds: Object.freeze([...step.gasAssetIds]) }))) });
}

export interface RouteCheckpoint {
  readonly version: "route-checkpoint/1";
  readonly offerId: string;
  readonly attemptId: string;
  readonly steps: readonly { readonly capabilityId: string; readonly quoteId: string; readonly operationId: string; readonly state: "prepared" | "dispatched" | "destination_observed" | "recovery_required" }[];
}
export type NextRouteAction = { readonly action: "intervention" | "awaiting_merchant_receipt" } | { readonly action: "request_step_approval" | "reconcile_existing_operation" | "owner_recovery"; readonly stepIndex: number; readonly operationId: string };

/** Resume decisions never dispatch by themselves. Missing/old/partial metadata never starts another operation. */
export function nextRouteAction(offer: FrozenRouteOffer, checkpoint: RouteCheckpoint | null, now: number): NextRouteAction {
  if (!checkpoint || checkpoint.version !== "route-checkpoint/1" || checkpoint.offerId !== offer.id || checkpoint.attemptId !== offer.attemptId ||
      !Number.isSafeInteger(now) || now < 0 || !Array.isArray(checkpoint.steps) || !Array.isArray(offer.steps) || checkpoint.steps.length !== offer.steps.length || checkpoint.steps.length === 0 ||
      checkpoint.steps.some((step) => !step || typeof step !== "object" || typeof step.operationId !== "string") || offer.steps.some((step) => !step || typeof step !== "object") ||
      new Set(checkpoint.steps.map((step) => step.operationId)).size !== checkpoint.steps.length) return { action: "intervention" };
  for (let index = 0; index < checkpoint.steps.length; index++) {
    const step = checkpoint.steps[index]!, quoted = offer.steps[index]!;
    if (typeof step.capabilityId !== "string" || typeof step.quoteId !== "string" || step.capabilityId !== quoted.capabilityId || step.quoteId !== quoted.quoteId || !/^[A-Za-z0-9_-]{16,128}$/.test(step.operationId) ||
        !["prepared", "dispatched", "destination_observed", "recovery_required"].includes(step.state)) return { action: "intervention" };
  }
  for (let index = 0; index < checkpoint.steps.length; index++) {
    const step = checkpoint.steps[index]!, quoted = offer.steps[index]!;
    if (step.state !== "destination_observed") {
      if (checkpoint.steps.slice(index + 1).some((later) => later.state !== "prepared")) return { action: "intervention" };
      if (step.state === "dispatched") return { action: "reconcile_existing_operation", stepIndex: index, operationId: step.operationId };
      if (step.state === "recovery_required") return { action: "owner_recovery", stepIndex: index, operationId: step.operationId };
      if (!Number.isSafeInteger(quoted.expiresAt) || now >= quoted.expiresAt) return { action: "intervention" };
      return { action: "request_step_approval", stepIndex: index, operationId: step.operationId };
    }
  }
  return { action: "awaiting_merchant_receipt" };
}
