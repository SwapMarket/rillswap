import { expect, test } from "bun:test";
import terms from "../../rill-docs/fixtures/checkout/native-lightning.json";
import { evaluateRoute, nextRouteAction, type FrozenRouteOffer, type RegisteredRouteCapability, type RouteCheckpoint, type RoutePolicy } from "../src/routing";

const destination = `lightning:${terms.network}:${terms.receiver}`;
const policy: RoutePolicy = { version: "native-lightning/1", merchantOrigin: terms.merchantOrigin, receiver: terms.receiver, network: "regtest", maxBuyerExtraMsat: "100000", maxBuyerExtraBps: 1000,
  allowedRouteClasses: ["direct_swap", "bridge_hub_swap", "sequential_swaps"], maxSteps: 3, maxSwaps: 2, signerIds: ["payer-source", "payer-hub"], gasAssetIdsWithApprovedBudget: ["source-gas", "hub-gas"], intermediateAssetIds: ["hub-usdt", "hub-btc"] };
const bridge: RegisteredRouteCapability = { version: "route-capability/1", id: "fixture_bridge", adapterVersion: "fixture/1", deploymentId: "fixture_nonoperational",
  kind: "bridge", stepAtomicity: "transport_only", sourceAssetId: "source-usdt", destinationAssetId: "hub-usdt", independentlyVerified: true, operationalConformanceVerified: true,
  sourceOwner: "payer", destinationOwner: "payer", sourceSigner: "payer-source", destinationSigner: null, gasAssetIds: ["source-gas"], recovery: { action: "delivery_retry", assetId: "hub-usdt", owner: "payer" } };
const swap: RegisteredRouteCapability = { ...bridge, id: "fixture_swap", kind: "swap", stepAtomicity: "atomic_swap", sourceAssetId: "hub-usdt", destinationAssetId: destination,
  sourceSigner: "payer-hub", destinationOwner: "merchant", gasAssetIds: ["hub-gas"], recovery: { action: "protocol_refund", assetId: "hub-usdt", owner: "payer" } };
const offer: FrozenRouteOffer = { version: "route-offer/1", id: "route_offer_fixture_1", intentId: terms.intentId, attemptId: terms.attemptId, paymentHash: terms.paymentHash,
  steps: [{ capabilityId: bridge.id, quoteId: "bridge_quote_fixture_1", expiresAt: 2000 }, { capabilityId: swap.id, quoteId: "swap_quote_fixture_001", expiresAt: 1800 }],
  totalBuyerExtraMsat: "50000", allCostsKnown: true, quoteType: "firm" };
const checkpoint: RouteCheckpoint = { version: "route-checkpoint/1", offerId: offer.id, attemptId: offer.attemptId,
  steps: offer.steps.map((step, index) => ({ capabilityId: step.capabilityId, quoteId: step.quoteId, operationId: "route_operation_000" + index, state: "prepared" })) };

test("approved bridge/hub swap is sequential, never promoted to end-to-end atomicity", () => {
  const result = evaluateRoute(terms, offer, [bridge, swap], policy, 1000); expect(result.eligible).toBe(true);
  if (!result.eligible) throw new Error(); expect(result.atomicity).toBe("sequential_nonatomic"); expect(result.routeClass).toBe("bridge_hub_swap");
  expect(result.steps[0]?.recovery.assetId).toBe("hub-usdt"); expect(Object.isFrozen(result.steps)).toBe(true);
});
test("only a standalone individually atomic swap carries the direct atomic label", () => {
  const direct = { ...offer, steps: [offer.steps[1]!] };
  const result = evaluateRoute(terms, direct, [swap], policy, 1000); expect(result.eligible).toBe(true);
  if (result.eligible) expect(result.atomicity).toBe("single_atomic_swap");
  expect(evaluateRoute(terms, direct, [{ ...swap, stepAtomicity: "transport_only" }], policy, 1000).eligible).toBe(false);
});
test("unknown costs, mismatched destination/hash, unavailable signer and catalog-only capability cannot admit a route", () => {
  for (const patch of [{ allCostsKnown: false as true }, { paymentHash: "f".repeat(64) }, { totalBuyerExtraMsat: "100001" }]) expect(evaluateRoute(terms, { ...offer, ...patch }, [bridge, swap], policy, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, { ...swap, operationalConformanceVerified: false as true }], policy, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, swap], { ...policy, signerIds: ["payer-source"] }, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, swap], { ...policy, gasAssetIdsWithApprovedBudget: [] }, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, { ...swap, destinationAssetId: "wrong-receiver" }], policy, 1000).eligible).toBe(false);
});
test("intermediate inventory, ownership and route limits are explicit, not inferred from provider branding", () => {
  expect(evaluateRoute(terms, offer, [bridge, swap], { ...policy, intermediateAssetIds: [] }, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, { ...swap, sourceOwner: "merchant" }], policy, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, swap], { ...policy, maxSteps: 1 }, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, swap], { ...policy, allowedRouteClasses: ["direct_swap"] }, 1000).eligible).toBe(false);
  expect(evaluateRoute(terms, offer, [bridge, swap, swap], policy, 1000).eligible).toBe(false);
});
test("unknown/partial/old checkpoints conservatively require intervention, never automatic dispatch", () => {
  expect(nextRouteAction(offer, null, 1000)).toEqual({ action: "intervention" });
  expect(nextRouteAction(offer, { ...checkpoint, version: "route-checkpoint/0" as "route-checkpoint/1" }, 1000)).toEqual({ action: "intervention" });
  expect(nextRouteAction(offer, { ...checkpoint, steps: [] }, 1000)).toEqual({ action: "intervention" });
  expect(nextRouteAction(offer, { ...checkpoint, steps: [checkpoint.steps[0]!, { ...checkpoint.steps[1]!, capabilityId: "changed" }] }, 1000)).toEqual({ action: "intervention" });
});
test("restart reconciles the same expired dispatched operation; hub quote expiration stops safely", () => {
  const sourceDispatched: RouteCheckpoint = { ...checkpoint, steps: [{ ...checkpoint.steps[0]!, state: "dispatched" }, checkpoint.steps[1]!] };
  expect(nextRouteAction(offer, sourceDispatched, 3000)).toEqual({ action: "reconcile_existing_operation", stepIndex: 0, operationId: checkpoint.steps[0]!.operationId });
  const sourceArrived: RouteCheckpoint = { ...checkpoint, steps: [{ ...checkpoint.steps[0]!, state: "destination_observed" }, checkpoint.steps[1]!] };
  expect(nextRouteAction(offer, sourceArrived, 1800)).toEqual({ action: "intervention" });
  expect(nextRouteAction(offer, sourceArrived, 1700)).toEqual({ action: "request_step_approval", stepIndex: 1, operationId: checkpoint.steps[1]!.operationId });
});
test("owner recovery and full route completion remain separate from merchant payment", () => {
  const recover: RouteCheckpoint = { ...checkpoint, steps: [{ ...checkpoint.steps[0]!, state: "recovery_required" }, checkpoint.steps[1]!] };
  expect(nextRouteAction(offer, recover, 3000).action).toBe("owner_recovery");
  const done: RouteCheckpoint = { ...checkpoint, steps: checkpoint.steps.map((step) => ({ ...step, state: "destination_observed" })) };
  expect(nextRouteAction(offer, done, 3000)).toEqual({ action: "awaiting_merchant_receipt" });
  const outOfOrder: RouteCheckpoint = { ...checkpoint, steps: [checkpoint.steps[0]!, { ...checkpoint.steps[1]!, state: "dispatched" }] };
  expect(nextRouteAction(offer, outOfOrder, 1000)).toEqual({ action: "intervention" });
});
test("deserialized numeric/array/duplicate operation IDs and malformed later steps cannot resume", () => {
  for (const operationId of [1234567890123456, ["route_operation_0001"]]) {
    const invalid = { ...checkpoint, steps: [{ ...checkpoint.steps[0]!, state: "dispatched", operationId }, checkpoint.steps[1]!] } as unknown as RouteCheckpoint;
    expect(nextRouteAction(offer, invalid, 1000)).toEqual({ action: "intervention" });
  }
  const duplicate: RouteCheckpoint = { ...checkpoint, steps: [checkpoint.steps[0]!, { ...checkpoint.steps[1]!, operationId: checkpoint.steps[0]!.operationId }] };
  expect(nextRouteAction(offer, duplicate, 1000)).toEqual({ action: "intervention" });
  const laterInvalid = { ...checkpoint, steps: [{ ...checkpoint.steps[0]!, state: "dispatched" }, { ...checkpoint.steps[1]!, operationId: null }] } as unknown as RouteCheckpoint;
  expect(nextRouteAction(offer, laterInvalid, 1000)).toEqual({ action: "intervention" });
});
