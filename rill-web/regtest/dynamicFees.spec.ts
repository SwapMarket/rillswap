import { test, expect } from "@playwright/test";
import { assertDisposableStack, compose, composeEnabled, run } from "./stack";

const FEATURE = "btc-network-fees/v1";
const EXTENSION = "org.rillswap/fee-policy-v1";

for (const direction of ["btc-to-ln", "ln-to-btc"] as const) {
  test(`real ${direction} CLI swap commits advertised fees and a 60-second quote`, async () => {
    test.skip(!composeEnabled || process.env.RILL_DEV_NETWORK_FEES !== "1", "Fresh disposable network-fee opt-in required");
    assertDisposableStack();
    await run("swap", direction, "30000");
    const terms = JSON.parse(compose("exec", "-T", "tools", "python", "-c",
      "import sqlite3,json,sys; " +
      "c=sqlite3.connect('file:/state/makers/'+sys.argv[1]+'/provider-store/live.sqlite?mode=ro',uri=True); " +
      "row=c.execute('select terms_offer from swaps order by rowid desc limit 1').fetchone(); " +
      "print(json.dumps(json.loads(row[0])['payload']['terms']['contract_terms']))", direction));
    expect(terms.required_features).toContain(FEATURE);
    const fees = terms.extensions[EXTENSION];
    expect(fees.policy.model).toBe("p2tr-cooperative-1in-2out/v1");
    expect(fees.policy.max_routing_fee_ppm).toBe(1000);
    expect(terms.terms_expiry - fees.issued_at).toBe(60);
    expect(fees.issued_at - fees.estimated_at).toBeLessThanOrEqual(10);
    const principal = BigInt(direction === "btc-to-ln" ? terms.economics.lightning_principal_sat : terms.economics.nominal_payout_sat);
    expect(principal).toBe(30000n);
    const service = BigInt(fees.policy.base_sat) + (principal * BigInt(fees.policy.proportional_millionths) + 999999n) / 1000000n;
    const network = (154n * BigInt(fees.feerate_sat_kvb) + 999n) / 1000n;
    expect(BigInt(fees.service_fee_sat)).toBe(service);
    expect(BigInt(fees.network_fee_sat)).toBe(network);
    expect(BigInt(terms.economics.success_fee_sat)).toBe(service + network);
    expect(fees.offer_event_id).toMatch(/^[0-9a-f]{64}$/);
  });
}
