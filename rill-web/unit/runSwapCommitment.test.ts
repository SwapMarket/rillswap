import { expect, test } from "bun:test";

for (const scenario of ["wallet_delay", "funded_recovery_delay", "checkpoint_delay", "ack_delay", "transport_after_share"]) {
  test(`actual runSwap commitment sequence: ${scenario}`, async () => {
    const child = Bun.spawn([process.execPath, "unit/fixtures/runSwapCommitmentFixture.ts", scenario], { stdout: "pipe", stderr: "pipe" });
    const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(errors).toBe(""); expect(status).toBe(0);
    const result = JSON.parse(output);
    expect(result.failed).toBe(true); expect(result.broadcasts).toBe(0); expect(result.redispatchRefused).toBe(true);
    const afterShare = scenario === "ack_delay" || scenario === "transport_after_share";
    expect(result.shared).toBe(afterShare ? 1 : 0); expect(result.checkpoint.stage).toBe("ambiguous");
    expect(result.recoveryStages).toContain("terms");
    if (scenario !== "wallet_delay") expect(result.recoveryStages).toContain("funded");
    expect(result.checkpoint.route.recoveryRef).toBe(scenario === "wallet_delay" ? "wallet:terms" : "wallet:funded");
    expect(JSON.stringify(result.checkpoint)).not.toContain("preimage");
  });
}
