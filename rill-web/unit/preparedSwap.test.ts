import { expect, test } from "bun:test";

for (const scenario of ["only", "disposed", "expired", "concurrent", "mutation", "callback_error"]) {
  test(`prepared quote lifecycle: ${scenario}`, async () => {
    const child = Bun.spawn([process.execPath, "unit/fixtures/runSwapCommitmentFixture.ts", `prepare_${scenario}`], { stdout: "pipe", stderr: "pipe" });
    const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(errors).toBe(""); expect(status).toBe(0);
    const result = JSON.parse(output);
    expect(result.before).toEqual({ accepted: false, shared: 0, recovery: 0 });
    expect(result.quoteFrozen).toBe(true);
    expect(result.secretsWiped).toBe(true);
    if (scenario === "only" || scenario === "disposed" || scenario === "expired") {
      expect(result.accepted).toBe(false); expect(result.shared).toBe(0); expect(result.recoveryStages).toEqual([]);
    }
    if (scenario !== "only" && scenario !== "mutation") expect(result.refused).toBe(true);
    if (scenario === "concurrent") { expect(result.activeSignerPreserved).toBe(true); expect(result.shared).toBe(1); }
    if (scenario === "mutation") { expect(result.recoveryBirthday).toBe(100); expect(result.shared).toBe(1); }
    if (scenario === "callback_error") { expect(result.accepted).toBe(false); expect(result.shared).toBe(0); }
  });
}

// A deposit found on chain is already broadcast: it is bound and shared, never handed back for broadcast.
for (const scenario of ["deposit", "deposit_refused"]) {
  test(`prepared quote funded by a discovered deposit: ${scenario}`, async () => {
    const child = Bun.spawn([process.execPath, "unit/fixtures/runSwapCommitmentFixture.ts", `prepare_${scenario}`], { stdout: "pipe", stderr: "pipe" });
    const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(errors).toBe(""); expect(status).toBe(0);
    const result = JSON.parse(output);
    expect(result.broadcasts).toBe(0);
    if (scenario === "deposit") {
      expect(result.refused).toBe(false); expect(result.shared).toBe(1); expect(result.recoveryStages).toEqual(["terms", "funded"]);
    } else {
      // The refusal is terminal (no second prompt) and names the deposit and the refund height.
      expect(result.refused).toBe(true); expect(result.shared).toBe(0); expect(result.recoveryStages).toEqual(["terms"]);
      expect(result.refusal).toContain(`deposit ${"7".repeat(64)} cannot fund this swap (funding fee exceeds the signed maximum)`);
      expect(result.refusal).toContain("refundable after block 200");
    }
  });
}
