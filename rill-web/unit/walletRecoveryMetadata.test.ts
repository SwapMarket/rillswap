import { expect, test } from "bun:test";

for (const scenario of ["prepare_wallet", "prepare_wallet_reserved"]) {
  test(`public refund hints are snapshotted and retained in all recovery stages: ${scenario}`, async () => {
    const child = Bun.spawn([process.execPath, "unit/fixtures/runSwapCommitmentFixture.ts", scenario], { stdout: "pipe", stderr: "pipe" });
    const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
    expect(errors).toBe(""); expect(status).toBe(0);
    const result = JSON.parse(output);
    expect(result.recoveryExtensions).toHaveLength(3);
    for (const extensions of result.recoveryExtensions) {
      expect(extensions["rillswap/browser-refund-wallet"]).toMatchObject({ index: 7, scheme: "bip84-rillswap-v1", network: "regtest" });
      expect(JSON.stringify(extensions)).not.toContain("mnemonic");
      expect(JSON.stringify(extensions)).not.toContain("privateKey");
    }
    if (scenario === "prepare_wallet_reserved") expect(result.recoveryExtensions[2].fixture).toBeDefined();
    expect(result.recoveryStages).toEqual(["terms", "funded"]);
    expect(result.shared).toBe(1);
  });
}
