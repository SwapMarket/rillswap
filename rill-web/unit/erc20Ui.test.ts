import { describe, expect, test } from "bun:test";

import { formatTokenAmount, parseTokenAmount } from "../src/erc20Ui";
import { selectEvmAsset, type LocatedProvider } from "../src/swap/marketplace";
import type { EvmAssetIdentity } from "../src/manualProviderAdvertisement";

describe("token amounts", () => {
  test("format drops trailing zeros and keeps whole units exact", () => {
    expect(formatTokenAmount(1_005_000n, 6)).toBe("1.005");
    expect(formatTokenAmount(100_200_000n, 6)).toBe("100.2");
    expect(formatTokenAmount(0n, 6)).toBe("0");
    expect(formatTokenAmount(7n, 6)).toBe("0.000007");
    expect(formatTokenAmount(10n ** 18n, 18)).toBe("1");
  });
  test("parse accepts at most the token's fraction digits", () => {
    expect(parseTokenAmount("5", 6, "fee")).toBe(5_000_000n);
    expect(parseTokenAmount(" 0.25 ", 6, "fee")).toBe(250_000n);
    expect(parseTokenAmount("0", 6, "fee")).toBe(0n);
    for (const bad of ["", "-1", "1.", ".5", "1.0000001", "01", "1e3", "abc"]) {
      expect(() => parseTokenAmount(bad, 6, "fee")).toThrow("fee must be a decimal amount");
    }
  });
});

describe("asset selection", () => {
  const asset = (chain_id: number, token_symbol: string, suffix = "2b"): EvmAssetIdentity => ({
    family: "evm", chain_id, name: `chain-${chain_id}`, htlc_contract: `0x${"1a".repeat(20)}`, htlc_version: 6,
    token_contract: `0x${suffix.repeat(20)}`, token_symbol, token_decimals: 6, block_seconds: 12, deployment_namespace: null,
  });
  const provider = (identity: string, evmAssets: EvmAssetIdentity[]): LocatedProvider =>
    ({ announcement: { identityXOnlyKey: identity, evmAssets }, rawAnnouncement: "", relayUrls: [] }) as unknown as LocatedProvider;

  test("trusted configuration fixes the asset regardless of provider order", () => {
    const trusted = asset(10, "USDC");
    const first = provider("aa", [asset(10, "USDC")]);
    const sameAsset = provider("bb", [asset(1, "USDT", "2c"), asset(10, "USDC")]);
    const otherChain = provider("cc", [asset(1, "USDC")]);
    const otherHtlc = provider("dd", [{ ...asset(10, "USDC"), htlc_contract: `0x${"1b".repeat(20)}` }]);
    const selected = selectEvmAsset([otherChain, otherHtlc, provider("ee", []), first, sameAsset], trusted);
    expect(selected?.asset).toBe(trusted);
    expect(selected?.providers.map((item) => item.announcement.identityXOnlyKey)).toEqual(["aa", "bb"]);
    expect(selectEvmAsset([otherChain], trusted)).toBeNull();
  });

  test("a counterfeit symbol or any altered identity field is excluded", () => {
    const trusted = asset(10, "USDC");
    const substitutions: Record<string, unknown> = {
      family: "btc", chain_id: 11, name: "different", htlc_contract: `0x${"1b".repeat(20)}`,
      htlc_version: 7, token_contract: `0x${"2c".repeat(20)}`, token_symbol: "fUSDC",
      token_decimals: 18, block_seconds: 1, deployment_namespace: "other-deployment",
    };
    for (const [field, value] of Object.entries(substitutions)) {
      const substitute = { ...trusted, [field]: value } as EvmAssetIdentity;
      expect(selectEvmAsset([provider("evil", [substitute])], trusted)).toBeNull();
      expect(selectEvmAsset([provider("evil", [substitute]), provider("honest", [trusted])], trusted)?.providers)
        .toHaveLength(1);
    }
  });
});
