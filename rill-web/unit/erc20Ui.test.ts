import { describe, expect, test } from "bun:test";

import { formatTokenAmount, parseTokenAmount } from "../src/erc20Ui";
import { matchEvmAsset, selectEvmAsset, type LocatedProvider } from "../src/swap/marketplace";
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

  test("a symbol matches by suffix, so a dev chain's fUSDC serves USDC", () => {
    expect(matchEvmAsset([asset(31337, "fUSDC")], "USDC")?.token_symbol).toBe("fUSDC");
    expect(matchEvmAsset([asset(1, "USDT", "2c"), asset(1, "USDC")], "USDC")?.token_contract).toBe(`0x${"2b".repeat(20)}`);
    expect(matchEvmAsset([asset(1, "USDCX")], "USDC")).toBeNull();
    expect(matchEvmAsset([{ ...asset(1, "USDC"), htlc_version: 7 as unknown as 6 }], "USDC")).toBeNull();
    expect(matchEvmAsset([], "USDT")).toBeNull();
  });

  test("the first eligible provider's match fixes the asset and keeps only providers serving exactly it", () => {
    const first = provider("aa", [asset(10, "USDC")]);
    const sameAsset = provider("bb", [asset(1, "USDT", "2c"), asset(10, "USDC")]);
    const otherChain = provider("cc", [asset(1, "USDC")]);
    const otherHtlc = provider("dd", [{ ...asset(10, "USDC"), htlc_contract: `0x${"1b".repeat(20)}` }]);
    const selected = selectEvmAsset([provider("ee", []), first, otherChain, sameAsset, otherHtlc], "USDC");
    expect(selected?.asset.chain_id).toBe(10);
    expect(selected?.providers.map((item) => item.announcement.identityXOnlyKey)).toEqual(["aa", "bb"]);
    expect(selectEvmAsset([otherChain], "USDT")).toBeNull();
  });
});
