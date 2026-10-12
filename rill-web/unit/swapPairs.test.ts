import { expect, test } from "bun:test";
import { ASSETS, routeFor } from "../src/swapPairs";

test("both Bitcoin and Lightning directions map to their protocol profiles and are quotable", () => {
  const forward = routeFor("btc", "ln");
  expect(forward).toMatchObject({ profile: "btc-to-ln/v1", unavailable: null, title: "Bitcoin in. Lightning out." });
  const reverse = routeFor("ln", "btc");
  expect(reverse.profile).toBe("ln-to-btc/v1");
  expect(reverse.unavailable).toBeNull();
  expect(reverse.title).toBe("Lightning in. Bitcoin out.");
});

test("stablecoins route to the RS-010 profiles against Lightning only", () => {
  for (const coin of ["usdt", "usdc"]) {
    expect(routeFor(coin, "ln").profile).toBe("erc20-to-ln/v1");
    expect(routeFor(coin, "ln").unavailable).toBeNull();
    expect(routeFor("ln", coin).profile).toBe("ln-to-erc20/v1");
    expect(routeFor("ln", coin).unavailable).toMatch(/quotes are coming soon/);
    for (const route of [routeFor(coin, "btc"), routeFor("btc", coin)]) {
      expect(route.profile).toBeNull();
      expect(route.unavailable).toMatch(/swaps are not offered/);
    }
  }
  expect(ASSETS.map((item) => item.symbol)).toEqual(["BTC", "LN", "USDT", "USDC"]);
});

test("identical and unknown assets are refused", () => {
  expect(routeFor("btc", "btc").unavailable).toBe("Choose two different assets.");
  expect(() => routeFor("btc", "eth")).toThrow("Unknown asset");
});
