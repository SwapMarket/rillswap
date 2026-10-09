import { expect, test } from "bun:test";
import { ASSETS, routeFor } from "../src/swapPairs";

test("only Bitcoin to Lightning is quotable; the reverse profile is mapped but not yet offered", () => {
  const forward = routeFor("btc", "ln");
  expect(forward).toMatchObject({ profile: "btc-to-ln/v1", unavailable: null, title: "Bitcoin in. Lightning out." });
  const reverse = routeFor("ln", "btc");
  expect(reverse.profile).toBe("ln-to-btc/v1");
  expect(reverse.unavailable).toBe("Lightning to Bitcoin quotes are coming soon.");
  expect(reverse.title).toBe("Lightning in. Bitcoin out.");
});

test("stablecoins are listed in both directions but never map to a protocol profile", () => {
  for (const coin of ["usdt", "usdc"]) {
    for (const other of ["btc", "ln"]) {
      for (const route of [routeFor(coin, other), routeFor(other, coin)]) {
        expect(route.profile).toBeNull();
        expect(route.unavailable).toBe("Stablecoin swaps are not supported yet.");
      }
    }
  }
  expect(ASSETS.map((item) => item.symbol)).toEqual(["BTC", "LN", "USDT", "USDC"]);
});

test("identical and unknown assets are refused", () => {
  expect(routeFor("btc", "btc").unavailable).toBe("Choose two different assets.");
  expect(() => routeFor("btc", "eth")).toThrow("Unknown asset");
});
