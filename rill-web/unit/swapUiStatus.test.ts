import { expect, test } from "bun:test";
import { confirmationsLabel, fundingWaitText, quoteSelectionLabel, stoppedSwapAdvice } from "../src/swapUiStatus";

test("failure before sharing does not claim independently broadcast funds are uncommitted", () => {
  const advice = stoppedSwapAdvice(false);
  expect(advice).toContain("has not shared");
  expect(advice).toContain("If you broadcast separately, do not fund again");
  expect(advice).not.toContain("no funds are committed");
});

test("failure after commitment but before broadcast directs the user to funded recovery", () => {
  const advice = stoppedSwapAdvice(true);
  expect(advice).toContain("Do not fund this swap again");
  expect(advice).toContain("funded recovery file");
  expect(advice).toContain("may already be broadcast");
  expect(advice).not.toContain("reload");
});

test("manual selection does not retain the automatic best-price claim", () => {
  expect(quoteSelectionLabel(true, 2, "price")).toContain("Lowest verified provider price");
  expect(quoteSelectionLabel(false, 2, "price")).toContain("Manually selected");
  expect(quoteSelectionLabel(false, 2, "price")).not.toContain("Lowest");
});

test("the automatic claim names the active ranking, and manual picks claim neither", () => {
  expect(quoteSelectionLabel(true, 3, "time")).toContain("Fastest verified provider");
  expect(quoteSelectionLabel(true, 3, "time")).not.toContain("Lowest verified");
  expect(quoteSelectionLabel(false, 3, "time")).not.toMatch(/Fastest|Lowest/);
});

test("funding waits never present an unannounced depth as zero or one", () => {
  expect(confirmationsLabel(null)).toBe("confirmations unknown");
  expect(confirmationsLabel(0)).toBe("0 confirmations");
  expect(confirmationsLabel(1)).toBe("1 confirmation");
  expect(fundingWaitText("btc-to-ln/v1", null)).toContain("did not announce");
  expect(fundingWaitText("btc-to-ln/v1", 0)).toContain("before any confirmation");
  expect(fundingWaitText("btc-to-ln/v1", 2)).toContain("after 2 confirmations of your deposit (about 20 min)");
  expect(fundingWaitText("ln-to-btc/v1", 1)).toBe("Payout after 1 confirmation (about 10 min).");
});
