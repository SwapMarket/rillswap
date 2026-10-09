import { expect, test } from "bun:test";
import { quoteSelectionLabel, stoppedSwapAdvice } from "../src/swapUiStatus";

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
  expect(quoteSelectionLabel(true, 2)).toContain("Lowest verified provider price");
  expect(quoteSelectionLabel(false, 2)).toContain("Manually selected");
  expect(quoteSelectionLabel(false, 2)).not.toContain("Lowest");
});
