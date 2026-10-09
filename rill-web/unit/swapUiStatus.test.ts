import { expect, test } from "bun:test";
import { stoppedSwapAdvice } from "../src/swapUiStatus";

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
