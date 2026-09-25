import { describe, expect, spyOn, test } from "bun:test";

import { parseStrictEventJson } from "../src/strictEventJson";

describe("raw signed-event JSON input boundary", () => {
  test.each([
    '{"a":1,"a":1}',
    '{"a":1,"\\u0061":2}',
    '{"x":{"a":1,"a":2}}',
    '{"x":[{"a":1,"\\u0061":2}]}',
    '{"a\\\\b":1,"a\\u005cb":2}',
    '{"x":1,"x":null}',
    '{"a":1 "b":2}',
    '{"a":"\\ud800"}',
    '{"a":0.2,"x":{"\\u0079":5,"y":5}}',
  ])("rejects duplicate or malformed input %s", (raw) => {
    expect(() => parseStrictEventJson(raw)).toThrow();
  });

  test("permits noncanonical event-object member order, whitespace and escaped strings", () => {
    const parsed = parseStrictEventJson(' { "sig":"x", "kind":1, "tags":[], "content":"\\u0068i" } ');
    expect(parsed).toEqual({ sig: "x", kind: 1, tags: [], content: "hi" });
    expect(parseStrictEventJson('{"a":1,"nested":{"a":2}}'))
      .toEqual({ a: 1, nested: { a: 2 } });
    expect(parseStrictEventJson('{"\\uD834\\uDD1E":1}')).toEqual({ "𝄞": 1 });
  });

  test("applies event bytes, object members, array items and depth caps before native parse", () => {
    expect(() => parseStrictEventJson('{"a":1}', 6)).toThrow();
    const atLimit = '['.repeat(16) + '0' + ']'.repeat(16);
    expect(parseStrictEventJson(atLimit)).toBeDefined();
    expect(() => parseStrictEventJson('['.repeat(17) + '0' + ']'.repeat(17))).toThrow();
    const object = Object.fromEntries(Array.from({ length: 129 }, (_, i) => [String(i), i]));
    expect(() => parseStrictEventJson(JSON.stringify(object))).toThrow();
    expect(() => parseStrictEventJson(JSON.stringify(Array.from({ length: 257 }, () => 0))))
      .toThrow();
  });

  test("refuses large code-unit input before encoding, then enforces UTF-8 bytes", () => {
    const encoder = spyOn(TextEncoder.prototype, "encode").mockImplementation(() => {
      throw new Error("oversized input must not be encoded");
    });
    try {
      expect(() => parseStrictEventJson("x".repeat(128 * 1024 + 1))).toThrow("NIP-01 event refused");
      expect(encoder).not.toHaveBeenCalled();
    } finally {
      encoder.mockRestore();
    }
    expect(() => parseStrictEventJson('"🍕"', 5)).toThrow("NIP-01 event refused");
    expect(parseStrictEventJson('"🍕"', 6)).toBe("🍕");
  });
});
