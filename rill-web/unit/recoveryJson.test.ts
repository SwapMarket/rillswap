import { expect, test } from "bun:test";
import { parseStrictEventJson, parseStrictRecoveryJson } from "../src/strictEventJson";

test("event parsing preserves legal floating-point tokens, whitespace, escapes, and its original container depth", () => {
  expect(parseStrictEventJson(' {"a":1.5,"b":1e2,"c":"\\u0061"} ')).toEqual({ a: 1.5, b: 100, c: "a" });
  expect(parseStrictEventJson("[".repeat(16) + "0" + "]".repeat(16))).toBeDefined();
  expect(() => parseStrictEventJson("[".repeat(17) + "]".repeat(17))).toThrow();
});

test("recovery integer tokens stay within Core's inclusive exact range", () => {
  for (const text of ["-9007199254740991", "9007199254740991", "0", "-0"]) expect(parseStrictRecoveryJson(text)).toBe(Number(text));
  for (const text of ["9007199254740992", "-9007199254740992", "1.0", "1e0", "1E0", "NaN", "Infinity", "01", "+1"]) {
    expect(() => parseStrictRecoveryJson(text)).toThrow();
  }
  expect(parseStrictRecoveryJson("[true,false,null]")).toEqual([true, false, null]);
});

test("recovery depth starts at zero and counts keys and scalars, including empty depth-16 containers", () => {
  expect(parseStrictRecoveryJson("[".repeat(17) + "]".repeat(17))).toBeDefined();
  expect(parseStrictRecoveryJson("[".repeat(16) + "0" + "]".repeat(16))).toBeDefined();
  for (const raw of ["[".repeat(17) + "0" + "]".repeat(17),
    "[".repeat(16) + '{"key":null}' + "]".repeat(16), "[".repeat(18) + "]".repeat(18)]) {
    expect(() => parseStrictRecoveryJson(raw)).toThrow();
  }
});

test("recovery decoded string bounds count UTF-8 bytes for both keys and values", () => {
  for (const value of ["a".repeat(16 * 1024), "🍀".repeat(4096)]) {
    expect(parseStrictRecoveryJson(JSON.stringify(value))).toBe(value);
    expect(parseStrictRecoveryJson(JSON.stringify({ [value]: true }))).toBeDefined();
    expect(() => parseStrictRecoveryJson(JSON.stringify(value + "a"))).toThrow();
    expect(() => parseStrictRecoveryJson(JSON.stringify({ [value + "a"]: true }))).toThrow();
  }
  const escaped = '"' + "\\u0061".repeat(16 * 1024) + '"';
  expect(parseStrictRecoveryJson(escaped)).toBe("a".repeat(16 * 1024));
  expect(() => parseStrictRecoveryJson(escaped.slice(0, -1) + '\\u0061"')).toThrow();
});

test("recovery limits object members, array members, duplicate names, Unicode, and trailing input", () => {
  expect(parseStrictRecoveryJson(JSON.stringify(Array(256).fill(0)))).toHaveLength(256);
  expect(() => parseStrictRecoveryJson(JSON.stringify(Array(257).fill(0)))).toThrow();
  const object = Object.fromEntries(Array.from({ length: 128 }, (_, i) => [String(i), null]));
  expect(parseStrictRecoveryJson(JSON.stringify(object))).toBeDefined();
  expect(() => parseStrictRecoveryJson(JSON.stringify({ ...object, extra: null }))).toThrow();
  for (const text of ['{"a":1,"\\u0061":1}', '"\\ud800"', '{"\\udfff":1}', 'null null', '[1,]']) {
    expect(() => parseStrictRecoveryJson(text)).toThrow();
  }
  expect(parseStrictRecoveryJson('"\\ud83c\\udf40"')).toBe("🍀");
});
