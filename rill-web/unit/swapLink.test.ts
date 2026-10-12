import { describe, expect, test } from "bun:test";
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "../src/recoveryAgeContainer";
import { parseSwapLink, swapLinkFragment } from "../src/swapLink";

describe("swap link fragment", () => {
  test("round-trips opaque bytes and the network name without padding or URL-unsafe characters", () => {
    const file = Uint8Array.from({ length: 300 }, (_, index) => (index * 37 + 251) % 256);
    const fragment = swapLinkFragment({ file, network: "regtest" });
    expect(fragment).toMatch(/^#swap=[A-Za-z0-9_-]+&network=regtest$/);
    const parsed = parseSwapLink(fragment)!;
    expect(parsed.network).toBe("regtest");
    expect(Array.from(parsed.file)).toEqual(Array.from(file));
    expect(parseSwapLink(fragment.slice(1))).toEqual(parsed);
  });

  test("refuses empty, oversized, or malformed records and invalid network names", () => {
    expect(() => swapLinkFragment({ file: new Uint8Array(), network: "regtest" })).toThrow("size");
    expect(() => swapLinkFragment({ file: new Uint8Array(MAX_RECOVERY_CIPHERTEXT_BYTES + 1), network: "regtest" })).toThrow("size");
    expect(() => swapLinkFragment({ file: new Uint8Array(1), network: "Main Net" })).toThrow("Network");
    expect(parseSwapLink("#swap=&network=regtest")).toBeNull();
    expect(parseSwapLink("#swap=AAAA")).toBeNull();
    expect(parseSwapLink("#swap=AAAA&network=")).toBeNull();
    expect(parseSwapLink("#swap=A&network=regtest")).toBeNull();
    expect(parseSwapLink("#swap=AA%2B&network=regtest")).toBeNull();
    expect(parseSwapLink("#invoice=lnbc1")).toBeNull();
    expect(parseSwapLink("")).toBeNull();
  });
});
