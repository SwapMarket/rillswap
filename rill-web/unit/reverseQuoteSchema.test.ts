import { expect, test } from "bun:test";
import vectors from "../../rill-docs/vectors/wire/quote-v1.json";
import {
  validateFirmQuoteRequest, validateReverseFirmQuoteRequest, validateReverseTermsOffer, validateTermsOffer,
} from "../src/generated/wireValidators.js";

const cases = vectors as unknown as Record<"valid" | "invalid", Record<string, unknown[]>>;

test("generated reverse validators match the Core-checked RS-004 vectors", () => {
  for (const [name, validate] of [["reverseFirmRequest", validateReverseFirmQuoteRequest],
    ["reverseTermsOffer", validateReverseTermsOffer]] as const) {
    expect(cases.valid[name]!.length).toBeGreaterThan(0);
    for (const document of cases.valid[name]!) expect(validate(document)).toBe(true);
    for (const document of cases.invalid[name]!) expect(validate(document)).toBe(false);
  }
});

test("forward and reverse quote shapes never validate as each other", () => {
  for (const document of cases.valid.reverseFirmRequest!) expect(validateFirmQuoteRequest(document)).toBe(false);
  for (const document of cases.valid.reverseTermsOffer!) expect(validateTermsOffer(document)).toBe(false);
  for (const document of cases.valid.termsOffer!) expect(validateReverseTermsOffer(document)).toBe(false);
});
