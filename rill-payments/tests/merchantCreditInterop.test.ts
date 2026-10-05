import { expect, test } from "bun:test";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { parseTerms } from "../src/contract";
import { signAcceptance, verifyAcceptance, type SignedAcceptance } from "../src/server";

const fixture = await Bun.file(new URL("../../rill-cli/tests/fixtures/merchant_acceptance.json", import.meta.url)).json() as {
  fixtureOnly: boolean; publicTestSeed: string; messageHex: string; envelope: SignedAcceptance;
  origins: { value: string; valid: boolean }[];
};
const seed = hexToBytes(fixture.publicTestSeed);
test("frozen Python merchant-credit fixture is the existing TypeScript pure Ed25519 contract", () => {
  expect(fixture.fixtureOnly).toBe(true);
  expect(signAcceptance(fixture.envelope.event, seed)).toEqual(fixture.envelope);
  expect(verifyAcceptance(fixture.envelope, fixture.envelope.publicKey)).toBe(true);
  const e = fixture.envelope.event;
  const message = new TextEncoder().encode(JSON.stringify(["rillswap-payment-event/1", e.version, e.id,
    e.merchantOrigin, e.type, e.intentId, e.attemptId, e.paymentHash, e.amountMsat, e.acceptedAt]));
  expect(bytesToHex(message)).toBe(fixture.messageHex);
});
for (const { value, valid } of fixture.origins) {
  test(`Python and TypeScript agree on exact canonical merchant origin: ${value}`, () => {
    const envelope = signAcceptance({ ...fixture.envelope.event, merchantOrigin: value }, seed);
    const terms = { version: "checkout/0.1", policyVersion: "native-lightning/1", merchantOrigin: value,
      intentId: envelope.event.intentId, attemptId: envelope.event.attemptId, network: "regtest",
      amountMsat: envelope.event.amountMsat, paymentHash: envelope.event.paymentHash,
      receiver: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", expiresAt: 1760001000, buyerExtraMsat: "0" };
    expect(verifyAcceptance(envelope, envelope.publicKey)).toBe(valid);
    if (valid) expect(parseTerms(terms).merchantOrigin).toBe(value);
    else expect(() => parseTerms(terms)).toThrow();
  });
}
