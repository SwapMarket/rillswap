import { expect, spyOn, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { encodeReverseEvidence, reverseDisclosureCases, reverseDisclosureFixture } from "./fixtures/reverseDisclosureCases";
import { inspectReverseRecoveryPlaintext, REVERSE_DISCLOSURE_EXTENSION } from "../src/recoveryInspection";

for (const item of reverseDisclosureCases()) {
  test(`reverse imported evidence: ${item.name}`, () => {
    const sign = spyOn(schnorr, "sign");
    try {
      if (item.accepted) {
        const report = inspectReverseRecoveryPlaintext(encodeReverseEvidence(item.record), item.expectedNetwork);
        expect(report.fallbackTxid).not.toBeNull();
        expect(JSON.stringify(report)).not.toContain(item.record.monotonic_knowledge.preimage!);
        expect(JSON.stringify(report)).not.toContain(REVERSE_DISCLOSURE_EXTENSION);
      } else expect(() => inspectReverseRecoveryPlaintext(encodeReverseEvidence(item.record), item.expectedNetwork)).toThrow("could not be authenticated");
      expect(sign).not.toHaveBeenCalled();
    } finally { sign.mockRestore(); }
  });
}

test.skipIf(process.env.RILLSWAP_TEST_RECOVERY_NATIVE !== "1")("Core and browser agree on historical CLI-style burn/disclosure evidence", async () => {
  const python = `
import json,os,sys
from rill_core.recovery import inspect_recovery_plaintext
from rill_core.wire.canonical import canonicalize
from rill_core.wire.types import NetworkIdentity
from rill_crypto import Context
outcomes=[]
with Context(library_path=os.environ['RILL_CRYPTO_LIBRARY']) as crypto:
 for case in json.load(sys.stdin):
  try:
   network=NetworkIdentity.model_validate_json(canonicalize(case['expectedNetwork']),strict=True)
   inspect_recovery_plaintext(canonicalize(case['record']),network,crypto=crypto)
   outcomes.append(True)
  except Exception: outcomes.append(False)
print(json.dumps(outcomes))
`;
  const cases = reverseDisclosureCases();
  const interpreter = new URL("../../rill-cli/.venv/bin/python", import.meta.url).pathname;
  const child = Bun.spawn([interpreter, "-c", python], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  child.stdin.write(JSON.stringify(cases)); child.stdin.end();
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  expect(JSON.parse(output)).toEqual(cases.map((item) => item.accepted));
  expect(reverseDisclosureFixture().disclosure.proposal.in_reply_to).toBeNull();
});
