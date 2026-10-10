import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { inspectRecoveryPlaintext } from "../src/recoveryInspection";
import { recoveryInspectionCases } from "./fixtures/recoveryInspectionCases";

// Read-only parity using the existing dev tools container and real native Schnorr
// verification. No daemon/container creation, chain access, signing, or writes.
test.skipIf(process.env.RILLSWAP_TEST_RECOVERY_NATIVE !== "1")("native Core and browser historical inspectors agree on the entire corpus", async () => {
  const cases = recoveryInspectionCases();
  const python = `
import json,os,sys
from rill_crypto import Context
from rill_core.recovery import inspect_recovery_plaintext
from rill_core.wire.types import NetworkIdentity
from rill_core.wire.canonical import canonicalize
outcomes=[]
with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
 for case in json.load(sys.stdin):
  try:
   inspect_recovery_plaintext(canonicalize(case["record"]),NetworkIdentity.model_validate_json(canonicalize(case["expectedNetwork"]),strict=True),crypto=crypto)
   outcomes.append(True)
  except Exception:
   outcomes.append(False)
print(json.dumps(outcomes))
`;
  const child = Bun.spawn(["docker", "exec", "-i", "rillswap-dev-tools-1", "python", "-c", python],
    { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  child.stdin.write(JSON.stringify(cases));
  child.stdin.end();
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  const native = JSON.parse(output) as boolean[];
  expect(native).toHaveLength(cases.length);
  for (const [i, item] of cases.entries()) {
    let accepted = false;
    try { inspectRecoveryPlaintext(new TextEncoder().encode(canonicalize(item.record)!), item.expectedNetwork); accepted = true; }
    catch { /* Only the boolean outcome belongs in this parity report. */ }
    expect(accepted, item.name).toBe(item.accepted);
    expect(native[i], item.name).toBe(accepted);
  }
});
