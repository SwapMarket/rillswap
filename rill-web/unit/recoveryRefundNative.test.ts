import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { constructSelectedRecoveryRefund } from "../src/recoveryInspection";
import { recoveryRefundCases } from "./fixtures/recoveryRefundCases";

/** Native signing is confined to published synthetic fixture keys, with no chain access. */
test.skipIf(process.env.RILLSWAP_TEST_RECOVERY_NATIVE !== "1")("native Core reproduces selected refund digest, signature, witness, bytes, txid, and vsize", async () => {
  const cases = recoveryRefundCases();
  const python = `
import json,os,sys
from rill_crypto import Context
from rill_core.recovery import construct_selected_recovery_refund,inspect_recovery_selected_funding_binding
from rill_core.settlement import (FundingOutput,UnilateralAuthorization,check_funding_binding_transaction,
 inspect_transaction_outputs,validate_unilateral_spend,build_unilateral_spend)
from rill_core.wire.canonical import canonicalize
from rill_core.wire.messages import ContractTerms
from rill_core.wire.types import NetworkIdentity
outcomes=[]
with Context(library_path=os.environ["RILL_CRYPTO_LIBRARY"]) as crypto:
 for case in json.load(sys.stdin):
  try:
   doc=canonicalize(case["record"])
   network=NetworkIdentity.model_validate_json(canonicalize(case["expectedNetwork"]),strict=True)
   terms=ContractTerms.model_validate_json(canonicalize(case["record"]["contract_terms"]),strict=True)
   binding=inspect_recovery_selected_funding_binding(doc,network,funding_attempt_id=case["fundingAttemptId"],binding_revision=case["bindingRevision"],crypto=crypto)
   raw=bytes.fromhex(case["fundingTxHex"])
   check_funding_binding_transaction(raw,binding,terms,keys=crypto)
   parsed=inspect_transaction_outputs(raw)
   output=parsed.outputs[binding.contract_vout]
   funding=FundingOutput(bytes.fromhex(parsed.txid),binding.contract_vout,output.value_sat,output.script_pubkey)
   signed=construct_selected_recovery_refund(doc,network,funding_attempt_id=binding.funding_attempt_id,
    binding_revision=binding.binding_revision,live_funding=funding,sampled_tip_height=case["tipHeight"],
    fee_sat=int(case["feeSat"]),auxiliary_random=b"\\x55"*32,crypto=crypto)
   auth=UnilateralAuthorization.from_terms(terms,funding,"refund",keys=crypto)
   checked=validate_unilateral_spend(signed,auth,verifier=crypto)
   digest=build_unilateral_spend(auth,fee_sat=int(case["feeSat"])).signature_hash
   outcomes.append({"accepted":True,"hex":signed.hex(),"txid":checked.txid,"vsize":checked.vsize,"digest":digest.hex()})
  except Exception:
   outcomes.append({"accepted":False})
print(json.dumps(outcomes))
`;
  const child = Bun.spawn(["docker", "exec", "-i", "rillswap-dev-tools-1", "python", "-c", python],
    { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  child.stdin.write(JSON.stringify(cases)); child.stdin.end();
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  const outcomes = JSON.parse(output) as ({ accepted: false } | { accepted: true; hex: string; txid: string; vsize: number; digest: string })[];
  expect(outcomes).toHaveLength(cases.length);
  const rng = spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => {
    if (!(array instanceof Uint8Array) || array.length !== 32) throw new Error("unexpected randomness request");
    array.fill(0x55); return array;
  });
  const sign = spyOn(schnorr, "sign");
  try {
    for (const [i, item] of cases.entries()) {
      sign.mockClear();
      let result: ReturnType<typeof constructSelectedRecoveryRefund> | undefined;
      try {
        result = constructSelectedRecoveryRefund(new TextEncoder().encode(canonicalize(item.record)!), item.expectedNetwork,
          { fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision,
            rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: BigInt(item.feeSat) });
      } catch { /* Report only acceptance, never underlying errors or document contents. */ }
      expect(Boolean(result), item.name).toBe(item.accepted);
      expect(outcomes[i]!.accepted, item.name).toBe(item.accepted);
      if (result) {
        const native = outcomes[i]!;
        if (!native.accepted) throw new Error(`Native constructor unexpectedly refused ${item.name}`);
        expect(result.transactionHex, item.name).toEqual(native.hex);
        expect(result.txid, item.name).toEqual(native.txid);
        expect(result.vsize, item.name).toEqual(native.vsize);
        expect(bytesToHex(sign.mock.calls[0]![0]), item.name).toEqual(native.digest);
      } else expect(sign, item.name).not.toHaveBeenCalled();
    }
  } finally { rng.mockRestore(); sign.mockRestore(); }
});
