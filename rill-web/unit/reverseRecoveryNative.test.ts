import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { hexToBytes } from "@noble/hashes/utils.js";
import { appendReverseClaimFallback, constructSelectedReverseClaim } from "../src/recoveryInspection";
import { reverseRecoveryCases, reverseCase, signReverseRecord } from "./fixtures/reverseRecoveryCases";

/** Native signing uses only published synthetic fixture keys, with no chain access. */
test.skipIf(process.env.RILLSWAP_TEST_RECOVERY_NATIVE !== "1")("native Core reproduces reverse claim bytes and accepts distinct funded/fallback successors", async () => {
  const capped = reverseCase("browser reserve cap is intentionally stricter than native fee cap");
  capped.record.contract_terms.economics.claim_fee_reserve_sat = "500"; capped.record.contract_terms.economics.nominal_payout_sat = "50500"; signReverseRecord(capped.record);
  const cases = [...reverseRecoveryCases().map((item) => ({ ...item, nativeAccepted: item.accepted })), { ...capped, feeSat: "900", accepted: false, nativeAccepted: true }];
  const rng = spyOn(crypto, "getRandomValues").mockImplementation((array: Uint8Array) => { array.fill(0x55); return array; });
  let inputs;
  try {
    inputs = cases.map((item) => {
      try {
        const funded = new TextEncoder().encode(canonicalize(item.record)!);
        const claim = constructSelectedReverseClaim(funded, item.expectedNetwork, { ...item, rawFundingTransaction: hexToBytes(item.fundingTxHex), sampledTipHeight: item.tipHeight, feeSat: BigInt(item.feeSat) });
        return { ...item, browser: claim, fallback: JSON.parse(new TextDecoder().decode(appendReverseClaimFallback(funded, item.expectedNetwork, hexToBytes(claim.transactionHex)))) };
      } catch { return { ...item, browser: null, fallback: null }; }
    });
  } finally { rng.mockRestore(); }
  const python = `
import json,os,sys
from rill_crypto import Context
from rill_core.recovery import (construct_selected_recovery_claim,inspect_recovery_selected_funding_binding,
 inspect_recovery_successor,inspect_recovery_plaintext)
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
   parsed=inspect_transaction_outputs(raw); output=parsed.outputs[binding.contract_vout]
   funding=FundingOutput(bytes.fromhex(parsed.txid),binding.contract_vout,output.value_sat,output.script_pubkey)
   signed=construct_selected_recovery_claim(doc,network,funding_attempt_id=binding.funding_attempt_id,
    binding_revision=binding.binding_revision,live_funding=funding,sampled_tip_height=case["tipHeight"],
    sampled_confirmations=case["confirmations"],fee_sat=int(case["feeSat"]),auxiliary_random=b"\\x55"*32,crypto=crypto)
   auth=UnilateralAuthorization.from_terms(terms,funding,"claim",keys=crypto)
   checked=validate_unilateral_spend(signed,auth,verifier=crypto)
   digest=build_unilateral_spend(auth,fee_sat=int(case["feeSat"]),claim_preimage=bytes.fromhex(case["record"]["monotonic_knowledge"]["preimage"])).signature_hash
   outcome={"accepted":True,"hex":signed.hex(),"txid":checked.txid,"vsize":checked.vsize,"digest":digest.hex()}
  except Exception:
   outcomes.append({"accepted":False});continue
  # Browser-provided successors cannot change independent native construction acceptance.
  outcome["fallbackAccepted"]=None;outcome["combinedInsertionRefused"]=None
  if case["fallback"] is not None:
   try:
    fallback=canonicalize(case["fallback"])
    inspect_recovery_plaintext(fallback,network,crypto=crypto)
    inspect_recovery_successor(doc,fallback,network,crypto=crypto)
    outcome["fallbackAccepted"]=True
   except Exception: outcome["fallbackAccepted"]=False
   unfunded=dict(case["record"]);unfunded["funding_history"]=[]
   try: inspect_recovery_successor(canonicalize(unfunded),fallback,network,crypto=crypto)
   except Exception: outcome["combinedInsertionRefused"]=True
   else: outcome["combinedInsertionRefused"]=False
  outcomes.append(outcome)
print(json.dumps(outcomes))
`;
  const child = Bun.spawn(["docker", "exec", "-i", "rillswap-dev-tools-1", "python", "-c", python], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  child.stdin.write(JSON.stringify(inputs)); child.stdin.end();
  const [output, errors, status] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  expect(errors).toBe(""); expect(status).toBe(0);
  const outcomes = JSON.parse(output) as { accepted: boolean; hex?: string; txid?: string; vsize?: number; digest?: string; fallbackAccepted?: boolean | null; combinedInsertionRefused?: boolean | null }[];
  expect(outcomes).toHaveLength(cases.length);
  for (const [index, item] of inputs.entries()) {
    const native = outcomes[index]!; expect(native.accepted, item.name).toBe(item.nativeAccepted);
    expect(Boolean(item.browser), item.name).toBe(item.accepted);
    if (item.browser) {
      expect(native.hex, item.name).toBe(item.browser.transactionHex); expect(native.txid, item.name).toBe(item.browser.txid);
      expect(native.vsize, item.name).toBe(item.browser.vsize); expect(native.digest, item.name).toBe(item.browser.signatureHash);
      expect(native.fallbackAccepted, item.name).toBe(true); expect(native.combinedInsertionRefused, item.name).toBe(true);
    }
  }
});
