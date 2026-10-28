import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { buildCooperativeClaimPlan, verifyCooperativeClaimProposal } from "../src/swap/cooperative";
import { constructSelectedReverseClaim } from "../src/recoveryInspection";
import { parseTransaction } from "../src/swap/transaction";
import { reverseCase } from "./fixtures/reverseRecoveryCases";
import { reverseCooperativeClaim } from "../src/swap/reverseCooperativeClaim";
import { memoryCosigner } from "../scripts/memoryCosigner";
import { reconstructTaprootContract } from "../src/swap/taproot";
import type { Session, Envelope } from "../src/swap/session";
import type { HandshakeInit, HandshakeAccept } from "../src/swap/wire";
import sharedCycle from "../../rill-docs/vectors/wire/cooperative-claim-v1.json";

test("reverse key-path and durable unilateral fallback commit the same payout, fee and txid", () => {
  const data = reverseCase(), terms = data.record.contract_terms, binding = data.record.funding_history[0]!.binding;
  const plan = buildCooperativeClaimPlan(terms, binding, 100n);
  const fallback = constructSelectedReverseClaim(new TextEncoder().encode(canonicalize(data.record)!), data.expectedNetwork,
    { fundingAttemptId: data.fundingAttemptId, bindingRevision: data.bindingRevision, rawFundingTransaction: hexToBytes(data.fundingTxHex),
      sampledTipHeight: data.tipHeight, confirmations: data.confirmations, feeSat: 100n });
  const unsigned = parseTransaction(plan.baseTransaction);
  expect(unsigned.txid).toBe(fallback.txid);
  expect(Buffer.from(unsigned.outputs[0]!.script).toString("hex")).toBe(terms.client_destination_script);
  expect(plan.outputValueSat.toString()).toBe(fallback.outputValueSat);
  expect(verifyCooperativeClaimProposal(plan.baseTransaction, terms, binding).signatureHash).toEqual(plan.signatureHash);
});

test("reverse cooperation cannot spend the payout, exceed the signed reserve or use the provider destination", () => {
  const data = reverseCase(), terms = data.record.contract_terms, binding = data.record.funding_history[0]!.binding;
  expect(() => buildCooperativeClaimPlan(terms, binding, 1001n)).toThrow();
  expect(() => buildCooperativeClaimPlan({ ...terms, max_claim_fee_sat: "10000" }, binding, 1001n)).toThrow();
  expect(() => buildCooperativeClaimPlan({ ...terms, economics: { ...terms.economics, nominal_payout_sat: "50901" } }, binding, 100n)).toThrow("signed payout");
});

async function claimant(mode = "signed", mutateReply: (reply: Envelope) => Envelope = (reply) => reply) {
  const data = reverseCase(), terms = data.record.contract_terms, verified = data.record.verification_context;
  const binding = data.record.funding_history[0]!.binding, contract = reconstructTaprootContract(terms);
  const plan = buildCooperativeClaimPlan(terms, binding, 100n);
  const capabilities = memoryCosigner(), provider = await memoryCosigner().loadMusig();
  const events: string[] = [], sent: Envelope[] = []; let mono = 100, sequence = 5, current = true;
  const load = capabilities.loadMusig;
  capabilities.loadMusig = async () => {
    const musig = await load(), begin = musig.begin;
    musig.begin = (...args) => { events.push("nonce"); return begin(...args); };
    if (mode === "slow preparation") mono += 31000;
    return musig;
  };
  const reserve = capabilities.reserve;
  capabilities.reserve = async (key, record, body) => reserve(key, record, async () => { events.push("burn"); return body(); });
  const session = {
    clock: () => 1700000000000, profile: "ln-to-btc/v1", network: data.expectedNetwork,
    sessionId: verified.handshake_init.session_id, key: verified.client_session_xonly_key, providerKey: verified.provider_session_xonly_key,
    envelope(type: string, payload: Record<string, unknown>, options: { contract: string; requiredFeatures: string[] }): Envelope {
      return { protocol: "rillswap", wire_version: "1", profile_id: "ln-to-btc/v1", network_identity: data.expectedNetwork,
        session_id: verified.handshake_init.session_id, message_id: String(sequence++).padStart(64, "0"), sender_session_key: verified.client_session_xonly_key,
        sequence, in_reply_to: null, contract_hash: options.contract, message_type: type, payload, required_features: options.requiredFeatures, extensions: {}, signature: "00".repeat(64) };
    },
    async send(envelope: Envelope, _recipient: string, check?: () => void) {
      check?.(); sent.push(envelope); events.push(envelope.payload.action === "cooperative_claim_propose" ? "propose" : "complete");
      if (mode === "lost completion" && envelope.payload.action === "cooperative_claim_complete") throw new Error("relay lost");
    },
    async replyTo(request: Envelope): Promise<Envelope> {
      if (mode === "expired reply") mono += 31000;
      if (mode === "canceled") current = false;
      const transcript = { clientKey: hexToBytes(terms.client_contract_compressed_key), providerKey: hexToBytes(terms.provider_contract_compressed_key),
        tapTweak: hexToBytes(contract.tap_tweak), message: plan.signatureHash };
      const attempt = provider.begin(transcript, hexToBytes("0".repeat(63) + "5"), hexToBytes(request.payload.cooperation_id as string));
      let partial: Uint8Array;
      try { partial = attempt.signOnce(hexToBytes(request.payload.public_nonce as string)); } finally { attempt.destroy(); }
      const payload: Record<string, unknown> = mode === "declined" ? { action: "cooperative_claim_propose", cooperation_id: request.payload.cooperation_id, status: "declined" } :
        { action: "cooperative_claim_propose", cooperation_id: request.payload.cooperation_id, status: "signed", public_nonce: bytesToHex(attempt.publicNonce), partial_signature: bytesToHex(partial) };
      if (mode === "bad partial") payload.partial_signature = "00".repeat(32);
      if (mode === "bad nonce") payload.public_nonce = "00".repeat(66);
      if (mode === "extra payload") payload.extra = true;
      return mutateReply({ ...request, message_type: "action_result", message_id: "ef".repeat(32), sequence: 10, in_reply_to: mode === "wrong reply" ? "00".repeat(32) : request.message_id,
        sender_session_key: mode === "wrong role" ? session.key : session.providerKey!,
        contract_hash: mode === "wrong contract" ? "00".repeat(32) : request.contract_hash,
        required_features: mode === "missing feature" ? [] : request.required_features, payload });
    },
  } as unknown as Session;
  const options = { session, init: verified.handshake_init as unknown as HandshakeInit, accept: verified.handshake_accept as unknown as HandshakeAccept,
    terms, binding, contractSecret: hexToBytes(data.record.user_secret.contract_secret_key), preimage: hexToBytes(data.record.monotonic_knowledge.preimage!),
    feeSat: 100n, expectedTxid: parseTransaction(plan.baseTransaction).txid, tipHeight: data.tipHeight,
    capabilities, assertCurrent: () => { if (!current) throw new Error("Selection changed"); }, monotonicClock: () => mono };
  return { options, events, sent, provider };
}

test("the reverse claimant burns before its nonce, verifies a key-path spend and sends its partial without waiting for a receipt", async () => {
  const f = await claimant();
  try {
    const result = await reverseCooperativeClaim(f.options);
    expect(result).not.toBeNull(); expect(result!.txid).toBe(f.options.expectedTxid);
    expect(parseTransaction(hexToBytes(result!.raw)).inputs[0]!.witness).toHaveLength(1);
    expect(f.events).toEqual(["burn", "nonce", "propose", "complete"]);
    expect(f.sent[1]!.in_reply_to).toBeNull(); expect(f.sent[1]!.payload.partial_signature).toMatch(/^[0-9a-f]{64}$/);
    expect(await reverseCooperativeClaim(f.options)).toBeNull();
    expect(f.events.filter((event) => event === "nonce")).toHaveLength(1);
  } finally { f.provider.destroy(); }
});

test("durable election precedes the publication-boundary disclosure marker", async () => {
  const f = await claimant();
  try {
    expect(await reverseCooperativeClaim({ ...f.options,
      beforeDisclosure: async () => { f.events.push("journal"); },
      onDisclosure: () => { f.events.push("disclosure"); },
    })).not.toBeNull();
    expect(f.events).toEqual(["burn", "nonce", "journal", "disclosure", "propose", "complete"]);
  } finally { f.provider.destroy(); }
});

test("a failed disclosure election never reaches publication or its disclosure marker", async () => {
  const f = await claimant();
  try {
    expect(await reverseCooperativeClaim({ ...f.options,
      beforeDisclosure: async () => { f.events.push("journal"); throw new Error("storage unavailable"); },
      onDisclosure: () => { f.events.push("disclosure"); },
    })).toBeNull();
    expect(f.events).toEqual(["burn", "nonce", "journal"]);
  } finally { f.provider.destroy(); }
});

for (const mode of ["declined", "bad partial", "bad nonce", "extra payload", "wrong reply", "wrong role", "wrong contract", "missing feature", "expired reply", "slow preparation", "canceled"]) {
  test(`reverse ${mode} leaves the saved unilateral fallback as the only claim path`, async () => {
    const f = await claimant(mode);
    try {
      expect(await reverseCooperativeClaim(f.options)).toBeNull();
      expect(f.events).not.toContain("complete");
      if (mode === "slow preparation") expect(f.events).not.toContain("nonce");
    } finally { f.provider.destroy(); }
  });
}

test("a lost completion message does not discard an independently verified key-path claim", async () => {
  const f = await claimant("lost completion");
  try { expect(await reverseCooperativeClaim(f.options)).not.toBeNull(); } finally { f.provider.destroy(); }
});

test("a mismatched durable fallback txid cannot obtain a nonce or disclose the preimage", async () => {
  const f = await claimant();
  try {
    expect(await reverseCooperativeClaim({ ...f.options, expectedTxid: "00".repeat(32) })).toBeNull();
    expect(f.events).toEqual([]);
  } finally { f.provider.destroy(); }
});

for (const variation of sharedCycle.invalid.filter((item) => item.message === "signed")) {
  test(`shared wire conformance: reverse ${variation.name}`, async () => {
    const f = await claimant("signed", (reply) => {
      if (variation.field === "sender_role") return { ...reply, sender_session_key: "ee".repeat(32) };
      const changed = structuredClone(reply), path = variation.field.split(".");
      const target = (path.length === 2 ? changed.payload : changed) as unknown as Record<string, unknown>;
      target[path.at(-1)!] = variation.replacement; return changed;
    });
    try {
      expect(await reverseCooperativeClaim(f.options)).toBeNull();
      expect(f.events).not.toContain("complete");
    } finally { f.provider.destroy(); }
  });
}

test("shared wire conformance: the claimant emits the proposal/completion cycle without a receipt dependency", async () => {
  const f = await claimant();
  try {
    expect(await reverseCooperativeClaim(f.options)).not.toBeNull();
    for (const [index, name] of ["propose", "complete"].entries()) {
      const expected = sharedCycle.messages[name as "propose" | "complete"], actual = f.sent[index]!;
      expect(actual.message_type).toBe(expected.message_type);
      expect(actual.in_reply_to).toBe(expected.in_reply_to);
      expect(actual.required_features).toEqual(expected.required_features);
      expect(Object.keys(actual.payload).sort()).toEqual(Object.keys(expected.payload).sort());
      expect(actual.payload.action).toBe(expected.payload.action);
    }
  } finally { f.provider.destroy(); }
});

test("the swap log says why the claim was or was not cooperative, with fixed secret-free lines", async () => {
  const fallback = "; claiming with the signed script-path transaction";
  const cases: [string, string, ((options: Awaited<ReturnType<typeof claimant>>["options"]) => object)?][] = [
    ["signed", "the provider cosigned; claiming with the private key-path transaction"],
    ["declined", `the provider declined${fallback}`],
    ["expired reply", `timed out waiting for the provider's signature${fallback}`],
    ["slow preparation", `timed out loading the signer${fallback}`],
    ["canceled", `stopped waiting for the provider's signature${fallback}`],
    ["bad partial", `stopped checking the provider's reply${fallback}`],
    ["signed", `skipped, too close to the provider's refund height${fallback}`, (options) => ({
      tipHeight: options.terms.refund_lock_height - options.terms.timing_policy.claim_confirmation_blocks + 1 })],
  ];
  for (const [mode, expected, change] of cases) {
    const f = await claimant(mode), lines: string[] = [];
    try {
      await reverseCooperativeClaim({ ...f.options, ...change?.(f.options), report: (line) => lines.push(line) });
      expect(lines).toEqual([`cooperation: ${expected}`]);
      if (change) expect(f.events).toEqual([]);
      // A second attempt for the same swap is refused by the journal before any nonce.
      if (mode === "signed" && !change) {
        lines.length = 0; await reverseCooperativeClaim({ ...f.options, report: (line) => lines.push(line) });
        expect(lines).toEqual([`cooperation: skipped, this browser already tried once for this swap or cannot store the attempt${fallback}`]);
      }
      for (const line of lines) expect(line).not.toMatch(/[0-9a-f]{16}/);
    } finally { f.provider.destroy(); }
  }
});

test("a throwing swap log never changes the cooperative claim", async () => {
  const f = await claimant();
  try {
    const result = await reverseCooperativeClaim({ ...f.options, report: () => { throw new Error("log gone"); } });
    expect(result).not.toBeNull(); expect(parseTransaction(hexToBytes(result!.raw)).inputs[0]!.witness).toHaveLength(1);
  } finally { f.provider.destroy(); }
});
