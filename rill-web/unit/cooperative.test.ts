import { beforeAll, describe, expect, test } from "bun:test";
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";

import { memoryCosigner } from "../scripts/memoryCosigner";
import {
  buildCooperativeClaimPlan,
  COOPERATIVE_RESERVATION_EXTENSION,
  finalizeCooperativeClaim,
  type ReservationRecord,
  settle,
  type SettlementContext,
  verifyCooperativeClaimProposal,
} from "../src/swap/cooperative";
import type { FundingBinding } from "../src/swap/funding";
import type { Musig, MusigTranscript } from "../src/swap/musig";
import { type Envelope, type Session, SwapError } from "../src/swap/session";
import { reconstructTaprootContract } from "../src/swap/taproot";
import { type BtcToLnTerms, COOPERATIVE_CLAIM_FEATURE } from "../src/swap/wire";
import vector from "./fixtures/cooperative-claim-v1.json";
import taproot from "./fixtures/taproot-cases-v1.json";

const fixture = taproot.valid[0]!;
const terms = vector.contract_terms as unknown as BtcToLnTerms;
const CLIENT_SECRET = hexToBytes(fixture.fixture_keys.client_contract_secret_key);
const PROVIDER_SECRET = hexToBytes(fixture.fixture_keys.provider_contract_secret_key);
const PREIMAGE = fixture.claim_preimage;
const CONTRACT_HASH = "cc".repeat(32);
const PROVIDER_KEY = "dd".repeat(32);
const NOW_MS = 1_700_000_000_000;
const NOW = NOW_MS / 1000;
const TIP = 900;
const contract = reconstructTaprootContract(terms);

function bindingFor(txid: string, vout: number): FundingBinding {
  return {
    contract_hash: CONTRACT_HASH,
    funding_attempt_id: "ee".repeat(32),
    binding_revision: 0,
    funder_role: "client",
    lineage_anchor_txid: txid,
    lineage_anchor_vout: vout,
    funding_txid: txid,
    contract_vout: vout,
    contract_value_sat: terms.economics.contract_amount_sat,
    contract_script_pubkey: contract.script_pubkey,
    replaces_txid: null,
    created_at: NOW,
  };
}

const binding = bindingFor(vector.cases[0]!.funding_txid, vector.cases[0]!.contract_vout);
let providerMusig: Musig;

beforeAll(async () => {
  providerMusig = await memoryCosigner().loadMusig();
});

describe("claim plan parity with rill-core", () => {
  test("reconstructs every rill-core vector byte for byte", () => {
    for (const item of vector.cases) {
      const plan = verifyCooperativeClaimProposal(
        hexToBytes(item.base_transaction),
        terms,
        bindingFor(item.funding_txid, item.contract_vout),
      );
      expect(bytesToHex(plan.signatureHash)).toBe(item.signature_hash);
      expect(plan.feeSat).toBe(BigInt(item.fee_sat));
    }
  });

  test("any changed byte, fee above the cap, or other funding is refused", () => {
    const raw = hexToBytes(vector.cases[0]!.base_transaction);
    for (const index of [0, 5, 40, 41, 45, 60, raw.length - 1]) {
      const changed = Uint8Array.from(raw);
      changed[index]! ^= 1;
      expect(() => verifyCooperativeClaimProposal(changed, terms, binding)).toThrow("cooperative claim refused");
    }
    expect(() => buildCooperativeClaimPlan(terms, binding, BigInt(terms.max_claim_fee_sat) + 1n)).toThrow(
      "fee exceeds the signed claim cap",
    );
    expect(() => verifyCooperativeClaimProposal(raw, terms, bindingFor("ab".repeat(32), 0))).toThrow();
    expect(() =>
      verifyCooperativeClaimProposal(raw, terms, { ...binding, contract_value_sat: "101001" }),
    ).toThrow("funding value");
  });
});

describe("WASM MuSig2 facade", () => {
  const transcript = (message: Uint8Array): MusigTranscript => ({
    clientKey: hexToBytes(terms.client_contract_compressed_key),
    providerKey: hexToBytes(terms.provider_contract_compressed_key),
    tapTweak: hexToBytes(contract.tap_tweak),
    message,
  });

  test("two attempts aggregate to a key-path signature for the contract output key", () => {
    const plan = buildCooperativeClaimPlan(terms, binding, 300n);
    const t = transcript(plan.signatureHash);
    const id = randomBytes(32);
    const provider = providerMusig.begin(t, PROVIDER_SECRET, id);
    const client = providerMusig.begin(t, CLIENT_SECRET, id);
    const clientPartial = client.signOnce(provider.publicNonce);
    expect(() => client.signOnce(provider.publicNonce)).toThrow("already consumed");
    const providerPartial = provider.signOnce(client.publicNonce);
    expect(providerMusig.verifyPartial(t, client.publicNonce, provider.publicNonce, "client", clientPartial)).toBe(true);
    expect(providerMusig.verifyPartial(t, client.publicNonce, provider.publicNonce, "provider", clientPartial)).toBe(
      false,
    );
    const signature = providerMusig.aggregate(t, client.publicNonce, provider.publicNonce, clientPartial, providerPartial);
    expect(schnorr.verify(signature, plan.signatureHash, hexToBytes(contract.output_xonly_key))).toBe(true);
    const claim = finalizeCooperativeClaim(plan, signature, terms, binding);
    expect(claim.raw).toContain(bytesToHex(signature));
    expect(() => finalizeCooperativeClaim(plan, Uint8Array.from(signature).fill(1, 0, 1), terms, binding)).toThrow();
  });

  test("malformed nonces are refused", () => {
    expect(providerMusig.validateNonce(new Uint8Array(66))).toBe(false);
  });
});

/** A scripted provider over an in-memory session (authentication is Session's job). */
class Harness {
  now = NOW_MS;
  readonly inbox: Envelope[] = [];
  readonly sent: Envelope[] = [];
  readonly cosigner = memoryCosigner();
  readonly lines: string[] = [];
  onSend: (envelope: Envelope) => void = () => {};
  private sequence = 0;

  readonly session = {
    clock: () => this.now,
    envelope: (
      type: string,
      payload: Record<string, unknown>,
      options: { inReplyTo?: string; contract?: string; requiredFeatures?: readonly string[] } = {},
    ): Envelope => this.make(type, payload, options.inReplyTo ?? null, [...(options.requiredFeatures ?? [])], "aa"),
    send: async (envelope: Envelope) => {
      this.sent.push(envelope);
      this.onSend(envelope);
    },
    receive: async (wanted: (envelope: Envelope) => boolean): Promise<Envelope> => {
      const index = this.inbox.findIndex(wanted);
      if (index < 0) throw new SwapError("timed out waiting for the provider");
      return this.inbox.splice(index, 1)[0]!;
    },
  };

  make(type: string, payload: Record<string, unknown>, inReplyTo: string | null, features: string[], sender = "dd") {
    this.sequence += 1;
    return {
      protocol: "rillswap",
      wire_version: "1",
      profile_id: "btc-to-ln/v1",
      network_identity: terms.network_identity,
      session_id: "11".repeat(32),
      message_id: bytesToHex(randomBytes(32)),
      sender_session_key: sender.repeat(32),
      sequence: this.sequence,
      in_reply_to: inReplyTo,
      contract_hash: CONTRACT_HASH,
      message_type: type,
      payload,
      required_features: features,
      extensions: {},
      signature: "ff".repeat(64),
    } as Envelope;
  }

  provide(type: string, payload: Record<string, unknown>, features = [COOPERATIVE_CLAIM_FEATURE]): void {
    this.inbox.push(this.make(type, payload, null, features));
  }

  context(): SettlementContext {
    return {
      session: this.session as unknown as Session,
      providerKey: PROVIDER_KEY,
      terms,
      contractHash: CONTRACT_HASH,
      binding,
      contractSecret: CLIENT_SECRET,
      tipHeight: TIP,
      settleMs: 600_000,
      cosigner: this.cosigner,
      report: (line) => this.lines.push(line),
    };
  }

  run() {
    return settle(this.context(), "refund hint");
  }

  sentActions(): string[] {
    return this.sent.map((item) => `${item.payload.action}:${item.payload.status}`);
  }
}

const DEADLINE_HEIGHT = terms.refund_lock_height - terms.timing_policy.claim_confirmation_blocks;
const ready = (overrides: Record<string, unknown> = {}) => ({
  action: "cooperative_claim_ready",
  challenge: "12".repeat(32),
  payment_preimage: PREIMAGE,
  deadline_at: NOW + 20,
  deadline_height: DEADLINE_HEIGHT,
  ...overrides,
});

/** Provider behavior after the readiness echo: propose, then complete with `partial`. */
function cooperativeProvider(
  harness: Harness,
  options: { fee?: bigint; tamper?: (raw: Uint8Array) => void; badPartial?: boolean } = {},
): void {
  const plan = buildCooperativeClaimPlan(terms, binding, options.fee ?? 300n);
  const t: MusigTranscript = {
    clientKey: hexToBytes(terms.client_contract_compressed_key),
    providerKey: hexToBytes(terms.provider_contract_compressed_key),
    tapTweak: hexToBytes(contract.tap_tweak),
    message: plan.signatureHash,
  };
  const id = randomBytes(32);
  const attempt = providerMusig.begin(t, PROVIDER_SECRET, id);
  harness.onSend = (envelope) => {
    const payload = envelope.payload;
    if (payload.action === "cooperative_claim_ready") {
      const raw = Uint8Array.from(plan.baseTransaction);
      options.tamper?.(raw);
      harness.provide("action_request", {
        action: "cooperative_claim_propose",
        cooperation_id: bytesToHex(id),
        unsigned_transaction: bytesToHex(raw),
        payment_preimage: PREIMAGE,
        public_nonce: bytesToHex(attempt.publicNonce),
        deadline_at: NOW + 20,
        deadline_height: DEADLINE_HEIGHT,
      });
    } else if (payload.action === "cooperative_claim_propose") {
      const partial = attempt.signOnce(hexToBytes(payload.public_nonce as string));
      if (options.badPartial) partial[31]! ^= 1;
      harness.provide("action_request", {
        action: "cooperative_claim_complete",
        cooperation_id: bytesToHex(id),
        partial_signature: bytesToHex(partial),
      });
    }
  };
}

describe("settlement and cooperation", () => {
  test("a paid swap completes one verified key-path claim", async () => {
    const harness = new Harness();
    cooperativeProvider(harness);
    harness.provide("observation", { kind: "payment_settled", payment_preimage: PREIMAGE }, []);
    harness.provide("action_request", ready());
    const outcome = await harness.run();
    expect(outcome.cooperation).toBe("verified");
    expect(outcome.preimage).toBe(PREIMAGE);
    expect(outcome.claimTxid).toMatch(/^[0-9a-f]{64}$/);
    expect(harness.sentActions()).toEqual([
      "cooperative_claim_ready:ready",
      "cooperative_claim_propose:signed",
      "cooperative_claim_complete:verified",
    ]);
    for (const item of harness.sent) expect(item.required_features).toEqual([COOPERATIVE_CLAIM_FEATURE]);
    const [record] = [...harness.cosigner.journal.values()] as ReservationRecord[];
    expect(record!.signature_hash).toBe(outcome.reservation!.signature_hash);
    expect(outcome.reservation!.proposal.payload.action).toBe("cooperative_claim_propose");
    expect(COOPERATIVE_RESERVATION_EXTENSION).toBe("rillswap/cooperative-claim-reservation");
  });

  test("readiness alone proves payment; a silent provider costs only privacy", async () => {
    const harness = new Harness();
    harness.provide("action_request", ready());
    const outcome = await harness.run();
    expect(outcome).toMatchObject({ preimage: PREIMAGE, cooperation: "abandoned", reservation: null });
    expect(harness.sentActions()).toEqual(["cooperative_claim_ready:ready"]);
  });

  test("payment without readiness returns paid with nothing sent", async () => {
    const harness = new Harness();
    harness.provide("observation", { kind: "payment_settled", payment_preimage: PREIMAGE }, []);
    expect((await harness.run()).cooperation).toBe("abandoned");
    expect(harness.sent).toEqual([]);
  });

  test.each([
    ["an expired deadline", { deadline_at: NOW }],
    ["a window over 30 seconds", { deadline_at: NOW + 31 }],
    ["a height past the claim cutoff", { deadline_height: DEADLINE_HEIGHT + 1 }],
    ["a height already reached", { deadline_height: TIP }],
    ["an extra field", { extra: 1 }],
  ])("readiness with %s is never echoed", async (_name, overrides) => {
    const harness = new Harness();
    harness.provide("observation", { kind: "payment_settled", payment_preimage: PREIMAGE }, []);
    harness.provide("action_request", ready(overrides));
    expect((await harness.run()).cooperation).toBe("abandoned");
    expect(harness.sent).toEqual([]);
  });

  test("readiness without the feature or with a wrong preimage grants nothing", async () => {
    const harness = new Harness();
    harness.provide("action_request", ready(), []);
    harness.provide("action_request", ready({ payment_preimage: "43".repeat(32) }));
    harness.provide("observation", { kind: "payment_settled", payment_preimage: PREIMAGE }, []);
    expect(await harness.run()).toMatchObject({ preimage: PREIMAGE, cooperation: "abandoned" });
    expect(harness.sent).toEqual([]);
  });

  test.each([
    ["a changed output script byte", { tamper: (raw: Uint8Array) => (raw[raw.length - 6]! ^= 1) }],
    ["a fee above the cap", { fee: BigInt(terms.max_claim_fee_sat) + 1n }],
  ])("a proposal with %s is never signed or reserved", async (_name, options) => {
    const harness = new Harness();
    try {
      cooperativeProvider(harness, options as { fee?: bigint; tamper?: (raw: Uint8Array) => void });
    } catch {
      return; // the plan itself refuses the fee; the client can never see it
    }
    harness.provide("action_request", ready());
    expect((await harness.run()).cooperation).toBe("abandoned");
    expect(harness.sentActions()).toEqual(["cooperative_claim_ready:ready"]);
    expect(harness.cosigner.journal.size).toBe(0);
  });

  test("an existing reservation refuses before any nonce exists", async () => {
    const harness = new Harness();
    harness.cosigner.journal.set(CONTRACT_HASH, {} as ReservationRecord);
    cooperativeProvider(harness);
    harness.provide("action_request", ready());
    const outcome = await harness.run();
    expect(outcome.cooperation).toBe("abandoned");
    expect(outcome.reservation).toBeNull();
    expect(harness.sentActions()).toEqual(["cooperative_claim_ready:ready"]);
  });

  test("an invalid provider partial gets no receipt", async () => {
    const harness = new Harness();
    cooperativeProvider(harness, { badPartial: true });
    harness.provide("action_request", ready());
    const outcome = await harness.run();
    expect(outcome.cooperation).toBe("abandoned");
    expect(outcome.reservation).not.toBeNull();
    expect(harness.sentActions()).toEqual(["cooperative_claim_ready:ready", "cooperative_claim_propose:signed"]);
  });

  test("a proposal without readiness is never signed", async () => {
    const harness = new Harness();
    harness.provide("observation", { kind: "payment_settled", payment_preimage: PREIMAGE }, []);
    harness.provide("action_request", {
      action: "cooperative_claim_propose",
      cooperation_id: "34".repeat(32),
      unsigned_transaction: vector.cases[0]!.base_transaction,
      payment_preimage: PREIMAGE,
      public_nonce: "02".repeat(66),
      deadline_at: NOW + 20,
      deadline_height: DEADLINE_HEIGHT,
    });
    harness.provide("action_request", ready());
    expect((await harness.run()).cooperation).toBe("abandoned");
    expect(harness.sent).toEqual([]);
  });

  test("unresolved or failed payment keeps the refund path", async () => {
    await expect(new Harness().run()).rejects.toThrow("provider did not pay in time; refund hint");
    const failed = new Harness();
    failed.provide("observation", { kind: "payment_failed" }, []);
    await expect(failed.run()).rejects.toThrow("provider reports the payment failed");
    const wrong = new Harness();
    wrong.provide("observation", { kind: "payment_settled", payment_preimage: "43".repeat(32) }, []);
    await expect(wrong.run()).rejects.toThrow("provider sent a wrong preimage");
  });
});
