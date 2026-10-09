import { describe, expect, test } from "bun:test";
import type { NostrEvent } from "nostr-tools";

import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";
import signet from "../src/networks/signet.json";
import { type Envelope, type RelayLink, Session, SwapError } from "../src/swap/session";
import { assertFundingWindow } from "../src/swap/swap";

class MemoryRelay implements RelayLink {
  readonly published: NostrEvent[] = [];
  readonly queue: string[] = [];
  async publish(event: NostrEvent): Promise<boolean> {
    this.published.push(event);
    return true;
  }
  async subscribe(): Promise<void> {}
  async next(): Promise<string | null> {
    return this.queue.shift() ?? null;
  }
}

const PROFILE = "btc-to-ln/v1";

function pair(): { client: Session; provider: Session; relay: MemoryRelay } {
  const relay = new MemoryRelay();
  const client = new Session(relay, regtest, PROFILE, 50);
  const provider = new Session(new MemoryRelay(), regtest, PROFILE);
  provider.sessionId = client.sessionId;
  return { client, provider, relay };
}

async function deliver(from: Session, to: Session, envelope: Envelope, relay: MemoryRelay): Promise<string> {
  await from.send(envelope, to.key);
  const outbox = from.relay as MemoryRelay;
  const raw = JSON.stringify(outbox.published.at(-1));
  relay.queue.push(raw);
  return raw;
}

describe("client session inbox", () => {
  test("terms acceptance cannot retry publication after its deadline", async () => {
    let now = 1999;
    const relay = new MemoryRelay();
    relay.publish = async (event) => { relay.published.push(event); now = 2000; return false; };
    const client = new Session(relay, regtest, PROFILE);
    const provider = new Session(new MemoryRelay(), regtest, PROFILE);
    const envelope = client.envelope("terms_accept", { acceptance: {}, client_acceptance_signature: "00".repeat(64) });
    await expect(client.send(envelope, provider.key, () => assertFundingWindow(2000, 2100, now)))
      .rejects.toThrow("funding deadline exceeded");
    expect(relay.published).toHaveLength(1);
  });
  test("a commitment guard runs immediately before every relay retry", async () => {
    const relay = new MemoryRelay(); let now = 1999, checks = 0;
    relay.publish = async (event) => { relay.published.push(event); now = 2000; return false; };
    const client = new Session(relay, regtest, PROFILE), provider = new Session(new MemoryRelay(), regtest, PROFILE);
    const envelope = client.envelope("ack", { acknowledged_message_id: "00".repeat(32) });
    await expect(client.send(envelope, provider.key, () => { checks++; if (now >= 2000) throw new SwapError("expired"); })).rejects.toThrow("expired");
    expect(checks).toBe(2); expect(relay.published).toHaveLength(1);
  });

  test("a signed provider envelope round-trips once", async () => {
    const { client, provider, relay } = pair();
    const request = client.envelope("quote_request", { kind: "btc-to-ln" });
    const answer = provider.envelope("ack", { acknowledged_message_id: request.message_id }, {
      inReplyTo: request.message_id,
    });
    const raw = await deliver(provider, client, answer, relay);
    expect((await client.replyTo(request, "ack")).message_id).toBe(answer.message_id);
    expect(client.admit(raw)).toBeNull(); // replay
  });

  test("forged, foreign-session, other-network, and unpinned senders are dropped", async () => {
    const { client, provider, relay } = pair();
    const stranger = new Session(new MemoryRelay(), regtest, PROFILE);
    stranger.sessionId = client.sessionId;
    const signetPeer = new Session(new MemoryRelay(), signet, PROFILE);
    signetPeer.sessionId = client.sessionId;
    const other = new Session(new MemoryRelay(), regtest, PROFILE);
    client.providerKey = provider.key;
    const candidates = [
      stranger.envelope("ack", { acknowledged_message_id: "00".repeat(32) }),
      signetPeer.envelope("ack", { acknowledged_message_id: "00".repeat(32) }),
      other.envelope("ack", { acknowledged_message_id: "00".repeat(32) }),
      provider.envelope("ack", { acknowledged_message_id: "00".repeat(32) }, { signed: false }),
    ];
    const senders = [stranger, signetPeer, other, provider];
    for (const [index, envelope] of candidates.entries()) {
      const raw = await deliver(senders[index]!, client, envelope, relay);
      expect(client.admit(raw)).toBeNull();
    }
    const tampered = JSON.parse(await deliver(provider, client, provider.envelope("ack", {}), relay)) as NostrEvent;
    tampered.content = `${tampered.content.slice(0, -4)}AAAA`;
    expect(client.admit(JSON.stringify(tampered))).toBeNull();
  });

  test("an unanswered request times out", async () => {
    const { client } = pair();
    const request = client.envelope("quote_request", {});
    await expect(client.replyTo(request, "terms_offer")).rejects.toThrow(SwapError);
  });
});

describe("rill-provider interop", () => {
  test("a gift wrap produced by rill-provider unwraps to the exact envelope", async () => {
    const { hexToBytes } = await import("@noble/hashes/utils.js");
    const { unwrapGiftWrap } = await import("../src/swap/session");
    const python = (await import("./fixtures/nip59-python-gift-wrap.json")).default;
    const auth = (await import("./fixtures/authentication-cases-v1.json")).default;
    const vector = auth.valid.find((item) => item.id === python.vector_id)!;
    const envelope = vector.confirm_envelope.object;
    const secret = hexToBytes(python.recipient_secret_key);
    const frame = unwrapGiftWrap(python.gift_wrap, secret, envelope.network_identity, envelope.profile_id);
    expect(frame.envelope).toEqual(envelope as never);
    expect(frame.sealAuthor).toBe(vector.confirm_envelope.signer_xonly_key);
    expect(() => unwrapGiftWrap(python.gift_wrap, secret, signet, envelope.profile_id)).toThrow();
    expect(() => unwrapGiftWrap(python.gift_wrap, hexToBytes(`${"00".repeat(31)}04`), envelope.network_identity,
      envelope.profile_id)).toThrow();
  });
});

describe("relay-visible metadata (N07/N08)", () => {
  test("a gift wrap exposes only the recipient, a fuzzed time, and its size", async () => {
    const { client, provider } = pair();
    const secret = { payment_hash: "5a".repeat(32), invoice: "lnbcrt500u1pexampleinvoice", contract: "6b".repeat(32) };
    const envelope = client.envelope("quote_request", secret, { contract: secret.contract });
    const before = Math.floor(Date.now() / 1000);
    await client.send(envelope, provider.key);
    const outer = (client.relay as MemoryRelay).published.at(-1)!;
    const visible = JSON.stringify(outer);
    for (const hidden of [secret.payment_hash, secret.invoice, secret.contract, envelope.session_id,
      envelope.message_id, client.key]) {
      expect(visible).not.toContain(hidden);
    }
    // What an observer does learn: the recipient key, a backdated time, and the size.
    expect(outer.tags).toEqual([["p", provider.key]]);
    expect(outer.kind).toBe(1059);
    expect(outer.created_at).toBeLessThanOrEqual(before + 1);
    expect(outer.pubkey).not.toBe(client.key);
  });
});
