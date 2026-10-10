import { expect, spyOn, test } from "bun:test";
import { getPublicKey } from "nostr-tools";
import { hexToBytes } from "@noble/hashes/utils.js";
import { restoreReverseFundingReader, Session, type RelayLink } from "../src/swap/session";
import { wrapPrivateRegtestEnvelope } from "../src/nip59Transport";
import canonicalize from "canonicalize";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";
import signet from "../src/networks/signet.json";
import { recoverReverseFundingEnvelopes } from "../src/swap/reverseFundingArchive";

const noop: RelayLink = { publish: async () => { throw new Error("read-only recovery must never publish"); }, subscribe: async () => {}, next: async () => null };
function setup() {
  const client = new Session(noop, regtest, "ln-to-btc/v1"), provider = new Session(noop, regtest, "ln-to-btc/v1");
  provider.sessionId = client.sessionId;
  const configuration = { secret: client.secret, clientKey: client.key, sessionId: client.sessionId, providerSessionKey: provider.key,
    network: structuredClone(regtest), contractHash: "a".repeat(64) };
  return { client, provider, configuration, reader: restoreReverseFundingReader(configuration) };
}
function message(provider: Session, clientKey: string, type = "funding_binding", options: { contract?: string; inReplyTo?: string; signed?: boolean } = {}): string {
  const envelope = provider.envelope(type, { binding: {}, funding_binding_signature: "0".repeat(128), funding_transaction: "00" }, { contract: "a".repeat(64), ...options });
  return JSON.stringify(wrapPrivateRegtestEnvelope(canonicalize(envelope)!, provider.secret, clientKey));
}
test("original keys admit signed historical funding without exposing outbound APIs or publication", () => {
  const { provider, client, reader } = setup(), raw = message(provider, client.key);
  const decoded = reader.admit(raw)!; expect(decoded.message_type).toBe("funding_binding"); expect(decoded.sender_session_key).toBe(provider.key);
  expect(reader.admit(raw)).toBeNull(); expect(Object.keys(reader).sort()).toEqual(["admit", "clientKey", "dispose"]);
  reader.dispose(); expect(reader.admit(message(provider, client.key))).toBeNull();
  expect(getPublicKey(client.secret)).toBe(client.key); // Disposing never mutates caller-owned saved key bytes.
});
for (const kind of ["sender", "session", "contract", "network", "profile", "signature", "reply", "message type", "malformed event"]) {
  test(`restored mailbox rejects ${kind}`, () => {
    const { provider, client, reader } = setup();
    let sender = provider;
    if (kind === "sender") { sender = new Session(noop, regtest, "ln-to-btc/v1"); sender.sessionId = client.sessionId; }
    if (kind === "session") provider.sessionId = "f".repeat(64);
    if (kind === "network") { sender = new Session(noop, signet, "ln-to-btc/v1"); sender.sessionId = client.sessionId; }
    if (kind === "profile") { sender = new Session(noop, regtest, "btc-to-ln/v1"); sender.sessionId = client.sessionId; }
    const raw = kind === "malformed event" ? "{}" : message(sender, client.key, kind === "message type" ? "handshake_accept" : "funding_binding",
      { ...(kind === "contract" ? { contract: "f".repeat(64) } : {}), ...(kind === "signature" ? { signed: false } : {}), ...(kind === "reply" ? { inReplyTo: "f".repeat(64) } : {}) });
    expect(reader.admit(raw)).toBeNull(); reader.dispose();
  });
}
test("receiver snapshots secrets and expectations without mutating caller configuration", () => {
  const { provider, client, configuration, reader } = setup(), key = client.key;
  configuration.secret.fill(0); configuration.network.deployment_namespace = "changed"; configuration.providerSessionKey = "f".repeat(64);
  expect(reader.admit(message(provider, key))!.sender_session_key).toBe(provider.key); reader.dispose();
});
test("absent/damaged restoration keys do not generate replacements", () => {
  const { configuration, reader } = setup(); reader.dispose();
  for (const patch of [{ secret: new Uint8Array(32) }, { secret: hexToBytes("01") }, { clientKey: "f".repeat(64) },
    { providerSessionKey: configuration.clientKey }, { network: null }, { sessionId: "invalid" }]) {
    expect(() => restoreReverseFundingReader({ ...configuration, ...patch })).toThrow("could not be restored");
  }
});

test("explicit archive recovery admits retained old events and never adds an author or recent-time filter", async () => {
  const { provider, client, reader } = setup(), clock = spyOn(Date, "now").mockReturnValue(1700000000000); let raw: string;
  try { raw = message(provider, client.key); } finally { clock.mockRestore(); }
  const filters: unknown[] = [];
  const result = await recoverReverseFundingEnvelopes([{ async queryDetailed(filter, limit, timeout) {
    filters.push(filter); expect(limit).toBe(64); expect(timeout).toBe(10000);
    return { events: [raw], truncated: false, completion: "eose" };
  } }], reader);
  expect(filters).toEqual([{ kinds: [1059], "#p": [client.key] }]); expect(result.envelopes).toHaveLength(1);
  expect(result.incomplete).toBe(false); reader.dispose();
});

test("EOSE without evidence, partial results, relay errors and truncation never infer funding or authorize payment", async () => {
  const { provider, client, reader } = setup(), raw = message(provider, client.key);
  const result = await recoverReverseFundingEnvelopes([
    { queryDetailed: async () => ({ events: [], truncated: false, completion: "eose" }) },
    { queryDetailed: async () => ({ events: [raw], truncated: false, completion: "timeout" }) },
    { queryDetailed: async () => { throw new Error("unavailable"); } },
    { queryDetailed: async () => ({ events: [message(provider, client.key)], truncated: true, completion: "limit" }) },
  ], reader);
  expect(result.envelopes).toHaveLength(1); expect(result.incomplete).toBe(true); reader.dispose();
  const next = setup(); expect(await recoverReverseFundingEnvelopes([{ queryDetailed: async () => ({ events: [], truncated: false, completion: "eose" }) }], next.reader))
    .toEqual({ envelopes: [], incomplete: false }); next.reader.dispose();
});

test("duplicate relay copies yield one candidate and absent relay selection does not connect", async () => {
  const { provider, client, reader } = setup(), raw = message(provider, client.key); let calls = 0;
  const relay = { queryDetailed: async () => { calls++; return { events: [raw], truncated: false, completion: "eose" as const }; } };
  expect((await recoverReverseFundingEnvelopes([relay, relay], reader)).envelopes).toHaveLength(1); expect(calls).toBe(2);
  await expect(recoverReverseFundingEnvelopes([], reader)).rejects.toThrow(); expect(calls).toBe(2); reader.dispose();
});
