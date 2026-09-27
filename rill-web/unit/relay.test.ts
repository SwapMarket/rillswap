import { afterEach, describe, expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import type { NostrEvent } from "nostr-tools";

import { discoverProvider } from "../src/swap/discovery";
import { checkRelayUrl, RelayConnection, RelayError } from "../src/swap/relay";
import { SwapError } from "../src/swap/session";
import application from "./fixtures/manual-advertisement-regtest-v1.json";
import vector from "./fixtures/nostr-announcement-regtest-v1.json";

const IDENTITY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const NETWORK = application.advertisement.network_identities[0];
const ANNOUNCEMENT = JSON.stringify({
  id: vector.id, pubkey: vector.pubkey, created_at: vector.created_at, kind: vector.kind,
  tags: vector.tags, content: canonicalize(application), sig: vector.sig,
});
const originalNow = Date.now;
afterEach(() => { Date.now = originalNow; });

class FakeSocket extends EventTarget {
  readonly sent: unknown[][] = [];
  send(text: string): void {
    this.sent.push(JSON.parse(text) as unknown[]);
  }
  close(): void {
    this.dispatchEvent(new Event("close"));
  }
  deliver(frame: unknown): void {
    this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(frame) }));
  }
}

async function connect(): Promise<{ relay: RelayConnection; socket: FakeSocket }> {
  const socket = new FakeSocket();
  const opening = RelayConnection.open("ws://127.0.0.1:7000", 1000, () => socket as unknown as WebSocket);
  socket.dispatchEvent(new Event("open"));
  return { relay: await opening, socket };
}

test("relay URLs must be wss unless loopback", () => {
  expect(checkRelayUrl("wss://relay.example.org")).toBe("wss://relay.example.org/");
  expect(checkRelayUrl("ws://127.0.0.1:7000")).toBe("ws://127.0.0.1:7000/");
  for (const bad of ["ws://relay.example.org", "https://relay.example.org", "nonsense"]) {
    expect(() => checkRelayUrl(bad)).toThrow(RelayError);
  }
});

describe("relay connection", () => {
  test("publish resolves on the relay's OK for that event", async () => {
    const { relay, socket } = await connect();
    const accepted = relay.publish({ id: "aa" } as NostrEvent);
    const refused = relay.publish({ id: "bb" } as NostrEvent);
    socket.deliver(["OK", "bb", false, "blocked"]);
    socket.deliver(["OK", "aa", true, ""]);
    expect(await accepted).toBe(true);
    expect(await refused).toBe(false);
  });

  test("an AUTH challenge never triggers stable-key authentication (N12)", async () => {
    const { relay, socket } = await connect();
    await relay.subscribe({ kinds: [1059] });
    socket.deliver(["AUTH", "relay-challenge"]);
    const published = relay.publish({ id: "aa" } as NostrEvent);
    socket.deliver(["OK", "aa", false, "auth-required"]);
    expect(await published).toBe(false);
    expect(socket.sent.map((frame) => frame[0])).toEqual(["REQ", "EVENT"]);
    relay.close();
  });

  test("live events are queued only for the current subscription", async () => {
    const { relay, socket } = await connect();
    await relay.subscribe({ kinds: [1059] });
    const [, live] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", "other", { id: "x" }]);
    socket.deliver(["EVENT", live, { id: "y" }]);
    expect(await relay.next(Date.now() + 50)).toBe(JSON.stringify({ id: "y" }));
    expect(await relay.next(Date.now() + 20)).toBeNull();
    const waiting = relay.next(Date.now() + 1000);
    socket.deliver(["EVENT", live, { id: "z" }]);
    expect(await waiting).toBe(JSON.stringify({ id: "z" }));
  });

  test("a query collects stored events until EOSE and reports a flood", async () => {
    const { relay, socket } = await connect();
    const small = relay.query({ kinds: [39417] }, 2);
    const [, id] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", id, { id: 1 }]);
    socket.deliver(["EOSE", id]);
    expect(await small).toEqual({ events: [JSON.stringify({ id: 1 })], truncated: false });
    const flood = relay.query({ kinds: [39417] }, 1);
    const [, second] = socket.sent.at(-1) as [string, string];
    socket.deliver(["EVENT", second, { id: 1 }]);
    socket.deliver(["EVENT", second, { id: 2 }]);
    expect((await flood).truncated).toBe(true);
  });
});

describe("provider discovery", () => {
  const at = (events: string[], truncated = false) => ({ query: async () => ({ events, truncated }) });

  test("the signed announcement is selected and garbage ignored", async () => {
    spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
    const found = await discoverProvider(at(["{}", ANNOUNCEMENT, ANNOUNCEMENT]), IDENTITY, NETWORK, "btc-to-ln/v1");
    expect(found.identityXOnlyKey).toBe(IDENTITY);
    expect(found.requiresEpochBinding).toBe(false);
  });

  test("floods, absence, and another identity are refused", async () => {
    spyOn(Date, "now").mockReturnValue(1703021600 * 1000);
    await expect(discoverProvider(at([ANNOUNCEMENT], true), IDENTITY, NETWORK, "btc-to-ln/v1")).rejects
      .toThrow(SwapError);
    await expect(discoverProvider(at([]), IDENTITY, NETWORK, "btc-to-ln/v1")).rejects.toThrow(SwapError);
    const other = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    await expect(discoverProvider(at([ANNOUNCEMENT]), other, NETWORK, "btc-to-ln/v1")).rejects.toThrow(SwapError);
  });
});
