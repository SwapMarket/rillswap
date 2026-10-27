import { expect, spyOn, test } from "bun:test";
import canonicalize from "canonicalize";
import { schnorr } from "@noble/curves/secp256k1.js";
import { observeRecoveryFunding, RecoveryFundingUnavailableError } from "../src/recoveryFunding";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "../src/recoveryAgeContainer";
import { appendBinding, fixtureRecord, signRecord } from "./fixtures/recoveryInspectionFixture";
import { refundCase, recoveryRefundCases, type RecoveryRefundCase } from "./fixtures/recoveryRefundCases";
import type { ChainFetch } from "../src/swap/chainTip";
import type { NetworkName } from "../src/swap/config";

const BASE = "http://127.0.0.1:8091/api";
const encoder = new TextEncoder();
const bytes = (item: RecoveryRefundCase): Uint8Array => encoder.encode(canonicalize(item.record)!);
const network = (item: RecoveryRefundCase) => item.expectedNetwork as { name: NetworkName; genesis_hash: string };
const selection = (item: RecoveryRefundCase) => ({ fundingAttemptId: item.fundingAttemptId, bindingRevision: item.bindingRevision });

function api(item = refundCase()) {
  const responses = new Map<string, string>([
    ["block-height/0", network(item).genesis_hash], ["blocks/tip/height", "1101"], ["blocks/tip/hash", "a".repeat(64)],
    ["block-height/1000", "d".repeat(64)],
    [`tx/${item.record.funding_history[item.bindingRevision]!.binding.funding_txid}/hex`, item.fundingTxHex],
    [`tx/${item.record.funding_history[item.bindingRevision]!.binding.funding_txid}/status`, JSON.stringify({ confirmed: true, block_height: 1000, block_hash: "d".repeat(64) })],
    [`tx/${item.record.funding_history[item.bindingRevision]!.binding.funding_txid}/outspend/0`, '{"spent":false}'],
  ]);
  const calls: { path: string; init: RequestInit }[] = [];
  const transport: ChainFetch = async (url, init) => {
    const path = String(url).slice(BASE.length + 1); calls.push({ path, init: init! });
    const response = responses.get(path);
    if (response === undefined) throw new Error("unexpected endpoint");
    return new Response(response);
  };
  const run = (fetch: ChainFetch = transport, signal?: AbortSignal) => observeRecoveryFunding(bytes(item), network(item), selection(item), BASE, { fetch, ...(signal ? { signal } : {}) });
  return { item, responses, calls, transport, run };
}

test("coherent observations return deeply immutable public metadata with no signing or request bodies", async () => {
  const mock = api(); const sign = spyOn(schnorr, "sign");
  try {
    const result = await mock.run();
    expect(result).toEqual({ observation: "trusted-api", networkName: "regtest", rawFundingTransactionHex: mock.item.fundingTxHex, fundingTxid: mock.item.record.funding_history[0]!.binding.funding_txid,
      fundingVout: 0, fundingBlockHeight: 1000, fundingBlockHash: "d".repeat(64), confirmations: 102,
      tipHeight: 1101, tipHash: "a".repeat(64), refundLockHeight: 1100, refundMatureAtObservedTip: true });
    expect(Object.isFrozen(result)).toBe(true); expect(sign).not.toHaveBeenCalled();
    expect(mock.calls.filter((c) => c.path.endsWith("/hex"))).toHaveLength(2);
    expect(mock.calls.filter((c) => c.path.endsWith("/status"))).toHaveLength(2);
    expect(mock.calls.filter((c) => c.path.includes("outspend"))).toHaveLength(2);
    for (const { init } of mock.calls) {
      expect(init.credentials).toBe("omit"); expect(init.redirect).toBe("error"); expect(init.cache).toBe("no-store");
      expect(init.referrerPolicy).toBe("no-referrer"); expect(init.body).toBeUndefined(); expect(init.headers).toBeUndefined();
    }
  } finally { sign.mockRestore(); }
});

test("height R is a coherent immature observation, R+1 is mature at the observed tip only", async () => {
  const mock = api(); mock.responses.set("blocks/tip/height", "1100");
  expect((await mock.run()).refundMatureAtObservedTip).toBe(false);
  mock.responses.set("blocks/tip/height", "1101");
  expect((await mock.run()).refundMatureAtObservedTip).toBe(true);
});

test("same-tip inclusion has one confirmation only when its hash matches the tip", async () => {
  const mock = api(), path = `tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/status`;
  mock.responses.set(path, JSON.stringify({ confirmed: true, block_height: 1101, block_hash: "d".repeat(64) }));
  mock.responses.set("block-height/1101", "d".repeat(64));
  await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  mock.responses.set(path, JSON.stringify({ confirmed: true, block_height: 1101, block_hash: "a".repeat(64) }));
  mock.responses.set("block-height/1101", "a".repeat(64));
  expect((await mock.run()).confirmations).toBe(1);
});

test("height-zero inclusion cannot contradict the configured genesis even when height lookups lie consistently", async () => {
  const mock = api();
  mock.responses.set(`tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/status`, JSON.stringify({ confirmed: true, block_height: 0, block_hash: "d".repeat(64) }));
  let genesisReads = 0;
  const transport: ChainFetch = (url, init) => {
    if (String(url).endsWith("block-height/0")) {
      genesisReads++;
      return Promise.resolve(new Response(genesisReads === 1 || genesisReads === 4 ? network(mock.item).genesis_hash : "d".repeat(64)));
    }
    return mock.transport(url, init);
  };
  await expect(mock.run(transport)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
});

test("invalid documents, full networks, selectors, or unselected history are refused before any connection", async () => {
  const mock = api();
  const damaged = structuredClone(mock.item); appendBinding(damaged.record); damaged.record.funding_history[1]!.funder_session_signature = "0".repeat(128);
  const empty = fixtureRecord();
  const unsupported = recoveryRefundCases().find((c) => c.name === "unsupported execution consensus profile")!;
  for (const [doc, selectedNetwork, chosen] of [
    [new Uint8Array(), network(mock.item), selection(mock.item)],
    [new Uint8Array(MAX_RECOVERY_PLAINTEXT_BYTES + 1), network(mock.item), selection(mock.item)],
    [bytes(damaged), network(mock.item), selection(mock.item)],
    [bytes(unsupported), network(unsupported), selection(unsupported)],
    [encoder.encode(canonicalize(empty)!), empty.network_identity, selection(mock.item)],
    [bytes(mock.item), { ...network(mock.item), genesis_hash: "0".repeat(64) }, selection(mock.item)],
    [bytes(mock.item), network(mock.item), { ...selection(mock.item), fundingAttemptId: "f".repeat(64) }],
    [bytes(mock.item), network(mock.item), { ...selection(mock.item), bindingRevision: true }],
  ] as const) {
    await expect(observeRecoveryFunding(doc, selectedNetwork as ReturnType<typeof network>, chosen as ReturnType<typeof selection>, BASE, { fetch: mock.transport })).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  }
  expect(mock.calls).toEqual([]);
});

test("raw transaction validation precedes outspend, including nonexistent vouts accompanied by spent:false", async () => {
  const cases = recoveryRefundCases();
  for (const name of ["funding vout nonexistent", "funding anchor absent", "funding duplicate inputs", "funding wrong contract value", "funding wrong contract script", "funding duplicate contract outputs", "funding unsupported change script", "funding bytes differ from binding txid"]) {
    const item = cases.find((c) => c.name === name)!;
    const mock = api(item);
    await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    expect(mock.calls.some((c) => c.path.includes("outspend")), name).toBe(false);
  }
});

for (const [name, status] of [
  ["unconfirmed", { confirmed: false }], ["missing height", { confirmed: true, block_hash: "d".repeat(64) }],
  ["height bool", { confirmed: true, block_height: true, block_hash: "d".repeat(64) }],
  ["negative height", { confirmed: true, block_height: -1, block_hash: "d".repeat(64) }],
  ["above tip", { confirmed: true, block_height: 1102, block_hash: "d".repeat(64) }],
  ["unsafe height", { confirmed: true, block_height: 9007199254740992, block_hash: "d".repeat(64) }],
  ["invalid hash", { confirmed: true, block_height: 1000, block_hash: "D".repeat(64) }],
  ["fractional height", { confirmed: true, block_height: 1000.5, block_hash: "d".repeat(64) }],
] as const) {
  test(`bad confirmation status is unknown: ${name}`, async () => {
    const mock = api(); mock.responses.set(`tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/status`, JSON.stringify(status));
    await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  });
}

for (const body of ['{"spent":true}', '{}', 'null', '{"spent":null}', '{"spent":0}', '{"spent":"false"}', '{"spent":false,"spent":false}']) {
  test(`absent, spent, malformed, or duplicate outspend is unknown: ${body}`, async () => {
    const mock = api(); mock.responses.set(`tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/outspend/0`, body);
    await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  });
}

test("inclusion hash mismatch or inconsistent status/raw/outspend/tips across reads is unknown without retry", async () => {
  for (const kind of ["inclusion", "status", "raw", "spent", "tip", "genesis"]) {
    const mock = api();
    const counts = new Map<string, number>();
    const transport: ChainFetch = async (url, init) => {
      const path = String(url).slice(BASE.length + 1), count = (counts.get(path) ?? 0) + 1; counts.set(path, count);
      if (kind === "inclusion" && path === "block-height/1000") return new Response("e".repeat(64));
      if (kind === "status" && path.endsWith("/status") && count === 2) return new Response('{"confirmed":true,"block_height":999,"block_hash":"' + "d".repeat(64) + '"}');
      if (kind === "raw" && path.endsWith("/hex") && count === 2) return new Response("00".repeat(60));
      if (kind === "spent" && path.includes("outspend") && count === 2) return new Response('{"spent":true}');
      if (kind === "tip" && path === "blocks/tip/hash" && count > 2) return new Response("e".repeat(64));
      if (kind === "genesis" && path === "block-height/0") return new Response("e".repeat(64));
      return mock.transport(url, init);
    };
    await expect(mock.run(transport)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    expect(Math.max(...counts.values())).toBeLessThanOrEqual(4);
  }
});

test("streaming bounds, invalid UTF-8, HTTP/redirect failures, and duplicate status keys fail redacted", async () => {
  for (const response of [
    new Response("0".repeat(200001)), new Response("0".repeat(120), { headers: { "Content-Length": "200001" } }),
    new Response(Uint8Array.of(0xff)), new Response("private-error-canary", { status: 404 }), Response.redirect("https://example.invalid", 302),
  ]) {
    const mock = api();
    const transport: ChainFetch = (url, init) => String(url).endsWith("/hex") ? Promise.resolve(response) : mock.transport(url, init);
    await expect(mock.run(transport)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    expect(mock.calls.some((c) => c.path.includes("outspend"))).toBe(false);
  }
  const mock = api(); mock.responses.set(`tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/status`, '{"confirmed":true,"confirmed":true}');
  await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  mock.responses.set(`tx/${mock.item.record.funding_history[0]!.binding.funding_txid}/status`, " ".repeat(2049));
  await expect(mock.run()).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
});

test("cancellation during a hung body read releases the stream and returns only the generic error", async () => {
  for (const suffix of ["/hex", "tip/height"]) {
    const mock = api(), controller = new AbortController();
    let canceled = false;
    const transport: ChainFetch = async (url, init) => {
      if (String(url).endsWith(suffix)) {
        queueMicrotask(() => controller.abort(new Error("private-error-canary")));
        return new Response(new ReadableStream({ cancel() { canceled = true; } }));
      }
      return mock.transport(url, init);
    };
    await expect(mock.run(transport, controller.signal)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    expect(canceled).toBe(true);
  }
});

test("mutating input bytes/network/selector after the first await cannot redirect the observation", async () => {
  const mock = api(), document = bytes(mock.item), selectedNetwork = structuredClone(network(mock.item)), chosen = selection(mock.item);
  let mutated = false;
  const transport: ChainFetch = async (url, init) => {
    if (!mutated) {
      mutated = true; document.fill(0); selectedNetwork.genesis_hash = "e".repeat(64); chosen.fundingAttemptId = "f".repeat(64); chosen.bindingRevision = 1;
    }
    return mock.transport(url, init);
  };
  const result = await observeRecoveryFunding(document, selectedNetwork, chosen, BASE, { fetch: transport });
  expect(result.fundingTxid).toBe(mock.item.record.funding_history[0]!.binding.funding_txid);
  expect(result.refundMatureAtObservedTip).toBe(true);
});

test("the total observation deadline cancels a hung response without automatic retry", async () => {
  const mock = api(); let canceled = false;
  const original = AbortSignal.timeout.bind(AbortSignal);
  const timeout = spyOn(AbortSignal, "timeout").mockImplementation((milliseconds: number) => original(milliseconds === 20000 ? 10 : milliseconds));
  try {
    const transport: ChainFetch = (url, init) => String(url).endsWith("/hex")
      ? Promise.resolve(new Response(new ReadableStream({ cancel() { canceled = true; } }))) : mock.transport(url, init);
    await expect(mock.run(transport)).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
    expect(canceled).toBe(true);
  } finally { timeout.mockRestore(); }
});

test("the explicitly selected older revision is observed, never silently replaced", async () => {
  const mock = api(); appendBinding(mock.item.record); signRecord(mock.item.record);
  const result = await mock.run();
  expect(result.fundingTxid).toBe(mock.item.record.funding_history[0]!.binding.funding_txid);
  expect(mock.calls.every((c) => !c.path.includes(mock.item.record.funding_history[1]!.binding.funding_txid))).toBe(true);
});

test("a mempool backend without the single outspend lookup is read from its outspends list", async () => {
  const run = (list: string, single: Response | undefined) => {
    const mock = api(); const txid = mock.item.record.funding_history[0]!.binding.funding_txid;
    mock.responses.delete(`tx/${txid}/outspend/0`); mock.responses.set(`tx/${txid}/outspends`, list);
    const transport: ChainFetch = (url, init) => String(url).endsWith(`/outspend/0`)
      ? (mock.calls.push({ path: String(url).slice(BASE.length + 1), init: init! }), Promise.resolve(single ?? new Response("Cannot GET", { status: 404 })))
      : mock.transport(url, init);
    return { mock, txid, result: mock.run(transport) };
  };
  const { mock, txid, result } = run('[{"spent":false},{"spent":true,"txid":"' + "e".repeat(64) + '","vin":0}]', undefined);
  expect((await result).fundingVout).toBe(0);
  expect(mock.calls.filter((c) => c.path === `tx/${txid}/outspends`)).toHaveLength(2);
  for (const list of ['[{"spent":true}]', "[]", '{"spent":false}', "[null]", '[{"spent":"false"}]', '[{"spent":false,"spent":false}]']) {
    await expect(run(list, undefined).result).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  }
  // An answer from the single lookup is final: the list never overrides it.
  const answered = run('[{"spent":false}]', new Response('{"spent":true}'));
  await expect(answered.result).rejects.toBeInstanceOf(RecoveryFundingUnavailableError);
  expect(answered.mock.calls.some((c) => c.path.endsWith("/outspends"))).toBe(false);
});
