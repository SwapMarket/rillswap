import { describe, expect, test } from "bun:test";
import { ConnectionPreferences, connectionDefaults } from "../src/connectionPreferences";
import { resolveSwapDefaults } from "../src/swap/config";
import mainnet from "../src/networks/mainnet.json";
import signet from "../src/networks/signet.json";
import regtest from "../src/networks/regtest-rillswap-e2e-v1.json";

const defaults = resolveSwapDefaults({});
const page = "https://swap.example/app/swap.html?ignored=1#ignored";
function storage() {
  const records = new Map<string, string>();
  return { records, getItem: (key: string) => records.get(key) ?? null,
    setItem: (key: string, value: string) => { records.set(key, value); }, removeItem: (key: string) => { records.delete(key); } };
}

describe("network connection preferences", () => {
  test("fresh upgrades read defaults without writing state", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    expect(prefs.read(mainnet, defaults)).toEqual({ values: connectionDefaults("mainnet", defaults), needsReset: false, message: "" });
    expect(disk.records.size).toBe(0);
  });

  test("persists normalized edits, including intentionally empty EVM RPC, across reloads", () => {
    const disk = storage(), configured = { ...defaults, evmRpc: "https://default-rpc.example" };
    const prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, configured, "relays", "wss://custom.example wss://custom.example/");
    prefs.save(mainnet, configured, "mempoolApi", " https://chain.example/api/ ");
    prefs.save(mainnet, configured, "broadcastApi", "https://send.example/api");
    prefs.save(mainnet, configured, "evmRpc", "");
    expect(new ConnectionPreferences(page, () => disk).read(mainnet, configured).values).toEqual({
      relays: ["wss://custom.example/"], mempoolApi: "https://chain.example/api", broadcastApi: "https://send.example/api", evmRpc: "",
    });
    expect(JSON.parse([...disk.records.values()][0]!)).toEqual({ version: 1, overrides: {
      relays: ["wss://custom.example/"], mempoolApi: "https://chain.example/api", broadcastApi: "https://send.example/api", evmRpc: "",
    } });
  });

  test("untouched defaults evolve, custom relay lists never merge, and new fields follow defaults", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "relays", "wss://private.example");
    const updated = { ...defaults, relays: ["wss://new-default.example/"], mempoolApi: "https://new-chain.example/api",
      broadcastApi: "https://new-send.example/api", evmRpc: "https://new-rpc.example" };
    expect(new ConnectionPreferences(page, () => disk).read(mainnet, updated).values).toEqual({
      relays: ["wss://private.example/"], mempoolApi: updated.mempoolApi, broadcastApi: updated.broadcastApi, evmRpc: updated.evmRpc,
    });
  });

  test("editing back to the current default removes only that override", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "mempoolApi", "https://custom.example/api");
    prefs.save(mainnet, defaults, "relays", "wss://private.example");
    prefs.save(mainnet, defaults, "mempoolApi", defaults.mempoolApi + "/");
    expect(JSON.parse([...disk.records.values()][0]!).overrides).toEqual({ relays: ["wss://private.example/"] });
    prefs.save(mainnet, defaults, "relays", defaults.relays.join("\n"));
    expect(disk.records.size).toBe(0);
  });

  test("an upstream default matching an override does not silently unpin it on another edit", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "mempoolApi", "https://custom.example/api");
    const updated = { ...defaults, mempoolApi: "https://custom.example/api" };
    const next = new ConnectionPreferences(page, () => disk);
    next.save(mainnet, updated, "relays", "wss://private.example");
    expect(new ConnectionPreferences(page, () => disk).read(mainnet, defaults).values.mempoolApi).toBe(updated.mempoolApi);
  });

  test("scope includes origin, deployment directory, complete network and regtest namespace, not filename", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "relays", "wss://private.example");
    for (const alias of ["https://swap.example/app/", "https://swap.example/app/index.html#other", "https://swap.example/app/swap.html"]) {
      expect(new ConnectionPreferences(alias, () => disk).read(mainnet, defaults).values.relays).toEqual(["wss://private.example/"]);
    }
    for (const other of ["https://other.example/app/", "https://swap.example/", "https://swap.example/app/signet/"]) {
      expect(new ConnectionPreferences(other, () => disk).read(mainnet, defaults).values.relays).toEqual(defaults.relays);
    }
    expect(prefs.read(signet, defaults).values.relays).toEqual(connectionDefaults("signet", defaults).relays);
    prefs.save(regtest, defaults, "relays", "ws://localhost:8777");
    expect(prefs.read({ ...regtest, deployment_namespace: "another-chain" }, defaults).values.relays).toEqual(["ws://127.0.0.1:7777/"]);
    expect(prefs.read({ ...mainnet, consensus_profile: "another-profile" }, defaults).values.relays).toEqual(defaults.relays);
    expect(prefs.read(Object.fromEntries(Object.entries(mainnet).reverse()) as typeof mainnet, defaults).values.relays).toEqual(["wss://private.example/"]);
  });

  test("reset removes only the current profile and restores the latest defaults", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "mempoolApi", "https://custom.example/api");
    prefs.save(signet, defaults, "relays", "wss://signet.example");
    disk.records.set("unrelated-recovery-marker", "keep");
    const updated = { ...defaults, mempoolApi: "https://new-default.example/api" };
    expect(prefs.reset(mainnet, updated).values.mempoolApi).toBe(updated.mempoolApi);
    expect(new ConnectionPreferences(page, () => disk).read(mainnet, updated).values.mempoolApi).toBe(updated.mempoolApi);
    expect(prefs.read(signet, defaults).values.relays).toEqual(["wss://signet.example/"]);
    expect(disk.records.get("unrelated-recovery-marker")).toBe("keep");
    expect(disk.records.size).toBe(2);
  });

  test("invalid edits keep the last saved override and never persist partial input", () => {
    const disk = storage(), prefs = new ConnectionPreferences(page, () => disk);
    prefs.save(mainnet, defaults, "mempoolApi", "https://custom.example/api");
    const before = [...disk.records];
    for (const [field, input] of [["relays", ""], ["relays", "ws://localhost:7777"], ["mempoolApi", "https://"],
      ["broadcastApi", "https://user:secret@host.example"], ["evmRpc", "https://rpc.example/?secret=1"]] as const) {
      expect(() => prefs.save(mainnet, defaults, field, input)).toThrow();
      expect([...disk.records]).toEqual(before);
    }
    expect(prefs.read(mainnet, defaults).values.mempoolApi).toBe("https://custom.example/api");
  });

  test.each(["{", "null", "[]", '{"version":2,"overrides":{}}', '{"version":0,"overrides":{}}',
    '{"version":1}', '{"version":1,"overrides":{"relays":[]}}', '{"version":1,"overrides":{"mempoolApi":5}}',
    '{"version":1,"overrides":{"ranking":"price"}}', '{"version":1,"overrides":{},"unknown":true}', " ".repeat(65_537)])(
    "unreadable records require explicit reset, without migration or replacement (%#)", (raw) => {
      const disk = storage();
      new ConnectionPreferences(page, () => disk).save(mainnet, defaults, "relays", "wss://private.example");
      const key = [...disk.records.keys()][0]!;
      disk.records.set(key, raw);
      const prefs = new ConnectionPreferences(page, () => disk);
      expect(prefs.read(mainnet, defaults).needsReset).toBe(true);
      expect(() => prefs.save(mainnet, defaults, "relays", "wss://other.example")).toThrow("Reset");
      expect(disk.records.get(key)).toBe(raw);
      expect(prefs.read(signet, defaults).needsReset).toBe(false);
      expect(prefs.reset(mainnet, defaults).needsReset).toBe(false);
      expect(disk.records.has(key)).toBe(false);
    });

  test("denied reads require explicit defaults choice, failed reset and edits remain session-only", () => {
    const prefs = new ConnectionPreferences(page, () => { throw new Error("denied"); });
    expect(prefs.read(mainnet, defaults).needsReset).toBe(true);
    const reset = prefs.reset(mainnet, defaults);
    expect(reset.needsReset).toBe(false);
    expect(reset.message).toContain("session only");
    expect(prefs.save(mainnet, defaults, "relays", "wss://private.example").message).toContain("session only");
    expect(prefs.read(mainnet, defaults).values.relays).toEqual(["wss://private.example/"]);
  });

  test("write failures preserve usable in-memory profiles without claiming persistence", () => {
    const disk = storage();
    const prefs = new ConnectionPreferences(page, () => ({ ...disk, setItem: () => { throw new Error("quota"); } }));
    expect(prefs.save(mainnet, defaults, "mempoolApi", "https://custom.example/api").message).toContain("session only");
    prefs.read(signet, defaults);
    expect(prefs.read(mainnet, defaults).values.mempoolApi).toBe("https://custom.example/api");
    expect(disk.records.size).toBe(0);
  });
});
