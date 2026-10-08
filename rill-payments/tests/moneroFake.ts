import type { MoneroRpc, MoneroSnapshot, MoneroTransfer } from "../src/moneroRpc";

export const PRIMARY = "4" + "A".repeat(94);
export const ANCHOR = "a".repeat(64);
export const NETWORK = { version: "monero-regtest/1" as const, namespace: "test", confirmations: 10, anchorHash: ANCHOR };
export const subaddress = (minor: number): string => "8" + String(minor).replace(/0/g, "z").padStart(94, "B");
export const txid = (n: number): string => n.toString(16).padStart(64, "0");

export function transfer(minor: number, amount: bigint, overrides: Partial<MoneroTransfer> = {}): MoneroTransfer {
  return { txid: txid(minor * 1000 + 1), type: "in", amountAtomic: amount, height: 100, confirmations: 10, timestamp: 1500, unlockTime: "0", locked: false,
    doubleSpendSeen: false, major: 0, minor, address: subaddress(minor), ...overrides };
}

/** In-memory wallet-rpc stand-in; `stored` models what survives a wallet-rpc crash. */
export class FakeMonero implements MoneroRpc {
  snap: Partial<MoneroSnapshot> = {};
  next = 1;
  stored = 0;
  calls: string[] = [];
  entries: MoneroTransfer[] = [];
  failStore = false;
  async snapshot(anchorHeight: number): Promise<MoneroSnapshot> {
    this.calls.push(`snapshot:${anchorHeight}`);
    return { nettype: "fakechain", daemonHeight: 200, walletHeight: 200, anchorHash: ANCHOR, primaryAddress: PRIMARY, ...this.snap };
  }
  async createSubaddress(label: string) {
    this.calls.push(`create:${label.slice(0, 5)}`); const minor = this.next++; return { minor, address: subaddress(minor) };
  }
  async store() { this.calls.push("store"); if (this.failStore) throw new Error("store failed"); this.stored = this.next; }
  async transfers(minors: readonly number[]) { this.calls.push(`transfers:${minors.join(",")}`); return this.entries.filter((entry) => minors.includes(entry.minor)); }
  /** wallet-rpc killed before `store`: unstored allocations are forgotten. */
  crash() { this.next = Math.max(this.stored, 1); }
}
