// Mock transport only. Real conservative ledger opening must refuse absent state.
import { mock } from "bun:test";
import { receiver } from "../helpers";
mock.module("../../src/lnd", () => ({
  lndRestTransport: () => ({}),
  LndInvoiceBackend: class {
    async identity() { return { issuerId: "fixture", origin: "https://merchant.invalid", receiver, network: "regtest" }; }
  },
}));
process.env.RILLSWAP_REGTEST_MERCHANT = "1";
process.argv = [process.execPath, "regtest-merchant.ts", "serve", process.argv[2]!];
await import("../../scripts/regtest-merchant");
