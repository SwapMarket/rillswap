import { expect, test } from "bun:test";

import { AddressRefusedError, addressScript, scriptAddress } from "../src/swap/address";
import core from "./fixtures/funding-psbt-regtest.json";
import taproot from "./fixtures/taproot-cases-v1.json";

test("BIP173/BIP350 vectors and the Core regtest contract address", () => {
  expect(addressScript("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "mainnet")).toBe(
    "0014751e76e8199196d454941c45d1b3a323f1433bd6",
  );
  expect(addressScript(core.contract_address, "regtest")).toBe(taproot.valid[0]!.artifacts.script_pubkey);
  expect(scriptAddress(taproot.valid[0]!.artifacts.script_pubkey, "regtest")).toBe(core.contract_address);
  expect(scriptAddress("0014751e76e8199196d454941c45d1b3a323f1433bd6", "mainnet")).toBe(
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  );
});

test("other networks, versions, and checksums are refused", () => {
  const refused: [string, string][] = [
    ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "signet"],
    ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "mainnet"],
    // P2WSH is a valid address but not a version-one destination.
    ["bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "mainnet"],
    // BIP350: a v1 program with a bech32 (not bech32m) checksum.
    ["bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "mainnet"],
  ];
  for (const [address, network] of refused) {
    expect(() => addressScript(address, network)).toThrow(AddressRefusedError);
  }
});
