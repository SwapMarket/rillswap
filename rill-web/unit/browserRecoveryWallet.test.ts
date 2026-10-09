import { expect, spyOn, test } from "bun:test";
import { HDKey } from "@scure/bip32";
import { deriveRefundKey, parseWalletBackup, refundDerivationPath, walletRecoveryKey, WALLET_SCHEME } from "../src/browserRecoveryWallet";
import { scriptAddress } from "../src/swap/address";

const backup = { format: "rillswap-browser-recovery", version: 1, scheme: WALLET_SCHEME,
  mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" } as const;

test("mainnet refund derivation matches BIP84's published first receiving address", () => {
  // https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
  const derived = deriveRefundKey(backup, "mainnet", 0);
  expect(derived.path).toBe("m/84'/0'/0'/0/0");
  expect(scriptAddress(derived.script, "mainnet")).toBe("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  derived.privateKey.fill(0);
});

test("v1 root-to-age derivation is deterministic and uses the frozen domain", async () => {
  const key = await walletRecoveryKey(backup);
  expect(key.recipient).toBe("age17qylr3cu8dakpdtuw0mq8n43uprl8r0pppavg4cttcrj77t29eysju3h89");
  expect((await walletRecoveryKey(backup)).identity).toBe(key.identity);
});

test("test-network accounts are distinct and address indices never wrap", () => {
  expect(refundDerivationPath("signet", 0)).toBe("m/84'/1'/0'/0/0");
  expect(refundDerivationPath("testnet4", 0)).toBe("m/84'/1'/1'/0/0");
  expect(refundDerivationPath("regtest", 0)).toBe("m/84'/1'/2'/0/0");
  const scripts = (["mainnet", "signet", "testnet4", "regtest"] as const).map((network) => {
    const derived = deriveRefundKey(backup, network, 0);
    derived.privateKey.fill(0); return derived.script;
  });
  expect(new Set(scripts).size).toBe(4);
  for (const index of [-1, 0.1, 2 ** 31, Number.MAX_SAFE_INTEGER]) expect(() => refundDerivationPath("mainnet", index)).toThrow();
});

test("backup verification rejects damaged, ambiguous, and unsupported formats", () => {
  expect(parseWalletBackup(JSON.stringify(backup))).toEqual(backup);
  for (const value of [{ ...backup, version: 2 }, { ...backup, scheme: "future" }, { ...backup, mnemonic: "abandon" },
    { ...backup, extra: "field" }, { ...backup, mnemonic: backup.mnemonic.replace("about", "abandon") }]) {
    expect(() => parseWalletBackup(JSON.stringify(value))).toThrow();
  }
  expect(() => parseWalletBackup(JSON.stringify(backup).replace('"version":1', '"version":1,"version":1'))).toThrow();
});

test("BIP32 child skips are refused at hardened and leaf derivation steps", () => {
  const original = HDKey.prototype.deriveChild;
  for (const skippedStep of [1, 3, 5]) {
    let step = 0;
    const spy = spyOn(HDKey.prototype, "deriveChild").mockImplementation(function(this: HDKey, index: number) {
      const child = original.call(this, index);
      if (++step === skippedStep) Object.defineProperty(child, "index", { value: child.index + 1 });
      return child;
    });
    try { expect(() => deriveRefundKey(backup, "mainnet", 0)).toThrow("skipped a child"); }
    finally { spy.mockRestore(); }
  }
});
