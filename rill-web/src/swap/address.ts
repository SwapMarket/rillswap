/** Native segwit v0 P2WPKH and v1 P2TR addresses for the selected network. */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bech32, bech32m } from "@scure/base";

export const ADDRESS_HRP: Readonly<Record<string, string>> = {
  mainnet: "bc",
  testnet3: "tb",
  testnet4: "tb",
  signet: "tb",
  regtest: "bcrt",
};

export class AddressRefusedError extends Error {
  constructor(reason: string) {
    super(`Address refused: ${reason}`);
    this.name = "AddressRefusedError";
  }
}

/** The output script of a P2WPKH or P2TR address on `networkName`. */
export function addressScript(address: string, networkName: string): string {
  const text = address.trim().toLowerCase();
  const hrp = ADDRESS_HRP[networkName];
  if (hrp === undefined || !text.startsWith(`${hrp}1`)) throw new AddressRefusedError("not for this network");
  const version = text.charAt(hrp.length + 1);
  try {
    if (version === "q") {
      const { words } = bech32.decode(text as `${string}1${string}`);
      const program = bech32.fromWords(words.slice(1));
      if (words[0] === 0 && program.length === 20) return `0014${bytesToHex(program)}`;
    } else if (version === "p") {
      const { words } = bech32m.decode(text as `${string}1${string}`);
      const program = bech32m.fromWords(words.slice(1));
      if (words[0] === 1 && program.length === 32) return `5120${bytesToHex(program)}`;
    }
  } catch {
    throw new AddressRefusedError("checksum or encoding invalid");
  }
  throw new AddressRefusedError("only P2WPKH (bc1q) and P2TR (bc1p) addresses are supported");
}

/** The address of a P2WPKH or P2TR script on `networkName`. */
export function scriptAddress(script: string, networkName: string): string {
  const hrp = ADDRESS_HRP[networkName];
  if (hrp === undefined) throw new AddressRefusedError("network unsupported");
  if (/^0014[0-9a-f]{40}$/.test(script)) return bech32.encode(hrp, [0, ...bech32.toWords(hexToBytes(script.slice(4)))]);
  if (/^5120[0-9a-f]{64}$/.test(script)) {
    return bech32m.encode(hrp, [1, ...bech32m.toWords(hexToBytes(script.slice(4)))]);
  }
  throw new AddressRefusedError("script is not P2WPKH or P2TR");
}
