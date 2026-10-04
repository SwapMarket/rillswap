/**
 * Non-browser cosigner for Bun: the same vendored WASM MuSig2 build, and an
 * in-process create-only journal in place of the Web Lock and IndexedDB.
 */
import createRillCrypto from "../src/vendor/rill-crypto/rill_crypto_wasm.mjs";
import type { Cosigner, ReservationRecord } from "../src/swap/cooperative";
import { createMusig } from "../src/swap/musig";

export function memoryCosigner(journal = new Map<string, ReservationRecord>()): Cosigner & {
  readonly journal: Map<string, ReservationRecord>;
} {
  return {
    journal,
    loadMusig: async () => createMusig(await createRillCrypto()),
    async reserve(key, record, body) {
      if (journal.has(key)) throw new Error("cooperation already reserved");
      journal.set(key, { ...record });
      return body();
    },
  };
}
