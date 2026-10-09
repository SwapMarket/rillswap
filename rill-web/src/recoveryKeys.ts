/** Browser-only age X25519 keys and bounded decryption, not recovery authorization. */
import { Decrypter, generateX25519Identity, identityToRecipient } from "age-encryption";
import { MAX_RECOVERY_CIPHERTEXT_BYTES, MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";

export interface RecoveryKey {
  readonly identity: string;
  readonly recipient: string;
  /** Standard age key file. Private: export locally, never log or persist in browser storage. */
  readonly file: Uint8Array;
}

export class RecoveryKeyRefusedError extends Error {
  constructor() {
    super("Recovery key or encrypted file could not be opened");
    this.name = "RecoveryKeyRefusedError";
  }
}

/** Accept exactly one native X25519 identity, optionally inside an age-keygen file. */
export async function parseRecoveryIdentity(text: string): Promise<string> {
  try {
    if (typeof text !== "string" || text.length === 0 || text.length > 4096) throw new RecoveryKeyRefusedError();
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"));
    if (lines.length !== 1 || !/^AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}$/.test(lines[0]!)) {
      throw new RecoveryKeyRefusedError();
    }
    await identityToRecipient(lines[0]!); // Decode/check checksum and exact X25519 key length.
    return lines[0]!;
  } catch { throw new RecoveryKeyRefusedError(); }
}

export async function createRecoveryKey(): Promise<RecoveryKey> {
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  return Object.freeze({ identity, recipient,
    file: new TextEncoder().encode(`# RillSwap recovery key. Keep private and backed up.\n# public key: ${recipient}\n${identity}\n`),
  });
}

/** Decrypted bytes still require full RS-007 schema, signature, and secret validation. */
export async function decryptRecoveryContainer(ciphertext: Uint8Array, identityText: string): Promise<Uint8Array> {
  try {
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0 || ciphertext.length > MAX_RECOVERY_CIPHERTEXT_BYTES) {
      throw new RecoveryKeyRefusedError();
    }
    const snapshot = Uint8Array.from(ciphertext);
    const identity = await parseRecoveryIdentity(identityText);
    const decrypter = new Decrypter();
    decrypter.addIdentity(identity);
    const plaintext = await decrypter.decrypt(snapshot);
    if (plaintext.length === 0 || plaintext.length > MAX_RECOVERY_PLAINTEXT_BYTES) throw new RecoveryKeyRefusedError();
    return plaintext;
  } catch { throw new RecoveryKeyRefusedError(); }
}
