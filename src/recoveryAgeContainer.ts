/** Disconnected binary age-X25519 container only, never a recovery export. */
import { Encrypter } from "age-encryption";
import canonicalize from "canonicalize";

const MAX_PLAINTEXT_BYTES = 128 * 1024;
const MAX_CIPHERTEXT_BYTES = 256 * 1024;
// Native age X25519 is Bech32 HRP "age" plus exactly 32 key bytes. Other
// valid age1-prefixed recipients (P-256 tags and hybrid/PQ) are not RS-007 v1.
const X25519_RECIPIENT = /^age1[023456789acdefghjklmnpqrstuvwxyz]{58}$/;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class RecoveryAgeContainerRefusedError extends Error {
  constructor() {
    super("Recovery age container construction refused");
    this.name = "RecoveryAgeContainerRefusedError";
  }
}

/**
 * Encrypt caller-validated canonical RS-007 bytes to ONE independently pinned
 * age X25519 recipient, returning binary age v1 ciphertext only. This does not
 * verify recovery signatures, schema, secret consistency, recipient ownership,
 * storage durability, or decryptability, and never creates an identity or UI.
 */
export async function encryptCanonicalRecoveryForRecipient(
  canonicalPlaintext: Uint8Array,
  selectedAgeRecipient: string,
): Promise<Uint8Array> {
  try {
    if (!(canonicalPlaintext instanceof Uint8Array) ||
        canonicalPlaintext.byteLength === 0 ||
        canonicalPlaintext.byteLength > MAX_PLAINTEXT_BYTES ||
        typeof selectedAgeRecipient !== "string" ||
        !X25519_RECIPIENT.test(selectedAgeRecipient)) {
      throw new RecoveryAgeContainerRefusedError();
    }
    // Keep the verified payload fixed across asynchronous key setup/encryption.
    const plaintext = Uint8Array.from(canonicalPlaintext);
    const content = decoder.decode(plaintext);
    const parsed: unknown = JSON.parse(content);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) ||
        canonicalize(parsed) !== content ||
        encoder.encode(content).length !== plaintext.length) {
      throw new RecoveryAgeContainerRefusedError();
    }
    const wrapper = parsed as Record<string, unknown>;
    if (wrapper.format !== "rillswap-recovery" ||
        wrapper.format_version !== "1-pre.1" ||
        wrapper.specification_version !== "0.1.0-pre.1") {
      throw new RecoveryAgeContainerRefusedError();
    }
    const encrypter = new Encrypter();
    encrypter.addRecipient(selectedAgeRecipient);
    const ciphertext = await encrypter.encrypt(plaintext);
    if (!(ciphertext instanceof Uint8Array) ||
        ciphertext.byteLength === 0 || ciphertext.byteLength > MAX_CIPHERTEXT_BYTES) {
      throw new RecoveryAgeContainerRefusedError();
    }
    return ciphertext;
  } catch {
    // Do not include caller plaintext, recipient, or cryptographic diagnostics.
    throw new RecoveryAgeContainerRefusedError();
  }
}
