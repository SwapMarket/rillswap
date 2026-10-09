import { expect, test } from "bun:test";
import canonicalize from "canonicalize";
import { createRecoveryKey, decryptRecoveryContainer, parseRecoveryIdentity, RecoveryKeyRefusedError } from "../src/recoveryKeys";
import { encryptCanonicalRecoveryForRecipient, MAX_RECOVERY_CIPHERTEXT_BYTES } from "../src/recoveryAgeContainer";

const plaintext = new TextEncoder().encode(canonicalize({ format: "rillswap-recovery", format_version: "1-pre.1",
  specification_version: "0.1.0-pre.1", fixture: "container test, not a validated recovery document" })!);

test("the browser generates standard X25519 keys that decrypt its native age exports", async () => {
  const key = await createRecoveryKey();
  expect(key.recipient).toMatch(/^age1/);
  expect(await parseRecoveryIdentity(new TextDecoder().decode(key.file))).toBe(key.identity);
  const encrypted = await encryptCanonicalRecoveryForRecipient(plaintext, key.recipient);
  expect(await decryptRecoveryContainer(encrypted, key.identity)).toEqual(plaintext);
});

test("independent generated identities cannot open one another's backup", async () => {
  const key = await createRecoveryKey(), other = await createRecoveryKey();
  expect(key.recipient).not.toBe(other.recipient);
  const encrypted = await encryptCanonicalRecoveryForRecipient(plaintext, key.recipient);
  await expect(decryptRecoveryContainer(encrypted, other.identity)).rejects.toThrow(RecoveryKeyRefusedError);
});

test("key import rejects ambiguity, unsupported identity formats, and invalid checksums", async () => {
  const key = await createRecoveryKey();
  for (const value of ["", key.recipient, `${key.identity}\n${key.identity}`, key.identity.toLowerCase(),
    "AGE-SECRET-KEY-PQ-1" + "A".repeat(58), key.identity.slice(0, -1) + (key.identity.endsWith("Q") ? "P" : "Q"), "A".repeat(4097)]) {
    await expect(parseRecoveryIdentity(value)).rejects.toThrow(RecoveryKeyRefusedError);
  }
});

test("malformed or oversized ciphertext is refused without leaking a key", async () => {
  const key = await createRecoveryKey();
  for (const value of [new Uint8Array(), new Uint8Array([1, 2, 3]), new Uint8Array(MAX_RECOVERY_CIPHERTEXT_BYTES + 1)]) {
    try { await decryptRecoveryContainer(value, key.identity); throw new Error("expected refusal"); }
    catch (error) {
      expect(error).toBeInstanceOf(RecoveryKeyRefusedError);
      expect((error as Error).message).not.toContain(key.identity);
    }
  }
});
