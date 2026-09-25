import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "bun:test";
import { Decrypter, generateIdentity, identityToRecipient } from "age-encryption";
import canonicalize from "canonicalize";

import {
  RecoveryAgeContainerRefusedError,
  encryptCanonicalRecoveryForRecipient,
} from "../src/recoveryAgeContainer";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CASES = [
  ["initial-btc-to-ln-v1.json", "c30fd383eb769973976f5600a05e0f3883d50bb3486a375131659b3be03b09eb"],
  ["initial-ln-to-btc-no-prepayment-v1.json", "41ec77f4c4adf3383b96a58d4fdf799ad8ee922deccd69bcc9e5d7cba69a43c3"],
] as const;

function fixture(name: string): Uint8Array {
  const object: unknown = JSON.parse(readFileSync(resolve(import.meta.dir, "fixtures", name), "utf8"));
  const content = canonicalize(object);
  if (content === undefined) throw new Error("synthetic recovery fixture invalid");
  return encoder.encode(content);
}

async function recipientPair(): Promise<{ identity: string; recipient: string }> {
  const identity = await generateIdentity();
  return { identity, recipient: await identityToRecipient(identity) };
}

async function decrypt(identity: string, ciphertext: Uint8Array): Promise<Uint8Array> {
  const d = new Decrypter();
  d.addIdentity(identity);
  return d.decrypt(ciphertext);
}

describe("disconnected recovery age-X25519 container", () => {
  test.each(CASES)("encrypts canonical %s fixture as binary age for one recipient", async (name, hash) => {
    const local = readFileSync(resolve(import.meta.dir, "fixtures", name));
    expect(createHash("sha256").update(local).digest("hex")).toBe(hash);
    const docs = resolve(import.meta.dir, "../../rill-docs/vectors/recovery", name);
    if (existsSync(docs)) expect(readFileSync(docs).equals(local)).toBe(true);
    const original = fixture(name);
    const { identity, recipient } = await recipientPair();
    const ciphertext = await encryptCanonicalRecoveryForRecipient(original, recipient);
    expect(ciphertext.length).toBeLessThanOrEqual(256 * 1024);
    expect(decoder.decode(ciphertext.subarray(0, 22))).toBe("age-encryption.org/v1\n");
    expect(await decrypt(identity, ciphertext)).toEqual(original);
    const tampered = Uint8Array.from(ciphertext);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;
    await expect(decrypt(identity, tampered)).rejects.toThrow();
  });

  test("copies caller bytes before asynchronous encryption and never silently changes recipient", async () => {
    const payload = fixture(CASES[0][0]);
    const first = await recipientPair();
    const second = await recipientPair();
    const copy = Uint8Array.from(payload);
    const pending = encryptCanonicalRecoveryForRecipient(payload, second.recipient);
    payload.fill(0);
    const ciphertext = await pending;
    expect(await decrypt(second.identity, ciphertext)).toEqual(copy);
    await expect(decrypt(first.identity, ciphertext)).rejects.toThrow();
    // A valid but substituted age recipient is not detected by this producer.
    expect(second.recipient).not.toBe(first.recipient);
  });

  test("rejects malformed input without leaking plaintext or recipient", async () => {
    const { recipient } = await recipientPair();
    const base = fixture(CASES[0][0]);
    for (const bytes of [
      new Uint8Array(), new Uint8Array([0xff]),
      encoder.encode(`\ufeff${decoder.decode(base)}`),
      encoder.encode(JSON.stringify(JSON.parse(decoder.decode(base)), null, 2)),
      encoder.encode('{"format":"rillswap-recovery","format":"rillswap-recovery","format_version":"1-pre.1","specification_version":"0.1.0-pre.1"}'),
      encoder.encode('{"format":"rillswap-recovery","format_version":"2","specification_version":"0.1.0-pre.1"}'),
      new Uint8Array(128 * 1024 + 1),
    ]) {
      try {
        await encryptCanonicalRecoveryForRecipient(bytes, recipient);
        throw new Error("invalid input unexpectedly encrypted");
      } catch (error) {
        expect(error).toBeInstanceOf(RecoveryAgeContainerRefusedError);
        expect(String(error)).not.toContain("rillswap-recovery");
        expect(String(error)).not.toContain(recipient);
      }
    }
    for (const invalid of [
      "", "AGE1invalid", "age1invalid", "age1" + "q".repeat(256),
      // Valid P-256 tag recipient: accepted by age-encryption but not RS-007 X25519.
      "age1tag1qd43050juykyy3lchnnw2caygre8wqmasyk7kvaq7jsnj3wcnrpfvt5hxye",
    ]) {
      await expect(encryptCanonicalRecoveryForRecipient(base, invalid))
        .rejects.toThrow(RecoveryAgeContainerRefusedError);
    }
  });

  test("uses UTF-8 byte ceilings, accepts exact 128 KiB and rejects the next byte", async () => {
    const { identity, recipient } = await recipientPair();
    const empty = canonicalize({ format: "rillswap-recovery", format_version: "1-pre.1",
      specification_version: "0.1.0-pre.1", note: "" });
    if (empty === undefined) throw new Error("synthetic empty fixture invalid");
    const max = 128 * 1024;
    const exact = encoder.encode(empty.replace('"note":""',
      `"note":"${"x".repeat(max - empty.length)}"`));
    expect(exact.length).toBe(max);
    const ciphertext = await encryptCanonicalRecoveryForRecipient(exact, recipient);
    expect(await decrypt(identity, ciphertext)).toEqual(exact);
    const over = encoder.encode(empty.replace('"note":""',
      `"note":"${"x".repeat(max - empty.length + 1)}"`));
    await expect(encryptCanonicalRecoveryForRecipient(over, recipient))
      .rejects.toThrow(RecoveryAgeContainerRefusedError);
  });
});
