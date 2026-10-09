/** Local RS-007 plaintext admission only. No cryptographic or action authority. */
import canonicalize from "canonicalize";
import { validateRecoveryPlaintext } from "./generated/recoveryValidators.js";
import { MAX_RECOVERY_PLAINTEXT_BYTES } from "./recoveryAgeContainer";
import { parseStrictRecoveryJson } from "./strictEventJson";

export interface UnverifiedRecoveryDocument {
  readonly authentication: "unverified";
  /** Secret-bearing data, not a report. Never log, display wholesale, or persist. */
  readonly document: Readonly<Record<string, unknown>>;
}

export class RecoveryDocumentRefusedError extends Error {
  constructor() {
    super("Recovery document could not be parsed");
    this.name = "RecoveryDocumentRefusedError";
  }
}

function freezeJson(value: unknown): void {
  if (value !== null && typeof value === "object") {
    for (const item of Object.values(value)) freezeJson(item);
    Object.freeze(value);
  }
}

/** Bytes must already be decrypted. Success does not authenticate any contract or history. */
export function parseRecoveryPlaintext(plaintext: Uint8Array): UnverifiedRecoveryDocument {
  try {
    if (!(plaintext instanceof Uint8Array) || plaintext.length === 0 || plaintext.length > MAX_RECOVERY_PLAINTEXT_BYTES) {
      throw new RecoveryDocumentRefusedError();
    }
    const snapshot = Uint8Array.from(plaintext);
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(snapshot);
    const value = parseStrictRecoveryJson(raw, MAX_RECOVERY_PLAINTEXT_BYTES);
    const canonical = canonicalize(value);
    if (typeof canonical !== "string") throw new RecoveryDocumentRefusedError();
    const bytes = new TextEncoder().encode(canonical);
    if (bytes.length !== snapshot.length || bytes.some((byte, index) => byte !== snapshot[index])) {
      throw new RecoveryDocumentRefusedError();
    }
    if (!validateRecoveryPlaintext(value)) throw new RecoveryDocumentRefusedError();
    freezeJson(value);
    return Object.freeze({ authentication: "unverified", document: value as Readonly<Record<string, unknown>> });
  } catch { throw new RecoveryDocumentRefusedError(); }
}
