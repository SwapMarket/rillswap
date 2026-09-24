/** Test-only cross-repository producer: no relay, persistence or real keys. */
import { wrapPrivateRegtestEnvelope } from "../src/nip59Transport";

try {
  const raw = await Bun.stdin.text();
  if (new TextEncoder().encode(raw).length > 20 * 1024) throw new Error("input too large");
  const request: unknown = JSON.parse(raw);
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("invalid request");
  }
  const fields = request as Record<string, unknown>;
  if (typeof fields.canonical_envelope !== "string" ||
      typeof fields.sender_secret_hex !== "string" ||
      !/^[0-9a-f]{64}$/.test(fields.sender_secret_hex) ||
      typeof fields.recipient_xonly_key !== "string") {
    throw new Error("invalid request");
  }
  const secret = Uint8Array.from(Buffer.from(fields.sender_secret_hex, "hex"));
  const wrap = wrapPrivateRegtestEnvelope(
    fields.canonical_envelope, secret, fields.recipient_xonly_key,
  );
  process.stdout.write(JSON.stringify(wrap));
} catch {
  process.stderr.write("Test-only NIP-59 fixture construction refused\n");
  process.exitCode = 1;
}
