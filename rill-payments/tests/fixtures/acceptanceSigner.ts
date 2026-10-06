// Test-owned separate key holder, not a production signer daemon or sandbox.
import { lstatSync, readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";

try {
  const path = process.argv[2]!;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 || stat.size !== 32) throw new Error();
  const key = readFileSync(path); console.log(JSON.stringify({ publicKey: bytesToHex(ed25519.getPublicKey(key)) }));
  const reader = Bun.stdin.stream().getReader(); let pending = "";
  try {
    while (true) {
      const chunk = await reader.read(); if (chunk.done) { if (pending) throw new Error(); break; }
      pending += new TextDecoder().decode(chunk.value); if (pending.length > 8192) throw new Error();
      while (pending.includes("\n")) {
        const end = pending.indexOf("\n"), message = JSON.parse(pending.slice(0, end)); pending = pending.slice(end + 1);
        if (end > 4096 || Object.keys(message).sort().join(",") !== "bytes,id" || !Number.isSafeInteger(message.id) || typeof message.bytes !== "string") throw new Error();
        const bytes = Buffer.from(message.bytes, "base64"), domain = JSON.parse(bytes.toString("utf8"));
        if (bytes.length > 2048 || !Array.isArray(domain) || domain.length !== 10 || domain[0] !== "rillswap-payment-event/1" || domain[1] !== "checkout-event/1" || domain[4] !== "payment.accepted") throw new Error();
        console.log(JSON.stringify({ id: message.id, signature: Buffer.from(ed25519.sign(bytes, key)).toString("base64") }));
      }
    }
  } finally { reader.releaseLock(); }
} catch { console.error("Owned acceptance signer refused"); process.exitCode = 1; }
