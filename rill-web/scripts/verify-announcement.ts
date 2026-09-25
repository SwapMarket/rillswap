/** Test-only cross-component check: run the web verifier over one raw event. */
import { verifyPrivateRegtestAnnouncement } from "../src/nostrProviderAnnouncement";

try {
  const raw = await Bun.stdin.text();
  if (new TextEncoder().encode(raw).length > 256 * 1024) throw new Error("input too large");
  const request = JSON.parse(raw) as Record<string, unknown>;
  if (typeof request.event !== "string" || typeof request.identity !== "string" ||
      (request.profile !== "btc-to-ln/v1" && request.profile !== "ln-to-btc/v1")) {
    throw new Error("invalid request");
  }
  const candidate = verifyPrivateRegtestAnnouncement(
    request.event, request.identity, request.network, request.profile,
  );
  process.stdout.write(JSON.stringify({
    addressD: candidate.addressD,
    outerEventId: candidate.outerEventId,
    epochInboxKeys: candidate.advertisedEpochInboxKeys,
    endpoints: candidate.advertisedEndpoints,
    revision: candidate.revision,
    expiresAt: candidate.expiresAt,
  }));
} catch {
  process.stderr.write("announcement refused\n");
  process.exitCode = 1;
}
