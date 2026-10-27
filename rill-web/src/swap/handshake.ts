/** RS-001 session handshake and fresh contract keys, shared by both swap directions. */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

import type { AnnouncementCandidate } from "../nostrProviderAnnouncement";
import { epochBoundSessionId, handshakeHash } from "./hashes";
import type { Session } from "./session";
import {
  checkHandshakeAccept, COOPERATIVE_CLAIM_FEATURE, EPOCH_SESSION_EXTENSION, EPOCH_SESSION_FEATURE, type HandshakeInit,
} from "./wire";

const ENCRYPTION_SUITES = ["noise-xk-secp256k1-chachapoly-sha256/v1"];
const CAPABILITIES = ["core/v1", "recovery/v1"];

export interface Handshake {
  readonly init: HandshakeInit;
  readonly accept: ReturnType<typeof checkHandshakeAccept>;
  readonly acceptSignature: string;
  readonly transcript: string;
}

/** Shared by both directions; the profile comes from the session. */
export async function handshake(session: Session, provider: AnnouncementCandidate, identity: string): Promise<Handshake> {
  const epoch = provider.advertisedEpochInboxKeys[0]!;
  if (provider.requiresEpochBinding) {
    session.sessionId = bytesToHex(epochBoundSessionId(session.network, identity, epoch, session.key));
  }
  const init: HandshakeInit = {
    protocol: "rillswap",
    wire_version: "1",
    profile_id: session.profile,
    network_identity: session.network,
    session_id: session.sessionId,
    client_challenge: bytesToHex(randomBytes(32)),
    client_session_xonly_key: session.key,
    expected_provider_identity_xonly_key: identity,
    requested_encryption_suites: ENCRYPTION_SUITES,
    requested_capabilities: CAPABILITIES,
    // Both Bitcoin profiles negotiate cooperation, with unilateral recovery always available.
    required_features: [
      ...(["btc-to-ln/v1", "ln-to-btc/v1"].includes(session.profile) ? [COOPERATIVE_CLAIM_FEATURE] : []),
      ...(provider.requiresEpochBinding ? [EPOCH_SESSION_FEATURE] : []),
    ],
    extensions: provider.requiresEpochBinding ? { [EPOCH_SESSION_EXTENSION]: { epoch_inbox_xonly_key: epoch } } : {},
  };
  const request = session.envelope("handshake_init", init as unknown as Record<string, unknown>, { signed: false });
  await session.listen();
  await session.send(request, epoch);
  const answer = await session.replyTo(request, "handshake_accept");
  const accept = checkHandshakeAccept(answer.payload, init, answer.sender_session_key);
  session.providerKey = answer.sender_session_key;
  const transcript = bytesToHex(handshakeHash(init, accept));
  const confirm = session.envelope(
    "handshake_confirm",
    {
      handshake_hash: transcript,
      session_id: session.sessionId,
      client_session_xonly_key: session.key,
      provider_session_xonly_key: session.providerKey,
    },
    { inReplyTo: answer.message_id },
  );
  await session.send(confirm, session.providerKey);
  const signature = (answer.payload as { provider_identity_signature: string }).provider_identity_signature;
  return { init, accept, acceptSignature: signature, transcript };
}

export function newKeyPair(): { secret: Uint8Array; compressed: string; xonly: string } {
  const secret = secp256k1.utils.randomSecretKey();
  const compressed = bytesToHex(secp256k1.getPublicKey(secret, true));
  return { secret, compressed, xonly: compressed.slice(2) };
}
