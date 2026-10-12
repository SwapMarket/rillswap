/**
 * A swap's address: the page URL whose fragment carries the latest encrypted
 * recovery container. Fragments never reach a server, so the link can be
 * bookmarked or revisited from history and reopened with the recovery key.
 * The ciphertext is opaque here; only its owner's key reveals anything.
 */
import { MAX_RECOVERY_CIPHERTEXT_BYTES } from "./recoveryAgeContainer";

export interface SwapLink {
  readonly file: Uint8Array;
  readonly network: string;
}

const NETWORK = /^[a-z0-9-]{1,32}$/;

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const padded = text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - text.length % 4) % 4);
  try { return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0)); } catch { return null; }
}

/** Fragment (with the leading `#`) that addresses this swap record. */
export function swapLinkFragment(link: SwapLink): string {
  if (!NETWORK.test(link.network)) throw new Error("Network name invalid");
  if (link.file.length === 0 || link.file.length > MAX_RECOVERY_CIPHERTEXT_BYTES) throw new Error("Recovery container size invalid");
  return `#swap=${base64url(link.file)}&network=${link.network}`;
}

/** Null when the fragment carries no usable swap record; malformed values are ignored, never partially used. */
export function parseSwapLink(hash: string): SwapLink | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const encoded = params.get("swap"), network = params.get("network") ?? "";
  if (encoded === null || !NETWORK.test(network)) return null;
  const file = fromBase64url(encoded);
  if (!file || file.length === 0 || file.length > MAX_RECOVERY_CIPHERTEXT_BYTES) return null;
  return { file, network };
}
