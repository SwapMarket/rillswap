/**
 * Default Nostr relays for public networks and the onion relay rule. Kept free
 * of imports so the Playwright fixtures can share the exact list.
 */

/**
 * Public-network defaults: every one serves kind-1059 reads without NIP-42
 * AUTH, keeps kind-39417 announcements, and accepts Tor exits, so makers
 * behind Tor and browsers meet on the same relays. The two onion relays are
 * opportunistic: they only connect from a browser that reaches onion services
 * (Tor Browser), and their failures are not reported.
 */
export const PUBLIC_RELAYS: readonly string[] = Object.freeze([
  "wss://relay.primal.net",
  "wss://relay.snort.social",
  "wss://nostr.oxtr.dev",
  "wss://relay.ditto.pub",
  "wss://nostr.bitcoiner.social",
  "wss://nostr.azzamo.net",
  "wss://relay.angor.io",
  "wss://nostr.stakey.net",
  "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion",
  "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion",
]);

const ONION_HOST = /^[a-z2-7]{56}\.onion$/;

/** A v3 onion relay: Tor encrypts and authenticates it end to end, so plain ws:// is allowed. */
export function isOnionRelay(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === "ws:" || url.protocol === "wss:") && ONION_HOST.test(url.hostname);
  } catch { return false; }
}
