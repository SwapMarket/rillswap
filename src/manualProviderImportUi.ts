/** Explicit, read-only manual advertisement selection for the preview tab. */
import mainnet from "./networks/mainnet.json";
import regtest from "./networks/regtest-rillswap-e2e-v1.json";
import signet from "./networks/signet.json";
import testnet3 from "./networks/testnet3.json";
import testnet4 from "./networks/testnet4.json";
import { verifyManualProviderAdvertisement } from "./manualProviderAdvertisement";

const NETWORKS = {
  mainnet, signet, testnet3, testnet4,
  "regtest-rillswap-e2e-v1": regtest,
} as const;

function labelFor(id: string, text: string): HTMLLabelElement {
  const label = document.createElement("label");
  label.htmlFor = id;
  label.textContent = text;
  return label;
}

export function mountManualProviderImport(root: HTMLElement): void {
  const heading = document.createElement("h2");
  heading.textContent = "Manual signed provider advertisement (read-only)";
  const disclosure = document.createElement("p");
  disclosure.textContent = "Only paste PUBLIC canonical advertisement JSON. Choose the network independently and enter a provider identity verified out of band. No endpoint is contacted, no key is saved, and a valid signature proves neither liquidity nor current authority.";

  const identity = document.createElement("input");
  identity.id = "approved-provider-identity";
  identity.type = "text";
  identity.maxLength = 64;
  identity.autocomplete = "off";
  identity.spellcheck = false;
  const network = document.createElement("select");
  network.id = "approved-network";
  network.append(new Option("Select a locally defined network", ""));
  for (const key of Object.keys(NETWORKS) as (keyof typeof NETWORKS)[]) {
    network.append(new Option(key, key));
  }
  const profile = document.createElement("select");
  profile.id = "approved-profile";
  profile.append(new Option("Select a profile", ""));
  for (const value of ["btc-to-ln/v1", "ln-to-btc/v1"] as const) {
    profile.append(new Option(value, value));
  }
  const advertisement = document.createElement("textarea");
  advertisement.id = "signed-provider-advertisement";
  advertisement.maxLength = 64 * 1024;
  advertisement.placeholder = "Canonical, signed public RS-005 advertisement JSON only";
  advertisement.spellcheck = false;
  const importButton = document.createElement("button");
  importButton.type = "button";
  importButton.textContent = "Verify manual advertisement";
  const status = document.createElement("p");
  status.id = "manual-provider-status";
  status.textContent = "Nothing selected. This tab has no saved trust or revision history.";
  const details = document.createElement("pre");
  details.id = "manual-provider-details";
  // This local-only map tracks the maximum revision observed *in this tab*,
  // never global currentness. An absent entry proves nothing about the past.
  const observedRevisions = new Map<string, number>();

  importButton.addEventListener("click", () => {
    const selectedNetwork = NETWORKS[network.value as keyof typeof NETWORKS];
    if (!selectedNetwork || !identity.value ||
        (profile.value !== "btc-to-ln/v1" && profile.value !== "ln-to-btc/v1")) {
      status.textContent = "Select the complete local network and profile, and supply an independently approved provider identity.";
      return;
    }
    try {
      const candidate = verifyManualProviderAdvertisement(
        advertisement.value, identity.value, selectedNetwork, profile.value,
      );
      const revisionKey = JSON.stringify([
        candidate.identityXOnlyKey, candidate.networkIdentityJcs, candidate.slot,
      ]);
      const observed = observedRevisions.get(revisionKey);
      if (observed !== undefined && candidate.revision <= observed) {
        status.textContent = "Same or lower revision already observed in this tab. Nothing replaced; historical state outside this tab remains unknown.";
        return;
      }
      observedRevisions.set(revisionKey, candidate.revision);
      status.textContent = "Application signature verified for this explicit selection. Historical offer only; no connection, session admission, or swap action. Prior revision history is unknown.";
      details.textContent = [
        `Approved identity: ${candidate.identityXOnlyKey}`,
        `Network: ${candidate.networkIdentityJcs}`,
        `Profile: ${candidate.profileId}`,
        `Slot: ${candidate.slot}, revision: ${candidate.revision}, expiry: ${candidate.expiresAt}`,
        `Advertised endpoints (inert, not approved for contact): ${candidate.advertisedEndpoints.join(", ")}`,
        `Advertised inbox keys (not proof of possession): ${candidate.advertisedEpochInboxKeys.join(", ")}`,
      ].join("\n");
    } catch {
      status.textContent = "Advertisement refused. No provider state, endpoint approval, or action was changed.";
    }
  });
  root.append(
    heading, disclosure,
    labelFor(identity.id, "Provider identity approved out of band (x-only hex)"), identity,
    labelFor(network.id, "Independently selected network"), network,
    labelFor(profile.id, "Selected settlement profile"), profile,
    labelFor(advertisement.id, "Canonical signed public advertisement JSON"), advertisement,
    importButton, status, details,
  );
}
