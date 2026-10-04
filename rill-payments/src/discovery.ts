export interface ProviderCatalogProbe {
  readonly provider: "atomiq" | "boltz";
  readonly endpoint: string;
  readonly checkedAt: number;
  readonly state: "unreachable" | "http_error" | "invalid_catalog" | "unverified_catalog";
  readonly httpStatus: number | null;
  readonly executable: false;
  readonly requiredEvidence: readonly ["deployment_verification", "directional_executable_quote", "wallet_and_recovery_conformance"];
}
const ENDPOINTS: readonly { provider: ProviderCatalogProbe["provider"]; endpoint: string }[] = [
  { provider: "atomiq", endpoint: "https://mainnet.swaps-api.atomiq.exchange/getSwapCounterTokens?token=LIGHTNING-BTC&side=OUTPUT" },
  { provider: "atomiq", endpoint: "https://mainnet.swaps-api.atomiq.exchange/getSwapLimits?srcToken=SOLANA-USDC&dstToken=LIGHTNING-BTC" },
  { provider: "boltz", endpoint: "https://api.boltz.exchange/v2/swap/submarine" },
  { provider: "boltz", endpoint: "https://api.boltz.exchange/v2/chain/contracts" },
];

/** Explicit read-only reachability probe, not trusted discovery or route admission. No URL input, swap creation or SDK init. */
export async function probeExternalProviders(
  request: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> = fetch,
  now: () => number = () => Math.floor(Date.now() / 1000),
): Promise<ProviderCatalogProbe[]> {
  return Promise.all(ENDPOINTS.map(async ({ provider, endpoint }): Promise<ProviderCatalogProbe> => {
    const checkedAt = now(); if (!Number.isSafeInteger(checkedAt) || checkedAt < 0) throw new Error("Invalid discovery clock");
    const base = { provider, endpoint, checkedAt, executable: false as const,
      requiredEvidence: ["deployment_verification", "directional_executable_quote", "wallet_and_recovery_conformance"] as const };
    try {
      const response = await request(endpoint, { method: "GET", redirect: "error", signal: AbortSignal.timeout(10000), cache: "no-store", credentials: "omit" });
      if (!response.ok) { await response.body?.cancel(); return { ...base, state: "http_error", httpStatus: response.status }; }
      if (!response.headers.get("Content-Type")?.toLowerCase().includes("application/json") || !response.body) {
        await response.body?.cancel(); return { ...base, state: "invalid_catalog", httpStatus: response.status };
      }
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let length = 0;
      while (true) { const part = await reader.read(); if (part.done) break; length += part.value.length;
        if (length > 262144) { await reader.cancel(); return { ...base, state: "invalid_catalog", httpStatus: response.status }; } chunks.push(part.value); }
      const bytes = new Uint8Array(length); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
      try {
        const catalog: unknown = JSON.parse(new TextDecoder().decode(bytes));
        if (!catalog || typeof catalog !== "object") throw new Error();
        // Catalog schema and contract identities are not independently established.
        // A 200 response must not accidentally create an execution capability.
        return { ...base, state: "unverified_catalog", httpStatus: response.status };
      } catch { return { ...base, state: "invalid_catalog", httpStatus: response.status }; }
    } catch { return { ...base, state: "unreachable", httpStatus: null }; }
  }));
}
