import { MAX_MSAT } from "./contract";

/** Trusted transport owns DNS/egress and must honor abort through body reads.
 * Descriptor callbacks can contain sensitive capabilities; never log them.
 */
export type LnurlPayTransport = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
export interface LnurlPayDescriptor {
  readonly version: "lnurl-pay-request/1";
  readonly lightningAddress: string;
  readonly receiverOrigin: string;
  readonly callback: string;
  readonly metadata: string;
  readonly description: string;
  readonly minSendableMsat: string;
  readonly maxSendableMsat: string;
}
function publicDns(host: string): boolean {
  return host.length <= 253 && /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(host) &&
    !/\.(local|localhost|localdomain|onion)$/.test(host);
}
function approvedUrl(value: string, origins: ReadonlySet<string>): URL {
  if (typeof value !== "string" || value.length > 4096 || /[\u0000-\u0020\u007f\\]/.test(value)) throw new Error("Unsupported LNURL endpoint");
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("Unsupported LNURL endpoint"); }
  if (url.protocol !== "https:" || url.username || url.password || url.href.includes("#") || url.port || !publicDns(url.hostname) || !origins.has(url.origin)) throw new Error("Unapproved LNURL endpoint");
  return url;
}
function parseUnambiguousJson(text: string): unknown {
  const parsed: unknown = JSON.parse(text);
  // Grammar is already checked. Consume whole escaped strings so punctuation
  // inside values is never interpreted as object structure. Decode key tokens
  // to catch escaped aliases, including nested extension values.
  const containers: (Set<string> | null)[] = [];
  for (const match of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]]/g)) {
    const token = match[0];
    if (token === "{") containers.push(new Set());
    else if (token === "[") containers.push(null);
    else if (token === "}" || token === "]") containers.pop();
    else {
      let next = match.index! + token.length;
      while (next < text.length && /[ \t\r\n]/.test(text[next]!)) next++;
      if (text[next] === ":") {
        const keys = containers.at(-1);
        const key: string = JSON.parse(token);
        if (!keys || keys.has(key)) throw new Error("Ambiguous LNURL JSON");
        keys.add(key);
      }
    }
  }
  return parsed;
}
function wellFormedText(value: string): boolean {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(new TextEncoder().encode(value)) === value;
}
async function boundedBody(response: Response, signal: AbortSignal): Promise<string> {
  if (!response.body) throw new Error("Missing LNURL body");
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let length = 0;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      if (signal.aborted) throw new Error("LNURL read expired");
      const part = await reader.read();
      if (signal.aborted) throw new Error("LNURL read expired");
      if (part.done) break;
      length += part.value.length;
      if (length > 65536) throw new Error("LNURL response exceeds limit");
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel(); // Do not wait for an unbounded underlying cancellation hook.
    reader.releaseLock();
  }
}
/** One explicitly authorized discovery GET. Never calls the invoice callback,
 * retries, enables payment, or establishes payee/order/receipt authority.
 */
export async function discoverLightningAddress(lightningAddress: string, approvedOrigins: readonly string[], transport?: LnurlPayTransport): Promise<Readonly<LnurlPayDescriptor>> {
  if (typeof lightningAddress !== "string" || !Array.isArray(approvedOrigins) || approvedOrigins.length === 0 || approvedOrigins.length > 32) throw new Error("Invalid LNURL discovery policy");
  const match = /^([a-z0-9][a-z0-9._+-]{0,63})@([^@]+)$/.exec(lightningAddress);
  if (!match || !publicDns(match[2]!)) throw new Error("Unsupported Lightning Address profile");
  const origins = new Set<string>();
  for (const origin of approvedOrigins) {
    if (typeof origin !== "string") throw new Error("Invalid approved LNURL origin");
    let url: URL;
    try { url = new URL(origin); } catch { throw new Error("Invalid approved LNURL origin"); }
    if (url.origin !== origin || url.protocol !== "https:" || url.username || url.password || url.port || !publicDns(url.hostname)) throw new Error("Invalid approved LNURL origin");
    origins.add(origin);
  }
  const url = approvedUrl(`https://${match[2]}/.well-known/lnurlp/${encodeURIComponent(match[1]!)}`, origins);
  const explicitlyTrusted = transport !== undefined;
  if (transport === undefined) {
    if (typeof window === "undefined" || typeof document === "undefined") throw new Error("LNURL discovery requires an explicitly trusted server transport");
    transport = globalThis.fetch.bind(globalThis);
  }
  if (typeof transport !== "function") throw new Error("Invalid LNURL transport");
  const signal = AbortSignal.timeout(10000);
  try {
    const response = await transport(url.href, { method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal, headers: { Accept: "application/json" } });
    if (!response.ok || response.redirected || (!response.url && !explicitlyTrusted) || (response.url && new URL(response.url).href !== url.href) || response.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
      void response.body?.cancel().catch(() => {});
      throw new Error("LNURL response refused");
    }
    const text = await boundedBody(response, signal);
    if (signal.aborted) throw new Error("LNURL read expired");
    const data = parseUnambiguousJson(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid LNURL pay request");
    const value = data as Record<string, unknown>;
    if (value.status === "ERROR" || value.tag !== "payRequest" || typeof value.callback !== "string" || typeof value.metadata !== "string" ||
        !Number.isSafeInteger(value.minSendable) || !Number.isSafeInteger(value.maxSendable)) throw new Error("Invalid LNURL pay request");
    const minimum = value.minSendable as number, maximum = value.maxSendable as number;
    if (minimum < 1 || maximum < minimum || BigInt(maximum) > MAX_MSAT) throw new Error("Unsupported LNURL amount range");
    if (value.metadata.length > 16384) throw new Error("LNURL metadata too large");
    const metadataBytes = new TextEncoder().encode(value.metadata);
    if (metadataBytes.length > 16384 || new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(metadataBytes) !== value.metadata) throw new Error("Unsupported LNURL metadata UTF-8");
    const metadata = parseUnambiguousJson(value.metadata);
    if (!Array.isArray(metadata) || !metadata.every((entry) => Array.isArray(entry) && entry.length === 2 && typeof entry[0] === "string")) throw new Error("Invalid LNURL metadata");
    const plain = metadata.filter((entry) => entry[0] === "text/plain"), identities = metadata.filter((entry) => entry[0] === "text/identifier" || entry[0] === "text/email");
    if (plain.length !== 1 || typeof plain[0][1] !== "string" || !wellFormedText(plain[0][1]) || identities.length === 0 || identities.some((entry) => typeof entry[1] !== "string" || entry[1].length === 0 || !wellFormedText(entry[1]))) throw new Error("Unsupported LNURL metadata profile");
    const callback = approvedUrl(value.callback, origins);
    if (callback.searchParams.has("amount")) throw new Error("LNURL callback already binds an amount");
    return Object.freeze({ version: "lnurl-pay-request/1", lightningAddress, receiverOrigin: url.origin,
      callback: callback.href, metadata: value.metadata, description: plain[0][1], minSendableMsat: minimum.toString(), maxSendableMsat: maximum.toString() });
  } catch {
    throw new Error("LNURL discovery is unresolved");
  }
}
