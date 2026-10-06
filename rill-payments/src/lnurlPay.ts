import { MAX_MSAT } from "./contract";
import { INVOICE_CURRENCY, invoiceBinding, invoiceMetadataBinding, type InvoiceBinding } from "./bolt11";

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
export interface LnurlInvoiceExpectation {
  readonly networkName: string;
  readonly amountMsat: string;
  readonly payee: string;
  readonly now: number;
  readonly minExpiresAt: number;
  readonly metadataHashPolicy: "not_required" | "strict_hash";
}
export interface LnurlPayInvoice {
  readonly invoice: string;
  readonly binding: Readonly<InvoiceBinding>;
  readonly metadataHashPolicy: LnurlInvoiceExpectation["metadataHashPolicy"];
}
export class LnurlInvoiceAcquisitionError extends Error {
  readonly state: "not_requested" | "issuance_unknown";
  constructor(state: "not_requested" | "issuance_unknown") {
    super(state === "not_requested" ? "LNURL invoice request was not invoked" : "LNURL invoice issuance is unknown");
    this.name = "LnurlInvoiceAcquisitionError";
    this.state = state;
  }
}
function approvedOriginSet(approvedOrigins: readonly string[]): ReadonlySet<string> {
  if (!Array.isArray(approvedOrigins) || approvedOrigins.length === 0 || approvedOrigins.length > 32) throw new Error("Invalid LNURL discovery policy");
  const origins = new Set<string>();
  for (const origin of approvedOrigins) {
    if (typeof origin !== "string") throw new Error("Invalid approved LNURL origin");
    let url: URL;
    try { url = new URL(origin); } catch { throw new Error("Invalid approved LNURL origin"); }
    if (url.origin !== origin || url.protocol !== "https:" || url.username || url.password || url.port || !publicDns(url.hostname)) throw new Error("Invalid approved LNURL origin");
    origins.add(origin);
  }
  return origins;
}
function trustedTransport(transport?: LnurlPayTransport) {
  const explicitlyTrusted = transport !== undefined;
  if (transport === undefined) {
    if (typeof window === "undefined" || typeof document === "undefined") throw new Error("LNURL discovery requires an explicitly trusted server transport");
    transport = globalThis.fetch.bind(globalThis);
  }
  if (typeof transport !== "function") throw new Error("Invalid LNURL transport");
  return { transport, explicitlyTrusted };
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
async function readJson(url: URL, selected: ReturnType<typeof trustedTransport>, signal: AbortSignal): Promise<unknown> {
  const response = await selected.transport(url.href, { method: "GET", redirect: "error", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal, headers: { Accept: "application/json" } });
  if (!response.ok || response.redirected || (!response.url && !selected.explicitlyTrusted) || (response.url && new URL(response.url).href !== url.href) || response.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") {
    void response.body?.cancel().catch(() => {});
    throw new Error("LNURL response refused");
  }
  const text = await boundedBody(response, signal);
  if (signal.aborted) throw new Error("LNURL read expired");
  return parseUnambiguousJson(text);
}
/** One explicitly authorized discovery GET. Never calls the invoice callback,
 * retries, enables payment, or establishes payee/order/receipt authority.
 */
export async function discoverLightningAddress(lightningAddress: string, approvedOrigins: readonly string[], transport?: LnurlPayTransport): Promise<Readonly<LnurlPayDescriptor>> {
  if (typeof lightningAddress !== "string" || !Array.isArray(approvedOrigins) || approvedOrigins.length === 0 || approvedOrigins.length > 32) throw new Error("Invalid LNURL discovery policy");
  const match = /^([a-z0-9][a-z0-9._+-]{0,63})@([^@]+)$/.exec(lightningAddress);
  if (!match || !publicDns(match[2]!)) throw new Error("Unsupported Lightning Address profile");
  const origins = approvedOriginSet(approvedOrigins);
  const url = approvedUrl(`https://${match[2]}/.well-known/lnurlp/${encodeURIComponent(match[1]!)}`, origins);
  const selected = trustedTransport(transport);
  const signal = AbortSignal.timeout(10000);
  try {
    const data = await readJson(url, selected, signal);
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

function positiveMsat(value: unknown): bigint {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value) || BigInt(value) > MAX_MSAT) throw new Error("Invalid LNURL amount");
  return BigInt(value);
}
function snapshotExpectation(expected: Omit<LnurlInvoiceExpectation, "now">, now: number): LnurlInvoiceExpectation {
  return { networkName: expected.networkName, amountMsat: expected.amountMsat, payee: expected.payee,
    now, minExpiresAt: expected.minExpiresAt, metadataHashPolicy: expected.metadataHashPolicy };
}
function invoiceContext(descriptor: LnurlPayDescriptor, expected: LnurlInvoiceExpectation) {
  if (!descriptor || !expected) throw new Error("Missing LNURL invoice context");
  // Capture only consumed scalar facts, not extension values or changing
  // getter-backed policies. No caller-owned records survive in the result.
  expected = snapshotExpectation(expected, expected.now);
  const facts = { version: descriptor.version, metadata: descriptor.metadata, minSendableMsat: descriptor.minSendableMsat, maxSendableMsat: descriptor.maxSendableMsat };
  if (facts.version !== "lnurl-pay-request/1" ||
      typeof expected.networkName !== "string" || !Object.hasOwn(INVOICE_CURRENCY, expected.networkName) ||
      typeof expected.payee !== "string" || !/^(02|03)[0-9a-f]{64}$/.test(expected.payee) ||
      !Number.isSafeInteger(expected.now) || expected.now < 0 || !Number.isSafeInteger(expected.minExpiresAt) || expected.minExpiresAt <= expected.now ||
      (expected.metadataHashPolicy !== "not_required" && expected.metadataHashPolicy !== "strict_hash")) throw new Error("Invalid LNURL invoice expectations");
  const amount = positiveMsat(expected.amountMsat), minimum = positiveMsat(facts.minSendableMsat), maximum = positiveMsat(facts.maxSendableMsat);
  if (minimum > maximum || maximum > BigInt(Number.MAX_SAFE_INTEGER) || amount % 1000n !== 0n || amount < minimum || amount > maximum ||
      typeof facts.metadata !== "string" || facts.metadata.length > 16384 || new TextEncoder().encode(facts.metadata).length > 16384 || !wellFormedText(facts.metadata)) throw new Error("LNURL invoice exceeds descriptor profile");
  return { facts, expected, amount };
}
/** Authenticate supplied invoice contents against independent trusted pins.
 * No request, issuance recovery, order authorization, payment or acceptance.
 * BOLT11 cannot distinguish testnet3/testnet4 (both use currency `tb`).
 */
export function validateLnurlPayInvoice(descriptor: LnurlPayDescriptor, response: unknown, expected: LnurlInvoiceExpectation): Readonly<LnurlPayInvoice> {
  try {
    const context = invoiceContext(descriptor, expected);
    const { facts, amount } = context; expected = context.expected;
    if (!response || typeof response !== "object" || Array.isArray(response)) throw new Error("Invalid LNURL invoice response");
    const data = response as Record<string, unknown>, invoice = data.pr, routes = data.routes;
    if (data.status === "ERROR" || typeof invoice !== "string" || !Array.isArray(routes) || routes.length !== 0) throw new Error("Unsupported LNURL invoice response");
    const binding = expected.metadataHashPolicy === "strict_hash" ? invoiceMetadataBinding(invoice, expected.networkName, facts.metadata) : invoiceBinding(invoice, expected.networkName);
    if (binding.amount_msat !== amount.toString() || binding.payee_compressed_pubkey !== expected.payee || binding.created_at > expected.now ||
        binding.expires_at <= expected.now || binding.expires_at < expected.minExpiresAt) throw new Error("LNURL invoice differs from trusted expectations");
    // Never read or retain verify/successAction or other extension values.
    return Object.freeze({ invoice, binding: Object.freeze(binding), metadataHashPolicy: expected.metadataHashPolicy });
  } catch {
    throw new Error("LNURL invoice response is unresolved");
  }
}

/** Explicit remote invoice acquisition, one transport invocation per call.
 * Every failure after invocation leaves issuance unknown, never retry rights.
 * NOT a recoverable InvoiceIssuer or an order-deadline/funding authorization.
 */
export async function requestLnurlPayInvoice(descriptor: LnurlPayDescriptor, expected: Omit<LnurlInvoiceExpectation, "now">,
  approvedOrigins: readonly string[], clock: () => number, transport?: LnurlPayTransport): Promise<Readonly<LnurlPayInvoice>> {
  let invoked = false;
  try {
    if (!descriptor || !expected || typeof clock !== "function") throw new Error("Missing LNURL request context");
    // Snapshot all consumed policy before invoking external code or awaiting.
    const pinned = snapshotExpectation(expected, 0);
    const captured = { version: descriptor.version, metadata: descriptor.metadata,
      minSendableMsat: descriptor.minSendableMsat, maxSendableMsat: descriptor.maxSendableMsat,
      callback: descriptor.callback, receiverOrigin: descriptor.receiverOrigin };
    const origins = approvedOriginSet(approvedOrigins);
    const receiver = approvedUrl(captured.receiverOrigin, origins);
    if (receiver.origin !== captured.receiverOrigin) throw new Error("Invalid LNURL receiver origin");
    const callback = approvedUrl(captured.callback, origins);
    if (callback.searchParams.has("amount")) throw new Error("LNURL callback already binds an amount");
    const selected = trustedTransport(transport);
    const startedAt = clock();
    const context = invoiceContext(captured as LnurlPayDescriptor, { ...pinned, now: startedAt });
    // Never reserialize opaque capability query bytes through URLSearchParams.
    // The original amount key has already been refused, including aliases.
    callback.search = (callback.search ? callback.search + "&" : "?") + "amount=" + context.amount.toString();
    const signal = AbortSignal.timeout(10000);
    if (signal.aborted) throw new Error("LNURL request expired before invocation");
    const elapsedStart = performance.now();
    if (!Number.isFinite(elapsedStart)) throw new Error("Invalid LNURL elapsed clock");
    invoked = true;
    const response = await readJson(callback, selected, signal);
    const completedAt = clock();
    if (!Number.isSafeInteger(completedAt) || completedAt < startedAt || signal.aborted) throw new Error("LNURL acquisition clock or budget invalid");
    const result = validateLnurlPayInvoice(captured as LnurlPayDescriptor, response, { ...context.expected, now: completedAt });
    const elapsedEnd = performance.now();
    if (!Number.isFinite(elapsedEnd) || elapsedEnd < elapsedStart || elapsedEnd - elapsedStart >= 10000 || signal.aborted) throw new Error("LNURL acquisition exceeded elapsed budget");
    return result;
  } catch {
    throw new LnurlInvoiceAcquisitionError(invoked ? "issuance_unknown" : "not_requested");
  }
}
