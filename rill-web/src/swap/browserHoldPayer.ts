/** One explicitly routed LND hold payment. No automatic dispatch, retry, or credential storage. */
import { hexToBytes } from "@noble/hashes/utils.js";
import canonicalize from "canonicalize";
import { decodeBolt11, invoiceBinding, type InvoiceBinding } from "./bolt11";
import { validateMempoolApi, type NetworkName } from "./config";
import { readBoundedChainText, type ChainFetch } from "./chainTip";
import { parseStrictEventJson } from "../strictEventJson";
import { isSupportedRecoveryNetwork } from "../recoveryInspection";

type ObjectValue = Record<string, unknown>;
const KEY = /^0[23][0-9a-f]{64}$/;
const MAX_MSAT = 2100000000000000000n;
const MAX_RESPONSE = 128 * 1024;
export type HoldPaymentStatus = "IN_FLIGHT" | "SUCCEEDED" | "FAILED" | "UNKNOWN";
export class BrowserHoldPaymentRefusedError extends Error {
  constructor() { super("Lightning payment unavailable or refused. Keep your backup; never retry an unknown payment."); this.name = "BrowserHoldPaymentRefusedError"; }
}
const require = (condition: boolean): void => { if (!condition) throw new BrowserHoldPaymentRefusedError(); };
const object = (value: unknown): ObjectValue => { require(value !== null && typeof value === "object" && !Array.isArray(value)); return value as ObjectValue; };
function integer(value: unknown, max = 499999999): number { require(typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max); return value as number; }
function amount(value: unknown): bigint { require(typeof value === "string" && /^(0|[1-9][0-9]{0,18})$/.test(value)); const n = BigInt(value as string); require(n <= MAX_MSAT); return n; }
const base64 = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes));
const empty = (value: unknown): boolean => value === undefined || value === null || value === "" || (Array.isArray(value) && value.length === 0) ||
  (typeof value === "object" && value !== null && Object.keys(value).length === 0);
function freeze<T>(value: T): T { if (value && typeof value === "object") { for (const child of Object.values(value)) freeze(child); Object.freeze(value); } return value; }

export interface HoldRouteLimits {
  readonly feeLimitSat: bigint;
  readonly minFinalExpiryHeight: number;
  readonly maxExpiryHeight: number;
  readonly deadlineAt: number;
}
export interface BoundedHoldPlan {
  readonly nodeIdentity: string;
  readonly networkIdentity: unknown;
  readonly paymentHash: string;
  readonly invoiceBinding: InvoiceBinding;
  readonly route: Readonly<ObjectValue>;
  readonly feeMsat: string;
  readonly limits: { readonly feeLimitSat: string; readonly minFinalExpiryHeight: number; readonly maxExpiryHeight: number; readonly deadlineAt: number };
}

function checkRoute(route: ObjectValue, binding: InvoiceBinding, limits: BoundedHoldPlan["limits"], tip: number, withSecret: boolean, secret: string): void {
  const routeFields = ["total_time_lock", "total_fees", "total_amt", "hops", "total_fees_msat", "total_amt_msat", "first_hop_amount_msat", "custom_channel_data"];
  require(Object.keys(route).every((key) => routeFields.includes(key)));
  const totalLock = integer(route.total_time_lock), fee = amount(route.total_fees_msat), total = amount(route.total_amt_msat);
  const principal = BigInt(binding.amount_msat);
  require(totalLock > tip && totalLock <= limits.maxExpiryHeight && fee <= BigInt(limits.feeLimitSat) * 1000n && total === principal + fee);
  require(amount(route.first_hop_amount_msat ?? "0") === 0n || amount(route.first_hop_amount_msat) === total);
  require(empty(route.custom_channel_data) && Array.isArray(route.hops) && route.hops.length > 0 && route.hops.length <= 20);
  let previous = totalLock;
  for (const [index, raw] of (route.hops as unknown[]).entries()) {
    const hop = object(raw), expiry = integer(hop.expiry), forward = amount(hop.amt_to_forward_msat), hopFee = amount(hop.fee_msat);
    const hopFields = ["chan_id", "chan_capacity", "amt_to_forward", "fee", "expiry", "amt_to_forward_msat", "fee_msat", "pub_key", "tlv_payload",
      "mpp_record", "amp_record", "custom_records", "metadata", "blinding_point", "encrypted_data", "total_amt_msat"];
    require(Object.keys(hop).every((key) => hopFields.includes(key)));
    require(expiry > tip && expiry <= previous && forward >= principal && hopFee <= fee && typeof hop.pub_key === "string" && KEY.test(hop.pub_key));
    require(typeof hop.chan_id === "string" && /^(0|[1-9][0-9]{0,19})$/.test(hop.chan_id) && BigInt(hop.chan_id) <= 0xffffffffffffffffn);
    for (const field of ["amp_record", "custom_records", "metadata", "blinding_point", "encrypted_data"]) require(empty(hop[field]));
    require(amount(hop.total_amt_msat ?? "0") === 0n);
    const last = index === (route.hops as unknown[]).length - 1;
    if (last) {
      require(hop.pub_key === binding.payee_compressed_pubkey && forward === principal && hopFee === 0n &&
        expiry >= tip + binding.min_final_cltv_delta && expiry >= limits.minFinalExpiryHeight);
    }
    if (withSecret && last) {
      const mpp = object(hop.mpp_record); require(Object.keys(mpp).length === 2 && mpp.payment_addr === secret && mpp.total_amt_msat === binding.amount_msat);
    } else require(empty(hop.mpp_record));
    if (withSecret) require(hop.tlv_payload === true);
    previous = expiry;
  }
}

/** Public, bounded metadata only. Not invoice authentication or present dispatch authority. */
export function validateStoredHoldPlan(plan: BoundedHoldPlan): void {
  require(Object.keys(plan).length === 7 && ["nodeIdentity", "networkIdentity", "paymentHash", "invoiceBinding", "route", "feeMsat", "limits"].every((key) => Object.hasOwn(plan, key)));
  require(KEY.test(plan.nodeIdentity) && isSupportedRecoveryNetwork(plan.networkIdentity) && /^[0-9a-f]{64}$/.test(plan.paymentHash));
  const binding = plan.invoiceBinding;
  require(Object.keys(binding).length === 7 && ["bolt11_sha256", "payment_hash", "amount_msat", "payee_compressed_pubkey", "created_at", "expires_at", "min_final_cltv_delta"].every((key) => Object.hasOwn(binding, key)));
  require(/^[0-9a-f]{64}$/.test(binding.bolt11_sha256) && binding.payment_hash === plan.paymentHash && KEY.test(binding.payee_compressed_pubkey));
  require(amount(binding.amount_msat) > 0n && amount(binding.amount_msat) % 1000n === 0n && integer(binding.created_at, Number.MAX_SAFE_INTEGER) < integer(binding.expires_at, Number.MAX_SAFE_INTEGER));
  require(integer(binding.min_final_cltv_delta) > 0);
  require(Object.keys(plan.limits).length === 4 && ["feeLimitSat", "minFinalExpiryHeight", "maxExpiryHeight", "deadlineAt"].every((key) => Object.hasOwn(plan.limits, key)));
  require(amount(plan.limits.feeLimitSat) <= MAX_MSAT / 1000n && integer(plan.limits.minFinalExpiryHeight) > 0 &&
    integer(plan.limits.maxExpiryHeight) >= plan.limits.minFinalExpiryHeight && integer(plan.limits.deadlineAt, Number.MAX_SAFE_INTEGER) > 0);
  const route = object(plan.route); require(plan.feeMsat === route.total_fees_msat && Array.isArray(route.hops));
  const mpp = object(object((route.hops as unknown[]).at(-1)).mpp_record);
  require(typeof mpp.payment_addr === "string" && atob(mpp.payment_addr).length === 32 && btoa(atob(mpp.payment_addr)) === mpp.payment_addr);
  checkRoute(route, binding, plan.limits, 0, true, mpp.payment_addr as string);
  require(canonicalize(plan)!.length <= MAX_RESPONSE);
}

export class BrowserHoldPayer {
  readonly #endpoint: string;
  readonly #macaroon: string;
  readonly #network: { readonly name: NetworkName; readonly genesis_hash: string };
  readonly #identity: string;
  readonly #fetch: ChainFetch;
  readonly #clock: () => number;
  readonly #plans = new WeakMap<BoundedHoldPlan, { readonly invoice: string; readonly secret: string }>();
  readonly #used = new WeakSet<BoundedHoldPlan>();
  /** Immutable normalized public transport metadata, never credentials. */
  get endpoint(): string { return this.#endpoint; }

  /** Construction validates only. No connection or credential persistence. */
  constructor(configuration: { readonly endpoint: string; readonly macaroon: string; readonly nodeIdentity: string;
    readonly network: { readonly name: NetworkName; readonly genesis_hash: string }; readonly fetch?: ChainFetch; readonly clock?: () => number }) {
    require(isSupportedRecoveryNetwork(configuration.network));
    require(KEY.test(configuration.nodeIdentity) && /^(?:[0-9a-f]{2}){1,4096}$/.test(configuration.macaroon));
    this.#network = freeze(structuredClone(configuration.network)); this.#identity = configuration.nodeIdentity;
    this.#endpoint = validateMempoolApi(configuration.endpoint, this.#network.name);
    this.#macaroon = configuration.macaroon; this.#fetch = (configuration.fetch ?? globalThis.fetch).bind(globalThis); this.#clock = configuration.clock ?? Date.now;
  }

  async #call(path: string, body?: unknown): Promise<unknown> {
    const signal = AbortSignal.timeout(10000);
    const response = await this.#fetch(this.#endpoint + path, { method: body === undefined ? "GET" : "POST",
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      headers: { "Grpc-Metadata-macaroon": this.#macaroon, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal });
    return parseStrictEventJson(await readBoundedChainText(response, signal, MAX_RESPONSE), MAX_RESPONSE);
  }

  async #attest(): Promise<number> {
    const info = object(await this.#call("/v1/getinfo"));
    require(info.identity_pubkey === this.#identity && info.synced_to_chain === true && Array.isArray(info.chains) && info.chains.length === 1);
    const chain = object((info.chains as unknown[])[0]);
    require(chain.chain === "bitcoin" && chain.network === this.#network.name);
    const tip = integer(info.block_height); require(tip > 0); return tip;
  }

  #current(limits: BoundedHoldPlan["limits"], binding: InvoiceBinding): void {
    require(this.#clock() < limits.deadlineAt * 1000 && this.#clock() < binding.expires_at * 1000);
  }

  async plan(invoice: string, expectedBinding: InvoiceBinding, limits: HoldRouteLimits): Promise<BoundedHoldPlan> {
    try {
      const binding = invoiceBinding(invoice, this.#network.name), decoded = decodeBolt11(invoice);
      require(canonicalize(binding) === canonicalize(expectedBinding) && decoded.paymentSecret !== null && BigInt(binding.amount_msat) % 1000n === 0n);
      const bounds = freeze({ feeLimitSat: limits.feeLimitSat.toString(), minFinalExpiryHeight: integer(limits.minFinalExpiryHeight),
        maxExpiryHeight: integer(limits.maxExpiryHeight), deadlineAt: integer(limits.deadlineAt, Number.MAX_SAFE_INTEGER) });
      require(limits.feeLimitSat >= 0n && limits.feeLimitSat * 1000n <= MAX_MSAT && bounds.maxExpiryHeight >= bounds.minFinalExpiryHeight);
      this.#current(bounds, binding);
      const remote = object(await this.#call(`/v1/payreq/${encodeURIComponent(invoice)}`));
      require(remote.payment_hash === binding.payment_hash && remote.destination === binding.payee_compressed_pubkey &&
        amount(remote.num_msat) === BigInt(binding.amount_msat) && amount(remote.timestamp) === BigInt(binding.created_at) &&
        amount(remote.expiry) === BigInt(binding.expires_at - binding.created_at) && amount(remote.cltv_expiry) === BigInt(binding.min_final_cltv_delta) && empty(remote.blinded_paths));
      const secret = base64(hexToBytes(decoded.paymentSecret!)); require(remote.payment_addr === secret);
      const features = object(remote.features), bits = Object.keys(features);
      require(bits.every((bit) => /^(8|9|14|15|17|25)$/.test(bit)) && [8, 9].filter((bit) => bits.includes(String(bit))).length === 1 &&
        [14, 15].filter((bit) => bits.includes(String(bit))).length === 1 && bits.length === decoded.features.size && bits.every((bit) => decoded.features.has(Number(bit))));
      require(remote.route_hints === undefined || (Array.isArray(remote.route_hints) && remote.route_hints.length <= 20));
      const tip = await this.#attest(); require(bounds.maxExpiryHeight > tip);
      const response = object(await this.#call(`/v1/graph/routes/${binding.payee_compressed_pubkey}/${BigInt(binding.amount_msat) / 1000n}`, {
        final_cltv_delta: binding.min_final_cltv_delta + 3, fee_limit: { fixed_msat: (BigInt(bounds.feeLimitSat) * 1000n).toString() },
        cltv_limit: bounds.maxExpiryHeight - tip, route_hints: remote.route_hints ?? [], dest_features: bits.map(Number),
      }));
      require(Array.isArray(response.routes) && response.routes.length === 1);
      const route = structuredClone(object((response.routes as unknown[])[0]));
      checkRoute(route, binding, bounds, tip, false, secret);
      for (const raw of route.hops as unknown[]) object(raw).tlv_payload = true;
      object((route.hops as unknown[]).at(-1)).mpp_record = { payment_addr: secret, total_amt_msat: binding.amount_msat };
      const plan = freeze({ nodeIdentity: this.#identity, networkIdentity: this.#network, paymentHash: binding.payment_hash,
        invoiceBinding: binding, route, feeMsat: route.total_fees_msat as string, limits: bounds });
      validateStoredHoldPlan(plan);
      this.#plans.set(plan, { invoice, secret }); this.#current(bounds, binding); return plan;
    } catch { throw new BrowserHoldPaymentRefusedError(); }
  }

  /** authorize must durably elect this invocation before dispatch. Failure grants no permission. */
  async pay(plan: BoundedHoldPlan, authorize: () => Promise<void>, assertCurrent: () => void): Promise<HoldPaymentStatus> {
    try {
      const privatePlan = this.#plans.get(plan); require(privatePlan !== undefined && !this.#used.has(plan));
      this.#used.add(plan); // Failure never makes this prepared object repayable.
      assertCurrent(); this.#current(plan.limits, plan.invoiceBinding);
      const tip = await this.#attest();
      checkRoute(plan.route as ObjectValue, plan.invoiceBinding, plan.limits, tip, true, privatePlan!.secret);
      assertCurrent(); this.#current(plan.limits, plan.invoiceBinding);
      await authorize();
      // Authorization can suspend. Recheck admission, never reset the durable marker.
      const currentTip = await this.#attest();
      checkRoute(plan.route as ObjectValue, plan.invoiceBinding, plan.limits, currentTip, true, privatePlan!.secret);
      assertCurrent(); this.#current(plan.limits, plan.invoiceBinding);
      const signal = AbortSignal.timeout(60000);
      const submission = this.#fetch(`${this.#endpoint}/v2/router/route/send`, { method: "POST",
        body: JSON.stringify({ payment_hash: base64(hexToBytes(plan.paymentHash)), route: plan.route, skip_temp_err: false }),
        headers: { "Grpc-Metadata-macaroon": this.#macaroon, "Content-Type": "application/json" },
        credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal })
        .then(async (response) => object(parseStrictEventJson(await readBoundedChainText(response, signal, MAX_RESPONSE), MAX_RESPONSE)).status)
        .then((status) => status === "FAILED" ? "FAILED" as const : "UNKNOWN" as const).catch(() => "UNKNOWN" as const);
      const until = Math.min(this.#clock() + 15000, plan.limits.deadlineAt * 1000);
      while (this.#clock() < until) {
        const status = await this.status(plan.paymentHash, plan.invoiceBinding.amount_msat);
        if (status !== "UNKNOWN") return status;
        const ended = await Promise.race([submission, new Promise<"PENDING">((resolve) => setTimeout(() => resolve("PENDING"), 300))]);
        if (ended === "FAILED") return "FAILED";
        if (ended === "UNKNOWN") await new Promise<void>((resolve) => setTimeout(resolve, 300));
      }
      return "UNKNOWN";
    } catch { throw new BrowserHoldPaymentRefusedError(); }
  }

  /** Read one bounded stream frame. Never dispatches, resumes, or repays. */
  async status(hash: string, expectedAmountMsat: string): Promise<HoldPaymentStatus> {
    try {
      require(/^[0-9a-f]{64}$/.test(hash)); amount(expectedAmountMsat);
      const tip = await this.#attest(); require(tip > 0);
      const signal = AbortSignal.timeout(5000);
      const response = await this.#fetch(`${this.#endpoint}/v2/router/track/${base64(hexToBytes(hash)).replaceAll("+", "-").replaceAll("/", "_")}?no_inflight_updates=false`,
        { headers: { "Grpc-Metadata-macaroon": this.#macaroon }, signal, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
      require(response.ok && response.body !== null);
      const reader = response.body!.getReader(), decoder = new TextDecoder("utf-8", { fatal: true }); let text = "", size = 0;
      const abort = (): void => { void reader.cancel().catch(() => {}); }; signal.addEventListener("abort", abort, { once: true });
      try {
        while (!text.includes("\n")) { signal.throwIfAborted(); const next = await reader.read(); signal.throwIfAborted();
          if (next.done) break; size += next.value.length; require(size <= MAX_RESPONSE); text += decoder.decode(next.value, { stream: true }); }
        text += decoder.decode();
        const frame = object(parseStrictEventJson(text.split("\n")[0]!, MAX_RESPONSE)); require(frame.error === undefined);
        const payment = object(frame.result); require(payment.payment_hash === hash && amount(payment.value_msat) === BigInt(expectedAmountMsat));
        if (payment.status === "IN_FLIGHT" || payment.status === "SUCCEEDED" || payment.status === "FAILED") return payment.status;
      } finally { signal.removeEventListener("abort", abort); await reader.cancel().catch(() => {}); reader.releaseLock(); }
    } catch { /* Node/network/parse failure is not evidence that a payment was never submitted. */ }
    return "UNKNOWN";
  }
}
