/** Explicit reload/import recovery. No payment or acceptance API; claim POST is one-shot. */
import canonicalize from "canonicalize";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { identityToRecipient } from "age-encryption";
import { BrowserReverseJournal, type ReverseJournalRecord, type ImportedClaimRecord } from "./browserReverseJournal";
import { decryptRecoveryContainer, parseRecoveryIdentity } from "./recoveryKeys";
import { parseRecoveryPlaintext } from "./recoveryDocument";
import { encryptCanonicalRecoveryForRecipient } from "./recoveryAgeContainer";
import { inspectReverseRecoveryPlaintext, constructSelectedReverseClaim, appendReverseClaimFallback, checkSelectedReverseFundingTransaction,
  REVERSE_FALLBACK_EXTENSION, type RecoveryFundingBinding } from "./recoveryInspection";
import { observeReverseRecoveryFunding } from "./recoveryFunding";
import { restoreReverseFundingReader, type Envelope } from "./swap/session";
import { recoverReverseFundingEnvelopes } from "./swap/reverseFundingArchive";
import { RelayConnection } from "./swap/relay";
import { requireShape, type LnToBtcTerms } from "./swap/wire";
import { validateRelays, validateMempoolApi, type NetworkName } from "./swap/config";
import { parseTransaction } from "./swap/transaction";
import { fundingBindingHash } from "./swap/hashes";
import { readBoundedChainText } from "./swap/chainTip";

type Network = { readonly name: NetworkName; readonly genesis_hash: string };
const require = (value: boolean): void => { if (!value) throw new Error("Reverse recovery remains blocked. Preserve backups; no payment or claim is automatically retried."); };
const bytes = (value: unknown): Uint8Array => new TextEncoder().encode(canonicalize(value)!);
type ClaimOwner = ReverseJournalRecord | ImportedClaimRecord;
interface Loaded { record: ClaimOwner; plaintext: Uint8Array; journal: BrowserReverseJournal; identity: string }
const ciphertextOf = (record: ClaimOwner): Uint8Array => hexToBytes("kind" in record ? (record.fallback ?? record.funded).ciphertextHex : record.snapshots.at(-1)!.ciphertextHex);
function withoutFallback(plaintext: Uint8Array): Uint8Array {
  const doc = parseRecoveryPlaintext(plaintext).document, extensions = { ...doc.extensions as Record<string, unknown> }; delete extensions[REVERSE_FALLBACK_EXTENSION];
  return bytes({ ...doc, extensions });
}

async function load(original: Uint8Array, identity: string, network: Network): Promise<Loaded> {
  identity = await parseRecoveryIdentity(identity);
  const imported = inspectReverseRecoveryPlaintext(original, network), source = parseRecoveryPlaintext(original).document;
  const context = source.verification_context as { handshake_init: { session_id: string } };
  const journal = await BrowserReverseJournal.open(); let plaintext: Uint8Array | undefined;
  try {
    const binding = imported.fundingHistory.at(-1);
    let record: ClaimOwner | undefined = binding ? await journal.claimOwner(network, binding.funding_txid, binding.contract_vout) : undefined;
    record ??= await journal.get(network, context.handshake_init.session_id); require(record !== undefined);
    plaintext = await decryptRecoveryContainer(ciphertextOf(record!), identity);
    // An original terms backup can find the funded execution's elected imported owner too.
    const recordedBinding = inspectReverseRecoveryPlaintext(plaintext, network).fundingHistory.at(-1);
    if (recordedBinding) {
      const elected = await journal.claimOwner(network, recordedBinding.funding_txid, recordedBinding.contract_vout);
      if (elected && elected.id !== record!.id) { plaintext.fill(0); record = elected; plaintext = await decryptRecoveryContainer(ciphertextOf(record), identity); }
    }
    const report = inspectReverseRecoveryPlaintext(plaintext, network), doc = parseRecoveryPlaintext(plaintext).document;
    require(report.contractHash === imported.contractHash);
    if ("kind" in record!) {
      const owner = record as ImportedClaimRecord, funded = withoutFallback(plaintext);
      try { require(bytesToHex(sha256(funded)) === owner.draft.fundedPlaintextDigest && canonicalize(owner.draft.networkIdentity) === canonicalize(network)); } finally { funded.fill(0); }
      const predecessor = await decryptRecoveryContainer(hexToBytes(owner.funded.ciphertextHex), identity);
      try { inspectReverseRecoveryPlaintext(predecessor, network); require(bytesToHex(sha256(predecessor)) === owner.draft.fundedPlaintextDigest); } finally { predecessor.fill(0); }
      const selected = report.fundingHistory.at(-1)!; require(selected.funding_txid === owner.draft.fundingTxid && selected.contract_vout === owner.draft.fundingVout && bytesToHex(fundingBindingHash(selected)) === owner.draft.bindingHash);
    } else {
      const verified = doc.verification_context as Record<string, unknown>, terms = doc.contract_terms as unknown as LnToBtcTerms, c = (record as ReverseJournalRecord).context;
      require(canonicalize(c.networkIdentity) === canonicalize(network) && verified.client_session_xonly_key === c.clientSessionKey && verified.provider_session_xonly_key === c.providerSessionKey && terms.provider_identity_key === c.providerIdentity &&
        terms.invoice_binding.payment_hash === c.request.payment_hash && terms.client_contract_compressed_key === c.request.client_contract_compressed_key &&
        terms.recovery_authorization_xonly_key === c.request.recovery_authorization_xonly_key && terms.client_destination_script === c.request.client_destination_script && terms.economics.nominal_payout_sat === c.request.nominal_payout_sat);
    }
    if (record!.claim) {
      const selectedFallback = (doc.extensions as Record<string, unknown>)[REVERSE_FALLBACK_EXTENSION] as { transaction: string };
      require(report.fallbackTxid === record!.claim!.txid && bytesToHex(sha256(hexToBytes(selectedFallback.transaction))) === record!.claim!.signedDigest);
    }
    return { record: record!, plaintext, journal, identity };
  } catch { plaintext?.fill(0); journal.close(); throw new Error("Matching local execution history is unavailable. Recovery cannot create payment authority from an imported file."); }
}

/** Read current encrypted origin-local evidence, never resume a side effect. */
export async function loadBrowserReverseRecovery(original: Uint8Array, identity: string, network: Network): Promise<{ readonly stage: string; readonly ciphertext: Uint8Array; readonly claimTxid: string | null; readonly claimFeeSat: string | null }> {
  const loaded = await load(original, identity, structuredClone(network));
  try { const report = inspectReverseRecoveryPlaintext(loaded.plaintext, network);
    return Object.freeze({ stage: loaded.record.stage, ciphertext: ciphertextOf(loaded.record), claimTxid: report.fallbackTxid, claimFeeSat: report.fallbackFeeSat }); }
  finally { loaded.plaintext.fill(0); loaded.journal.close(); }
}

/** Recover only retained signed funding for an existing UNKNOWN attempt. No new session or relay publication. */
export async function recoverBrowserReverseFunding(original: Uint8Array, identity: string, network: Network, urls: readonly string[], assertCurrent: () => void): Promise<Uint8Array> {
  network = structuredClone(network); urls = validateRelays(urls.join("\n"), network.name);
  const loaded = await load(original, identity, network), connections: RelayConnection[] = []; let receiver: ReturnType<typeof restoreReverseFundingReader> | undefined;
  try {
    assertCurrent(); require(loaded.record.stage === "payment-unknown" && !("kind" in loaded.record));
    const doc = parseRecoveryPlaintext(loaded.plaintext).document, extensions = doc.extensions as Record<string, unknown>, metadata = extensions["rillswap/browser-reverse-session"] as Record<string, unknown>;
    require(metadata !== null && typeof metadata === "object" && Object.keys(metadata).sort().join() === "client_session_secret,original_deadline_at");
    require(typeof metadata.client_session_secret === "string" && /^[0-9a-f]{64}$/.test(metadata.client_session_secret));
    const secret = hexToBytes(metadata.client_session_secret as string), c = (loaded.record as ReverseJournalRecord).context;
    try { receiver = restoreReverseFundingReader({ secret, clientKey: c.clientSessionKey, providerSessionKey: c.providerSessionKey, sessionId: c.sessionId, network, contractHash: doc.contract_hash as string }); }
    finally { secret.fill(0); }
    for (const url of urls) { assertCurrent(); const relay = await RelayConnection.open(url); connections.push(relay); assertCurrent(); }
    const result = await recoverReverseFundingEnvelopes(connections, receiver); assertCurrent();
    const candidates: { document: Uint8Array; event: Envelope }[] = [];
    for (const event of result.envelopes) {
      try {
        const payload = requireShape<{ binding: RecoveryFundingBinding; funding_binding_signature: string; funding_transaction: string }>("validateFundingBindingMessage", event.payload);
        require(payload.binding.funder_role === "provider" && payload.binding.binding_revision === 0 && payload.binding.replaces_txid === null);
        const candidate = bytes({ ...doc, updated_at: Math.max(doc.updated_at as number, payload.binding.created_at), funding_history: [{ binding: payload.binding, funder_session_signature: payload.funding_binding_signature }] });
        try { checkSelectedReverseFundingTransaction(candidate, network, { fundingAttemptId: payload.binding.funding_attempt_id, bindingRevision: 0 }, hexToBytes(payload.funding_transaction));
          candidates.push({ document: candidate, event }); } catch { candidate.fill(0); }
      } catch { /* Reject malformed/foreign archive payloads without diagnostics. */ }
    }
    try {
      // Distinct signed candidates/revisions and incomplete archives do not select a preferred history.
      require(!result.incomplete && candidates.length === 1);
      const ciphertext = await encryptCanonicalRecoveryForRecipient(candidates[0]!.document, await identityToRecipient(loaded.identity)); assertCurrent();
      await loaded.journal.saveFunding(loaded.record as ReverseJournalRecord, ciphertext); assertCurrent(); return ciphertext;
    } finally { for (const candidate of candidates) candidate.document.fill(0); }
  } finally { for (const relay of connections) relay.close(); receiver?.dispose(); loaded.plaintext.fill(0); loaded.journal.close(); }
}

/** Explicitly approved signing from an AFFIRMATIVE, checked funded predecessor, never missing local state. */
export async function prepareRecoveredReverseClaim(original: Uint8Array, identity: string, network: Network, api: string, feeSat: bigint, approve: () => void): Promise<Uint8Array> {
  // Explicit claim-only import is also available after device loss. It never creates a session/payment attempt.
  network = structuredClone(network); identity = await parseRecoveryIdentity(identity); approve();
  const report = inspectReverseRecoveryPlaintext(original, network), binding = report.fundingHistory.at(-1); require(binding !== undefined);
  const funded = withoutFallback(original), journal = await BrowserReverseJournal.open(); let fallback: Uint8Array | undefined, retainedFunded: Uint8Array | undefined;
  try {
    approve(); require(typeof feeSat === "bigint" && feeSat >= 0n && feeSat <= BigInt(report.maxClaimFeeSat) && feeSat <= BigInt(report.claimFeeReserveSat));
    const elected = await journal.claimOwner(network, binding!.funding_txid, binding!.contract_vout); approve();
    if (elected) {
      require("kind" in elected && elected.draft.fundedPlaintextDigest === bytesToHex(sha256(funded)) && elected.draft.feeSat === feeSat.toString());
      if (elected.stage !== "recovery-reserved") {
        const verified = await load(original, identity, network); try { approve(); return ciphertextOf(verified.record); } finally { verified.plaintext.fill(0); verified.journal.close(); }
      }
    }
    const selection = { fundingAttemptId: binding!.funding_attempt_id, bindingRevision: binding!.binding_revision };
    const observation = await observeReverseRecoveryFunding(funded, network, selection, api); approve();
    const recipient = await identityToRecipient(identity), encryptedFunded = await encryptCanonicalRecoveryForRecipient(funded, recipient); approve();
    const reservation = await journal.reserveImportedClaim({ networkIdentity: network, fundingTxid: binding!.funding_txid, fundingVout: binding!.contract_vout, bindingHash: bytesToHex(fundingBindingHash(binding!)), fundedPlaintextDigest: bytesToHex(sha256(funded)), feeSat: feeSat.toString() }, encryptedFunded); approve();
    if (reservation.stage !== "recovery-reserved") {
      const verified = await load(original, identity, network); try { approve(); return ciphertextOf(verified.record); } finally { verified.plaintext.fill(0); verified.journal.close(); }
    }
    // The first reservation may belong to another tab/identity. Authenticate
    // its ACTUAL retained predecessor, not the newly randomized input copy.
    retainedFunded = await decryptRecoveryContainer(hexToBytes(reservation.funded.ciphertextHex), identity); approve();
    const retained = inspectReverseRecoveryPlaintext(retainedFunded, network), retainedBinding = retained.fundingHistory.at(-1)!;
    require(bytesToHex(sha256(retainedFunded)) === reservation.draft.fundedPlaintextDigest && retained.contractHash === report.contractHash &&
      retainedBinding.funding_txid === reservation.draft.fundingTxid && retainedBinding.contract_vout === reservation.draft.fundingVout &&
      bytesToHex(fundingBindingHash(retainedBinding)) === reservation.draft.bindingHash);
    let transactionHex: string;
    if (report.fallbackTxid) {
      const imported = parseRecoveryPlaintext(original).document; transactionHex = ((imported.extensions as Record<string, unknown>)[REVERSE_FALLBACK_EXTENSION] as { transaction: string }).transaction;
      require(BigInt(binding!.contract_value_sat) - parseTransaction(hexToBytes(transactionHex)).outputs[0]!.value === feeSat); fallback = Uint8Array.from(original);
    } else {
      const claim = constructSelectedReverseClaim(retainedFunded, network, { ...selection, rawFundingTransaction: hexToBytes(observation.rawFundingTransactionHex), sampledTipHeight: observation.tipHeight, confirmations: observation.confirmations, feeSat });
      transactionHex = claim.transactionHex; fallback = appendReverseClaimFallback(retainedFunded, network, hexToBytes(transactionHex));
    }
    const ciphertext = await encryptCanonicalRecoveryForRecipient(fallback, recipient); approve();
    await journal.saveImportedClaim(reservation, { fundingTxid: binding!.funding_txid, fundingVout: binding!.contract_vout, txid: parseTransaction(hexToBytes(transactionHex)).txid, signedDigest: bytesToHex(sha256(hexToBytes(transactionHex))) }, ciphertext, report.fallbackTxid !== null);
    approve(); return ciphertext;
  } finally { fallback?.fill(0); retainedFunded?.fill(0); funded.fill(0); journal.close(); }
}

/** First exposure wins CAS. UNKNOWN permits identical manual export only, never another POST. */
export async function exposeRecoveredReverseClaim(original: Uint8Array, identity: string, network: Network, api: string,
  broadcastApi: string, approvedFeeSat: bigint, approvedClaimTxid: string, action: "download" | "broadcast", approve: () => void): Promise<{ readonly outcome: "exported" | "accepted" | "unknown"; readonly txid: string; readonly transactionHex?: string }> {
  network = structuredClone(network); approve(); const loaded = await load(original, identity, network);
  try {
    approve(); const report = inspectReverseRecoveryPlaintext(loaded.plaintext, network), doc = parseRecoveryPlaintext(loaded.plaintext).document,
      fallback = (doc.extensions as Record<string, unknown>)[REVERSE_FALLBACK_EXTENSION] as { transaction: string };
    require(report.fallbackTxid !== null && report.fallbackTxid === approvedClaimTxid && loaded.record.claim?.txid === report.fallbackTxid &&
      loaded.record.claim.signedDigest === bytesToHex(sha256(hexToBytes(fallback.transaction))));
    const binding = report.fundingHistory.at(-1)!;
    const parsed = parseTransaction(hexToBytes(fallback.transaction));
    require(BigInt(binding.contract_value_sat) - parsed.outputs[0]!.value === approvedFeeSat);
    const broadcast = validateMempoolApi(broadcastApi, network.name);
    if (loaded.record.stage === "claim-ready") {
      const observation = await observeReverseRecoveryFunding(loaded.plaintext, network, { fundingAttemptId: binding.funding_attempt_id, bindingRevision: binding.binding_revision }, api); approve();
      require(observation.confirmations >= report.minFundingDepth && observation.tipHeight + report.claimConfirmationBlocks < report.refundLockHeight + 1);
      if ("kind" in loaded.record) await loaded.journal.exposeImportedClaim(loaded.record); else await loaded.journal.beginClaimExposure(loaded.record);
      // From this point, ambiguity never renews submission authority.
      try {
        approve();
        if (action === "download") return Object.freeze({ outcome: "exported", txid: report.fallbackTxid!, transactionHex: fallback.transaction });
        const signal = AbortSignal.timeout(15000), response = await fetch(`${broadcast}/tx`, { signal, method: "POST", body: fallback.transaction,
          headers: { "Content-Type": "text/plain" }, credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
        require(await readBoundedChainText(response, signal) === report.fallbackTxid);
        // Imported records retain UNKNOWN, including an accepted transport response.
        return Object.freeze({ outcome: "accepted", txid: report.fallbackTxid! });
      } catch { return Object.freeze({ outcome: "unknown", txid: report.fallbackTxid! }); }
    } else {
      require(action === "download" && (loaded.record.stage === "claim-unknown" || loaded.record.stage === "accepted"));
      if ("kind" in loaded.record) await loaded.journal.reexportImportedClaim(loaded.record); else await loaded.journal.reexportIdentical(loaded.record); approve();
    }
    require(parsed.txid === report.fallbackTxid); return Object.freeze({ outcome: "exported", txid: report.fallbackTxid!, transactionHex: fallback.transaction });
  } finally { loaded.plaintext.fill(0); loaded.journal.close(); }
}
