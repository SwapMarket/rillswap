/**
 * Browser capabilities for the cooperative claim: the vendored WASM MuSig2
 * signer and a create-only IndexedDB refusal journal held under an exclusive
 * Web Lock. The journal never grants anything: an existing record refuses,
 * and its absence proves nothing. A page restored from the back/forward
 * cache never signs again.
 */
import type { Cosigner, ReservationRecord } from "./cooperative";
import { loadMusig } from "./rillCrypto";

const DATABASE = "rillswap-cooperation";
const STORE = "reservations";
let restoredFromCache = false;
if (typeof addEventListener === "function") {
  addEventListener("pageshow", (event) => {
    if ((event as PageTransitionEvent).persisted) restoredFromCache = true;
  });
}

function request<T>(operation: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(operation.error ?? new Error("IndexedDB request failed"));
  });
}

function openJournal(): Promise<IDBDatabase> {
  const opening = indexedDB.open(DATABASE, 1);
  opening.onupgradeneeded = () => opening.result.createObjectStore(STORE);
  return request(opening);
}

/** Create-only insert; resolves only once the strict-durability transaction committed. */
export async function journalReservation(key: string, record: ReservationRecord): Promise<void> {
  const database = await openJournal();
  try {
    const transaction = database.transaction(STORE, "readwrite", { durability: "strict" });
    const committed = new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onabort = () => reject(transaction.error ?? new Error("reservation aborted"));
      transaction.onerror = () => reject(transaction.error ?? new Error("reservation failed"));
    });
    transaction.objectStore(STORE).add({ ...record }, key); // a ConstraintError aborts on an existing key
    await committed;
  } finally {
    database.close();
  }
}

export const browserCosigner: Cosigner = {
  loadMusig,
  async reserve(key, record, body) {
    if (restoredFromCache) throw new Error("page was restored; cooperation disabled");
    if (typeof navigator === "undefined" || !navigator.locks || typeof indexedDB === "undefined") {
      throw new Error("Web Locks or IndexedDB unavailable; cooperation disabled");
    }
    return navigator.locks.request(`rillswap-cooperation-${key}`, { mode: "exclusive", ifAvailable: true }, async (lock) => {
      if (lock === null) throw new Error("another tab holds this cooperation");
      await journalReservation(key, record);
      if (restoredFromCache) throw new Error("page was restored; cooperation disabled");
      return body();
    });
  },
};
