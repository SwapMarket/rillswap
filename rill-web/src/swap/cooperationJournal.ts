/**
 * The cooperative claim's create-only IndexedDB refusal journal, held under an
 * exclusive Web Lock. The journal never grants anything: an existing record
 * refuses (whatever its age or shape), and its absence proves nothing. It is
 * never pruned: neither age nor a free lock proves that every context able to
 * sign for that contract is gone, and each swap adds one small record. A page
 * restored from the back/forward cache never signs again.
 */
import type { ReservationRecord } from "./cooperative";

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

/** Run `body` only after a create-only journal record for `key` committed under an exclusive Web Lock. */
export async function reserveCooperation<T>(key: string, record: ReservationRecord, body: () => Promise<T>): Promise<T> {
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
}
