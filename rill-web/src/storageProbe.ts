/** User-triggered, synthetic storage diagnostic. Never writes swap state. */

export type PersistenceResult = "granted" | "denied" | "unavailable";

export interface ProbeResult {
  readonly roundTrip: boolean;
  readonly persistence: PersistenceResult;
  readonly cleanup: boolean;
}

function request<T>(operation: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result);
    operation.onerror = () => reject(new Error("Browser storage operation failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(new Error("Browser storage transaction aborted"));
    transaction.onerror = () => reject(new Error("Browser storage transaction failed"));
  });
}

function removeDiagnostic(name: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const deletion = indexedDB.deleteDatabase(name);
      deletion.onsuccess = () => resolve(true);
      deletion.onerror = () => resolve(false);
      deletion.onblocked = () => resolve(false);
    } catch {
      resolve(false);
    }
  });
}

async function persistenceRequest(): Promise<PersistenceResult> {
  if (typeof navigator.storage?.persist !== "function") return "unavailable";
  try {
    return (await navigator.storage.persist()) ? "granted" : "denied";
  } catch {
    return "unavailable";
  }
}

/** No startup call. The caller must obtain a direct user click first. */
export async function testBrowserStorage(): Promise<ProbeResult> {
  if (typeof indexedDB === "undefined" || typeof crypto.randomUUID !== "function") {
    return { roundTrip: false, persistence: "unavailable", cleanup: true };
  }
  const name = `rillswap-diagnostic-1-${crypto.randomUUID()}`;
  let database: IDBDatabase | undefined;
  let roundTrip = false;
  let persistence: PersistenceResult = "unavailable";
  try {
    const opening = indexedDB.open(name, 1);
    opening.onupgradeneeded = () => opening.result.createObjectStore("synthetic");
    database = await request(opening);
    const marker = crypto.randomUUID();
    const write = database.transaction("synthetic", "readwrite");
    const committed = transactionDone(write);
    try {
      write.objectStore("synthetic").put(marker, "probe");
    } catch {
      write.abort();
      await committed.catch(() => undefined);
      throw new Error("Synthetic storage write failed");
    }
    await committed;
    const read = database.transaction("synthetic", "readonly");
    const readComplete = transactionDone(read);
    let retrieved: unknown;
    try {
      retrieved = await request(read.objectStore("synthetic").get("probe"));
      await readComplete;
    } catch {
      await readComplete.catch(() => undefined);
      throw new Error("Synthetic storage read failed");
    }
    roundTrip = retrieved === marker;
    if (roundTrip) persistence = await persistenceRequest();
  } catch {
    // Failure proves only that this particular diagnostic did not pass.
  } finally {
    database?.close();
  }
  const cleanup = await removeDiagnostic(name);
  return { roundTrip, persistence, cleanup };
}
