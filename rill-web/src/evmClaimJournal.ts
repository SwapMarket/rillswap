/** Encrypted reverse-swap backups and an atomic preimage-exposure grant, committed before external effects. */
export const EVM_JOURNAL_DATABASE = "rillswap-evm-claims-v1";
export interface EvmJournalEntry {
  readonly id: string;
  readonly ciphertext: Uint8Array;
  readonly exposure: "unexposed" | "unknown";
}

/** Missing state never authorizes a claim, including imported files from another browser. */
export class EvmClaimJournal {
  private database: Promise<IDBDatabase> | undefined;
  private open(): Promise<IDBDatabase> {
    return this.database ??= new Promise((resolve, reject) => {
      const request = indexedDB.open(EVM_JOURNAL_DATABASE, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("records", { keyPath: "id" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("Could not open stablecoin recovery storage"));
      request.onblocked = () => reject(new Error("Close other swap tabs before opening recovery storage"));
    });
  }

  async read(id: string): Promise<EvmJournalEntry | null> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction("records", "readonly");
      const request = tx.objectStore("records").get(id);
      tx.oncomplete = () => resolve(request.result ?? null);
      tx.onabort = tx.onerror = () => reject(new Error("Could not read stablecoin recovery storage"));
    });
  }

  /** Fresh identifiers only. Used for the pre-firm secret and then the authenticated contract. */
  async create(id: string, ciphertext: Uint8Array): Promise<void> {
    const snapshot = Uint8Array.from(ciphertext);
    await this.change(id, (old) => {
      if (old) throw new Error("This stablecoin recovery record already exists");
      return { id, ciphertext: snapshot, exposure: "unexposed" };
    });
  }

  async save(id: string, ciphertext: Uint8Array): Promise<void> {
    const snapshot = Uint8Array.from(ciphertext);
    await this.change(id, (old) => {
      if (!old) throw new Error("Stablecoin recovery storage is missing; claim status is unknown");
      return { ...old, ciphertext: snapshot };
    });
  }

  /** Exactly one tab may disclose the preimage. Failure or a lost wallet response leaves UNKNOWN. */
  async expose(id: string): Promise<void> {
    await this.change(id, (old) => {
      if (!old || old.exposure !== "unexposed") throw new Error("Claim exposure is unknown. Check the chain; no automatic retry is allowed");
      return { ...old, exposure: "unknown" };
    });
  }

  private async change(id: string, update: (old: EvmJournalEntry | undefined) => EvmJournalEntry): Promise<void> {
    const db = await this.open();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("records", "readwrite", { durability: "strict" });
      if (tx.durability !== "strict") { tx.abort(); reject(new Error("Durable stablecoin recovery storage is unavailable")); return; }
      let failure: unknown;
      const store = tx.objectStore("records"), request = store.get(id);
      request.onsuccess = () => {
        try { store.put(update(request.result)); } catch (error) { failure = error; tx.abort(); }
      };
      tx.oncomplete = () => resolve();
      tx.onabort = tx.onerror = () => reject(failure ?? new Error("Stablecoin recovery commit failed; no external action is authorized"));
    });
  }
}
