/**
 * Minimal NIP-01 relay client for one swap: publish with OK confirmation,
 * one live subscription, and one bounded one-shot query. Frames over the
 * size cap are dropped; nothing received is trusted before verification.
 */
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";
import type { NostrEvent } from "nostr-tools";

import type { RelayLink } from "./session";

const MAX_FRAME_BYTES = 128 * 1024;
const MAX_QUEUE = 1024;
const PUBLISH_TIMEOUT_MS = 10_000;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

export class RelayError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayError";
  }
}

/** wss:// anywhere; plain ws:// only to a loopback relay (local regtest). */
export function checkRelayUrl(text: string): string {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    throw new RelayError("relay URL is not a URL");
  }
  if (url.protocol === "wss:" || (url.protocol === "ws:" && LOOPBACK.has(url.hostname))) return url.toString();
  throw new RelayError("relay URL must use wss:// (ws:// only for a loopback relay)");
}

type Waiter = () => void;

export class RelayConnection implements RelayLink {
  private readonly queue: string[] = [];
  private readonly waiters = new Set<Waiter>();
  private readonly acks = new Map<string, (ok: boolean) => void>();
  private readonly queries = new Map<string, { events: string[]; done: () => void; limit: number }>();
  private live: string | null = null;
  private closed = false;

  private constructor(private readonly socket: WebSocket) {
    socket.addEventListener("message", (message) => this.onMessage(message.data));
    socket.addEventListener("close", () => {
      this.closed = true;
      for (const resolve of this.acks.values()) resolve(false);
      for (const query of this.queries.values()) query.done();
      this.wake();
    });
  }

  static open(url: string, timeoutMs = 10_000, factory = (target: string) => new WebSocket(target)):
    Promise<RelayConnection> {
    const socket = factory(checkRelayUrl(url));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.close();
        reject(new RelayError("relay connection timed out"));
      }, timeoutMs);
      socket.addEventListener("open", () => {
        clearTimeout(timer);
        resolve(new RelayConnection(socket));
      });
      socket.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new RelayError("relay connection failed"));
      });
    });
  }

  close(): void {
    this.socket.close();
  }

  private wake(): void {
    for (const waiter of [...this.waiters]) waiter();
  }

  private onMessage(data: unknown): void {
    if (typeof data !== "string" || new TextEncoder().encode(data).length > MAX_FRAME_BYTES) return;
    let frame: unknown;
    try {
      frame = JSON.parse(data);
    } catch {
      return;
    }
    if (!Array.isArray(frame)) return;
    const [type, first, second] = frame as unknown[];
    if (type === "OK" && typeof first === "string") {
      this.acks.get(first)?.(second === true);
      this.acks.delete(first);
    } else if (type === "EVENT" && typeof first === "string" && second !== null && typeof second === "object") {
      const raw = JSON.stringify(second);
      const query = this.queries.get(first);
      if (query) {
        query.events.push(raw);
        if (query.events.length > query.limit) query.done();
      } else if (first === this.live && this.queue.length < MAX_QUEUE) {
        this.queue.push(raw);
        this.wake();
      }
    } else if ((type === "EOSE" || type === "CLOSED") && typeof first === "string") {
      this.queries.get(first)?.done();
    }
  }

  private send(frame: unknown[]): void {
    if (this.closed) throw new RelayError("relay connection closed");
    this.socket.send(JSON.stringify(frame));
  }

  publish(event: NostrEvent): Promise<boolean> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.acks.delete(event.id);
        resolve(false);
      }, PUBLISH_TIMEOUT_MS);
      this.acks.set(event.id, (ok) => {
        clearTimeout(timer);
        resolve(ok);
      });
      try {
        this.send(["EVENT", event]);
      } catch {
        this.acks.get(event.id)?.(false);
      }
    });
  }

  async subscribe(filter: Record<string, unknown>): Promise<void> {
    if (this.live !== null) this.send(["CLOSE", this.live]);
    this.live = bytesToHex(randomBytes(8));
    this.queue.length = 0;
    this.send(["REQ", this.live, filter]);
  }

  async next(deadline: number): Promise<string | null> {
    for (;;) {
      const item = this.queue.shift();
      if (item !== undefined) return item;
      const remaining = deadline - Date.now();
      if (this.closed || remaining <= 0) return null;
      await new Promise<void>((resolve) => {
        const waiter = (): void => {
          clearTimeout(timer);
          this.waiters.delete(waiter);
          resolve();
        };
        const timer = setTimeout(waiter, remaining);
        this.waiters.add(waiter);
      });
    }
  }

  /**
   * Stored events for `filter` until EOSE or the timeout. More than `limit`
   * events ends the query with `truncated` so a caller can refuse a flood.
   */
  query(filter: Record<string, unknown>, limit: number, timeoutMs = 10_000):
    Promise<{ events: string[]; truncated: boolean }> {
    const id = bytesToHex(randomBytes(8));
    return new Promise((resolve) => {
      const events: string[] = [];
      const done = (): void => {
        clearTimeout(timer);
        if (!this.queries.delete(id)) return;
        if (!this.closed) this.socket.send(JSON.stringify(["CLOSE", id]));
        resolve({ events: events.slice(0, limit), truncated: events.length > limit });
      };
      const timer = setTimeout(done, timeoutMs);
      this.queries.set(id, { events, done, limit });
      try {
        this.send(["REQ", id, filter]);
      } catch {
        done();
      }
    });
  }
}
