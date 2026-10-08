// Demo-shop logic kept apart from server.ts (which starts services on import)
// so it can be unit tested.
import { existsSync, readdirSync, readFileSync, renameSync } from "node:fs";
import { basename, dirname } from "node:path";
import { verifyAcceptance, type SignedAcceptance } from "../../src/server";

export const DEMO_USD_PER_BTC = 100_000;

/** Demo pricing: USD cents at a fixed BTC rate, in whole satoshis. */
export function priceSat(usdCents: number): number {
  return Math.round((usdCents / 100 / DEMO_USD_PER_BTC) * 1e8);
}

/**
 * The merchant's signed acceptance for exactly this intent and amount, checked
 * against a key pinned independently of the merchant API response.
 */
export function findAcceptance(
  events: readonly SignedAcceptance[],
  pinnedKey: string,
  intentId: string,
  amountSat: number,
): SignedAcceptance | undefined {
  return events.find((envelope) =>
    verifyAcceptance(envelope, pinnedKey) &&
    envelope.event.intentId === intentId &&
    envelope.event.amountMsat === String(amountSat * 1000));
}

/**
 * Reads the order history file. An unreadable file is moved aside (so the next
 * save cannot overwrite it), and while any moved-aside file remains the
 * history counts as unknown, across restarts and later saves alike, until the
 * stack is reset or that file is dealt with by hand.
 */
export function readOrderHistory<T>(file: string): { orders: T[]; known: boolean } {
  let orders: T[] = [];
  if (existsSync(file)) {
    try {
      const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
      if (!Array.isArray(parsed)) throw new Error("not a JSON list");
      orders = parsed as T[];
    } catch (error) {
      const aside = `${file}.unreadable-${Date.now()}`;
      renameSync(file, aside);
      console.error(`cannot read ${file} (${(error as Error).message}); moved it to ${aside}`);
    }
  }
  const quarantined = existsSync(dirname(file)) && readdirSync(dirname(file)).some((name) => name.startsWith(`${basename(file)}.unreadable-`));
  return { orders, known: !quarantined };
}
