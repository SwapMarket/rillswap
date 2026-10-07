// Pure demo-shop logic, kept apart from server.ts so it can be unit tested.
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
